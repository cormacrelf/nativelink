// Copyright 2025 The NativeLink Authors. All rights reserved.
//
// Licensed under the Functional Source License, Version 1.1, Apache 2.0 Future License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    See LICENSE file for details
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::io::{self, Cursor, Write};
use std::path::PathBuf;

mod support;

use bytes::Bytes;
use flate2::Compression;
use flate2::write::{DeflateEncoder, GzEncoder};
use nativelink_config::stores::{FilesystemSpec, MemorySpec};
use nativelink_error::{Code, Error};
use nativelink_fetch::archive_expander::{
    ArchiveFormat, ArchiveLimits, ArchiveOptions, Entry as ListingEntry, ExpandHook, ExtractedTree,
    FileMeta, Held, Kind, Listing, NoHook, extract_archive, git_cmp,
};
use nativelink_macro::nativelink_test;
use nativelink_proto::build::bazel::remote::execution::v2::Directory;
use nativelink_store::filesystem_store::{FileEntryImpl, FilesystemStore};
use nativelink_store::memory_store::MemoryStore;
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::DigestHasherFunc;
use nativelink_util::store_trait::{Store, StoreLike};
use pretty_assertions::assert_eq;
use prost::Message;
use tokio_util::io::StreamReader;
use tonic::async_trait;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

/// `(name, content, unix_mode)`.
type Entry<'a> = (&'a str, &'a [u8], u32);

fn build_zip(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, content, mode) in entries {
        let options = SimpleFileOptions::default().unix_permissions(*mode);
        writer.start_file(*name, options).unwrap();
        writer.write_all(content).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn tar_header(mode: u32, size: usize) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_mode(mode);
    header.set_size(size as u64);
    header.set_entry_type(tar::EntryType::Regular);
    header
}

fn build_tar(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, content, mode) in entries {
        let mut header = tar_header(*mode, content.len());
        builder.append_data(&mut header, name, *content).unwrap();
    }
    builder.into_inner().unwrap()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// One entry for [`raw_zip`], which writes zips the `zip` crate won't.
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent knobs of a test helper"
)]
struct RawEntry<'a> {
    name: &'a str,
    content: &'a [u8],
    mode: u32,
    deflated: bool,
    /// Put the CRC and sizes in a data descriptor after the data.
    descriptor: bool,
    /// With a data descriptor, write the sizes in the local header too.
    sizes_in_header: bool,
    /// Record a wrong CRC-32.
    bad_crc: bool,
}

impl<'a> RawEntry<'a> {
    const fn new(name: &'a str, content: &'a [u8]) -> Self {
        Self {
            name,
            content,
            mode: 0o100_644,
            deflated: true,
            descriptor: false,
            sizes_in_header: false,
            bad_crc: false,
        }
    }

    const fn sizes_in_header(mut self) -> Self {
        self.sizes_in_header = true;
        self
    }

    const fn stored(mut self) -> Self {
        self.deflated = false;
        self
    }

    const fn descriptor(mut self) -> Self {
        self.descriptor = true;
        self
    }

    const fn mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }

    const fn bad_crc(mut self) -> Self {
        self.bad_crc = true;
        self
    }
}

fn u16_le<T: TryInto<u16, Error: core::fmt::Debug>>(n: T) -> [u8; 2] {
    n.try_into().unwrap().to_le_bytes()
}

fn u32_le<T: TryInto<u32, Error: core::fmt::Debug>>(n: T) -> [u8; 4] {
    n.try_into().unwrap().to_le_bytes()
}

/// Writes a zip by hand. With `zip64`, every size and offset is written in
/// zip64 form (including the zip64 end records).
fn raw_zip(entries: &[RawEntry<'_>], zip64: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for entry in entries {
        let offset = out.len() as u64;
        let crc = crc32fast::hash(entry.content) ^ u32::from(entry.bad_crc);
        let body = if entry.deflated {
            deflate(entry.content)
        } else {
            entry.content.to_vec()
        };
        let method: u16 = if entry.deflated { 8 } else { 0 };
        let flags: u16 = if entry.descriptor { 8 } else { 0 };
        let (size, csize) = (entry.content.len() as u64, body.len() as u64);

        // Local header.
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&(if zip64 { 45u16 } else { 20 }).to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&[0; 4]); // time, date
        let header_crc = if entry.descriptor { 0 } else { crc };
        out.extend_from_slice(&header_crc.to_le_bytes());
        let local_extra: Vec<u8> = if zip64 {
            let (usize64, csize64) = if entry.descriptor {
                (0, 0)
            } else {
                (size, csize)
            };
            let mut extra = vec![1, 0, 16, 0];
            extra.extend_from_slice(&usize64.to_le_bytes());
            extra.extend_from_slice(&csize64.to_le_bytes());
            extra
        } else {
            Vec::new()
        };
        let (packed_field, plain_field) = match (entry.descriptor, zip64) {
            (true, false) if entry.sizes_in_header => {
                (u32::try_from(csize).unwrap(), u32::try_from(size).unwrap())
            }
            (true, _) => (0, 0),
            (false, true) => (u32::MAX, u32::MAX),
            (false, false) => (u32::try_from(csize).unwrap(), u32::try_from(size).unwrap()),
        };
        out.extend_from_slice(&packed_field.to_le_bytes());
        out.extend_from_slice(&plain_field.to_le_bytes());
        out.extend_from_slice(&u16_le(entry.name.len()));
        out.extend_from_slice(&u16_le(local_extra.len()));
        out.extend_from_slice(entry.name.as_bytes());
        out.extend_from_slice(&local_extra);
        out.extend_from_slice(&body);
        if entry.descriptor {
            out.extend_from_slice(&0x0807_4b50u32.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            if zip64 {
                out.extend_from_slice(&csize.to_le_bytes());
                out.extend_from_slice(&size.to_le_bytes());
            } else {
                out.extend_from_slice(&u32_le(csize));
                out.extend_from_slice(&u32_le(size));
            }
        }

        // Central directory record.
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&((3u16 << 8) | 0x2d).to_le_bytes());
        central.extend_from_slice(&(if zip64 { 45u16 } else { 20 }).to_le_bytes());
        central.extend_from_slice(&flags.to_le_bytes());
        central.extend_from_slice(&method.to_le_bytes());
        central.extend_from_slice(&[0; 4]);
        central.extend_from_slice(&crc.to_le_bytes());
        let central_extra: Vec<u8> = if zip64 {
            let mut extra = vec![1, 0, 24, 0];
            for value in [size, csize, offset] {
                extra.extend_from_slice(&value.to_le_bytes());
            }
            extra
        } else {
            Vec::new()
        };
        if zip64 {
            central.extend_from_slice(&u32::MAX.to_le_bytes());
            central.extend_from_slice(&u32::MAX.to_le_bytes());
        } else {
            central.extend_from_slice(&u32_le(csize));
            central.extend_from_slice(&u32_le(size));
        }
        central.extend_from_slice(&u16_le(entry.name.len()));
        central.extend_from_slice(&u16_le(central_extra.len()));
        central.extend_from_slice(&[0; 2]); // comment length
        central.extend_from_slice(&[0; 2]); // disk number
        central.extend_from_slice(&[0; 2]); // internal attributes
        central.extend_from_slice(&(entry.mode << 16).to_le_bytes());
        if zip64 {
            central.extend_from_slice(&u32::MAX.to_le_bytes());
        } else {
            central.extend_from_slice(&u32_le(offset));
        }
        central.extend_from_slice(entry.name.as_bytes());
        central.extend_from_slice(&central_extra);
    }

    let central_offset = out.len() as u64;
    out.extend_from_slice(&central);
    let count = entries.len() as u64;
    if zip64 {
        let end64_offset = out.len() as u64;
        out.extend_from_slice(&0x0606_4b50u32.to_le_bytes());
        out.extend_from_slice(&44u64.to_le_bytes());
        out.extend_from_slice(&45u16.to_le_bytes());
        out.extend_from_slice(&45u16.to_le_bytes());
        out.extend_from_slice(&[0; 8]); // disk numbers
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&(central.len() as u64).to_le_bytes());
        out.extend_from_slice(&central_offset.to_le_bytes());
        out.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&end64_offset.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
    }
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0; 4]); // disk numbers
    if zip64 {
        out.extend_from_slice(&u16::MAX.to_le_bytes());
        out.extend_from_slice(&u16::MAX.to_le_bytes());
        out.extend_from_slice(&u32::MAX.to_le_bytes());
        out.extend_from_slice(&u32::MAX.to_le_bytes());
    } else {
        out.extend_from_slice(&u16_le(count));
        out.extend_from_slice(&u16_le(count));
        out.extend_from_slice(&u32_le(central.len()));
        out.extend_from_slice(&u32_le(central_offset));
    }
    out.extend_from_slice(&[0; 2]); // comment length
    out
}

struct Fixture {
    cas_store: Store,
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            cas_store: Store::new(MemoryStore::new(&MemorySpec::default())),
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn options(&self, limits: ArchiveLimits) -> ArchiveOptions {
        let mut options = ArchiveOptions::new(DigestHasherFunc::Sha256);
        options.limits = limits;
        options.temp_dir = Some(self.dir.path().to_path_buf());
        options
    }

    /// Streams `data` through the extractor in `chunk_size` byte pieces.
    async fn extract_with(
        &self,
        data: &[u8],
        options: &ArchiveOptions,
        chunk_size: usize,
    ) -> Result<ExtractedTree, Error> {
        let chunks: Vec<io::Result<Bytes>> = data
            .chunks(chunk_size)
            .map(|chunk| Ok(Bytes::copy_from_slice(chunk)))
            .collect();
        let mut reader = StreamReader::new(futures::stream::iter(chunks));
        extract_archive(&mut reader, self.cas_store.as_pin(), options, &mut NoHook).await
    }

    async fn extract(&self, data: &[u8], limits: ArchiveLimits) -> Result<ExtractedTree, Error> {
        self.extract_with(data, &self.options(limits), 4096).await
    }

    async fn read_directory(&self, digest: DigestInfo) -> Directory {
        let raw = self
            .cas_store
            .get_part_unchunked(digest, 0, None)
            .await
            .unwrap();
        Directory::decode(raw).unwrap()
    }

    async fn read_file(
        &self,
        node_digest: Option<&nativelink_proto::build::bazel::remote::execution::v2::Digest>,
    ) -> Vec<u8> {
        let digest: DigestInfo = node_digest.unwrap().clone().try_into().unwrap();
        self.cas_store
            .get_part_unchunked(digest, 0, None)
            .await
            .unwrap()
            .to_vec()
    }
}

const SAMPLE: &[Entry<'static>] = &[
    ("hello.txt", b"hello", 0o644),
    ("bin/run.sh", b"#!/bin/sh\n", 0o755),
    ("bin/lib/inner.txt", b"inner", 0o644),
];

#[nativelink_test]
async fn all_formats_produce_identical_trees() -> Result<(), Error> {
    let fixture = Fixture::new();
    let tar_data = build_tar(SAMPLE);
    let zip = fixture
        .extract(&build_zip(SAMPLE), ArchiveLimits::default())
        .await?;
    let tar = fixture.extract(&tar_data, ArchiveLimits::default()).await?;
    let targz = fixture
        .extract(&gzip(&tar_data), ArchiveLimits::default())
        .await?;
    assert_eq!(zip, tar);
    assert_eq!(zip, targz);

    let root = fixture.read_directory(zip.root_digest).await;
    assert_eq!(root.files.len(), 1);
    assert_eq!(root.files[0].name, "hello.txt");
    assert!(!root.files[0].is_executable);
    assert_eq!(
        fixture.read_file(root.files[0].digest.as_ref()).await,
        b"hello"
    );
    assert_eq!(root.directories.len(), 1);
    assert_eq!(root.directories[0].name, "bin");

    let bin_digest: DigestInfo = root.directories[0]
        .digest
        .clone()
        .unwrap()
        .try_into()
        .unwrap();
    let bin = fixture.read_directory(bin_digest).await;
    assert_eq!(bin.files.len(), 1);
    assert_eq!(bin.files[0].name, "run.sh");
    assert!(bin.files[0].is_executable);
    assert_eq!(bin.directories[0].name, "lib");
    Ok(())
}

#[nativelink_test]
async fn result_does_not_depend_on_chunking() -> Result<(), Error> {
    let fixture = Fixture::new();
    let tar_data = build_tar(SAMPLE);
    let options = fixture.options(ArchiveLimits::default());
    for data in [build_zip(SAMPLE), tar_data.clone(), gzip(&tar_data)] {
        let expected = fixture.extract_with(&data, &options, 1 << 20).await?;
        for chunk_size in [1, 7, 511, 513] {
            let tree = fixture.extract_with(&data, &options, chunk_size).await?;
            assert_eq!(tree, expected, "chunk size {chunk_size}");
        }
    }
    Ok(())
}

#[nativelink_test]
async fn gzip_with_multiple_members() -> Result<(), Error> {
    let fixture = Fixture::new();
    let tar_data = build_tar(SAMPLE);
    let (first, second) = tar_data.split_at(1000);
    let mut data = gzip(first);
    data.extend_from_slice(&gzip(second));
    let tree = fixture.extract(&data, ArchiveLimits::default()).await?;
    let plain = fixture.extract(&tar_data, ArchiveLimits::default()).await?;
    assert_eq!(tree, plain);
    Ok(())
}

#[nativelink_test]
async fn tar_symlinks_and_hard_links() -> Result<(), Error> {
    let fixture = Fixture::new();
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar_header(0o755, 3);
    builder
        .append_data(&mut header, "./a/tool", &b"abc"[..])
        .unwrap();
    let mut link = tar::Header::new_gnu();
    link.set_entry_type(tar::EntryType::Symlink);
    link.set_size(0);
    link.set_mode(0o777);
    builder.append_link(&mut link, "a/z-link", "tool").unwrap();
    let mut link = tar::Header::new_gnu();
    link.set_entry_type(tar::EntryType::Symlink);
    link.set_size(0);
    link.set_mode(0o777);
    builder.append_link(&mut link, "a/b-link", "../x").unwrap();
    let mut hard = tar::Header::new_gnu();
    hard.set_entry_type(tar::EntryType::Link);
    hard.set_size(0);
    hard.set_mode(0o644);
    builder.append_link(&mut hard, "a/hard", "a/tool").unwrap();
    let data = builder.into_inner().unwrap();

    let tree = fixture.extract(&data, ArchiveLimits::default()).await?;
    let root = fixture.read_directory(tree.root_digest).await;
    let a_digest: DigestInfo = root.directories[0]
        .digest
        .clone()
        .unwrap()
        .try_into()
        .unwrap();
    let a = fixture.read_directory(a_digest).await;
    let names: Vec<_> = a.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["hard", "tool"]);
    assert_eq!(a.files[0].digest, a.files[1].digest);
    assert!(a.files[0].is_executable);
    // Symlinks are sorted by name.
    let links: Vec<_> = a
        .symlinks
        .iter()
        .map(|s| (s.name.as_str(), s.target.as_str()))
        .collect();
    assert_eq!(links, [("b-link", "../x"), ("z-link", "tool")]);

    // A hard link to something we haven't seen is an error.
    let mut builder = tar::Builder::new(Vec::new());
    let mut hard = tar::Header::new_gnu();
    hard.set_entry_type(tar::EntryType::Link);
    hard.set_size(0);
    builder.append_link(&mut hard, "hard", "missing").unwrap();
    let err = fixture
        .extract(&builder.into_inner().unwrap(), ArchiveLimits::default())
        .await
        .unwrap_err();
    assert_eq!(err.code, Code::InvalidArgument);
    Ok(())
}

#[nativelink_test]
async fn zip_symlinks() -> Result<(), Error> {
    let fixture = Fixture::new();
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            "f.txt",
            SimpleFileOptions::default().unix_permissions(0o644),
        )
        .unwrap();
    writer.write_all(b"data").unwrap();
    writer
        .add_symlink("link", "f.txt", SimpleFileOptions::default())
        .unwrap();
    let data = writer.finish().unwrap().into_inner();

    let tree = fixture.extract(&data, ArchiveLimits::default()).await?;
    let root = fixture.read_directory(tree.root_digest).await;
    assert_eq!(root.files.len(), 1);
    assert_eq!(root.symlinks.len(), 1);
    assert_eq!(root.symlinks[0].name, "link");
    assert_eq!(root.symlinks[0].target, "f.txt");
    Ok(())
}

#[nativelink_test]
async fn zip_directory_entries_and_empty_files() -> Result<(), Error> {
    let fixture = Fixture::new();
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .add_directory("empty/", SimpleFileOptions::default())
        .unwrap();
    writer
        .start_file("zero", SimpleFileOptions::default())
        .unwrap();
    let data = writer.finish().unwrap().into_inner();

    let tree = fixture.extract(&data, ArchiveLimits::default()).await?;
    let root = fixture.read_directory(tree.root_digest).await;
    assert_eq!(root.directories.len(), 1);
    assert_eq!(root.directories[0].name, "empty");
    assert_eq!(root.files.len(), 1);
    assert_eq!(root.files[0].name, "zero");
    Ok(())
}

#[nativelink_test]
async fn unsafe_paths_are_rejected() {
    let fixture = Fixture::new();
    for name in ["../evil", "a/../../evil", "/abs"] {
        let zip = build_zip(&[(name, b"x", 0o644)]);
        let err = fixture
            .extract(&zip, ArchiveLimits::default())
            .await
            .expect_err(name);
        assert_eq!(err.code, Code::InvalidArgument, "zip {name}");

        // `tar::Builder` refuses such names, so write the raw header bytes.
        let mut header = tar_header(0o644, 1);
        let gnu = header.as_gnu_mut().unwrap();
        gnu.name[..name.len()].copy_from_slice(name.as_bytes());
        header.set_cksum();
        let mut data = header.as_bytes().to_vec();
        data.extend_from_slice(&[b'x'; 512]);
        data.extend_from_slice(&[0; 1024]);
        let err = fixture
            .extract(&data, ArchiveLimits::default())
            .await
            .unwrap_err();
        assert_eq!(err.code, Code::InvalidArgument, "tar {name}");
    }
}

#[nativelink_test]
async fn limits_are_enforced() {
    let fixture = Fixture::new();
    let tar_data = build_tar(SAMPLE);

    let err = fixture
        .extract(
            &tar_data,
            ArchiveLimits {
                max_entries: Some(2),
                max_total_uncompressed_bytes: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, Code::ResourceExhausted);

    // 5 + 10 + 5 = 20 bytes of content.
    for (limit, ok) in [(20, true), (19, false)] {
        for data in [build_zip(SAMPLE), tar_data.clone(), gzip(&tar_data)] {
            let result = fixture
                .extract(
                    &data,
                    ArchiveLimits {
                        max_entries: Some(3),
                        max_total_uncompressed_bytes: Some(limit),
                    },
                )
                .await;
            match result {
                Ok(_) => assert!(ok, "limit {limit}"),
                Err(err) => {
                    assert!(!ok, "limit {limit}: {err:?}");
                    assert_eq!(err.code, Code::ResourceExhausted);
                }
            }
        }
    }
}

#[nativelink_test]
async fn highly_compressible_entry_hits_byte_limit() {
    let fixture = Fixture::new();
    let big = vec![0u8; 4 * 1024 * 1024];
    let limits = ArchiveLimits {
        max_entries: None,
        max_total_uncompressed_bytes: Some(1024 * 1024),
    };
    for data in [
        gzip(&build_tar(&[("zeros", &big, 0o644)])),
        build_zip(&[("zeros", &big, 0o644)]),
    ] {
        assert!(data.len() < 100 * 1024);
        let err = fixture.extract(&data, limits).await.unwrap_err();
        assert_eq!(err.code, Code::ResourceExhausted);
    }
}

#[nativelink_test]
async fn large_entries_spill_to_temp_file() -> Result<(), Error> {
    let fixture = Fixture::new();
    let spill_dir = tempfile::tempdir().unwrap();
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let entries: &[Entry<'_>] = &[("small", b"tiny", 0o644), ("big", &big, 0o644)];

    for data in [build_zip(entries), build_tar(entries)] {
        let mut options = fixture.options(ArchiveLimits::default());
        options.temp_dir = Some(spill_dir.path().to_path_buf());
        options.inline_threshold = 1024;
        let tree = fixture.extract_with(&data, &options, 4096).await?;

        // Temp files are cleaned up once uploaded.
        assert_eq!(std::fs::read_dir(spill_dir.path()).unwrap().count(), 0);

        let root = fixture.read_directory(tree.root_digest).await;
        assert_eq!(root.files[0].name, "big");
        assert_eq!(fixture.read_file(root.files[0].digest.as_ref()).await, big);
        assert_eq!(
            fixture.read_file(root.files[1].digest.as_ref()).await,
            b"tiny"
        );

        // The result is independent of the threshold.
        let default = fixture.extract(&data, ArchiveLimits::default()).await?;
        assert_eq!(tree, default);
    }
    Ok(())
}

#[nativelink_test]
async fn inline_threshold_boundary() -> Result<(), Error> {
    let fixture = Fixture::new();
    // With a temp dir that doesn't exist, any file that needs a temp file
    // fails, which shows which side of the threshold a file falls on.
    let mut options = fixture.options(ArchiveLimits::default());
    options.temp_dir = Some(PathBuf::from("/nonexistent/archive-temp-dir"));
    options.inline_threshold = 100;

    let at_threshold = build_tar(&[("f", &[7u8; 100], 0o644)]);
    fixture.extract_with(&at_threshold, &options, 4096).await?;

    let over_threshold = build_tar(&[("f", &[7u8; 101], 0o644)]);
    let err = fixture
        .extract_with(&over_threshold, &options, 4096)
        .await
        .unwrap_err();
    assert!(err.message_string().contains("temp file"), "{err:?}");

    // A threshold of zero spills everything but an empty file.
    options.inline_threshold = 0;
    fixture
        .extract_with(&build_tar(&[("empty", b"", 0o644)]), &options, 4096)
        .await?;
    assert!(
        fixture
            .extract_with(&at_threshold, &options, 4096)
            .await
            .is_err()
    );
    Ok(())
}

#[nativelink_test]
async fn tar_duplicate_paths_last_wins() -> Result<(), Error> {
    let fixture = Fixture::new();
    let data = build_tar(&[("f", b"old", 0o644), ("f", b"new", 0o755)]);
    let tree = fixture.extract(&data, ArchiveLimits::default()).await?;
    let root = fixture.read_directory(tree.root_digest).await;
    assert_eq!(root.files.len(), 1);
    assert!(root.files[0].is_executable);
    assert_eq!(
        fixture.read_file(root.files[0].digest.as_ref()).await,
        b"new"
    );
    Ok(())
}

#[nativelink_test]
async fn garbage_is_rejected() {
    let fixture = Fixture::new();
    for data in [&b"not an archive"[..], b""] {
        let err = fixture
            .extract(data, ArchiveLimits::default())
            .await
            .unwrap_err();
        assert_eq!(err.code, Code::InvalidArgument);
    }
    // Right magic, wrong contents.
    for data in [&b"\x1f\x8bgarbage"[..], b"PK\x03\x04garbage"] {
        let err = fixture
            .extract(data, ArchiveLimits::default())
            .await
            .unwrap_err();
        assert_eq!(err.code, Code::InvalidArgument);
    }
}

#[nativelink_test]
async fn truncated_archives_are_rejected() {
    let fixture = Fixture::new();
    let tar_data = build_tar(SAMPLE);
    for data in [
        build_zip(SAMPLE),
        gzip(&tar_data),
        tar_data[..tar_data.len() - 1500].to_vec(),
    ] {
        let err = fixture
            .extract(&data[..data.len() - 30], ArchiveLimits::default())
            .await
            .unwrap_err();
        assert_eq!(err.code, Code::InvalidArgument);
    }
}

#[test]
fn sniffs_formats() {
    let tar_data = build_tar(SAMPLE);
    assert_eq!(
        ArchiveFormat::sniff(&build_zip(SAMPLE)),
        Some(ArchiveFormat::Zip)
    );
    assert_eq!(
        ArchiveFormat::sniff(b"PK\x05\x06rest"),
        Some(ArchiveFormat::Zip)
    );
    assert_eq!(
        ArchiveFormat::sniff(&gzip(&tar_data)),
        Some(ArchiveFormat::TarGz)
    );
    assert_eq!(ArchiveFormat::sniff(&tar_data), Some(ArchiveFormat::Tar));
    assert_eq!(ArchiveFormat::sniff(b"plain text"), None);
    assert_eq!(ArchiveFormat::sniff(b""), None);
}

#[nativelink_test]
async fn empty_zip_is_an_empty_directory() -> Result<(), Error> {
    let fixture = Fixture::new();
    let data = build_zip(&[]);
    assert!(data.starts_with(b"PK\x05\x06"));
    let tree = fixture.extract(&data, ArchiveLimits::default()).await?;
    let root = fixture.read_directory(tree.root_digest).await;
    assert_eq!(root, Directory::default());
    Ok(())
}

// ---- zip specifics ----

fn sample_raw_entries() -> Vec<RawEntry<'static>> {
    vec![
        RawEntry::new("hello.txt", b"hello"),
        RawEntry::new("bin/run.sh", b"#!/bin/sh\n").mode(0o100_755),
        RawEntry::new("bin/lib/inner.txt", b"inner"),
    ]
}

#[nativelink_test]
async fn raw_zip_matches_zip_crate() -> Result<(), Error> {
    let fixture = Fixture::new();
    let expected = fixture
        .extract(&build_zip(SAMPLE), ArchiveLimits::default())
        .await?;
    for zip64 in [false, true] {
        let data = raw_zip(&sample_raw_entries(), zip64);
        let tree = fixture.extract(&data, ArchiveLimits::default()).await?;
        assert_eq!(tree, expected, "zip64: {zip64}");
    }
    Ok(())
}

#[nativelink_test]
async fn deflated_entries_with_data_descriptors() -> Result<(), Error> {
    let fixture = Fixture::new();
    let expected = fixture
        .extract(&build_zip(SAMPLE), ArchiveLimits::default())
        .await?;
    for zip64 in [false, true] {
        let entries: Vec<_> = sample_raw_entries()
            .into_iter()
            .map(RawEntry::descriptor)
            .collect();
        let data = raw_zip(&entries, zip64);
        for chunk_size in [1, 13, 4096] {
            let tree = fixture
                .extract_with(
                    &data,
                    &fixture.options(ArchiveLimits::default()),
                    chunk_size,
                )
                .await?;
            assert_eq!(tree, expected, "zip64: {zip64}, chunk size {chunk_size}");
        }
    }

    // A zip written to a non-seekable stream by the `zip` crate.
    let mut writer = ZipWriter::new_stream(Cursor::new(Vec::new()));
    for (name, content, mode) in SAMPLE {
        writer
            .start_file(*name, SimpleFileOptions::default().unix_permissions(*mode))
            .unwrap();
        writer.write_all(content).unwrap();
    }
    let data = writer.finish().unwrap().into_inner().into_inner();
    let tree = fixture.extract(&data, ArchiveLimits::default()).await?;
    assert_eq!(tree, expected);
    Ok(())
}

#[nativelink_test]
async fn stored_entries_with_data_descriptors_are_read_from_a_spool() -> Result<(), Error> {
    let fixture = Fixture::new();
    let big: Vec<u8> = (0..100_000u32).map(|i| (i % 253) as u8).collect();
    let content: Vec<(&str, &[u8], u32)> = vec![
        ("a.txt", b"first", 0o644),
        ("b.bin", &big, 0o755),
        ("dir/c.txt", b"third", 0o644),
        ("dir/d.txt", b"fourth", 0o644),
    ];
    let expected = fixture
        .extract(&build_zip(&content), ArchiveLimits::default())
        .await?;

    // Every position of the stored entry with a descriptor: first, middle and
    // last, so that entries before it are streamed and those after are not.
    for stored_index in 0..content.len() {
        for zip64 in [false, true] {
            let entries: Vec<_> = content
                .iter()
                .enumerate()
                .map(|(i, (name, data, mode))| {
                    let entry = RawEntry::new(name, data).mode(0o100_000 | mode);
                    if i == stored_index {
                        entry.stored().descriptor()
                    } else {
                        entry
                    }
                })
                .collect();
            let data = raw_zip(&entries, zip64);
            let mut options = fixture.options(ArchiveLimits::default());
            options.inline_threshold = 1024;
            let tree = fixture.extract_with(&data, &options, 777).await?;
            assert_eq!(tree, expected, "index {stored_index}, zip64: {zip64}");
        }
    }

    // The limits and checks still apply to the entries read from the spool.
    let entries = [
        RawEntry::new("a", b"hello").stored().descriptor(),
        RawEntry::new("b", b"world").bad_crc().stored().descriptor(),
    ];
    let err = fixture
        .extract(&raw_zip(&entries, false), ArchiveLimits::default())
        .await
        .unwrap_err();
    assert_eq!(err.code, Code::InvalidArgument);
    let err = fixture
        .extract(
            &raw_zip(&entries[..1], false),
            ArchiveLimits {
                max_entries: None,
                max_total_uncompressed_bytes: Some(4),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, Code::ResourceExhausted);
    Ok(())
}

#[nativelink_test]
async fn stored_entry_with_data_descriptor_matches_central_directory() -> Result<(), Error> {
    // A symlink and an executable, whose modes only the central directory has,
    // are honored on the spooled path too.
    let fixture = Fixture::new();
    let entries = [
        RawEntry::new("tool", b"#!/bin/sh").mode(0o100_755),
        RawEntry::new("link", b"tool")
            .mode(0o120_777)
            .stored()
            .descriptor(),
    ];
    let tree = fixture
        .extract(&raw_zip(&entries, false), ArchiveLimits::default())
        .await?;
    let root = fixture.read_directory(tree.root_digest).await;
    assert_eq!(root.files.len(), 1);
    assert!(root.files[0].is_executable);
    assert_eq!(root.symlinks.len(), 1);
    assert_eq!(root.symlinks[0].target, "tool");
    Ok(())
}

#[nativelink_test]
async fn zip_modes_come_from_the_central_directory() -> Result<(), Error> {
    let fixture = Fixture::new();
    let entries = [
        RawEntry::new("tool", b"#!/bin/sh").mode(0o100_755),
        RawEntry::new("plain", b"data"),
        RawEntry::new("link", b"tool").mode(0o120_777),
    ];
    for zip64 in [false, true] {
        let tree = fixture
            .extract(&raw_zip(&entries, zip64), ArchiveLimits::default())
            .await?;
        let root = fixture.read_directory(tree.root_digest).await;
        let files: Vec<_> = root
            .files
            .iter()
            .map(|f| (f.name.as_str(), f.is_executable))
            .collect();
        assert_eq!(files, [("plain", false), ("tool", true)]);
        assert_eq!(root.symlinks.len(), 1);
        assert_eq!(root.symlinks[0].name, "link");
        assert_eq!(root.symlinks[0].target, "tool");
    }
    Ok(())
}

#[nativelink_test]
async fn zip_bad_crc_is_rejected() {
    let fixture = Fixture::new();
    for (deflated, descriptor) in [(true, false), (false, false), (true, true)] {
        let mut entry = RawEntry::new("f", b"content").bad_crc();
        entry.deflated = deflated;
        entry.descriptor = descriptor;
        let err = fixture
            .extract(&raw_zip(&[entry], false), ArchiveLimits::default())
            .await
            .unwrap_err();
        assert_eq!(err.code, Code::InvalidArgument);
        assert!(err.message_string().contains("CRC"), "{err:?}");
    }
}

#[nativelink_test]
async fn zip_central_directory_must_match_streamed_entries() {
    let fixture = Fixture::new();
    let good = raw_zip(&sample_raw_entries(), false);

    // An entry that precedes the archive proper, which a reader that starts at
    // the central directory never sees.
    let stub = {
        let zip = raw_zip(&[RawEntry::new("stub", b"hidden")], false);
        let central_start = zip
            .windows(4)
            .position(|w| w == b"PK\x01\x02")
            .expect("central directory");
        zip[..central_start].to_vec()
    };
    let mut prepended = stub.clone();
    prepended.extend_from_slice(&good);

    // An entry after the last one the central directory lists.
    let central_start = good
        .windows(4)
        .position(|w| w == b"PK\x01\x02")
        .expect("central directory");
    let mut appended = good[..central_start].to_vec();
    appended.extend_from_slice(&stub);
    appended.extend_from_slice(&good[central_start..]);

    // An entry listed twice.
    let duplicate = raw_zip(
        &[RawEntry::new("f", b"one"), RawEntry::new("f", b"two")],
        false,
    );

    // The central directory describes different content than was streamed.
    let mut mismatched = good.clone();
    let name_at = mismatched
        .windows(9)
        .rposition(|w| w == b"hello.txt")
        .unwrap();
    mismatched[name_at] = b'j';

    // Junk after the end of central directory record.
    let mut trailing = good.clone();
    trailing.extend_from_slice(b"extra");

    for (what, data) in [
        ("prepended", prepended),
        ("appended", appended),
        ("duplicate", duplicate),
        ("renamed", mismatched),
        ("trailing", trailing),
    ] {
        let err = fixture
            .extract(&data, ArchiveLimits::default())
            .await
            .expect_err(what);
        assert_eq!(err.code, Code::InvalidArgument, "{what}: {err:?}");
    }
}

#[nativelink_test]
async fn zip_unsupported_features_are_rejected() {
    let fixture = Fixture::new();
    let mut encrypted = raw_zip(&[RawEntry::new("f", b"x")], false);
    encrypted[6] |= 1; // general purpose flag: encrypted
    let mut unknown_method = raw_zip(&[RawEntry::new("f", b"x")], false);
    unknown_method[8] = 12; // bzip2
    for (what, data) in [("encrypted", encrypted), ("method", unknown_method)] {
        let err = fixture
            .extract(&data, ArchiveLimits::default())
            .await
            .expect_err(what);
        assert_eq!(err.code, Code::InvalidArgument, "{what}");
    }
}

#[nativelink_test]
async fn spool_handles_archives_larger_than_its_buffers() -> Result<(), Error> {
    let fixture = Fixture::new();
    // Incompressible, so the raw archive is a few MiB, past the point where
    // the spool file is written in the middle of an entry.
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let big: Vec<u8> = (0..3 * 1024 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            u8::try_from((state >> 24) & 0xff).unwrap()
        })
        .collect();
    let content: Vec<(&str, &[u8], u32)> = vec![
        ("big", &big, 0o644),
        ("small", b"x", 0o644),
        ("tail", &big[..1_500_000], 0o644),
    ];
    let expected = fixture
        .extract(&build_zip(&content), ArchiveLimits::default())
        .await?;
    let entries = [
        RawEntry::new("big", &big),
        RawEntry::new("small", b"x").stored().descriptor(),
        RawEntry::new("tail", &big[..1_500_000]),
    ];
    let tree = fixture
        .extract(&raw_zip(&entries, false), ArchiveLimits::default())
        .await?;
    assert_eq!(tree, expected);
    // The spool file is gone afterwards.
    assert_eq!(std::fs::read_dir(fixture.dir.path()).unwrap().count(), 0);
    Ok(())
}

/// Records what an [`ExpandHook`] is told, one line per call.
#[derive(Default)]
struct Recorder {
    lines: Vec<String>,
    content: Vec<u8>,
    held: Vec<Held>,
}

#[async_trait]
impl ExpandHook for Recorder {
    fn directory(&mut self, path: &[String]) {
        self.lines.push(format!("dir {}", path.join("/")));
    }

    fn begin_file(&mut self, path: &[String], meta: &FileMeta) {
        self.lines.push(format!(
            "file {} {:?} {:?}",
            path.join("/"),
            meta.size,
            meta.mode
        ));
        self.content.clear();
    }

    fn file_chunk(&mut self, chunk: &[u8]) {
        assert!(!chunk.is_empty());
        self.content.extend_from_slice(chunk);
    }

    async fn end_file(&mut self, digest: DigestInfo, held: &Held) -> Result<(), Error> {
        let kind = match held {
            Held::Inline(_) => "inline",
            Held::Spilled(_) => "spilled",
            Held::NotKept => "not kept",
        };
        self.lines.push(format!(
            "  {:?} {} {kind}",
            String::from_utf8_lossy(&self.content),
            digest.size_bytes()
        ));
        self.held.push(held.clone());
        Ok(())
    }

    fn symlink(&mut self, path: &[String], target: &str) {
        self.lines
            .push(format!("link {} -> {target}", path.join("/")));
    }

    fn hard_link(&mut self, path: &[String], digest: DigestInfo) {
        self.lines
            .push(format!("hard {} {}", path.join("/"), digest.size_bytes()));
    }

    fn needs_held(&self) -> bool {
        true
    }
}

impl Fixture {
    async fn record(
        &self,
        data: &[u8],
        options: &ArchiveOptions,
    ) -> Result<(ExtractedTree, Recorder), Error> {
        let mut recorder = Recorder::default();
        let mut reader = data;
        let tree =
            extract_archive(&mut reader, self.cas_store.as_pin(), options, &mut recorder).await?;
        Ok((tree, recorder))
    }
}

/// The leaves of `listing`, as `path kind` lines.
fn leaf_lines(listing: &Listing) -> Vec<String> {
    listing
        .leaves(listing.root())
        .into_iter()
        .map(|(path, entry)| match &entry.kind {
            Kind::File { digest, executable } => {
                format!("{path} {} x={executable}", digest.size_bytes())
            }
            Kind::Symlink { target } => format!("{path} -> {target}"),
            Kind::Dir(_) => format!("{path}/"),
        })
        .collect()
}

#[nativelink_test]
async fn hook_sees_tar_entries_in_archive_order() -> Result<(), Error> {
    let fixture = Fixture::new();
    let mut builder = tar::Builder::new(Vec::new());
    let mut dir = tar_header(0o755, 0);
    dir.set_entry_type(tar::EntryType::Directory);
    builder.append_data(&mut dir, "d/", io::empty()).unwrap();
    builder
        .append_data(&mut tar_header(0o755, 3), "d/x", &b"one"[..])
        .unwrap();
    let mut link = tar_header(0o777, 0);
    link.set_entry_type(tar::EntryType::Symlink);
    builder.append_link(&mut link, "l", "d/x").unwrap();
    let mut hard = tar_header(0o644, 0);
    hard.set_entry_type(tar::EntryType::Link);
    builder.append_link(&mut hard, "h", "d/x").unwrap();
    // A later entry for the same path replaces it.
    builder
        .append_data(&mut tar_header(0o644, 5), "d/x", &b"three"[..])
        .unwrap();
    let data = builder.into_inner().unwrap();

    let (tree, recorder) = fixture
        .record(&data, &fixture.options(ArchiveLimits::default()))
        .await?;
    assert_eq!(
        recorder.lines,
        [
            "dir d",
            "file d/x Exact(3) Known { executable: true }",
            "  \"one\" 3 inline",
            "link l -> d/x",
            "hard h 3",
            "file d/x Exact(5) Known { executable: false }",
            "  \"three\" 5 inline",
        ]
    );
    assert_eq!(
        leaf_lines(&tree.listing),
        ["d/x 5 x=false", "h 3 x=true", "l -> d/x"]
    );
    Ok(())
}

#[nativelink_test]
async fn hook_sees_zip_sizes_and_the_listing_has_the_modes() -> Result<(), Error> {
    let fixture = Fixture::new();
    let data = raw_zip(
        &[
            RawEntry::new("dir/", b"").stored().mode(0o040_755),
            RawEntry::new("dir/exact", b"exact").mode(0o100_755),
            RawEntry::new("hint", b"hinted")
                .descriptor()
                .sizes_in_header(),
            RawEntry::new("unknown", b"unknown").descriptor(),
            RawEntry::new("link", b"dir/exact").mode(0o120_777),
            // Read from the spool, where the central directory gives sizes.
            RawEntry::new("spooled", b"spooled").stored().descriptor(),
        ],
        false,
    );
    let (tree, recorder) = fixture
        .record(&data, &fixture.options(ArchiveLimits::default()))
        .await?;
    assert_eq!(
        recorder.lines,
        [
            "dir dir",
            "file dir/exact Exact(5) AtEnd",
            "  \"exact\" 5 inline",
            "file hint Hint(6) AtEnd",
            "  \"hinted\" 6 inline",
            "file unknown Unknown AtEnd",
            "  \"unknown\" 7 inline",
            "file link Exact(9) AtEnd",
            "  \"dir/exact\" 9 inline",
            "file spooled Exact(7) AtEnd",
            "  \"spooled\" 7 inline",
        ]
    );
    assert_eq!(
        leaf_lines(&tree.listing),
        [
            "dir/exact 5 x=true",
            "hint 6 x=false",
            "link -> dir/exact",
            "spooled 7 x=false",
            "unknown 7 x=false",
        ]
    );
    Ok(())
}

#[nativelink_test]
async fn held_bytes_outlive_the_expander_and_then_go() -> Result<(), Error> {
    let fixture = Fixture::new();
    let big: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    let data = build_tar(&[("small", b"tiny", 0o644), ("big", &big, 0o644)]);
    let mut options = fixture.options(ArchiveLimits::default());
    options.inline_threshold = 100;
    let (_, recorder) = fixture.record(&data, &options).await?;
    assert_eq!(recorder.lines[1], "  \"tiny\" 4 inline");
    assert!(recorder.lines[3].ends_with(" 10000 spilled"));
    for (held, expected) in recorder.held.iter().zip([&b"tiny"[..], &big]) {
        let mut read = Vec::new();
        held.read(&mut |chunk| read.extend_from_slice(chunk))
            .await?;
        assert!(read == expected, "held content differs");
    }
    // The spilled file is kept only while a clone of its handle is.
    assert_eq!(std::fs::read_dir(fixture.dir.path()).unwrap().count(), 1);
    drop(recorder);
    support::assert_temp_dir_is_empty(fixture.dir.path());
    Ok(())
}

#[nativelink_test]
async fn held_bytes_survive_a_cas_that_moves_spilled_files() -> Result<(), Error> {
    // A filesystem CAS takes a spilled file over by renaming it into place.
    let root = tempfile::tempdir().unwrap();
    let spill_dir = root.path().join("spill");
    std::fs::create_dir(&spill_dir).unwrap();
    let cas = Store::new(
        FilesystemStore::<FileEntryImpl>::new(&FilesystemSpec {
            content_path: root.path().join("content").to_string_lossy().into_owned(),
            temp_path: root.path().join("tmp").to_string_lossy().into_owned(),
            ..Default::default()
        })
        .await?,
    );
    let big: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    let data = build_tar(&[("big", &big, 0o644)]);
    let mut options = ArchiveOptions::new(DigestHasherFunc::Sha256);
    options.temp_dir = Some(spill_dir.clone());
    options.inline_threshold = 100;

    let mut recorder = Recorder::default();
    let mut reader = data.as_slice();
    extract_archive(&mut reader, cas.as_pin(), &options, &mut recorder).await?;
    let mut read = Vec::new();
    recorder.held[0]
        .read(&mut |chunk| read.extend_from_slice(chunk))
        .await?;
    assert!(read == big, "held content differs");
    drop(recorder);
    support::assert_temp_dir_is_empty(&spill_dir);

    // A hook that does not ask for the bytes does not get them kept.
    let mut reader = data.as_slice();
    extract_archive(&mut reader, cas.as_pin(), &options, &mut NoHook).await?;
    support::assert_temp_dir_is_empty(&spill_dir);
    Ok(())
}

#[nativelink_test]
async fn zip_symlink_targets_come_from_the_expanders_copy() -> Result<(), Error> {
    let store = Store::new(MemoryStore::new(&MemorySpec::default()));
    let dir = tempfile::tempdir().unwrap();
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .add_symlink("link", "some/target", SimpleFileOptions::default())
        .unwrap();
    let data = writer.finish().unwrap().into_inner();
    // Spilled or not, the target comes from the expander's own copy.
    for inline_threshold in [0, 1024] {
        let mut options = ArchiveOptions::new(DigestHasherFunc::Sha256);
        options.temp_dir = Some(dir.path().to_path_buf());
        options.inline_threshold = inline_threshold;
        let mut reader = data.as_slice();
        let tree = extract_archive(&mut reader, store.as_pin(), &options, &mut NoHook).await?;
        assert_eq!(leaf_lines(&tree.listing), ["link -> some/target"]);
    }
    support::assert_temp_dir_is_empty(dir.path());
    Ok(())
}

#[nativelink_test]
async fn listing_orders_and_finds_entries() -> Result<(), Error> {
    let fixture = Fixture::new();
    let data = build_tar(&[
        ("a/z", b"zz", 0o755),
        ("a-b", b"ab", 0o644),
        ("a.c/d", b"d", 0o644),
        ("b", b"b", 0o644),
    ]);
    let tree = fixture.extract(&data, ArchiveLimits::default()).await?;
    let listing = &tree.listing;
    let root = listing.dir(listing.root());
    // Bytewise by name.
    let names: Vec<&str> = root.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["a", "a-b", "a.c", "b"]);
    // Git compares the directory `a` as `a/`, after `a-b` and `a.c/`.
    let mut sorted: Vec<&ListingEntry> = root.entries.iter().collect();
    sorted.sort_by(|a, b| git_cmp(a, b));
    let sorted: Vec<&str> = sorted.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(sorted, ["a-b", "a.c", "a", "b"]);
    // Leaves come in full-path order.
    assert_eq!(
        leaf_lines(listing),
        [
            "a-b 2 x=false",
            "a.c/d 1 x=false",
            "a/z 2 x=true",
            "b 1 x=false"
        ]
    );
    assert!(matches!(
        listing.get(listing.root(), "a/z").map(|e| &e.kind),
        Some(Kind::File {
            executable: true,
            ..
        })
    ));
    assert!(listing.get(listing.root(), "a/y").is_none());
    assert!(listing.get(listing.root(), "b/c").is_none());
    assert_eq!(listing.only_subdir(listing.root()), None);

    let single = fixture
        .extract(
            &build_tar(&[("top/f", b"f", 0o644)]),
            ArchiveLimits::default(),
        )
        .await?;
    let (name, top) = single.listing.only_subdir(single.listing.root()).unwrap();
    assert_eq!(name, "top");
    assert_eq!(single.listing.dir(top).entries[0].name, "f");
    let file = fixture
        .extract(&build_tar(&[("f", b"f", 0o644)]), ArchiveLimits::default())
        .await?;
    assert_eq!(file.listing.only_subdir(file.listing.root()), None);
    Ok(())
}
