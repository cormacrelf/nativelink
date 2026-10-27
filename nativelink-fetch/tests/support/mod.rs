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

//! Archives and a CAS for the tree-hash tests. Every test crate uses a
//! different part of this.
#![allow(dead_code, unreachable_pub, reason = "shared by several test crates")]

use std::io::{Cursor, Write};
use std::path::Path;

use flate2::Compression;
use flate2::write::{DeflateEncoder, GzEncoder};
use nativelink_config::stores::MemorySpec;
use nativelink_error::Error;
use nativelink_fetch::archive_expander::{ArchiveOptions, extract_archive};
use nativelink_fetch::tree_hash::{
    Computed, TreeChecksum, TreeHashContext, TreeHashFailure, TreeHashFormat, TreeHashSet,
};
use nativelink_store::memory_store::MemoryStore;
use nativelink_util::digest_hasher::DigestHasherFunc;
use nativelink_util::store_trait::{Store, StoreLike};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

/// One entry of [`tar`].
#[derive(Clone, Copy, Debug)]
pub enum TarEntry<'a> {
    /// A regular file: path, content, mode.
    File(&'a str, &'a [u8], u32),
    Dir(&'a str),
    /// A symlink: path, target.
    Link(&'a str, &'a str),
    /// A hard link: path, target.
    Hard(&'a str, &'a str),
}

/// A tar of `entries`, in the order given.
pub fn tar(entries: &[TarEntry<'_>]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for entry in entries {
        let mut header = tar::Header::new_gnu();
        match *entry {
            TarEntry::File(name, content, mode) => {
                header.set_mode(mode);
                header.set_size(content.len() as u64);
                header.set_entry_type(tar::EntryType::Regular);
                builder.append_data(&mut header, name, content).unwrap();
            }
            TarEntry::Dir(name) => {
                header.set_mode(0o755);
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Directory);
                builder
                    .append_data(&mut header, name, std::io::empty())
                    .unwrap();
            }
            TarEntry::Link(name, target) => {
                header.set_mode(0o777);
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Symlink);
                builder.append_link(&mut header, name, target).unwrap();
            }
            TarEntry::Hard(name, target) => {
                header.set_mode(0o644);
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Link);
                builder.append_link(&mut header, name, target).unwrap();
            }
        }
    }
    builder.into_inner().unwrap()
}

/// `entries` as files under `prefix`, with directories as `name/` entries.
pub fn tar_under(prefix: &str, entries: &[TarEntry<'_>]) -> Vec<u8> {
    let owned: Vec<(String, TarEntry<'_>)> = entries
        .iter()
        .map(|entry| {
            let name = match entry {
                TarEntry::File(name, ..)
                | TarEntry::Dir(name)
                | TarEntry::Link(name, _)
                | TarEntry::Hard(name, _) => format!("{prefix}{name}"),
            };
            (name, *entry)
        })
        .collect();
    let renamed: Vec<TarEntry<'_>> = owned
        .iter()
        .map(|(name, entry)| match *entry {
            TarEntry::File(_, content, mode) => TarEntry::File(name, content, mode),
            TarEntry::Dir(_) => TarEntry::Dir(name),
            TarEntry::Link(_, target) => TarEntry::Link(name, target),
            TarEntry::Hard(_, target) => TarEntry::Hard(name, target),
        })
        .collect();
    tar(&renamed)
}

pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// One entry of [`zip`].
#[derive(Clone, Copy, Debug)]
pub enum ZipEntry<'a> {
    /// A file: path, content, unix mode.
    File(&'a str, &'a [u8], u32),
    Dir(&'a str),
    /// A symlink: path, target.
    Link(&'a str, &'a str),
}

/// A zip of `entries`, written by the `zip` crate.
pub fn zip(entries: &[ZipEntry<'_>]) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for entry in entries {
        match *entry {
            ZipEntry::File(name, content, mode) => {
                let options = SimpleFileOptions::default().unix_permissions(mode);
                writer.start_file(name, options).unwrap();
                writer.write_all(content).unwrap();
            }
            ZipEntry::Dir(name) => {
                writer
                    .add_directory(name, SimpleFileOptions::default())
                    .unwrap();
            }
            ZipEntry::Link(name, target) => {
                writer
                    .add_symlink(name, target, SimpleFileOptions::default())
                    .unwrap();
            }
        }
    }
    writer.finish().unwrap().into_inner()
}

/// A zip of deflated files whose CRC and sizes are only in data descriptors
/// after their data, as streaming zip writers produce them: the local
/// headers say 0.
pub fn zip_with_data_descriptors(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, content) in entries {
        let offset = u32::try_from(out.len()).unwrap();
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(content).unwrap();
        let body = encoder.finish().unwrap();
        let crc = crc32fast::hash(content);
        let size = u32::try_from(content.len()).unwrap();
        let csize = u32::try_from(body.len()).unwrap();
        let name_len = u16::try_from(name.len()).unwrap();

        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes()); // data descriptor
        out.extend_from_slice(&8u16.to_le_bytes()); // deflated
        out.extend_from_slice(&[0; 4]); // time, date
        out.extend_from_slice(&[0; 12]); // CRC and sizes
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&0x0807_4b50u32.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&csize.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&((3u16 << 8) | 0x14).to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&8u16.to_le_bytes());
        central.extend_from_slice(&8u16.to_le_bytes());
        central.extend_from_slice(&[0; 4]);
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&csize.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&name_len.to_le_bytes());
        central.extend_from_slice(&[0; 6]); // extra, comment, disk
        central.extend_from_slice(&[0; 2]); // internal attributes
        central.extend_from_slice(&(0o100_644u32 << 16).to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let central_offset = u32::try_from(out.len()).unwrap();
    let count = u16::try_from(entries.len()).unwrap();
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&u32::try_from(central.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&[0; 2]);
    out
}

/// How [`hash_archive`] runs.
#[derive(Clone, Copy, Debug)]
pub struct Run {
    pub hasher_func: DigestHasherFunc,
    pub inline_threshold: Option<u64>,
}

impl Default for Run {
    fn default() -> Self {
        Self {
            hasher_func: DigestHasherFunc::Sha256,
            inline_threshold: None,
        }
    }
}

/// Expands `archive` once, computing every checksum in `checksums` in the
/// same pass, and returns what each format computed. Checks that no temp
/// file outlives the run.
pub async fn compute_with(
    archive: &[u8],
    checksums: &[(&'static dyn TreeHashFormat, &str)],
    run: Run,
) -> Result<Vec<Computed>, Error> {
    let temp_dir = tempfile::tempdir().unwrap();
    let parsed: Vec<TreeChecksum> = checksums
        .iter()
        .map(|(format, value)| TreeChecksum::parse(*format, value))
        .collect::<Result<_, _>>()?;
    let store = Store::new(MemoryStore::new(&MemorySpec::default()));
    let result = expand(archive, &store, temp_dir.path(), &parsed, run).await;
    assert_temp_dir_is_empty(temp_dir.path());
    result
}

async fn expand(
    archive: &[u8],
    store: &Store,
    temp_dir: &Path,
    checksums: &[TreeChecksum],
    run: Run,
) -> Result<Vec<Computed>, Error> {
    let mut options = ArchiveOptions::new(run.hasher_func);
    options.temp_dir = Some(temp_dir.to_path_buf());
    if let Some(threshold) = run.inline_threshold {
        options.inline_threshold = threshold;
    }
    let context = TreeHashContext {
        hasher_func: run.hasher_func,
        temp_dir: Some(temp_dir.to_path_buf()),
    };
    let mut set = TreeHashSet::new(checksums, &context);
    let mut reader = archive;
    let tree = extract_archive(&mut reader, store.as_pin(), &options, &mut set).await?;
    let computed = set.compute(&tree.listing).await?;
    Ok(computed.into_iter().map(|(_, computed)| computed).collect())
}

pub async fn compute(
    archive: &[u8],
    format: &'static dyn TreeHashFormat,
    expected: &str,
) -> Result<Computed, Error> {
    let mut computed = compute_with(archive, &[(format, expected)], Run::default()).await?;
    Ok(computed.remove(0))
}

/// The values `format` computes for `archive`, which must be some.
pub async fn values(archive: &[u8], format: &'static dyn TreeHashFormat, any: &str) -> Vec<String> {
    match compute(archive, format, any).await.unwrap() {
        Computed::Values(values) => values,
        other => panic!("expected values, got {other:?}"),
    }
}

/// Expands `archive` once and checks it against all of `checksums`.
pub async fn verify_with(
    archive: &[u8],
    checksums: &[(&'static dyn TreeHashFormat, &str)],
    run: Run,
) -> Result<(), TreeHashFailure> {
    let temp_dir = tempfile::tempdir().unwrap();
    let parsed: Vec<TreeChecksum> = checksums
        .iter()
        .map(|(format, value)| TreeChecksum::parse(*format, value))
        .collect::<Result<_, _>>()
        .map_err(TreeHashFailure::Failed)?;
    let store = Store::new(MemoryStore::new(&MemorySpec::default()));
    let mut options = ArchiveOptions::new(run.hasher_func);
    options.temp_dir = Some(temp_dir.path().to_path_buf());
    if let Some(threshold) = run.inline_threshold {
        options.inline_threshold = threshold;
    }
    let context = TreeHashContext {
        hasher_func: run.hasher_func,
        temp_dir: Some(temp_dir.path().to_path_buf()),
    };
    let mut set = TreeHashSet::new(&parsed, &context);
    let mut reader = archive;
    let tree = extract_archive(&mut reader, store.as_pin(), &options, &mut set)
        .await
        .map_err(TreeHashFailure::Failed)?;
    let result = set.finish(&tree.listing).await;
    assert_temp_dir_is_empty(temp_dir.path());
    result
}

pub async fn verify(
    archive: &[u8],
    format: &'static dyn TreeHashFormat,
    expected: &str,
) -> Result<(), TreeHashFailure> {
    verify_with(archive, &[(format, expected)], Run::default()).await
}

pub fn assert_temp_dir_is_empty(dir: &Path) {
    let left: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert!(left.is_empty(), "temp files left behind: {left:?}");
}

/// Asserts that `result` is a mismatch, and returns its message.
pub fn expect_mismatch(result: Result<(), TreeHashFailure>) -> String {
    match result {
        Err(TreeHashFailure::Mismatch(err)) => {
            assert_eq!(err.code, nativelink_error::Code::Aborted);
            err.message_string()
        }
        other => panic!("expected a mismatch, got {other:?}"),
    }
}

/// Asserts that `result` is unverifiable, and returns its message.
pub fn expect_unverifiable(result: Result<(), TreeHashFailure>) -> String {
    match result {
        Err(TreeHashFailure::Unverifiable(err)) => {
            assert_eq!(err.code, nativelink_error::Code::FailedPrecondition);
            err.message_string()
        }
        other => panic!("expected unverifiable, got {other:?}"),
    }
}
