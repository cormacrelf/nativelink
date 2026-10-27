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

//! Builds a REAPI [`Directory`] tree in a CAS from a zip, tar or tar.gz archive
//! read as a stream.
//!
//! The archive is never held or stored in full. Entries are read in the order
//! they appear in the stream and each file's content is uploaded to the CAS as
//! it arrives. Because the CAS needs a digest before an upload starts, content
//! is hashed as it is read: files up to a threshold are buffered in memory and
//! uploaded with `update_oneshot`, larger ones are written to a temp file and
//! uploaded with `update_with_whole_file`. Only when the end of the archive is
//! reached are the `Directory` protos built, so memory use is proportional to
//! the number of entries, not their size.
//!
//! Callers that check a hash of the expanded contents pass an
//! [`ExpandHook`], which sees every entry in archive order and every file's
//! content as it streams past, and get back a [`Listing`] of the finished
//! tree. The hook can keep a file's bytes after
//! upload through its [`Held`] handle, so nothing ever needs to be read back
//! from the CAS.
//!
//! Formats:
//! - tar is read with `astral-tokio-tar`, and tar.gz additionally goes through
//!   a multi-member gzip decoder.
//! - zip local file headers are parsed sequentially from the stream and
//!   deflated entries are decoded on the fly. Facts that only the central
//!   directory knows (unix modes, and so symlinks) are applied once it
//!   arrives, after the last entry. The central directory must match the
//!   streamed entries exactly (names, local header offsets, count, CRC and
//!   sizes), otherwise the archive is rejected, which defeats archives that
//!   hide content from sequential readers (prepended stubs, appended or
//!   updated entries). Zip64 is supported. A stored (uncompressed) entry
//!   followed by a data descriptor cannot be delimited in a stream, so on
//!   reaching one the rest of the archive is spooled to a temp file and
//!   processed from there using its central directory. To make that possible a
//!   zip is always copied to a temp file as it streams.
//!
//! Entry policy:
//! - Absolute paths and any `..` component are rejected (`InvalidArgument`);
//!   `.` components are ignored.
//! - The executable bit is set if any of the `0o111` mode bits are set.
//! - Symlinks (tar, and zip entries with a symlink unix mode) become
//!   `SymlinkNode`s. Targets are stored verbatim and not validated, which the
//!   REAPI permits.
//! - Tar hard links become regular file nodes referencing the target's content;
//!   a hard link to a path not yet seen in the archive is an error.
//! - Anything else (devices, fifos, ...) is skipped.
//! - If a path appears more than once in a tar the last entry wins. A zip with
//!   duplicate names is rejected.

use core::cmp::Ordering;
use core::pin::Pin;
use core::task::{Context, Poll, ready};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsString;
use std::io::{self, Cursor};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use async_compression::tokio::bufread::{DeflateDecoder, GzipDecoder};
use bytes::Bytes;
use futures::StreamExt;
use futures::future::{BoxFuture, FutureExt};
use nativelink_error::{Code, Error, ResultExt, make_err, make_input_err};
use nativelink_proto::build::bazel::remote::execution::v2::{
    Directory, DirectoryNode, FileNode, SymlinkNode,
};
use nativelink_store::ac_utils::serialize_and_upload_message;
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::{DigestHasher, DigestHasherFunc, DigestHasherImpl};
use nativelink_util::store_trait::{Store, StoreLike, UploadSizeInfo};
use nativelink_util::{fs, spawn_blocking};
use tempfile::{NamedTempFile, TempPath};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_tar::Archive;
use tonic::async_trait;
use tracing::trace;

use crate::spill::Spill;

/// Files up to this size are buffered in memory before upload; larger ones are
/// spilled to a temp file.
pub const DEFAULT_INLINE_THRESHOLD: u64 = 1024 * 1024;

/// Longest symlink target accepted from a zip entry (zip stores it as content).
const MAX_SYMLINK_TARGET: u64 = 4096;

/// Most bytes of the end of a zip (central directory plus end records) that are
/// held in memory.
const MAX_ZIP_TAIL: u64 = 256 * 1024 * 1024;

/// Buffered raw zip bytes are written to the spool file once this many have
/// accumulated.
const SPOOL_FLUSH_BYTES: usize = 1024 * 1024;

const SNIFF_LEN: usize = 512;
const TAR_MAGIC_OFFSET: usize = 257;
const ZIP_SYMLINK_MODE: u32 = 0o120_000;
const UNIX_FILE_TYPE_MASK: u32 = 0o170_000;

const ZIP_LOCAL_SIG: u32 = 0x0403_4b50;
const ZIP_CENTRAL_SIG: u32 = 0x0201_4b50;
const ZIP_EOCD_SIG: u32 = 0x0605_4b50;
const ZIP_EOCD64_SIG: u32 = 0x0606_4b50;
const ZIP_EOCD64_LOCATOR_SIG: u32 = 0x0706_4b50;
const ZIP_DATA_DESCRIPTOR_SIG: u32 = 0x0807_4b50;
const ZIP_EOCD_LEN: usize = 22;
const ZIP_EOCD64_LOCATOR_LEN: usize = 20;
const ZIP_CENTRAL_HEADER_LEN: usize = 46;
const ZIP64_EXTRA_ID: u16 = 0x0001;
const ZIP_FLAG_ENCRYPTED: u16 = 0x0001;
const ZIP_FLAG_DATA_DESCRIPTOR: u16 = 0x0008;
const ZIP_FLAG_STRONG_ENCRYPTION: u16 = 0x0040;
const ZIP_METHOD_STORED: u16 = 0;
const ZIP_METHOD_DEFLATED: u16 = 8;
const ZIP_HOST_UNIX: u16 = 3;

/// The supported archive formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    Tar,
    TarGz,
}

impl ArchiveFormat {
    /// Identifies the format from the first bytes of an archive (at least 262
    /// are needed to recognize a plain tar). A gzip stream is assumed to be a
    /// tar.gz; if it is not, extraction fails with `InvalidArgument`.
    pub fn sniff(head: &[u8]) -> Option<Self> {
        if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
            Some(Self::Zip)
        } else if head.starts_with(&[0x1f, 0x8b]) {
            Some(Self::TarGz)
        } else if head.get(TAR_MAGIC_OFFSET..TAR_MAGIC_OFFSET + 5) == Some(b"ustar".as_slice()) {
            Some(Self::Tar)
        } else {
            None
        }
    }
}

/// Upper bounds applied while extracting, to defend against archive bombs.
/// Sizes are counted from the bytes actually read, never from declared sizes.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArchiveLimits {
    pub max_entries: Option<usize>,
    pub max_total_uncompressed_bytes: Option<u64>,
}

/// How an archive is expanded.
#[derive(Clone, Debug)]
pub struct ArchiveOptions {
    /// Hash function for the CAS digests of file contents and `Directory`
    /// protos.
    pub hasher_func: DigestHasherFunc,
    pub limits: ArchiveLimits,
    /// Files up to this many bytes are buffered in memory before upload; larger
    /// ones are written to a temp file.
    pub inline_threshold: u64,
    /// Directory for temp files (the system temp dir if `None`).
    pub temp_dir: Option<PathBuf>,
}

impl ArchiveOptions {
    pub const fn new(hasher_func: DigestHasherFunc) -> Self {
        Self {
            hasher_func,
            limits: ArchiveLimits {
                max_entries: None,
                max_total_uncompressed_bytes: None,
            },
            inline_threshold: DEFAULT_INLINE_THRESHOLD,
            temp_dir: None,
        }
    }
}

/// The result of expanding an archive into the CAS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractedTree {
    /// Digest of the root `Directory` proto.
    pub root_digest: DigestInfo,
    /// The tree that was uploaded, without file content.
    pub listing: Listing,
}

/// What is known about a file's size when its content starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SizeInfo {
    /// The size the content will have; the expander fails the archive if it
    /// does not.
    Exact(u64),
    /// A size the entry's header gives but nothing checks until the content
    /// has been read: a zip entry with a data descriptor whose local header
    /// still records its size. A hook that relies on it must check it in
    /// [`ExpandHook::end_file`].
    Hint(u64),
    /// Not known until the content has been read.
    Unknown,
}

/// What is known about a file's mode when its content starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeInfo {
    /// A tar entry's mode is in its header.
    Known { executable: bool },
    /// A zip entry's mode is only in the central directory, at the end of the
    /// archive, and the entry may turn out to be a symlink whose target is
    /// its content. The [`Listing`] has the outcome.
    AtEnd,
}

/// What is known about a file entry when its content starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileMeta {
    /// Tar: exact, except for a sparse file. Zip without a data descriptor,
    /// or read from the spool: exact. Zip with a data descriptor: the local
    /// header's size as a hint, when it is nonzero.
    pub size: SizeInfo,
    pub mode: ModeInfo,
}

/// A file's bytes, still held by the expander after upload: in memory up to
/// the inline threshold, otherwise in a temp file. Cheap to clone; a clone
/// keeps the bytes after the expander moves on, and the temp file is removed
/// when the last clone is dropped.
///
/// A CAS may take a spilled file over by moving it into place, so the
/// expander keeps a hard link to it (or, where links fail, a copy), and only
/// when the hook asks for that with [`ExpandHook::needs_held`].
#[derive(Clone, Debug)]
#[expect(
    variant_size_differences,
    reason = "boxing the Bytes would cost an allocation per file, and a Held is passed by reference"
)]
pub enum Held {
    Inline(Bytes),
    Spilled(Arc<TempPath>),
    /// The bytes went to the CAS and were not kept, as the hook did not ask.
    NotKept,
}

impl Held {
    /// Streams the bytes again, from memory or the local temp file, never
    /// from the CAS.
    pub async fn read(&self, f: &mut (dyn FnMut(&[u8]) + Send)) -> Result<(), Error> {
        match self {
            Self::Inline(bytes) => {
                if !bytes.is_empty() {
                    f(bytes);
                }
                Ok(())
            }
            Self::Spilled(path) => {
                let mut file = fs::open_file(path.as_ref(), 0, u64::MAX)
                    .await
                    .err_tip(|| "Opening spilled archive entry")?;
                let mut buf = vec![0u8; fs::DEFAULT_READ_BUFF_SIZE];
                loop {
                    let n = file
                        .read(&mut buf)
                        .await
                        .err_tip(|| "Reading spilled archive entry")?;
                    if n == 0 {
                        return Ok(());
                    }
                    f(&buf[..n]);
                }
            }
            Self::NotKept => Err(make_err!(
                Code::Internal,
                "An archive entry's bytes were not kept after upload"
            )),
        }
    }
}

/// Keeps the spilled file at `path` past its upload, which may move it: a
/// hard link next to it, or a copy where that fails.
async fn keep_spilled(path: &Path) -> Result<TempPath, Error> {
    let path = path.to_path_buf();
    spawn_blocking!("archive_keep_spilled", move || {
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let builder = tempfile::Builder::new();
        builder
            .make_in(dir, |kept| std::fs::hard_link(&path, kept))
            .or_else(|_| builder.make_in(dir, |kept| std::fs::copy(&path, kept).map(drop)))
            .map(NamedTempFile::into_temp_path)
            .err_tip(|| "Keeping a spilled archive entry")
    })
    .await
    .err_tip(|| "Joining the task keeping a spilled archive entry")?
}

/// Sees an archive's entries in the order they appear, as they are expanded.
///
/// A path is an entry's components; they are never empty, `.` or `..`, and
/// contain no `/` or NUL. A file is [`begin_file`](Self::begin_file), its
/// content as [`file_chunk`](Self::file_chunk) calls of arbitrary size, then
/// [`end_file`](Self::end_file) once it is in the CAS. Paths may repeat in a
/// tar, where the last entry wins, so a hook that collects per-file results
/// should key them by content digest and take paths from the [`Listing`].
#[async_trait]
pub trait ExpandHook: Send {
    /// An explicit directory entry. Directories implied by other paths are
    /// not reported.
    fn directory(&mut self, _path: &[String]) {}

    /// A regular file starts. A zip symlink is reported as a file whose
    /// content is its target; see [`ModeInfo::AtEnd`].
    fn begin_file(&mut self, path: &[String], meta: &FileMeta);

    /// The next piece of the current file's content.
    fn file_chunk(&mut self, chunk: &[u8]);

    /// The current file is complete and uploaded as `digest`. `held` can be
    /// cloned to read the bytes again later, if [`needs_held`](Self::needs_held).
    async fn end_file(&mut self, digest: DigestInfo, held: &Held) -> Result<(), Error>;

    /// Whether [`end_file`](Self::end_file) may read or keep the bytes. If
    /// not, a spilled file is not kept past its upload and is
    /// [`Held::NotKept`].
    fn needs_held(&self) -> bool {
        false
    }

    /// A tar symlink. Zip symlinks are only in the [`Listing`].
    fn symlink(&mut self, _path: &[String], _target: &str) {}

    /// A tar hard link to an earlier file, whose content has `digest`.
    fn hard_link(&mut self, _path: &[String], _digest: DigestInfo) {}
}

/// An [`ExpandHook`] that does nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoHook;

#[async_trait]
impl ExpandHook for NoHook {
    fn begin_file(&mut self, _path: &[String], _meta: &FileMeta) {}

    fn file_chunk(&mut self, _chunk: &[u8]) {}

    async fn end_file(&mut self, _digest: DigestInfo, _held: &Held) -> Result<(), Error> {
        Ok(())
    }
}

/// The expanded tree as it was uploaded, without file content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listing {
    /// The root is first.
    dirs: Vec<Dir>,
}

/// A directory of a [`Listing`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DirId(u32);

/// One directory's entries of every kind, sorted bytewise by name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dir {
    pub entries: Vec<Entry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    File {
        digest: DigestInfo,
        executable: bool,
    },
    Symlink {
        target: String,
    },
    Dir(DirId),
}

impl Listing {
    pub const fn root(&self) -> DirId {
        DirId(0)
    }

    pub fn dir(&self, id: DirId) -> &Dir {
        &self.dirs[id.0 as usize]
    }

    /// The name and id of the only entry of `id`, if that is a directory: the
    /// candidate for formats that strip a single top-level directory.
    pub fn only_subdir(&self, id: DirId) -> Option<(&str, DirId)> {
        match self.dir(id).entries.as_slice() {
            [
                Entry {
                    name,
                    kind: Kind::Dir(sub),
                },
            ] => Some((name, *sub)),
            _ => None,
        }
    }

    /// The files and symlinks under `id`, with their paths below it joined by
    /// `/`, sorted bytewise by that path. That is the order of a depth-first
    /// walk with siblings in [`git_cmp`] order, so no path is sorted.
    pub fn leaves(&self, id: DirId) -> Vec<(String, &Entry)> {
        let mut out = Vec::new();
        self.collect_leaves(id, "", &mut out);
        out
    }

    fn collect_leaves<'a>(&'a self, id: DirId, prefix: &str, out: &mut Vec<(String, &'a Entry)>) {
        let mut entries: Vec<&Entry> = self.dir(id).entries.iter().collect();
        entries.sort_by(|a, b| git_cmp(a, b));
        for entry in entries {
            let path = if prefix.is_empty() {
                entry.name.clone()
            } else {
                format!("{prefix}/{}", entry.name)
            };
            match &entry.kind {
                Kind::Dir(sub) => self.collect_leaves(*sub, &path, out),
                Kind::File { .. } | Kind::Symlink { .. } => out.push((path, entry)),
            }
        }
    }

    /// The entry at `path`, components joined by `/`, below `id`.
    pub fn get(&self, id: DirId, path: &str) -> Option<&Entry> {
        let mut dir = id;
        let mut components = path.split('/').peekable();
        while let Some(name) = components.next() {
            let entries = &self.dir(dir).entries;
            let index = entries
                .binary_search_by(|entry| entry.name.as_str().cmp(name))
                .ok()?;
            let entry = &entries[index];
            if components.peek().is_none() {
                return Some(entry);
            }
            let Kind::Dir(sub) = entry.kind else {
                return None;
            };
            dir = sub;
        }
        None
    }

    /// Builds the listing of `root`.
    fn of(root: &DirBuilder) -> Self {
        let mut listing = Self { dirs: Vec::new() };
        listing.add(root);
        listing
    }

    fn add(&mut self, dir: &DirBuilder) -> DirId {
        let id = DirId(u32::try_from(self.dirs.len()).unwrap_or(u32::MAX));
        self.dirs.push(Dir::default());
        let mut entries =
            Vec::with_capacity(dir.files.len() + dir.symlinks.len() + dir.subdirs.len());
        for (name, &(digest, executable)) in &dir.files {
            entries.push(Entry {
                name: name.clone(),
                kind: Kind::File { digest, executable },
            });
        }
        for (name, target) in &dir.symlinks {
            entries.push(Entry {
                name: name.clone(),
                kind: Kind::Symlink {
                    target: target.clone(),
                },
            });
        }
        for (name, subdir) in &dir.subdirs {
            let sub = self.add(subdir);
            entries.push(Entry {
                name: name.clone(),
                kind: Kind::Dir(sub),
            });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        self.dirs[id.0 as usize].entries = entries;
        id
    }
}

/// Git's order of tree entries (`base_name_compare`): bytewise, with a
/// directory compared as if its name ended in `/`.
pub fn git_cmp(a: &Entry, b: &Entry) -> Ordering {
    git_key(a).cmp(git_key(b))
}

fn git_key(entry: &Entry) -> impl Iterator<Item = u8> + '_ {
    let slash = matches!(entry.kind, Kind::Dir(_)).then_some(b'/');
    entry.name.bytes().chain(slash)
}

/// Expands the archive read from `reader`, uploading every file's content and
/// each `Directory` proto to `cas_store`, and returns the root digest and the
/// listing. `hook` sees every entry as it is expanded.
///
/// The format is detected from the first bytes. The reader is always read to
/// its end on success, so a caller that checksums the raw bytes as they are
/// pulled from the source sees the whole archive. Returns `InvalidArgument`
/// for malformed archives or unsafe paths and `ResourceExhausted` if the
/// limits in `options` are exceeded. Errors from `reader` itself also surface
/// as `InvalidArgument`; a caller that needs to tell them apart should record
/// them at the source.
pub async fn extract_archive<R>(
    reader: &mut R,
    cas_store: Pin<&Store>,
    options: &ArchiveOptions,
    hook: &mut dyn ExpandHook,
) -> Result<ExtractedTree, Error>
where
    R: AsyncBufRead + Unpin + Send,
{
    // Peek at the start of the stream to identify the format, then put the
    // bytes back in front of the rest.
    let mut head = Vec::with_capacity(SNIFF_LEN);
    (&mut *reader)
        .take(SNIFF_LEN as u64)
        .read_to_end(&mut head)
        .await
        .map_err(|e| make_input_err!("Failed to read archive: {e}"))?;
    let format = ArchiveFormat::sniff(&head).ok_or_else(|| {
        make_input_err!("Unrecognized archive format (expected zip, tar or tar.gz)")
    })?;
    let mut stream = Cursor::new(head).chain(&mut *reader);

    let mut extractor = Extractor::new(cas_store, options, hook);
    match format {
        ArchiveFormat::Zip => extractor.extract_zip(&mut stream).await?,
        ArchiveFormat::Tar => extractor.extract_tar(&mut stream).await?,
        ArchiveFormat::TarGz => {
            let mut gzip = GzipDecoder::new(&mut stream);
            gzip.multiple_members(true);
            extractor.extract_tar(&mut gzip).await?;
            // Read the rest of the decompressed stream (tar padding) so the
            // gzip trailer's CRC is checked too.
            tokio::io::copy(&mut gzip, &mut tokio::io::sink())
                .await
                .map_err(|e| make_input_err!("Failed to decompress archive: {e}"))?;
        }
    }
    tokio::io::copy(&mut stream, &mut tokio::io::sink())
        .await
        .map_err(|e| make_input_err!("Failed to read archive: {e}"))?;
    extractor.finish().await
}

async fn upload_spilled(
    cas_store: Pin<&Store>,
    digest: DigestInfo,
    path: &TempPath,
) -> Result<(), Error> {
    let file = fs::open_file(path, 0, u64::MAX)
        .await
        .err_tip(|| "Opening spilled archive entry")?
        .into_inner();
    let path_os: OsString = path.as_os_str().to_owned();
    cas_store
        .update_with_whole_file(
            digest,
            path_os,
            file,
            UploadSizeInfo::ExactSize(digest.size_bytes()),
        )
        .await
        .err_tip(|| "Uploading spilled archive file content to CAS")?;
    Ok(())
}

/// Splits non-empty `components` into (file name, parent components).
const fn split_name(components: &[String]) -> (&str, &[String]) {
    let (name, parent) = components
        .split_last()
        .expect("components are non-empty, checked by the extractor");
    (name.as_str(), parent)
}

/// Receives a file's content chunk by chunk, hashing it and holding it either
/// in memory or in a temp file until the digest is known and it can be
/// uploaded.
struct FileSink {
    hasher: DigestHasherImpl,
    inline: Vec<u8>,
    spill: Option<(TempPath, fs::FileSlot)>,
    inline_threshold: u64,
    temp_dir: Option<PathBuf>,
}

impl FileSink {
    fn new(options: &ArchiveOptions) -> Self {
        Self {
            hasher: options.hasher_func.hasher(),
            inline: Vec::new(),
            spill: None,
            inline_threshold: options.inline_threshold,
            temp_dir: options.temp_dir.clone(),
        }
    }

    async fn write(&mut self, chunk: &[u8]) -> Result<(), Error> {
        self.hasher.update(chunk);
        if let Some((_, file)) = &mut self.spill {
            return file
                .write_all(chunk)
                .await
                .err_tip(|| "Writing archive entry to temp file");
        }
        self.inline.extend_from_slice(chunk);
        if self.inline.len() as u64 > self.inline_threshold {
            let temp = match &self.temp_dir {
                Some(dir) => NamedTempFile::new_in(dir),
                None => NamedTempFile::new(),
            }
            .err_tip(|| "Could not create temp file for archive entry")?
            .into_temp_path();
            let mut file = fs::create_file(&temp)
                .await
                .err_tip(|| "Could not open temp file for archive entry")?;
            file.write_all(&self.inline)
                .await
                .err_tip(|| "Writing archive entry to temp file")?;
            self.inline = Vec::new();
            self.spill = Some((temp, file));
        }
        Ok(())
    }

    /// Uploads the content to `cas_store`, and hands back its digest and the
    /// bytes, which are dropped (and a temp file removed) unless a hook keeps
    /// them. A spilled file is only kept if `keep`.
    async fn finish(
        mut self,
        cas_store: Pin<&Store>,
        keep: bool,
    ) -> Result<(DigestInfo, Held), Error> {
        let digest = self.hasher.finalize_digest();
        let held = if let Some((path, mut file)) = self.spill {
            file.flush()
                .await
                .err_tip(|| "Flushing archive entry temp file")?;
            drop(file);
            let kept = if keep {
                Some(keep_spilled(&path).await?)
            } else {
                None
            };
            upload_spilled(cas_store, digest, &path).await?;
            // Removes the file, unless the CAS moved it.
            drop(path);
            kept.map_or(Held::NotKept, |kept| Held::Spilled(Arc::new(kept)))
        } else {
            let bytes = Bytes::from(self.inline);
            cas_store
                .update_oneshot(digest, bytes.clone())
                .await
                .err_tip(|| "Uploading archive file content to CAS")?;
            Held::Inline(bytes)
        };
        Ok((digest, held))
    }
}

/// Expands an archive entry by entry, building up the tree in memory.
struct Extractor<'a> {
    cas_store: Pin<&'a Store>,
    options: &'a ArchiveOptions,
    hook: &'a mut dyn ExpandHook,
    entries: usize,
    total_bytes: u64,
    /// Extracted tar files by path, for hard links.
    stored: HashMap<Vec<String>, (DigestInfo, bool)>,
    /// The content of every zip entry small enough to be a symlink target,
    /// until the central directory says which ones are.
    maybe_symlinks: Spill,
    root: DirBuilder,
}

impl<'a> Extractor<'a> {
    fn new(
        cas_store: Pin<&'a Store>,
        options: &'a ArchiveOptions,
        hook: &'a mut dyn ExpandHook,
    ) -> Self {
        Self {
            cas_store,
            options,
            hook,
            entries: 0,
            total_bytes: 0,
            stored: HashMap::new(),
            maybe_symlinks: Spill::new(options.temp_dir.clone()),
            root: DirBuilder::default(),
        }
    }

    async fn finish(self) -> Result<ExtractedTree, Error> {
        let root_digest = upload_dir(&self.root, self.cas_store, self.options.hasher_func).await?;
        Ok(ExtractedTree {
            root_digest,
            listing: Listing::of(&self.root),
        })
    }

    fn count_entry(&mut self) -> Result<(), Error> {
        self.entries += 1;
        if let Some(max) = self.options.limits.max_entries
            && self.entries > max
        {
            // ResourceExhausted rather than InvalidArgument: the archive may be
            // well-formed, it just exceeds the operator-configured budget.
            return Err(make_err!(
                Code::ResourceExhausted,
                "Archive has more than {max} entries"
            ));
        }
        Ok(())
    }

    fn count_bytes(&mut self, n: usize) -> Result<(), Error> {
        self.total_bytes = self.total_bytes.saturating_add(n as u64);
        if let Some(max) = self.options.limits.max_total_uncompressed_bytes
            && self.total_bytes > max
        {
            return Err(make_err!(
                Code::ResourceExhausted,
                "Archive expands to more than {max} bytes"
            ));
        }
        Ok(())
    }

    /// Reads `reader` to its end, counting the bytes against the limits and
    /// handing them to `sink` and the hook (if there is a sink) and `crc` (if
    /// any). Returns the number of bytes read.
    async fn pump<D>(
        &mut self,
        name: &str,
        reader: &mut D,
        mut sink: Option<&mut FileSink>,
        mut crc: Option<&mut crc32fast::Hasher>,
    ) -> Result<u64, Error>
    where
        D: AsyncRead + Unpin + Send,
    {
        let mut buf = vec![0u8; fs::DEFAULT_READ_BUFF_SIZE];
        let mut total = 0u64;
        loop {
            let n = reader
                .read(&mut buf)
                .await
                .map_err(|e| make_input_err!("Failed to read archive entry '{name}': {e}"))?;
            if n == 0 {
                return Ok(total);
            }
            self.count_bytes(n)?;
            total += n as u64;
            let chunk = &buf[..n];
            if let Some(crc) = crc.as_deref_mut() {
                crc.update(chunk);
            }
            if let Some(sink) = sink.as_deref_mut() {
                sink.write(chunk).await?;
                self.hook.file_chunk(chunk);
            }
        }
    }

    /// Reads `reader` into the CAS.
    async fn store_file<D>(
        &mut self,
        components: &[String],
        meta: &FileMeta,
        reader: &mut D,
    ) -> Result<DigestInfo, Error>
    where
        D: AsyncRead + Unpin + Send,
    {
        self.hook.begin_file(components, meta);
        let mut sink = FileSink::new(self.options);
        self.pump(&components.join("/"), reader, Some(&mut sink), None)
            .await?;
        let (digest, held) = sink.finish(self.cas_store, self.hook.needs_held()).await?;
        self.hook.end_file(digest, &held).await?;
        Ok(digest)
    }

    fn add_file(&mut self, components: &[String], executable: bool, digest: DigestInfo) {
        let (name, parent) = split_name(components);
        self.root
            .dir_mut(parent)
            .insert_file(name, digest, executable);
    }

    fn add_symlink(&mut self, components: &[String], target: &[u8]) {
        let target = String::from_utf8_lossy(target).into_owned();
        let (name, parent) = split_name(components);
        self.root.dir_mut(parent).insert_symlink(name, target);
    }

    // ---- tar ----

    async fn extract_tar<R>(&mut self, reader: &mut R) -> Result<(), Error>
    where
        R: AsyncRead + Unpin + Send,
    {
        let mut archive = Archive::new(&mut *reader);
        let mut entries = archive
            .entries()
            .map_err(|e| make_input_err!("Failed to read tar archive: {e}"))?;
        while let Some(entry) = entries.next().await {
            let mut entry = entry.map_err(|e| make_input_err!("Failed to read tar entry: {e}"))?;
            let entry_path = entry
                .path()
                .map_err(|e| make_input_err!("Invalid tar entry path: {e}"))?
                .into_owned();
            let components = normalize_path(&entry_path)?;
            self.count_entry()?;
            if components.is_empty() {
                continue;
            }
            let entry_type = entry.header().entry_type();
            if entry_type.is_dir() {
                self.root.dir_mut(&components);
                self.hook.directory(&components);
            } else if entry_type.is_file()
                || entry_type.is_contiguous()
                || entry_type.is_gnu_sparse()
            {
                let mode = entry
                    .header()
                    .mode()
                    .map_err(|e| make_input_err!("Invalid tar entry mode: {e}"))?;
                let executable = mode & 0o111 != 0;
                // A sparse file's header holds the size of its stored
                // fragments, not of the file they expand to.
                let size = if entry_type.is_gnu_sparse() {
                    SizeInfo::Unknown
                } else {
                    SizeInfo::Exact(entry.effective_size())
                };
                let meta = FileMeta {
                    size,
                    mode: ModeInfo::Known { executable },
                };
                let digest = self.store_file(&components, &meta, &mut entry).await?;
                self.add_file(&components, executable, digest);
                self.stored.insert(components, (digest, executable));
            } else if entry_type.is_symlink() {
                let target = entry
                    .link_name_bytes()
                    .map_err(|e| make_input_err!("Invalid tar symlink target: {e}"))?
                    .ok_or_else(|| make_input_err!("Tar symlink {entry_path:?} has no target"))?
                    .into_owned();
                self.count_bytes(target.len())?;
                self.hook
                    .symlink(&components, &String::from_utf8_lossy(&target));
                self.add_symlink(&components, &target);
            } else if entry_type.is_hard_link() {
                let target = entry
                    .link_name()
                    .map_err(|e| make_input_err!("Invalid tar hard link target: {e}"))?
                    .ok_or_else(|| make_input_err!("Tar hard link {entry_path:?} has no target"))?
                    .into_owned();
                let target = normalize_path(&target)?;
                let (digest, executable) = *self.stored.get(&target).ok_or_else(|| {
                    make_input_err!(
                        "Tar hard link to '{}' which is not an earlier file entry",
                        target.join("/")
                    )
                })?;
                self.hook.hard_link(&components, digest);
                self.add_file(&components, executable, digest);
                self.stored.insert(components, (digest, executable));
            } else {
                trace!(path = ?entry_path, ?entry_type, "Skipping unsupported tar entry");
            }
        }
        Ok(())
    }

    // ---- zip ----

    async fn extract_zip<R>(&mut self, reader: &mut R) -> Result<(), Error>
    where
        R: AsyncRead + Unpin + Send,
    {
        let mut stream = ZipStream::new(reader, self.options.temp_dir.as_deref())?;
        let mut records: Vec<ZipRecord> = Vec::new();
        let tail = loop {
            let offset = stream.pos;
            let sig = u32::from_le_bytes(read_array(&mut stream, "header").await?);
            match sig {
                ZIP_LOCAL_SIG => {
                    if let Some(record) = self.zip_local_entry(&mut stream, offset).await? {
                        records.push(record);
                    } else {
                        let (records, central) =
                            self.zip_from_spool(&mut stream, records, offset).await?;
                        return self.zip_build(records, &central).await;
                    }
                }
                ZIP_CENTRAL_SIG | ZIP_EOCD_SIG | ZIP_EOCD64_SIG => {
                    let mut tail = sig.to_le_bytes().to_vec();
                    (&mut stream)
                        .take(MAX_ZIP_TAIL)
                        .read_to_end(&mut tail)
                        .await
                        .map_err(|e| {
                            make_input_err!("Failed to read zip central directory: {e}")
                        })?;
                    if !stream.fill().await?.is_empty() {
                        return Err(make_input_err!("Zip central directory is too large"));
                    }
                    break (offset, tail);
                }
                _ => {
                    return Err(make_input_err!(
                        "Unexpected data in zip archive at offset {offset} (signature {sig:#010x})"
                    ));
                }
            }
        };
        let (tail_offset, tail) = tail;
        let central = parse_central_directory(&tail, tail_offset)?;
        self.zip_build(records, &central).await
    }

    /// Reads one local file entry, whose signature has just been consumed from
    /// `stream` and began at `offset`. Returns `None` for a stored entry
    /// followed by a data descriptor, which cannot be read in a stream.
    async fn zip_local_entry<R>(
        &mut self,
        stream: &mut ZipStream<R>,
        offset: u64,
    ) -> Result<Option<ZipRecord>, Error>
    where
        R: AsyncRead + Unpin + Send,
    {
        let fixed: [u8; 26] = read_array(stream, "local header").await?;
        let flags = le16(&fixed, 2)?;
        let method = le16(&fixed, 4)?;
        let header_crc = le32(&fixed, 10)?;
        let packed_in_header = le32(&fixed, 14)?;
        let size_in_header = le32(&fixed, 18)?;
        let name_len = usize::from(le16(&fixed, 22)?);
        let extra_len = usize::from(le16(&fixed, 24)?);
        let mut name = vec![0u8; name_len];
        read_exact_into(stream, &mut name, "local header name").await?;
        let mut extra = vec![0u8; extra_len];
        read_exact_into(stream, &mut extra, "local header extra field").await?;

        if flags & (ZIP_FLAG_ENCRYPTED | ZIP_FLAG_STRONG_ENCRYPTION) != 0 {
            return Err(make_input_err!("Encrypted zip entries are not supported"));
        }
        let name_lossy = String::from_utf8_lossy(&name).into_owned();
        if method != ZIP_METHOD_STORED && method != ZIP_METHOD_DEFLATED {
            return Err(make_input_err!(
                "Zip entry '{name_lossy}' uses unsupported compression method {method}"
            ));
        }
        let has_descriptor = flags & ZIP_FLAG_DATA_DESCRIPTOR != 0;
        if has_descriptor && method == ZIP_METHOD_STORED {
            return Ok(None);
        }
        let components = zip_entry_components(&name, &name_lossy)?;
        self.count_entry()?;

        let zip64 = find_extra(&extra, ZIP64_EXTRA_ID);
        let mut zip64_fields = Zip64Fields(zip64.unwrap_or_default());
        let size = zip64_fields.take(size_in_header == u32::MAX, u64::from(size_in_header))?;
        let csize = zip64_fields.take(packed_in_header == u32::MAX, u64::from(packed_in_header))?;

        let is_dir = name.ends_with(b"/");
        let mut sink = (!is_dir && !components.is_empty()).then(|| FileSink::new(self.options));
        if sink.is_some() {
            // Without a data descriptor the header's size is checked against
            // the content below; with one, only the descriptor's is.
            let size = match (has_descriptor, size) {
                (false, size) => SizeInfo::Exact(size),
                (true, 0) => SizeInfo::Unknown,
                (true, size) => SizeInfo::Hint(size),
            };
            let meta = FileMeta {
                size,
                mode: ModeInfo::AtEnd,
            };
            self.hook.begin_file(&components, &meta);
        } else if is_dir && !components.is_empty() {
            self.hook.directory(&components);
        }
        let mut crc = crc32fast::Hasher::new();
        let data_start = stream.pos;
        let actual_size = match (method, has_descriptor) {
            (ZIP_METHOD_STORED, _) => {
                let mut limited = (&mut *stream).take(csize);
                let n = self
                    .pump(&name_lossy, &mut limited, sink.as_mut(), Some(&mut crc))
                    .await?;
                if n != csize {
                    return Err(make_input_err!("Zip entry '{name_lossy}' is truncated"));
                }
                n
            }
            (_, false) => {
                let mut decoder = DeflateDecoder::new((&mut *stream).take(csize));
                let n = self
                    .pump(&name_lossy, &mut decoder, sink.as_mut(), Some(&mut crc))
                    .await?;
                if decoder.into_inner().limit() != 0 {
                    return Err(make_input_err!(
                        "Zip entry '{name_lossy}' has trailing data after its compressed content"
                    ));
                }
                n
            }
            (_, true) => {
                let mut decoder = DeflateDecoder::new(&mut *stream);
                self.pump(&name_lossy, &mut decoder, sink.as_mut(), Some(&mut crc))
                    .await?
            }
        };
        let packed_read = stream.pos - data_start;
        let actual_crc = crc.finalize();

        let (crc_declared, packed_declared, size_declared) = if has_descriptor {
            let mut first = u32::from_le_bytes(read_array(stream, "data descriptor").await?);
            if first == ZIP_DATA_DESCRIPTOR_SIG {
                first = u32::from_le_bytes(read_array(stream, "data descriptor").await?);
            }
            let (csize, size) = if zip64.is_some() {
                let sizes: [u8; 16] = read_array(stream, "data descriptor").await?;
                (le64(&sizes, 0)?, le64(&sizes, 8)?)
            } else {
                let sizes: [u8; 8] = read_array(stream, "data descriptor").await?;
                (u64::from(le32(&sizes, 0)?), u64::from(le32(&sizes, 4)?))
            };
            (first, csize, size)
        } else {
            (header_crc, csize, size)
        };
        if crc_declared != actual_crc {
            return Err(make_input_err!("Zip entry '{name_lossy}' has a bad CRC-32"));
        }
        if size_declared != actual_size || packed_declared != packed_read {
            return Err(make_input_err!(
                "Zip entry '{name_lossy}' does not have the size it declares"
            ));
        }
        if is_dir && actual_size != 0 {
            return Err(make_input_err!(
                "Zip directory entry '{name_lossy}' has content"
            ));
        }
        let file = match sink {
            Some(sink) => Some(self.zip_finish_file(sink, actual_size).await?),
            None => None,
        };
        Ok(Some(ZipRecord {
            name,
            offset,
            method,
            crc: actual_crc,
            csize: packed_read,
            size: actual_size,
            components,
            file,
        }))
    }

    /// Fallback for a stored entry with a data descriptor: reads the rest of the
    /// archive into the spool file and then uses its central directory to find
    /// where entries start and end. Entries already streamed (all of those
    /// before `stop_offset`) are kept, not extracted again.
    async fn zip_from_spool<R>(
        &mut self,
        stream: &mut ZipStream<R>,
        records: Vec<ZipRecord>,
        stop_offset: u64,
    ) -> Result<(Vec<ZipRecord>, Vec<CentralEntry>), Error>
    where
        R: AsyncRead + Unpin + Send,
    {
        while !stream.fill().await?.is_empty() {
            let n = stream.buffered();
            stream.consume_buffered(n);
        }
        let spool_path = stream.finish_spool().await?;
        let central = {
            let path = spool_path.to_path_buf();
            spawn_blocking!("zip_central_directory", move || {
                list_central_directory(&path)
            })
            .await
            .err_tip(|| "Joining zip central directory task")??
        };

        let streamed = records.len();
        let mut by_offset: HashMap<u64, ZipRecord> =
            records.into_iter().map(|r| (r.offset, r)).collect();
        let mut out = Vec::with_capacity(central.len());
        let mut reused = 0;
        for entry in &central {
            if let Some(record) = by_offset.remove(&entry.offset) {
                reused += 1;
                out.push(record);
            } else if entry.offset < stop_offset {
                return Err(make_input_err!(
                    "Zip central directory entry '{}' does not match the streamed entries",
                    String::from_utf8_lossy(&entry.name)
                ));
            } else {
                out.push(self.zip_record_from_spool(spool_path, entry).await?);
            }
        }
        if reused != streamed {
            return Err(make_input_err!(
                "Zip central directory does not list every entry in the archive"
            ));
        }
        Ok((out, central))
    }

    /// Extracts the entry described by `entry` from the spool file.
    async fn zip_record_from_spool(
        &mut self,
        spool_path: &Path,
        entry: &CentralEntry,
    ) -> Result<ZipRecord, Error> {
        let name_lossy = String::from_utf8_lossy(&entry.name).into_owned();
        let components = zip_entry_components(&entry.name, &name_lossy)?;
        self.count_entry()?;
        let is_dir = entry.name.ends_with(b"/");
        let mut sink = (!is_dir && !components.is_empty()).then(|| FileSink::new(self.options));
        if sink.is_some() {
            let meta = FileMeta {
                size: SizeInfo::Exact(entry.size),
                mode: ModeInfo::AtEnd,
            };
            self.hook.begin_file(&components, &meta);
        } else if is_dir && !components.is_empty() {
            self.hook.directory(&components);
        }
        let mut crc = crc32fast::Hasher::new();
        let data_start = entry
            .data_start
            .ok_or_else(|| make_err!(Code::Internal, "Zip entry has no known data start"))?;
        let raw = fs::open_file(spool_path, data_start, entry.csize)
            .await
            .err_tip(|| "Opening zip spool file")?;
        let size = if entry.method == ZIP_METHOD_STORED {
            let mut raw = raw;
            self.pump(&name_lossy, &mut raw, sink.as_mut(), Some(&mut crc))
                .await?
        } else {
            let mut decoder = DeflateDecoder::new(tokio::io::BufReader::new(raw));
            self.pump(&name_lossy, &mut decoder, sink.as_mut(), Some(&mut crc))
                .await?
        };
        if crc.finalize() != entry.crc {
            return Err(make_input_err!("Zip entry '{name_lossy}' has a bad CRC-32"));
        }
        if size != entry.size {
            return Err(make_input_err!(
                "Zip entry '{name_lossy}' does not have the size it declares"
            ));
        }
        if is_dir && size != 0 {
            return Err(make_input_err!(
                "Zip directory entry '{name_lossy}' has content"
            ));
        }
        let file = match sink {
            Some(sink) => Some(self.zip_finish_file(sink, size).await?),
            None => None,
        };
        Ok(ZipRecord {
            name: entry.name.clone(),
            offset: entry.offset,
            method: entry.method,
            crc: entry.crc,
            csize: entry.csize,
            size,
            components,
            file,
        })
    }

    /// Uploads a zip entry's content and tells the hook. The bytes of an entry
    /// small enough to be a symlink are kept in a local spill, since only the
    /// central directory says whether it is one, and then they are its
    /// target. Memory holds an offset per content, not the bytes, however
    /// many small entries the archive has.
    async fn zip_finish_file(&mut self, sink: FileSink, size: u64) -> Result<ZipFile, Error> {
        let maybe_symlink = size <= MAX_SYMLINK_TARGET;
        let (digest, held) = sink
            .finish(self.cas_store, maybe_symlink || self.hook.needs_held())
            .await?;
        self.hook.end_file(digest, &held).await?;
        if maybe_symlink {
            self.maybe_symlinks.keep(digest, &held).await?;
        }
        Ok(ZipFile {
            digest,
            maybe_symlink,
        })
    }

    /// Checks the streamed `records` against the `central` directory entry by
    /// entry, then adds them to the tree.
    async fn zip_build(
        &mut self,
        records: Vec<ZipRecord>,
        central: &[CentralEntry],
    ) -> Result<(), Error> {
        if records.len() != central.len() {
            return Err(make_input_err!(
                "Zip central directory lists {} entries but the archive streams {}",
                central.len(),
                records.len()
            ));
        }
        for (record, entry) in records.iter().zip(central) {
            if record.name != entry.name
                || record.offset != entry.offset
                || record.method != entry.method
                || record.crc != entry.crc
                || record.csize != entry.csize
                || record.size != entry.size
            {
                return Err(make_input_err!(
                    "Zip central directory entry '{}' does not match the entry streamed at offset {}",
                    String::from_utf8_lossy(&entry.name),
                    record.offset
                ));
            }
        }
        let mut names = HashSet::new();
        for record in &records {
            if !names.insert(record.name.as_slice()) {
                return Err(make_input_err!(
                    "Zip archive has more than one entry named '{}'",
                    String::from_utf8_lossy(&record.name)
                ));
            }
        }
        let modes: Vec<Option<u32>> = central.iter().map(|e| e.mode).collect();
        self.zip_add_records(records, &modes).await
    }

    async fn zip_add_records(
        &mut self,
        records: Vec<ZipRecord>,
        modes: &[Option<u32>],
    ) -> Result<(), Error> {
        for (record, mode) in records.into_iter().zip(modes) {
            if record.components.is_empty() {
                continue;
            }
            let Some(file) = record.file else {
                self.root.dir_mut(&record.components);
                continue;
            };
            if mode.is_some_and(|m| m & UNIX_FILE_TYPE_MASK == ZIP_SYMLINK_MODE) {
                // The target is the entry's content, kept when it streamed
                // past.
                if !file.maybe_symlink {
                    return Err(make_input_err!("Zip symlink target is too long"));
                }
                let mut target = Vec::new();
                self.maybe_symlinks
                    .read(file.digest, &mut |chunk| target.extend_from_slice(chunk))
                    .await
                    .err_tip(|| "Reading zip symlink target")?;
                self.add_symlink(&record.components, &target);
                continue;
            }
            let executable = mode.is_some_and(|m| m & 0o111 != 0);
            self.add_file(&record.components, executable, file.digest);
        }
        Ok(())
    }
}

/// A zip entry read from the stream (or the spool), with its content uploaded.
struct ZipRecord {
    name: Vec<u8>,
    /// Offset of the local file header from the start of the archive.
    offset: u64,
    method: u16,
    crc: u32,
    csize: u64,
    size: u64,
    components: Vec<String>,
    /// `None` for a directory or an entry naming the root itself.
    file: Option<ZipFile>,
}

/// A zip entry's content, in the CAS.
struct ZipFile {
    digest: DigestInfo,
    /// Whether there are few enough bytes for a symlink target, in which case
    /// they are in the extractor's spill.
    maybe_symlink: bool,
}

/// An entry of a zip's central directory.
struct CentralEntry {
    name: Vec<u8>,
    offset: u64,
    method: u16,
    crc: u32,
    csize: u64,
    size: u64,
    /// Unix mode, when the archive was made on a unix host.
    mode: Option<u32>,
    /// Offset of the entry's data, when known (only read from a spool file).
    data_start: Option<u64>,
}

/// Normalizes a zip entry name and rejects unsafe ones.
fn zip_entry_components(name: &[u8], name_lossy: &str) -> Result<Vec<String>, Error> {
    if name.contains(&0) {
        return Err(make_input_err!(
            "Zip entry has an unsafe path: '{name_lossy}'"
        ));
    }
    normalize_path(Path::new(name_lossy))
}

fn le16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    bytes
        .get(offset..offset + 2)
        .and_then(|b| b.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| make_input_err!("Truncated zip record"))
}

fn le32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    bytes
        .get(offset..offset + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| make_input_err!("Truncated zip record"))
}

fn le64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    bytes
        .get(offset..offset + 8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| make_input_err!("Truncated zip record"))
}

/// Finds the body of the extra field with the given id.
fn find_extra(mut extra: &[u8], id: u16) -> Option<&[u8]> {
    while extra.len() >= 4 {
        let field_id = u16::from_le_bytes([extra[0], extra[1]]);
        let len = usize::from(u16::from_le_bytes([extra[2], extra[3]]));
        let body = extra.get(4..4 + len)?;
        if field_id == id {
            return Some(body);
        }
        extra = &extra[4 + len..];
    }
    None
}

/// The values of a zip64 extra field, which holds only those header fields
/// that overflowed (were set to all ones), in a fixed order.
struct Zip64Fields<'a>(&'a [u8]);

impl Zip64Fields<'_> {
    fn take(&mut self, needed: bool, header_value: u64) -> Result<u64, Error> {
        if !needed {
            return Ok(header_value);
        }
        let (value, rest) = self
            .0
            .split_first_chunk::<8>()
            .ok_or_else(|| make_input_err!("Zip header needs a zip64 extra field it lacks"))?;
        self.0 = rest;
        Ok(u64::from_le_bytes(*value))
    }
}

/// Parses the end of a zip, which starts at `tail_offset` in the archive and
/// must consist of exactly the central directory and the end-of-central-directory
/// records, with the latter agreeing about where the former is.
fn parse_central_directory(tail: &[u8], tail_offset: u64) -> Result<Vec<CentralEntry>, Error> {
    let mut entries = Vec::new();
    let mut pos = 0;
    while le32(tail, pos).ok() == Some(ZIP_CENTRAL_SIG) {
        let header = tail
            .get(pos..pos + ZIP_CENTRAL_HEADER_LEN)
            .ok_or_else(|| make_input_err!("Truncated zip central directory"))?;
        let made_by = le16(header, 4)?;
        let flags = le16(header, 8)?;
        let method = le16(header, 10)?;
        let crc = le32(header, 16)?;
        let csize = le32(header, 20)?;
        let size = le32(header, 24)?;
        let name_len = usize::from(le16(header, 28)?);
        let extra_len = usize::from(le16(header, 30)?);
        let comment_len = usize::from(le16(header, 32)?);
        let disk = le16(header, 34)?;
        let external_attrs = le32(header, 38)?;
        let offset = le32(header, 42)?;
        let variable = pos + ZIP_CENTRAL_HEADER_LEN;
        let name = tail
            .get(variable..variable + name_len)
            .ok_or_else(|| make_input_err!("Truncated zip central directory"))?;
        let extra = tail
            .get(variable + name_len..variable + name_len + extra_len)
            .ok_or_else(|| make_input_err!("Truncated zip central directory"))?;
        pos = variable + name_len + extra_len + comment_len;
        if pos > tail.len() {
            return Err(make_input_err!("Truncated zip central directory"));
        }
        if flags & (ZIP_FLAG_ENCRYPTED | ZIP_FLAG_STRONG_ENCRYPTION) != 0 {
            return Err(make_input_err!("Encrypted zip entries are not supported"));
        }
        let mut zip64 = Zip64Fields(find_extra(extra, ZIP64_EXTRA_ID).unwrap_or_default());
        let size = zip64.take(size == u32::MAX, u64::from(size))?;
        let csize = zip64.take(csize == u32::MAX, u64::from(csize))?;
        let offset = zip64.take(offset == u32::MAX, u64::from(offset))?;
        let disk = zip64.take(disk == u16::MAX, u64::from(disk))?;
        if disk != 0 {
            return Err(make_input_err!("Multi-disk zip archives are not supported"));
        }
        entries.push(CentralEntry {
            name: name.to_vec(),
            offset,
            method,
            crc,
            csize,
            size,
            mode: (made_by >> 8 == ZIP_HOST_UNIX).then_some(external_attrs >> 16),
            data_start: None,
        });
    }
    let central_len = pos as u64;

    // An optional zip64 end record and its locator, then the classic end
    // record, which must finish the archive.
    let mut zip64_end = None;
    if le32(tail, pos).ok() == Some(ZIP_EOCD64_SIG) {
        let record_len = usize::try_from(le64(tail, pos + 4)?)
            .map_err(|_| make_input_err!("Invalid zip64 end of central directory"))?;
        let record = tail
            .get(pos..pos + 12 + record_len)
            .ok_or_else(|| make_input_err!("Truncated zip64 end of central directory"))?;
        let disks = (le32(record, 16)?, le32(record, 20)?);
        zip64_end = Some((
            le64(record, 32)?,
            le64(record, 40)?,
            le64(record, 48)?,
            disks,
        ));
        pos += 12 + record_len;
        if tail.len() < pos + ZIP_EOCD64_LOCATOR_LEN
            || le32(tail, pos).ok() != Some(ZIP_EOCD64_LOCATOR_SIG)
        {
            return Err(make_input_err!(
                "Zip64 end of central directory has no locator"
            ));
        }
        pos += ZIP_EOCD64_LOCATOR_LEN;
    }
    if le32(tail, pos).ok() != Some(ZIP_EOCD_SIG) {
        return Err(make_input_err!(
            "Zip archive has unexpected data after its entries"
        ));
    }
    let eocd_comment_len = usize::from(le16(tail, pos + 20)?);
    if pos + ZIP_EOCD_LEN + eocd_comment_len != tail.len() {
        return Err(make_input_err!(
            "Zip archive has trailing data after its end of central directory"
        ));
    }
    let disks = (
        u32::from(le16(tail, pos + 4)?),
        u32::from(le16(tail, pos + 6)?),
    );
    let (count, cd_size, cd_offset, disks) = match zip64_end {
        Some((count, cd_size, cd_offset, disks64)) => {
            if disks64 != (0, 0) {
                return Err(make_input_err!("Multi-disk zip archives are not supported"));
            }
            (count, cd_size, cd_offset, disks)
        }
        None => (
            u64::from(le16(tail, pos + 10)?),
            u64::from(le32(tail, pos + 12)?),
            u64::from(le32(tail, pos + 16)?),
            disks,
        ),
    };
    if disks != (0, 0) {
        return Err(make_input_err!("Multi-disk zip archives are not supported"));
    }
    if count != entries.len() as u64 || cd_size != central_len || cd_offset != tail_offset {
        return Err(make_input_err!(
            "Zip end of central directory does not match the archive's entries"
        ));
    }
    Ok(entries)
}

/// Reads the central directory of the zip file at `path` with the `zip` crate,
/// including where each entry's data starts.
fn list_central_directory(path: &Path) -> Result<Vec<CentralEntry>, Error> {
    let file = std::fs::File::open(path).map_err(|e| {
        make_err!(
            Code::Internal,
            "Failed to open zip spool file {path:?}: {e}"
        )
    })?;
    let mut archive = zip::ZipArchive::new(io::BufReader::new(file))
        .map_err(|e| make_input_err!("Failed to read zip archive: {e}"))?;
    let mut entries = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        let entry = archive
            .by_index_raw(i)
            .map_err(|e| make_input_err!("Failed to read zip entry {i}: {e}"))?;
        let method = match entry.compression() {
            zip::CompressionMethod::Stored => ZIP_METHOD_STORED,
            zip::CompressionMethod::Deflated => ZIP_METHOD_DEFLATED,
            other => {
                return Err(make_input_err!(
                    "Zip entry uses unsupported compression method {other:?}"
                ));
            }
        };
        entries.push(CentralEntry {
            name: entry.name_raw().to_vec(),
            offset: entry.header_start(),
            method,
            crc: entry.crc32(),
            csize: entry.compressed_size(),
            size: entry.size(),
            mode: entry.unix_mode(),
            data_start: entry.data_start(),
        });
    }
    Ok(entries)
}

async fn read_exact_into<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    what: &str,
) -> Result<(), Error> {
    reader
        .read_exact(buf)
        .await
        .map(|_| ())
        .map_err(|e| make_input_err!("Failed to read zip {what}: {e}"))
}

async fn read_array<const N: usize, R: AsyncRead + Unpin>(
    reader: &mut R,
    what: &str,
) -> Result<[u8; N], Error> {
    let mut buf = [0u8; N];
    read_exact_into(reader, &mut buf, what).await?;
    Ok(buf)
}

/// A buffered reader over a zip stream that counts the bytes consumed, so entry
/// offsets are known, and optionally copies every consumed byte to a spool
/// file, so that the archive can be read again from the start.
struct ZipStream<R> {
    inner: R,
    buf: Box<[u8]>,
    start: usize,
    end: usize,
    /// Bytes consumed so far.
    pos: u64,
    spool: Option<Spool>,
}

struct Spool {
    path: TempPath,
    file: tokio::fs::File,
    /// Consumed bytes not yet handed to the file.
    pending: Vec<u8>,
    /// Bytes being written to the file, and how many are done.
    writing: Option<(Vec<u8>, usize)>,
}

impl<R: AsyncRead + Unpin> ZipStream<R> {
    fn new(inner: R, temp_dir: Option<&Path>) -> Result<Self, Error> {
        let (file, path) = match temp_dir {
            Some(dir) => NamedTempFile::new_in(dir),
            None => NamedTempFile::new(),
        }
        .err_tip(|| "Could not create spool file for zip archive")?
        .into_parts();
        Ok(Self {
            inner,
            buf: vec![0u8; fs::DEFAULT_READ_BUFF_SIZE].into_boxed_slice(),
            start: 0,
            end: 0,
            pos: 0,
            spool: Some(Spool {
                path,
                file: tokio::fs::File::from_std(file),
                pending: Vec::new(),
                writing: None,
            }),
        })
    }

    const fn buffered(&self) -> usize {
        self.end - self.start
    }

    fn consume_buffered(&mut self, amt: usize) {
        let amt = amt.min(self.buffered());
        if let Some(spool) = &mut self.spool {
            spool
                .pending
                .extend_from_slice(&self.buf[self.start..self.start + amt]);
        }
        self.start += amt;
        self.pos += amt as u64;
    }

    /// Drives writing buffered bytes to the spool file: those that have
    /// accumulated enough to be worth it, or all of them if `all`.
    fn poll_spool(&mut self, cx: &mut Context<'_>, all: bool) -> Poll<io::Result<()>> {
        let Some(spool) = &mut self.spool else {
            return Poll::Ready(Ok(()));
        };
        loop {
            if let Some((data, written)) = &mut spool.writing {
                let n = ready!(Pin::new(&mut spool.file).poll_write(cx, &data[*written..]))?;
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                *written += n;
                if *written == data.len() {
                    spool.writing = None;
                }
            } else if spool.pending.len() >= SPOOL_FLUSH_BYTES || (all && !spool.pending.is_empty())
            {
                spool.writing = Some((core::mem::take(&mut spool.pending), 0));
            } else {
                if all {
                    ready!(Pin::new(&mut spool.file).poll_flush(cx))?;
                }
                return Poll::Ready(Ok(()));
            }
        }
    }

    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        if self.start >= self.end {
            ready!(self.poll_spool(cx, false))?;
            let mut read_buf = ReadBuf::new(&mut self.buf);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read_buf))?;
            self.start = 0;
            self.end = read_buf.filled().len();
        }
        Poll::Ready(Ok(&self.buf[self.start..self.end]))
    }

    async fn fill(&mut self) -> Result<&[u8], Error> {
        // Poll once to fill, then borrow the buffer outside the poll.
        core::future::poll_fn(|cx| self.poll_fill(cx).map_ok(|_| ()))
            .await
            .map_err(|e| make_input_err!("Failed to read zip archive: {e}"))?;
        Ok(&self.buf[self.start..self.end])
    }

    /// Writes out everything consumed and returns the spool file's path. After
    /// this the stream no longer spools.
    async fn finish_spool(&mut self) -> Result<&Path, Error> {
        core::future::poll_fn(|cx| self.poll_spool(cx, true))
            .await
            .err_tip(|| "Writing zip spool file")?;
        let spool = self
            .spool
            .as_ref()
            .ok_or_else(|| make_err!(Code::Internal, "Zip spool file already finished"))?;
        Ok(&spool.path)
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ZipStream<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let available = ready!(this.poll_fill(cx))?;
        let n = available.len().min(out.remaining());
        out.put_slice(&available[..n]);
        this.consume_buffered(n);
        Poll::Ready(Ok(()))
    }
}

impl<R: AsyncRead + Unpin> AsyncBufRead for ZipStream<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        self.get_mut().poll_fill(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.get_mut().consume_buffered(amt);
    }
}

/// Converts an archive path to its components, ignoring `.` and rejecting
/// anything absolute or containing `..`. An empty result means the root itself.
fn normalize_path(path: &Path) -> Result<Vec<String>, Error> {
    let mut out = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => out.push(name.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(make_input_err!(
                    "Archive entry has an unsafe path: {path:?}"
                ));
            }
        }
    }
    Ok(out)
}

/// An intermediate, mutable representation of a directory tree built up while
/// walking the (flat) list of archive entries. All maps are keyed by name so
/// iteration yields REAPI's required sorted order and later entries replace
/// earlier ones.
#[derive(Default)]
struct DirBuilder {
    /// Each file's digest and executable bit.
    files: BTreeMap<String, (DigestInfo, bool)>,
    /// Each symlink's target.
    symlinks: BTreeMap<String, String>,
    subdirs: BTreeMap<String, Self>,
}

impl DirBuilder {
    /// Returns (creating if necessary) the descendant directory identified by
    /// the given path components, relative to `self`. A file or symlink in the
    /// way is replaced by the directory.
    fn dir_mut(&mut self, components: &[String]) -> &mut Self {
        let mut current = self;
        for component in components {
            current.files.remove(component);
            current.symlinks.remove(component);
            current = current.subdirs.entry(component.clone()).or_default();
        }
        current
    }

    fn insert_file(&mut self, name: &str, digest: DigestInfo, executable: bool) {
        self.symlinks.remove(name);
        self.subdirs.remove(name);
        self.files.insert(name.to_string(), (digest, executable));
    }

    fn insert_symlink(&mut self, name: &str, target: String) {
        self.files.remove(name);
        self.subdirs.remove(name);
        self.symlinks.insert(name.to_string(), target);
    }
}

/// Recursively serializes a [`DirBuilder`] into REAPI [`Directory`] protos,
/// uploading each to `cas_store` bottom-up, and returns the digest of `dir`.
fn upload_dir<'a>(
    dir: &'a DirBuilder,
    cas_store: Pin<&'a Store>,
    hasher_func: DigestHasherFunc,
) -> BoxFuture<'a, Result<DigestInfo, Error>> {
    async move {
        let mut directories = Vec::with_capacity(dir.subdirs.len());
        for (name, subdir) in &dir.subdirs {
            let digest = upload_dir(subdir, cas_store, hasher_func).await?;
            directories.push(DirectoryNode {
                name: name.clone(),
                digest: Some(digest.into()),
            });
        }

        let directory = Directory {
            files: dir
                .files
                .iter()
                .map(|(name, &(digest, executable))| FileNode {
                    name: name.clone(),
                    digest: Some(digest.into()),
                    is_executable: executable,
                    node_properties: None,
                })
                .collect(),
            directories,
            symlinks: dir
                .symlinks
                .iter()
                .map(|(name, target)| SymlinkNode {
                    name: name.clone(),
                    target: target.clone(),
                    node_properties: None,
                })
                .collect(),
            node_properties: None,
        };

        let mut hasher = hasher_func.hasher();
        serialize_and_upload_message(&directory, cas_store, &mut hasher)
            .await
            .err_tip(|| "Uploading Directory proto to CAS")
    }
    .boxed()
}
