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

//! Checksums of the expanded contents of a fetched directory, as opposed to
//! the bytes of the archive it came in.
//!
//! Package managers record hashes like these in their lockfiles because they
//! survive a host re-packing its archives (a new gzip level, different zip
//! framing), which a hash of the archive bytes does not. Only `FetchDirectory`
//! can verify them, since only it expands the archive.
//!
//! Each format is a [`TreeHashFormat`], listed in [`TREE_HASH_FORMATS`]: the
//! qualifier that carries it, how to parse its values, and a constructor for
//! the [`TreeHash`] that computes it. Every format hashes during the archive
//! expander's single pass, as the bytes stream from the decompressor to the
//! CAS, and nothing is ever read back from the CAS. A [`TreeHashSet`] is the
//! expander's [`ExpandHook`]: it hands every entry, in archive order, to each
//! requested hash, which keeps what it needs (a per-file hash, keyed by
//! content digest) and combines it in [`TreeHash::finish`] with the
//! [`Listing`] of the finished tree, in the format's own order and with its
//! own rule for stripping a top-level directory. All the checksums a request
//! carries are computed in that one pass, and all of them must match.
//!
//! # Strip-root
//!
//! Many tools hash a source archive with its single top-level directory
//! removed: Nix's `fetchzip` and `fetchFromGitHub`, Zig, Stack, and git tree
//! ids taken from GitHub tarballs (`repo-<rev>/...`). A format that allows it
//! reports both values, and a checksum matches either. Accepting either is
//! safe because the match itself is the proof: the client gets the content its
//! hash describes, inside one extra directory level whose name is not covered
//! by the hash. The directory digest returned to the client is always the
//! unstripped root.

use core::fmt::{self, Write};
use core::hash::{Hash, Hasher};
use std::path::PathBuf;

use nativelink_error::{Code, Error, make_err, make_input_err};
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::DigestHasherFunc;
use sha2::{Digest, Sha256};
use tonic::async_trait;

use crate::archive_expander::{ExpandHook, FileMeta, Held, Listing};

pub mod git_tree;
pub mod h1;
pub mod nar;

/// Every supported tree-hash format.
pub static TREE_HASH_FORMATS: &[&dyn TreeHashFormat] = &[&h1::H1, &nar::Nar, &git_tree::GitTree];

/// Describes one tree-hash format. See the [module docs](self).
pub trait TreeHashFormat: Sync {
    /// The Remote Asset qualifier that carries the expected value, e.g.
    /// `checksum.nar`.
    fn qualifier(&self) -> &'static str;

    /// Validates a qualifier value and puts it in canonical notation, failing
    /// with `InvalidArgument` when it is malformed. Computed values use the
    /// same notation, so checking one is string equality.
    fn parse(&self, value: &str) -> Result<String, Error>;

    /// Starts hashing one tree for the canonical `expected` value, which fixes
    /// any parameters, such as the hash function of a git tree id.
    fn start(&self, expected: &str, context: &TreeHashContext) -> Box<dyn TreeHash>;
}

/// What a [`TreeHash`] may need to know about the fetch.
#[derive(Clone, Debug)]
pub struct TreeHashContext {
    /// The CAS digest function of the fetch.
    pub hasher_func: DigestHasherFunc,
    /// Where temp files go; the system temp dir if `None`.
    pub temp_dir: Option<PathBuf>,
}

/// A file that has been uploaded, as a [`TreeHash`] sees it.
#[derive(Clone, Copy, Debug)]
pub struct EndedFile<'a> {
    /// The content's CAS digest.
    pub digest: DigestInfo,
    /// The content's SHA-256, when the hash asked for it with
    /// [`TreeHash::needs_sha256`]. It is computed at most once per file for
    /// every hash in a set, and is free under a SHA-256 CAS.
    pub sha256: Option<[u8; 32]>,
    /// The bytes, which can be read again from memory or a local temp file.
    pub held: &'a Held,
}

/// Computes one tree hash, in two phases.
///
/// Phase 1 is the archive's entries, in archive order, as the expander
/// reports them to its [`ExpandHook`]. Results per file should be keyed by
/// content digest (or by path and digest when the path is hashed), never by
/// path alone: a path may repeat in a tar, and a hard link reuses content.
///
/// Phase 2 is [`finish`](Self::finish), which combines them over the
/// [`Listing`] in the format's order.
#[async_trait]
pub trait TreeHash: Send {
    /// Whether [`EndedFile::sha256`] should be given.
    fn needs_sha256(&self) -> bool {
        false
    }

    /// Whether [`EndedFile::held`] may be read or kept; see
    /// [`ExpandHook::needs_held`].
    fn needs_held(&self) -> bool {
        false
    }

    /// An explicit directory entry.
    fn directory(&mut self, _path: &[String]) {}

    /// A file starts. Returns whether this hash wants its content as
    /// [`file_chunk`](Self::file_chunk) calls.
    fn begin_file(&mut self, path: &[String], meta: &FileMeta) -> bool;

    /// The next piece of the current file's content, if it was wanted.
    fn file_chunk(&mut self, _chunk: &[u8]) {}

    /// The current file is complete.
    async fn end_file(&mut self, file: &EndedFile<'_>) -> Result<(), Error>;

    /// A tar symlink.
    fn symlink(&mut self, _path: &[String], _target: &str) {}

    /// A tar hard link to an earlier file whose content has `digest`.
    fn hard_link(&mut self, _path: &[String], _digest: DigestInfo) {}

    /// Combines everything into the values the tree may match.
    async fn finish(self: Box<Self>, listing: &Listing) -> Result<Computed, Error>;
}

/// What a [`TreeHash`] makes of a tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Computed {
    /// Every value the format would accept for the tree: the root's first,
    /// then any strip-root candidates. A checksum matches one of them, or it
    /// is a mismatch.
    Values(Vec<String>),
    /// The tree is not one the format hashes, e.g. not a Hex package; the
    /// reason. A mismatch.
    NotApplicable(String),
    /// The archive cannot be checked in one pass; the reason. Unlike a
    /// mismatch, it says nothing about the content.
    Unverifiable(String),
}

/// An expected tree hash: a format and the canonical value a request asked
/// for.
#[derive(Clone)]
pub struct TreeChecksum {
    format: &'static dyn TreeHashFormat,
    expected: String,
}

impl TreeChecksum {
    /// Parses `value`, the value of `format`'s qualifier. A malformed value
    /// is an `InvalidArgument` error naming the qualifier.
    pub fn parse(format: &'static dyn TreeHashFormat, value: &str) -> Result<Self, Error> {
        let expected = format.parse(value).map_err(|err| {
            make_input_err!(
                "Malformed qualifier '{}': {}",
                format.qualifier(),
                err.message_string()
            )
        })?;
        Ok(Self { format, expected })
    }

    pub fn format(&self) -> &'static dyn TreeHashFormat {
        self.format
    }

    pub fn qualifier(&self) -> &'static str {
        self.format.qualifier()
    }

    /// The expected value, in canonical notation.
    pub fn expected(&self) -> &str {
        &self.expected
    }

    /// Checks what the format computed against the expected value.
    pub fn check(&self, computed: Computed) -> Result<(), TreeHashFailure> {
        let qualifier = self.qualifier();
        let expected = &self.expected;
        match computed {
            Computed::Values(values) if values.iter().any(|value| value == expected) => Ok(()),
            Computed::Values(values) => {
                let mut values = values.into_iter();
                let root = values.next().unwrap_or_default();
                let stripped = values.fold(String::new(), |mut out, value| {
                    // Writing to a `String` cannot fail.
                    let _ = write!(out, " (its single top-level directory: '{value}')");
                    out
                });
                Err(TreeHashFailure::Mismatch(make_err!(
                    Code::Aborted,
                    "{qualifier} mismatch: expected '{expected}', got '{root}'{stripped}"
                )))
            }
            Computed::NotApplicable(reason) => Err(TreeHashFailure::Mismatch(make_err!(
                Code::Aborted,
                "{qualifier} mismatch: expected '{expected}', but {reason}"
            ))),
            Computed::Unverifiable(reason) => Err(TreeHashFailure::Unverifiable(make_err!(
                Code::FailedPrecondition,
                "{reason}; cannot verify {qualifier}"
            ))),
        }
    }
}

impl fmt::Debug for TreeChecksum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TreeChecksum")
            .field("qualifier", &self.qualifier())
            .field("expected", &self.expected)
            .finish()
    }
}

impl PartialEq for TreeChecksum {
    fn eq(&self, other: &Self) -> bool {
        self.qualifier() == other.qualifier() && self.expected == other.expected
    }
}

impl Eq for TreeChecksum {}

impl Hash for TreeChecksum {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.qualifier().hash(state);
        self.expected.hash(state);
    }
}

/// Why a tree did not verify.
#[derive(Debug)]
pub enum TreeHashFailure {
    /// The tree does not match a checksum (`Aborted`).
    Mismatch(Error),
    /// A checksum cannot be checked against this archive
    /// (`FailedPrecondition`). Another URI may serve one that can be.
    Unverifiable(Error),
    /// Computing a hash failed, e.g. reading a local temp file.
    Failed(Error),
}

/// Where a set gets each file's SHA-256 from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sha256Source {
    /// No hash in the set needs it.
    None,
    /// The CAS digest is the SHA-256.
    Digest,
    /// It is computed as the content streams past.
    Computed,
}

/// The requested tree hashes of one fetch, fed together in one pass as the
/// archive expander's [`ExpandHook`].
pub struct TreeHashSet {
    members: Vec<(TreeChecksum, Box<dyn TreeHash>)>,
    /// Which members want the current file's content.
    wants: Vec<bool>,
    sha256_source: Sha256Source,
    sha256: Option<Sha256>,
    needs_held: bool,
}

impl fmt::Debug for TreeHashSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.members.iter().map(|(checksum, _)| checksum))
            .finish()
    }
}

impl TreeHashSet {
    /// Starts a hash for each distinct checksum.
    pub fn new<'a>(
        checksums: impl IntoIterator<Item = &'a TreeChecksum>,
        context: &TreeHashContext,
    ) -> Self {
        let mut members: Vec<(TreeChecksum, Box<dyn TreeHash>)> = Vec::new();
        for checksum in checksums {
            if members.iter().any(|(seen, _)| seen == checksum) {
                continue;
            }
            let hash = checksum.format.start(&checksum.expected, context);
            members.push((checksum.clone(), hash));
        }
        let sha256_source = if !members.iter().any(|(_, hash)| hash.needs_sha256()) {
            Sha256Source::None
        } else if context.hasher_func == DigestHasherFunc::Sha256 {
            Sha256Source::Digest
        } else {
            Sha256Source::Computed
        };
        Self {
            needs_held: members.iter().any(|(_, hash)| hash.needs_held()),
            wants: vec![false; members.len()],
            members,
            sha256_source,
            sha256: None,
        }
    }

    /// The number of distinct checksums.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Finishes every hash over `listing`.
    pub async fn compute(self, listing: &Listing) -> Result<Vec<(TreeChecksum, Computed)>, Error> {
        let mut computed = Vec::with_capacity(self.members.len());
        for (checksum, hash) in self.members {
            let value = hash.finish(listing).await.map_err(|err| {
                err.append(format!("Computing {} of the tree", checksum.qualifier()))
            })?;
            computed.push((checksum, value));
        }
        Ok(computed)
    }

    /// Finishes every hash over `listing` and checks it. A mismatch of any
    /// checksum wins over one that cannot be checked.
    pub async fn finish(self, listing: &Listing) -> Result<(), TreeHashFailure> {
        let mut unverifiable = None;
        for (checksum, computed) in self
            .compute(listing)
            .await
            .map_err(TreeHashFailure::Failed)?
        {
            match checksum.check(computed) {
                Ok(()) => {}
                Err(TreeHashFailure::Unverifiable(err)) => {
                    unverifiable.get_or_insert(err);
                }
                Err(failure) => return Err(failure),
            }
        }
        unverifiable.map_or(Ok(()), |err| Err(TreeHashFailure::Unverifiable(err)))
    }
}

#[async_trait]
impl ExpandHook for TreeHashSet {
    fn directory(&mut self, path: &[String]) {
        for (_, hash) in &mut self.members {
            hash.directory(path);
        }
    }

    fn begin_file(&mut self, path: &[String], meta: &FileMeta) {
        for ((_, hash), wants) in self.members.iter_mut().zip(&mut self.wants) {
            *wants = hash.begin_file(path, meta);
        }
        if self.sha256_source == Sha256Source::Computed {
            self.sha256 = Some(Sha256::new());
        }
    }

    fn file_chunk(&mut self, chunk: &[u8]) {
        for ((_, hash), wants) in self.members.iter_mut().zip(&self.wants) {
            if *wants {
                hash.file_chunk(chunk);
            }
        }
        if let Some(sha256) = &mut self.sha256 {
            sha256.update(chunk);
        }
    }

    async fn end_file(&mut self, digest: DigestInfo, held: &Held) -> Result<(), Error> {
        let sha256 = match self.sha256_source {
            Sha256Source::None => None,
            Sha256Source::Digest => Some(**digest.packed_hash()),
            Sha256Source::Computed => self.sha256.take().map(|sha256| sha256.finalize().into()),
        };
        let file = EndedFile {
            digest,
            sha256,
            held,
        };
        for (_, hash) in &mut self.members {
            hash.end_file(&file).await?;
        }
        self.wants.fill(false);
        Ok(())
    }

    fn symlink(&mut self, path: &[String], target: &str) {
        for (_, hash) in &mut self.members {
            hash.symlink(path, target);
        }
    }

    fn hard_link(&mut self, path: &[String], digest: DigestInfo) {
        for (_, hash) in &mut self.members {
            hash.hard_link(path, digest);
        }
    }

    fn needs_held(&self) -> bool {
        self.needs_held
    }
}

/// Decodes hex digits in either case.
pub(crate) fn hex_decode(digits: &str) -> Option<Vec<u8>> {
    let digits = digits.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |c: u8| char::from(c).to_digit(16);
    digits
        .chunks_exact(2)
        .map(|pair| u8::try_from((nibble(pair[0])? << 4) | nibble(pair[1])?).ok())
        .collect()
}

/// Lower-case hex, as most formats print their values.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}
