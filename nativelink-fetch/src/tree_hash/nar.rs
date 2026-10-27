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

//! The Nix NAR hash: the SHA-256 of a tree's Nix archive serialisation, as
//! `nix hash path` prints it and as `flake.lock` (`narHash`) and nixpkgs
//! fixed-output derivations (`hash =`, or the older `sha256 =`) record it.
//!
//! The serialisation follows the Nix manual's "Nix Archive (NAR) format" and
//! `SourceAccessor::dumpPath` in Nix's `src/libutil/archive.cc`:
//!
//! ```text
//! nar           = str("nix-archive-1"), nar-obj
//! nar-obj       = str("("), nar-obj-inner, str(")")
//! nar-obj-inner = str("type"), str("regular"), [str("executable"), str("")],
//!                     str("contents"), str(contents)
//!               | str("type"), str("symlink"), str("target"), str(target)
//!               | str("type"), str("directory"), { entry }
//! entry         = str("entry"), str("("), str("name"), str(name),
//!                     str("node"), nar-obj, str(")")
//! str(s)        = u64-le(len(s)), s, zero padding to a multiple of 8 bytes
//! ```
//!
//! A directory's entries are sorted by name, bytewise. Nix's `parse()` in the
//! same file insists on it: each name must be strictly greater than the one
//! before, on raw bytes, so a repeated name is out of order too.
//!
//! # One pass, and a replay
//!
//! The archive is written as a NAR in archive order, straight into SHA-256,
//! while its entries stream past. That works for as long as the entries come
//! in NAR order, which tools that walk a sorted tree produce. When one does
//! not (a sibling that sorts lower, a directory entered again, a repeated
//! path, a hard link, a file whose size is not known before its content, or
//! a zip entry that turns out to be executable or a symlink), the streamed
//! hash is dropped. `git archive` gets there for any directory `P` beside a
//! sibling named `P` plus a byte below `/`, such as `foo.rs` beside `foo/`,
//! since git sorts a directory as if its name ended in `/`.
//!
//! So that such an archive can still be checked, every file's bytes are kept
//! on local disk during the fetch, never in memory and
//! never read from the CAS. The NAR is then written again from the
//! [`Listing`] of the expanded tree, in NAR order, reading content from that
//! spill. An archive that was in order is never read back.
//!
//! # Strip-root
//!
//! `fetchzip` and `fetchFromGitHub` hash an archive without its single
//! top-level directory, so when the root holds only a directory, a value also
//! matches that directory's NAR hash. Both are computed in the same pass.

use core::mem;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use nativelink_error::{Code, Error, make_err, make_input_err};
use nativelink_util::common::DigestInfo;
use sha2::{Digest, Sha256};
use tonic::async_trait;
use tracing::debug;

use super::{Computed, EndedFile, TreeHash, TreeHashContext, TreeHashFormat, hex_decode};
use crate::archive_expander::{DirId, FileMeta, Kind, Listing, ModeInfo, SizeInfo};
use crate::spill::Spill;

/// The Remote Asset qualifier carrying a NAR hash.
pub const QUALIFIER_CHECKSUM_NAR: &str = "checksum.nar";

const SHA256_LEN: usize = 32;

/// Nix's base-32 alphabet: digits and lowercase letters without `e`, `o`, `u`
/// and `t` (`BaseNix32::characters` in Nix).
const NIX32_ALPHABET: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// Length of a SHA-256 hash in Nix base-32.
const NIX32_SHA256_LEN: usize = (SHA256_LEN * 8 - 1) / 5 + 1;

/// The NAR hash format.
#[derive(Clone, Copy, Debug)]
pub struct Nar;

impl TreeHashFormat for Nar {
    fn qualifier(&self) -> &'static str {
        QUALIFIER_CHECKSUM_NAR
    }

    /// The canonical notation is SRI, as current Nix prints it.
    fn parse(&self, value: &str) -> Result<String, Error> {
        parse_nar_hash(value).map(|hash| sri(&hash))
    }

    fn start(&self, _expected: &str, context: &TreeHashContext) -> Box<dyn TreeHash> {
        Box::new(NarHash {
            fast: Some(Fast {
                root: Stream::new(),
                stripped: Strip::Undecided,
            }),
            modes_at_end: false,
            file: None,
            spill: Spill::new(context.temp_dir.clone()),
        })
    }
}

/// Parses a SHA-256 NAR hash written in any of the notations Nix itself
/// prints:
/// - SRI, `sha256-<base64>`;
/// - Nix base-32, `sha256:<52 chars>` or the bare 52 characters;
/// - hexadecimal, `sha256:<64 hex digits>` or the bare 64 digits.
pub fn parse_nar_hash(value: &str) -> Result<Vec<u8>, Error> {
    if let Some(base64) = value.strip_prefix("sha256-") {
        let hash = BASE64_STANDARD
            .decode(base64)
            .map_err(|e| make_input_err!("Invalid base64 in NAR hash '{value}': {e}"))?;
        if hash.len() != SHA256_LEN {
            return Err(make_input_err!("NAR hash '{value}' is not a SHA-256 hash"));
        }
        return Ok(hash);
    }
    let digits = value.strip_prefix("sha256:").unwrap_or(value);
    let hash = match digits.len() {
        NIX32_SHA256_LEN => nix32_decode(digits),
        len if len == SHA256_LEN * 2 => hex_decode(digits),
        _ => None,
    };
    hash.ok_or_else(|| {
        make_input_err!(
            "Invalid NAR hash '{value}': expected sha256-<base64>, or a SHA-256 in Nix base-32 or hex, optionally prefixed with sha256:"
        )
    })
}

/// A hash in SRI notation, as current Nix prints it.
fn sri(hash: &[u8]) -> String {
    format!("sha256-{}", BASE64_STANDARD.encode(hash))
}

/// Encodes `bytes` in Nix base-32 (`BaseNix32::encode`). It is not RFC 4648:
/// the first character holds the most significant bits of the *last* byte.
pub fn nix32_encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let len = (bytes.len() * 8 - 1) / 5 + 1;
    (0..len)
        .rev()
        .map(|n| {
            let bit = n * 5;
            let (i, j) = (bit / 8, bit % 8);
            let low = usize::from(bytes[i]) >> j;
            let high = bytes.get(i + 1).map_or(0, |&b| usize::from(b) << (8 - j));
            char::from(NIX32_ALPHABET[(low | high) & 0x1f])
        })
        .collect()
}

/// Decodes a SHA-256 hash from Nix base-32 (`BaseNix32::decode`), rejecting
/// anything that is not exactly 32 bytes.
fn nix32_decode(digits: &str) -> Option<Vec<u8>> {
    let mut out = vec![0u8; SHA256_LEN];
    for (n, c) in digits.bytes().rev().enumerate() {
        let digit = NIX32_ALPHABET.iter().position(|&a| a == c)?;
        let bit = n * 5;
        let (i, j) = (bit / 8, bit % 8);
        let [low, high, ..] = (digit << j).to_le_bytes();
        *out.get_mut(i)? |= low;
        // Bits that spill past the last byte make the value too long.
        if high != 0 {
            *out.get_mut(i + 1)? |= high;
        }
    }
    Some(out)
}

/// Writes NAR tokens into SHA-256: one hash, or, for strip-root, the root's
/// and the top-level directory's at once.
struct Writer {
    root: Sha256,
    /// The top-level directory's, and whether writes reach it.
    inner: Option<(Sha256, bool)>,
}

impl Writer {
    fn new(inner: bool) -> Self {
        Self {
            root: Sha256::new(),
            inner: inner.then(|| (Sha256::new(), false)),
        }
    }

    fn raw(&mut self, bytes: &[u8]) {
        self.root.update(bytes);
        if let Some((inner, true)) = &mut self.inner {
            inner.update(bytes);
        }
    }

    fn padding(&mut self, len: u64) {
        let rem = usize::from(len.to_le_bytes()[0] & 7);
        if rem != 0 {
            self.raw(&[0u8; 8][rem..]);
        }
    }

    fn int(&mut self, n: u64) {
        self.raw(&n.to_le_bytes());
    }

    /// `str(s)`: length, bytes, padding.
    fn str(&mut self, s: &[u8]) {
        self.int(s.len() as u64);
        self.raw(s);
        self.padding(s.len() as u64);
    }

    fn strs(&mut self, tokens: &[&[u8]]) {
        for token in tokens {
            self.str(token);
        }
    }

    /// `entry ( name <name> node`.
    fn entry(&mut self, name: &str) {
        self.strs(&[b"entry", b"(", b"name", name.as_bytes(), b"node"]);
    }

    /// `( type regular [executable ""] contents <size>`, before the content.
    fn regular(&mut self, executable: bool, size: u64) {
        self.strs(&[b"(", b"type", b"regular"]);
        if executable {
            self.strs(&[b"executable", b""]);
        }
        self.str(b"contents");
        self.int(size);
    }

    /// `( type symlink target <target> )`.
    fn symlink(&mut self, target: &str) {
        self.strs(&[
            b"(",
            b"type",
            b"symlink",
            b"target",
            target.as_bytes(),
            b")",
        ]);
    }

    fn finish(self) -> (String, Option<String>) {
        (
            sri(&self.root.finalize()),
            self.inner.map(|(inner, _)| sri(&inner.finalize())),
        )
    }
}

/// One directory open in a [`Stream`].
struct Level {
    name: String,
    /// The last entry written in it.
    last: Option<String>,
}

/// A NAR written in archive order, for as long as the archive is in NAR
/// order.
struct Stream {
    out: Writer,
    /// The directories open, the root first.
    open: Vec<Level>,
}

impl Stream {
    fn new() -> Self {
        let mut out = Writer::new(false);
        out.strs(&[b"nix-archive-1", b"(", b"type", b"directory"]);
        Self {
            out,
            open: vec![Level {
                name: String::new(),
                last: None,
            }],
        }
    }

    /// Positions the stream at the entry `path`, a directory or else a leaf,
    /// closing the directories it is not in and opening those it is. A
    /// leaf's `entry ( name <name> node` is written, and its object must
    /// follow. Fails when `path` is not in NAR order after what came before.
    fn enter(&mut self, path: &[String], is_dir: bool) -> Result<(), String> {
        let dirs = if is_dir { path.len() } else { path.len() - 1 };
        let mut depth = 0;
        while depth < dirs
            && depth + 1 < self.open.len()
            && self.open[depth + 1].name == path[depth]
        {
            depth += 1;
        }
        if is_dir && depth == path.len() {
            // A directory already open, e.g. named after its first child.
            return Ok(());
        }
        while self.open.len() > depth + 1 {
            self.open.pop();
            self.out.strs(&[b")", b")"]);
        }
        for (i, name) in path.iter().enumerate().skip(depth) {
            let level = self
                .open
                .last_mut()
                .ok_or_else(|| "the root was closed".to_owned())?;
            if let Some(last) = &level.last
                && name.as_bytes() <= last.as_bytes()
            {
                let parent: String = path[..i].iter().flat_map(|c| [c.as_str(), "/"]).collect();
                return Err(format!(
                    "'{}{}' after '{parent}{last}'",
                    path[..=i].join("/"),
                    if i < dirs { "/" } else { "" },
                ));
            }
            level.last = Some(name.clone());
            self.out.entry(name);
            if i < dirs {
                self.out.strs(&[b"(", b"type", b"directory"]);
                self.open.push(Level {
                    name: name.clone(),
                    last: None,
                });
            }
        }
        Ok(())
    }

    fn finish(mut self) -> String {
        while self.open.len() > 1 {
            self.open.pop();
            self.out.strs(&[b")", b")"]);
        }
        self.out.str(b")");
        self.out.finish().0
    }
}

/// The NAR of the root's single top-level directory, written as it streams.
enum Strip {
    /// Nothing has been seen yet.
    Undecided,
    /// Everything so far is under this directory.
    Under(String, Box<Stream>),
    /// Something is not.
    No,
}

/// The NARs written in archive order.
struct Fast {
    root: Stream,
    stripped: Strip,
}

impl Fast {
    /// Enters `path` in both streams, then lets `leaf` write the leaf's
    /// object into each.
    fn entry(
        &mut self,
        path: &[String],
        is_dir: bool,
        leaf: impl Fn(&mut Writer),
    ) -> Result<(), String> {
        self.root.enter(path, is_dir)?;
        if !is_dir {
            leaf(&mut self.root.out);
        }
        self.stripped = match mem::replace(&mut self.stripped, Strip::No) {
            Strip::Undecided if is_dir || path.len() > 1 => {
                let mut inner = Stream::new();
                inner.enter(&path[1..], is_dir)?;
                if !is_dir {
                    leaf(&mut inner.out);
                }
                Strip::Under(path[0].clone(), Box::new(inner))
            }
            Strip::Under(top, mut inner) if path[0] == top && (is_dir || path.len() > 1) => {
                inner.enter(&path[1..], is_dir)?;
                if !is_dir {
                    leaf(&mut inner.out);
                }
                Strip::Under(top, inner)
            }
            _ => Strip::No,
        };
        Ok(())
    }

    fn content(&mut self, chunk: &[u8]) {
        self.root.out.raw(chunk);
        if let Strip::Under(_, inner) = &mut self.stripped {
            inner.out.raw(chunk);
        }
    }

    fn end_regular(&mut self, size: u64) {
        for out in self.outs() {
            out.padding(size);
            out.strs(&[b")", b")"]);
        }
    }

    fn outs(&mut self) -> impl Iterator<Item = &mut Writer> {
        let inner = match &mut self.stripped {
            Strip::Under(_, inner) => Some(&mut inner.out),
            Strip::Undecided | Strip::No => None,
        };
        core::iter::once(&mut self.root.out).chain(inner)
    }
}

/// Computes a NAR hash in archive order while that works, keeping every
/// file's bytes in a local spill for when it does not.
struct NarHash {
    /// `None` once the archive is known not to be in NAR order.
    fast: Option<Fast>,
    /// A file's mode was not known while it streamed (a zip).
    modes_at_end: bool,
    /// The current file's declared size and the bytes seen.
    file: Option<(u64, u64)>,
    spill: Spill,
}

impl NarHash {
    fn abandon(&mut self, reason: &str) {
        if self.fast.take().is_some() {
            debug!(
                reason,
                "Archive entries are not in NAR order; the NAR hash will be computed again from the expanded tree"
            );
        }
    }

    /// Runs `step` on the streams, abandoning them if it fails.
    fn step(&mut self, step: impl FnOnce(&mut Fast) -> Result<(), String>) {
        if let Some(fast) = &mut self.fast
            && let Err(reason) = step(fast)
        {
            self.abandon(&reason);
        }
    }

    /// Writes the NAR of the expanded tree from `listing`, reading file
    /// content from the spill.
    async fn replay(&mut self, listing: &Listing) -> Result<Vec<String>, Error> {
        debug!("Computing the NAR hash again from the expanded tree");
        let stripped = listing.only_subdir(listing.root());
        let mut out = Writer::new(stripped.is_some());
        out.str(b"nix-archive-1");
        match stripped {
            Some((name, top)) => {
                out.strs(&[b"(", b"type", b"directory"]);
                out.entry(name);
                if let Some((inner, writing)) = &mut out.inner {
                    inner.update(nar_str(b"nix-archive-1"));
                    *writing = true;
                }
                self.dump(listing, top, &mut out).await?;
                if let Some((_, writing)) = &mut out.inner {
                    *writing = false;
                }
                out.strs(&[b")", b")"]);
            }
            None => self.dump(listing, listing.root(), &mut out).await?,
        }
        let (root, inner) = out.finish();
        Ok(core::iter::once(root).chain(inner).collect())
    }

    /// Writes the directory `id` as a NAR object, its entries in NAR order.
    async fn dump(&mut self, listing: &Listing, id: DirId, out: &mut Writer) -> Result<(), Error> {
        out.strs(&[b"(", b"type", b"directory"]);
        // The listing's entries are already sorted bytewise by name.
        let mut stack = vec![(id, 0usize)];
        while let Some((dir, next)) = stack.last_mut() {
            let Some(entry) = listing.dir(*dir).entries.get(*next) else {
                stack.pop();
                out.str(b")");
                if !stack.is_empty() {
                    out.str(b")");
                }
                continue;
            };
            *next += 1;
            out.entry(&entry.name);
            match &entry.kind {
                Kind::File { digest, executable } => {
                    self.dump_file(*digest, *executable, out).await?;
                    out.str(b")");
                }
                Kind::Symlink { target } => {
                    out.symlink(target);
                    out.str(b")");
                }
                Kind::Dir(sub) => {
                    out.strs(&[b"(", b"type", b"directory"]);
                    stack.push((*sub, 0));
                }
            }
        }
        Ok(())
    }

    async fn dump_file(
        &mut self,
        digest: DigestInfo,
        executable: bool,
        out: &mut Writer,
    ) -> Result<(), Error> {
        let size = digest.size_bytes();
        out.regular(executable, size);
        let mut read = 0u64;
        self.spill
            .read(digest, &mut |chunk| {
                read += chunk.len() as u64;
                out.raw(chunk);
            })
            .await?;
        if read != size {
            return Err(make_err!(
                Code::Internal,
                "The NAR spill holds {read} bytes of {digest}"
            ));
        }
        out.padding(size);
        out.str(b")");
        Ok(())
    }
}

/// `str(s)`, as bytes.
fn nar_str(s: &[u8]) -> Vec<u8> {
    let mut out = (s.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(s);
    out.resize(out.len().next_multiple_of(8), 0);
    out
}

/// Whether the tree holds anything the stream wrote as a regular,
/// non-executable file, as it did for every zip entry.
fn has_executable_or_symlink(listing: &Listing) -> bool {
    listing.leaves(listing.root()).iter().any(|(_, entry)| {
        matches!(
            entry.kind,
            Kind::Symlink { .. }
                | Kind::File {
                    executable: true,
                    ..
                }
        )
    })
}

#[async_trait]
impl TreeHash for NarHash {
    fn needs_held(&self) -> bool {
        true
    }

    fn directory(&mut self, path: &[String]) {
        self.step(|fast| fast.entry(path, true, |_| {}));
    }

    fn begin_file(&mut self, path: &[String], meta: &FileMeta) -> bool {
        self.file = None;
        let size = match meta.size {
            SizeInfo::Exact(size) | SizeInfo::Hint(size) => size,
            SizeInfo::Unknown => {
                self.abandon("a file's size is not known before its content");
                return false;
            }
        };
        let executable = match meta.mode {
            ModeInfo::Known { executable } => executable,
            // A guess, checked against the listing at the end.
            ModeInfo::AtEnd => {
                self.modes_at_end = true;
                false
            }
        };
        self.step(|fast| fast.entry(path, false, |out| out.regular(executable, size)));
        if self.fast.is_some() {
            self.file = Some((size, 0));
        }
        self.fast.is_some()
    }

    fn file_chunk(&mut self, chunk: &[u8]) {
        if let (Some(fast), Some((_, seen))) = (&mut self.fast, &mut self.file) {
            fast.content(chunk);
            *seen += chunk.len() as u64;
        }
    }

    async fn end_file(&mut self, file: &EndedFile<'_>) -> Result<(), Error> {
        if let Some((size, seen)) = self.file.take() {
            if seen == size {
                if let Some(fast) = &mut self.fast {
                    fast.end_regular(size);
                }
            } else {
                self.abandon("a zip entry's size differs from its local header");
            }
        }
        self.spill.keep(file.digest, file.held).await
    }

    fn symlink(&mut self, path: &[String], target: &str) {
        self.step(|fast| {
            fast.entry(path, false, |out| {
                out.symlink(target);
                out.str(b")");
            })
        });
    }

    fn hard_link(&mut self, _path: &[String], _digest: DigestInfo) {
        self.abandon("a hard link");
    }

    async fn finish(mut self: Box<Self>, listing: &Listing) -> Result<Computed, Error> {
        if self.modes_at_end && has_executable_or_symlink(listing) {
            self.abandon("a zip entry is executable or a symlink");
        }
        if let Some(fast) = self.fast.take() {
            let stripped = match (listing.only_subdir(listing.root()), fast.stripped) {
                (None, _) => Some(None),
                (Some(_), Strip::Under(_, inner)) => Some(Some(inner.finish())),
                // Cannot happen for a tree streamed in order, but replaying
                // is always right.
                (Some(_), Strip::Undecided | Strip::No) => None,
            };
            if let Some(stripped) = stripped {
                let root = fast.root.finish();
                return Ok(Computed::Values(
                    core::iter::once(root).chain(stripped).collect(),
                ));
            }
        }
        Ok(Computed::Values(self.replay(listing).await?))
    }
}
