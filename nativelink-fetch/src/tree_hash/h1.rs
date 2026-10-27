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

//! Go module directory hashing (`h1:`), as implemented by
//! `golang.org/x/mod/sumdb/dirhash`'s `Hash1`.
//!
//! The hash is computed by, for every *file* in the tree, taking the SHA-256
//! of its content, then feeding the line `"{hex}  {name}\n"` (note the two
//! spaces) for each file — sorted by name — into an outer SHA-256. The result
//! is `"h1:" + base64(outer_digest)`.
//!
//! Directories are intentionally not hashed. Go's
//! `HashZip` includes zero-length directory entries while `HashDir` (which
//! walks a real directory tree) does not, so the two disagree for archives
//! that carry explicit directory entries — a known inconsistency, see
//! <https://github.com/golang/go/issues/53448>. We match `HashDir`, the
//! canonical hash of a directory's *contents*, since `checksum.h1` identifies
//! the fetched directory tree rather than a specific zip framing. Symlinks are
//! not hashed either; Go module zips cannot contain them.
//!
//! The file SHA-256s come from the expander's pass (free under a SHA-256
//! CAS), and the lines are written in [`Listing::leaves`] order, which is
//! sorted by path. If a tar lists a path twice, only the last entry counts,
//! as in the expanded tree.
//!
//! Strip-root does not apply: a module zip puts every file under
//! `<module>@<version>/` and Go's `h1` covers that prefix, so the hash of the
//! root is always the one Go records.
//!
//! The value is compared as text, so a malformed `checksum.h1` is not rejected
//! up front; it simply never matches.

use core::fmt::Write;
use std::collections::HashMap;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use nativelink_error::{Code, Error, make_err};
use nativelink_util::common::DigestInfo;
use sha2::{Digest, Sha256};
use tonic::async_trait;

use super::{Computed, EndedFile, TreeHash, TreeHashContext, TreeHashFormat, hex};
use crate::archive_expander::{FileMeta, Kind, Listing};

/// The Remote Asset API qualifier name carrying a Go `h1:` directory hash.
pub const QUALIFIER_CHECKSUM_H1: &str = "checksum.h1";

/// The Go `h1:` format.
#[derive(Clone, Copy, Debug)]
pub struct H1;

/// Builds the Go `h1:` directory hash from `(path, sha256-of-content)` pairs
/// for every regular file (directories excluded). Pairs may be in any order;
/// they are sorted by path here. Paths use `/` separators and are relative.
pub fn h1_from_file_hashes(mut files: Vec<(String, [u8; 32])>) -> String {
    // Sort by name lexicographically, then fold into the outer hash.
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut outer = Sha256::new();
    let mut line = String::new();
    for (name, content_hash) in &files {
        line.clear();
        line.push_str(&hex(content_hash));
        // Writing to a `String` cannot fail.
        let _ = writeln!(line, "  {name}");
        outer.update(line.as_bytes());
    }
    format!("h1:{}", BASE64_STANDARD.encode(outer.finalize()))
}

impl TreeHashFormat for H1 {
    fn qualifier(&self) -> &'static str {
        QUALIFIER_CHECKSUM_H1
    }

    fn parse(&self, value: &str) -> Result<String, Error> {
        Ok(value.to_owned())
    }

    fn start(&self, _expected: &str, _context: &TreeHashContext) -> Box<dyn TreeHash> {
        Box::new(H1Hash {
            sha256: HashMap::new(),
        })
    }
}

/// Keeps the SHA-256 of every file's content, then combines them.
struct H1Hash {
    sha256: HashMap<DigestInfo, [u8; 32]>,
}

#[async_trait]
impl TreeHash for H1Hash {
    fn needs_sha256(&self) -> bool {
        true
    }

    fn begin_file(&mut self, _path: &[String], _meta: &FileMeta) -> bool {
        false
    }

    async fn end_file(&mut self, file: &EndedFile<'_>) -> Result<(), Error> {
        let sha256 = file
            .sha256
            .ok_or_else(|| make_err!(Code::Internal, "h1 was not given a file's SHA-256"))?;
        self.sha256.insert(file.digest, sha256);
        Ok(())
    }

    async fn finish(self: Box<Self>, listing: &Listing) -> Result<Computed, Error> {
        let mut files = Vec::new();
        for (path, entry) in listing.leaves(listing.root()) {
            if let Kind::File { digest, .. } = entry.kind {
                let sha256 = self
                    .sha256
                    .get(&digest)
                    .ok_or_else(|| make_err!(Code::Internal, "h1 has no SHA-256 for '{path}'"))?;
                files.push((path, *sha256));
            }
        }
        Ok(Computed::Values(vec![h1_from_file_hashes(files)]))
    }
}
