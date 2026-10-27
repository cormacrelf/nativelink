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

//! Git tree object ids: the id `git write-tree` prints for a tree, and the
//! one a commit points to (`git rev-parse <commit>^{tree}`). Julia records
//! the same value as `git-tree-sha1` in `Manifest.toml` and `Artifacts.toml`.
//!
//! Following git 2.55.0, `update_one` in `cache-tree.c` (which `write-tree`
//! runs) and `format_object_header` in `object-file.c`, a tree is the object
//!
//! ```text
//! "tree " <decimal size> NUL { <mode> " " <name> NUL <raw id> }
//! ```
//!
//! hashed with the repository's hash function, its entries sorted by
//! `base_name_compare` in `tree.c` (bytewise, a directory compared as if its
//! name ended in `/`). `mode` is printed with `%o`, so a directory is `40000`
//! with no leading zero; a regular file is `100755` when executable and
//! `100644` otherwise (`create_ce_mode` in `object.h`), and a symlink
//! `120000`. A file or symlink is the blob `"blob " <size> NUL <content>`,
//! a symlink's content being its target.
//!
//! The index git builds a tree from holds only files, so a directory with no
//! files or symlinks anywhere below it is not in the tree. git also refuses to
//! track anything named `.git` (`verify_dotfile` in `read-cache.c`), so such
//! entries are left out, as Julia's `Pkg.GitTools.tree_hash` does. The root
//! is always hashed, as the empty tree when there is nothing in it.
//!
//! A SHA-1 repository's ids are 40 hex digits and a SHA-256 one's
//! (`git init --object-format=sha256`) 64, so the length of the expected
//! value picks the hash function.
//!
//! Each file's blob id is computed as its content streams past, which needs
//! its size first, for the header. Tar and most zip entries give it; for a
//! zip entry whose size only follows its data, the blob is hashed from the
//! expander's copy once the entry is complete, from memory or, past the
//! inline threshold, its local spill file. Trees are then built bottom-up
//! from the listing.
//!
//! Strip-root applies: a GitHub or GitLab archive of a commit holds the
//! commit's tree under one `<repo>-<rev>/` directory, and Julia's `Pkg`
//! (`install_archive` in `Operations.jl`) hashes such an archive without it.
//! The package server's and artifact tarballs have no such directory, and
//! the root's own hash covers them.

use std::collections::HashMap;

use nativelink_error::{Code, Error, make_err, make_input_err};
use nativelink_util::common::DigestInfo;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tonic::async_trait;

use super::{Computed, EndedFile, TreeHash, TreeHashContext, TreeHashFormat, hex, hex_decode};
use crate::archive_expander::{DirId, FileMeta, Kind, Listing, SizeInfo, git_cmp};

/// The Remote Asset qualifier carrying a git tree id.
pub const QUALIFIER_CHECKSUM_GIT_TREE: &str = "checksum.git_tree";

const SHA1_LEN: usize = 20;
const SHA256_LEN: usize = 32;

/// The git tree id format.
#[derive(Clone, Copy, Debug)]
pub struct GitTree;

impl TreeHashFormat for GitTree {
    fn qualifier(&self) -> &'static str {
        QUALIFIER_CHECKSUM_GIT_TREE
    }

    /// 40 hex digits for SHA-1, 64 for SHA-256, in either case; the canonical
    /// form is lower case, as git prints it.
    fn parse(&self, value: &str) -> Result<String, Error> {
        parse_git_tree_id(value).map(|id| hex(&id))
    }

    fn start(&self, expected: &str, _context: &TreeHashContext) -> Box<dyn TreeHash> {
        let algorithm = if expected.len() == SHA256_LEN * 2 {
            Algorithm::Sha256
        } else {
            Algorithm::Sha1
        };
        Box::new(GitTreeHash {
            algorithm,
            blobs: HashMap::new(),
            file: None,
        })
    }
}

/// Parses a git tree id: 40 hex digits for SHA-1, 64 for SHA-256, in either
/// case.
pub fn parse_git_tree_id(value: &str) -> Result<Vec<u8>, Error> {
    let id = match value.len() {
        len if len == SHA1_LEN * 2 || len == SHA256_LEN * 2 => hex_decode(value),
        _ => None,
    };
    id.ok_or_else(|| {
        make_input_err!(
            "Invalid git tree id '{value}': expected 40 (SHA-1) or 64 (SHA-256) hex digits"
        )
    })
}

/// A repository's object format.
#[derive(Clone, Copy, Debug)]
enum Algorithm {
    Sha1,
    Sha256,
}

/// Hashes one object, header first.
enum ObjectHasher {
    Sha1(Sha1),
    Sha256(Sha256),
}

impl Algorithm {
    /// Starts an object of `kind` (`blob`, `tree`) and `size` bytes.
    fn object(self, kind: &str, size: u64) -> ObjectHasher {
        let header = format!("{kind} {size}\0");
        match self {
            Self::Sha1 => ObjectHasher::Sha1(Sha1::new_with_prefix(header)),
            Self::Sha256 => ObjectHasher::Sha256(Sha256::new_with_prefix(header)),
        }
    }

    /// The id of the object of `kind` whose content is `content`.
    fn id(self, kind: &str, content: &[u8]) -> Vec<u8> {
        let mut object = self.object(kind, content.len() as u64);
        object.update(content);
        object.finish()
    }
}

impl ObjectHasher {
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha1(hasher) => hasher.update(data),
            Self::Sha256(hasher) => hasher.update(data),
        }
    }

    fn finish(self) -> Vec<u8> {
        match self {
            Self::Sha1(hasher) => hasher.finalize().to_vec(),
            Self::Sha256(hasher) => hasher.finalize().to_vec(),
        }
    }
}

/// Keeps a blob id per content, then builds the trees.
struct GitTreeHash {
    algorithm: Algorithm,
    blobs: HashMap<DigestInfo, Vec<u8>>,
    /// The current file's blob, while it streams, and the size it declared.
    file: Option<(ObjectHasher, u64, u64)>,
}

impl GitTreeHash {
    /// The id of the tree `id`, or `None` when nothing in it is tracked.
    fn tree(&self, listing: &Listing, id: DirId) -> Result<Option<Vec<u8>>, Error> {
        let mut entries: Vec<_> = listing
            .dir(id)
            .entries
            .iter()
            .filter(|entry| entry.name != ".git")
            .collect();
        entries.sort_by(|a, b| git_cmp(a, b));
        let mut content = Vec::new();
        for entry in entries {
            let (mode, id) = match &entry.kind {
                Kind::File { digest, executable } => {
                    let blob = self.blobs.get(digest).ok_or_else(|| {
                        make_err!(Code::Internal, "No blob id for '{}'", entry.name)
                    })?;
                    let mode = if *executable { "100755" } else { "100644" };
                    (mode, blob.clone())
                }
                Kind::Symlink { target } => {
                    ("120000", self.algorithm.id("blob", target.as_bytes()))
                }
                Kind::Dir(sub) => match self.tree(listing, *sub)? {
                    Some(id) => ("40000", id),
                    None => continue,
                },
            };
            content.extend_from_slice(format!("{mode} {}\0", entry.name).as_bytes());
            content.extend_from_slice(&id);
        }
        Ok((!content.is_empty()).then(|| self.algorithm.id("tree", &content)))
    }

    /// The id of the tree `id`, the empty tree when nothing in it is tracked.
    fn root(&self, listing: &Listing, id: DirId) -> Result<String, Error> {
        let tree = self
            .tree(listing, id)?
            .unwrap_or_else(|| self.algorithm.id("tree", &[]));
        Ok(hex(&tree))
    }
}

#[async_trait]
impl TreeHash for GitTreeHash {
    fn needs_held(&self) -> bool {
        true
    }

    fn begin_file(&mut self, _path: &[String], meta: &FileMeta) -> bool {
        self.file = match meta.size {
            SizeInfo::Exact(size) | SizeInfo::Hint(size) => {
                Some((self.algorithm.object("blob", size), size, 0))
            }
            SizeInfo::Unknown => None,
        };
        self.file.is_some()
    }

    fn file_chunk(&mut self, chunk: &[u8]) {
        if let Some((blob, _, seen)) = &mut self.file {
            blob.update(chunk);
            *seen += chunk.len() as u64;
        }
    }

    async fn end_file(&mut self, file: &EndedFile<'_>) -> Result<(), Error> {
        let streamed = self.file.take();
        if self.blobs.contains_key(&file.digest) {
            return Ok(());
        }
        let id = match streamed {
            Some((blob, size, seen)) if seen == size => blob.finish(),
            // The size was not known, or a zip's local header gave a wrong
            // one: hash the expander's copy.
            _ => {
                let mut blob = self.algorithm.object("blob", file.digest.size_bytes());
                file.held.read(&mut |chunk| blob.update(chunk)).await?;
                blob.finish()
            }
        };
        self.blobs.insert(file.digest, id);
        Ok(())
    }

    async fn finish(self: Box<Self>, listing: &Listing) -> Result<Computed, Error> {
        let mut values = vec![self.root(listing, listing.root())?];
        if let Some((name, top)) = listing.only_subdir(listing.root())
            && name != ".git"
        {
            values.push(self.root(listing, top)?);
        }
        Ok(Computed::Values(values))
    }
}
