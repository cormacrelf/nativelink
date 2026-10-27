// Copyright 2026 The NativeLink Authors. All rights reserved.
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

//! How Remote Asset metadata is stored: as ordinary Action Cache entries.
//!
//! An asset (`uri` + qualifiers, blob or directory) maps to the digest of its
//! content. That mapping is stored as an `ActionResult` under the digest of a
//! synthetic `Action`, so any Action Cache store can hold it: a `grpc` store
//! (e.g. a fetch tier writing to a central cluster), a `verify` store, and a
//! `completeness_checking` store that refuses entries whose content has left
//! the CAS.
//!
//! * **Key**: the digest of `Action { command_digest: digest(Command) }`, hashed
//!   with the request's digest function. The `Command` is
//!   `["nativelink-remote-asset", "<blob|directory>", "<uri>"]` with the
//!   qualifiers (sorted, HTTP header qualifiers excluded) as environment
//!   variables. Neither the `Action` nor the `Command` is uploaded to the CAS:
//!   an Action Cache entry does not need them. A push made with one digest
//!   function is not found by a fetch asking for another.
//! * **Value**: an `ActionResult` with the content as output `out`: an
//!   `OutputFile` for a blob, or an `OutputDirectory` whose `tree_digest` is a
//!   `Tree` uploaded to the CAS for a directory. `execution_metadata` carries
//!   the times (`worker_start_timestamp` is when the content was retrieved or
//!   pushed) and a [`RemoteAssetMetadata`] in `auxiliary_metadata`.

use std::collections::HashSet;
use std::time::SystemTime;

use bytes::BytesMut;
use futures::future::try_join_all;
use nativelink_error::{Code, Error, ResultExt, make_err};
use nativelink_proto::build::bazel::remote::asset::v1::Qualifier;
use nativelink_proto::build::bazel::remote::execution::v2::command::EnvironmentVariable;
use nativelink_proto::build::bazel::remote::execution::v2::{
    Action, ActionResult, Command, Digest, Directory, ExecutedActionMetadata, OutputDirectory,
    OutputFile, Tree,
};
use nativelink_store::ac_utils::{
    get_and_decode_digest, message_to_digest, serialize_and_upload_message,
};
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::DigestHasherFunc;
use nativelink_util::redact::redact_uri;
use nativelink_util::store_trait::{Store, StoreLike};
use prost::Message;
use prost_types::{Any, Timestamp};

/// Qualifier Bazel sets to distinguish otherwise identical requests (for
/// example the same URL fetched under different repository rules). It is part
/// of the asset's identity.
pub const QUALIFIER_BAZEL_CANONICAL_ID: &str = "bazel.canonical_id";
/// Prefix of a qualifier carrying an HTTP header sent to every URI:
/// `http_header:<name>`.
pub const QUALIFIER_HTTP_HEADER_PREFIX: &str = "http_header:";
/// Prefix of a qualifier carrying an HTTP header sent only to `uris[idx]`:
/// `http_header_url:<idx>:<name>`.
pub const QUALIFIER_HTTP_HEADER_URL_PREFIX: &str = "http_header_url:";

/// `ExecutedActionMetadata.worker` of every entry we write. It is also the
/// first argument of the synthetic `Command`, which keeps these entries
/// distinct from any real action's.
pub const REMOTE_ASSET_WORKER: &str = "nativelink-remote-asset";
/// Type URL of the [`RemoteAssetMetadata`] in `auxiliary_metadata`.
pub const REMOTE_ASSET_METADATA_TYPE_URL: &str =
    "type.googleapis.com/nativelink.RemoteAssetMetadata";
/// Path of the single output of every entry.
const OUTPUT_PATH: &str = "out";

/// Whether `name` is an HTTP header qualifier. These are request parameters
/// (often credentials), not part of an asset's identity: they must neither
/// affect the metadata key nor be persisted.
pub fn is_http_header_qualifier(name: &str) -> bool {
    name.starts_with(QUALIFIER_HTTP_HEADER_PREFIX)
        || name.starts_with(QUALIFIER_HTTP_HEADER_URL_PREFIX)
}

/// The names of `qualifiers`, for logging them: their values may be credentials.
pub fn qualifier_names(qualifiers: &[Qualifier]) -> Vec<&str> {
    qualifiers
        .iter()
        .map(|qualifier| qualifier.name.as_str())
        .collect()
}

/// `uris` with their credentials redacted, for logging them.
pub fn redacted_uris(uris: &[String]) -> Vec<String> {
    uris.iter().map(|uri| redact_uri(uri)).collect()
}

/// The current time as a proto `Timestamp`, for stamping entries as they are
/// stored.
pub fn now_timestamp() -> Timestamp {
    Timestamp::from(SystemTime::now())
}

/// Whether `a` is strictly earlier than `b`.
pub fn timestamp_is_before(a: &Timestamp, b: &Timestamp) -> bool {
    (a.seconds, a.nanos) < (b.seconds, b.nanos)
}

/// What kind of asset an entry describes. Blob and directory entries for the
/// same URI are independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetKind {
    Blob,
    Directory,
}

impl AssetKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Directory => "directory",
        }
    }
}

/// What the `ActionResult` itself cannot say about an entry: what the server
/// echoes back in responses, and when the entry expires.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct RemoteAssetMetadata {
    #[prost(string, tag = "1")]
    pub uri: String,

    #[prost(message, repeated, tag = "2")]
    pub qualifiers: Vec<Qualifier>,

    #[prost(message, optional, tag = "3")]
    pub expire_at: Option<Timestamp>,

    #[prost(
        enumeration = "nativelink_proto::build::bazel::remote::execution::v2::digest_function::Value",
        tag = "4"
    )]
    pub digest_function: i32,

    /// For a directory, the digest of the root `Directory` blob as it is in the
    /// CAS, which may differ from that of re-encoding the `Tree`'s `root`. It is
    /// kept here so that serving a hit needs no read of the `Tree` from the CAS.
    #[prost(message, optional, tag = "5")]
    pub root_directory_digest: Option<Digest>,
}

/// The identity of an asset: its kind, URI and qualifiers. HTTP header
/// qualifiers are dropped on construction: they are request parameters (often
/// credentials), not part of the identity, and must be neither keyed nor
/// persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAssetQuery {
    pub kind: AssetKind,
    pub uri: String,
    pub qualifiers: Vec<Qualifier>,
}

impl RemoteAssetQuery {
    pub fn new(kind: AssetKind, uri: String, qualifiers: Vec<Qualifier>) -> Self {
        let qualifiers = qualifiers
            .into_iter()
            .filter(|qualifier| !is_http_header_qualifier(&qualifier.name))
            .collect();
        Self {
            kind,
            uri,
            qualifiers,
        }
    }

    /// The Action Cache key of this asset: the digest of its synthetic `Action`,
    /// computed with `hasher_func`. Qualifiers are sorted by `(name, value)`
    /// first so the key does not depend on the order the client sent them in.
    pub fn key(&self, hasher_func: DigestHasherFunc) -> Result<DigestInfo, Error> {
        let mut sorted: Vec<&Qualifier> = self.qualifiers.iter().collect();
        sorted.sort_by(|a, b| (&a.name, &a.value).cmp(&(&b.name, &b.value)));
        let command = Command {
            arguments: vec![
                REMOTE_ASSET_WORKER.to_owned(),
                self.kind.as_str().to_owned(),
                self.uri.clone(),
            ],
            environment_variables: sorted
                .into_iter()
                .map(|qualifier| EnvironmentVariable {
                    name: qualifier.name.clone(),
                    value: qualifier.value.clone(),
                })
                .collect(),
            ..Default::default()
        };
        let command_digest =
            message_to_digest(&command, &mut BytesMut::new(), &mut hasher_func.hasher())
                .err_tip(|| "Hashing the Remote Asset command")?;
        let action = Action {
            command_digest: Some(command_digest.into()),
            do_not_cache: false,
            ..Default::default()
        };
        message_to_digest(&action, &mut BytesMut::new(), &mut hasher_func.hasher())
            .err_tip(|| "Hashing the Remote Asset action")
    }
}

/// A stored asset: what [`write_remote_asset_entry`] writes and
/// [`read_remote_asset_entry`] returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAssetEntry {
    pub query: RemoteAssetQuery,
    /// The blob's digest, or the root `Directory`'s for a directory. It is
    /// stored and served as given (a directory's root with its hex lowercased),
    /// so it must be the digest the content is in the CAS under (which, for a
    /// `Directory` a client uploaded, may not be that of its canonical
    /// encoding).
    pub digest: Digest,
    pub expire_at: Option<Timestamp>,
    /// When the content was Push'd, or when the retrieval from origin that
    /// produced it was started: what `oldest_content_accepted` is compared
    /// against. Stored as the `worker_start_timestamp`.
    pub stored_at: Option<Timestamp>,
    /// The digest function as the request gave it (zero when unset). It selects
    /// how the key and any `Tree` are hashed. What is stored, and read back
    /// here, is the function it resolves to.
    pub digest_function: i32,
    /// For a directory read back from the Action Cache, the digest of its
    /// `Tree` in the CAS. Ignored on write, which builds and uploads the `Tree`
    /// itself.
    pub tree_digest: Option<Digest>,
}

/// The digests of the subdirectories of `directory` that are not in `seen`,
/// which they are added to.
fn new_subdirectories(
    directory: &Directory,
    seen: &mut HashSet<DigestInfo>,
) -> Result<Vec<DigestInfo>, Error> {
    let mut found = Vec::new();
    for node in &directory.directories {
        let digest = node
            .digest
            .as_ref()
            .err_tip(|| "Directory node without a digest")?;
        let digest = DigestInfo::try_from(digest).err_tip(|| "Invalid directory node digest")?;
        if seen.insert(digest) {
            found.push(digest);
        }
    }
    Ok(found)
}

/// Builds the REAPI `Tree` rooted at the `Directory` `root` by walking it and
/// its subdirectories in `cas_store`, a level at a time. Fails if any
/// `Directory` proto is missing, so success also proves the tree's structure
/// is complete (file contents are not checked).
pub async fn build_tree(cas_store: &Store, root: DigestInfo) -> Result<Tree, Error> {
    let root_directory = get_and_decode_digest::<Directory>(cas_store, root.into())
        .await
        .err_tip(|| format!("Root directory {root} is not in the CAS"))?;
    let mut seen = HashSet::from([root]);
    let mut level = new_subdirectories(&root_directory, &mut seen)?;
    let mut children = Vec::new();
    while !level.is_empty() {
        let directories = try_join_all(level.iter().map(|digest| async move {
            get_and_decode_digest::<Directory>(cas_store, (*digest).into())
                .await
                .err_tip(|| format!("Subdirectory {digest} is not in the CAS"))
        }))
        .await?;
        level = Vec::new();
        for directory in directories {
            level.extend(new_subdirectories(&directory, &mut seen)?);
            children.push(directory);
        }
    }
    Ok(Tree {
        root: Some(root_directory),
        children,
    })
}

/// Writes `entry` to the Action Cache `ac_store` as described in the module
/// docs. For a directory, `cas_store` is used to read the `Directory` protos
/// and to upload the `Tree`; this fails if any `Directory` is missing, or with
/// `FailedPrecondition` if there is no `cas_store`. A blob needs none.
pub async fn write_remote_asset_entry(
    ac_store: &Store,
    cas_store: Option<&Store>,
    entry: &RemoteAssetEntry,
) -> Result<(), Error> {
    let hasher_func = DigestHasherFunc::try_from(entry.digest_function)
        .err_tip(|| "Digest function of Remote Asset entry")?;
    let key = entry.query.key(hasher_func)?;
    let (output_files, output_directories, root_directory_digest) = match entry.query.kind {
        AssetKind::Blob => (
            vec![OutputFile {
                path: OUTPUT_PATH.to_owned(),
                digest: Some(entry.digest.clone()),
                is_executable: false,
                ..Default::default()
            }],
            vec![],
            None,
        ),
        AssetKind::Directory => {
            let cas_store = cas_store.ok_or_else(|| {
                make_err!(
                    Code::FailedPrecondition,
                    "Writing a directory asset needs a CAS store"
                )
            })?;
            let root =
                DigestInfo::try_from(&entry.digest).err_tip(|| "Invalid root directory digest")?;
            // The entry names both the `Tree` and the root `Directory`, so
            // `completeness_checking` also checks the separately stored
            // `Directory` blobs that clients walk from the root. The root
            // digest stored is the one the client gave, which exists in the
            // CAS by the `build_tree` read, whereas re-encoding the decoded
            // root may give other bytes. It is stored in its parsed form so
            // that the hex is lowercase whatever the client sent.
            let tree = build_tree(cas_store, root).await?;
            let tree_digest =
                serialize_and_upload_message(&tree, cas_store.as_pin(), &mut hasher_func.hasher())
                    .await
                    .err_tip(|| "Uploading the Tree")?;
            (
                vec![],
                vec![OutputDirectory {
                    path: OUTPUT_PATH.to_owned(),
                    tree_digest: Some(tree_digest.into()),
                    is_topologically_sorted: false,
                    root_directory_digest: Some(root.into()),
                }],
                Some(root.into()),
            )
        }
    };
    let metadata = RemoteAssetMetadata {
        uri: entry.query.uri.clone(),
        qualifiers: entry.query.qualifiers.clone(),
        expire_at: entry.expire_at,
        digest_function: hasher_func.proto_digest_func().into(),
        root_directory_digest,
    };
    let action_result = ActionResult {
        output_files,
        output_directories,
        execution_metadata: Some(ExecutedActionMetadata {
            worker: REMOTE_ASSET_WORKER.to_owned(),
            worker_start_timestamp: entry.stored_at.or_else(|| Some(now_timestamp())),
            worker_completed_timestamp: Some(now_timestamp()),
            auxiliary_metadata: vec![Any {
                type_url: REMOTE_ASSET_METADATA_TYPE_URL.to_owned(),
                value: metadata.encode_to_vec(),
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    ac_store
        .update_oneshot(key, action_result.encode_to_vec().into())
        .await
        .err_tip(|| "Writing the Remote Asset entry to the Action Cache")
}

/// Reads the entry for `query` from the Action Cache `ac_store`, looking it up
/// with the digest function `digest_function` (zero meaning the default).
/// Returns `None` if there is no entry, or what is stored is not a Remote
/// Asset entry of the right kind (including a corrupt value).
pub async fn read_remote_asset_entry(
    ac_store: &Store,
    query: &RemoteAssetQuery,
    digest_function: i32,
) -> Result<Option<RemoteAssetEntry>, Error> {
    let hasher_func = DigestHasherFunc::try_from(digest_function)
        .err_tip(|| "Digest function of Remote Asset lookup")?;
    let key = query.key(hasher_func)?;
    let action_result = match get_and_decode_digest::<ActionResult>(ac_store, key.into()).await {
        Ok(action_result) => action_result,
        Err(err) if err.code == Code::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    Ok(entry_from_action_result(query.kind, action_result))
}

/// Decodes a stored `ActionResult`, or `None` if it is not a Remote Asset entry
/// of `kind`.
fn entry_from_action_result(
    kind: AssetKind,
    action_result: ActionResult,
) -> Option<RemoteAssetEntry> {
    let execution_metadata = action_result.execution_metadata?;
    let any = execution_metadata
        .auxiliary_metadata
        .iter()
        .find(|any| any.type_url == REMOTE_ASSET_METADATA_TYPE_URL)?;
    let metadata = RemoteAssetMetadata::decode(any.value.as_slice()).ok()?;
    let (digest, tree_digest) = match kind {
        AssetKind::Blob => {
            let [file] = action_result.output_files.as_slice() else {
                return None;
            };
            (file.digest.clone()?, None)
        }
        AssetKind::Directory => {
            let [directory] = action_result.output_directories.as_slice() else {
                return None;
            };
            (
                metadata.root_directory_digest.clone()?,
                directory.tree_digest.clone(),
            )
        }
    };
    Some(RemoteAssetEntry {
        query: RemoteAssetQuery {
            kind,
            uri: metadata.uri,
            qualifiers: metadata.qualifiers,
        },
        digest,
        expire_at: metadata.expire_at,
        stored_at: execution_metadata.worker_start_timestamp,
        digest_function: metadata.digest_function,
        tree_digest,
    })
}
