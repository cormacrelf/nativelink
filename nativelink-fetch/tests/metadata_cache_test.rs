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

use core::time::Duration;
use std::collections::HashSet;
use std::sync::Arc;

use nativelink_config::stores::{MemorySpec, StoreSpec};
use nativelink_error::{Code, Error, make_err};
use nativelink_fetch::fetcher::{
    DirectoryChecksum, FetchBlobTask, FetchDirectoryJob, FetchHeaders, FetchOutcome, Fetcher,
    Validators,
};
use nativelink_fetch::metadata_cache::{MetadataCache, MetadataCacheOptions};
use nativelink_fetch::remote_asset_proto::{
    AssetKind, RemoteAssetEntry, RemoteAssetMetadata, RemoteAssetQuery, read_remote_asset_entry,
    timestamp_is_before, write_remote_asset_entry,
};
use nativelink_fetch::tree_hash::TreeChecksum;
use nativelink_fetch::tree_hash::h1::H1;
use nativelink_macro::nativelink_test;
use nativelink_proto::build::bazel::remote::asset::v1::Qualifier;
use nativelink_proto::build::bazel::remote::execution::v2::command::EnvironmentVariable;
use nativelink_proto::build::bazel::remote::execution::v2::{
    Action, ActionResult, Command, Digest, Directory, DirectoryNode, ExecutedActionMetadata,
    FileNode, OutputFile, Tree, digest_function,
};
use nativelink_store::ac_utils::{get_and_decode_digest, serialize_and_upload_message};
use nativelink_store::default_store_factory::store_factory;
use nativelink_store::store_manager::StoreManager;
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::{DigestHasher, DigestHasherFunc};
use nativelink_util::sri::ByteChecksum;
use nativelink_util::store_trait::{Store, StoreLike};
use prost::Message;
use prost_types::Timestamp;
use tonic::async_trait;

/// An inner `Fetcher` that always succeeds with a fixed outcome.
#[derive(Debug)]
struct OkFetcher {
    uri: String,
    digest: DigestInfo,
}

#[async_trait]
impl Fetcher for OkFetcher {
    async fn fetch_blob(&self, _job: &FetchBlobTask) -> Result<FetchOutcome, Error> {
        Ok(FetchOutcome::new(self.uri.clone(), self.digest))
    }
    async fn fetch_directory(&self, _job: &FetchDirectoryJob) -> Result<FetchOutcome, Error> {
        Ok(FetchOutcome::new(self.uri.clone(), self.digest))
    }
}

/// An inner `Fetcher` that always fails.
#[derive(Debug)]
struct ErrFetcher;

#[async_trait]
impl Fetcher for ErrFetcher {
    async fn fetch_blob(&self, _job: &FetchBlobTask) -> Result<FetchOutcome, Error> {
        Err(make_err!(Code::NotFound, "no uri served the blob"))
    }
    async fn fetch_directory(&self, _job: &FetchDirectoryJob) -> Result<FetchOutcome, Error> {
        Err(make_err!(Code::NotFound, "no uri served the directory"))
    }
}

async fn memory_store() -> Store {
    let store_manager = Arc::new(StoreManager::new());
    store_factory(
        &StoreSpec::Memory(MemorySpec::default()),
        &store_manager,
        None,
    )
    .await
    .expect("failed to build memory store")
}

fn qualifiers() -> Vec<(String, String)> {
    vec![("resource_type".to_string(), "test".to_string())]
}

fn proto_qualifiers() -> Vec<Qualifier> {
    qualifiers()
        .into_iter()
        .map(|(name, value)| Qualifier { name, value })
        .collect()
}

fn blob_job(uri: &str, qualifiers: Vec<(String, String)>) -> FetchBlobTask {
    FetchBlobTask {
        uris: vec![uri.to_string()],
        qualifiers,
        checksums: vec![],
        hasher_func: DigestHasherFunc::Sha256,
        timeout: None,
        headers: FetchHeaders::default(),
        revalidate: vec![],
        shared_deadline: None,
    }
}

fn directory_job(uri: &str) -> FetchDirectoryJob {
    FetchDirectoryJob {
        verified_by_action: false,
        uris: vec![uri.to_string()],
        qualifiers: qualifiers(),
        checksums: vec![DirectoryChecksum::Tree(
            TreeChecksum::parse(&H1, "h1:abc").unwrap(),
        )],
        hasher_func: DigestHasherFunc::Sha256,
        timeout: None,
        headers: FetchHeaders::default(),
        revalidate: vec![],
        shared_deadline: None,
    }
}

fn sha256_digest_of(bytes: &[u8]) -> DigestInfo {
    let mut hasher = DigestHasherFunc::Sha256.hasher();
    hasher.update(bytes);
    hasher.finalize_digest()
}

/// Uploads `directory` to `cas` and returns its digest.
async fn upload_directory(cas: &Store, directory: &Directory) -> DigestInfo {
    serialize_and_upload_message(
        directory,
        cas.as_pin(),
        &mut DigestHasherFunc::Sha256.hasher(),
    )
    .await
    .unwrap()
}

fn file_node(name: &str, content: &[u8]) -> FileNode {
    FileNode {
        name: name.to_string(),
        digest: Some(sha256_digest_of(content).into()),
        ..Default::default()
    }
}

fn directory_node(name: &str, digest: DigestInfo) -> DirectoryNode {
    DirectoryNode {
        name: name.to_string(),
        digest: Some(digest.into()),
    }
}

/// Uploads `root/{a.txt, sub/{b.txt, deep/c.txt}}` and returns the digests of
/// `(root, sub, deep)`.
async fn upload_nested_directories(cas: &Store) -> (DigestInfo, DigestInfo, DigestInfo) {
    let deep = upload_directory(
        cas,
        &Directory {
            files: vec![file_node("c.txt", b"c")],
            ..Default::default()
        },
    )
    .await;
    let sub = upload_directory(
        cas,
        &Directory {
            files: vec![file_node("b.txt", b"b")],
            directories: vec![directory_node("deep", deep)],
            ..Default::default()
        },
    )
    .await;
    let root = upload_directory(
        cas,
        &Directory {
            files: vec![file_node("a.txt", b"a")],
            directories: vec![directory_node("sub", sub)],
            ..Default::default()
        },
    )
    .await;
    (root, sub, deep)
}

/// Reads and decodes the raw `ActionResult` stored under `key`.
async fn stored_action_result(store: &Store, key: DigestInfo) -> ActionResult {
    let raw = store
        .get_part_unchunked(key, 0, None)
        .await
        .expect("metadata should have been written");
    ActionResult::decode(raw).expect("stored value should be an ActionResult")
}

/// Decodes the single `RemoteAssetMetadata` in `action_result`'s auxiliary
/// metadata.
fn stored_metadata(action_result: &ActionResult) -> RemoteAssetMetadata {
    let execution_metadata = action_result.execution_metadata.as_ref().unwrap();
    assert_eq!(execution_metadata.auxiliary_metadata.len(), 1);
    let any = &execution_metadata.auxiliary_metadata[0];
    assert_eq!(
        any.type_url,
        "type.googleapis.com/nativelink.RemoteAssetMetadata"
    );
    RemoteAssetMetadata::decode(any.value.as_slice()).unwrap()
}

fn key_of(kind: AssetKind, uri: &str, qualifiers: Vec<Qualifier>) -> DigestInfo {
    RemoteAssetQuery::new(kind, uri.to_string(), qualifiers)
        .key(DigestHasherFunc::Sha256)
        .unwrap()
}

#[nativelink_test]
async fn writes_blob_metadata_as_an_action_result_on_success() {
    let ac_store = memory_store().await;
    let cas_store = memory_store().await;
    let digest = DigestInfo::try_new(&"ab".repeat(32), 11).unwrap();
    let inner: Arc<dyn Fetcher> = Arc::new(OkFetcher {
        uri: "http://example/blob".to_string(),
        digest,
    });
    let mc = MetadataCache::new(inner, ac_store.clone(), cas_store);

    let outcome = mc
        .fetch_blob(&blob_job("http://example/blob", qualifiers()))
        .await
        .unwrap();
    assert_eq!(outcome.digest, digest);

    // The metadata must be readable at the same key the FetchServer computes
    // from the request's qualifiers on a later lookup.
    let key = key_of(AssetKind::Blob, "http://example/blob", proto_qualifiers());
    let action_result = stored_action_result(&ac_store, key).await;
    let expected_digest: Digest = digest.into();
    assert_eq!(
        action_result.output_files,
        vec![OutputFile {
            path: "out".to_string(),
            digest: Some(expected_digest),
            is_executable: false,
            ..Default::default()
        }]
    );
    assert!(action_result.output_directories.is_empty());
    let execution_metadata = action_result.execution_metadata.as_ref().unwrap();
    assert_eq!(execution_metadata.worker, "nativelink-remote-asset");
    let started = execution_metadata.worker_start_timestamp.unwrap();
    let completed = execution_metadata.worker_completed_timestamp.unwrap();
    assert!(!timestamp_is_before(&completed, &started));
    let metadata = stored_metadata(&action_result);
    assert_eq!(metadata.uri, "http://example/blob");
    assert_eq!(metadata.qualifiers, proto_qualifiers());
    // An unpinned request with no caching headers gets the default lifetime.
    assert_eq!(
        metadata.expire_at,
        Some(Timestamp {
            seconds: started.seconds + 24 * 60 * 60,
            nanos: started.nanos
        })
    );
    assert_eq!(outcome.expire_at, metadata.expire_at);
    assert_eq!(
        metadata.digest_function,
        i32::from(digest_function::Value::Sha256)
    );

    // And it reads back as an entry.
    let entry = read_remote_asset_entry(
        &ac_store,
        &RemoteAssetQuery::new(
            AssetKind::Blob,
            "http://example/blob".to_string(),
            proto_qualifiers(),
        ),
        digest_function::Value::Sha256.into(),
    )
    .await
    .unwrap()
    .expect("entry should be readable");
    assert_eq!(entry.digest, Digest::from(digest));
    assert_eq!(entry.stored_at, Some(started));
}

/// The key is the digest of a real `Action`, which an ordinary Action Cache
/// (or a `grpc` store in front of one) can hold: recompute it from scratch.
#[nativelink_test]
async fn key_is_the_digest_of_a_synthetic_action() {
    let query = RemoteAssetQuery::new(
        AssetKind::Directory,
        "http://example/dir".to_string(),
        vec![
            Qualifier {
                name: "b".to_string(),
                value: "2".to_string(),
            },
            Qualifier {
                name: "http_header:Authorization".to_string(),
                value: "Bearer secret".to_string(),
            },
            Qualifier {
                name: "a".to_string(),
                value: "1".to_string(),
            },
        ],
    );
    for hasher_func in [DigestHasherFunc::Sha256, DigestHasherFunc::Blake3] {
        let command = Command {
            arguments: vec![
                "nativelink-remote-asset".to_string(),
                "directory".to_string(),
                "http://example/dir".to_string(),
            ],
            environment_variables: vec![
                EnvironmentVariable {
                    name: "a".to_string(),
                    value: "1".to_string(),
                },
                EnvironmentVariable {
                    name: "b".to_string(),
                    value: "2".to_string(),
                },
            ],
            ..Default::default()
        };
        let mut hasher = hasher_func.hasher();
        hasher.update(&command.encode_to_vec());
        let command_digest = hasher.finalize_digest();
        let action = Action {
            command_digest: Some(command_digest.into()),
            do_not_cache: false,
            ..Default::default()
        };
        let mut hasher = hasher_func.hasher();
        hasher.update(&action.encode_to_vec());
        assert_eq!(query.key(hasher_func).unwrap(), hasher.finalize_digest());
    }
    // Different digest functions give different keys.
    assert_ne!(
        query.key(DigestHasherFunc::Sha256).unwrap(),
        query.key(DigestHasherFunc::Blake3).unwrap()
    );
}

#[nativelink_test]
async fn blob_and_directory_keys_differ_for_the_same_uri() {
    assert_ne!(
        key_of(AssetKind::Blob, "http://example/x", vec![]),
        key_of(AssetKind::Directory, "http://example/x", vec![])
    );
}

#[nativelink_test]
async fn key_does_not_depend_on_qualifier_order_or_headers() {
    let qualifier = |name: &str, value: &str| Qualifier {
        name: name.to_string(),
        value: value.to_string(),
    };
    let key = |qualifiers: Vec<Qualifier>| key_of(AssetKind::Blob, "http://example/x", qualifiers);
    let base = key(vec![qualifier("a", "1"), qualifier("b", "2")]);
    assert_eq!(base, key(vec![qualifier("b", "2"), qualifier("a", "1")]));
    assert_eq!(
        base,
        key(vec![
            qualifier("a", "1"),
            qualifier("http_header:X-Token", "t"),
            qualifier("b", "2"),
            qualifier("http_header_url:0:X-Token", "t"),
        ])
    );
    assert_ne!(base, key(vec![qualifier("a", "1"), qualifier("b", "3")]));
}

#[nativelink_test]
async fn writes_directory_metadata_with_a_tree_on_success() {
    let ac_store = memory_store().await;
    let cas_store = memory_store().await;
    let (root, sub, deep) = upload_nested_directories(&cas_store).await;
    let inner: Arc<dyn Fetcher> = Arc::new(OkFetcher {
        uri: "http://example/dir".to_string(),
        digest: root,
    });
    let mc = MetadataCache::new(inner, ac_store.clone(), cas_store.clone());

    let outcome = mc
        .fetch_directory(&directory_job("http://example/dir"))
        .await
        .unwrap();
    assert_eq!(outcome.digest, root);

    let key = key_of(
        AssetKind::Directory,
        "http://example/dir",
        proto_qualifiers(),
    );
    let action_result = stored_action_result(&ac_store, key).await;
    assert!(action_result.output_files.is_empty());
    assert_eq!(action_result.output_directories.len(), 1);
    let output_directory = &action_result.output_directories[0];
    assert_eq!(output_directory.path, "out");
    let tree_digest = DigestInfo::try_from(output_directory.tree_digest.as_ref().unwrap()).unwrap();
    assert_eq!(
        stored_metadata(&action_result).root_directory_digest,
        Some(Digest::from(root))
    );

    // The Tree is in the CAS and holds the root and every descendant.
    let tree: Tree = get_and_decode_digest(&cas_store, tree_digest.into())
        .await
        .unwrap();
    let expected_root: Directory = get_and_decode_digest(&cas_store, root.into())
        .await
        .unwrap();
    assert_eq!(tree.root, Some(expected_root));
    let child_digests: HashSet<DigestInfo> = tree
        .children
        .iter()
        .map(|child| sha256_digest_of(&child.encode_to_vec()))
        .collect();
    assert_eq!(tree.children.len(), 2);
    assert_eq!(child_digests, HashSet::from([sub, deep]));
}

#[nativelink_test]
async fn directory_with_a_missing_subdirectory_is_an_error_and_writes_nothing() {
    let ac_store = memory_store().await;
    let cas_store = memory_store().await;
    // The root refers to a subdirectory that was never uploaded.
    let missing = DigestInfo::try_new(&"ef".repeat(32), 5).unwrap();
    let root = upload_directory(
        &cas_store,
        &Directory {
            directories: vec![directory_node("sub", missing)],
            ..Default::default()
        },
    )
    .await;
    let inner: Arc<dyn Fetcher> = Arc::new(OkFetcher {
        uri: "http://example/dir".to_string(),
        digest: root,
    });
    let mc = MetadataCache::new(inner, ac_store.clone(), cas_store);

    let err = mc
        .fetch_directory(&directory_job("http://example/dir"))
        .await
        .unwrap_err();
    assert_eq!(err.code, Code::NotFound);

    let key = key_of(
        AssetKind::Directory,
        "http://example/dir",
        proto_qualifiers(),
    );
    assert!(ac_store.get_part_unchunked(key, 0, None).await.is_err());
}

#[nativelink_test]
async fn does_not_write_metadata_on_failure() {
    let ac_store = memory_store().await;
    let inner: Arc<dyn Fetcher> = Arc::new(ErrFetcher);
    let mc = MetadataCache::new(inner, ac_store.clone(), memory_store().await);

    let err = mc
        .fetch_blob(&blob_job("http://example/blob", qualifiers()))
        .await
        .unwrap_err();
    assert_eq!(err.code, Code::NotFound);

    // Nothing should have been written to the metadata store.
    let key = key_of(AssetKind::Blob, "http://example/blob", proto_qualifiers());
    assert!(
        ac_store.get_part_unchunked(key, 0, None).await.is_err(),
        "no metadata should be written when the inner fetch fails"
    );
}

#[nativelink_test]
async fn does_not_persist_or_key_on_header_qualifiers() {
    let ac_store = memory_store().await;
    let digest = DigestInfo::try_new(&"ab".repeat(32), 11).unwrap();
    let inner: Arc<dyn Fetcher> = Arc::new(OkFetcher {
        uri: "http://example/blob".to_string(),
        digest,
    });
    let mc = MetadataCache::new(inner, ac_store.clone(), memory_store().await);

    // Even if header qualifiers reach the job's qualifiers, they must be
    // neither persisted nor part of the metadata key.
    let mut job_qualifiers = qualifiers();
    job_qualifiers.push(("http_header:Authorization".into(), "Bearer secret".into()));
    job_qualifiers.push((
        "http_header_url:0:Authorization".into(),
        "Bearer secret".into(),
    ));
    mc.fetch_blob(&blob_job("http://example/blob", job_qualifiers))
        .await
        .unwrap();

    let key = key_of(AssetKind::Blob, "http://example/blob", proto_qualifiers());
    let action_result = stored_action_result(&ac_store, key).await;
    assert_eq!(
        stored_metadata(&action_result).qualifiers,
        proto_qualifiers()
    );
    assert!(
        !action_result
            .encode_to_vec()
            .windows(6)
            .any(|window| window == b"secret"),
        "no header value should be stored anywhere in the entry"
    );
}

/// An inner `Fetcher` that succeeds with a fixed digest and the freshness the
/// origin's headers are taken to have given.
#[derive(Debug)]
struct HeaderFetcher {
    digest: DigestInfo,
    freshness: Option<Duration>,
    validators: Validators,
}

#[async_trait]
impl Fetcher for HeaderFetcher {
    async fn fetch_blob(&self, job: &FetchBlobTask) -> Result<FetchOutcome, Error> {
        Ok(FetchOutcome {
            freshness: self.freshness,
            validators: self.validators.clone(),
            ..FetchOutcome::new(job.uris[0].clone(), self.digest)
        })
    }
    async fn fetch_directory(&self, _job: &FetchDirectoryJob) -> Result<FetchOutcome, Error> {
        Err(make_err!(Code::Unimplemented, "not used"))
    }
}

const fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// Fetches an asset through a `MetadataCache` whose inner fetcher reports
/// `freshness`, and returns how long after being stored the entry expires
/// (`None`: never), as written to the Action Cache.
async fn lifetime_of(
    options: MetadataCacheOptions,
    freshness: Option<Duration>,
    checksums: Vec<ByteChecksum>,
) -> Option<i64> {
    let ac_store = memory_store().await;
    let cas_store = memory_store().await;
    let digest = sha256_digest_of(b"payload");
    let inner: Arc<dyn Fetcher> = Arc::new(HeaderFetcher {
        digest,
        freshness,
        validators: Validators::default(),
    });
    let mc = MetadataCache::with_options(inner, ac_store.clone(), cas_store, options);
    let mut job = blob_job("http://example/blob", qualifiers());
    job.checksums = checksums;
    mc.fetch_blob(&job).await.unwrap();

    let key = key_of(AssetKind::Blob, "http://example/blob", proto_qualifiers());
    let action_result = stored_action_result(&ac_store, key).await;
    let stored_at = action_result
        .execution_metadata
        .as_ref()
        .unwrap()
        .worker_start_timestamp
        .unwrap();
    stored_metadata(&action_result)
        .expire_at
        .map(|expire_at| expire_at.seconds - stored_at.seconds)
}

const fn limits(default: u64, min: u64, max: u64) -> MetadataCacheOptions {
    MetadataCacheOptions {
        unpinned_default_ttl: secs(default),
        unpinned_min_ttl: secs(min),
        unpinned_max_ttl: secs(max),
    }
}

#[nativelink_test]
async fn unpinned_entry_without_headers_gets_the_default_lifetime() {
    let options = limits(1000, 10, 5000);
    assert_eq!(lifetime_of(options, None, vec![]).await, Some(1000));
    // The default is limited like any other lifetime.
    assert_eq!(
        lifetime_of(limits(1, 10, 5000), None, vec![]).await,
        Some(10)
    );
    assert_eq!(
        lifetime_of(limits(9000, 10, 5000), None, vec![]).await,
        Some(5000)
    );
}

#[nativelink_test]
async fn unpinned_entry_uses_the_origins_lifetime_within_the_limits() {
    let options = limits(1000, 10, 5000);
    assert_eq!(lifetime_of(options, Some(secs(60)), vec![]).await, Some(60));
    assert_eq!(lifetime_of(options, Some(secs(3)), vec![]).await, Some(10));
    assert_eq!(
        lifetime_of(options, Some(secs(86_400)), vec![]).await,
        Some(5000)
    );
}

#[nativelink_test]
async fn unpinned_entry_the_origin_forbids_reusing_is_stale_at_once() {
    // Not lifted to the minimum.
    assert_eq!(
        lifetime_of(limits(1000, 10, 5000), Some(Duration::ZERO), vec![]).await,
        Some(0)
    );
}

#[nativelink_test]
async fn pinned_entry_never_expires_whatever_the_headers_say() {
    let checksum = ByteChecksum::from_qualifier(
        "checksum.sha256",
        &sha256_digest_of(b"payload").packed_hash().to_string(),
    )
    .unwrap();
    let options = limits(1000, 10, 5000);
    for freshness in [
        None,
        Some(secs(1)),
        Some(Duration::ZERO),
        Some(secs(99_999)),
    ] {
        assert_eq!(
            lifetime_of(options, freshness, vec![checksum.clone()]).await,
            None,
            "{freshness:?}"
        );
    }
}

#[nativelink_test]
async fn pinned_directory_never_expires_and_unpinned_directory_does() {
    for (pinned, expected) in [(true, None), (false, Some(1000))] {
        let ac_store = memory_store().await;
        let cas_store = memory_store().await;
        let root = upload_directory(&cas_store, &Directory::default()).await;
        let inner: Arc<dyn Fetcher> = Arc::new(OkFetcher {
            uri: "http://example/dir".to_string(),
            digest: root,
        });
        let mc =
            MetadataCache::with_options(inner, ac_store.clone(), cas_store, limits(1000, 10, 5000));
        let mut job = directory_job("http://example/dir");
        if !pinned {
            job.checksums.clear();
        }
        mc.fetch_directory(&job).await.unwrap();

        let key = key_of(
            AssetKind::Directory,
            "http://example/dir",
            proto_qualifiers(),
        );
        let action_result = stored_action_result(&ac_store, key).await;
        let stored_at = action_result
            .execution_metadata
            .as_ref()
            .unwrap()
            .worker_start_timestamp
            .unwrap();
        assert_eq!(
            stored_metadata(&action_result)
                .expire_at
                .map(|expire_at| expire_at.seconds - stored_at.seconds),
            expected,
            "pinned: {pinned}"
        );
    }
}

fn validators() -> Validators {
    Validators {
        etag: Some("\"v1\"".to_string()),
        last_modified: Some("Sun, 06 Nov 1994 08:49:37 GMT".to_string()),
    }
}

/// Fetches through a `MetadataCache` over an origin that gave `validators`, and
/// reads the entry back.
async fn entry_after_fetch(checksums: Vec<ByteChecksum>) -> RemoteAssetEntry {
    let ac_store = memory_store().await;
    let digest = sha256_digest_of(b"payload");
    let inner: Arc<dyn Fetcher> = Arc::new(HeaderFetcher {
        digest,
        freshness: None,
        validators: validators(),
    });
    let mc = MetadataCache::new(inner, ac_store.clone(), memory_store().await);
    let mut job = blob_job("http://example/blob", qualifiers());
    job.checksums = checksums;
    mc.fetch_blob(&job).await.unwrap();
    read_remote_asset_entry(
        &ac_store,
        &RemoteAssetQuery::new(
            AssetKind::Blob,
            "http://example/blob".to_string(),
            proto_qualifiers(),
        ),
        digest_function::Value::Sha256.into(),
    )
    .await
    .unwrap()
    .unwrap()
}

#[nativelink_test]
async fn unpinned_entry_stores_the_validators() {
    let entry = entry_after_fetch(vec![]).await;
    assert_eq!(entry.etag, validators().etag);
    assert_eq!(entry.last_modified, validators().last_modified);
}

#[nativelink_test]
async fn pinned_entry_stores_no_validators() {
    let checksum = ByteChecksum::from_qualifier(
        "checksum.sha256",
        &sha256_digest_of(b"payload").packed_hash().to_string(),
    )
    .unwrap();
    let entry = entry_after_fetch(vec![checksum]).await;
    assert_eq!(entry.etag, None);
    assert_eq!(entry.last_modified, None);
}

#[nativelink_test]
async fn a_revalidated_outcome_rewrites_the_entry_with_new_times() {
    let ac_store = memory_store().await;
    let digest = sha256_digest_of(b"payload");
    let inner: Arc<dyn Fetcher> = Arc::new(RevalidatedFetcher { digest });
    let mc = MetadataCache::new(inner, ac_store.clone(), memory_store().await);

    let outcome = mc
        .fetch_blob(&blob_job("http://example/blob", qualifiers()))
        .await
        .unwrap();

    assert!(outcome.revalidated);
    let key = key_of(AssetKind::Blob, "http://example/blob", proto_qualifiers());
    let action_result = stored_action_result(&ac_store, key).await;
    let stored_at = action_result
        .execution_metadata
        .as_ref()
        .unwrap()
        .worker_start_timestamp
        .unwrap();
    let metadata = stored_metadata(&action_result);
    // Freshness from the 304: ten minutes.
    assert_eq!(metadata.expire_at.unwrap().seconds - stored_at.seconds, 600);
    assert_eq!(metadata.etag, "\"v1\"");
}

/// An inner `Fetcher` that reports the content its caller offered as still
/// current.
#[derive(Debug)]
struct RevalidatedFetcher {
    digest: DigestInfo,
}

#[async_trait]
impl Fetcher for RevalidatedFetcher {
    async fn fetch_blob(&self, job: &FetchBlobTask) -> Result<FetchOutcome, Error> {
        Ok(FetchOutcome {
            freshness: Some(Duration::from_mins(10)),
            validators: validators(),
            revalidated: true,
            ..FetchOutcome::new(job.uris[0].clone(), self.digest)
        })
    }
    async fn fetch_directory(&self, _job: &FetchDirectoryJob) -> Result<FetchOutcome, Error> {
        Err(make_err!(Code::Unimplemented, "not used"))
    }
}

/// The Action Cache value of an entry written before validators were stored
/// has a `RemoteAssetMetadata` without them.
#[derive(Clone, PartialEq, prost::Message)]
struct LegacyMetadata {
    #[prost(string, tag = "1")]
    uri: String,
    #[prost(message, repeated, tag = "2")]
    qualifiers: Vec<Qualifier>,
    #[prost(message, optional, tag = "3")]
    expire_at: Option<Timestamp>,
    #[prost(int32, tag = "4")]
    digest_function: i32,
    #[prost(message, optional, tag = "5")]
    root_directory_digest: Option<Digest>,
}

#[nativelink_test]
async fn an_entry_without_validators_still_decodes() {
    let ac_store = memory_store().await;
    let digest = sha256_digest_of(b"payload");
    let legacy = LegacyMetadata {
        uri: "http://example/blob".to_string(),
        qualifiers: proto_qualifiers(),
        expire_at: None,
        digest_function: digest_function::Value::Sha256.into(),
        root_directory_digest: None,
    };
    let action_result = ActionResult {
        output_files: vec![OutputFile {
            path: "out".to_string(),
            digest: Some(digest.into()),
            ..Default::default()
        }],
        execution_metadata: Some(ExecutedActionMetadata {
            worker: "nativelink-remote-asset".to_string(),
            auxiliary_metadata: vec![prost_types::Any {
                type_url: "type.googleapis.com/nativelink.RemoteAssetMetadata".to_string(),
                value: legacy.encode_to_vec(),
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    let key = key_of(AssetKind::Blob, "http://example/blob", proto_qualifiers());
    ac_store
        .update_oneshot(key, action_result.encode_to_vec().into())
        .await
        .unwrap();

    let entry = read_remote_asset_entry(
        &ac_store,
        &RemoteAssetQuery::new(
            AssetKind::Blob,
            "http://example/blob".to_string(),
            proto_qualifiers(),
        ),
        digest_function::Value::Sha256.into(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(entry.digest, Digest::from(digest));
    assert_eq!(entry.etag, None);
    assert_eq!(entry.last_modified, None);
    assert!(entry.references_blobs.is_empty());
    assert!(entry.references_directories.is_empty());
}

/// Writes an entry of `kind` for the tree `upload_nested_directories` uploads
/// (its root for a directory, `a.txt` for a blob) with the given references,
/// and reads it back.
async fn round_trip(
    kind: AssetKind,
    references_blobs: Vec<Digest>,
    references_directories: Vec<Digest>,
) -> (ActionResult, RemoteAssetEntry) {
    let ac_store = memory_store().await;
    let cas_store = memory_store().await;
    let (root, _, _) = upload_nested_directories(&cas_store).await;
    let digest: Digest = match kind {
        AssetKind::Blob => sha256_digest_of(b"a").into(),
        AssetKind::Directory => root.into(),
    };
    let query = RemoteAssetQuery::new(kind, "http://example/asset".to_string(), proto_qualifiers());
    write_remote_asset_entry(
        &ac_store,
        Some(&cas_store),
        &RemoteAssetEntry {
            query: query.clone(),
            digest: digest.clone(),
            expire_at: None,
            stored_at: None,
            digest_function: digest_function::Value::Sha256.into(),
            tree_digest: None,
            etag: None,
            last_modified: None,
            references_blobs: references_blobs.clone(),
            references_directories: references_directories.clone(),
        },
    )
    .await
    .unwrap();
    let action_result =
        stored_action_result(&ac_store, query.key(DigestHasherFunc::Sha256).unwrap()).await;
    let entry = read_remote_asset_entry(&ac_store, &query, digest_function::Value::Sha256.into())
        .await
        .unwrap()
        .expect("entry should be readable");
    assert_eq!(entry.digest, digest);
    assert_eq!(entry.tree_digest.is_some(), kind == AssetKind::Directory);
    assert_eq!(entry.references_blobs, references_blobs);
    assert_eq!(entry.references_directories, references_directories);
    (action_result, entry)
}

/// A Push's references are stored as extra outputs under paths of their own,
/// which `completeness_checking` checks, and read back without being taken
/// for the asset or its `Tree`.
#[nativelink_test]
async fn an_entry_with_references_round_trips() {
    let blobs: Vec<Digest> = vec![sha256_digest_of(b"b").into(), sha256_digest_of(b"c").into()];
    let cas_store = memory_store().await;
    let (_, sub, deep) = upload_nested_directories(&cas_store).await;
    let directories: Vec<Digest> = vec![sub.into(), deep.into()];

    for kind in [AssetKind::Blob, AssetKind::Directory] {
        let (action_result, _) = round_trip(kind, blobs.clone(), directories.clone()).await;
        let file_paths: Vec<&str> = action_result
            .output_files
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        let directory_paths: Vec<&str> = action_result
            .output_directories
            .iter()
            .map(|directory| directory.path.as_str())
            .collect();
        let (mut expected_files, mut expected_directories) = match kind {
            AssetKind::Blob => (vec!["out"], vec![]),
            AssetKind::Directory => (vec![], vec!["out"]),
        };
        expected_files.extend(["references/blobs/0", "references/blobs/1"]);
        expected_directories.extend(["references/directories/0", "references/directories/1"]);
        assert_eq!(file_paths, expected_files);
        assert_eq!(directory_paths, expected_directories);
        // A referenced directory is named by its root `Directory`, with no
        // `Tree`, so `completeness_checking` walks it from the root.
        for directory in &action_result.output_directories[expected_directories.len() - 2..] {
            assert_eq!(directory.tree_digest, None);
            assert!(directory.root_directory_digest.is_some());
        }
    }
}

/// Without references an entry is written exactly as before they were stored:
/// a single output, which still decodes.
#[nativelink_test]
async fn an_entry_without_references_round_trips() {
    for kind in [AssetKind::Blob, AssetKind::Directory] {
        let (action_result, _) = round_trip(kind, vec![], vec![]).await;
        assert_eq!(
            action_result.output_files.len() + action_result.output_directories.len(),
            1
        );
    }
}
