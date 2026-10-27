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

use std::sync::Arc;

use nativelink_config::stores::{MemorySpec, StoreSpec};
use nativelink_error::{Code, Error, make_err};
use nativelink_fetch::fetcher::{FetchBlobTask, FetchHeaders, FetchOutcome, Fetcher};
use nativelink_fetch::metadata_cache::MetadataCache;
use nativelink_fetch::remote_asset_proto::{
    AssetKind, RemoteAssetMetadata, RemoteAssetQuery, read_remote_asset_entry, timestamp_is_before,
};
use nativelink_macro::nativelink_test;
use nativelink_proto::build::bazel::remote::asset::v1::Qualifier;
use nativelink_proto::build::bazel::remote::execution::v2::command::EnvironmentVariable;
use nativelink_proto::build::bazel::remote::execution::v2::{
    Action, ActionResult, Command, Digest, OutputFile, digest_function,
};
use nativelink_store::default_store_factory::store_factory;
use nativelink_store::store_manager::StoreManager;
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::{DigestHasher, DigestHasherFunc};
use nativelink_util::store_trait::{Store, StoreLike};
use prost::Message;
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
        Ok(FetchOutcome {
            uri: self.uri.clone(),
            digest: self.digest,
        })
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
        header_timeout: None,
        headers: FetchHeaders::default(),
    }
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
    let digest = DigestInfo::try_new(&"ab".repeat(32), 11).unwrap();
    let inner: Arc<dyn Fetcher> = Arc::new(OkFetcher {
        uri: "http://example/blob".to_string(),
        digest,
    });
    let mc = MetadataCache::new(inner, ac_store.clone());

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
    assert_eq!(metadata.expire_at, None);
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
        AssetKind::Blob,
        "http://example/blob".to_string(),
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
                "blob".to_string(),
                "http://example/blob".to_string(),
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
async fn does_not_write_metadata_on_failure() {
    let ac_store = memory_store().await;
    let inner: Arc<dyn Fetcher> = Arc::new(ErrFetcher);
    let mc = MetadataCache::new(inner, ac_store.clone());

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
    let mc = MetadataCache::new(inner, ac_store.clone());

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
