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

use nativelink_config::cas_server::{FetchConfig, WithInstanceName};
use nativelink_config::stores::{CompletenessCheckingSpec, MemorySpec, RefSpec, StoreSpec};
use nativelink_error::Error;
use nativelink_fetch::remote_asset_proto::{
    AssetKind, RemoteAssetEntry, RemoteAssetQuery, now_timestamp, write_remote_asset_entry,
};
use nativelink_macro::nativelink_test;
use nativelink_proto::build::bazel::remote::asset::v1::fetch_server::Fetch;
use nativelink_proto::build::bazel::remote::asset::v1::{
    FetchBlobRequest, FetchBlobResponse, Qualifier,
};
use nativelink_proto::build::bazel::remote::execution::v2::{
    ActionResult, Digest, digest_function,
};
use nativelink_proto::google::rpc::Status as GoogleStatus;
use nativelink_service::fetch_server::FetchServer;
use nativelink_store::default_store_factory::store_factory;
use nativelink_store::store_manager::StoreManager;
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::DigestHasherFunc;
use nativelink_util::store_trait::StoreLike;
use prost::Message;
use tonic::{Code, Request, Status};

/// Builds the stores a fetch service uses: a CAS, an Action Cache, and the
/// fetch store, which is that Action Cache wrapped in a `completeness_checking`
/// store over the CAS, as recommended for production.
async fn make_store_manager() -> Result<Arc<StoreManager>, Error> {
    let store_manager = Arc::new(StoreManager::new());
    for name in ["test_cas_store", "test_ac_store"] {
        store_manager.add_store(
            name,
            store_factory(
                &StoreSpec::Memory(MemorySpec::default()),
                &store_manager,
                None,
            )
            .await?,
        )?;
    }
    let ref_store = |name: &str| {
        StoreSpec::RefStore(RefSpec {
            name: name.to_string(),
        })
    };
    store_manager.add_store(
        "test_fetch_store",
        store_factory(
            &StoreSpec::CompletenessChecking(Box::new(CompletenessCheckingSpec {
                backend: ref_store("test_ac_store"),
                cas_store: ref_store("test_cas_store"),
            })),
            &store_manager,
            None,
        )
        .await?,
    )?;
    store_manager.run_post_init().await?;
    Ok(store_manager)
}

#[nativelink_test]
async fn test_fetch_blob() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let instance_name = "foo_instance_name".to_string();
    let fs = FetchServer::new(
        &[WithInstanceName {
            instance_name: instance_name.clone(),
            config: FetchConfig {
                fetch_store: String::from("test_fetch_store"),
            },
        }],
        &store_manager,
    )
    .expect("FetchServer config error");

    let digest = Digest {
        hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        size_bytes: 4,
    };
    // The content is in the CAS, so the completeness check passes.
    store_manager
        .get_store("test_cas_store")
        .unwrap()
        .update_oneshot(DigestInfo::try_from(&digest).unwrap(), vec![0; 4].into())
        .await
        .unwrap();
    write_entry(
        &store_manager,
        AssetKind::Blob,
        "http://1234",
        vec![Qualifier {
            name: "bazel.canonical_id".to_owned(),
            value: "test".to_owned(),
        }],
        digest,
        None,
        None,
    )
    .await;

    let raw_response: tonic::Response<FetchBlobResponse> = fs
        .fetch_blob(Request::new(FetchBlobRequest {
            instance_name,
            timeout: None,
            oldest_content_accepted: None,
            uris: vec!["http://1234".to_owned()],
            qualifiers: vec![Qualifier {
                name: "bazel.canonical_id".to_owned(),
                value: "test".to_owned(),
            }],
            digest_function: 0,
        }))
        .await?;
    assert_eq!(
        raw_response.into_inner(),
        FetchBlobResponse {
            status: Some(GoogleStatus {
                code: 0,
                message: "Fetch object found".to_owned(),
                details: vec![]
            }),
            uri: "http://1234".to_owned(),
            qualifiers: vec![Qualifier {
                name: "bazel.canonical_id".to_owned(),
                value: "test".to_owned(),
            }],
            expires_at: None,
            blob_digest: Some(Digest {
                hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned(),
                size_bytes: 4
            }),
            digest_function: i32::from(digest_function::Value::Sha256)
        }
    );
    Ok(())
}

const HELLO_WORLD: &[u8] = b"hello world";
const HELLO_WORLD_SHA256_HEX: &str =
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

fn blob_request(uris: Vec<String>, qualifiers: Vec<Qualifier>) -> Request<FetchBlobRequest> {
    Request::new(FetchBlobRequest {
        instance_name: "foo_instance_name".to_string(),
        timeout: None,
        oldest_content_accepted: None,
        uris,
        qualifiers,
        digest_function: 0,
    })
}

/// Builds a lookup-only `FetchServer` (no fetcher) over the completeness-checked
/// `test_fetch_store`.
fn make_lookup_server(store_manager: &StoreManager) -> FetchServer {
    FetchServer::new(
        &[WithInstanceName {
            instance_name: "foo_instance_name".to_string(),
            config: FetchConfig {
                fetch_store: String::from("test_fetch_store"),
            },
        }],
        store_manager,
    )
    .expect("FetchServer config error")
}

/// The Action Cache key of the blob entry for `uri` and `qualifiers`, under the
/// default digest function.
fn blob_key(uri: &str, qualifiers: Vec<Qualifier>) -> DigestInfo {
    RemoteAssetQuery::new(AssetKind::Blob, uri.to_owned(), qualifiers)
        .key(DigestHasherFunc::Sha256)
        .unwrap()
}

/// Writes an entry for `uri` -> `digest` through the fetch store, like a Push
/// or the `MetadataCache` would.
async fn write_entry(
    store_manager: &StoreManager,
    kind: AssetKind,
    uri: &str,
    qualifiers: Vec<Qualifier>,
    digest: Digest,
    expire_at: Option<prost_types::Timestamp>,
    stored_at: Option<prost_types::Timestamp>,
) {
    let fetch_store = store_manager.get_store("test_fetch_store").unwrap();
    write_remote_asset_entry(
        &fetch_store,
        &RemoteAssetEntry {
            query: RemoteAssetQuery::new(kind, uri.to_owned(), qualifiers),
            digest,
            expire_at,
            stored_at,
            digest_function: 0,
        },
    )
    .await
    .unwrap();
}

/// Records `uri` -> the `HELLO_WORLD` blob in the metadata store without putting
/// the blob in the CAS.
async fn seed_hello_world_metadata(store_manager: &StoreManager, uri: &str) -> Digest {
    let digest = Digest {
        hash: HELLO_WORLD_SHA256_HEX.to_owned(),
        size_bytes: i64::try_from(HELLO_WORLD.len()).unwrap(),
    };
    write_entry(
        store_manager,
        AssetKind::Blob,
        uri,
        vec![],
        digest.clone(),
        None,
        None,
    )
    .await;
    digest
}

#[nativelink_test]
async fn test_fetch_blob_corrupt_metadata_entry_is_a_miss() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = FetchServer::new(
        &[WithInstanceName {
            instance_name: "foo_instance_name".to_string(),
            config: FetchConfig {
                fetch_store: String::from("test_fetch_store"),
            },
        }],
        &store_manager,
    )
    .expect("FetchServer config error");

    // Store bytes that are not a valid `ActionResult` under the key the request
    // will look up.
    let uri = "http://example.invalid/blob".to_owned();
    store_manager
        .get_store("test_ac_store")
        .unwrap()
        .update_oneshot(blob_key(&uri, vec![]), vec![0xff; 8].into())
        .await
        .unwrap();

    let response = fs
        .fetch_blob(blob_request(vec![uri], vec![]))
        .await?
        .into_inner();
    assert_eq!(
        response.status.as_ref().map(|s| s.code),
        Some(i32::from(Code::NotFound))
    );
    assert!(response.blob_digest.is_none());
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_present_in_cas_is_a_hit() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_lookup_server(&store_manager);
    let uri = "http://example.invalid/blob".to_owned();
    let digest = seed_hello_world_metadata(&store_manager, &uri).await;
    store_manager
        .get_store("test_cas_store")
        .unwrap()
        .update_oneshot(
            DigestInfo::try_from(&digest).unwrap(),
            HELLO_WORLD.to_vec().into(),
        )
        .await
        .unwrap();

    let response = fs
        .fetch_blob(blob_request(vec![uri], vec![]))
        .await?
        .into_inner();
    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    assert_eq!(response.blob_digest, Some(digest));
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_missing_from_cas_is_a_miss() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_lookup_server(&store_manager);
    let uri = "http://example.invalid/blob".to_owned();
    seed_hello_world_metadata(&store_manager, &uri).await;

    // The metadata entry exists but the blob was evicted from the CAS.
    let response = fs
        .fetch_blob(blob_request(vec![uri], vec![]))
        .await?
        .into_inner();
    assert_eq!(
        response.status.as_ref().map(|s| s.code),
        Some(i32::from(Code::NotFound))
    );
    assert!(response.blob_digest.is_none());
    Ok(())
}

/// Decodes the `ActionResult` stored in `test_ac_store` for an asset.
async fn stored_action_result(
    store_manager: &StoreManager,
    kind: AssetKind,
    uri: &str,
    qualifiers: Vec<Qualifier>,
) -> ActionResult {
    let key = RemoteAssetQuery::new(kind, uri.to_owned(), qualifiers)
        .key(DigestHasherFunc::Sha256)
        .unwrap();
    let raw = store_manager
        .get_store("test_ac_store")
        .unwrap()
        .get_part_unchunked(key, 0, None)
        .await
        .expect("entry should be stored");
    ActionResult::decode(raw).expect("entry should be an ActionResult")
}

#[nativelink_test]
async fn test_fetch_blob_valid_action_result_that_is_not_an_entry_is_a_miss() -> Result<(), Status>
{
    let store_manager = make_store_manager().await?;
    let fs = make_lookup_server(&store_manager);
    let uri = "http://example.invalid/blob".to_owned();
    // A well-formed `ActionResult` under the key, but without our metadata.
    store_manager
        .get_store("test_ac_store")
        .unwrap()
        .update_oneshot(
            blob_key(&uri, vec![]),
            ActionResult::default().encode_to_vec().into(),
        )
        .await
        .unwrap();

    let response = fs
        .fetch_blob(blob_request(vec![uri], vec![]))
        .await?
        .into_inner();
    assert_eq!(
        response.status.as_ref().map(|s| s.code),
        Some(i32::from(Code::NotFound))
    );
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_entries_are_per_digest_function() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_lookup_server(&store_manager);
    let uri = "http://example.invalid/blob";
    let digest = seed_hello_world_metadata(&store_manager, uri).await;
    store_manager
        .get_store("test_cas_store")
        .unwrap()
        .update_oneshot(
            DigestInfo::try_from(&digest).unwrap(),
            HELLO_WORLD.to_vec().into(),
        )
        .await
        .unwrap();
    let fetch = |digest_function: digest_function::Value| {
        let mut request = blob_request(vec![uri.to_owned()], vec![]);
        request.get_mut().digest_function = i32::from(digest_function);
        fs.fetch_blob(request)
    };

    // Written with the default (SHA256) digest function: found by a request for
    // SHA256, not by one for BLAKE3.
    let found = fetch(digest_function::Value::Sha256).await?.into_inner();
    assert_eq!(found.blob_digest, Some(digest));
    let not_found = fetch(digest_function::Value::Blake3).await?.into_inner();
    assert!(not_found.blob_digest.is_none());
    Ok(())
}

/// A timestamp `secs` seconds before now (or after, when negative).
fn timestamp_ago(secs: i64) -> prost_types::Timestamp {
    let mut now = now_timestamp();
    now.seconds -= secs;
    now
}

/// Like [`seed_hello_world_metadata`], with the entry's `expire_at` and
/// `stored_at` set, and the blob itself put in the CAS.
async fn seed_hello_world_with_times(
    store_manager: &StoreManager,
    uri: &str,
    expire_at: Option<prost_types::Timestamp>,
    stored_at: Option<prost_types::Timestamp>,
) -> Digest {
    let digest = Digest {
        hash: HELLO_WORLD_SHA256_HEX.to_owned(),
        size_bytes: i64::try_from(HELLO_WORLD.len()).unwrap(),
    };
    write_entry(
        store_manager,
        AssetKind::Blob,
        uri,
        vec![],
        digest.clone(),
        expire_at,
        stored_at,
    )
    .await;
    store_manager
        .get_store("test_cas_store")
        .unwrap()
        .update_oneshot(
            DigestInfo::try_from(&digest).unwrap(),
            HELLO_WORLD.to_vec().into(),
        )
        .await
        .unwrap();
    digest
}

fn blob_request_oldest(
    uri: &str,
    oldest_content_accepted: Option<prost_types::Timestamp>,
) -> Request<FetchBlobRequest> {
    Request::new(FetchBlobRequest {
        instance_name: "foo_instance_name".to_string(),
        timeout: None,
        oldest_content_accepted,
        uris: vec![uri.to_owned()],
        qualifiers: vec![],
        digest_function: 0,
    })
}

#[nativelink_test]
async fn test_fetch_blob_expired_entry_is_a_miss() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_lookup_server(&store_manager);
    let uri = "http://example.invalid/blob";
    seed_hello_world_with_times(&store_manager, uri, Some(timestamp_ago(60)), None).await;

    let response = fs
        .fetch_blob(blob_request_oldest(uri, None))
        .await?
        .into_inner();
    assert_eq!(
        response.status.as_ref().map(|s| s.code),
        Some(i32::from(Code::NotFound))
    );
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_unexpired_entry_is_a_hit_and_reports_expires_at() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_lookup_server(&store_manager);
    let uri = "http://example.invalid/blob";
    let expire_at = timestamp_ago(-3600);
    let digest = seed_hello_world_with_times(&store_manager, uri, Some(expire_at), None).await;

    let response = fs
        .fetch_blob(blob_request_oldest(uri, None))
        .await?
        .into_inner();
    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    assert_eq!(response.blob_digest, Some(digest));
    assert_eq!(response.expires_at, Some(expire_at));
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_oldest_content_accepted() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_lookup_server(&store_manager);
    let uri = "http://example.invalid/blob";
    let found = |response: &FetchBlobResponse| response.status.as_ref().map(|s| s.code) == Some(0);

    // Stored 100s ago.
    seed_hello_world_with_times(&store_manager, uri, None, Some(timestamp_ago(100))).await;
    // Accepting content from the last hour: hit. From the last 10s: too old.
    let response = fs
        .fetch_blob(blob_request_oldest(uri, Some(timestamp_ago(3600))))
        .await?
        .into_inner();
    assert!(found(&response));
    let response = fs
        .fetch_blob(blob_request_oldest(uri, Some(timestamp_ago(10))))
        .await?
        .into_inner();
    assert!(!found(&response));
    // Without `oldest_content_accepted`, any age is accepted.
    let response = fs
        .fetch_blob(blob_request_oldest(uri, None))
        .await?
        .into_inner();
    assert!(found(&response));

    // An entry with no start timestamp (one that something else wrote) can not
    // be shown to be new enough.
    let key = blob_key(uri, vec![]);
    let ac_store = store_manager.get_store("test_ac_store").unwrap();
    let mut action_result =
        stored_action_result(&store_manager, AssetKind::Blob, uri, vec![]).await;
    action_result
        .execution_metadata
        .as_mut()
        .unwrap()
        .worker_start_timestamp = None;
    ac_store
        .update_oneshot(key, action_result.encode_to_vec().into())
        .await
        .unwrap();
    let response = fs
        .fetch_blob(blob_request_oldest(uri, Some(timestamp_ago(3600))))
        .await?
        .into_inner();
    assert!(!found(&response));
    let response = fs
        .fetch_blob(blob_request_oldest(uri, None))
        .await?
        .into_inner();
    assert!(found(&response));
    Ok(())
}
