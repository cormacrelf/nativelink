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

use std::collections::HashMap;
use std::sync::Arc;

use nativelink_config::cas_server::{FetchConfig, PushConfig, WithInstanceName};
use nativelink_config::stores::{CompletenessCheckingSpec, MemorySpec, RefSpec, StoreSpec};
use nativelink_error::Error;
use nativelink_fetch::remote_asset_proto::{AssetKind, RemoteAssetMetadata, RemoteAssetQuery};
use nativelink_macro::nativelink_test;
use nativelink_proto::build::bazel::remote::asset::v1::fetch_server::Fetch;
use nativelink_proto::build::bazel::remote::asset::v1::push_server::Push;
use nativelink_proto::build::bazel::remote::asset::v1::{
    FetchBlobRequest, PushBlobRequest, PushBlobResponse, Qualifier,
};
use nativelink_proto::build::bazel::remote::execution::v2::{
    ActionResult, Digest, digest_function,
};
use nativelink_service::fetch_server::FetchServer;
use nativelink_service::push_server::PushServer;
use nativelink_store::default_store_factory::store_factory;
use nativelink_store::store_manager::StoreManager;
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::{DigestHasher, DigestHasherFunc};
use nativelink_util::store_trait::{Store, StoreLike};
use prost::Message;
use tonic::{Code, Request, Status};

const INSTANCE_NAME: &str = "foo_instance_name";

/// Builds the stores a push/fetch pair uses: a CAS, an Action Cache, and the
/// push store, which is that Action Cache wrapped in a `completeness_checking`
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
        "test_push_store",
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

fn make_push_server(store_manager: &StoreManager, read_only: bool) -> PushServer {
    PushServer::new(
        &[WithInstanceName {
            instance_name: INSTANCE_NAME.to_string(),
            config: PushConfig {
                push_store: String::from("test_push_store"),
                read_only,
            },
        }],
        store_manager,
    )
    .expect("PushServer config error")
}

fn make_fetch_server(store_manager: &StoreManager) -> FetchServer {
    FetchServer::new(
        &[WithInstanceName {
            instance_name: INSTANCE_NAME.to_string(),
            config: FetchConfig {
                fetch_store: String::from("test_push_store"),
                fetcher: None,
            },
        }],
        &HashMap::new(),
        store_manager,
    )
    .expect("FetchServer config error")
}

fn test_qualifiers() -> Vec<Qualifier> {
    vec![Qualifier {
        name: "bazel.canonical_id".to_owned(),
        value: "test".to_owned(),
    }]
}

fn sha256_digest_of(data: &[u8]) -> DigestInfo {
    let mut hasher = DigestHasherFunc::Sha256.hasher();
    hasher.update(data);
    hasher.finalize_digest()
}

/// Stores `data` in the CAS under its SHA256 digest and returns that digest.
async fn put_blob(store_manager: &StoreManager, data: &[u8]) -> Digest {
    let info = sha256_digest_of(data);
    store_manager
        .get_store("test_cas_store")
        .unwrap()
        .update_oneshot(info, data.to_vec().into())
        .await
        .unwrap();
    info.into()
}

fn push_blob_request(uris: Vec<String>, blob_digest: Option<Digest>) -> PushBlobRequest {
    PushBlobRequest {
        instance_name: INSTANCE_NAME.to_string(),
        uris,
        qualifiers: test_qualifiers(),
        expire_at: None,
        blob_digest,
        references_blobs: vec![],
        references_directories: vec![],
        digest_function: 0,
    }
}

fn fetch_blob_request(
    uri: &str,
    qualifiers: Vec<Qualifier>,
    digest_function: i32,
) -> FetchBlobRequest {
    FetchBlobRequest {
        instance_name: INSTANCE_NAME.to_string(),
        timeout: None,
        oldest_content_accepted: None,
        uris: vec![uri.to_owned()],
        qualifiers,
        digest_function,
    }
}

/// Reads and decodes the `ActionResult` a push stored in the Action Cache for
/// an asset, looked up under the default digest function.
async fn stored_action_result(
    store_manager: &StoreManager,
    kind: AssetKind,
    uri: &str,
    qualifiers: Vec<Qualifier>,
) -> ActionResult {
    let key = RemoteAssetQuery::new(kind, uri.to_owned(), qualifiers)
        .key(DigestHasherFunc::Sha256)
        .unwrap();
    let ac_store: Store = store_manager.get_store("test_ac_store").unwrap();
    let raw = ac_store
        .get_part_unchunked(key, 0, None)
        .await
        .expect("the push should have stored an entry");
    ActionResult::decode(raw).expect("the entry should be an ActionResult")
}

fn stored_metadata(action_result: &ActionResult) -> RemoteAssetMetadata {
    let execution_metadata = action_result.execution_metadata.as_ref().unwrap();
    assert_eq!(execution_metadata.worker, "nativelink-remote-asset");
    assert!(execution_metadata.worker_start_timestamp.is_some());
    assert!(execution_metadata.worker_completed_timestamp.is_some());
    assert_eq!(execution_metadata.auxiliary_metadata.len(), 1);
    let any = &execution_metadata.auxiliary_metadata[0];
    assert_eq!(
        any.type_url,
        "type.googleapis.com/nativelink.RemoteAssetMetadata"
    );
    RemoteAssetMetadata::decode(any.value.as_slice()).unwrap()
}

#[nativelink_test]
async fn test_push_blob() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let ps = make_push_server(&store_manager, false);
    let digest = put_blob(&store_manager, b"hello").await;
    let raw_response = ps
        .push_blob(Request::new(push_blob_request(
            vec!["http://1234".to_owned()],
            Some(digest.clone()),
        )))
        .await?;
    assert_eq!(raw_response.into_inner(), PushBlobResponse {});

    let action_result = stored_action_result(
        &store_manager,
        AssetKind::Blob,
        "http://1234",
        test_qualifiers(),
    )
    .await;
    assert_eq!(action_result.output_files.len(), 1);
    assert_eq!(action_result.output_files[0].path, "out");
    assert_eq!(action_result.output_files[0].digest, Some(digest));
    assert!(!action_result.output_files[0].is_executable);
    assert!(action_result.output_directories.is_empty());
    assert_eq!(
        stored_metadata(&action_result),
        RemoteAssetMetadata {
            uri: "http://1234".to_owned(),
            qualifiers: test_qualifiers(),
            expire_at: None,
            digest_function: i32::from(digest_function::Value::Sha256),
        }
    );
    Ok(())
}

#[nativelink_test]
async fn test_push_blob_is_fetchable() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let ps = make_push_server(&store_manager, false);
    let fs = make_fetch_server(&store_manager);
    let digest = put_blob(&store_manager, b"hello").await;
    let mut request = push_blob_request(
        vec!["http://1234".to_owned(), "http://5678".to_owned()],
        Some(digest.clone()),
    );
    request.digest_function = i32::from(digest_function::Value::Sha256);
    ps.push_blob(Request::new(request)).await?;

    // Each URI is retrievable on its own.
    for uri in ["http://1234", "http://5678"] {
        let response = fs
            .fetch_blob(Request::new(fetch_blob_request(
                uri,
                test_qualifiers(),
                i32::from(digest_function::Value::Sha256),
            )))
            .await?
            .into_inner();
        assert_eq!(response.status.unwrap().code, i32::from(Code::Ok));
        assert_eq!(response.uri, uri);
        assert_eq!(response.qualifiers, test_qualifiers());
        assert_eq!(response.blob_digest, Some(digest.clone()));
        assert_eq!(
            response.digest_function,
            i32::from(digest_function::Value::Sha256)
        );
    }
    Ok(())
}

#[nativelink_test]
async fn test_push_with_unset_digest_function_is_fetched_with_the_resolved_one()
-> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let ps = make_push_server(&store_manager, false);
    let fs = make_fetch_server(&store_manager);
    let blob = put_blob(&store_manager, b"hello").await;
    ps.push_blob(Request::new(push_blob_request(
        vec!["http://1234".to_owned()],
        Some(blob),
    )))
    .await?;

    // The request leaves the digest function unset, as the push did; a hit
    // reports the function in effect, like a miss that was then fetched does.
    let blob_response = fs
        .fetch_blob(Request::new(fetch_blob_request(
            "http://1234",
            test_qualifiers(),
            0,
        )))
        .await?
        .into_inner();
    assert_eq!(blob_response.status.unwrap().code, i32::from(Code::Ok));
    assert_eq!(
        blob_response.digest_function,
        i32::from(digest_function::Value::Sha256)
    );
    Ok(())
}

#[nativelink_test]
async fn test_push_blob_whose_content_is_not_in_the_cas_is_not_fetchable() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let ps = make_push_server(&store_manager, false);
    let fs = make_fetch_server(&store_manager);
    // The blob was never uploaded (or has been evicted since).
    let digest = Digest::from(sha256_digest_of(b"hello"));
    ps.push_blob(Request::new(push_blob_request(
        vec!["http://1234".to_owned()],
        Some(digest),
    )))
    .await?;

    let response = fs
        .fetch_blob(Request::new(fetch_blob_request(
            "http://1234",
            test_qualifiers(),
            0,
        )))
        .await?
        .into_inner();
    assert_eq!(response.status.unwrap().code, i32::from(Code::NotFound));
    assert!(response.blob_digest.is_none());
    Ok(())
}

#[nativelink_test]
async fn test_push_blob_is_found_only_with_the_same_digest_function() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let ps = make_push_server(&store_manager, false);
    let fs = make_fetch_server(&store_manager);
    let digest = put_blob(&store_manager, b"hello").await;
    let mut request = push_blob_request(vec!["http://1234".to_owned()], Some(digest.clone()));
    request.digest_function = i32::from(digest_function::Value::Blake3);
    ps.push_blob(Request::new(request)).await?;

    let response = fs
        .fetch_blob(Request::new(fetch_blob_request(
            "http://1234",
            test_qualifiers(),
            i32::from(digest_function::Value::Blake3),
        )))
        .await?
        .into_inner();
    assert_eq!(response.blob_digest, Some(digest));
    let response = fs
        .fetch_blob(Request::new(fetch_blob_request(
            "http://1234",
            test_qualifiers(),
            i32::from(digest_function::Value::Sha256),
        )))
        .await?
        .into_inner();
    assert!(response.blob_digest.is_none());
    Ok(())
}

fn credential_qualifiers() -> Vec<Qualifier> {
    let mut qualifiers = test_qualifiers();
    qualifiers.push(Qualifier {
        name: "http_header:Authorization".to_owned(),
        value: "Bearer secret".to_owned(),
    });
    qualifiers.push(Qualifier {
        name: "http_header_url:0:X-Token".to_owned(),
        value: "secret".to_owned(),
    });
    qualifiers
}

#[nativelink_test]
async fn test_push_does_not_persist_http_header_qualifiers() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let ps = make_push_server(&store_manager, false);
    let blob = put_blob(&store_manager, b"hello").await;

    // Header qualifiers are not part of the key, so the entry is found by the
    // key the fetch side computes without them, and holds none of them.
    let mut blob_request = push_blob_request(vec!["http://1234".to_owned()], Some(blob));
    blob_request.qualifiers = credential_qualifiers();
    ps.push_blob(Request::new(blob_request)).await?;
    let action_result = stored_action_result(
        &store_manager,
        AssetKind::Blob,
        "http://1234",
        test_qualifiers(),
    )
    .await;
    assert_eq!(
        stored_metadata(&action_result).qualifiers,
        test_qualifiers()
    );
    assert!(
        !action_result
            .encode_to_vec()
            .windows(6)
            .any(|window| window == b"secret")
    );
    Ok(())
}

#[nativelink_test]
async fn test_fetch_finds_a_push_regardless_of_qualifier_order_and_headers() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let ps = make_push_server(&store_manager, false);
    let fs = make_fetch_server(&store_manager);
    let digest = put_blob(&store_manager, b"hello").await;
    let qualifier = |name: &str, value: &str| Qualifier {
        name: name.to_owned(),
        value: value.to_owned(),
    };

    let mut request = push_blob_request(vec!["http://1234".to_owned()], Some(digest.clone()));
    request.qualifiers = vec![
        qualifier("bazel.canonical_id", "x"),
        qualifier("checksum.sri", "sha256-abc"),
        qualifier("http_header:Authorization", "Bearer one"),
    ];
    ps.push_blob(Request::new(request)).await?;

    let response = fs
        .fetch_blob(Request::new(fetch_blob_request(
            "http://1234",
            vec![
                qualifier("http_header:Authorization", "Bearer two"),
                qualifier("checksum.sri", "sha256-abc"),
                qualifier("bazel.canonical_id", "x"),
            ],
            0,
        )))
        .await?
        .into_inner();
    assert_eq!(response.blob_digest, Some(digest));
    Ok(())
}
