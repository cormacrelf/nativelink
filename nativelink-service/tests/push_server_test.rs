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
    FetchBlobRequest, FetchDirectoryRequest, PushBlobRequest, PushBlobResponse,
    PushDirectoryRequest, PushDirectoryResponse, Qualifier,
};
use nativelink_proto::build::bazel::remote::execution::v2::{
    ActionResult, Digest, Directory, DirectoryNode, FileNode, Tree, digest_function,
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
    make_push_server_with_cas(store_manager, read_only, Some("test_cas_store"))
}

fn make_push_server_with_cas(
    store_manager: &StoreManager,
    read_only: bool,
    cas_store: Option<&str>,
) -> PushServer {
    PushServer::new(
        &[WithInstanceName {
            instance_name: INSTANCE_NAME.to_string(),
            config: PushConfig {
                push_store: String::from("test_push_store"),
                cas_store: cas_store.map(String::from),
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

/// Uploads `directory` to the CAS and returns its digest.
async fn put_directory(store_manager: &StoreManager, directory: &Directory) -> Digest {
    put_blob(store_manager, &directory.encode_to_vec()).await
}

fn file_node(name: &str, digest: Digest) -> FileNode {
    FileNode {
        name: name.to_owned(),
        digest: Some(digest),
        ..Default::default()
    }
}

fn directory_node(name: &str, digest: Digest) -> DirectoryNode {
    DirectoryNode {
        name: name.to_owned(),
        digest: Some(digest),
    }
}

/// The directories of `root/{a.txt, sub/{b.txt, deep/c.txt}}` and the digests
/// of `(root, sub, deep)`, with all their files and protos put in the CAS.
async fn put_nested_directory(store_manager: &StoreManager) -> (Digest, Digest, Digest) {
    let deep = put_directory(
        store_manager,
        &Directory {
            files: vec![file_node("c.txt", put_blob(store_manager, b"c").await)],
            ..Default::default()
        },
    )
    .await;
    let sub = put_directory(
        store_manager,
        &Directory {
            files: vec![file_node("b.txt", put_blob(store_manager, b"b").await)],
            directories: vec![directory_node("deep", deep.clone())],
            ..Default::default()
        },
    )
    .await;
    let root = put_directory(
        store_manager,
        &Directory {
            files: vec![file_node("a.txt", put_blob(store_manager, b"a").await)],
            directories: vec![directory_node("sub", sub.clone())],
            ..Default::default()
        },
    )
    .await;
    (root, sub, deep)
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

fn push_directory_request(uris: Vec<String>, root: Option<Digest>) -> PushDirectoryRequest {
    PushDirectoryRequest {
        instance_name: INSTANCE_NAME.to_string(),
        uris,
        qualifiers: test_qualifiers(),
        expire_at: None,
        root_directory_digest: root,
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

fn fetch_directory_request(uri: &str, qualifiers: Vec<Qualifier>) -> FetchDirectoryRequest {
    FetchDirectoryRequest {
        instance_name: INSTANCE_NAME.to_string(),
        timeout: None,
        oldest_content_accepted: None,
        uris: vec![uri.to_owned()],
        qualifiers,
        digest_function: 0,
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
            root_directory_digest: None,
            etag: String::new(),
            last_modified: String::new(),
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
    let (root, _, _) = put_nested_directory(&store_manager).await;
    ps.push_blob(Request::new(push_blob_request(
        vec!["http://1234".to_owned()],
        Some(blob),
    )))
    .await?;
    ps.push_directory(Request::new(push_directory_request(
        vec!["http://1234".to_owned()],
        Some(root),
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
    let directory_response = fs
        .fetch_directory(Request::new(fetch_directory_request(
            "http://1234",
            test_qualifiers(),
        )))
        .await?
        .into_inner();
    assert_eq!(directory_response.status.unwrap().code, i32::from(Code::Ok));
    assert_eq!(
        directory_response.digest_function,
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

#[nativelink_test]
async fn test_push_directory() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let ps = make_push_server(&store_manager, false);
    let (root, sub, deep) = put_nested_directory(&store_manager).await;
    let raw_response = ps
        .push_directory(Request::new(push_directory_request(
            vec!["http://1234".to_owned()],
            Some(root.clone()),
        )))
        .await?;
    assert_eq!(raw_response.into_inner(), PushDirectoryResponse {});

    let action_result = stored_action_result(
        &store_manager,
        AssetKind::Directory,
        "http://1234",
        test_qualifiers(),
    )
    .await;
    assert!(action_result.output_files.is_empty());
    assert_eq!(action_result.output_directories.len(), 1);
    assert_eq!(action_result.output_directories[0].path, "out");
    let metadata = stored_metadata(&action_result);
    assert_eq!(metadata.uri, "http://1234");
    assert_eq!(metadata.qualifiers, test_qualifiers());
    assert_eq!(metadata.root_directory_digest, Some(root.clone()));

    // The `Tree` uploaded to the CAS has the root and every descendant
    // directory, including the nested one.
    let tree_digest = DigestInfo::try_from(
        action_result.output_directories[0]
            .tree_digest
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    let cas_store = store_manager.get_store("test_cas_store").unwrap();
    let tree = Tree::decode(
        cas_store
            .get_part_unchunked(tree_digest, 0, None)
            .await
            .unwrap(),
    )
    .unwrap();
    let digest_of =
        |directory: &Directory| Digest::from(sha256_digest_of(&directory.encode_to_vec()));
    assert_eq!(digest_of(tree.root.as_ref().unwrap()), root);
    let mut children: Vec<Digest> = tree.children.iter().map(digest_of).collect();
    children.sort_by(|a, b| a.hash.cmp(&b.hash));
    let mut expected = vec![sub, deep];
    expected.sort_by(|a, b| a.hash.cmp(&b.hash));
    assert_eq!(children, expected);
    Ok(())
}

#[nativelink_test]
async fn test_push_directory_is_fetchable() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let ps = make_push_server(&store_manager, false);
    let fs = make_fetch_server(&store_manager);
    let (root, _, _) = put_nested_directory(&store_manager).await;

    let mut request = push_directory_request(
        vec!["http://1234".to_owned(), "http://5678".to_owned()],
        Some(root.clone()),
    );
    request.digest_function = i32::from(digest_function::Value::Sha256);
    ps.push_directory(Request::new(request)).await?;

    // Each URI is retrievable on its own, as a directory only.
    for uri in ["http://1234", "http://5678"] {
        let mut request = fetch_directory_request(uri, test_qualifiers());
        request.digest_function = i32::from(digest_function::Value::Sha256);
        let response = fs
            .fetch_directory(Request::new(request))
            .await?
            .into_inner();
        assert_eq!(response.status.unwrap().code, i32::from(Code::Ok));
        assert_eq!(response.uri, uri);
        assert_eq!(response.qualifiers, test_qualifiers());
        assert_eq!(response.root_directory_digest, Some(root.clone()));
        assert_eq!(
            response.digest_function,
            i32::from(digest_function::Value::Sha256)
        );

        let blob_response = fs
            .fetch_blob(Request::new(fetch_blob_request(
                uri,
                test_qualifiers(),
                i32::from(digest_function::Value::Sha256),
            )))
            .await?
            .into_inner();
        assert_eq!(
            blob_response.status.unwrap().code,
            i32::from(Code::NotFound)
        );
    }
    Ok(())
}

#[nativelink_test]
async fn test_push_directory_with_a_missing_subdirectory_is_an_error() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let ps = make_push_server(&store_manager, false);
    let fs = make_fetch_server(&store_manager);
    // The root is in the CAS, but the `deep` directory it refers to through
    // `sub` is not.
    let deep = Directory {
        files: vec![file_node("c.txt", put_blob(&store_manager, b"c").await)],
        ..Default::default()
    };
    let sub = put_directory(
        &store_manager,
        &Directory {
            directories: vec![directory_node(
                "deep",
                Digest::from(sha256_digest_of(&deep.encode_to_vec())),
            )],
            ..Default::default()
        },
    )
    .await;
    let root = put_directory(
        &store_manager,
        &Directory {
            directories: vec![directory_node("sub", sub)],
            ..Default::default()
        },
    )
    .await;

    let err = ps
        .push_directory(Request::new(push_directory_request(
            vec!["http://1234".to_owned()],
            Some(root),
        )))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);

    // Nothing was recorded.
    let response = fs
        .fetch_directory(Request::new(fetch_directory_request(
            "http://1234",
            test_qualifiers(),
        )))
        .await?
        .into_inner();
    assert!(response.root_directory_digest.is_none());
    Ok(())
}

#[nativelink_test]
async fn test_push_directory_with_a_missing_root_is_an_error() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let ps = make_push_server(&store_manager, false);
    let err = ps
        .push_directory(Request::new(push_directory_request(
            vec!["http://1234".to_owned()],
            Some(Digest::from(sha256_digest_of(b"not uploaded"))),
        )))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    Ok(())
}

#[nativelink_test]
async fn test_push_directory_invalid_arguments() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let ps = make_push_server(&store_manager, false);
    let (root, _, _) = put_nested_directory(&store_manager).await;

    let no_uris = ps
        .push_directory(Request::new(push_directory_request(vec![], Some(root))))
        .await
        .unwrap_err();
    assert_eq!(no_uris.code(), Code::InvalidArgument);

    let no_digest = ps
        .push_directory(Request::new(push_directory_request(
            vec!["http://1234".to_owned()],
            None,
        )))
        .await
        .unwrap_err();
    assert_eq!(no_digest.code(), Code::InvalidArgument);
    Ok(())
}

#[nativelink_test]
async fn test_push_directory_read_only() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let ps = make_push_server(&store_manager, true);
    let (root, _, _) = put_nested_directory(&store_manager).await;
    let err = ps
        .push_directory(Request::new(push_directory_request(
            vec!["http://1234".to_owned()],
            Some(root),
        )))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    Ok(())
}

#[nativelink_test]
async fn test_push_directory_without_a_cas_store_is_a_failed_precondition() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let ps = make_push_server_with_cas(&store_manager, false, None);
    let (root, _, _) = put_nested_directory(&store_manager).await;
    let err = ps
        .push_directory(Request::new(push_directory_request(
            vec!["http://1234".to_owned()],
            Some(root),
        )))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(err.message().contains("cas_store"), "{}", err.message());

    // PushBlob does not need it.
    let blob = put_blob(&store_manager, b"hello").await;
    ps.push_blob(Request::new(push_blob_request(
        vec!["http://1234".to_owned()],
        Some(blob),
    )))
    .await?;
    Ok(())
}

#[nativelink_test]
async fn test_push_directory_stores_the_clients_root_digest() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let ps = make_push_server(&store_manager, false);
    let fs = make_fetch_server(&store_manager);
    let file = put_blob(&store_manager, b"hello").await;

    // A root `Directory` with an unknown field, which is dropped when it is
    // decoded, so re-encoding it gives different bytes (and a different digest).
    let mut root_bytes = Directory {
        files: vec![file_node("a.txt", file)],
        ..Default::default()
    }
    .encode_to_vec();
    root_bytes.extend_from_slice(&[0xa0, 0x06, 0x01]); // Field 100, varint 1.
    let root = put_blob(&store_manager, &root_bytes).await;
    let decoded = Directory::decode(root_bytes.as_slice()).unwrap();
    assert_ne!(
        Digest::from(sha256_digest_of(&decoded.encode_to_vec())),
        root
    );

    let mut request = push_directory_request(vec!["http://1234".to_owned()], Some(root.clone()));
    request.digest_function = i32::from(digest_function::Value::Sha256);
    ps.push_directory(Request::new(request)).await?;

    let mut request = fetch_directory_request("http://1234", test_qualifiers());
    request.digest_function = i32::from(digest_function::Value::Sha256);
    let response = fs
        .fetch_directory(Request::new(request))
        .await?
        .into_inner();
    assert_eq!(response.status.unwrap().code, i32::from(Code::Ok));
    assert_eq!(response.root_directory_digest, Some(root));
    Ok(())
}

#[nativelink_test]
async fn test_push_directory_with_uppercase_root_digest_is_fetched_in_lowercase()
-> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let ps = make_push_server(&store_manager, false);
    let fs = make_fetch_server(&store_manager);
    let (root, _, _) = put_nested_directory(&store_manager).await;
    let uppercase = Digest {
        hash: root.hash.to_uppercase(),
        size_bytes: root.size_bytes,
    };
    assert_ne!(uppercase, root);

    ps.push_directory(Request::new(push_directory_request(
        vec!["http://1234".to_owned()],
        Some(uppercase),
    )))
    .await?;

    let response = fs
        .fetch_directory(Request::new(fetch_directory_request(
            "http://1234",
            test_qualifiers(),
        )))
        .await?
        .into_inner();
    assert_eq!(response.status.unwrap().code, i32::from(Code::Ok));
    assert_eq!(response.root_directory_digest, Some(root));
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
    let (root, _, _) = put_nested_directory(&store_manager).await;
    let blob = put_blob(&store_manager, b"hello").await;

    // Header qualifiers are not part of the key, so both entries are found by
    // the key the fetch side computes without them, and hold none of them.
    let mut directory_request = push_directory_request(vec!["http://1234".to_owned()], Some(root));
    directory_request.qualifiers = credential_qualifiers();
    ps.push_directory(Request::new(directory_request)).await?;
    let action_result = stored_action_result(
        &store_manager,
        AssetKind::Directory,
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
