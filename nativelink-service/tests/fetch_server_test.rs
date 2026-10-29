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

use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use nativelink_config::cas_server::{FetchConfig, WithInstanceName};
use nativelink_config::fetchers::{BackgroundSpec, FetcherSpec, MetadataCacheSpec, UrlFetcherSpec};
use nativelink_config::stores::{CompletenessCheckingSpec, MemorySpec, RefSpec, StoreSpec};
use nativelink_error::Error;
use nativelink_fetch::fetcher::Fetcher;
use nativelink_fetch::fetcher_factory::fetcher_factory;
use nativelink_fetch::remote_asset_proto::{
    AssetKind, RemoteAssetEntry, RemoteAssetMetadata, RemoteAssetQuery, now_timestamp,
    write_remote_asset_entry,
};
use nativelink_macro::nativelink_test;
use nativelink_proto::build::bazel::remote::asset::v1::fetch_server::Fetch;
use nativelink_proto::build::bazel::remote::asset::v1::{
    FetchBlobRequest, FetchBlobResponse, Qualifier,
};
use nativelink_proto::build::bazel::remote::execution::v2::{
    ActionResult, Digest, digest_function,
};
use nativelink_proto::google::rpc::{BadRequest, ErrorInfo, Status as GoogleStatus};
use nativelink_service::fetch_server::{FetchServer, parse_grpc_timeout};
use nativelink_store::default_store_factory::store_factory;
use nativelink_store::store_manager::StoreManager;
use nativelink_util::background_spawn;
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::DigestHasherFunc;
use nativelink_util::store_trait::StoreLike;
use parking_lot::Mutex;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
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

/// Spawns a single-shot HTTP/1.1 server that serves `body` for the first
/// request it receives, then returns the URL pointing at it.
async fn serve_once(body: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    background_spawn!("fetch_test_http_server", async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        // Drain the request line and headers, reading until the terminating
        // blank line (`\r\n\r\n`). These are GET requests with no body, so the
        // headers are all we need to consume before replying.
        let mut request = Vec::new();
        let mut buf = [0u8; 2048];
        loop {
            let read = socket.read(&mut buf).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buf[..read]);
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        socket.write_all(header.as_bytes()).await.unwrap();
        socket.write_all(&body).await.unwrap();
        socket.flush().await.unwrap();
    });
    format!("http://{addr}/blob")
}

/// Spawns an HTTP/1.1 server that serves `body` to every request, recording
/// each raw request (lowercased, so header names compare case-insensitively).
/// Returns the URL and the recorded requests.
async fn serve_recording(body: Vec<u8>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    background_spawn!("fetch_test_recording_http_server", async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 2048];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let read = socket.read(&mut buf).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..read]);
            }
            recorded
                .lock()
                .push(String::from_utf8_lossy(&request).to_lowercase());
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(header.as_bytes()).await.unwrap();
            socket.write_all(&body).await.unwrap();
            socket.flush().await.unwrap();
        }
    });
    (format!("http://{addr}/blob"), requests)
}

/// Spawns a single-shot server that replies with `body` but no `Content-Length`
/// header, delimiting the body by closing the connection, so a client can only
/// learn the size by receiving it.
async fn serve_once_without_content_length(body: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    background_spawn!("fetch_test_no_content_length_server", async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 2048];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let read = socket.read(&mut buf).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buf[..read]);
        }
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        socket.write_all(&body).await.unwrap();
        socket.flush().await.unwrap();
    });
    format!("http://{addr}/blob")
}

/// Spawns a server that accepts one connection and then never responds,
/// holding the socket open so the client hits its own timeout.
async fn serve_stalls() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    background_spawn!("fetch_test_stall_server", async move {
        let (socket, _) = listener.accept().await.unwrap();
        // Never reply; just keep the connection open until the test ends.
        tokio::time::sleep(core::time::Duration::from_secs(30)).await;
        drop(socket);
    });
    format!("http://{addr}/blob")
}

/// Spawns an HTTP/1.1 server that answers every request promptly with the
/// headers of a `body.len()`-byte response and then sends the body `chunk`
/// bytes at a time, `interval` apart, so the response headers arrive at once
/// but the body takes `body.len() / chunk * interval` to finish. It stops
/// writing when the client goes away. Returns the URL and the number of
/// requests the server has received.
async fn serve_trickling(
    body: Vec<u8>,
    chunk: usize,
    interval: Duration,
) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    background_spawn!("fetch_test_trickling_http_server", async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let body = body.clone();
            let counted = counted.clone();
            background_spawn!("fetch_test_trickling_http_connection", async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 2048];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let read = socket.read(&mut buf).await.unwrap_or(0);
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&buf[..read]);
                }
                counted.fetch_add(1, Ordering::SeqCst);
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                if socket.write_all(header.as_bytes()).await.is_err() {
                    return;
                }
                for piece in body.chunks(chunk) {
                    tokio::time::sleep(interval).await;
                    if socket.write_all(piece).await.is_err() || socket.flush().await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (format!("http://{addr}/blob"), requests)
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
                fetcher: None,
            },
        }],
        &HashMap::new(),
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
// `sha256("hello world")`, base64-encoded, as an SRI checksum value.
const HELLO_WORLD_SRI: &str = "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=";
const HELLO_WORLD_SHA256_HEX: &str =
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

/// Builds a `FetchServer` whose fetcher is the production chain
/// `Background(MetadataCache(Url))`, composed via the config factory exactly as
/// the JSON config would.
fn make_fetch_server_with_cas(store_manager: &StoreManager) -> FetchServer {
    make_fetch_server_with_cas_and_limit(store_manager, None)
}

/// Like [`make_fetch_server_with_cas`], with the URL fetcher's download size
/// cap set to `max_size_bytes`.
fn make_fetch_server_with_cas_and_limit(
    store_manager: &StoreManager,
    max_size_bytes: Option<u64>,
) -> FetchServer {
    make_fetch_server_with_url_spec(
        store_manager,
        UrlFetcherSpec {
            cas_store: String::from("test_cas_store"),
            temp_path: None,
            max_size_bytes,
            ..Default::default()
        },
    )
}

/// Like [`make_fetch_server_with_cas`], with the URL fetcher configured by
/// `url_spec`.
fn make_fetch_server_with_url_spec(
    store_manager: &StoreManager,
    url_spec: UrlFetcherSpec,
) -> FetchServer {
    make_fetch_server_with_clamps(store_manager, url_spec, None, None)
}

/// Like [`make_fetch_server_with_url_spec`], with the background fetcher's
/// `min_timeout_s` and `max_timeout_s` set.
fn make_fetch_server_with_clamps(
    store_manager: &StoreManager,
    url_spec: UrlFetcherSpec,
    min_timeout_s: Option<u64>,
    max_timeout_s: Option<u64>,
) -> FetchServer {
    let mut fetchers: HashMap<String, Arc<dyn Fetcher>> = HashMap::new();
    let url = fetcher_factory(&FetcherSpec::Url(url_spec), store_manager, &fetchers)
        .expect("failed to build url fetcher");
    fetchers.insert("URL".to_string(), url);

    let cached = fetcher_factory(
        &FetcherSpec::MetadataCache(MetadataCacheSpec {
            fetch_store: String::from("test_fetch_store"),
            fetcher: String::from("URL"),
        }),
        store_manager,
        &fetchers,
    )
    .expect("failed to build metadata cache fetcher");
    fetchers.insert("CACHED".to_string(), cached);

    let background = fetcher_factory(
        &FetcherSpec::Background(BackgroundSpec {
            fetcher: String::from("CACHED"),
            max_concurrent_fetches: None,
            min_timeout_s,
            max_timeout_s,
        }),
        store_manager,
        &fetchers,
    )
    .expect("failed to build background fetcher");
    fetchers.insert("FETCH".to_string(), background);

    FetchServer::new(
        &[WithInstanceName {
            instance_name: "foo_instance_name".to_string(),
            config: FetchConfig {
                fetch_store: String::from("test_fetch_store"),
                fetcher: Some(String::from("FETCH")),
            },
        }],
        &fetchers,
        store_manager,
    )
    .expect("FetchServer config error")
}

#[nativelink_test]
async fn test_fetch_blob_active_download_with_sri() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let uri = serve_once(HELLO_WORLD.to_vec()).await;

    let response = fs
        .fetch_blob(Request::new(FetchBlobRequest {
            instance_name: "foo_instance_name".to_string(),
            timeout: None,
            oldest_content_accepted: None,
            uris: vec![uri.clone()],
            qualifiers: vec![Qualifier {
                name: "checksum.sri".to_owned(),
                value: HELLO_WORLD_SRI.to_owned(),
            }],
            digest_function: 0,
        }))
        .await?
        .into_inner();

    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    let blob_digest = response.blob_digest.expect("expected a blob digest");
    assert_eq!(blob_digest.hash, HELLO_WORLD_SHA256_HEX);
    assert_eq!(
        blob_digest.size_bytes,
        i64::try_from(HELLO_WORLD.len()).unwrap()
    );

    // The downloaded content should have been uploaded into the CAS store.
    let cas_store = store_manager.get_store("test_cas_store").unwrap();
    let digest = DigestInfo::try_new(HELLO_WORLD_SHA256_HEX, HELLO_WORLD.len() as u64).unwrap();
    let stored = cas_store.get_part_unchunked(digest, 0, None).await.unwrap();
    assert_eq!(stored.as_ref(), HELLO_WORLD);

    // The metadata was recorded as an `ActionResult` with the blob as its
    // output and our metadata attached.
    let qualifiers = vec![header_qualifier("checksum.sri", HELLO_WORLD_SRI)];
    let action_result =
        stored_action_result(&store_manager, AssetKind::Blob, &uri, qualifiers.clone()).await;
    assert_eq!(action_result.output_files.len(), 1);
    assert_eq!(action_result.output_files[0].path, "out");
    assert_eq!(action_result.output_files[0].digest, Some(blob_digest));
    assert!(action_result.output_directories.is_empty());
    let execution_metadata = action_result.execution_metadata.unwrap();
    assert_eq!(execution_metadata.worker, "nativelink-remote-asset");
    assert!(execution_metadata.worker_start_timestamp.is_some());
    assert!(execution_metadata.worker_completed_timestamp.is_some());
    let metadata =
        RemoteAssetMetadata::decode(execution_metadata.auxiliary_metadata[0].value.as_slice())
            .unwrap();
    assert_eq!(metadata.uri, uri);
    assert_eq!(metadata.qualifiers, qualifiers);

    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_checksum_mismatch_falls_through_to_next_uri() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    // The first URI serves corrupt content that won't match the checksum; the
    // second serves the real content. A mismatch on the first URI must not
    // abort the request -- we should fall through and succeed from the second.
    let bad_uri = serve_once(b"corrupted".to_vec()).await;
    let good_uri = serve_once(HELLO_WORLD.to_vec()).await;

    let response = fs
        .fetch_blob(Request::new(FetchBlobRequest {
            instance_name: "foo_instance_name".to_string(),
            timeout: None,
            oldest_content_accepted: None,
            uris: vec![bad_uri, good_uri.clone()],
            qualifiers: vec![Qualifier {
                name: "checksum.sri".to_owned(),
                value: HELLO_WORLD_SRI.to_owned(),
            }],
            digest_function: 0,
        }))
        .await?
        .into_inner();

    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    let blob_digest = response.blob_digest.expect("expected a blob digest");
    assert_eq!(blob_digest.hash, HELLO_WORLD_SHA256_HEX);
    assert_eq!(response.uri, good_uri);

    // The good content should have ended up in the CAS, the corrupt one not.
    let cas_store = store_manager.get_store("test_cas_store").unwrap();
    let digest = DigestInfo::try_new(HELLO_WORLD_SHA256_HEX, HELLO_WORLD.len() as u64).unwrap();
    let stored = cas_store.get_part_unchunked(digest, 0, None).await.unwrap();
    assert_eq!(stored.as_ref(), HELLO_WORLD);

    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_active_download_without_checksum() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    // No checksum.sri qualifier: the content is downloaded unverified and
    // stored under its computed CAS digest.
    let uri = serve_once(HELLO_WORLD.to_vec()).await;

    let response = fs
        .fetch_blob(Request::new(FetchBlobRequest {
            instance_name: "foo_instance_name".to_string(),
            timeout: None,
            oldest_content_accepted: None,
            uris: vec![uri.clone()],
            qualifiers: vec![],
            digest_function: 0,
        }))
        .await?
        .into_inner();

    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    let blob_digest = response.blob_digest.expect("expected a blob digest");
    assert_eq!(blob_digest.hash, HELLO_WORLD_SHA256_HEX);
    assert_eq!(
        blob_digest.size_bytes,
        i64::try_from(HELLO_WORLD.len()).unwrap()
    );

    let cas_store = store_manager.get_store("test_cas_store").unwrap();
    let digest = DigestInfo::try_new(HELLO_WORLD_SHA256_HEX, HELLO_WORLD.len() as u64).unwrap();
    let stored = cas_store.get_part_unchunked(digest, 0, None).await.unwrap();
    assert_eq!(stored.as_ref(), HELLO_WORLD);

    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_qualifier_order_does_not_affect_cache_key() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    // `serve_once` only answers a single request, so the second fetch can only
    // succeed by hitting the metadata cache.
    let uri = serve_once(HELLO_WORLD.to_vec()).await;
    let qualifier = |name: &str, value: &str| Qualifier {
        name: name.to_owned(),
        value: value.to_owned(),
    };
    let request = |qualifiers: Vec<Qualifier>| {
        Request::new(FetchBlobRequest {
            instance_name: "foo_instance_name".to_string(),
            timeout: None,
            oldest_content_accepted: None,
            uris: vec![uri.clone()],
            qualifiers,
            digest_function: 0,
        })
    };

    let first = fs
        .fetch_blob(request(vec![
            qualifier("bazel.canonical_id", "x"),
            qualifier("checksum.sri", HELLO_WORLD_SRI),
        ]))
        .await?
        .into_inner();
    assert_eq!(first.status.as_ref().map(|s| s.code), Some(0));

    let second = fs
        .fetch_blob(request(vec![
            qualifier("checksum.sri", HELLO_WORLD_SRI),
            qualifier("bazel.canonical_id", "x"),
        ]))
        .await?
        .into_inner();
    assert_eq!(second.status.as_ref().map(|s| s.code), Some(0));
    assert_eq!(second.blob_digest, first.blob_digest);

    Ok(())
}

fn header_qualifier(name: &str, value: &str) -> Qualifier {
    Qualifier {
        name: name.to_owned(),
        value: value.to_owned(),
    }
}

/// Decodes the single `ErrorInfo` detail of `status`, checking its type URL.
fn error_info_of(status: &GoogleStatus) -> ErrorInfo {
    assert_eq!(status.details.len(), 1, "{status:?}");
    let detail = &status.details[0];
    assert_eq!(detail.type_url, "type.googleapis.com/google.rpc.ErrorInfo");
    ErrorInfo::decode(detail.value.as_slice()).unwrap()
}

/// Asserts that `status` is `code` with a single `nativelink.com` `ErrorInfo`
/// of `reason`.
fn assert_error_info(status: Option<&GoogleStatus>, code: Code, reason: &str) {
    let status = status.expect("response has no status");
    assert_eq!(status.code, i32::from(code), "{status:?}");
    let info = error_info_of(status);
    assert_eq!(info.reason, reason);
    assert_eq!(info.domain, "nativelink.com");
}

/// Decodes the `BadRequest` detail that a rejected RPC carries in its details.
fn bad_request_of(err: &Status) -> BadRequest {
    let status = GoogleStatus::decode(err.details()).unwrap();
    assert_eq!(status.code, i32::from(err.code()));
    assert_eq!(status.details.len(), 1, "{status:?}");
    let detail = &status.details[0];
    assert_eq!(detail.type_url, "type.googleapis.com/google.rpc.BadRequest");
    BadRequest::decode(detail.value.as_slice()).unwrap()
}

/// The `(field, description)` pairs of `bad_request`'s violations.
fn violations_of(bad_request: &BadRequest) -> Vec<(&str, &str)> {
    bad_request
        .field_violations
        .iter()
        .map(|violation| (violation.field.as_str(), violation.description.as_str()))
        .collect()
}

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

#[nativelink_test]
async fn test_fetch_blob_sends_http_header_qualifiers() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let (uri, requests) = serve_recording(HELLO_WORLD.to_vec()).await;

    let response = fs
        .fetch_blob(blob_request(
            vec![uri.clone()],
            vec![
                header_qualifier("http_header:Authorization", "Bearer global"),
                header_qualifier("http_header:X-Other", "other"),
                // URL-specific headers override global ones of the same name,
                // regardless of case.
                header_qualifier("http_header_url:0:authorization", "Bearer specific"),
            ],
        ))
        .await?
        .into_inner();
    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));

    let requests = requests.lock();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("authorization: bearer specific\r\n"));
    assert!(!requests[0].contains("bearer global"));
    assert!(requests[0].contains("x-other: other\r\n"));
    Ok(())
}

const SECRET_HEADER_VALUE: &str = "Bearer header-secret-5f3a";
const SECRET_USER: &str = "userinfo-user-77c1";
const SECRET_PASSWORD: &str = "userinfo-pass-9d42";
const SECRET_SIGNATURE: &str = "signature-secret-e1b8";
const SECRET_TOKEN: &str = "token-secret-3c07";

/// `uri` (an `http://host:port/path` URL) with the secrets above in its userinfo
/// and query.
fn uri_with_secrets(uri: &str) -> String {
    let userinfo = format!("http://{SECRET_USER}:{SECRET_PASSWORD}@");
    let url = uri.replacen("http://", &userinfo, 1);
    format!("{url}?X-Amz-Signature={SECRET_SIGNATURE}&token={SECRET_TOKEN}&plain=1")
}

/// A URL nothing is listening on.
async fn unreachable_uri() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{addr}/blob")
}

/// Fails if any secret above is in the logs captured so far. Check that the
/// fetch logged something first, or this proves nothing.
fn assert_no_secrets_in_logs(logs_contain: impl Fn(&str) -> bool) {
    for secret in [
        SECRET_HEADER_VALUE,
        SECRET_USER,
        SECRET_PASSWORD,
        SECRET_SIGNATURE,
        SECRET_TOKEN,
    ] {
        assert!(!logs_contain(secret), "{secret} was logged");
    }
}

#[nativelink_test]
async fn test_fetch_blob_never_logs_header_values_or_uri_credentials() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let (served_uri, _requests) = serve_recording(HELLO_WORLD.to_vec()).await;
    let qualifiers = vec![
        header_qualifier("http_header:Authorization", SECRET_HEADER_VALUE),
        header_qualifier("http_header_url:0:X-Other", SECRET_HEADER_VALUE),
    ];

    // The first URI fails to connect, which makes the HTTP client's error
    // message carry the URL, and the second is served.
    let response = fs
        .fetch_blob(blob_request(
            vec![
                uri_with_secrets(&unreachable_uri().await),
                uri_with_secrets(&served_uri),
            ],
            qualifiers.clone(),
        ))
        .await?
        .into_inner();
    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    assert!(logs_contain(
        "Failed to download fetch asset, trying next uri"
    ));
    assert!(logs_contain("Fetched asset"));
    assert!(logs_contain("X-Amz-Signature=REDACTED"));
    assert!(logs_contain("plain=REDACTED"));

    // Every URI failing.
    let response = fs
        .fetch_blob(blob_request(
            vec![uri_with_secrets(&unreachable_uri().await)],
            qualifiers,
        ))
        .await?
        .into_inner();
    assert_error_info(response.status.as_ref(), Code::NotFound, "FETCH_FAILED");
    assert_no_secrets_in_logs(logs_contain);
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_url_specific_header_only_applies_to_that_uri() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    // The first URI serves content that fails the checksum, so the second is
    // tried; only the second has the URL-specific header.
    let (bad_uri, bad_requests) = serve_recording(b"wrong".to_vec()).await;
    let (good_uri, good_requests) = serve_recording(HELLO_WORLD.to_vec()).await;

    let response = fs
        .fetch_blob(blob_request(
            vec![bad_uri, good_uri],
            vec![
                header_qualifier("checksum.sri", HELLO_WORLD_SRI),
                header_qualifier("http_header_url:1:x-token", "t1"),
            ],
        ))
        .await?
        .into_inner();
    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    assert!(!bad_requests.lock()[0].contains("x-token"));
    assert!(good_requests.lock()[0].contains("x-token: t1\r\n"));
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_headers_do_not_affect_cache_key_or_get_persisted() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let (uri, requests) = serve_recording(HELLO_WORLD.to_vec()).await;

    let first = fs
        .fetch_blob(blob_request(
            vec![uri.clone()],
            vec![
                header_qualifier("checksum.sri", HELLO_WORLD_SRI),
                header_qualifier("http_header:Authorization", "Bearer one"),
            ],
        ))
        .await?
        .into_inner();
    assert_eq!(first.status.as_ref().map(|s| s.code), Some(0));

    // A different token is the same asset: served from the metadata cache
    // without contacting the origin again.
    let second = fs
        .fetch_blob(blob_request(
            vec![uri.clone()],
            vec![
                header_qualifier("checksum.sri", HELLO_WORLD_SRI),
                header_qualifier("http_header:Authorization", "Bearer two"),
            ],
        ))
        .await?
        .into_inner();
    assert_eq!(second.status.as_ref().map(|s| s.code), Some(0));
    assert_eq!(second.blob_digest, first.blob_digest);
    assert_eq!(requests.lock().len(), 1);

    // The stored metadata holds no header qualifiers (often credentials).
    assert!(
        second
            .qualifiers
            .iter()
            .all(|qualifier| !qualifier.name.starts_with("http_header")),
    );
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_malformed_header_qualifier_is_invalid_argument() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let (uri, requests) = serve_recording(HELLO_WORLD.to_vec()).await;

    for name in [
        "http_header:",
        "http_header_url:0:",
        "http_header_url:x:Foo",
        "http_header_url:5:Foo",
        "http_header_url:Foo",
    ] {
        let err = fs
            .fetch_blob(blob_request(
                vec![uri.clone()],
                vec![header_qualifier(name, "v")],
            ))
            .await
            .expect_err(name);
        assert_eq!(err.code(), Code::InvalidArgument, "{name}");
    }
    assert!(
        requests.lock().is_empty(),
        "no download should be attempted"
    );
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_content_length_over_limit_is_resource_exhausted() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas_and_limit(&store_manager, Some(5));
    let uri = serve_once(HELLO_WORLD.to_vec()).await;

    let response = fs
        .fetch_blob(blob_request(vec![uri], vec![]))
        .await?
        .into_inner();
    assert_eq!(
        response.status.as_ref().map(|s| s.code),
        Some(i32::from(Code::ResourceExhausted))
    );
    assert!(response.blob_digest.is_none());
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_streamed_body_over_limit_is_resource_exhausted() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas_and_limit(&store_manager, Some(50));
    // No Content-Length, so the cap can only be enforced while streaming.
    let uri = serve_once_without_content_length(vec![b'x'; 100]).await;

    let response = fs
        .fetch_blob(blob_request(vec![uri], vec![]))
        .await?
        .into_inner();
    assert_eq!(
        response.status.as_ref().map(|s| s.code),
        Some(i32::from(Code::ResourceExhausted))
    );
    assert!(response.blob_digest.is_none());
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_over_limit_falls_through_to_next_uri() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let limit = HELLO_WORLD.len() as u64;
    let fs = make_fetch_server_with_cas_and_limit(&store_manager, Some(limit));
    let too_big = serve_once(vec![b'x'; 100]).await;
    // Exactly at the limit is allowed.
    let ok = serve_once_without_content_length(HELLO_WORLD.to_vec()).await;

    let response = fs
        .fetch_blob(blob_request(vec![too_big, ok.clone()], vec![]))
        .await?
        .into_inner();
    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    assert_eq!(response.uri, ok);
    assert_eq!(
        response.blob_digest.expect("digest").hash,
        HELLO_WORLD_SHA256_HEX
    );
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_timeout_is_deadline_exceeded() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    // The server accepts the connection but never responds; the request's short
    // timeout must surface as DEADLINE_EXCEEDED.
    let uri = serve_stalls().await;

    let response = fs
        .fetch_blob(Request::new(FetchBlobRequest {
            instance_name: "foo_instance_name".to_string(),
            timeout: Some(prost_types::Duration {
                seconds: 0,
                nanos: 200_000_000,
            }),
            oldest_content_accepted: None,
            uris: vec![uri],
            qualifiers: vec![],
            digest_function: 0,
        }))
        .await?
        .into_inner();

    assert_eq!(
        response.status.as_ref().map(|s| s.code),
        Some(i32::from(Code::DeadlineExceeded))
    );
    assert!(response.blob_digest.is_none());

    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_checksum_mismatch_is_aborted() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let uri = serve_once(HELLO_WORLD.to_vec()).await;

    let response = fs
        .fetch_blob(Request::new(FetchBlobRequest {
            instance_name: "foo_instance_name".to_string(),
            timeout: None,
            oldest_content_accepted: None,
            uris: vec![uri],
            qualifiers: vec![Qualifier {
                name: "checksum.sri".to_owned(),
                // Valid SRI of the empty string, which will not match.
                value: "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".to_owned(),
            }],
            digest_function: 0,
        }))
        .await?
        .into_inner();

    // The fetch error's code survives, marked as a fetch failure rather than a
    // miss.
    assert_error_info(response.status.as_ref(), Code::Aborted, "FETCH_FAILED");
    assert!(response.blob_digest.is_none());

    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_no_cas_store_returns_not_found() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    // No fetcher configured: an unknown asset cannot be actively fetched.
    let fs = FetchServer::new(
        &[WithInstanceName {
            instance_name: "foo_instance_name".to_string(),
            config: FetchConfig {
                fetch_store: String::from("test_fetch_store"),
                fetcher: None,
            },
        }],
        &HashMap::new(),
        &store_manager,
    )
    .expect("FetchServer config error");

    let response = fs
        .fetch_blob(Request::new(FetchBlobRequest {
            instance_name: "foo_instance_name".to_string(),
            timeout: None,
            oldest_content_accepted: None,
            uris: vec!["http://example.invalid/blob".to_owned()],
            qualifiers: vec![Qualifier {
                name: "checksum.sri".to_owned(),
                value: HELLO_WORLD_SRI.to_owned(),
            }],
            digest_function: i32::from(digest_function::Value::Sha256),
        }))
        .await?
        .into_inner();

    assert_error_info(
        response.status.as_ref(),
        Code::NotFound,
        "NOT_CACHED_NO_FETCHER",
    );
    assert_eq!(
        response.status.as_ref().map(|s| s.message.as_str()),
        Some("not cached, and this instance has no fetcher configured")
    );
    assert!(response.blob_digest.is_none());
    // The request's qualifiers and digest function are echoed back.
    assert_eq!(
        response.qualifiers,
        vec![header_qualifier("checksum.sri", HELLO_WORLD_SRI)]
    );
    assert_eq!(
        response.digest_function,
        i32::from(digest_function::Value::Sha256)
    );

    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_corrupt_metadata_entry_is_a_miss() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = FetchServer::new(
        &[WithInstanceName {
            instance_name: "foo_instance_name".to_string(),
            config: FetchConfig {
                fetch_store: String::from("test_fetch_store"),
                fetcher: None,
            },
        }],
        &HashMap::new(),
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
    assert_error_info(
        response.status.as_ref(),
        Code::NotFound,
        "NOT_CACHED_NO_FETCHER",
    );
    assert!(response.blob_digest.is_none());
    Ok(())
}

/// Builds a lookup-only `FetchServer` (no fetcher) over the completeness-checked
/// `test_fetch_store`.
fn make_lookup_server(store_manager: &StoreManager) -> FetchServer {
    FetchServer::new(
        &[WithInstanceName {
            instance_name: "foo_instance_name".to_string(),
            config: FetchConfig {
                fetch_store: String::from("test_fetch_store"),
                fetcher: None,
            },
        }],
        &HashMap::new(),
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
    assert_error_info(
        response.status.as_ref(),
        Code::NotFound,
        "NOT_CACHED_NO_FETCHER",
    );
    assert!(response.blob_digest.is_none());
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_missing_from_cas_is_refetched() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let (uri, requests) = serve_recording(HELLO_WORLD.to_vec()).await;
    let digest = seed_hello_world_metadata(&store_manager, &uri).await;

    let response = fs
        .fetch_blob(blob_request(vec![uri], vec![]))
        .await?
        .into_inner();
    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    assert_eq!(response.blob_digest, Some(digest.clone()));
    // The stale entry was not served: the origin was contacted and the blob is
    // back in the CAS.
    assert_eq!(requests.lock().len(), 1);
    assert!(
        store_manager
            .get_store("test_cas_store")
            .unwrap()
            .has(DigestInfo::try_from(&digest).unwrap())
            .await
            .unwrap()
            .is_some()
    );
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
    assert_error_info(
        response.status.as_ref(),
        Code::NotFound,
        "NOT_CACHED_NO_FETCHER",
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

#[nativelink_test]
async fn test_fetch_blob_too_old_entry_is_refetched_and_restamped() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let (uri, requests) = serve_recording(HELLO_WORLD.to_vec()).await;
    seed_hello_world_with_times(&store_manager, &uri, None, Some(timestamp_ago(100))).await;
    let oldest = Some(timestamp_ago(10));

    let response = fs
        .fetch_blob(blob_request_oldest(&uri, oldest))
        .await?
        .into_inner();
    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    assert_eq!(requests.lock().len(), 1);

    // The refetch refreshed `stored_at`, so the same request now hits.
    let response = fs
        .fetch_blob(blob_request_oldest(&uri, oldest))
        .await?
        .into_inner();
    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    assert_eq!(requests.lock().len(), 1);
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_unsupported_qualifier_is_invalid_argument() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let (uri, requests) = serve_recording(HELLO_WORLD.to_vec()).await;

    // `checksum.h1` is only meaningful for directories.
    for name in ["resource_type", "vcs.commit", "checksum.h1", "made.up"] {
        let err = fs
            .fetch_blob(blob_request(
                vec![uri.clone()],
                vec![
                    header_qualifier("checksum.sri", HELLO_WORLD_SRI),
                    header_qualifier(name, "v"),
                ],
            ))
            .await
            .expect_err(name);
        assert_eq!(err.code(), Code::InvalidArgument, "{name}");
        // The message names the offender and what is supported.
        assert!(err.message().contains(name), "{}", err.message());
        assert!(err.message().contains("checksum.sri"), "{}", err.message());
        assert!(
            err.message().contains("bazel.canonical_id"),
            "{}",
            err.message()
        );
        // One violation per unsupported qualifier, not per qualifier.
        assert_eq!(
            violations_of(&bad_request_of(&err)),
            vec![(
                "qualifiers.name",
                format!("\"{name}\" not supported").as_str()
            )],
            "{name}"
        );
    }
    assert!(
        requests.lock().is_empty(),
        "no download should be attempted"
    );
    Ok(())
}

/// The spec lets a server trust the qualifiers of a pushed asset, so one
/// stored under a qualifier we could not honour on a download is still found,
/// with or without a fetcher, and nothing is downloaded.
#[nativelink_test]
async fn test_fetch_blob_pushed_asset_with_unsupported_qualifier_is_a_hit() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let (uri, requests) = serve_recording(HELLO_WORLD.to_vec()).await;
    let qualifiers = vec![header_qualifier("resource_type", "test")];
    let digest = Digest {
        hash: HELLO_WORLD_SHA256_HEX.to_owned(),
        size_bytes: i64::try_from(HELLO_WORLD.len()).unwrap(),
    };
    store_manager
        .get_store("test_cas_store")
        .unwrap()
        .update_oneshot(
            DigestInfo::try_from(&digest).unwrap(),
            HELLO_WORLD.to_vec().into(),
        )
        .await
        .unwrap();
    write_entry(
        &store_manager,
        AssetKind::Blob,
        &uri,
        qualifiers.clone(),
        digest.clone(),
        None,
        None,
    )
    .await;

    for fs in [
        make_lookup_server(&store_manager),
        make_fetch_server_with_cas(&store_manager),
    ] {
        let response = fs
            .fetch_blob(blob_request(vec![uri.clone()], qualifiers.clone()))
            .await?
            .into_inner();
        assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
        assert_eq!(response.blob_digest, Some(digest.clone()));
        assert_eq!(response.qualifiers, qualifiers);
    }
    assert!(requests.lock().is_empty(), "a hit needs no download");
    Ok(())
}

/// Without a fetcher nothing is downloaded, so there is nothing to reject: an
/// unsupported qualifier on a miss is just a miss.
#[nativelink_test]
async fn test_fetch_blob_unsupported_qualifier_without_fetcher_is_not_cached() -> Result<(), Status>
{
    let store_manager = make_store_manager().await?;
    let fs = make_lookup_server(&store_manager);
    let response = fs
        .fetch_blob(blob_request(
            vec!["http://example.invalid/blob".to_owned()],
            vec![header_qualifier("resource_type", "test")],
        ))
        .await?
        .into_inner();
    assert_error_info(
        response.status.as_ref(),
        Code::NotFound,
        "NOT_CACHED_NO_FETCHER",
    );
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_unsupported_qualifiers_each_get_a_violation() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let (uri, requests) = serve_recording(HELLO_WORLD.to_vec()).await;
    let err = fs
        .fetch_blob(blob_request(
            vec![uri],
            vec![
                header_qualifier("resource_type", "a"),
                header_qualifier("checksum.sri", HELLO_WORLD_SRI),
                header_qualifier("vcs.commit", "b"),
                header_qualifier("http_header:Authorization", "Bearer t"),
            ],
        ))
        .await
        .expect_err("unsupported qualifiers");
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(
        violations_of(&bad_request_of(&err)),
        vec![
            ("qualifiers.name", "\"resource_type\" not supported"),
            ("qualifiers.name", "\"vcs.commit\" not supported"),
        ]
    );
    assert!(
        requests.lock().is_empty(),
        "no download should be attempted"
    );
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_supported_qualifiers_are_accepted() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let (uri, requests) = serve_recording(HELLO_WORLD.to_vec()).await;

    // Nothing is cached, so this downloads, and every qualifier is one a
    // download honours.
    let response = fs
        .fetch_blob(blob_request(
            vec![uri],
            vec![
                header_qualifier("checksum.sri", HELLO_WORLD_SRI),
                header_qualifier("bazel.canonical_id", "id"),
                header_qualifier("http_header:Authorization", "Bearer t"),
                header_qualifier("http_header_url:0:X-Token", "t"),
            ],
        ))
        .await?
        .into_inner();
    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    assert_eq!(requests.lock().len(), 1);
    Ok(())
}

/// The status code a response carries.
fn status_code_of(status: Option<&GoogleStatus>) -> Option<i32> {
    Some(status?.code)
}

#[nativelink_test]
async fn test_fetch_blob_timeout_bounds_a_trickling_body() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    // The headers arrive at once and the body would take 100 seconds, one byte
    // at a time, so every read is well inside the 30 second idle timeout. Only a
    // timeout on the whole fetch can stop it.
    let (uri, _requests) = serve_trickling(vec![b'x'; 1000], 1, Duration::from_millis(100)).await;

    let started = Instant::now();
    let mut request = blob_request(vec![uri], vec![]);
    request.get_mut().timeout = Some(prost_types::Duration {
        seconds: 0,
        nanos: 500_000_000,
    });
    let response = fs.fetch_blob(request).await?.into_inner();

    assert_eq!(
        status_code_of(response.status.as_ref()),
        Some(i32::from(Code::DeadlineExceeded)),
        "{response:?}"
    );
    assert!(response.blob_digest.is_none());
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the fetch outlived its timeout: {:?}",
        started.elapsed()
    );
    Ok(())
}

#[nativelink_test]
async fn test_max_fetch_duration_caps_the_request_timeout() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_url_spec(
        &store_manager,
        UrlFetcherSpec {
            cas_store: String::from("test_cas_store"),
            max_fetch_duration_s: Some(1),
            ..Default::default()
        },
    );
    let (uri, _requests) = serve_trickling(vec![b'x'; 1000], 1, Duration::from_millis(100)).await;

    // A request with no timeout, and one asking for far longer than the cap,
    // are both cut off after the one second the fetcher allows.
    for timeout in [
        None,
        Some(prost_types::Duration {
            seconds: 3600,
            nanos: 0,
        }),
    ] {
        let started = Instant::now();
        let mut request = blob_request(vec![uri.clone()], vec![]);
        request.get_mut().timeout = timeout;
        let response = fs.fetch_blob(request).await?.into_inner();

        assert_eq!(
            status_code_of(response.status.as_ref()),
            Some(i32::from(Code::DeadlineExceeded)),
            "{response:?}"
        );
        assert!(
            response
                .status
                .as_ref()
                .is_some_and(|status| status.message.contains("max_fetch_duration_s")),
            "{response:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the fetch outlived the cap: {:?}",
            started.elapsed()
        );
    }
    Ok(())
}

#[nativelink_test]
async fn test_background_clamps_apply_to_the_total_timeout() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    // The background fetcher caps a request's timeout at one second, well under
    // the hour the request asks for and the hour the URL fetcher allows.
    let fs = make_fetch_server_with_clamps(
        &store_manager,
        UrlFetcherSpec {
            cas_store: String::from("test_cas_store"),
            ..Default::default()
        },
        None,
        Some(1),
    );
    let (uri, _requests) = serve_trickling(vec![b'x'; 1000], 1, Duration::from_millis(100)).await;

    let started = Instant::now();
    let mut request = blob_request(vec![uri], vec![]);
    request.get_mut().timeout = Some(prost_types::Duration {
        seconds: 3600,
        nanos: 0,
    });
    let response = fs.fetch_blob(request).await?.into_inner();

    assert_eq!(
        status_code_of(response.status.as_ref()),
        Some(i32::from(Code::DeadlineExceeded)),
        "{response:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the fetch outlived the clamped timeout: {:?}",
        started.elapsed()
    );
    Ok(())
}

#[nativelink_test]
async fn test_rpc_deadline_returns_deadline_exceeded_and_a_retry_joins_the_fetch()
-> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    // The body takes about 1.1 seconds to arrive, eleven bytes 100ms apart.
    let (uri, requests) =
        serve_trickling(HELLO_WORLD.to_vec(), 1, Duration::from_millis(100)).await;

    // The client's RPC deadline is 300ms, far short of the fetch.
    let mut request = blob_request(vec![uri.clone()], vec![]);
    request.set_timeout(Duration::from_millis(300));
    let started = Instant::now();
    let err = fs
        .fetch_blob(request)
        .await
        .expect_err("the fetch cannot finish within the RPC deadline");
    assert_eq!(err.code(), Code::DeadlineExceeded, "{err:?}");
    assert!(
        err.message().contains("retry"),
        "the message should say a retry joins the fetch: {err:?}"
    );
    // The server answered before the 300ms deadline, which is what stops tonic
    // from answering CANCELLED first.
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "answered after the RPC deadline: {:?}",
        started.elapsed()
    );

    // The fetch carried on in the background, so an identical request with no
    // deadline joins it and gets the finished result without a second request
    // to the origin.
    let response = fs
        .fetch_blob(blob_request(vec![uri], vec![]))
        .await?
        .into_inner();
    assert_eq!(
        status_code_of(response.status.as_ref()),
        Some(0),
        "{response:?}"
    );
    assert_eq!(
        response.blob_digest.expect("expected a blob digest").hash,
        HELLO_WORLD_SHA256_HEX
    );
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    Ok(())
}

#[nativelink_test]
async fn test_no_rpc_deadline_waits_for_the_fetch() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let (uri, _requests) =
        serve_trickling(HELLO_WORLD.to_vec(), 1, Duration::from_millis(50)).await;

    let response = fs
        .fetch_blob(blob_request(vec![uri], vec![]))
        .await?
        .into_inner();
    assert_eq!(
        status_code_of(response.status.as_ref()),
        Some(0),
        "{response:?}"
    );
    Ok(())
}

#[nativelink_test]
async fn test_parse_grpc_timeout() {
    assert_eq!(parse_grpc_timeout("1H"), Some(Duration::from_hours(1)));
    assert_eq!(parse_grpc_timeout("2M"), Some(Duration::from_mins(2)));
    assert_eq!(parse_grpc_timeout("30S"), Some(Duration::from_secs(30)));
    assert_eq!(parse_grpc_timeout("250m"), Some(Duration::from_millis(250)));
    assert_eq!(parse_grpc_timeout("15u"), Some(Duration::from_micros(15)));
    assert_eq!(parse_grpc_timeout("7n"), Some(Duration::from_nanos(7)));
    assert_eq!(
        parse_grpc_timeout("99999999S"),
        Some(Duration::from_secs(99_999_999))
    );
    // More than eight digits, no digits, no unit, an unknown unit, a sign and
    // non-ASCII input are all malformed.
    for bad in [
        "123456789S",
        "S",
        "",
        "10",
        "10s",
        "10x",
        "-5S",
        "+5S",
        "1.5S",
        "5\u{e9}",
    ] {
        assert_eq!(parse_grpc_timeout(bad), None, "{bad:?}");
    }
}

/// A URL fetcher spec that fetches through `http_proxy` (or the URL in
/// `http_proxy_secret_file`), bypassing it for the `no_proxy` hosts.
fn proxy_spec(
    http_proxy: Option<&str>,
    http_proxy_secret_file: Option<&str>,
    no_proxy: &[&str],
) -> UrlFetcherSpec {
    UrlFetcherSpec {
        cas_store: String::from("test_cas_store"),
        http_proxy: http_proxy.map(str::to_owned),
        http_proxy_secret_file: http_proxy_secret_file.map(str::to_owned),
        no_proxy: no_proxy.iter().map(|host| (*host).to_owned()).collect(),
        ..Default::default()
    }
}

/// Spawns a forward proxy (a server answering every request, recording it) and
/// returns its base URL, `http://127.0.0.1:<port>`, and the requests it saw.
/// A proxy is sent the absolute-form request target, `GET http://host/path`.
async fn serve_proxy(body: Vec<u8>) -> (String, Arc<Mutex<Vec<String>>>) {
    let (uri, requests) = serve_recording(body).await;
    (uri.trim_end_matches("/blob").to_owned(), requests)
}

/// Builds the URL fetcher `spec` describes, the way the server does.
async fn build_url_fetcher(spec: UrlFetcherSpec) -> Result<Arc<dyn Fetcher>, Error> {
    let store_manager = make_store_manager().await?;
    fetcher_factory(&FetcherSpec::Url(spec), &store_manager, &HashMap::new())
}

#[nativelink_test]
async fn test_fetch_blob_through_http_proxy() -> Result<(), Status> {
    use base64::Engine;
    use base64::prelude::BASE64_STANDARD;

    let store_manager = make_store_manager().await?;
    let (proxy, proxy_requests) = serve_proxy(HELLO_WORLD.to_vec()).await;
    let proxy_with_credentials = proxy.replacen("http://", "http://user:s3cret@", 1);
    let fs = make_fetch_server_with_url_spec(
        &store_manager,
        proxy_spec(Some(&proxy_with_credentials), None, &[]),
    );

    // The origin's name does not resolve, so the fetch can only succeed
    // through the proxy.
    let response = fs
        .fetch_blob(blob_request(
            vec!["http://origin.invalid/blob".to_owned()],
            vec![],
        ))
        .await?
        .into_inner();

    assert_eq!(
        status_code_of(response.status.as_ref()),
        Some(0),
        "{response:?}"
    );
    assert_eq!(
        response.blob_digest.expect("expected a blob digest").hash,
        HELLO_WORLD_SHA256_HEX
    );
    let seen = proxy_requests.lock().clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(
        seen[0].starts_with("get http://origin.invalid/blob http/1.1"),
        "{seen:?}"
    );
    // The credentials in the proxy URL are sent to the proxy as basic auth.
    let credentials = BASE64_STANDARD.encode("user:s3cret").to_lowercase();
    assert!(
        seen[0].contains(&format!("proxy-authorization: basic {credentials}")),
        "{seen:?}"
    );
    Ok(())
}

#[nativelink_test]
async fn test_no_proxy_hosts_bypass_the_proxy() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let (proxy, proxy_requests) = serve_proxy(b"from the proxy".to_vec()).await;
    let (origin, origin_requests) = serve_recording(HELLO_WORLD.to_vec()).await;
    let fs = make_fetch_server_with_url_spec(
        &store_manager,
        proxy_spec(Some(&proxy), None, &["127.0.0.1"]),
    );

    // The origin is on 127.0.0.1, which `no_proxy` names, so it is fetched
    // from directly.
    let response = fs
        .fetch_blob(blob_request(vec![origin], vec![]))
        .await?
        .into_inner();

    assert_eq!(
        status_code_of(response.status.as_ref()),
        Some(0),
        "{response:?}"
    );
    assert_eq!(
        response.blob_digest.expect("expected a blob digest").hash,
        HELLO_WORLD_SHA256_HEX
    );
    assert_eq!(origin_requests.lock().len(), 1);
    assert!(
        origin_requests.lock()[0].starts_with("get /blob http/1.1"),
        "{:?}",
        origin_requests.lock()
    );
    assert!(proxy_requests.lock().is_empty());

    // A host `no_proxy` does not name still goes through the proxy.
    let response = fs
        .fetch_blob(blob_request(
            vec!["http://origin.invalid/other".to_owned()],
            vec![],
        ))
        .await?
        .into_inner();
    assert_eq!(
        status_code_of(response.status.as_ref()),
        Some(0),
        "{response:?}"
    );
    assert_eq!(proxy_requests.lock().len(), 1);
    Ok(())
}

#[nativelink_test]
async fn test_proxy_secret_file_is_trimmed() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let (proxy, proxy_requests) = serve_proxy(HELLO_WORLD.to_vec()).await;
    let dir = tempfile::tempdir().unwrap();
    let secret_file = dir.path().join("proxy_url");
    std::fs::write(&secret_file, format!("  {proxy}\n")).unwrap();
    let fs = make_fetch_server_with_url_spec(
        &store_manager,
        proxy_spec(None, Some(secret_file.to_str().unwrap()), &[]),
    );

    let response = fs
        .fetch_blob(blob_request(
            vec!["http://origin.invalid/blob".to_owned()],
            vec![],
        ))
        .await?
        .into_inner();

    assert_eq!(
        status_code_of(response.status.as_ref()),
        Some(0),
        "{response:?}"
    );
    assert_eq!(proxy_requests.lock().len(), 1);
    Ok(())
}

#[nativelink_test]
async fn test_invalid_proxy_config_is_an_error_without_credentials() -> Result<(), Error> {
    let dir = tempfile::tempdir().unwrap();
    let write_secret = |name: &str, contents: &str| {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path.to_str().unwrap().to_owned()
    };
    let valid_file = write_secret("valid", "http://user:s3cret@proxy.invalid:3128\n");
    let bad_scheme_file = write_secret("bad_scheme", "socks5://user:s3cret@proxy.invalid:1080\n");
    let empty_file = write_secret("empty", " \n");
    let missing_file = dir.path().join("missing").to_str().unwrap().to_owned();

    let cases = [
        // Both sources set.
        proxy_spec(
            Some("http://user:s3cret@proxy.invalid:3128"),
            Some(&valid_file),
            &[],
        ),
        // Not http or https.
        proxy_spec(Some("socks5://user:s3cret@proxy.invalid:1080"), None, &[]),
        proxy_spec(Some("ftp://user:s3cret@proxy.invalid"), None, &[]),
        // Not a URL, and a URL without a host.
        proxy_spec(Some("user:s3cret not a url"), None, &[]),
        proxy_spec(Some("http://user:s3cret@"), None, &[]),
        proxy_spec(Some("http://user:s3cret@:3128"), None, &[]),
        // The same faults, in the secret file.
        proxy_spec(None, Some(&bad_scheme_file), &[]),
        proxy_spec(None, Some(&empty_file), &[]),
        proxy_spec(None, Some(&missing_file), &[]),
    ];
    for (idx, spec) in cases.into_iter().enumerate() {
        let err = build_url_fetcher(spec)
            .await
            .expect_err(&format!("case {idx} should not build"));
        assert_eq!(err.code, Code::InvalidArgument, "case {idx}: {err:?}");
        let shown = format!("{err:?} {err}");
        assert!(
            !shown.contains("s3cret"),
            "credentials in the error: {shown}"
        );
    }

    // And the valid one builds.
    build_url_fetcher(proxy_spec(None, Some(&valid_file), &["localhost"])).await?;
    Ok(())
}

#[nativelink_test]
async fn test_proxy_credentials_are_not_in_debug_output() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let spec = proxy_spec(
        Some("http://user:s3cret@proxy.invalid:3128"),
        None,
        &["internal.example.com"],
    );

    let fetcher = build_url_fetcher(spec.clone()).await?;
    let shown = format!("{fetcher:?}");
    assert!(!shown.contains("s3cret"), "{shown}");
    assert!(!shown.contains("proxy.invalid"), "{shown}");
    assert!(shown.contains("proxy_configured: true"), "{shown}");

    // Nor in the Debug output of the whole server that holds the fetcher chain.
    let fs = make_fetch_server_with_url_spec(&store_manager, spec);
    let shown = format!("{fs:?}");
    assert!(!shown.contains("s3cret"), "{shown}");
    Ok(())
}
