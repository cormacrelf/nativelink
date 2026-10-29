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
use nativelink_config::fetchers::{
    ActionVerifySpec, BackgroundSpec, FetcherSpec, MetadataCacheSpec, UrlFetcherSpec,
};
use nativelink_config::stores::{CompletenessCheckingSpec, MemorySpec, RefSpec, StoreSpec};
use nativelink_error::{Code as ErrorCode, Error, make_err};
use nativelink_fetch::fetcher::Fetcher;
use nativelink_fetch::fetcher_factory::fetcher_factory;
use nativelink_fetch::remote_asset_proto::{
    AssetKind, RemoteAssetEntry, RemoteAssetMetadata, RemoteAssetQuery, now_timestamp,
    write_remote_asset_entry,
};
use nativelink_macro::nativelink_test;
use nativelink_metric::{
    MetricFieldData, MetricKind, MetricPublishKnownKindData, MetricsComponent,
};
use nativelink_proto::build::bazel::remote::asset::v1::fetch_server::Fetch;
use nativelink_proto::build::bazel::remote::asset::v1::{
    FetchBlobRequest, FetchBlobResponse, FetchDirectoryRequest, FetchDirectoryResponse, Qualifier,
};
use nativelink_proto::build::bazel::remote::execution::v2::command::EnvironmentVariable;
use nativelink_proto::build::bazel::remote::execution::v2::{
    Action, ActionResult, Command, Digest, Directory, DirectoryNode, FileNode, Tree,
    digest_function,
};
use nativelink_proto::google::rpc::{
    BadRequest, ErrorInfo, PreconditionFailure, Status as GoogleStatus,
};
use nativelink_service::fetch_server::{FetchServer, parse_grpc_timeout};
use nativelink_store::default_store_factory::store_factory;
use nativelink_store::memory_store::MemoryStore;
use nativelink_store::store_manager::StoreManager;
use nativelink_util::action_messages::{ActionInfo, OperationId};
use nativelink_util::background_spawn;
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::{DigestHasher, DigestHasherFunc};
use nativelink_util::operation_state_manager::{
    ActionStateResult, ActionStateResultStream, ClientStateManager, OperationFilter,
};
use nativelink_util::store_trait::{Store, StoreLike};
use parking_lot::Mutex;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tonic::{Code, Request, Status, async_trait};

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
    serve_recording_with_headers(body, "").await
}

/// Like [`serve_recording`], with `extra_headers` (zero or more complete
/// `Name: value\r\n` lines) added to every response.
async fn serve_recording_with_headers(
    body: Vec<u8>,
    extra_headers: &'static str,
) -> (String, Arc<Mutex<Vec<String>>>) {
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
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n",
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

/// Computes the `sha256-...` SRI checksum value for `data`.
fn sri_of(data: &[u8]) -> String {
    use base64::Engine;
    use base64::prelude::BASE64_STANDARD;
    use sha2::{Digest, Sha256};
    format!("sha256-{}", BASE64_STANDARD.encode(Sha256::digest(data)))
}

/// Computes the Go `h1:` directory hash of `(name, content)` entries, as the
/// server derives it from the files of an expanded archive.
fn h1_of(entries: &[(&str, &[u8])]) -> String {
    use nativelink_fetch::tree_hash::h1::h1_from_file_hashes;
    use sha2::{Digest, Sha256};
    h1_from_file_hashes(
        entries
            .iter()
            .map(|(name, content)| ((*name).to_string(), Sha256::digest(content).into()))
            .collect(),
    )
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
            archive_entry_inline_threshold_bytes: None,
            max_archive_entries: None,
            max_archive_uncompressed_bytes: None,
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

/// The metadata cache's default
/// `(unpinned_default_ttl_s, unpinned_min_ttl_s, unpinned_max_ttl_s)`.
const DEFAULT_TTLS: (u64, u64, u64) = (24 * 60 * 60, 5 * 60, 30 * 24 * 60 * 60);

/// Like [`make_fetch_server_with_url_spec`], with the background fetcher's
/// `min_timeout_s` and `max_timeout_s` set.
fn make_fetch_server_with_clamps(
    store_manager: &StoreManager,
    url_spec: UrlFetcherSpec,
    min_timeout_s: Option<u64>,
    max_timeout_s: Option<u64>,
) -> FetchServer {
    make_fetch_server_with_options(
        store_manager,
        url_spec,
        DEFAULT_TTLS,
        min_timeout_s,
        max_timeout_s,
    )
}

/// Like [`make_fetch_server_with_url_spec`], with the metadata cache's
/// `(unpinned_default_ttl_s, unpinned_min_ttl_s, unpinned_max_ttl_s)`.
fn make_fetch_server_with_ttls(
    store_manager: &StoreManager,
    url_spec: UrlFetcherSpec,
    ttls: (u64, u64, u64),
) -> FetchServer {
    make_fetch_server_with_options(store_manager, url_spec, ttls, None, None)
}

/// Like [`make_fetch_server_with_url_spec`], with the metadata cache's TTLs and
/// the background fetcher's timeout clamps set.
fn make_fetch_server_with_options(
    store_manager: &StoreManager,
    url_spec: UrlFetcherSpec,
    (default_ttl_s, min_ttl_s, max_ttl_s): (u64, u64, u64),
    min_timeout_s: Option<u64>,
    max_timeout_s: Option<u64>,
) -> FetchServer {
    let schedulers: HashMap<String, Arc<dyn ClientStateManager>> = HashMap::new();
    let mut fetchers: HashMap<String, Arc<dyn Fetcher>> = HashMap::new();
    let url = fetcher_factory(
        &FetcherSpec::Url(url_spec),
        store_manager,
        &schedulers,
        &fetchers,
    )
    .expect("failed to build url fetcher");
    fetchers.insert("URL".to_string(), url);

    let cached = fetcher_factory(
        &FetcherSpec::MetadataCache(MetadataCacheSpec {
            fetch_store: String::from("test_fetch_store"),
            cas_store: String::from("test_cas_store"),
            fetcher: String::from("URL"),
            unpinned_default_ttl_s: default_ttl_s,
            unpinned_min_ttl_s: min_ttl_s,
            unpinned_max_ttl_s: max_ttl_s,
        }),
        store_manager,
        &schedulers,
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
        &schedulers,
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
    let digest = DigestInfo::try_new(
        HELLO_WORLD_SHA256_HEX,
        u64::try_from(HELLO_WORLD.len()).unwrap(),
    )
    .unwrap();
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
    let digest = DigestInfo::try_new(
        HELLO_WORLD_SHA256_HEX,
        u64::try_from(HELLO_WORLD.len()).unwrap(),
    )
    .unwrap();
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
    let digest = DigestInfo::try_new(
        HELLO_WORLD_SHA256_HEX,
        u64::try_from(HELLO_WORLD.len()).unwrap(),
    )
    .unwrap();
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
async fn test_fetch_directory_never_logs_header_values_or_uri_credentials() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let (served_uri, _requests) = serve_recording(build_zip(&[("a.txt", b"alpha")])).await;
    let qualifiers = vec![header_qualifier(
        "http_header:Authorization",
        SECRET_HEADER_VALUE,
    )];

    let response = fs
        .fetch_directory(directory_request_with(
            vec![
                uri_with_secrets(&unreachable_uri().await),
                uri_with_secrets(&served_uri),
            ],
            qualifiers.clone(),
        ))
        .await?
        .into_inner();
    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    assert!(logs_contain("Fetched directory"));
    assert!(logs_contain("X-Amz-Signature=REDACTED"));

    let response = fs
        .fetch_directory(directory_request_with(
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
async fn test_responses_never_echo_header_qualifiers() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let lookup_only = FetchServer::new(
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
    let canonical_id = header_qualifier("bazel.canonical_id", "id");
    let qualifiers = vec![
        canonical_id.clone(),
        header_qualifier("http_header:Authorization", SECRET_HEADER_VALUE),
        header_qualifier("http_header_url:0:X-Other", SECRET_HEADER_VALUE),
    ];
    let expected = vec![
        canonical_id,
        header_qualifier("http_header:Authorization", "<REDACTED>"),
        header_qualifier("http_header_url:0:X-Other", "<REDACTED>"),
    ];

    // Downloaded, failed, and not cached with no fetcher to fetch it.
    let (uri, _requests) = serve_recording(HELLO_WORLD.to_vec()).await;
    let unreachable = unreachable_uri().await;
    for (server, uri, code) in [
        (&fs, uri, 0),
        (&fs, unreachable.clone(), i32::from(Code::NotFound)),
        (&lookup_only, unreachable.clone(), i32::from(Code::NotFound)),
    ] {
        let response = server
            .fetch_blob(blob_request(vec![uri], qualifiers.clone()))
            .await?
            .into_inner();
        assert_eq!(response.status.as_ref().map(|s| s.code), Some(code));
        assert_eq!(response.qualifiers, expected, "{response:?}");
    }

    let (uri, _requests) = serve_recording(build_zip(&[("a.txt", b"alpha")])).await;
    for (server, uri, code) in [
        (&fs, uri, 0),
        (&fs, unreachable.clone(), i32::from(Code::NotFound)),
        (&lookup_only, unreachable, i32::from(Code::NotFound)),
    ] {
        let response = server
            .fetch_directory(directory_request_with(vec![uri], qualifiers.clone()))
            .await?
            .into_inner();
        assert_eq!(response.status.as_ref().map(|s| s.code), Some(code));
        assert_eq!(response.qualifiers, expected, "{response:?}");
    }
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
    let limit = u64::try_from(HELLO_WORLD.len()).unwrap();
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
async fn test_fetch_directory_over_limit_is_resource_exhausted() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas_and_limit(&store_manager, Some(10));
    let zip_data = build_zip(&[("a.txt", b"alpha")]);
    let sri = sri_of(&zip_data);
    let uri = serve_once(zip_data).await;

    let response = fs
        .fetch_directory(Request::new(FetchDirectoryRequest {
            instance_name: "foo_instance_name".to_string(),
            timeout: None,
            oldest_content_accepted: None,
            uris: vec![uri],
            qualifiers: vec![header_qualifier("checksum.sri", &sri)],
            digest_function: 0,
        }))
        .await?
        .into_inner();
    assert_eq!(
        response.status.as_ref().map(|s| s.code),
        Some(i32::from(Code::ResourceExhausted))
    );
    assert!(response.root_directory_digest.is_none());
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

/// Builds an in-memory zip archive from `(name, content)` entries.
fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::{Cursor, Write};

    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, content) in entries {
        writer
            .start_file(*name, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(content).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[nativelink_test]
async fn test_fetch_directory_active_download_with_sri() -> Result<(), Status> {
    use nativelink_proto::build::bazel::remote::asset::v1::fetch_server::Fetch as _;
    use prost::Message;

    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);

    let zip_data = build_zip(&[("a.txt", b"alpha"), ("dir/b.txt", b"beta")]);
    let sri = sri_of(&zip_data);
    let uri = serve_once(zip_data).await;

    let response = fs
        .fetch_directory(Request::new(FetchDirectoryRequest {
            instance_name: "foo_instance_name".to_string(),
            timeout: None,
            oldest_content_accepted: None,
            uris: vec![uri.clone()],
            qualifiers: vec![Qualifier {
                name: "checksum.sri".to_owned(),
                value: sri.clone(),
            }],
            digest_function: 0,
        }))
        .await?
        .into_inner();

    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    let root_digest = response
        .root_directory_digest
        .expect("expected a root directory digest");

    // The root Directory proto should be retrievable from the CAS and describe
    // the archive's top-level entries.
    let cas_store = store_manager.get_store("test_cas_store").unwrap();
    let root_info: DigestInfo = root_digest.try_into().unwrap();
    let root_raw = cas_store
        .get_part_unchunked(root_info, 0, None)
        .await
        .unwrap();
    let root = Directory::decode(root_raw).unwrap();
    assert_eq!(root.files.len(), 1);
    assert_eq!(root.files[0].name, "a.txt");
    assert_eq!(root.directories.len(), 1);
    assert_eq!(root.directories[0].name, "dir");

    // The metadata is an `ActionResult` whose output directory is a `Tree` of
    // the whole archive, uploaded to the CAS.
    let qualifiers = vec![header_qualifier("checksum.sri", &sri)];
    let tree_digest =
        stored_tree_digest(&store_manager, AssetKind::Directory, &uri, qualifiers).await;
    let tree = Tree::decode(
        cas_store
            .get_part_unchunked(tree_digest, 0, None)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(tree.root, Some(root));
    assert_eq!(tree.children.len(), 1);
    assert_eq!(tree.children[0].files[0].name, "b.txt");

    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_checksum_mismatch_is_aborted() -> Result<(), Status> {
    use nativelink_proto::build::bazel::remote::asset::v1::fetch_server::Fetch as _;

    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);

    let zip_data = build_zip(&[("a.txt", b"alpha")]);
    let uri = serve_once(zip_data).await;

    let response = fs
        .fetch_directory(Request::new(FetchDirectoryRequest {
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

    assert_error_info(response.status.as_ref(), Code::Aborted, "FETCH_FAILED");
    assert!(response.root_directory_digest.is_none());

    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_active_download_with_h1() -> Result<(), Status> {
    use nativelink_proto::build::bazel::remote::asset::v1::fetch_server::Fetch as _;

    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);

    let entries: &[(&str, &[u8])] = &[("a.txt", b"alpha"), ("dir/b.txt", b"beta")];
    let zip_data = build_zip(entries);
    let h1 = h1_of(entries);
    let uri = serve_once(zip_data).await;

    let response = fs
        .fetch_directory(Request::new(FetchDirectoryRequest {
            instance_name: "foo_instance_name".to_string(),
            timeout: None,
            oldest_content_accepted: None,
            uris: vec![uri],
            qualifiers: vec![Qualifier {
                name: "checksum.h1".to_owned(),
                value: h1,
            }],
            digest_function: 0,
        }))
        .await?
        .into_inner();

    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    assert!(response.root_directory_digest.is_some());

    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_h1_mismatch_is_aborted() -> Result<(), Status> {
    use nativelink_proto::build::bazel::remote::asset::v1::fetch_server::Fetch as _;

    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);

    let zip_data = build_zip(&[("a.txt", b"alpha")]);
    let uri = serve_once(zip_data).await;

    let response = fs
        .fetch_directory(Request::new(FetchDirectoryRequest {
            instance_name: "foo_instance_name".to_string(),
            timeout: None,
            oldest_content_accepted: None,
            uris: vec![uri],
            qualifiers: vec![Qualifier {
                name: "checksum.h1".to_owned(),
                value: "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            }],
            digest_function: 0,
        }))
        .await?
        .into_inner();

    assert_error_info(response.status.as_ref(), Code::Aborted, "FETCH_FAILED");
    assert!(response.root_directory_digest.is_none());

    Ok(())
}

/// Builds an in-memory tar.gz archive from `(name, content)` entries.
fn build_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    let mut builder = tar::Builder::new(Vec::new());
    for (name, content) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(u64::try_from(content.len()).unwrap());
        header.set_entry_type(tar::EntryType::Regular);
        builder.append_data(&mut header, name, *content).unwrap();
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&builder.into_inner().unwrap()).unwrap();
    encoder.finish().unwrap()
}

/// Reads the root `Directory` a successful directory fetch returned from the CAS.
async fn read_root(store_manager: &StoreManager, response: &FetchDirectoryResponse) -> Directory {
    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    let root_info: DigestInfo = response
        .root_directory_digest
        .clone()
        .expect("expected a root directory digest")
        .try_into()
        .unwrap();
    let cas_store = store_manager.get_store("test_cas_store").unwrap();
    Directory::decode(
        cas_store
            .get_part_unchunked(root_info, 0, None)
            .await
            .unwrap(),
    )
    .unwrap()
}

fn directory_request_with(
    uris: Vec<String>,
    qualifiers: Vec<Qualifier>,
) -> Request<FetchDirectoryRequest> {
    let mut request = directory_request(uris);
    request.get_mut().qualifiers = qualifiers;
    request
}

#[nativelink_test]
async fn test_fetch_directory_without_checksum_succeeds() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let uri = serve_once(build_zip(&[("a.txt", b"alpha"), ("dir/b.txt", b"beta")])).await;

    let response = fs
        .fetch_directory(directory_request_with(vec![uri.clone()], vec![]))
        .await?
        .into_inner();
    assert_eq!(response.uri, uri);
    let root = read_root(&store_manager, &response).await;
    assert_eq!(root.files.len(), 1);
    assert_eq!(root.files[0].name, "a.txt");
    assert_eq!(root.directories[0].name, "dir");

    // The content is in the CAS.
    let cas_store = store_manager.get_store("test_cas_store").unwrap();
    let file: DigestInfo = root.files[0].digest.clone().unwrap().try_into().unwrap();
    assert_eq!(
        cas_store
            .get_part_unchunked(file, 0, None)
            .await
            .unwrap()
            .as_ref(),
        b"alpha"
    );
    Ok(())
}

/// URIs whose archives fail the checksum (or are not archives at all) are
/// skipped in favour of a later one that matches.
async fn directory_checksum_mismatch_falls_through(
    checksum: impl Fn(&[u8]) -> Qualifier,
) -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let good = build_zip(&[("a.txt", b"alpha"), ("dir/b.txt", b"beta")]);
    let qualifier = checksum(&good);
    let not_an_archive = serve_once(b"<html>moved</html>".to_vec()).await;
    let other_archive = serve_once(build_zip(&[("a.txt", b"different")])).await;
    let good_uri = serve_once(good).await;

    let response = fs
        .fetch_directory(directory_request_with(
            vec![not_an_archive, other_archive, good_uri.clone()],
            vec![qualifier],
        ))
        .await?
        .into_inner();
    assert_eq!(response.uri, good_uri);
    let root = read_root(&store_manager, &response).await;
    assert_eq!(root.files[0].name, "a.txt");
    let cas_store = store_manager.get_store("test_cas_store").unwrap();
    let file: DigestInfo = root.files[0].digest.clone().unwrap().try_into().unwrap();
    assert_eq!(
        cas_store
            .get_part_unchunked(file, 0, None)
            .await
            .unwrap()
            .as_ref(),
        b"alpha"
    );
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_sri_mismatch_falls_through_to_next_uri() -> Result<(), Status> {
    directory_checksum_mismatch_falls_through(|archive| {
        header_qualifier("checksum.sri", &sri_of(archive))
    })
    .await
}

#[nativelink_test]
async fn test_fetch_directory_h1_mismatch_falls_through_to_next_uri() -> Result<(), Status> {
    directory_checksum_mismatch_falls_through(|_archive| {
        header_qualifier(
            "checksum.h1",
            &h1_of(&[("a.txt", b"alpha"), ("dir/b.txt", b"beta")]),
        )
    })
    .await
}

#[nativelink_test]
async fn test_fetch_directory_every_checksum_must_match() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let entries: &[(&str, &[u8])] = &[("a.txt", b"alpha")];
    let archive = build_zip(entries);
    let sri = header_qualifier("checksum.sri", &sri_of(&archive));

    // The SRI matches but the h1 does not.
    let uri = serve_once(archive.clone()).await;
    let response = fs
        .fetch_directory(directory_request_with(
            vec![uri],
            vec![
                sri.clone(),
                header_qualifier(
                    "checksum.h1",
                    "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                ),
            ],
        ))
        .await?
        .into_inner();
    assert_error_info(response.status.as_ref(), Code::Aborted, "FETCH_FAILED");

    // Both match.
    let uri = serve_once(archive).await;
    let response = fs
        .fetch_directory(directory_request_with(
            vec![uri],
            vec![sri, header_qualifier("checksum.h1", &h1_of(entries))],
        ))
        .await?
        .into_inner();
    read_root(&store_manager, &response).await;
    Ok(())
}

/// One entry of [`build_tar_gz_tree`].
enum TarEntry {
    File(&'static str, &'static [u8], u32),
    Dir(&'static str),
    Link(&'static str, &'static str),
}

/// Builds a tar.gz with every path under `prefix`, directories, modes and
/// symlinks included.
fn build_tar_gz_tree(prefix: &str, entries: &[TarEntry]) -> Vec<u8> {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    let mut builder = tar::Builder::new(Vec::new());
    for entry in entries {
        let mut header = tar::Header::new_gnu();
        match entry {
            TarEntry::File(name, content, mode) => {
                header.set_mode(*mode);
                header.set_size(u64::try_from(content.len()).unwrap());
                header.set_entry_type(tar::EntryType::Regular);
                builder
                    .append_data(&mut header, format!("{prefix}{name}"), *content)
                    .unwrap();
            }
            TarEntry::Dir(name) => {
                header.set_mode(0o755);
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Directory);
                builder
                    .append_data(&mut header, format!("{prefix}{name}"), std::io::empty())
                    .unwrap();
            }
            TarEntry::Link(name, target) => {
                header.set_mode(0o777);
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Symlink);
                builder
                    .append_link(&mut header, format!("{prefix}{name}"), target)
                    .unwrap();
            }
        }
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&builder.into_inner().unwrap()).unwrap();
    encoder.finish().unwrap()
}

/// A tree with a regular file, an executable, a symlink, nested and empty
/// directories, a non-ASCII name and names whose bytewise order matters.
const NAR_TREE: &[TarEntry] = &[
    TarEntry::Dir("bin/"),
    TarEntry::File("bin/run.sh", b"#!/bin/sh\necho hi\n", 0o755),
    TarEntry::Dir("empty/"),
    TarEntry::Link("link", "bin/run.sh"),
    TarEntry::File("nested/deeper/f", b"deep", 0o644),
    TarEntry::File("café.txt", b"unicode", 0o644),
    TarEntry::File("B", b"upper", 0o644),
    TarEntry::File("a/x", b"in a", 0o644),
    TarEntry::File("a-b", b"dash", 0o644),
    TarEntry::File("a.b", b"dot", 0o644),
    TarEntry::File("zero", b"", 0o644),
    TarEntry::File("pad7", b"1234567", 0o644),
    TarEntry::File("pad8", b"12345678", 0o644),
];

/// `nix hash path --type sha256` (Nix 2.35.3) of [`NAR_TREE`] built on disk
/// with `printf`, `mkdir`, `ln -s` and `chmod`, and the same hash in Nix
/// base-32 (`nix hash convert --to nix32`).
const NAR_TREE_HASH: &str = "sha256-CD7RjZWP2Wwdf1cvg37MXDGv/B/+cZ8c3FZ2dlJs3xk=";
const NAR_TREE_HASH_NIX32: &str = "sha256:06fzdi97cxjnvhf9ywgy3zyaycawriz86bspgwfnrncgjn6x2gh8";

#[nativelink_test]
async fn test_fetch_directory_with_nar_hash() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let archive = build_tar_gz_tree("", NAR_TREE);

    let mut roots = Vec::new();
    for value in [NAR_TREE_HASH, NAR_TREE_HASH_NIX32] {
        let uri = serve_once(archive.clone()).await;
        let response = fs
            .fetch_directory(directory_request_with(
                vec![uri],
                vec![header_qualifier("checksum.nar", value)],
            ))
            .await?
            .into_inner();
        let root = read_root(&store_manager, &response).await;
        assert_eq!(root.files.len(), 7, "{value}");
        assert_eq!(root.directories.len(), 4, "{value}");
        assert_eq!(root.symlinks.len(), 1, "{value}");
        roots.push(response.root_directory_digest);
    }
    assert_eq!(roots[0], roots[1]);
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_nar_mismatch_falls_through_to_next_uri() -> Result<(), Status> {
    directory_checksum_mismatch_falls_through(|_archive| {
        // `nix hash path` of {a.txt: "alpha", dir/b.txt: "beta"}.
        header_qualifier(
            "checksum.nar",
            "sha256-CsoZjhXuorHhbAO4sSoI+rDGBTK8qjwbH58H0hD8vNo=",
        )
    })
    .await
}

#[nativelink_test]
async fn test_fetch_directory_nar_hash_of_the_single_top_level_directory() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    // As GitHub serves a tarball: everything under one `<repo>-<rev>/`.
    let uri = serve_once(build_tar_gz_tree("repo-1.0/", NAR_TREE)).await;

    // Nix hashes the tree without the top-level directory, as fetchzip and
    // fetchFromGitHub do.
    let response = fs
        .fetch_directory(directory_request_with(
            vec![uri],
            vec![header_qualifier("checksum.nar", NAR_TREE_HASH)],
        ))
        .await?
        .into_inner();
    // The returned root is still the archive's root.
    let root = read_root(&store_manager, &response).await;
    assert!(root.files.is_empty());
    assert!(root.symlinks.is_empty());
    assert_eq!(root.directories.len(), 1);
    assert_eq!(root.directories[0].name, "repo-1.0");
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_nar_hash_of_a_git_ordered_tarball() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    // `git archive` puts `foo-x` and `foo.rs` before `foo/`; a NAR does not.
    let uri = serve_once(build_tar_gz_tree(
        "repo-abc/",
        &[
            TarEntry::File("foo-x", b"x\n", 0o644),
            TarEntry::File("foo.rs", b"rs\n", 0o644),
            TarEntry::Dir("foo/"),
            TarEntry::File("foo/bar.rs", b"bar\n", 0o644),
            TarEntry::File("foo/sub/z", b"z\n", 0o644),
            TarEntry::File("zzz", b"end\n", 0o644),
        ],
    ))
    .await;
    // `nix hash path` of the tree without `repo-abc/`.
    let response = fs
        .fetch_directory(directory_request_with(
            vec![uri],
            vec![header_qualifier(
                "checksum.nar",
                "sha256-yZWOCm1M493qYScZuhHicLRdChJQZdDW2Nz8Zcm5nD4=",
            )],
        ))
        .await?
        .into_inner();
    read_root(&store_manager, &response).await;
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_malformed_nar_hash_is_invalid_argument() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    for value in ["sha256-abc", "sha256:0000", "md5-AAAA", "not a hash"] {
        let err = fs
            .fetch_directory(directory_request_with(
                vec!["http://example.invalid/dir".to_owned()],
                vec![header_qualifier("checksum.nar", value)],
            ))
            .await
            .expect_err(value);
        assert_eq!(err.code(), Code::InvalidArgument, "{value}");
        assert!(err.message().contains("checksum.nar"), "{}", err.message());
    }
    Ok(())
}

/// A commit of [`NAR_TREE`] made with git 2.55.0, and its tree:
/// `git write-tree` of the tree built on disk as for [`NAR_TREE_HASH`] (in a
/// SHA-1 and a SHA-256 repository, `core.filemode=true`), then
/// `git commit-tree`. Its `empty/` is not in the tree, since git does not
/// record empty directories.
const GIT_COMMIT: &str = "3a454c8d322612c3f261f9989db87c22a1ddee6a";
const GIT_TREE_SHA1: &str = "5f9826c0f4c82dab9800ca2e0a49f6686301b34d";
const GIT_TREE_SHA256: &str = "3b0894a9b14b20aebb709deaaa6fadc41eb6b7f6cf1227eff676f8ab6645b454";

/// [`NAR_TREE`] as GitHub serves a commit's tarball, which is what
/// `git archive --prefix=repo-<commit>/ <commit>` writes: a pax global
/// header carrying the commit id, then everything under `repo-<commit>/`.
fn github_archive() -> Vec<u8> {
    use std::io::{Read, Write};

    use flate2::Compression;
    use flate2::read::GzDecoder;
    use flate2::write::GzEncoder;

    let mut builder = tar::Builder::new(Vec::new());
    let comment = format!("52 comment={GIT_COMMIT}\n");
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::XGlobalHeader);
    header.set_mode(0o666);
    header.set_size(u64::try_from(comment.len()).unwrap());
    builder
        .append_data(&mut header, "pax_global_header", comment.as_bytes())
        .unwrap();
    let mut tree = Vec::new();
    GzDecoder::new(&build_tar_gz_tree(&format!("repo-{GIT_COMMIT}/"), NAR_TREE)[..])
        .read_to_end(&mut tree)
        .unwrap();
    let mut entries = tar::Archive::new(&tree[..]);
    for entry in entries.entries().unwrap() {
        let mut entry = entry.unwrap();
        let mut header = entry.header().clone();
        let path = entry.path().unwrap().into_owned();
        if let Some(target) = entry.link_name().unwrap() {
            let target = target.into_owned();
            builder.append_link(&mut header, path, target).unwrap();
        } else {
            builder.append_data(&mut header, path, &mut entry).unwrap();
        }
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&builder.into_inner().unwrap()).unwrap();
    encoder.finish().unwrap()
}

#[nativelink_test]
async fn test_fetch_directory_github_archive_with_git_tree_id() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);

    // The commit's tree id, as `git rev-parse <commit>^{tree}` or a Julia
    // `git-tree-sha1` gives it, matches the single top-level directory.
    let mut roots = Vec::new();
    for value in [
        GIT_TREE_SHA1,
        &GIT_TREE_SHA1.to_uppercase(),
        GIT_TREE_SHA256,
    ] {
        let uri = serve_once(github_archive()).await;
        let response = fs
            .fetch_directory(directory_request_with(
                vec![uri],
                vec![header_qualifier("checksum.git_tree", value)],
            ))
            .await?
            .into_inner();
        // The returned root is still the archive's root, without the pax
        // header.
        let root = read_root(&store_manager, &response).await;
        assert!(root.files.is_empty(), "{value}");
        assert!(root.symlinks.is_empty(), "{value}");
        assert_eq!(root.directories.len(), 1, "{value}");
        assert_eq!(
            root.directories[0].name,
            format!("repo-{GIT_COMMIT}"),
            "{value}"
        );
        roots.push(response.root_directory_digest);
    }
    assert_eq!(roots[0], roots[1]);
    assert_eq!(roots[0], roots[2]);
    Ok(())
}

/// GitHub's tarball of Julia's `Example.jl` at `v0.5.5`, downloaded from
/// <https://github.com/JuliaLang/Example.jl/archive/refs/tags/v0.5.5.tar.gz>
/// (SHA-256 `e758fc96eaf4d3c0cc6dfe116b1d0e26b788f880ae900012d1532b6e7370edfc`).
const EXAMPLE_JL_ARCHIVE: &[u8] = include_bytes!("data/Example.jl-0.5.5.tar.gz");

/// The `git-tree-sha1` of `Example` 0.5.5 in Julia's General registry
/// (`E/Example/Versions.toml`). `git write-tree` and Julia's
/// `Pkg.GitTools.tree_hash` of the archive's `Example.jl-0.5.5/` agree.
const EXAMPLE_JL_TREE: &str = "e1f0e1a832ccd8e97d6d0348dec33ee139a5aeaf";

#[nativelink_test]
async fn test_fetch_directory_julia_package_from_github_with_git_tree_sha1() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let uri = serve_once(EXAMPLE_JL_ARCHIVE.to_vec()).await;
    let response = fs
        .fetch_directory(directory_request_with(
            vec![uri],
            vec![header_qualifier("checksum.git_tree", EXAMPLE_JL_TREE)],
        ))
        .await?
        .into_inner();
    let root = read_root(&store_manager, &response).await;
    assert_eq!(root.directories.len(), 1);
    assert_eq!(root.directories[0].name, "Example.jl-0.5.5");
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_git_tree_mismatch_falls_through_to_next_uri() -> Result<(), Status> {
    directory_checksum_mismatch_falls_through(|_archive| {
        // The SHA-1 tree id of {a.txt: "alpha", dir/b.txt: "beta"}.
        header_qualifier(
            "checksum.git_tree",
            "7b202b7775c7bfcdb392cc43bf9463fd13a19eac",
        )
    })
    .await
}

#[nativelink_test]
async fn test_fetch_directory_malformed_git_tree_id_is_invalid_argument() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    for value in ["", "5f9826c", &GIT_TREE_SHA1[1..], "not a tree id"] {
        let err = fs
            .fetch_directory(directory_request_with(
                vec!["http://example.invalid/dir".to_owned()],
                vec![header_qualifier("checksum.git_tree", value)],
            ))
            .await
            .expect_err(value);
        assert_eq!(err.code(), Code::InvalidArgument, "{value}");
        assert!(
            err.message().contains("checksum.git_tree"),
            "{}",
            err.message()
        );
    }
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_all_uris_mismatching_reports_the_last_error() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let archive = build_zip(&[("a.txt", b"alpha")]);
    let uris = vec![
        serve_once(archive.clone()).await,
        serve_once(archive.clone()).await,
    ];
    let response = fs
        .fetch_directory(directory_request_with(
            uris,
            vec![header_qualifier(
                "checksum.sri",
                // Valid SRI of the empty string.
                "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
            )],
        ))
        .await?
        .into_inner();
    assert_error_info(response.status.as_ref(), Code::Aborted, "FETCH_FAILED");
    assert!(response.root_directory_digest.is_none());
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_streamed_body_over_limit_is_resource_exhausted() -> Result<(), Status>
{
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas_and_limit(&store_manager, Some(20));
    // No `Content-Length`, so only the bytes received can trip the cap.
    let uri = serve_once_without_content_length(build_zip(&[("a.txt", b"alpha")])).await;

    let response = fs
        .fetch_directory(directory_request_with(vec![uri], vec![]))
        .await?
        .into_inner();
    assert_eq!(
        response.status.as_ref().map(|s| s.code),
        Some(i32::from(Code::ResourceExhausted))
    );
    assert!(response.root_directory_digest.is_none());
    Ok(())
}

/// A URL fetcher spec with the given archive limits and nothing else set.
fn archive_limits_spec(
    max_archive_entries: Option<usize>,
    max_archive_uncompressed_bytes: Option<u64>,
) -> UrlFetcherSpec {
    UrlFetcherSpec {
        cas_store: String::from("test_cas_store"),
        temp_path: None,
        max_size_bytes: None,
        archive_entry_inline_threshold_bytes: None,
        max_archive_entries,
        max_archive_uncompressed_bytes,
        ..Default::default()
    }
}

#[nativelink_test]
async fn test_fetch_directory_archive_entry_limit() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_url_spec(&store_manager, archive_limits_spec(Some(2), None));
    let archive = build_tar_gz(&[("a.txt", b"a"), ("b.txt", b"b"), ("c.txt", b"c")]);
    let uri = serve_once(archive).await;

    let response = fs
        .fetch_directory(directory_request_with(vec![uri], vec![]))
        .await?
        .into_inner();
    assert_eq!(
        response.status.as_ref().map(|s| s.code),
        Some(i32::from(Code::ResourceExhausted))
    );
    assert!(response.root_directory_digest.is_none());
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_archive_uncompressed_bytes_limit() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs =
        make_fetch_server_with_url_spec(&store_manager, archive_limits_spec(None, Some(1 << 20)));
    // 8 MiB of zeroes compresses to a few KiB, far below any download cap.
    let bomb = vec![0u8; 8 << 20];
    let archive = build_tar_gz(&[("bomb.bin", &bomb)]);
    assert!(archive.len() < 64 * 1024);
    let first = serve_once(archive).await;
    // The next URI is tried after the first fails, and the last error returned.
    let second = serve_once(build_tar_gz(&[("a.txt", b"a"), ("b.txt", b"b")])).await;
    let fs_ok =
        make_fetch_server_with_url_spec(&store_manager, archive_limits_spec(None, Some(1 << 20)));

    let response = fs
        .fetch_directory(directory_request_with(vec![first.clone()], vec![]))
        .await?
        .into_inner();
    assert_eq!(
        response.status.as_ref().map(|s| s.code),
        Some(i32::from(Code::ResourceExhausted))
    );
    assert!(response.root_directory_digest.is_none());

    let response = fs_ok
        .fetch_directory(directory_request_with(vec![second.clone()], vec![]))
        .await?
        .into_inner();
    assert_eq!(response.uri, second);
    assert_eq!(read_root(&store_manager, &response).await.files.len(), 2);
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_archive_over_limit_uri_falls_back_to_next() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_url_spec(&store_manager, archive_limits_spec(Some(2), None));
    let too_many = serve_once(build_tar_gz(&[("a", b"a"), ("b", b"b"), ("c", b"c")])).await;
    let fine = serve_once(build_tar_gz(&[("a", b"a")])).await;

    let response = fs
        .fetch_directory(directory_request_with(vec![too_many, fine.clone()], vec![]))
        .await?
        .into_inner();
    assert_eq!(response.uri, fine);
    assert_eq!(read_root(&store_manager, &response).await.files.len(), 1);
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_archive_under_limits_succeeds() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_url_spec(
        &store_manager,
        archive_limits_spec(Some(10), Some(1 << 20)),
    );
    let uri = serve_once(build_tar_gz(&[("a.txt", b"alpha"), ("dir/b.txt", b"beta")])).await;

    let response = fs
        .fetch_directory(directory_request_with(vec![uri.clone()], vec![]))
        .await?
        .into_inner();
    assert_eq!(response.uri, uri);
    let root = read_root(&store_manager, &response).await;
    assert_eq!(root.files[0].name, "a.txt");
    assert_eq!(root.directories[0].name, "dir");
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_tar_gz_is_streamed_end_to_end() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let temp_dir = tempfile::tempdir().unwrap();
    // Files over 1 KiB are written to a temp file on their way to the CAS.
    let fs = make_fetch_server_with_url_spec(
        &store_manager,
        UrlFetcherSpec {
            cas_store: String::from("test_cas_store"),
            temp_path: Some(temp_dir.path().to_str().unwrap().to_owned()),
            max_size_bytes: None,
            archive_entry_inline_threshold_bytes: Some(1024),
            max_archive_entries: None,
            max_archive_uncompressed_bytes: None,
            ..Default::default()
        },
    );
    let big = vec![b'x'; 3 * 1024 * 1024];
    let entries: &[(&str, &[u8])] = &[("small.txt", b"alpha"), ("dir/big.bin", &big)];
    let tar_gz = build_tar_gz(entries);
    let h1 = h1_of(entries);

    // Verified by SRI of the compressed bytes, and by h1 of the files.
    let mut roots = Vec::new();
    for qualifier in [
        header_qualifier("checksum.sri", &sri_of(&tar_gz)),
        header_qualifier("checksum.h1", &h1),
    ] {
        let uri = serve_once(tar_gz.clone()).await;
        let response = fs
            .fetch_directory(directory_request_with(vec![uri], vec![qualifier]))
            .await?
            .into_inner();
        let root = read_root(&store_manager, &response).await;
        assert_eq!(root.files[0].name, "small.txt");
        assert_eq!(root.directories[0].name, "dir");
        roots.push(response.root_directory_digest);
    }
    assert_eq!(roots[0], roots[1]);

    let cas_store = store_manager.get_store("test_cas_store").unwrap();
    let dir: DigestInfo = Directory::decode(
        cas_store
            .get_part_unchunked(
                DigestInfo::try_from(roots[0].clone().unwrap()).unwrap(),
                0,
                None,
            )
            .await
            .unwrap(),
    )
    .unwrap()
    .directories[0]
        .digest
        .clone()
        .unwrap()
        .try_into()
        .unwrap();
    let dir = Directory::decode(cas_store.get_part_unchunked(dir, 0, None).await.unwrap()).unwrap();
    let big_digest: DigestInfo = dir.files[0].digest.clone().unwrap().try_into().unwrap();
    assert_eq!(
        cas_store
            .get_part_unchunked(big_digest, 0, None)
            .await
            .unwrap()
            .as_ref(),
        big.as_slice()
    );
    // Temp files are gone once uploaded.
    assert_eq!(std::fs::read_dir(temp_dir.path()).unwrap().count(), 0);
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_zip_with_stored_entries_and_data_descriptors() -> Result<(), Status> {
    use std::io::{Cursor, Write};

    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    // Written to a non-seekable stream, so entries carry a data descriptor
    // instead of sizes in their headers, which a reader of the stream can not
    // delimit when they are stored uncompressed.
    let mut writer = ZipWriter::new_stream(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, content) in [("a.txt", &b"alpha"[..]), ("dir/b.txt", b"beta")] {
        writer.start_file(name, options).unwrap();
        writer.write_all(content).unwrap();
    }
    let archive = writer.finish().unwrap().into_inner().into_inner();
    assert_eq!(archive[8], 0, "first entry is stored");
    assert_ne!(archive[6] & 8, 0, "first entry has a data descriptor");

    let expected = make_fetch_server_with_cas(&store_manager)
        .fetch_directory(directory_request_with(
            vec![serve_once(build_zip(&[("a.txt", b"alpha"), ("dir/b.txt", b"beta")])).await],
            vec![],
        ))
        .await?
        .into_inner();

    let sri = sri_of(&archive);
    let uri = serve_once(archive).await;
    let response = fs
        .fetch_directory(directory_request_with(
            vec![uri],
            vec![header_qualifier("checksum.sri", &sri)],
        ))
        .await?
        .into_inner();
    read_root(&store_manager, &response).await;
    assert_eq!(
        response.root_directory_digest,
        expected.root_directory_digest
    );
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

fn directory_request(uris: Vec<String>) -> Request<FetchDirectoryRequest> {
    Request::new(FetchDirectoryRequest {
        instance_name: "foo_instance_name".to_string(),
        timeout: None,
        oldest_content_accepted: None,
        uris,
        qualifiers: vec![],
        digest_function: 0,
    })
}

fn sha256_digest_of(data: &[u8]) -> DigestInfo {
    let mut hasher = DigestHasherFunc::Sha256.hasher();
    hasher.update(data);
    hasher.finalize_digest()
}

/// Stores `data` in `store` under its digest, and returns that digest.
async fn put_blob(store: &Store, data: &[u8]) -> Digest {
    let info = sha256_digest_of(data);
    store
        .update_oneshot(info, data.to_vec().into())
        .await
        .unwrap();
    info.into()
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
    let cas_store = store_manager.get_store("test_cas_store").unwrap();
    write_remote_asset_entry(
        &fetch_store,
        Some(&cas_store),
        &RemoteAssetEntry {
            query: RemoteAssetQuery::new(kind, uri.to_owned(), qualifiers),
            digest,
            expire_at,
            stored_at,
            digest_function: 0,
            tree_digest: None,
            etag: None,
            last_modified: None,
        },
    )
    .await
    .unwrap();
}

/// Removes `digest` from the in-memory CAS, as an eviction would.
async fn evict(store_manager: &StoreManager, digest: &Digest) {
    let cas_store = store_manager.get_store("test_cas_store").unwrap();
    let memory_store = cas_store
        .downcast_ref::<MemoryStore>(None)
        .expect("test_cas_store is a memory store");
    assert!(
        memory_store
            .remove_entry(DigestInfo::try_from(digest).unwrap().into())
            .await,
        "{digest:?} was not in the CAS"
    );
}

/// The digests of a directory seeded by [`seed_directory`].
struct SeededDirectory {
    root: Digest,
    file_a: Digest,
    file_b: Digest,
    sub: Digest,
}

/// Seeds the CAS with `root -> {a.txt, sub -> {b.txt}}` and records the
/// directory in the metadata store under `uri`.
async fn seed_directory(store_manager: &StoreManager, uri: &str) -> SeededDirectory {
    let cas = store_manager.get_store("test_cas_store").unwrap();
    let file_node = |name: &str, digest: &Digest| FileNode {
        name: name.to_owned(),
        digest: Some(digest.clone()),
        ..Default::default()
    };
    let file_a = put_blob(&cas, b"alpha").await;
    let file_b = put_blob(&cas, b"beta").await;
    let sub = Directory {
        files: vec![file_node("b.txt", &file_b)],
        ..Default::default()
    }
    .encode_to_vec();
    let sub = put_blob(&cas, &sub).await;
    let root = Directory {
        files: vec![file_node("a.txt", &file_a)],
        directories: vec![DirectoryNode {
            name: "sub".to_owned(),
            digest: Some(sub.clone()),
        }],
        ..Default::default()
    }
    .encode_to_vec();
    let root = put_blob(&cas, &root).await;
    write_entry(
        store_manager,
        AssetKind::Directory,
        uri,
        vec![],
        root.clone(),
        None,
        None,
    )
    .await;
    SeededDirectory {
        root,
        file_a,
        file_b,
        sub,
    }
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

#[nativelink_test]
async fn test_fetch_directory_complete_in_cas_is_a_hit() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_lookup_server(&store_manager);
    let uri = "http://example.invalid/dir".to_owned();
    let seeded = seed_directory(&store_manager, &uri).await;

    let response = fs
        .fetch_directory(directory_request(vec![uri]))
        .await?
        .into_inner();
    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    assert_eq!(response.root_directory_digest, Some(seeded.root));
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_with_missing_file_is_a_miss() -> Result<(), Status> {
    // `a.txt` is in the tree's root, `b.txt` in a child directory.
    for evicted in ["a.txt", "b.txt"] {
        let store_manager = make_store_manager().await?;
        let fs = make_lookup_server(&store_manager);
        let uri = "http://example.invalid/dir".to_owned();
        let seeded = seed_directory(&store_manager, &uri).await;
        evict(
            &store_manager,
            if evicted == "a.txt" {
                &seeded.file_a
            } else {
                &seeded.file_b
            },
        )
        .await;

        let response = fs
            .fetch_directory(directory_request(vec![uri]))
            .await?
            .into_inner();
        assert_eq!(
            response.status.as_ref().map(|s| s.code),
            Some(i32::from(Code::NotFound)),
            "evicting {evicted}"
        );
        assert!(response.root_directory_digest.is_none());
    }
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_with_missing_tree_is_a_miss() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_lookup_server(&store_manager);
    let uri = "http://example.invalid/dir".to_owned();
    seed_directory(&store_manager, &uri).await;
    let tree_digest =
        Digest::from(stored_tree_digest(&store_manager, AssetKind::Directory, &uri, vec![]).await);
    evict(&store_manager, &tree_digest).await;

    let response = fs
        .fetch_directory(directory_request(vec![uri]))
        .await?
        .into_inner();
    assert_eq!(
        response.status.as_ref().map(|s| s.code),
        Some(i32::from(Code::NotFound))
    );
    assert!(response.root_directory_digest.is_none());
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_with_missing_directory_blob_is_a_miss() -> Result<(), Status> {
    // The root `Directory` blob, then the child's.
    for evicted in ["root", "sub"] {
        let store_manager = make_store_manager().await?;
        let fs = make_lookup_server(&store_manager);
        let uri = "http://example.invalid/dir".to_owned();
        let seeded = seed_directory(&store_manager, &uri).await;
        evict(
            &store_manager,
            if evicted == "root" {
                &seeded.root
            } else {
                &seeded.sub
            },
        )
        .await;

        let response = fs
            .fetch_directory(directory_request(vec![uri]))
            .await?
            .into_inner();
        assert_eq!(
            response.status.as_ref().map(|s| s.code),
            Some(i32::from(Code::NotFound)),
            "evicting {evicted}"
        );
        assert!(response.root_directory_digest.is_none());
    }
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_missing_from_cas_is_refetched() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let zip_data = build_zip(&[("a.txt", b"alpha")]);
    let sri = sri_of(&zip_data);
    let (uri, requests) = serve_recording(zip_data).await;
    let request = || {
        let mut request = directory_request(vec![uri.clone()]);
        request.get_mut().qualifiers = vec![header_qualifier("checksum.sri", &sri)];
        request
    };

    let first = fs.fetch_directory(request()).await?.into_inner();
    assert_eq!(first.status.as_ref().map(|s| s.code), Some(0));
    assert_eq!(requests.lock().len(), 1);
    // A second request is a hit.
    let second = fs.fetch_directory(request()).await?.into_inner();
    assert_eq!(second.root_directory_digest, first.root_directory_digest);
    assert_eq!(requests.lock().len(), 1);

    // Once the archive's file leaves the CAS, the entry is a miss and the
    // directory is fetched again.
    evict(&store_manager, &Digest::from(sha256_digest_of(b"alpha"))).await;
    let third = fs.fetch_directory(request()).await?.into_inner();
    assert_eq!(third.root_directory_digest, first.root_directory_digest);
    assert_eq!(requests.lock().len(), 2);
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

/// The digest of the `Tree` of a stored directory entry.
async fn stored_tree_digest(
    store_manager: &StoreManager,
    kind: AssetKind,
    uri: &str,
    qualifiers: Vec<Qualifier>,
) -> DigestInfo {
    let action_result = stored_action_result(store_manager, kind, uri, qualifiers).await;
    assert_eq!(action_result.output_directories.len(), 1);
    DigestInfo::try_from(
        action_result.output_directories[0]
            .tree_digest
            .as_ref()
            .unwrap(),
    )
    .unwrap()
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
async fn test_fetch_directory_expired_or_too_old_entry_is_a_miss() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_lookup_server(&store_manager);
    let uri = "http://example.invalid/dir".to_owned();
    let seeded = seed_directory(&store_manager, &uri).await;
    let store_entry = |expire_at, stored_at| {
        write_entry(
            &store_manager,
            AssetKind::Directory,
            &uri,
            vec![],
            seeded.root.clone(),
            expire_at,
            stored_at,
        )
    };
    let fetch = |oldest_content_accepted| {
        let mut request = directory_request(vec![uri.clone()]);
        request.get_mut().oldest_content_accepted = oldest_content_accepted;
        fs.fetch_directory(request)
    };

    store_entry(Some(timestamp_ago(60)), None).await;
    assert!(
        fetch(None)
            .await?
            .into_inner()
            .root_directory_digest
            .is_none()
    );

    store_entry(None, Some(timestamp_ago(100))).await;
    assert!(
        fetch(Some(timestamp_ago(10)))
            .await?
            .into_inner()
            .root_directory_digest
            .is_none()
    );
    assert!(
        fetch(Some(timestamp_ago(3600)))
            .await?
            .into_inner()
            .root_directory_digest
            .is_some()
    );
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

#[nativelink_test]
async fn test_fetch_directory_miss_without_fetcher_is_not_cached() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_lookup_server(&store_manager);
    let qualifiers = vec![header_qualifier("checksum.h1", "h1:abc")];
    let mut request = directory_request(vec!["http://example.invalid/dir".to_owned()]);
    request.get_mut().qualifiers = qualifiers.clone();
    request.get_mut().digest_function = i32::from(digest_function::Value::Sha256);

    let response = fs.fetch_directory(request).await?.into_inner();
    assert_error_info(
        response.status.as_ref(),
        Code::NotFound,
        "NOT_CACHED_NO_FETCHER",
    );
    assert_eq!(
        response.status.as_ref().map(|s| s.message.as_str()),
        Some("not cached, and this instance has no fetcher configured")
    );
    assert!(response.root_directory_digest.is_none());
    assert_eq!(response.qualifiers, qualifiers);
    assert_eq!(
        response.digest_function,
        i32::from(digest_function::Value::Sha256)
    );
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_qualifiers() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let entries: &[(&str, &[u8])] = &[("a.txt", b"alpha")];
    let zip_data = build_zip(entries);
    let (uri, requests) = serve_recording(zip_data.clone()).await;
    let request = |qualifiers| {
        let mut request = directory_request(vec![uri.clone()]);
        request.get_mut().qualifiers = qualifiers;
        request
    };

    // On a miss with a fetcher, an unsupported qualifier is rejected before
    // anything is downloaded.
    for name in ["resource_type", "vcs.commit"] {
        let err = fs
            .fetch_directory(request(vec![header_qualifier(name, "v")]))
            .await
            .expect_err(name);
        assert_eq!(err.code(), Code::InvalidArgument, "{name}");
        assert!(err.message().contains(name), "{}", err.message());
        assert!(err.message().contains("checksum.h1"), "{}", err.message());
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

    // Every checksum flavour, the canonical id and headers are supported, so
    // the fetch goes ahead.
    fs.fetch_directory(request(vec![
        header_qualifier("checksum.sri", &sri_of(&zip_data)),
        header_qualifier("checksum.h1", &h1_of(entries)),
        header_qualifier("checksum.nar", NAR_TREE_HASH),
        header_qualifier("checksum.git_tree", GIT_TREE_SHA1),
        header_qualifier("bazel.canonical_id", "id"),
        header_qualifier("http_header:Authorization", "Bearer t"),
    ]))
    .await?;
    assert_eq!(requests.lock().len(), 1);
    Ok(())
}

/// The spec lets a server trust the qualifiers of a pushed directory, so one
/// stored under a qualifier we could not honour on a download is still found,
/// with or without a fetcher, and nothing is downloaded.
#[nativelink_test]
async fn test_fetch_directory_pushed_with_unsupported_qualifier_is_a_hit() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let (uri, requests) = serve_recording(build_zip(&[("a.txt", b"alpha")])).await;
    let seeded = seed_directory(&store_manager, &uri).await;
    let qualifiers = vec![header_qualifier("resource_type", "test")];
    write_entry(
        &store_manager,
        AssetKind::Directory,
        &uri,
        qualifiers.clone(),
        seeded.root.clone(),
        None,
        None,
    )
    .await;

    for fs in [
        make_lookup_server(&store_manager),
        make_fetch_server_with_cas(&store_manager),
    ] {
        let response = fs
            .fetch_directory(directory_request_with(
                vec![uri.clone()],
                qualifiers.clone(),
            ))
            .await?
            .into_inner();
        assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
        assert_eq!(response.root_directory_digest, Some(seeded.root.clone()));
        assert_eq!(response.qualifiers, qualifiers);
    }
    assert!(requests.lock().is_empty(), "a hit needs no download");
    Ok(())
}

/// Without a fetcher nothing is downloaded, so there is nothing to reject: an
/// unsupported qualifier on a directory miss is just a miss.
#[nativelink_test]
async fn test_fetch_directory_unsupported_qualifier_without_fetcher_is_not_cached()
-> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_lookup_server(&store_manager);
    let response = fs
        .fetch_directory(directory_request_with(
            vec!["http://example.invalid/dir".to_owned()],
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

// Known vectors for the hex checksum qualifiers, from
// `printf 'hello world' | sha1sum` (and `sha384sum`, `sha512sum`).
const HELLO_WORLD_SHA1_HEX: &str = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed";
const HELLO_WORLD_SHA384_HEX: &str = "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd";
const HELLO_WORLD_SHA512_HEX: &str = "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";

/// The `sha256` of `data` as lowercase hex.
fn sha256_hex_of(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

#[nativelink_test]
async fn test_fetch_blob_with_each_hex_checksum() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let upper_sha1 = HELLO_WORLD_SHA1_HEX.to_uppercase();
    let prefixed_sha256 = format!("sha256:{HELLO_WORLD_SHA256_HEX}");
    let cases: [(&str, &str); 5] = [
        ("checksum.sha1", HELLO_WORLD_SHA1_HEX),
        ("checksum.sha1", &upper_sha1),
        ("checksum.sha256", &prefixed_sha256),
        ("checksum.sha384", HELLO_WORLD_SHA384_HEX),
        ("checksum.sha512", HELLO_WORLD_SHA512_HEX),
    ];
    for (name, value) in cases {
        let uri = serve_once(HELLO_WORLD.to_vec()).await;
        let response = fs
            .fetch_blob(blob_request(
                vec![uri.clone()],
                vec![header_qualifier(name, value)],
            ))
            .await?
            .into_inner();
        assert_eq!(response.status.as_ref().map(|s| s.code), Some(0), "{name}");
        assert_eq!(response.uri, uri, "{name}");
        assert_eq!(
            response.blob_digest.expect("blob digest").hash,
            HELLO_WORLD_SHA256_HEX,
            "{name}"
        );
    }
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_sha1_mismatch_falls_through_to_next_uri() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let bad_uri = serve_once(b"corrupted".to_vec()).await;
    let good_uri = serve_once(HELLO_WORLD.to_vec()).await;

    let response = fs
        .fetch_blob(blob_request(
            vec![bad_uri, good_uri.clone()],
            vec![header_qualifier("checksum.sha1", HELLO_WORLD_SHA1_HEX)],
        ))
        .await?
        .into_inner();

    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    assert_eq!(response.uri, good_uri);
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_hex_checksum_mismatch_is_aborted() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let uri = serve_once(b"corrupted".to_vec()).await;

    let response = fs
        .fetch_blob(blob_request(
            vec![uri],
            vec![header_qualifier("checksum.sha256", HELLO_WORLD_SHA256_HEX)],
        ))
        .await?
        .into_inner();

    assert_error_info(response.status.as_ref(), Code::Aborted, "FETCH_FAILED");
    assert!(response.blob_digest.is_none());
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_every_checksum_must_match() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let wrong_sha1 = "0".repeat(40);
    let empty_sri = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

    // The SRI matches but the SHA-1 does not.
    let uri = serve_once(HELLO_WORLD.to_vec()).await;
    let response = fs
        .fetch_blob(blob_request(
            vec![uri],
            vec![
                header_qualifier("checksum.sri", HELLO_WORLD_SRI),
                header_qualifier("checksum.sha1", &wrong_sha1),
            ],
        ))
        .await?
        .into_inner();
    assert_error_info(response.status.as_ref(), Code::Aborted, "FETCH_FAILED");

    // The SHA-1 matches but the SRI (of the empty string) does not.
    let uri = serve_once(HELLO_WORLD.to_vec()).await;
    let response = fs
        .fetch_blob(blob_request(
            vec![uri],
            vec![
                header_qualifier("checksum.sri", empty_sri),
                header_qualifier("checksum.sha1", HELLO_WORLD_SHA1_HEX),
            ],
        ))
        .await?
        .into_inner();
    assert_error_info(response.status.as_ref(), Code::Aborted, "FETCH_FAILED");

    // All of them match.
    let uri = serve_once(HELLO_WORLD.to_vec()).await;
    let response = fs
        .fetch_blob(blob_request(
            vec![uri],
            vec![
                header_qualifier("checksum.sri", HELLO_WORLD_SRI),
                header_qualifier("checksum.sha1", HELLO_WORLD_SHA1_HEX),
                header_qualifier("checksum.sha512", HELLO_WORLD_SHA512_HEX),
            ],
        ))
        .await?
        .into_inner();
    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_malformed_hex_checksum_is_invalid_argument() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let too_short = &HELLO_WORLD_SHA1_HEX[..39];
    let non_hex = format!("{}g", &HELLO_WORLD_SHA1_HEX[..39]);
    let sha256_prefix_on_sha1 = format!("sha256:{HELLO_WORLD_SHA1_HEX}");
    let sha1_prefix_on_sha256 = format!("sha1:{HELLO_WORLD_SHA256_HEX}");
    let cases: [(&str, &str); 6] = [
        ("checksum.sha1", too_short),
        ("checksum.sha1", &non_hex),
        ("checksum.sha1", &sha256_prefix_on_sha1),
        ("checksum.sha256", &sha1_prefix_on_sha256),
        ("checksum.sha256", HELLO_WORLD_SHA1_HEX),
        ("checksum.sha512", ""),
    ];
    for (name, value) in cases {
        let err = fs
            .fetch_blob(blob_request(
                vec!["http://example.invalid/blob".to_owned()],
                vec![header_qualifier(name, value)],
            ))
            .await
            .expect_err(value);
        assert_eq!(err.code(), Code::InvalidArgument, "{name}={value}");
        assert!(err.message().contains(name), "{}", err.message());
    }
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_with_sha256_of_archive() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let archive = build_zip(&[("a.txt", b"alpha"), ("dir/b.txt", b"beta")]);
    let checksum = header_qualifier("checksum.sha256", &sha256_hex_of(&archive));
    let uri = serve_once(archive).await;

    let response = fs
        .fetch_directory(directory_request_with(vec![uri.clone()], vec![checksum]))
        .await?
        .into_inner();
    assert_eq!(response.uri, uri);
    let root = read_root(&store_manager, &response).await;
    assert_eq!(root.files[0].name, "a.txt");
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_sha256_mismatch_falls_through_to_next_uri() -> Result<(), Status> {
    directory_checksum_mismatch_falls_through(|archive| {
        header_qualifier("checksum.sha256", &sha256_hex_of(archive))
    })
    .await
}

#[nativelink_test]
async fn test_fetch_directory_hex_and_sri_must_all_match() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let archive = build_zip(&[("a.txt", b"alpha")]);
    let sri = header_qualifier("checksum.sri", &sri_of(&archive));

    // The SRI matches but the SHA-256 does not.
    let uri = serve_once(archive.clone()).await;
    let response = fs
        .fetch_directory(directory_request_with(
            vec![uri],
            vec![
                sri.clone(),
                header_qualifier("checksum.sha256", HELLO_WORLD_SHA256_HEX),
            ],
        ))
        .await?
        .into_inner();
    assert_error_info(response.status.as_ref(), Code::Aborted, "FETCH_FAILED");

    // Both match.
    let uri = serve_once(archive.clone()).await;
    let response = fs
        .fetch_directory(directory_request_with(
            vec![uri],
            vec![
                sri,
                header_qualifier("checksum.sha256", &sha256_hex_of(&archive)),
            ],
        ))
        .await?
        .into_inner();
    read_root(&store_manager, &response).await;
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_malformed_hex_checksum_is_invalid_argument() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let sha1_prefix = format!("sha1:{HELLO_WORLD_SHA256_HEX}");
    for value in ["abc", "zz", &sha1_prefix] {
        let err = fs
            .fetch_directory(directory_request_with(
                vec!["http://example.invalid/dir".to_owned()],
                vec![header_qualifier("checksum.sha256", value)],
            ))
            .await
            .expect_err(value);
        assert_eq!(err.code(), Code::InvalidArgument, "{value}");
    }
    Ok(())
}

#[nativelink_test]
async fn test_fetch_directory_malformed_action_digest_is_invalid_argument() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let hash = "0".repeat(64);
    for value in [
        String::new(),
        "abc/12".to_owned(),
        hash.clone(),
        format!("{hash}/"),
        format!("{hash}/-1"),
        format!("{hash}/x"),
    ] {
        let err = fs
            .fetch_directory(directory_request_with(
                vec!["http://example.invalid/dir".to_owned()],
                vec![header_qualifier("checksum.action_digest", &value)],
            ))
            .await
            .expect_err(&value);
        assert_eq!(err.code(), Code::InvalidArgument, "{value}");
        assert!(
            err.message().contains("checksum.action_digest"),
            "{}",
            err.message()
        );
    }
    Ok(())
}

/// Without an `action_verify` fetcher nothing would run the action, so the
/// fetch fails rather than returning an unverified directory.
#[nativelink_test]
async fn test_fetch_directory_action_digest_needs_an_action_verify_fetcher() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let response = fs
        .fetch_directory(directory_request_with(
            vec!["http://example.invalid/dir".to_owned()],
            vec![header_qualifier(
                "checksum.action_digest",
                &format!("{}/10", "0".repeat(64)),
            )],
        ))
        .await?
        .into_inner();
    assert_error_info(
        response.status.as_ref(),
        Code::FailedPrecondition,
        "FETCH_FAILED",
    );
    assert!(
        response
            .status
            .as_ref()
            .is_some_and(|status| status.message.contains("action_verify")),
        "{response:?}"
    );
    Ok(())
}

/// The status code a response carries.
fn status_code_of(status: Option<&GoogleStatus>) -> Option<i32> {
    Some(status?.code)
}

#[nativelink_test]
async fn test_negative_or_malformed_timeout_is_invalid_argument() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let (uri, requests) = serve_recording(HELLO_WORLD.to_vec()).await;

    for (seconds, nanos) in [(-1, 0), (0, -1), (1, -1), (0, 1_000_000_000)] {
        let timeout = Some(prost_types::Duration { seconds, nanos });
        let mut request = blob_request(vec![uri.clone()], vec![]);
        request.get_mut().timeout = timeout;
        let err = fs
            .fetch_blob(request)
            .await
            .expect_err("a bad timeout is rejected");
        assert_eq!(
            err.code(),
            Code::InvalidArgument,
            "{seconds}s {nanos}ns: {err:?}"
        );

        let mut request = directory_request_with(vec![uri.clone()], vec![]);
        request.get_mut().timeout = timeout;
        let err = fs
            .fetch_directory(request)
            .await
            .expect_err("a bad timeout is rejected");
        assert_eq!(
            err.code(),
            Code::InvalidArgument,
            "{seconds}s {nanos}ns: {err:?}"
        );
    }
    assert!(requests.lock().is_empty(), "nothing is fetched");
    Ok(())
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
async fn test_fetch_directory_timeout_bounds_a_trickling_body() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let archive = build_tar_gz(&[("a.txt", b"alpha")]);
    let (uri, _requests) = serve_trickling(archive, 1, Duration::from_millis(100)).await;

    let mut request = directory_request_with(vec![uri], vec![]);
    request.get_mut().timeout = Some(prost_types::Duration {
        seconds: 0,
        nanos: 300_000_000,
    });
    let response = fs.fetch_directory(request).await?.into_inner();

    assert_eq!(
        status_code_of(response.status.as_ref()),
        Some(i32::from(Code::DeadlineExceeded)),
        "{response:?}"
    );
    assert!(response.root_directory_digest.is_none());
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
async fn test_short_timeout_does_not_fail_a_longer_identical_request() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = Arc::new(make_fetch_server_with_cas(&store_manager));
    // The body takes about 1.1 seconds to arrive.
    let (uri, requests) =
        serve_trickling(HELLO_WORLD.to_vec(), 1, Duration::from_millis(100)).await;

    let with_timeout = |timeout: prost_types::Duration| {
        let mut request = blob_request(vec![uri.clone()], vec![]);
        request.get_mut().timeout = Some(timeout);
        request
    };
    let short = with_timeout(prost_types::Duration {
        seconds: 0,
        nanos: 300_000_000,
    });
    let long = with_timeout(prost_types::Duration {
        seconds: 600,
        nanos: 0,
    });
    let short = {
        let fs = fs.clone();
        tokio::spawn(async move { fs.fetch_blob(short).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let long = {
        let fs = fs.clone();
        tokio::spawn(async move { fs.fetch_blob(long).await })
    };

    // The short request times out; the long one joined the same download and
    // gets its result.
    let short = short.await.unwrap()?.into_inner();
    assert_eq!(
        status_code_of(short.status.as_ref()),
        Some(i32::from(Code::DeadlineExceeded)),
        "{short:?}"
    );
    let long = long.await.unwrap()?.into_inner();
    assert_eq!(status_code_of(long.status.as_ref()), Some(0), "{long:?}");
    assert_eq!(
        long.blob_digest.expect("expected a blob digest").hash,
        HELLO_WORLD_SHA256_HEX
    );
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    Ok(())
}

/// Spawns an HTTP/1.1 server that waits `delay` before answering each request:
/// with `body` if it carries `authorization: <token>`, else with `401`. Returns
/// the URL and the number of requests the server has received.
async fn serve_authorizing(
    body: Vec<u8>,
    token: &'static str,
    delay: Duration,
) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    background_spawn!("fetch_test_authorizing_http_server", async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let body = body.clone();
            let counted = counted.clone();
            background_spawn!("fetch_test_authorizing_http_connection", async move {
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
                tokio::time::sleep(delay).await;
                let request = String::from_utf8_lossy(&request).to_lowercase();
                let authorized = request.contains(&format!("authorization: {token}\r\n"));
                let (status, body) = if authorized {
                    ("200 OK", body)
                } else {
                    ("401 Unauthorized", Vec::new())
                };
                let header = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                drop(socket.write_all(header.as_bytes()).await);
                drop(socket.write_all(&body).await);
                drop(socket.flush().await);
            });
        }
    });
    (format!("http://{addr}/blob"), requests)
}

#[nativelink_test]
async fn test_bad_credentials_do_not_fail_a_concurrent_good_request() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = Arc::new(make_fetch_server_with_cas(&store_manager));
    let (uri, requests) = serve_authorizing(
        HELLO_WORLD.to_vec(),
        "bearer good",
        Duration::from_millis(500),
    )
    .await;

    let with_token = |token: &str| {
        blob_request(
            vec![uri.clone()],
            vec![
                header_qualifier("checksum.sri", HELLO_WORLD_SRI),
                header_qualifier("http_header:Authorization", token),
            ],
        )
    };
    let bad = with_token("Bearer expired");
    let good = with_token("Bearer good");
    let bad = {
        let fs = fs.clone();
        tokio::spawn(async move { fs.fetch_blob(bad).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let good = {
        let fs = fs.clone();
        tokio::spawn(async move { fs.fetch_blob(good).await })
    };

    // The good request arrived while the bad one's fetch was under way, but it
    // ran its own fetch with its own credentials.
    let bad = bad.await.unwrap()?.into_inner();
    assert_ne!(status_code_of(bad.status.as_ref()), Some(0), "{bad:?}");
    let good = good.await.unwrap()?.into_inner();
    assert_eq!(status_code_of(good.status.as_ref()), Some(0), "{good:?}");
    assert_eq!(
        good.blob_digest.expect("expected a blob digest").hash,
        HELLO_WORLD_SHA256_HEX
    );
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    Ok(())
}

#[nativelink_test]
async fn test_rpc_deadline_applies_to_directory_fetches() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let archive = build_tar_gz(&[("a.txt", b"alpha")]);
    let (uri, _requests) = serve_trickling(archive, 1, Duration::from_millis(100)).await;

    let mut request = directory_request_with(vec![uri], vec![]);
    request.set_timeout(Duration::from_millis(300));
    let err = fs
        .fetch_directory(request)
        .await
        .expect_err("the fetch cannot finish within the RPC deadline");
    assert_eq!(err.code(), Code::DeadlineExceeded, "{err:?}");
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
    let schedulers: HashMap<String, Arc<dyn ClientStateManager>> = HashMap::new();
    fetcher_factory(
        &FetcherSpec::Url(spec),
        &store_manager,
        &schedulers,
        &HashMap::new(),
    )
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

/// A URL fetcher spec that requires every fetch to carry a checksum.
fn require_checksum_spec() -> UrlFetcherSpec {
    UrlFetcherSpec {
        cas_store: String::from("test_cas_store"),
        require_checksum: true,
        ..Default::default()
    }
}

#[nativelink_test]
async fn test_require_checksum_rejects_a_blob_without_one() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_url_spec(&store_manager, require_checksum_spec());
    let (uri, origin_requests) = serve_recording(HELLO_WORLD.to_vec()).await;

    // Even a request carrying other qualifiers and headers has no checksum.
    let err = fs
        .fetch_blob(blob_request(
            vec![uri],
            vec![
                header_qualifier("bazel.canonical_id", "id"),
                header_qualifier("http_header:Authorization", "Bearer t"),
            ],
        ))
        .await
        .expect_err("a blob without a checksum is rejected");

    // An RPC error, not a failed fetch in the response status, and no origin
    // was contacted.
    assert_eq!(err.code(), Code::InvalidArgument, "{err:?}");
    assert!(err.message().contains("checksum"), "{}", err.message());
    assert!(origin_requests.lock().is_empty());
    Ok(())
}

#[nativelink_test]
async fn test_require_checksum_rejects_a_directory_without_one() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_url_spec(&store_manager, require_checksum_spec());
    let (uri, origin_requests) = serve_recording(build_tar_gz(&[("a.txt", b"alpha")])).await;

    let err = fs
        .fetch_directory(directory_request(vec![uri]))
        .await
        .expect_err("a directory without a checksum is rejected");

    assert_eq!(err.code(), Code::InvalidArgument, "{err:?}");
    assert!(err.message().contains("checksum"), "{}", err.message());
    assert!(origin_requests.lock().is_empty());
    Ok(())
}

#[nativelink_test]
async fn test_require_checksum_downloads_when_there_is_one() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_url_spec(&store_manager, require_checksum_spec());

    let (uri, origin_requests) = serve_recording(HELLO_WORLD.to_vec()).await;
    let response = fs
        .fetch_blob(blob_request(
            vec![uri],
            vec![header_qualifier("checksum.sri", HELLO_WORLD_SRI)],
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
    assert_eq!(origin_requests.lock().len(), 1);

    // A directory is satisfied by a checksum of the archive, and by a tree hash.
    let entries: &[(&str, &[u8])] = &[("a.txt", b"alpha")];
    let archive = build_tar_gz(entries);
    for qualifier in [
        header_qualifier("checksum.sri", &sri_of(&archive)),
        header_qualifier("checksum.h1", &h1_of(entries)),
    ] {
        let (uri, origin_requests) = serve_recording(archive.clone()).await;
        let response = fs
            .fetch_directory(directory_request_with(vec![uri], vec![qualifier]))
            .await?
            .into_inner();
        assert_eq!(
            status_code_of(response.status.as_ref()),
            Some(0),
            "{response:?}"
        );
        assert!(response.root_directory_digest.is_some());
        assert_eq!(origin_requests.lock().len(), 1);
    }
    Ok(())
}

#[nativelink_test]
async fn test_require_checksum_still_serves_a_pushed_asset_without_one() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_url_spec(&store_manager, require_checksum_spec());
    let (uri, origin_requests) = serve_recording(b"not what was pushed".to_vec()).await;

    // An asset pushed under this URI, with no checksum qualifier, and its
    // content.
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
        vec![],
        digest.clone(),
        None,
        None,
    )
    .await;

    // Nothing is downloaded, so there is nothing to require a checksum of.
    let response = fs
        .fetch_blob(blob_request(vec![uri], vec![]))
        .await?
        .into_inner();
    assert_eq!(
        status_code_of(response.status.as_ref()),
        Some(0),
        "{response:?}"
    );
    assert_eq!(response.blob_digest, Some(digest));
    assert!(origin_requests.lock().is_empty());
    Ok(())
}

#[nativelink_test]
async fn test_malformed_archive_is_a_fetch_failure_not_an_invalid_request() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let uri = serve_once(b"this is not an archive".to_vec()).await;

    // The origin served bad content, which is outside the server's control, so
    // it is reported in the response status; INVALID_ARGUMENT is reserved for
    // a bad request.
    let response = fs
        .fetch_directory(directory_request(vec![uri]))
        .await?
        .into_inner();
    assert_eq!(
        status_code_of(response.status.as_ref()),
        Some(i32::from(Code::Aborted)),
        "{response:?}"
    );
    assert!(response.root_directory_digest.is_none());
    Ok(())
}

/// A scheduler for fetchers that must not reach it: a missing verification
/// template fails before anything is scheduled.
#[derive(Debug)]
struct UnusedScheduler;

impl MetricsComponent for UnusedScheduler {
    fn publish(
        &self,
        _kind: MetricKind,
        _field_metadata: MetricFieldData,
    ) -> Result<MetricPublishKnownKindData, nativelink_metric::Error> {
        Ok(MetricPublishKnownKindData::Component)
    }
}

#[async_trait]
impl ClientStateManager for UnusedScheduler {
    async fn add_action(
        &self,
        _client_operation_id: OperationId,
        _action_info: Arc<ActionInfo>,
    ) -> Result<Box<dyn ActionStateResult>, Error> {
        Err(make_err!(
            ErrorCode::Unimplemented,
            "no scheduler in this test"
        ))
    }

    async fn filter_operations(
        &self,
        _filter: OperationFilter,
    ) -> Result<ActionStateResultStream, Error> {
        Err(make_err!(
            ErrorCode::Unimplemented,
            "no scheduler in this test"
        ))
    }
}

/// A `FetchServer` whose fetcher is an `action_verify` over a `url` fetcher.
fn make_action_verify_server(store_manager: &StoreManager) -> FetchServer {
    let mut schedulers: HashMap<String, Arc<dyn ClientStateManager>> = HashMap::new();
    schedulers.insert("SCHEDULER".to_string(), Arc::new(UnusedScheduler));
    let mut fetchers: HashMap<String, Arc<dyn Fetcher>> = HashMap::new();
    let url = fetcher_factory(
        &FetcherSpec::Url(UrlFetcherSpec {
            cas_store: String::from("test_cas_store"),
            temp_path: None,
            max_size_bytes: None,
            archive_entry_inline_threshold_bytes: None,
            max_archive_entries: None,
            max_archive_uncompressed_bytes: None,
            ..Default::default()
        }),
        store_manager,
        &schedulers,
        &fetchers,
    )
    .expect("failed to build url fetcher");
    fetchers.insert("URL".to_string(), url);
    let verify = fetcher_factory(
        &FetcherSpec::ActionVerify(ActionVerifySpec {
            fetcher: String::from("URL"),
            cas_store: String::from("test_cas_store"),
            scheduler: String::from("SCHEDULER"),
            instance_name: String::new(),
        }),
        store_manager,
        &schedulers,
        &fetchers,
    )
    .expect("failed to build action_verify fetcher");
    fetchers.insert("VERIFY".to_string(), verify);
    FetchServer::new(
        &[WithInstanceName {
            instance_name: "foo_instance_name".to_string(),
            config: FetchConfig {
                fetch_store: String::from("test_fetch_store"),
                fetcher: Some(String::from("VERIFY")),
            },
        }],
        &fetchers,
        store_manager,
    )
    .expect("FetchServer config error")
}

/// The `subject`s of the `MISSING` violations in the `PreconditionFailure`
/// detail of `status`, decoded from the wire form.
fn missing_subjects(status: &GoogleStatus) -> Vec<String> {
    let detail = status
        .details
        .iter()
        .find(|detail| detail.type_url == "type.googleapis.com/google.rpc.PreconditionFailure")
        .unwrap_or_else(|| panic!("no PreconditionFailure detail: {status:?}"));
    let failure = PreconditionFailure::decode(detail.value.as_slice()).unwrap();
    assert!(
        failure
            .violations
            .iter()
            .all(|violation| violation.r#type == "MISSING"),
        "{failure:?}"
    );
    let mut subjects: Vec<String> = failure
        .violations
        .into_iter()
        .map(|violation| violation.subject)
        .collect();
    subjects.sort();
    subjects
}

fn blob_subject(digest: &Digest) -> String {
    format!("blobs/{}/{}", digest.hash, digest.size_bytes)
}

/// Fetches a directory with `action` as its `checksum.action_digest`.
async fn fetch_with_action(fs: &FetchServer, action: &Digest) -> FetchDirectoryResponse {
    fs.fetch_directory(directory_request_with(
        vec!["http://example.invalid/dir".to_owned()],
        vec![header_qualifier(
            "checksum.action_digest",
            &format!("{}/{}", action.hash, action.size_bytes),
        )],
    ))
    .await
    .unwrap()
    .into_inner()
}

/// A verification template with blobs missing from the CAS fails the fetch
/// with a `PreconditionFailure` naming every blob to upload, so that the client
/// can upload exactly those and retry.
#[nativelink_test]
async fn test_fetch_directory_missing_template_blobs_are_a_precondition_failure()
-> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_action_verify_server(&store_manager);
    let cas = store_manager.get_store("test_cas_store").unwrap();
    let absent = |data: &[u8]| -> Digest { sha256_digest_of(data).into() };

    // The action itself is missing: it is the only blob that can be named.
    let action_digest = absent(b"no such action");
    let response = fetch_with_action(&fs, &action_digest).await;
    let status = response.status.as_ref().expect("response has no status");
    assert_eq!(
        status.code,
        i32::from(Code::FailedPrecondition),
        "{status:?}"
    );
    assert_eq!(missing_subjects(status), vec![blob_subject(&action_digest)]);
    // The detail does not displace the reason clients branch on.
    assert!(
        status
            .details
            .iter()
            .any(|detail| detail.type_url == "type.googleapis.com/google.rpc.ErrorInfo"),
        "{status:?}"
    );

    // The action is there but its command and its input root are not: both
    // are named at once.
    let (command, root) = (absent(b"no such command"), absent(b"no such root"));
    let action = Action {
        command_digest: Some(command.clone()),
        input_root_digest: Some(root.clone()),
        ..Default::default()
    };
    let action_digest = put_blob(&cas, &action.encode_to_vec()).await;
    let response = fetch_with_action(&fs, &action_digest).await;
    let status = response.status.as_ref().expect("response has no status");
    assert_eq!(
        status.code,
        i32::from(Code::FailedPrecondition),
        "{status:?}"
    );
    let mut want = vec![blob_subject(&command), blob_subject(&root)];
    want.sort();
    assert_eq!(missing_subjects(status), want);

    // The command and the input root are there but a directory on the way to
    // where the fetched tree goes is not.
    let subdirectory = absent(b"no such directory");
    let root = Directory {
        directories: vec![DirectoryNode {
            name: "bin".to_owned(),
            digest: Some(subdirectory.clone()),
        }],
        ..Default::default()
    };
    let root = put_blob(&cas, &root.encode_to_vec()).await;
    let command = Command {
        environment_variables: vec![EnvironmentVariable {
            name: "NATIVELINK_FETCHED_DIRECTORY".to_owned(),
            value: "bin/src".to_owned(),
        }],
        ..Default::default()
    };
    let action = Action {
        command_digest: Some(put_blob(&cas, &command.encode_to_vec()).await),
        input_root_digest: Some(root),
        ..Default::default()
    };
    let action_digest = put_blob(&cas, &action.encode_to_vec()).await;
    let response = fetch_with_action(&fs, &action_digest).await;
    let status = response.status.as_ref().expect("response has no status");
    assert_eq!(
        status.code,
        i32::from(Code::FailedPrecondition),
        "{status:?}"
    );
    assert_eq!(missing_subjects(status), vec![blob_subject(&subdirectory)]);
    Ok(())
}

/// A `FetchBlob` request for one URI, with `qualifiers`.
fn plain_blob_request(uri: &str, qualifiers: Vec<Qualifier>) -> Request<FetchBlobRequest> {
    Request::new(FetchBlobRequest {
        instance_name: "foo_instance_name".to_string(),
        timeout: None,
        oldest_content_accepted: None,
        uris: vec![uri.to_string()],
        qualifiers,
        digest_function: 0,
    })
}

/// A server whose metadata cache lets a one second `max-age` through.
fn make_short_ttl_server(store_manager: &StoreManager) -> FetchServer {
    make_fetch_server_with_ttls(
        store_manager,
        UrlFetcherSpec {
            cas_store: String::from("test_cas_store"),
            temp_path: None,
            max_size_bytes: None,
            archive_entry_inline_threshold_bytes: None,
            max_archive_entries: None,
            max_archive_uncompressed_bytes: None,
            ..Default::default()
        },
        (60, 0, 60),
    )
}

#[nativelink_test]
async fn test_fetch_blob_unpinned_entry_expires_by_the_origins_max_age() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_short_ttl_server(&store_manager);
    let (uri, requests) =
        serve_recording_with_headers(HELLO_WORLD.to_vec(), "Cache-Control: max-age=1\r\n").await;

    let first = fs
        .fetch_blob(plain_blob_request(&uri, vec![]))
        .await?
        .into_inner();
    assert_eq!(first.status.as_ref().map(|s| s.code), Some(0));
    let expires_at = first.expires_at.expect("an unpinned fetch should expire");
    let now = now_timestamp();
    let remaining = expires_at.seconds - now.seconds;
    assert!((0..=1).contains(&remaining), "expires in {remaining}s");

    // Fresh: served from the cache.
    fs.fetch_blob(plain_blob_request(&uri, vec![])).await?;
    assert_eq!(requests.lock().len(), 1);

    // Past it: fetched again, and given a new expiry.
    tokio::time::sleep(core::time::Duration::from_millis(1200)).await;
    let third = fs
        .fetch_blob(plain_blob_request(&uri, vec![]))
        .await?
        .into_inner();
    assert_eq!(third.status.as_ref().map(|s| s.code), Some(0));
    assert_eq!(requests.lock().len(), 2);
    assert!(third.expires_at.unwrap().seconds > expires_at.seconds);
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_unpinned_no_store_is_refetched_every_time() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_fetch_server_with_cas(&store_manager);
    let (uri, requests) =
        serve_recording_with_headers(HELLO_WORLD.to_vec(), "Cache-Control: no-store\r\n").await;

    for expected in 1..=3 {
        let response = fs
            .fetch_blob(plain_blob_request(&uri, vec![]))
            .await?
            .into_inner();
        assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
        assert_eq!(requests.lock().len(), expected);
    }
    // The content is in the CAS all the same.
    let cas_store = store_manager.get_store("test_cas_store").unwrap();
    assert!(
        cas_store
            .has(sha256_digest_of(HELLO_WORLD))
            .await
            .unwrap()
            .is_some()
    );
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_pinned_entry_ignores_the_origins_max_age() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_short_ttl_server(&store_manager);
    let (uri, requests) =
        serve_recording_with_headers(HELLO_WORLD.to_vec(), "Cache-Control: max-age=1\r\n").await;
    let qualifiers = vec![Qualifier {
        name: "checksum.sri".to_string(),
        value: sri_of(HELLO_WORLD),
    }];

    let first = fs
        .fetch_blob(plain_blob_request(&uri, qualifiers.clone()))
        .await?
        .into_inner();
    assert_eq!(first.status.as_ref().map(|s| s.code), Some(0));
    assert_eq!(first.expires_at, None);

    tokio::time::sleep(core::time::Duration::from_millis(1200)).await;
    let second = fs
        .fetch_blob(plain_blob_request(&uri, qualifiers))
        .await?
        .into_inner();
    assert_eq!(second.status.as_ref().map(|s| s.code), Some(0));
    assert_eq!(second.expires_at, None);
    assert_eq!(requests.lock().len(), 1, "a pinned entry never expires");
    Ok(())
}

/// Spawns an origin that serves `body` with `ETag: "v1"` and
/// `Cache-Control: max-age=1`, and answers a request carrying
/// `If-None-Match: "v1"` with `304`, as long as `current` is set. Returns the
/// URL and every request seen.
async fn serve_validating(
    body: Vec<u8>,
    current: Arc<core::sync::atomic::AtomicBool>,
) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    background_spawn!("fetch_test_validating_http_server", async move {
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
            let request = String::from_utf8_lossy(&request).to_lowercase();
            let not_modified = request.contains("if-none-match: \"v1\"")
                && current.load(core::sync::atomic::Ordering::SeqCst);
            recorded.lock().push(request);
            let response = if not_modified {
                "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nCache-Control: max-age=1\r\nConnection: close\r\n\r\n"
                    .to_string()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"v1\"\r\nCache-Control: max-age=1\r\nConnection: close\r\n\r\n",
                    body.len()
                )
            };
            socket.write_all(response.as_bytes()).await.unwrap();
            if !not_modified {
                socket.write_all(&body).await.unwrap();
            }
            socket.flush().await.unwrap();
        }
    });
    (format!("http://{addr}/blob"), requests)
}

#[nativelink_test]
async fn test_fetch_blob_stale_unpinned_entry_is_revalidated() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_short_ttl_server(&store_manager);
    let current = Arc::new(core::sync::atomic::AtomicBool::new(true));
    let (uri, requests) = serve_validating(HELLO_WORLD.to_vec(), current.clone()).await;

    let first = fs
        .fetch_blob(plain_blob_request(&uri, vec![]))
        .await?
        .into_inner();
    assert_eq!(first.status.as_ref().map(|s| s.code), Some(0));
    assert!(!requests.lock()[0].contains("if-none-match"));

    // Expired: asked whether it is still current, and it is.
    tokio::time::sleep(core::time::Duration::from_millis(1200)).await;
    let second = fs
        .fetch_blob(plain_blob_request(&uri, vec![]))
        .await?
        .into_inner();
    assert_eq!(second.status.as_ref().map(|s| s.code), Some(0));
    assert_eq!(second.blob_digest, first.blob_digest);
    assert!(requests.lock()[1].contains("if-none-match: \"v1\""));
    assert!(second.expires_at.unwrap().seconds > first.expires_at.unwrap().seconds);

    // The entry was rewritten with a new expiry, so it is fresh again.
    fs.fetch_blob(plain_blob_request(&uri, vec![])).await?;
    assert_eq!(requests.lock().len(), 2);

    // Once the content changes, a revalidation downloads it.
    tokio::time::sleep(core::time::Duration::from_millis(1200)).await;
    current.store(false, core::sync::atomic::Ordering::SeqCst);
    let fourth = fs
        .fetch_blob(plain_blob_request(&uri, vec![]))
        .await?
        .into_inner();
    assert_eq!(fourth.blob_digest, first.blob_digest);
    let requests = requests.lock();
    assert_eq!(requests.len(), 3);
    assert!(requests[2].contains("if-none-match: \"v1\""));
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_revalidated_content_gone_from_the_cas_is_downloaded() -> Result<(), Status>
{
    let store_manager = make_store_manager().await?;
    let fs = make_short_ttl_server(&store_manager);
    let current = Arc::new(core::sync::atomic::AtomicBool::new(true));
    let (uri, requests) = serve_validating(HELLO_WORLD.to_vec(), current).await;
    let first = fs
        .fetch_blob(plain_blob_request(&uri, vec![]))
        .await?
        .into_inner();
    let digest = first.blob_digest.unwrap();

    // The stale entry reads as a miss through the completeness-checking fetch
    // store once its content is gone, so there is nothing to revalidate; the
    // content comes back all the same.
    tokio::time::sleep(core::time::Duration::from_millis(1200)).await;
    evict(&store_manager, &digest).await;
    let second = fs
        .fetch_blob(plain_blob_request(&uri, vec![]))
        .await?
        .into_inner();
    assert_eq!(second.status.as_ref().map(|s| s.code), Some(0));
    assert_eq!(second.blob_digest, Some(digest.clone()));
    assert_eq!(requests.lock().len(), 2);
    let cas_store = store_manager.get_store("test_cas_store").unwrap();
    assert!(
        cas_store
            .has(DigestInfo::try_from(&digest).unwrap())
            .await
            .unwrap()
            .is_some()
    );
    Ok(())
}

#[nativelink_test]
async fn test_fetch_blob_pinned_request_never_revalidates() -> Result<(), Status> {
    let store_manager = make_store_manager().await?;
    let fs = make_short_ttl_server(&store_manager);
    let current = Arc::new(core::sync::atomic::AtomicBool::new(true));
    let (uri, requests) = serve_validating(HELLO_WORLD.to_vec(), current).await;
    let qualifiers = vec![Qualifier {
        name: "checksum.sri".to_string(),
        value: sri_of(HELLO_WORLD),
    }];
    fs.fetch_blob(plain_blob_request(&uri, qualifiers.clone()))
        .await?;
    tokio::time::sleep(core::time::Duration::from_millis(1200)).await;

    // Too old for the client, but pinned: downloaded again, with no
    // conditional request, though the origin sent an ETag the first time.
    let mut request = plain_blob_request(&uri, qualifiers);
    request.get_mut().oldest_content_accepted = Some(now_timestamp());
    let response = fs.fetch_blob(request).await?.into_inner();
    assert_eq!(response.status.as_ref().map(|s| s.code), Some(0));
    let requests = requests.lock();
    assert_eq!(requests.len(), 2);
    assert!(!requests[1].contains("if-none-match"));
    Ok(())
}
