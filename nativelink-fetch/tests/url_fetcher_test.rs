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

//! Tests of [`UrlFetcher`] against scriptable local HTTP servers.

use core::fmt::Write as _;
use core::time::Duration;
use std::sync::Arc;

use nativelink_config::stores::{MemorySpec, StoreSpec};
use nativelink_error::Code;
use nativelink_fetch::fetcher::{
    FetchBlobTask, FetchDirectoryJob, FetchHeaders, Fetcher, Revalidation, Validators,
};
use nativelink_fetch::url_fetcher::{UrlFetcher, UrlFetcherOptions};
use nativelink_macro::nativelink_test;
use nativelink_proto::build::bazel::remote::asset::v1::Qualifier;
use nativelink_store::default_store_factory::store_factory;
use nativelink_store::memory_store::MemoryStore;
use nativelink_store::store_manager::StoreManager;
use nativelink_util::background_spawn;
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::{DigestHasher, DigestHasherFunc};
use nativelink_util::store_trait::{Store, StoreLike};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

mod support;

const BODY: &[u8] = b"Hello, world!";

/// A request as a test server saw it. `raw` is the whole request head,
/// lowercased so header names compare case-insensitively.
#[derive(Clone, Debug)]
struct Seen {
    path: String,
    raw: String,
}

/// A scripted response.
struct Reply {
    status: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn ok(body: &[u8]) -> Self {
        Self {
            status: "200 OK",
            headers: vec![],
            body: body.to_vec(),
        }
    }

    const fn not_modified() -> Self {
        Self {
            status: "304 Not Modified",
            headers: vec![],
            body: vec![],
        }
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    fn redirect(location: &str) -> Self {
        Self {
            status: "302 Found",
            headers: vec![("Location".to_string(), location.to_string())],
            body: vec![],
        }
    }
}

/// Serves every request on a fresh local port with `handler`, returning the
/// server's base URL (`http://127.0.0.1:<port>`) and every request seen.
async fn serve<F>(handler: F) -> (String, Arc<Mutex<Vec<Seen>>>)
where
    F: Fn(&Seen) -> Reply + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = seen.clone();
    background_spawn!("url_fetcher_test_http_server", async move {
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
            let raw = String::from_utf8_lossy(&request).to_lowercase();
            let path = raw
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_string();
            let request = Seen { path, raw };
            let reply = handler(&request);
            recorded.lock().push(request);
            let mut head = format!(
                "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                reply.status,
                reply.body.len()
            );
            for (name, value) in &reply.headers {
                write!(head, "{name}: {value}\r\n").unwrap();
            }
            head.push_str("\r\n");
            socket.write_all(head.as_bytes()).await.unwrap();
            socket.write_all(&reply.body).await.unwrap();
            socket.flush().await.unwrap();
        }
    });
    (base, seen)
}

async fn memory_store() -> Store {
    let store_manager = Arc::new(StoreManager::new());
    store_factory(
        &StoreSpec::Memory(MemorySpec::default()),
        &store_manager,
        None,
    )
    .await
    .unwrap()
}

fn digest_of(data: &[u8]) -> DigestInfo {
    let mut hasher = DigestHasherFunc::Sha256.hasher();
    hasher.update(data);
    hasher.finalize_digest()
}

fn job(uri: &str, headers: FetchHeaders) -> FetchBlobTask {
    FetchBlobTask {
        uris: vec![uri.to_string()],
        qualifiers: vec![],
        checksums: vec![],
        hasher_func: DigestHasherFunc::Sha256,
        timeout: None,
        headers,
        revalidate: vec![],
        shared_deadline: None,
    }
}

fn authorization_header() -> FetchHeaders {
    FetchHeaders::from_qualifiers(
        &[Qualifier {
            name: "http_header:Authorization".to_string(),
            value: "Bearer s3cret".to_string(),
        }],
        1,
    )
    .unwrap()
}

#[nativelink_test]
async fn a_redirect_is_followed() {
    let (target, _) = serve(|_| Reply::ok(BODY)).await;
    let final_url = format!("{target}/final");
    let (origin, _) = serve(move |_| Reply::redirect(&final_url)).await;
    let cas = memory_store().await;
    let fetcher = UrlFetcher::new(cas.clone(), UrlFetcherOptions::default()).unwrap();

    let uri = format!("{origin}/start");
    let outcome = fetcher
        .fetch_blob(&job(&uri, FetchHeaders::default()))
        .await
        .unwrap();

    assert_eq!(outcome.digest, digest_of(BODY));
    assert_eq!(outcome.uri, uri);
    assert!(cas.has(outcome.digest).await.unwrap().is_some());
}

#[nativelink_test]
async fn authorization_is_not_forwarded_on_a_cross_host_redirect() {
    let (target, target_seen) = serve(|_| Reply::ok(BODY)).await;
    let final_url = format!("{target}/final");
    let (origin, origin_seen) = serve(move |_| Reply::redirect(&final_url)).await;
    let fetcher = UrlFetcher::new(memory_store().await, UrlFetcherOptions::default()).unwrap();

    fetcher
        .fetch_blob(&job(&format!("{origin}/start"), authorization_header()))
        .await
        .unwrap();

    let origin_requests = origin_seen.lock().clone();
    assert!(
        origin_requests[0]
            .raw
            .contains("authorization: bearer s3cret"),
        "the origin should get the header: {origin_requests:?}"
    );
    let target_requests = target_seen.lock().clone();
    assert_eq!(target_requests.len(), 1);
    assert_eq!(target_requests[0].path, "/final");
    assert!(
        !target_requests[0].raw.contains("authorization"),
        "the redirect target must not get the header: {target_requests:?}"
    );
}

#[nativelink_test]
async fn a_redirect_loop_fails_with_a_clear_error() {
    // Redirects to itself forever.
    let (origin, seen) = serve(|_| Reply::redirect("/again")).await;
    let fetcher = UrlFetcher::new(memory_store().await, UrlFetcherOptions::default()).unwrap();

    let err = fetcher
        .fetch_blob(&job(&format!("{origin}/start"), FetchHeaders::default()))
        .await
        .unwrap_err();

    assert_eq!(err.code, Code::NotFound);
    assert!(
        err.message_string().contains("too many redirects"),
        "{err:?}"
    );
    // The first request plus ten redirects followed.
    assert_eq!(seen.lock().len(), 11);
}

#[nativelink_test]
async fn freshness_comes_from_the_final_response_after_a_redirect() {
    let fetcher = UrlFetcher::new(memory_store().await, UrlFetcherOptions::default()).unwrap();

    // The redirect says no-store, the content says ten minutes.
    let (target, _) = serve(|_| Reply::ok(BODY).with_header("Cache-Control", "max-age=600")).await;
    let final_url = format!("{target}/final");
    let (origin, _) =
        serve(move |_| Reply::redirect(&final_url).with_header("Cache-Control", "no-store")).await;
    let outcome = fetcher
        .fetch_blob(&job(&format!("{origin}/start"), FetchHeaders::default()))
        .await
        .unwrap();
    assert_eq!(outcome.freshness, Some(Duration::from_mins(10)));

    // And the other way round.
    let (target, _) = serve(|_| Reply::ok(BODY).with_header("Cache-Control", "no-store")).await;
    let final_url = format!("{target}/final");
    let (origin, _) =
        serve(move |_| Reply::redirect(&final_url).with_header("Cache-Control", "max-age=600"))
            .await;
    let outcome = fetcher
        .fetch_blob(&job(&format!("{origin}/start"), FetchHeaders::default()))
        .await
        .unwrap();
    assert_eq!(outcome.freshness, Some(Duration::ZERO));
}

#[nativelink_test]
async fn freshness_is_none_when_the_response_says_nothing() {
    let (origin, _) = serve(|_| Reply::ok(BODY)).await;
    let fetcher = UrlFetcher::new(memory_store().await, UrlFetcherOptions::default()).unwrap();
    let outcome = fetcher
        .fetch_blob(&job(&format!("{origin}/x"), FetchHeaders::default()))
        .await
        .unwrap();
    assert_eq!(outcome.freshness, None);
}

#[nativelink_test]
async fn a_directory_fetch_reports_freshness_too() {
    let archive = support::tar(&[support::TarEntry::File("a.txt", b"alpha", 0o644)]);
    let (origin, _) = serve(move |_| {
        Reply::ok(&archive).with_header("Cache-Control", "public, s-maxage=120, max-age=5")
    })
    .await;
    let fetcher = UrlFetcher::new(memory_store().await, UrlFetcherOptions::default()).unwrap();

    let outcome = fetcher
        .fetch_directory(&FetchDirectoryJob {
            uris: vec![format!("{origin}/archive.tar")],
            qualifiers: vec![],
            checksums: vec![],
            hasher_func: DigestHasherFunc::Sha256,
            verified_by_action: false,
            timeout: None,
            headers: FetchHeaders::default(),
            revalidate: vec![],
            shared_deadline: None,
        })
        .await
        .unwrap();

    assert_eq!(outcome.freshness, Some(Duration::from_mins(2)));
}

const ETAG: &str = "\"v1\"";
const LAST_MODIFIED: &str = "Sun, 06 Nov 1994 08:49:37 GMT";

/// An origin that serves `body` with an `ETag` and a `Last-Modified`, and
/// answers `304` to a request carrying either as a validator.
async fn serve_validating(body: Vec<u8>) -> (String, Arc<Mutex<Vec<Seen>>>) {
    serve(move |request| {
        if request
            .raw
            .contains(&format!("if-none-match: {}", ETAG.to_lowercase()))
            || request.raw.contains("if-modified-since: sun, 06 nov 1994")
        {
            Reply::not_modified().with_header("Cache-Control", "max-age=600")
        } else {
            Reply::ok(&body)
                .with_header("ETag", ETAG)
                .with_header("Last-Modified", LAST_MODIFIED)
        }
    })
    .await
}

fn revalidation(uri: &str, digest: DigestInfo, validators: Validators) -> Revalidation {
    Revalidation {
        uri: uri.to_string(),
        digest,
        validators,
    }
}

fn both_validators() -> Validators {
    Validators {
        etag: Some(ETAG.to_string()),
        last_modified: Some(LAST_MODIFIED.to_string()),
    }
}

#[nativelink_test]
async fn a_fetch_reports_the_validators_of_the_final_response() {
    let (origin, _) = serve_validating(BODY.to_vec()).await;
    let fetcher = UrlFetcher::new(memory_store().await, UrlFetcherOptions::default()).unwrap();

    let outcome = fetcher
        .fetch_blob(&job(&format!("{origin}/x"), FetchHeaders::default()))
        .await
        .unwrap();

    assert_eq!(outcome.validators, both_validators());
    assert!(!outcome.revalidated);
}

#[nativelink_test]
async fn a_current_blob_is_revalidated_without_downloading_it() {
    let (origin, seen) = serve_validating(BODY.to_vec()).await;
    let cas = memory_store().await;
    let fetcher = UrlFetcher::new(cas, UrlFetcherOptions::default()).unwrap();
    let uri = format!("{origin}/x");
    let first = fetcher
        .fetch_blob(&job(&uri, FetchHeaders::default()))
        .await
        .unwrap();

    for validators in [
        both_validators(),
        Validators {
            etag: Some(ETAG.to_string()),
            last_modified: None,
        },
        Validators {
            etag: None,
            last_modified: Some(LAST_MODIFIED.to_string()),
        },
    ] {
        let mut revalidating = job(&uri, FetchHeaders::default());
        revalidating.revalidate = vec![revalidation(&uri, first.digest, validators.clone())];
        let outcome = fetcher.fetch_blob(&revalidating).await.unwrap();

        assert!(outcome.revalidated);
        assert_eq!(outcome.digest, first.digest);
        assert_eq!(outcome.uri, uri);
        // The 304's caching headers set the new lifetime, and validators it
        // did not repeat are kept.
        assert_eq!(outcome.freshness, Some(Duration::from_mins(10)));
        assert_eq!(outcome.validators, validators);

        let request = seen.lock().last().unwrap().clone();
        assert_eq!(
            request.raw.contains("if-none-match"),
            validators.etag.is_some()
        );
        assert_eq!(
            request.raw.contains("if-modified-since"),
            validators.last_modified.is_some()
        );
    }
}

#[nativelink_test]
async fn a_changed_blob_is_downloaded_normally_when_revalidating() {
    let new_body = b"new content";
    let (origin, seen) = serve(|request| {
        if request.raw.contains("if-none-match: \"v1\"") {
            Reply::ok(new_body).with_header("ETag", "\"v2\"")
        } else {
            Reply::ok(BODY)
        }
    })
    .await;
    let cas = memory_store().await;
    let fetcher = UrlFetcher::new(cas.clone(), UrlFetcherOptions::default()).unwrap();
    let uri = format!("{origin}/x");

    let mut revalidating = job(&uri, FetchHeaders::default());
    revalidating.revalidate = vec![revalidation(&uri, digest_of(BODY), both_validators())];
    let outcome = fetcher.fetch_blob(&revalidating).await.unwrap();

    assert!(!outcome.revalidated);
    assert_eq!(outcome.digest, digest_of(new_body));
    assert_eq!(outcome.validators.etag.as_deref(), Some("\"v2\""));
    assert!(cas.has(outcome.digest).await.unwrap().is_some());
    assert_eq!(seen.lock().len(), 1);
}

#[nativelink_test]
async fn a_checksum_is_still_checked_on_a_changed_blob_that_was_revalidated() {
    // Revalidation is for unpinned requests, but the verifiers still run on
    // any 200 so a job that carries both cannot skip them.
    let (origin, _) = serve(|_| Reply::ok(b"not what the checksum says")).await;
    let fetcher = UrlFetcher::new(memory_store().await, UrlFetcherOptions::default()).unwrap();
    let uri = format!("{origin}/x");
    let mut revalidating = job(&uri, FetchHeaders::default());
    revalidating.checksums = vec![
        nativelink_util::sri::ByteChecksum::from_qualifier(
            "checksum.sha256",
            &digest_of(BODY).packed_hash().to_string(),
        )
        .unwrap(),
    ];
    revalidating.revalidate = vec![revalidation(&uri, digest_of(BODY), both_validators())];

    let err = fetcher.fetch_blob(&revalidating).await.unwrap_err();

    assert_eq!(err.code, Code::Aborted);
}

#[nativelink_test]
async fn a_revalidated_blob_missing_from_the_cas_is_downloaded_again() {
    let (origin, seen) = serve_validating(BODY.to_vec()).await;
    let uri = format!("{origin}/x");
    // A CAS that has never held the content the entry names.
    let cas = memory_store().await;
    let fetcher = UrlFetcher::new(cas.clone(), UrlFetcherOptions::default()).unwrap();

    let mut revalidating = job(&uri, FetchHeaders::default());
    revalidating.revalidate = vec![revalidation(&uri, digest_of(BODY), both_validators())];
    let outcome = fetcher.fetch_blob(&revalidating).await.unwrap();

    assert!(!outcome.revalidated);
    assert_eq!(outcome.digest, digest_of(BODY));
    assert!(cas.has(outcome.digest).await.unwrap().is_some());
    // The conditional request, then an unconditional one.
    let requests = seen.lock().clone();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].raw.contains("if-none-match"));
    assert!(!requests[1].raw.contains("if-none-match"));
    assert!(!requests[1].raw.contains("if-modified-since"));
}

#[nativelink_test]
async fn a_revalidation_for_another_uri_is_not_sent() {
    let (origin, seen) = serve_validating(BODY.to_vec()).await;
    let fetcher = UrlFetcher::new(memory_store().await, UrlFetcherOptions::default()).unwrap();
    let uri = format!("{origin}/x");

    let mut plain = job(&uri, FetchHeaders::default());
    plain.revalidate = vec![revalidation(
        &format!("{origin}/other"),
        digest_of(BODY),
        both_validators(),
    )];
    let outcome = fetcher.fetch_blob(&plain).await.unwrap();

    assert!(!outcome.revalidated);
    assert!(!seen.lock()[0].raw.contains("if-none-match"));
}

#[nativelink_test]
async fn a_304_to_an_unconditional_request_is_an_error() {
    let (origin, _) = serve(|_| Reply::not_modified()).await;
    let fetcher = UrlFetcher::new(memory_store().await, UrlFetcherOptions::default()).unwrap();

    let err = fetcher
        .fetch_blob(&job(&format!("{origin}/x"), FetchHeaders::default()))
        .await
        .unwrap_err();

    assert_eq!(err.code, Code::NotFound);
    assert!(err.message_string().contains("304"), "{err:?}");
}

fn directory_job(uri: &str) -> FetchDirectoryJob {
    FetchDirectoryJob {
        uris: vec![uri.to_string()],
        qualifiers: vec![],
        checksums: vec![],
        hasher_func: DigestHasherFunc::Sha256,
        verified_by_action: false,
        timeout: None,
        headers: FetchHeaders::default(),
        revalidate: vec![],
        shared_deadline: None,
    }
}

#[nativelink_test]
async fn a_current_directory_is_revalidated_without_expanding_it() {
    let archive = support::tar(&[
        support::TarEntry::File("a.txt", b"alpha", 0o644),
        support::TarEntry::File("dir/b.txt", b"beta", 0o644),
    ]);
    let (origin, seen) = serve_validating(archive).await;
    let uri = format!("{origin}/archive.tar");
    let cas = memory_store().await;
    let fetcher = UrlFetcher::new(cas.clone(), UrlFetcherOptions::default()).unwrap();
    let first = fetcher.fetch_directory(&directory_job(&uri)).await.unwrap();
    assert_eq!(first.validators, both_validators());

    let mut revalidating = directory_job(&uri);
    revalidating.revalidate = vec![revalidation(&uri, first.digest, both_validators())];
    let outcome = fetcher.fetch_directory(&revalidating).await.unwrap();

    assert!(outcome.revalidated);
    assert_eq!(outcome.digest, first.digest);
    assert!(seen.lock().last().unwrap().raw.contains("if-none-match"));

    // A file the tree names has left the CAS: expand the archive again.
    let memory_store = cas
        .downcast_ref::<MemoryStore>(None)
        .expect("a memory store");
    assert!(memory_store.remove_entry(digest_of(b"alpha").into()).await);
    let outcome = fetcher.fetch_directory(&revalidating).await.unwrap();
    assert!(!outcome.revalidated);
    assert_eq!(outcome.digest, first.digest);
    assert!(cas.has(digest_of(b"alpha")).await.unwrap().is_some());
}
