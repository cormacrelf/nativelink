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
use std::sync::Arc;

use nativelink_error::{Code, Error, make_err};
use nativelink_fetch::background_fetcher::{BackgroundFetcher, BackgroundFetcherOpts};
use nativelink_fetch::fetcher::{
    FetchBlobTask, FetchDirectoryJob, FetchHeaders, FetchOutcome, Fetcher,
};
use nativelink_macro::nativelink_test;
use nativelink_proto::build::bazel::remote::asset::v1::Qualifier;
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::DigestHasherFunc;
use parking_lot::Mutex;
use tokio::sync::{Semaphore, mpsc};
use tonic::async_trait;

/// A `Fetcher` test double. Records calls, can block until released, and tracks
/// peak concurrency so the decorator's behavior can be observed in isolation
/// from any real HTTP work.
#[derive(Debug)]
struct MockFetcher {
    started: Arc<AtomicUsize>,
    completed: Arc<AtomicUsize>,
    concurrent: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    seen_timeouts: Arc<Mutex<Vec<Option<Duration>>>>,
    start_tx: mpsc::UnboundedSender<()>,
    done_tx: mpsc::UnboundedSender<()>,
    /// A semaphore with 0 initial permits; when `block` is set each fetch waits
    /// for a permit (released by the test via `add_permits`).
    gate: Arc<Semaphore>,
    block: bool,
}

/// Channels/handles the test uses to observe and steer a [`MockFetcher`].
struct MockHandles {
    started: Arc<AtomicUsize>,
    completed: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    seen_timeouts: Arc<Mutex<Vec<Option<Duration>>>>,
    start_rx: mpsc::UnboundedReceiver<()>,
    done_rx: mpsc::UnboundedReceiver<()>,
    gate: Arc<Semaphore>,
}

fn mock_fetcher(block: bool) -> (Arc<MockFetcher>, MockHandles) {
    let started = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));
    let concurrent = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let seen_timeouts = Arc::new(Mutex::new(Vec::new()));
    let gate = Arc::new(Semaphore::new(0));
    let (start_tx, start_rx) = mpsc::unbounded_channel();
    let (done_tx, done_rx) = mpsc::unbounded_channel();
    let fetcher = Arc::new(MockFetcher {
        started: started.clone(),
        completed: completed.clone(),
        concurrent,
        peak: peak.clone(),
        seen_timeouts: seen_timeouts.clone(),
        start_tx,
        done_tx,
        gate: gate.clone(),
        block,
    });
    let handles = MockHandles {
        started,
        completed,
        peak,
        seen_timeouts,
        start_rx,
        done_rx,
        gate,
    };
    (fetcher, handles)
}

#[async_trait]
impl Fetcher for MockFetcher {
    async fn fetch_blob(&self, job: &FetchBlobTask) -> Result<FetchOutcome, Error> {
        self.started.fetch_add(1, Ordering::SeqCst);
        let now = self.concurrent.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        self.seen_timeouts.lock().push(job.timeout);
        let _ = self.start_tx.send(());
        if self.block {
            // Blocked as a download would be: under way, until the gate opens or
            // the shared deadline passes.
            let deadline = job
                .shared_deadline
                .clone()
                .expect("set by BackgroundFetcher");
            let _retrieving = deadline.retrieving();
            tokio::select! {
                permit = self.gate.acquire() => permit.expect("gate not closed").forget(),
                () = deadline.expired() => {
                    self.concurrent.fetch_sub(1, Ordering::SeqCst);
                    return Err(make_err!(Code::DeadlineExceeded, "shared deadline passed"));
                }
            }
        }
        self.concurrent.fetch_sub(1, Ordering::SeqCst);
        self.completed.fetch_add(1, Ordering::SeqCst);
        let _ = self.done_tx.send(());
        Ok(FetchOutcome::new(
            job.uris.first().cloned().unwrap_or_default(),
            DigestInfo::try_new(&"0".repeat(64), 1).unwrap(),
        ))
    }

    async fn fetch_directory(&self, _job: &FetchDirectoryJob) -> Result<FetchOutcome, Error> {
        Err(make_err!(
            Code::Unimplemented,
            "fetch_directory is not exercised by these tests"
        ))
    }
}

fn blob_job(uri: &str, timeout: Option<Duration>) -> FetchBlobTask {
    FetchBlobTask {
        uris: vec![uri.to_owned()],
        qualifiers: vec![],
        checksums: vec![],
        hasher_func: DigestHasherFunc::Sha256,
        timeout,
        headers: FetchHeaders::default(),
        revalidate: vec![],
        shared_deadline: None,
    }
}

#[nativelink_test]
async fn dedups_concurrent_identical_jobs() {
    let (mock, mut handles) = mock_fetcher(true);
    let bg = BackgroundFetcher::new(mock, BackgroundFetcherOpts::default());

    // Three concurrent requests for the same job.
    let job = blob_job("http://example/blob", None);
    let awaiters: Vec<_> = (0..3)
        .map(|_| {
            let bg = bg.clone();
            let job = job.clone();
            tokio::spawn(async move { bg.fetch_blob(&job).await })
        })
        .collect();

    // Exactly one inner fetch should start.
    handles.start_rx.recv().await.expect("a fetch should start");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(handles.started.load(Ordering::SeqCst), 1);

    handles.gate.add_permits(1);
    for awaiter in awaiters {
        let outcome = awaiter.await.unwrap().unwrap();
        assert_eq!(outcome.uri, "http://example/blob");
    }
    assert_eq!(handles.started.load(Ordering::SeqCst), 1);
    assert_eq!(handles.completed.load(Ordering::SeqCst), 1);
}

#[nativelink_test]
async fn dedups_despite_different_timeout_and_qualifier_order() {
    let (mock, mut handles) = mock_fetcher(true);
    let bg = BackgroundFetcher::new(mock, BackgroundFetcherOpts::default());

    let qualifier = |name: &str, value: &str| (name.to_owned(), value.to_owned());
    let mut first = blob_job("http://example/blob", Some(Duration::from_secs(5)));
    first.qualifiers = vec![qualifier("a", "1"), qualifier("b", "2")];
    let mut second = blob_job("http://example/blob", Some(Duration::from_mins(1)));
    second.qualifiers = vec![qualifier("b", "2"), qualifier("a", "1")];

    let first_call = {
        let bg = bg.clone();
        tokio::spawn(async move { bg.fetch_blob(&first).await })
    };
    handles.start_rx.recv().await.expect("a fetch should start");
    let second_call = {
        let bg = bg.clone();
        tokio::spawn(async move { bg.fetch_blob(&second).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(handles.started.load(Ordering::SeqCst), 1);

    handles.gate.add_permits(1);
    first_call.await.unwrap().unwrap();
    second_call.await.unwrap().unwrap();
    assert_eq!(handles.started.load(Ordering::SeqCst), 1);
    // The duplicate joined the first requester's fetch, which was started with
    // that requester's timeout.
    assert_eq!(
        *handles.seen_timeouts.lock(),
        vec![Some(Duration::from_secs(5))]
    );
}

fn headers(qualifiers: &[(&str, &str)]) -> FetchHeaders {
    let qualifiers: Vec<_> = qualifiers
        .iter()
        .map(|&(name, value)| Qualifier {
            name: name.to_owned(),
            value: value.to_owned(),
        })
        .collect();
    FetchHeaders::from_qualifiers(&qualifiers, 2).unwrap()
}

#[nativelink_test]
async fn jobs_with_different_headers_do_not_share_a_fetch() {
    let (mock, mut handles) = mock_fetcher(true);
    let bg = BackgroundFetcher::new(mock, BackgroundFetcherOpts::default());

    // Differing only in a global header, or only in a URI-specific one.
    let mut jobs = Vec::new();
    for token in ["Bearer a", "Bearer b"] {
        let mut job = blob_job("http://example/blob", None);
        job.headers = headers(&[("http_header:Authorization", token)]);
        jobs.push(job);
    }
    for token in ["Bearer a", "Bearer b"] {
        let mut job = blob_job("http://example/blob", None);
        job.headers = headers(&[("http_header_url:0:Authorization", token)]);
        jobs.push(job);
    }
    let calls: Vec<_> = jobs
        .into_iter()
        .map(|job| {
            let bg = bg.clone();
            tokio::spawn(async move { bg.fetch_blob(&job).await })
        })
        .collect();
    for _ in 0..4 {
        handles.start_rx.recv().await.expect("a fetch should start");
    }
    assert_eq!(handles.started.load(Ordering::SeqCst), 4);

    handles.gate.add_permits(4);
    for call in calls {
        call.await.unwrap().unwrap();
    }
    assert_eq!(handles.completed.load(Ordering::SeqCst), 4);
}

#[nativelink_test]
async fn jobs_with_the_same_headers_in_another_order_share_a_fetch() {
    let (mock, mut handles) = mock_fetcher(true);
    let bg = BackgroundFetcher::new(mock, BackgroundFetcherOpts::default());

    let mut first = blob_job("http://example/blob", None);
    first.headers = headers(&[
        ("http_header:Authorization", "Bearer a"),
        ("http_header:X-Other", "other"),
        ("http_header_url:0:X-Mirror", "0"),
        ("http_header_url:1:X-Mirror", "1"),
    ]);
    let mut second = blob_job("http://example/blob", None);
    second.headers = headers(&[
        ("http_header_url:1:x-mirror", "1"),
        ("http_header:x-other", "other"),
        ("http_header_url:0:X-MIRROR", "0"),
        ("http_header:AUTHORIZATION", "Bearer a"),
    ]);
    assert_eq!(first, second);

    let first_call = {
        let bg = bg.clone();
        tokio::spawn(async move { bg.fetch_blob(&first).await })
    };
    handles.start_rx.recv().await.expect("a fetch should start");
    let second_call = {
        let bg = bg.clone();
        tokio::spawn(async move { bg.fetch_blob(&second).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(handles.started.load(Ordering::SeqCst), 1);

    handles.gate.add_permits(1);
    first_call.await.unwrap().unwrap();
    second_call.await.unwrap().unwrap();
    assert_eq!(handles.started.load(Ordering::SeqCst), 1);
}

#[nativelink_test]
async fn limits_concurrency() {
    let (mock, mut handles) = mock_fetcher(true);
    let bg = BackgroundFetcher::new(
        mock,
        BackgroundFetcherOpts {
            max_concurrent_fetches: Some(2),
            ..Default::default()
        },
    );

    // Four distinct jobs; only two may run at once.
    let awaiters: Vec<_> = (0..4)
        .map(|i| {
            let bg = bg.clone();
            let job = blob_job(&format!("http://example/blob{i}"), None);
            tokio::spawn(async move { bg.fetch_blob(&job).await })
        })
        .collect();

    handles.start_rx.recv().await.expect("first fetch starts");
    handles.start_rx.recv().await.expect("second fetch starts");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        handles.started.load(Ordering::SeqCst),
        2,
        "only two fetches may be in flight at once"
    );

    handles.gate.add_permits(4);
    for awaiter in awaiters {
        awaiter.await.unwrap().unwrap();
    }
    assert_eq!(handles.completed.load(Ordering::SeqCst), 4);
    assert_eq!(
        handles.peak.load(Ordering::SeqCst),
        2,
        "peak concurrency should be capped at two"
    );
}

#[nativelink_test]
async fn queued_caller_that_disconnects_leaves_no_fetch_behind() {
    let (mock, mut handles) = mock_fetcher(true);
    let bg = BackgroundFetcher::new(
        mock,
        BackgroundFetcherOpts {
            max_concurrent_fetches: Some(1),
            ..Default::default()
        },
    );

    // The first fetch takes the only slot.
    let running = {
        let bg = bg.clone();
        tokio::spawn(async move { bg.fetch_blob(&blob_job("http://example/a", None)).await })
    };
    handles.start_rx.recv().await.expect("first fetch starts");

    // A second, distinct fetch queues for the slot; its caller then goes away.
    let queued = {
        let bg = bg.clone();
        tokio::spawn(async move { bg.fetch_blob(&blob_job("http://example/b", None)).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    queued.abort();
    assert!(queued.await.unwrap_err().is_cancelled());

    // Freeing the slot must not start the abandoned fetch.
    handles.gate.add_permits(2);
    running.await.unwrap().unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(handles.started.load(Ordering::SeqCst), 1);
}

#[nativelink_test]
async fn identical_callers_queued_for_a_slot_share_one_fetch() {
    let (mock, mut handles) = mock_fetcher(true);
    let bg = BackgroundFetcher::new(
        mock,
        BackgroundFetcherOpts {
            max_concurrent_fetches: Some(1),
            ..Default::default()
        },
    );

    let running = {
        let bg = bg.clone();
        tokio::spawn(async move { bg.fetch_blob(&blob_job("http://example/a", None)).await })
    };
    handles.start_rx.recv().await.expect("first fetch starts");

    // Three identical requests queue for the slot behind it. The first of them
    // goes away; the others must still get, and share, one fetch.
    let mut queued: Vec<_> = (0..3)
        .map(|_| {
            let bg = bg.clone();
            tokio::spawn(async move { bg.fetch_blob(&blob_job("http://example/b", None)).await })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(50)).await;
    queued.remove(0).abort();
    tokio::time::sleep(Duration::from_millis(50)).await;

    handles.gate.add_permits(3);
    running.await.unwrap().unwrap();
    for call in queued {
        call.await.unwrap().unwrap();
    }
    assert_eq!(handles.started.load(Ordering::SeqCst), 2);
}

#[nativelink_test]
async fn short_timeout_does_not_cut_short_a_longer_joined_one() {
    let (mock, mut handles) = mock_fetcher(true);
    let bg = BackgroundFetcher::new(mock, BackgroundFetcherOpts::default());

    let short = {
        let bg = bg.clone();
        let job = blob_job("http://example/blob", Some(Duration::from_millis(100)));
        tokio::spawn(async move { bg.fetch_blob(&job).await })
    };
    handles.start_rx.recv().await.expect("a fetch should start");
    let long = {
        let bg = bg.clone();
        let job = blob_job("http://example/blob", Some(Duration::from_mins(1)));
        tokio::spawn(async move { bg.fetch_blob(&job).await })
    };

    // The short request gets DEADLINE_EXCEEDED at its own deadline...
    let err = short
        .await
        .unwrap()
        .expect_err("the short request times out");
    assert_eq!(err.code, Code::DeadlineExceeded, "{err:?}");
    // ...while the shared fetch carries on for the long one.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(handles.completed.load(Ordering::SeqCst), 0);
    handles.gate.add_permits(1);
    long.await
        .unwrap()
        .expect("the long request gets the result");
    assert_eq!(handles.started.load(Ordering::SeqCst), 1);
}

/// Takes a while, but spends none of it retrieving from origin, as an action
/// verifying a fetched directory would.
#[derive(Debug)]
struct SlowVerifier;

#[async_trait]
impl Fetcher for SlowVerifier {
    async fn fetch_blob(&self, job: &FetchBlobTask) -> Result<FetchOutcome, Error> {
        tokio::time::sleep(Duration::from_millis(300)).await;
        Ok(FetchOutcome::new(
            job.uris[0].clone(),
            DigestInfo::try_new(&"0".repeat(64), 1).unwrap(),
        ))
    }

    async fn fetch_directory(&self, _job: &FetchDirectoryJob) -> Result<FetchOutcome, Error> {
        Err(make_err!(Code::Unimplemented, "not exercised"))
    }
}

#[nativelink_test]
async fn timeout_bounds_only_the_retrieval() {
    let bg = BackgroundFetcher::new(Arc::new(SlowVerifier), BackgroundFetcherOpts::default());
    bg.fetch_blob(&blob_job(
        "http://example/blob",
        Some(Duration::from_millis(50)),
    ))
    .await
    .expect("time spent outside a retrieval is not held against the timeout");
}

#[nativelink_test]
async fn fetch_survives_caller_dropping() {
    let (mock, mut handles) = mock_fetcher(true);
    let bg = BackgroundFetcher::new(mock, BackgroundFetcherOpts::default());

    let job = blob_job("http://example/blob", None);
    let awaiter = {
        let bg = bg.clone();
        let job = job.clone();
        tokio::spawn(async move { bg.fetch_blob(&job).await })
    };

    // Wait until the inner fetch is running, then abandon the caller.
    handles.start_rx.recv().await.expect("fetch should start");
    awaiter.abort();

    // The detached fetch must still run to completion despite the caller going
    // away -- that's the whole point of backgrounding.
    handles.gate.add_permits(1);
    handles.done_rx.recv().await.expect("fetch should complete");
    assert_eq!(handles.completed.load(Ordering::SeqCst), 1);
}

#[nativelink_test]
async fn clamps_total_timeout() {
    let (mock, handles) = mock_fetcher(false);
    let bg = BackgroundFetcher::new(
        mock,
        BackgroundFetcherOpts {
            min_timeout: Some(Duration::from_secs(1)),
            max_timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        },
    );

    // Above the max is clamped down; below the min is clamped up; unset stays
    // unset. Distinct URIs keep these from deduping into one another.
    bg.fetch_blob(&blob_job(
        "http://example/a",
        Some(Duration::from_secs(100)),
    ))
    .await
    .unwrap();
    bg.fetch_blob(&blob_job(
        "http://example/b",
        Some(Duration::from_millis(500)),
    ))
    .await
    .unwrap();
    bg.fetch_blob(&blob_job("http://example/c", None))
        .await
        .unwrap();

    let seen = handles.seen_timeouts.lock().clone();
    assert_eq!(
        seen,
        vec![
            Some(Duration::from_secs(5)),
            Some(Duration::from_secs(1)),
            None,
        ]
    );
}

#[nativelink_test]
async fn revalidation_input_is_not_part_of_the_dedup_identity() {
    use core::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

    use nativelink_fetch::fetcher::{Revalidation, Validators};

    let plain = blob_job("http://example/blob", None);
    let mut revalidating = plain.clone();
    revalidating.revalidate = vec![Revalidation {
        uri: "http://example/blob".to_string(),
        digest: DigestInfo::try_new(&"0".repeat(64), 1).unwrap(),
        validators: Validators {
            etag: Some("\"v1\"".to_string()),
            last_modified: None,
        },
    }];

    assert_eq!(plain, revalidating);
    let hash = |job: &FetchBlobTask| {
        let mut hasher = DefaultHasher::new();
        job.hash(&mut hasher);
        hasher.finish()
    };
    assert_eq!(hash(&plain), hash(&revalidating));
}
