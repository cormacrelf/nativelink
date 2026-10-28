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
            self.gate.acquire().await.expect("gate not closed").forget();
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
    second.headers = FetchHeaders::from_qualifiers(
        &[Qualifier {
            name: "http_header:Authorization".to_owned(),
            value: "Bearer other".to_owned(),
        }],
        1,
    )
    .unwrap();

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
    // The duplicate joined the first requester's fetch and its timeout.
    assert_eq!(
        *handles.seen_timeouts.lock(),
        vec![Some(Duration::from_secs(5))]
    );
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
