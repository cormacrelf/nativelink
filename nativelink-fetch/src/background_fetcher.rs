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

//! [`BackgroundFetcher`]: a [`Fetcher`] decorator that adds in-flight
//! deduplication, optional concurrency limiting, timeout clamping, and -- most
//! importantly -- *background continuation*.
//!
//! The Remote Asset API says that if a request's `timeout` exceeds the RPC
//! deadline the server *should* keep the fetch going after the RPC completes,
//! so a later Fetch call can reuse it. `BackgroundFetcher` achieves this by
//! running each inner fetch in a detached task that owns a
//! [`tokio::sync::watch`] sender; callers merely *subscribe* to the result. If
//! a client gives up on its RPC the subscriber is dropped, but the detached
//! task -- and the watch sender it owns -- keeps running to completion.
//!
//! A pinned request (one that carries a checksum) runs one such task per URI,
//! in turn, and a concurrent or subsequent pinned request that reaches the
//! same URI with the same qualifiers and headers finds the in-flight entry and
//! subscribes to that task instead of starting a new download. Requests that
//! list different mirrors of one asset so share the mirrors they have in
//! common. An unpinned request always runs its own fetch, whole.
//!
//! A request's `timeout` is, in the API's words, "the timeout for the
//! underlying fetch, if content needs to be retrieved from origin". It bounds
//! the server's retrieval, not the RPC (the client's RPC deadline does that)
//! and not time queued for a concurrency slot, which retrieves nothing: a
//! queued caller is bounded by its RPC deadline alone. Identical pinned
//! requests share one fetch, which runs until the latest of their deadlines,
//! while each request still gets `DEADLINE_EXCEEDED` at its own (see
//! [`SharedDeadline`]).
//!
//! This mirrors the kernel of the scheduler's `MemoryAwaitedActionDb`
//! (`HashMap<key, watch::Sender<..>>` + `subscribe()`), but with the opposite
//! drop semantics: the action DB cancels an operation once its last client
//! disconnects, whereas a fetch deliberately survives.

use core::future::Future;
use core::hash::Hash;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;

use futures::future::BoxFuture;
use nativelink_config::fetchers::DEFAULT_MAX_CONCURRENT_FETCHES;
use nativelink_error::{Error, make_err};
use nativelink_util::background_spawn;
use parking_lot::Mutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::Instant;
use tonic::{Code, async_trait};
use tracing::debug;

use crate::fetcher::{
    FetchBlobTask, FetchDirectoryJob, FetchOutcome, Fetcher, SharedDeadline, fails_only_these_uris,
};

/// Where one fetch is. Once `Done`, every current and future subscriber
/// observes the same `Arc`-wrapped result.
#[derive(Clone, Debug)]
enum FetchState {
    /// Its first caller is waiting for a concurrency slot. Identical requests
    /// join it here rather than queueing a duplicate fetch.
    Queued,
    /// The detached task is running it, until this deadline.
    Running(SharedDeadline),
    Done(Arc<Result<FetchOutcome, Error>>),
}

/// The shared state of one fetch. The matching `watch::Sender` is held by the
/// caller queued for a slot, then by the detached task, which runs to
/// completion regardless of how many subscribers remain.
type SharedResult = watch::Receiver<FetchState>;

/// Tuning for [`BackgroundFetcher`].
#[derive(Clone, Copy, Debug)]
pub struct BackgroundFetcherOpts {
    /// Maximum number of inner fetches running at once. `None` is unbounded.
    /// Defaults to [`DEFAULT_MAX_CONCURRENT_FETCHES`].
    pub max_concurrent_fetches: Option<usize>,
    /// Lower bound applied to a job's `timeout`, the budget for the whole fetch
    /// (only when the job sets one). `None` leaves it unchanged.
    pub min_timeout: Option<Duration>,
    /// Upper bound applied to a job's `timeout`, the budget for the whole fetch
    /// (only when the job sets one). `None` leaves it unchanged.
    pub max_timeout: Option<Duration>,
}

impl Default for BackgroundFetcherOpts {
    fn default() -> Self {
        Self {
            max_concurrent_fetches: Some(DEFAULT_MAX_CONCURRENT_FETCHES),
            min_timeout: None,
            max_timeout: None,
        }
    }
}

/// A [`Fetcher`] decorator providing dedup + background continuation.
#[derive(Debug)]
pub struct BackgroundFetcher {
    inner: Arc<dyn Fetcher>,
    blob_in_flight: Arc<Mutex<HashMap<FetchBlobTask, SharedResult>>>,
    dir_in_flight: Arc<Mutex<HashMap<FetchDirectoryJob, SharedResult>>>,
    permits: Option<Arc<Semaphore>>,
    min_timeout: Option<Duration>,
    max_timeout: Option<Duration>,
}

impl BackgroundFetcher {
    /// Wraps `inner` with the given options.
    pub fn new(inner: Arc<dyn Fetcher>, opts: BackgroundFetcherOpts) -> Arc<Self> {
        Arc::new(Self {
            inner,
            blob_in_flight: Arc::new(Mutex::new(HashMap::new())),
            dir_in_flight: Arc::new(Mutex::new(HashMap::new())),
            permits: opts
                .max_concurrent_fetches
                .map(|n| Arc::new(Semaphore::new(n))),
            min_timeout: opts.min_timeout,
            max_timeout: opts.max_timeout,
        })
    }

    /// Clamps a job's total timeout into `[min, max]`. Only applies when the
    /// job actually sets a timeout -- an unset deadline is left unset.
    fn clamp(&self, timeout: Option<Duration>) -> Option<Duration> {
        let mut timeout = timeout?;
        if let Some(min) = self.min_timeout {
            timeout = timeout.max(min);
        }
        if let Some(max) = self.max_timeout {
            timeout = timeout.min(max);
        }
        Some(timeout)
    }
}

/// Removes a queued fetch's map entry if its caller goes away before the fetch
/// is spawned, so that a later request does not join a fetch nobody will run.
struct QueuedEntry<'a, K: Eq + Hash> {
    map: &'a Mutex<HashMap<K, SharedResult>>,
    key: Option<K>,
}

impl<K: Eq + Hash> Drop for QueuedEntry<'_, K> {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.map.lock().remove(&key);
        }
    }
}

/// Subscribes to the fetch for `key`, or starts one by spawning a detached task
/// running `run`, under a [`SharedDeadline`] that starts at `timeout`. Returns a
/// receiver the caller can await; dropping it does not cancel a spawned task.
/// When `share` is false the fetch neither joins nor can be joined.
///
/// The concurrency permit (when configured) is taken here, by the caller,
/// before anything is spawned. A caller queued for a slot holds nothing but its
/// own future, so one that disconnects stops waiting and leaves no work behind;
/// only a fetch that holds a slot is detached, which bounds the number of
/// detached tasks by `max_concurrent_fetches`. Identical requests that arrive
/// meanwhile join the queued fetch; if its caller goes away they see it
/// abandoned (see [`await_shared`]) and call this again.
async fn schedule_or_join<K, F, Fut>(
    map: &Arc<Mutex<HashMap<K, SharedResult>>>,
    permits: Option<&Arc<Semaphore>>,
    key: K,
    share: bool,
    timeout: Option<Duration>,
    run: F,
) -> SharedResult
where
    K: Clone + Eq + Hash + Send + 'static,
    F: FnOnce(SharedDeadline) -> Fut + Send + 'static,
    Fut: Future<Output = Result<FetchOutcome, Error>> + Send + 'static,
{
    let key = share.then_some(key);
    let (tx, rx) = watch::channel(FetchState::Queued);
    if let Some(key) = &key {
        let mut guard = map.lock();
        if let Some(existing) = guard.get(key) {
            return existing.clone();
        }
        guard.insert(key.clone(), rx.clone());
    }
    let mut queued = QueuedEntry { map, key };
    let permit: Option<OwnedSemaphorePermit> = match permits {
        // `acquire_owned` only fails if the semaphore is closed, which we
        // never do.
        Some(semaphore) => Some(
            semaphore
                .clone()
                .acquire_owned()
                .await
                .expect("fetch semaphore is never closed"),
        ),
        None => None,
    };
    let key = queued.key.take();
    // The deadline starts now, not when the request arrived: the timeout bounds
    // the retrieval from origin, and time queued for a slot is not part of it.
    let deadline = SharedDeadline::new(timeout);
    tx.send_replace(FetchState::Running(deadline.clone()));

    let map = map.clone();
    background_spawn!("background_fetch", async move {
        let _permit = permit;
        let result = run(deadline).await;
        // Publish first so a late subscriber that joined just before removal
        // still sees the result, then drop the in-flight entry.
        tx.send_replace(FetchState::Done(Arc::new(result)));
        if let Some(key) = key {
            map.lock().remove(&key);
        }
    });
    rx
}

/// Awaits a [`SharedResult`] for a request with `timeout` and unwraps it into
/// an owned result, with how long the request waited on it once it was
/// running: the part of the wait that counts against its timeout. `None` when
/// the fetch was abandoned while queued for a slot, so the caller should
/// schedule it again.
///
/// The request lengthens the shared deadline to its own `timeout`, and gives up
/// with `DeadlineExceeded` once that has passed with the retrieval still under
/// way, while the fetch carries on for any request that allowed it longer.
async fn await_shared(
    mut rx: SharedResult,
    timeout: Option<Duration>,
) -> Option<(Result<FetchOutcome, Error>, Duration)> {
    let started = rx
        .wait_for(|state| !matches!(state, FetchState::Queued))
        .await
        .map(|state| state.clone())
        .ok();
    let deadline = match started.unwrap_or_else(|| rx.borrow().clone()) {
        FetchState::Queued => return None,
        FetchState::Done(value) => return Some((unwrap_shared(&value), Duration::ZERO)),
        FetchState::Running(deadline) => deadline,
    };
    deadline.extend(timeout);
    let running_since = Instant::now();
    let own_deadline = timeout.and_then(|timeout| running_since.checked_add(timeout));
    let done = async {
        let done = rx
            .wait_for(|state| matches!(state, FetchState::Done(_)))
            .await
            .map(|state| state.clone());
        match done {
            Ok(FetchState::Done(value)) => unwrap_shared(&value),
            _ => Err(make_err!(
                Code::Internal,
                "Background fetch task ended without publishing a result"
            )),
        }
    };
    let result = tokio::select! {
        result = done => result,
        () = deadline.outlived(own_deadline) => Err(make_err!(
            Code::DeadlineExceeded,
            "The fetch did not finish within the request's timeout; it continues for an \
             identical request that allowed longer"
        )),
    };
    Some((result, running_since.elapsed()))
}

fn unwrap_shared(value: &Result<FetchOutcome, Error>) -> Result<FetchOutcome, Error> {
    match value {
        Ok(outcome) => Ok(outcome.clone()),
        Err(err) => Err(err.clone()),
    }
}

/// What [`BackgroundFetcher`] needs of a job, so that blobs and directories
/// share one implementation.
trait Job: Clone + Eq + Hash + Send + Sync + 'static {
    fn uris(&self) -> &[String];
    fn timeout(&self) -> Option<Duration>;
    fn is_pinned(&self) -> bool;
    fn select(&self, indices: &[usize], timeout: Option<Duration>) -> Self;
    fn in_flight(fetcher: &BackgroundFetcher) -> &Arc<Mutex<HashMap<Self, SharedResult>>>;
    /// Runs the job on `inner`, under `deadline`.
    fn run(
        self,
        inner: Arc<dyn Fetcher>,
        deadline: SharedDeadline,
    ) -> BoxFuture<'static, Result<FetchOutcome, Error>>;
}

impl Job for FetchBlobTask {
    fn uris(&self) -> &[String] {
        &self.uris
    }

    fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    fn is_pinned(&self) -> bool {
        Self::is_pinned(self)
    }

    fn select(&self, indices: &[usize], timeout: Option<Duration>) -> Self {
        Self::select(self, indices, timeout)
    }

    fn in_flight(fetcher: &BackgroundFetcher) -> &Arc<Mutex<HashMap<Self, SharedResult>>> {
        &fetcher.blob_in_flight
    }

    fn run(
        mut self,
        inner: Arc<dyn Fetcher>,
        deadline: SharedDeadline,
    ) -> BoxFuture<'static, Result<FetchOutcome, Error>> {
        Box::pin(async move {
            self.shared_deadline = Some(deadline);
            inner.fetch_blob(&self).await
        })
    }
}

impl Job for FetchDirectoryJob {
    fn uris(&self) -> &[String] {
        &self.uris
    }

    fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    fn is_pinned(&self) -> bool {
        Self::is_pinned(self)
    }

    fn select(&self, indices: &[usize], timeout: Option<Duration>) -> Self {
        Self::select(self, indices, timeout)
    }

    fn in_flight(fetcher: &BackgroundFetcher) -> &Arc<Mutex<HashMap<Self, SharedResult>>> {
        &fetcher.dir_in_flight
    }

    fn run(
        mut self,
        inner: Arc<dyn Fetcher>,
        deadline: SharedDeadline,
    ) -> BoxFuture<'static, Result<FetchOutcome, Error>> {
        Box::pin(async move {
            self.shared_deadline = Some(deadline);
            inner.fetch_directory(&self).await
        })
    }
}

impl BackgroundFetcher {
    /// Fetches `job`. A pinned job is fetched one URI at a time, each as a
    /// fetch of its own that an identical pinned request for that URI joins,
    /// so requests that list different mirrors of one asset share the
    /// download of the mirrors they have in common. The URIs are tried in
    /// order until one succeeds, or one fails in a way the rest would too (see
    /// [`fails_only_these_uris`]), and the job's timeout covers them all.
    ///
    /// An unpinned job joins nothing, so it is run whole.
    async fn fetch<J: Job>(&self, job: &J) -> Result<FetchOutcome, Error> {
        let timeout = self.clamp(job.timeout());
        if !job.is_pinned() || job.uris().len() <= 1 {
            let all: Vec<usize> = (0..job.uris().len()).collect();
            return self.run(job.select(&all, timeout)).await.0;
        }
        let mut spent = Duration::ZERO;
        let mut last_err = None;
        for idx in 0..job.uris().len() {
            let left = match timeout {
                Some(timeout) => {
                    let left = timeout.saturating_sub(spent);
                    if left.is_zero() {
                        last_err = Some(make_err!(
                            Code::DeadlineExceeded,
                            "The fetch ran out of time before every URI was tried"
                        ));
                        break;
                    }
                    Some(left)
                }
                None => None,
            };
            let (result, waited) = self.run(job.select(&[idx], left)).await;
            spent += waited;
            match result {
                Ok(outcome) => return Ok(outcome),
                Err(err) if fails_only_these_uris(err.code) => {
                    debug!(idx, code = ?err.code, "Fetch of one URI failed, trying the next");
                    last_err = Some(err);
                }
                Err(err) => return Err(err),
            }
        }
        Err(last_err.expect("there are several URIs, and each failed"))
    }

    /// Runs `job`, or joins an identical pinned one, and waits for it. Returns
    /// the result and how long of the wait counts against the job's timeout.
    async fn run<J: Job>(&self, job: J) -> (Result<FetchOutcome, Error>, Duration) {
        loop {
            let inner = self.inner.clone();
            let run_job = job.clone();
            let rx = schedule_or_join(
                J::in_flight(self),
                self.permits.as_ref(),
                job.clone(),
                // An unpinned request accepts only what the origin serves now, so it
                // must not take the result of a fetch that started before it.
                job.is_pinned(),
                job.timeout(),
                move |deadline| run_job.run(inner, deadline),
            )
            .await;
            if let Some(done) = await_shared(rx, job.timeout()).await {
                return done;
            }
        }
    }
}

#[async_trait]
impl Fetcher for BackgroundFetcher {
    async fn fetch_blob(&self, job: &FetchBlobTask) -> Result<FetchOutcome, Error> {
        self.fetch(job).await
    }

    async fn fetch_directory(&self, job: &FetchDirectoryJob) -> Result<FetchOutcome, Error> {
        self.fetch(job).await
    }
}
