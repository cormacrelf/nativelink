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
//! task -- and the watch sender it owns -- keeps running to completion. A
//! concurrent or subsequent identical pinned request (one that carries a
//! checksum) finds the in-flight entry and subscribes to the same task instead
//! of starting a new download. An unpinned request always runs its own fetch.
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

use nativelink_config::fetchers::DEFAULT_MAX_CONCURRENT_FETCHES;
use nativelink_error::{Error, make_err};
use nativelink_util::background_spawn;
use parking_lot::Mutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::Instant;
use tonic::{Code, async_trait};

use crate::fetcher::{FetchBlobTask, FetchDirectoryJob, FetchOutcome, Fetcher, SharedDeadline};

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
/// an owned result. `None` when the fetch was abandoned while queued for a
/// slot, so the caller should schedule it again.
///
/// The request lengthens the shared deadline to its own `timeout`, and gives up
/// with `DeadlineExceeded` once that has passed with the retrieval still under
/// way, while the fetch carries on for any request that allowed it longer.
async fn await_shared(
    mut rx: SharedResult,
    timeout: Option<Duration>,
) -> Option<Result<FetchOutcome, Error>> {
    let started = rx
        .wait_for(|state| !matches!(state, FetchState::Queued))
        .await
        .map(|state| state.clone())
        .ok();
    let deadline = match started.unwrap_or_else(|| rx.borrow().clone()) {
        FetchState::Queued => return None,
        FetchState::Done(value) => return Some(unwrap_shared(&value)),
        FetchState::Running(deadline) => deadline,
    };
    deadline.extend(timeout);
    let own_deadline = timeout.and_then(|timeout| Instant::now().checked_add(timeout));
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
    Some(tokio::select! {
        result = done => result,
        () = deadline.outlived(own_deadline) => Err(make_err!(
            Code::DeadlineExceeded,
            "The fetch did not finish within the request's timeout; it continues for an \
             identical request that allowed longer"
        )),
    })
}

fn unwrap_shared(value: &Result<FetchOutcome, Error>) -> Result<FetchOutcome, Error> {
    match value {
        Ok(outcome) => Ok(outcome.clone()),
        Err(err) => Err(err.clone()),
    }
}

#[async_trait]
impl Fetcher for BackgroundFetcher {
    async fn fetch_blob(&self, job: &FetchBlobTask) -> Result<FetchOutcome, Error> {
        let mut job = job.clone();
        job.timeout = self.clamp(job.timeout);
        loop {
            let inner = self.inner.clone();
            let mut run_job = job.clone();
            let rx = schedule_or_join(
                &self.blob_in_flight,
                self.permits.as_ref(),
                job.clone(),
                // An unpinned request accepts only what the origin serves now, so it
                // must not take the result of a fetch that started before it.
                job.is_pinned(),
                job.timeout,
                move |deadline| async move {
                    run_job.shared_deadline = Some(deadline);
                    inner.fetch_blob(&run_job).await
                },
            )
            .await;
            if let Some(result) = await_shared(rx, job.timeout).await {
                return result;
            }
        }
    }

    async fn fetch_directory(&self, job: &FetchDirectoryJob) -> Result<FetchOutcome, Error> {
        let mut job = job.clone();
        job.timeout = self.clamp(job.timeout);
        loop {
            let inner = self.inner.clone();
            let mut run_job = job.clone();
            let rx = schedule_or_join(
                &self.dir_in_flight,
                self.permits.as_ref(),
                job.clone(),
                job.is_pinned(),
                job.timeout,
                move |deadline| async move {
                    run_job.shared_deadline = Some(deadline);
                    inner.fetch_directory(&run_job).await
                },
            )
            .await;
            if let Some(result) = await_shared(rx, job.timeout).await {
                return result;
            }
        }
    }
}
