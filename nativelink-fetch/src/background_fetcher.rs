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
//! concurrent or subsequent identical request finds the in-flight entry and
//! subscribes to the same task instead of starting a new download.
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

use nativelink_error::{Error, make_err};
use nativelink_util::background_spawn;
use parking_lot::Mutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tonic::{Code, async_trait};

use crate::fetcher::{FetchBlobTask, FetchOutcome, Fetcher};

/// The shared, in-flight result of one fetch. `None` until the fetch completes;
/// once set, every current and future subscriber observes the same
/// `Arc`-wrapped result. The producing task owns the matching `watch::Sender`
/// and runs to completion regardless of how many subscribers remain.
type SharedResult = watch::Receiver<Option<Arc<Result<FetchOutcome, Error>>>>;

/// Tuning for [`BackgroundFetcher`].
#[derive(Clone, Copy, Debug, Default)]
pub struct BackgroundFetcherOpts {
    /// Maximum number of inner fetches running at once. `None` is unbounded.
    pub max_concurrent_fetches: Option<usize>,
    /// Lower bound applied to a job's `header_timeout` (only when the job sets
    /// one). `None` leaves it unchanged.
    pub min_timeout: Option<Duration>,
    /// Upper bound applied to a job's `header_timeout` (only when the job sets
    /// one). `None` leaves it unchanged.
    pub max_timeout: Option<Duration>,
}

/// A [`Fetcher`] decorator providing dedup + background continuation.
#[derive(Debug)]
pub struct BackgroundFetcher {
    inner: Arc<dyn Fetcher>,
    blob_in_flight: Arc<Mutex<HashMap<FetchBlobTask, SharedResult>>>,
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
            permits: opts
                .max_concurrent_fetches
                .map(|n| Arc::new(Semaphore::new(n))),
            min_timeout: opts.min_timeout,
            max_timeout: opts.max_timeout,
        })
    }

    /// Clamps a job's header timeout into `[min, max]`. Only applies when the
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

/// Subscribes to an in-flight fetch for `key`, or starts one by spawning a
/// detached task running `run`. The task acquires a concurrency permit (when
/// configured), publishes its result to the watch channel, then removes itself
/// from the map. Returns a receiver the caller can await; dropping it does not
/// cancel the task.
fn schedule_or_join<K, F, Fut>(
    map: &Arc<Mutex<HashMap<K, SharedResult>>>,
    permits: &Option<Arc<Semaphore>>,
    key: K,
    run: F,
) -> SharedResult
where
    K: Clone + Eq + Hash + Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<FetchOutcome, Error>> + Send + 'static,
{
    let mut guard = map.lock();
    if let Some(rx) = guard.get(&key) {
        return rx.clone();
    }
    let (tx, rx) = watch::channel(None);
    guard.insert(key.clone(), rx.clone());
    drop(guard);

    let map = map.clone();
    let permits = permits.clone();
    background_spawn!("background_fetch", async move {
        let _permit: Option<OwnedSemaphorePermit> = match &permits {
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
        let result = run().await;
        // Publish first so a late subscriber that joined just before removal
        // still sees the result, then drop the in-flight entry. The send only
        // errors if every receiver has been dropped, which we ignore -- the
        // fetch result is still cached in the watch channel's last value.
        drop(tx.send(Some(Arc::new(result))));
        map.lock().remove(&key);
    });
    rx
}

/// Awaits a [`SharedResult`] and unwraps it into an owned result.
async fn await_shared(mut rx: SharedResult) -> Result<FetchOutcome, Error> {
    let guard = rx.wait_for(Option::is_some).await.map_err(|_| {
        make_err!(
            Code::Internal,
            "Background fetch task ended without publishing a result"
        )
    })?;
    let value = (*guard).clone().expect("wait_for guarantees Some");
    drop(guard);
    match &*value {
        Ok(outcome) => Ok(outcome.clone()),
        Err(err) => Err(err.clone()),
    }
}

#[async_trait]
impl Fetcher for BackgroundFetcher {
    async fn fetch_blob(&self, job: &FetchBlobTask) -> Result<FetchOutcome, Error> {
        let mut job = job.clone();
        job.header_timeout = self.clamp(job.header_timeout);
        let inner = self.inner.clone();
        let run_job = job.clone();
        let rx = schedule_or_join(
            &self.blob_in_flight,
            &self.permits,
            job,
            move || async move { inner.fetch_blob(&run_job).await },
        );
        await_shared(rx).await
    }
}
