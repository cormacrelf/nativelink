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

//! [`MetadataCache`]: a [`Fetcher`] decorator that writes the fetched asset's
//! Remote Asset metadata (the URI+qualifiers -> digest mapping) into an Action
//! Cache store on success, as described in [`crate::remote_asset_proto`].
//!
//! It is placed *inside* [`crate::background_fetcher::BackgroundFetcher`] in the
//! chain (`Background(MetadataCache(Url))`) so that the metadata write runs in
//! the same detached, deduplicated unit of work as the download and CAS upload.
//! That way the write survives a client abandoning its RPC -- without this, a
//! backgrounded fetch could land the blob in the CAS while the URI->digest
//! pointer was never written, leaving the asset undiscoverable by future Fetch
//! calls.
//!
//! Only the *write* lives here. The metadata *read* (cache lookup) stays in the
//! `FetchServer`, where a hit is served verbatim from the stored entry and
//! never has to spawn a background task.

use core::time::Duration;
use std::sync::Arc;
use std::time::SystemTime;

use nativelink_error::{Error, ResultExt};
use nativelink_proto::build::bazel::remote::asset::v1::Qualifier;
use nativelink_proto::build::bazel::remote::execution::v2::Digest;
use nativelink_util::digest_hasher::DigestHasherFunc;
use nativelink_util::redact::redact_uri;
use nativelink_util::store_trait::Store;
use prost_types::Timestamp;
use tonic::async_trait;
use tracing::debug;

use crate::fetcher::{FetchBlobTask, FetchDirectoryJob, FetchOutcome, Fetcher};
use crate::remote_asset_proto::{
    AssetKind, RemoteAssetEntry, RemoteAssetQuery, write_remote_asset_entry,
};

/// How long entries for unpinned requests (those with no checksum) stay fresh.
/// Entries for pinned requests never expire. Built from the
/// `unpinned_*_ttl_s` fields of
/// [`MetadataCacheSpec`](nativelink_config::fetchers::MetadataCacheSpec).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetadataCacheOptions {
    /// Lifetime when the origin's headers say nothing.
    pub unpinned_default_ttl: Duration,
    /// Shortest lifetime given when the headers do give one. A lifetime of
    /// zero (the response must not be reused) is kept as zero.
    pub unpinned_min_ttl: Duration,
    /// Longest lifetime given.
    pub unpinned_max_ttl: Duration,
}

impl Default for MetadataCacheOptions {
    fn default() -> Self {
        Self {
            unpinned_default_ttl: Duration::from_hours(24),
            unpinned_min_ttl: Duration::from_mins(5),
            unpinned_max_ttl: Duration::from_hours(720),
        }
    }
}

impl MetadataCacheOptions {
    /// The lifetime of an unpinned entry whose fetch reported `freshness`
    /// (see [`FetchOutcome::freshness`]).
    fn unpinned_ttl(&self, freshness: Option<Duration>) -> Duration {
        match freshness {
            Some(Duration::ZERO) => Duration::ZERO,
            Some(ttl) => self.clamp(ttl),
            None => self.clamp(self.unpinned_default_ttl),
        }
    }

    fn clamp(&self, ttl: Duration) -> Duration {
        // Not `Duration::clamp`, which panics when `min > max`.
        ttl.max(self.unpinned_min_ttl).min(self.unpinned_max_ttl)
    }
}

/// A [`Fetcher`] decorator that caches fetched-asset metadata on success.
#[derive(Debug)]
pub struct MetadataCache {
    inner: Arc<dyn Fetcher>,
    /// The Action Cache store the metadata is written to, as an `ActionResult`
    /// (see [`crate::remote_asset_proto`]).
    ac_store: Store,
    /// The CAS the fetched content lives in, used to build the `Tree` of a
    /// directory.
    cas_store: Store,
    options: MetadataCacheOptions,
}

impl MetadataCache {
    /// Wraps `inner`, writing fetched-asset metadata into `ac_store`, with the
    /// default [`MetadataCacheOptions`].
    pub fn new(inner: Arc<dyn Fetcher>, ac_store: Store, cas_store: Store) -> Arc<Self> {
        Self::with_options(inner, ac_store, cas_store, MetadataCacheOptions::default())
    }

    /// Like [`Self::new`], with the given freshness options.
    pub fn with_options(
        inner: Arc<dyn Fetcher>,
        ac_store: Store,
        cas_store: Store,
        options: MetadataCacheOptions,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner,
            ac_store,
            cas_store,
            options,
        })
    }

    /// Writes the metadata for a successful fetch. The hash-function context
    /// of the request reaches here through the background task's propagated
    /// context, as it does for the content upload.
    ///
    /// A pinned request's entry never expires. An unpinned one expires
    /// `stored_at` plus the lifetime the origin's headers gave
    /// (`outcome.freshness`), within the configured limits. The expiry is
    /// recorded on `outcome` too, for the `Fetch` response.
    async fn write(
        &self,
        kind: AssetKind,
        outcome: &mut FetchOutcome,
        qualifiers: &[(String, String)],
        hasher_func: DigestHasherFunc,
        pinned: bool,
        started: SystemTime,
    ) -> Result<(), Error> {
        let expire_at = if pinned {
            None
        } else {
            let ttl = self.options.unpinned_ttl(outcome.freshness);
            started.checked_add(ttl).map(Timestamp::from)
        };
        outcome.expire_at = expire_at;
        let qualifiers = qualifiers
            .iter()
            .map(|(name, value)| Qualifier {
                name: name.clone(),
                value: value.clone(),
            })
            .collect();
        let digest: Digest = outcome.digest.into();
        let entry = RemoteAssetEntry {
            // Header qualifiers are dropped by `RemoteAssetQuery::new` as a
            // safeguard: they are often credentials and must never be persisted.
            query: RemoteAssetQuery::new(kind, outcome.uri.clone(), qualifiers),
            digest: digest.clone(),
            expire_at,
            stored_at: Some(Timestamp::from(started)),
            digest_function: hasher_func.proto_digest_func().into(),
            tree_digest: None,
        };
        write_remote_asset_entry(&self.ac_store, Some(&self.cas_store), &entry)
            .await
            .err_tip(|| "Caching fetched asset metadata")?;
        debug!(
            uri = %redact_uri(&outcome.uri),
            digest = %digest.hash,
            "Cached fetched asset metadata"
        );
        Ok(())
    }
}

#[async_trait]
impl Fetcher for MetadataCache {
    async fn fetch_blob(&self, job: &FetchBlobTask) -> Result<FetchOutcome, Error> {
        // The spec measures content age from when retrieval started.
        let started = SystemTime::now();
        let mut outcome = self.inner.fetch_blob(job).await?;
        self.write(
            AssetKind::Blob,
            &mut outcome,
            &job.qualifiers,
            job.hasher_func,
            job.is_pinned(),
            started,
        )
        .await?;
        Ok(outcome)
    }

    async fn fetch_directory(&self, job: &FetchDirectoryJob) -> Result<FetchOutcome, Error> {
        let started = SystemTime::now();
        let mut outcome = self.inner.fetch_directory(job).await?;
        self.write(
            AssetKind::Directory,
            &mut outcome,
            &job.qualifiers,
            job.hasher_func,
            job.is_pinned(),
            started,
        )
        .await?;
        Ok(outcome)
    }
}
