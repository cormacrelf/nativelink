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

use std::sync::Arc;

use nativelink_error::{Error, ResultExt};
use nativelink_proto::build::bazel::remote::asset::v1::Qualifier;
use nativelink_proto::build::bazel::remote::execution::v2::Digest;
use nativelink_util::digest_hasher::DigestHasherFunc;
use nativelink_util::redact::redact_uri;
use nativelink_util::store_trait::Store;
use prost_types::Timestamp;
use tonic::async_trait;
use tracing::debug;

use crate::fetcher::{FetchBlobTask, FetchOutcome, Fetcher};
use crate::remote_asset_proto::{
    AssetKind, RemoteAssetEntry, RemoteAssetQuery, now_timestamp, write_remote_asset_entry,
};

/// A [`Fetcher`] decorator that caches fetched-asset metadata on success.
#[derive(Debug)]
pub struct MetadataCache {
    inner: Arc<dyn Fetcher>,
    /// The Action Cache store the metadata is written to, as an `ActionResult`
    /// (see [`crate::remote_asset_proto`]).
    ac_store: Store,
}

impl MetadataCache {
    /// Wraps `inner`, writing fetched-asset metadata into `ac_store`.
    pub fn new(inner: Arc<dyn Fetcher>, ac_store: Store) -> Arc<Self> {
        Arc::new(Self { inner, ac_store })
    }

    /// Writes the metadata for a successful fetch. The hash-function context
    /// of the request reaches here through the background task's propagated
    /// context, as it does for the content upload.
    async fn write(
        &self,
        kind: AssetKind,
        outcome: &FetchOutcome,
        qualifiers: &[(String, String)],
        hasher_func: DigestHasherFunc,
        stored_at: Timestamp,
    ) -> Result<(), Error> {
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
            expire_at: None,
            stored_at: Some(stored_at),
            digest_function: hasher_func.proto_digest_func().into(),
        };
        write_remote_asset_entry(&self.ac_store, &entry)
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
        let stored_at = now_timestamp();
        let outcome = self.inner.fetch_blob(job).await?;
        self.write(
            AssetKind::Blob,
            &outcome,
            &job.qualifiers,
            job.hasher_func,
            stored_at,
        )
        .await?;
        Ok(outcome)
    }
}
