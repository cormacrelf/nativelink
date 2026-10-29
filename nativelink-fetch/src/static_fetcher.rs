// Copyright 2026 The NativeLink Authors. All rights reserved.
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

//! [`StaticFetcher`]: a [`Fetcher`] that serves a fixed set of URIs from
//! content it was built with, in place of a [`crate::url_fetcher::UrlFetcher`]
//! that would download them. It is for tests, demos and diagrams, where
//! running an origin server is more trouble than the thing being tried.
//!
//! It answers as a `url` fetcher does: a URI it does not hold is `NotFound`,
//! the request's checksums must match (`Aborted` if not), URIs are tried in
//! the order the request lists them, and the content lands in the CAS under
//! its digest.

use std::collections::HashMap;

use bytes::Bytes;
use nativelink_error::{Code, Error, ResultExt, make_err};
use nativelink_util::digest_hasher::DigestHasher;
use nativelink_util::sri::ChecksumVerifier;
use nativelink_util::store_trait::{Store, StoreLike};
use tonic::async_trait;

use crate::fetcher::{FetchBlobTask, FetchDirectoryJob, FetchOutcome, Fetcher};

/// A [`Fetcher`] that serves the URIs it was built with. See the
/// [module docs](self).
#[derive(Debug)]
pub struct StaticFetcher {
    cas_store: Store,
    content: HashMap<String, Bytes>,
}

impl StaticFetcher {
    /// A fetcher that writes to `cas_store` the content it holds for each URI
    /// of `content`, and refuses every other URI as not found.
    #[must_use]
    pub fn new<U, B>(cas_store: Store, content: impl IntoIterator<Item = (U, B)>) -> Self
    where
        U: Into<String>,
        B: Into<Bytes>,
    {
        Self {
            cas_store,
            content: content
                .into_iter()
                .map(|(uri, body)| (uri.into(), body.into()))
                .collect(),
        }
    }

    /// Serves `body` for `uri`, if every checksum of `job` matches it.
    async fn serve(
        &self,
        job: &FetchBlobTask,
        uri: &str,
        body: &Bytes,
    ) -> Result<FetchOutcome, Error> {
        for checksum in &job.checksums {
            let mut verifier = ChecksumVerifier::new(checksum);
            verifier.update(body);
            verifier.finalize_and_verify()?;
        }
        let mut hasher = job.hasher_func.hasher();
        hasher.update(body);
        let digest = hasher.finalize_digest();
        self.cas_store
            .update_oneshot(digest, body.clone())
            .await
            .err_tip(|| "Uploading static content to CAS")?;
        Ok(FetchOutcome::new(uri.to_owned(), digest))
    }
}

#[async_trait]
impl Fetcher for StaticFetcher {
    async fn fetch_blob(&self, job: &FetchBlobTask) -> Result<FetchOutcome, Error> {
        let mut last_err = None;
        for uri in &job.uris {
            let Some(body) = self.content.get(uri) else {
                last_err = Some(make_err!(
                    Code::NotFound,
                    "'{uri}' is not one of the static URIs"
                ));
                continue;
            };
            match self.serve(job, uri, body).await {
                Ok(outcome) => return Ok(outcome),
                // Corrupt content from this mirror; another may be right.
                Err(err) if err.code == Code::Aborted => last_err = Some(err),
                Err(err) => return Err(err),
            }
        }
        Err(last_err.unwrap_or_else(|| make_err!(Code::NotFound, "No URIs available to fetch")))
    }

    async fn fetch_directory(&self, _job: &FetchDirectoryJob) -> Result<FetchOutcome, Error> {
        Err(make_err!(
            Code::Unimplemented,
            "The 'static' fetcher serves blobs only"
        ))
    }
}
