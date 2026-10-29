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

//! The [`Fetcher`] abstraction: something that downloads a blob or directory
//! from one of a set of URIs, verifies it, stores it in a CAS, and returns the
//! resulting digest.
//!
//! Implementations compose as decorators. The leaf is
//! [`crate::url_fetcher::UrlFetcher`], which does the real HTTP work; wrappers
//! such as [`crate::background_fetcher::BackgroundFetcher`] layer on policy
//! (in-flight deduplication, background continuation, timeout clamping) without
//! knowing how a fetch is actually performed. This keeps each concern testable
//! in isolation: the URL fetcher against a fake HTTP server, the decorators
//! against a mock `Fetcher`.

use core::hash::{Hash, Hasher};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;

use nativelink_error::{Error, make_input_err};
use nativelink_proto::build::bazel::remote::asset::v1::Qualifier;
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::DigestHasherFunc;
use nativelink_util::sri::ByteChecksum;
use parking_lot::Mutex;
use prost_types::Timestamp;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use tokio::sync::watch;
use tokio::time::Instant;
use tonic::async_trait;

use crate::remote_asset_proto::{QUALIFIER_HTTP_HEADER_PREFIX, QUALIFIER_HTTP_HEADER_URL_PREFIX};
use crate::tree_hash::TreeChecksum;

/// A checksum used to verify a downloaded directory archive: of the raw
/// archive bytes, of the expanded files, or by running an action on them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DirectoryChecksum {
    /// A hash of the raw archive bytes: the `checksum.sri` qualifier or one of
    /// the hex `checksum.sha*` qualifiers.
    Bytes(ByteChecksum),
    /// A hash of the expanded tree in one of the [`crate::tree_hash`] formats.
    Tree(TreeChecksum),
    /// The digest of an `Action` to run on the expanded tree; the
    /// `checksum.action_digest` qualifier. Checked by
    /// [`crate::action_verifier::ActionVerifier`].
    Action(DigestInfo),
}

/// HTTP headers a request asks the fetcher to send to the origin, parsed from
/// its `http_header:<name>` and `http_header_url:<idx>:<name>` qualifiers (the
/// convention Bazel's remote downloader uses). They are request parameters, not
/// part of the asset's identity: they are excluded from the metadata key, never
/// persisted, and marked sensitive so they are redacted from `Debug` output
/// (they are often credentials).
///
/// They are part of the in-memory deduplication identity, though: different
/// credentials can get different answers from the origin, so requests with
/// different headers don't share a fetch. `Eq` compares the headers themselves,
/// ignoring order and name case; `Hash` covers only the header names, so no
/// credential is ever fed to a hasher.
///
/// Header qualifiers must never be persisted, logged or made part of any
/// persisted cache key, because they typically carry auth credentials. A
/// fetcher that sends work elsewhere (another process or node) must carry them
/// over a non-persisted channel or refuse such requests.
#[derive(Clone, Debug, Default)]
pub struct FetchHeaders {
    /// Headers sent to every URI.
    global: HeaderMap,
    /// Headers sent only to the URI at the given index; these override a
    /// global header of the same name.
    per_uri: HashMap<usize, HeaderMap>,
}

impl FetchHeaders {
    /// Parses the header qualifiers out of `qualifiers`, ignoring all others.
    /// Header names are case-insensitive. A malformed qualifier (empty or
    /// invalid header name, bad or out-of-range URI index, invalid value) is an
    /// `InvalidArgument` error.
    pub fn from_qualifiers(qualifiers: &[Qualifier], num_uris: usize) -> Result<Self, Error> {
        let mut headers = Self::default();
        for qualifier in qualifiers {
            let (target, name) = if let Some(rest) = qualifier
                .name
                .strip_prefix(QUALIFIER_HTTP_HEADER_URL_PREFIX)
            {
                let (idx, name) = rest.split_once(':').ok_or_else(|| {
                    make_input_err!(
                        "Malformed qualifier '{}': expected http_header_url:<idx>:<name>",
                        qualifier.name
                    )
                })?;
                let idx: usize = idx.parse().map_err(|_| {
                    make_input_err!("Malformed qualifier '{}': bad URI index", qualifier.name)
                })?;
                if idx >= num_uris {
                    return Err(make_input_err!(
                        "Malformed qualifier '{}': URI index out of range",
                        qualifier.name
                    ));
                }
                (Some(idx), name)
            } else if let Some(name) = qualifier.name.strip_prefix(QUALIFIER_HTTP_HEADER_PREFIX) {
                (None, name)
            } else {
                continue;
            };
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
                make_input_err!(
                    "Malformed qualifier '{}': bad header name: {e}",
                    qualifier.name
                )
            })?;
            let mut value = HeaderValue::from_str(&qualifier.value).map_err(|e| {
                make_input_err!(
                    "Malformed qualifier '{}': bad header value: {e}",
                    qualifier.name
                )
            })?;
            value.set_sensitive(true);
            let map = match target {
                Some(idx) => headers.per_uri.entry(idx).or_default(),
                None => &mut headers.global,
            };
            map.append(name, value);
        }
        Ok(headers)
    }

    /// The headers to send to `uris[idx]`: the global headers, with any
    /// URI-specific header replacing the global one of the same name.
    pub fn for_uri(&self, idx: usize) -> HeaderMap {
        let mut headers = self.global.clone();
        if let Some(specific) = self.per_uri.get(&idx) {
            for name in specific.keys() {
                headers.remove(name);
            }
            for (name, value) in specific {
                headers.append(name.clone(), value.clone());
            }
        }
        headers
    }

    /// The headers for the URIs from `uris[first]` on, indexed from there:
    /// what a job holding only `uris[first..]` must carry.
    #[must_use]
    pub fn from_uri(&self, first: usize) -> Self {
        Self {
            global: self.global.clone(),
            per_uri: self
                .per_uri
                .iter()
                .filter_map(|(&idx, headers)| {
                    idx.checked_sub(first).map(|idx| (idx, headers.clone()))
                })
                .collect(),
        }
    }
}

impl PartialEq for FetchHeaders {
    fn eq(&self, other: &Self) -> bool {
        // `HeaderMap` equality ignores the order of names, and names are
        // lowercased on parsing.
        self.global == other.global && self.per_uri == other.per_uri
    }
}

impl Eq for FetchHeaders {}

impl Hash for FetchHeaders {
    fn hash<H: Hasher>(&self, state: &mut H) {
        fn hash_names<H: Hasher>(headers: &HeaderMap, state: &mut H) {
            let mut names: Vec<&str> = headers.keys().map(HeaderName::as_str).collect();
            names.sort_unstable();
            for name in names {
                name.hash(state);
            }
        }
        hash_names(&self.global, state);
        let mut per_uri: Vec<_> = self.per_uri.iter().collect();
        per_uri.sort_unstable_by_key(|&(&idx, _)| idx);
        for (idx, headers) in per_uri {
            idx.hash(state);
            hash_names(headers, state);
        }
    }
}

/// The validators an origin gave a response, which let it be revalidated
/// later with a conditional request instead of downloaded again. Opaque
/// strings, stored and sent back as the origin gave them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Validators {
    /// The `ETag`, sent back as `If-None-Match`.
    pub etag: Option<String>,
    /// The `Last-Modified`, sent back as `If-Modified-Since`.
    pub last_modified: Option<String>,
}

impl Validators {
    /// Whether there is nothing to revalidate with.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.etag.is_none() && self.last_modified.is_none()
    }
}

/// A stale cached answer for one URI of an unpinned request, offered to the
/// fetcher so that it can ask the origin whether the content is still current
/// (`If-None-Match` / `If-Modified-Since`) rather than download it again. If
/// the origin says it is (`304 Not Modified`) and the content is still
/// complete in the CAS, the fetch returns `digest` without downloading;
/// otherwise it proceeds as if there were no cached answer.
///
/// It is a parameter of the request, not part of its identity: it is excluded
/// from `Hash`/`Eq`. Only an unpinned request carries one, and an unpinned
/// request never shares an in-flight fetch, so each fetch revalidates its own
/// caller's stale entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revalidation {
    /// The URI the stale answer was stored for; the fetcher uses it only for
    /// that URI.
    pub uri: String,
    /// The CAS digest of the stale answer: of the blob, or of the root
    /// `Directory`.
    pub digest: DigestInfo,
    /// What to revalidate with. Never empty.
    pub validators: Validators,
}

/// The deadline of a fetch shared by identical pinned requests, set on the job by
/// [`crate::background_fetcher::BackgroundFetcher`].
///
/// A request's `timeout` bounds the retrieval from origin, so a fetch that
/// several requests share runs until the latest of their deadlines, each
/// counted from when the request started or joined it, and without one (but
/// for the fetcher's own cap) once any request set no timeout. A request that
/// joins later lengthens it. Each request's own `timeout` is held to by
/// [`Self::outlived`], which is what its caller waits on.
#[derive(Clone, Debug)]
pub struct SharedDeadline(Arc<SharedDeadlineState>);

#[derive(Debug)]
struct SharedDeadlineState {
    /// When the fetch must stop. `None` is no deadline.
    until: Mutex<Option<Instant>>,
    /// How many retrievals from origin are under way: the part of a fetch the
    /// timeout bounds, as opposed to, say, an action verifying the result.
    retrieving: watch::Sender<usize>,
}

/// Marks a retrieval from origin as under way until dropped. See
/// [`SharedDeadline::retrieving`].
#[derive(Debug)]
pub struct Retrieving(SharedDeadline);

impl Drop for Retrieving {
    fn drop(&mut self) {
        self.0.0.retrieving.send_modify(|count| *count -= 1);
    }
}

impl SharedDeadline {
    /// The deadline of a fetch starting now for a request with `timeout`.
    #[must_use]
    pub fn new(timeout: Option<Duration>) -> Self {
        Self(Arc::new(SharedDeadlineState {
            until: Mutex::new(timeout.and_then(|timeout| Instant::now().checked_add(timeout))),
            retrieving: watch::Sender::new(0),
        }))
    }

    /// Lets the fetch run at least `timeout` from now, for a request that
    /// joins it. `None` takes the deadline away.
    pub fn extend(&self, timeout: Option<Duration>) {
        let mut until = self.0.until.lock();
        *until = match (*until, timeout) {
            (Some(until), Some(timeout)) => Instant::now()
                .checked_add(timeout)
                .map(|joined| until.max(joined)),
            _ => None,
        };
    }

    /// Resolves once the deadline has passed; never, if there is none.
    pub async fn expired(&self) {
        loop {
            let Some(until) = *self.0.until.lock() else {
                return core::future::pending().await;
            };
            if Instant::now() >= until {
                return;
            }
            // The deadline only ever moves later, so check it again on waking.
            tokio::time::sleep_until(until).await;
        }
    }

    /// Marks a retrieval from origin as under way until the guard is dropped.
    #[must_use]
    pub fn retrieving(&self) -> Retrieving {
        self.0.retrieving.send_modify(|count| *count += 1);
        Retrieving(self.clone())
    }

    /// Resolves when a request whose own deadline is `deadline` has run out of
    /// time: the deadline has passed and a retrieval is still, or again, under
    /// way. Time the fetch spends on anything else, such as running an action
    /// to verify the result, is not held against it. Never resolves for a
    /// request without a deadline.
    pub async fn outlived(&self, deadline: Option<Instant>) {
        let Some(deadline) = deadline else {
            return core::future::pending().await;
        };
        tokio::time::sleep_until(deadline).await;
        let mut retrieving = self.0.retrieving.subscribe();
        // `self` holds the sender, so this cannot fail.
        drop(retrieving.wait_for(|count| *count > 0).await);
    }
}

/// A request to fetch a single blob from one of `uris`.
///
/// `Hash`/`Eq` (implemented manually) define the in-flight deduplication
/// identity used by [`crate::background_fetcher::BackgroundFetcher`]: the URIs,
/// the qualifiers (order-insensitive), the checksum, the hash function and the
/// `headers` (see [`FetchHeaders`]). Other per-request parameters such as
/// `timeout` are deliberately excluded, so a concurrent duplicate joins the
/// in-flight fetch, which runs until the latest of the requesters' deadlines
/// (see [`SharedDeadline`]). Only pinned jobs (see [`Self::is_pinned`]) are
/// shared this way; an unpinned job always runs its own fetch.
#[derive(Clone, Debug)]
pub struct FetchBlobTask {
    /// Candidate URIs, tried in order until one serves valid content.
    pub uris: Vec<String>,
    /// The request's qualifiers as `(name, value)` pairs, excluding the HTTP
    /// header qualifiers (see [`FetchHeaders`]). Used to build/key the
    /// cached asset metadata (see [`crate::metadata_cache::MetadataCache`])
    /// and, because differing qualifiers map to distinct metadata entries,
    /// included in the deduplication identity (order-insensitively).
    pub qualifiers: Vec<(String, String)>,
    /// Checksums of the downloaded bytes (`checksum.sri` and the hex
    /// `checksum.sha*` qualifiers) that must all match. When empty, the
    /// content is downloaded unverified and stored under its computed CAS
    /// digest.
    pub checksums: Vec<ByteChecksum>,
    /// Hash function used to compute the CAS digest.
    pub hasher_func: DigestHasherFunc,
    /// The time budget for the whole job: every URI attempt, the download,
    /// verification and the CAS upload. Comes from the request's `timeout`. The
    /// fetcher fails the job with `DeadlineExceeded` when it runs out. `None`
    /// leaves only the fetcher's own cap in effect. Not part of the
    /// deduplication identity.
    pub timeout: Option<Duration>,
    /// Set by a [`crate::background_fetcher::BackgroundFetcher`] for a fetch
    /// identical requests share; it then bounds the job in place of `timeout`.
    /// Not part of the deduplication identity.
    pub shared_deadline: Option<SharedDeadline>,
    /// HTTP headers to send to the origin. Part of the deduplication identity,
    /// since different credentials can get different answers.
    pub headers: FetchHeaders,
    /// Stale cached answers to revalidate, for an unpinned request. Not part of
    /// the deduplication identity.
    pub revalidate: Vec<Revalidation>,
}

/// A request to fetch a directory (a zip, tar or tar.gz archive) from one of
/// `uris`.
///
/// `Hash`/`Eq` follow the same identity rules as [`FetchBlobTask`].
#[derive(Clone, Debug)]
pub struct FetchDirectoryJob {
    /// Candidate URIs, tried in order until one downloads successfully.
    pub uris: Vec<String>,
    /// The request's qualifiers as `(name, value)` pairs. Used to build/key the
    /// cached asset metadata and included in the deduplication identity
    /// (order-insensitively).
    pub qualifiers: Vec<(String, String)>,
    /// Checksums the downloaded archive must all match. When empty the
    /// archive is expanded without verification, as for a blob without a
    /// checksum.
    pub checksums: Vec<DirectoryChecksum>,
    /// Hash function used to compute the CAS digests of the expanded tree.
    pub hasher_func: DigestHasherFunc,
    /// Set by an [`crate::action_verifier::ActionVerifier`] on the job it passes
    /// on, after taking the [`DirectoryChecksum::Action`] checksums off it: the
    /// content will be verified by running those actions, which is a checksum as
    /// far as a fetcher that requires one is concerned. Not part of the
    /// deduplication identity.
    pub verified_by_action: bool,
    /// The time budget for the whole job: every URI attempt, the download,
    /// archive expansion, verification and the CAS upload. Not part of the
    /// deduplication identity.
    pub timeout: Option<Duration>,
    /// As for [`FetchBlobTask::shared_deadline`].
    pub shared_deadline: Option<SharedDeadline>,
    /// HTTP headers to send to the origin. Part of the deduplication identity,
    /// since different credentials can get different answers.
    pub headers: FetchHeaders,
    /// Stale cached answers to revalidate, for an unpinned request. Not part of
    /// the deduplication identity.
    pub revalidate: Vec<Revalidation>,
}

/// Returns `qualifiers` sorted by `(name, value)`, the canonical order used for
/// identity so that request qualifier order never matters.
fn sorted_qualifiers(qualifiers: &[(String, String)]) -> Vec<&(String, String)> {
    let mut sorted: Vec<_> = qualifiers.iter().collect();
    sorted.sort();
    sorted
}

impl PartialEq for FetchBlobTask {
    fn eq(&self, other: &Self) -> bool {
        self.uris == other.uris
            && sorted_qualifiers(&self.qualifiers) == sorted_qualifiers(&other.qualifiers)
            && self.checksums == other.checksums
            && self.hasher_func == other.hasher_func
            && self.headers == other.headers
    }
}

impl Eq for FetchBlobTask {}

impl Hash for FetchBlobTask {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.uris.hash(state);
        sorted_qualifiers(&self.qualifiers).hash(state);
        self.checksums.hash(state);
        self.hasher_func.hash(state);
        self.headers.hash(state);
    }
}

impl PartialEq for FetchDirectoryJob {
    fn eq(&self, other: &Self) -> bool {
        self.uris == other.uris
            && sorted_qualifiers(&self.qualifiers) == sorted_qualifiers(&other.qualifiers)
            && self.checksums == other.checksums
            && self.hasher_func == other.hasher_func
            && self.headers == other.headers
    }
}

impl Eq for FetchDirectoryJob {}

impl Hash for FetchDirectoryJob {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.uris.hash(state);
        sorted_qualifiers(&self.qualifiers).hash(state);
        self.checksums.hash(state);
        self.hasher_func.hash(state);
        self.headers.hash(state);
    }
}

impl FetchBlobTask {
    /// Whether the request is pinned: it carries a checksum, so the content it
    /// can accept is fixed and a cached answer can never go out of date. An
    /// unpinned request takes whatever the origin serves, which changes.
    #[must_use]
    pub const fn is_pinned(&self) -> bool {
        !self.checksums.is_empty()
    }
}

impl FetchDirectoryJob {
    /// Whether the request is pinned: it carries a checksum of any kind (of the
    /// archive bytes, of the expanded tree or an action to check it), so the
    /// content it can accept is fixed. See [`FetchBlobTask::is_pinned`].
    #[must_use]
    pub const fn is_pinned(&self) -> bool {
        !self.checksums.is_empty()
    }
}

/// The result of a successful fetch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchOutcome {
    /// The URI that successfully served the content.
    pub uri: String,
    /// CAS digest of the fetched blob, or of the root `Directory` for a
    /// directory fetch.
    pub digest: DigestInfo,
    /// How long the origin said the content stays fresh, from the headers of
    /// the final response (see [`crate::http_cache::freshness_lifetime`]).
    /// `None` when the headers said nothing; `Some(Duration::ZERO)` when they
    /// said it must not be reused without checking (`no-store`, `no-cache`,
    /// `private`, or already expired). Only
    /// [`crate::metadata_cache::MetadataCache`] reads it, and only for
    /// unpinned requests.
    pub freshness: Option<Duration>,
    /// When the stored metadata for this outcome expires, set by
    /// [`crate::metadata_cache::MetadataCache`]. `None` for content that does
    /// not expire.
    pub expire_at: Option<Timestamp>,
    /// The `ETag` and `Last-Modified` of the final response, stored so a stale
    /// entry can be revalidated. Empty for a pushed or pinned answer.
    pub validators: Validators,
    /// Whether the origin confirmed the content a [`Revalidation`] offered
    /// still current, so nothing was downloaded.
    pub revalidated: bool,
}

impl FetchOutcome {
    /// An outcome with no freshness information, validators or expiry.
    #[must_use]
    pub const fn new(uri: String, digest: DigestInfo) -> Self {
        Self {
            uri,
            digest,
            freshness: None,
            expire_at: None,
            validators: Validators {
                etag: None,
                last_modified: None,
            },
            revalidated: false,
        }
    }
}

/// Fetches blobs and directories from URIs into a CAS.
///
/// A returned `Err` carries a meaningful gRPC [`Code`](nativelink_error::Code)
/// (e.g. `Aborted` on checksum mismatch, `DeadlineExceeded` on timeout,
/// `NotFound` when no URI served the content) so callers can map it onto a
/// `FetchResponse.status`.
#[async_trait]
pub trait Fetcher: core::fmt::Debug + Send + Sync + 'static {
    /// Fetches a blob, returning its CAS digest and the URI that served it.
    async fn fetch_blob(&self, job: &FetchBlobTask) -> Result<FetchOutcome, Error>;

    /// Fetches and expands a directory archive, returning the root `Directory`
    /// digest and the URI that served it.
    async fn fetch_directory(&self, job: &FetchDirectoryJob) -> Result<FetchOutcome, Error>;
}
