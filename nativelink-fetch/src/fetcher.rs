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

use nativelink_error::{Error, make_input_err};
use nativelink_proto::build::bazel::remote::asset::v1::Qualifier;
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::DigestHasherFunc;
use nativelink_util::sri::ByteChecksum;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use tonic::async_trait;

use crate::remote_asset_proto::{QUALIFIER_HTTP_HEADER_PREFIX, QUALIFIER_HTTP_HEADER_URL_PREFIX};
use crate::tree_hash::TreeChecksum;

/// A checksum used to verify a downloaded directory archive: either of the
/// raw archive bytes, or of the expanded files.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DirectoryChecksum {
    /// A hash of the raw archive bytes: the `checksum.sri` qualifier or one of
    /// the hex `checksum.sha*` qualifiers.
    Bytes(ByteChecksum),
    /// A hash of the expanded tree in one of the [`crate::tree_hash`] formats.
    Tree(TreeChecksum),
}

/// HTTP headers a request asks the fetcher to send to the origin, parsed from
/// its `http_header:<name>` and `http_header_url:<idx>:<name>` qualifiers (the
/// convention Bazel's remote downloader uses). They are request parameters, not
/// part of the asset's identity: they are excluded from the metadata key and
/// the deduplication identity, never persisted, and marked sensitive so they
/// are redacted from `Debug` output (they are often credentials).
///
/// Header qualifiers must never be persisted, logged or made part of any
/// cache/dedup identity, because they typically carry auth credentials. A
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
}

/// A request to fetch a single blob from one of `uris`.
///
/// `Hash`/`Eq` (implemented manually) define the in-flight deduplication
/// identity used by [`crate::background_fetcher::BackgroundFetcher`]: the URIs,
/// the qualifiers (order-insensitive), the checksum and the hash function.
/// Per-request parameters such as `timeout` are deliberately excluded, so a
/// concurrent duplicate joins the in-flight fetch and runs with the first
/// requester's parameters (`timeout` and `headers`).
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
    /// HTTP headers to send to the origin. Not part of the deduplication
    /// identity.
    pub headers: FetchHeaders,
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
    /// The time budget for the whole job: every URI attempt, the download,
    /// archive expansion, verification and the CAS upload. Not part of the
    /// deduplication identity.
    pub timeout: Option<Duration>,
    /// HTTP headers to send to the origin. Not part of the deduplication
    /// identity.
    pub headers: FetchHeaders,
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
    }
}

impl Eq for FetchBlobTask {}

impl Hash for FetchBlobTask {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.uris.hash(state);
        sorted_qualifiers(&self.qualifiers).hash(state);
        self.checksums.hash(state);
        self.hasher_func.hash(state);
    }
}

impl PartialEq for FetchDirectoryJob {
    fn eq(&self, other: &Self) -> bool {
        self.uris == other.uris
            && sorted_qualifiers(&self.qualifiers) == sorted_qualifiers(&other.qualifiers)
            && self.checksums == other.checksums
            && self.hasher_func == other.hasher_func
    }
}

impl Eq for FetchDirectoryJob {}

impl Hash for FetchDirectoryJob {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.uris.hash(state);
        sorted_qualifiers(&self.qualifiers).hash(state);
        self.checksums.hash(state);

        self.hasher_func.hash(state);
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
