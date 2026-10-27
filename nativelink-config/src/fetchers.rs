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

#[cfg(feature = "dev-schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::serde_utils::{
    convert_optional_numeric_with_shellexpand, convert_optional_string_with_shellexpand,
    convert_string_with_shellexpand,
};
use crate::stores::StoreRefName;

/// Name of a fetcher. Used to reference a fetcher defined in the
/// `CasConfig::fetchers` list, either from a `FetchConfig` or from another
/// fetcher that wraps it (e.g. `Background` wrapping `Url`).
pub type FetcherRefName = String;

/// A composable fetcher. Fetchers form a chain via name references: a leaf
/// [`FetcherSpec::Url`] does the real HTTP work, and decorators
/// ([`FetcherSpec::MetadataCache`], [`FetcherSpec::Background`]) wrap an inner
/// fetcher referenced by name. A production config typically composes
/// `Background -> MetadataCache -> Url` so that the metadata write happens
/// inside the background unit of work that joins identical fetches.
///
/// Referenced fetchers must be defined earlier in the `fetchers` list than the
/// fetchers that reference them.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "dev-schema", derive(JsonSchema))]
pub enum FetcherSpec {
    /// Downloads content over HTTP or HTTPS and uploads it to a CAS store.
    Url(UrlFetcherSpec),
    /// Writes fetched-asset metadata into an Action Cache store on success.
    MetadataCache(MetadataCacheSpec),
    /// Joins identical in-flight fetches and keeps them running past a
    /// client's RPC deadline.
    Background(BackgroundSpec),
}

/// The leaf fetcher: performs the HTTP or HTTPS download and CAS upload.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "dev-schema", derive(JsonSchema))]
pub struct UrlFetcherSpec {
    /// The CAS store (from the `stores` map) downloaded content is written to.
    #[serde(deserialize_with = "convert_string_with_shellexpand")]
    pub cas_store: StoreRefName,

    /// Directory in which downloaded content is buffered to a temporary file
    /// before being moved into `cas_store`. For the fast (move-without-copy)
    /// upload path to a filesystem-backed `cas_store` this should be on the same
    /// block device as that store's `content_path`; otherwise the upload falls
    /// back to a streaming copy. When unset, the system temporary directory is
    /// used.
    #[serde(default, deserialize_with = "convert_optional_string_with_shellexpand")]
    pub temp_path: Option<String>,

    /// Maximum size, in bytes, of content downloaded from a single URI. A
    /// download whose `Content-Length` exceeds this is rejected up front, and
    /// one that streams more than this many bytes (including when the server
    /// omits or misreports `Content-Length`) is aborted. The URI is then treated
    /// as failed and the next one is tried; if none succeed the request fails
    /// with `RESOURCE_EXHAUSTED`. When unset, downloads are unbounded.
    #[serde(
        default,
        deserialize_with = "convert_optional_numeric_with_shellexpand"
    )]
    pub max_size_bytes: Option<u64>,
}

/// A decorator that caches fetched-asset metadata.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "dev-schema", derive(JsonSchema))]
pub struct MetadataCacheSpec {
    /// The Action Cache store (from the `stores` map) the fetched asset's
    /// URI+qualifiers -> digest mapping is written to, as an `ActionResult`.
    /// For lookups to hit, this should be the same store named by the
    /// `FetchConfig::fetch_store` of any service using this fetcher, or one
    /// backed by the same data. It may be a `grpc` store, to record metadata in
    /// a central cluster.
    #[serde(deserialize_with = "convert_string_with_shellexpand")]
    pub fetch_store: StoreRefName,

    /// The inner fetcher (from the `fetchers` list) this decorates.
    #[serde(deserialize_with = "convert_string_with_shellexpand")]
    pub fetcher: FetcherRefName,
}

/// A decorator providing in-flight deduplication and background continuation.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "dev-schema", derive(JsonSchema))]
pub struct BackgroundSpec {
    /// The inner fetcher (from the `fetchers` list) this decorates.
    #[serde(deserialize_with = "convert_string_with_shellexpand")]
    pub fetcher: FetcherRefName,

    /// Maximum number of inner fetches running at once. When unset, the number
    /// of concurrent fetches is unbounded.
    #[serde(
        default,
        deserialize_with = "convert_optional_numeric_with_shellexpand"
    )]
    pub max_concurrent_fetches: Option<usize>,

    /// Lower bound (in seconds) applied to a request's `timeout` before it is
    /// passed to the inner fetcher. Only applies when the request sets a
    /// timeout. When unset, no lower bound is enforced.
    #[serde(
        default,
        deserialize_with = "convert_optional_numeric_with_shellexpand"
    )]
    pub min_timeout_s: Option<u64>,

    /// Upper bound (in seconds) applied to a request's `timeout` before it is
    /// passed to the inner fetcher. Only applies when the request sets a
    /// timeout. When unset, no upper bound is enforced.
    #[serde(
        default,
        deserialize_with = "convert_optional_numeric_with_shellexpand"
    )]
    pub max_timeout_s: Option<u64>,
}
