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
    convert_boolean_with_shellexpand, convert_optional_numeric_with_shellexpand,
    convert_optional_string_with_shellexpand, convert_string_with_shellexpand,
    convert_vec_string_with_shellexpand,
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
#[derive(Deserialize, Serialize, Debug, Clone, Default)]
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
    ///
    /// Directory (archive) fetches also use it, for files in the archive larger
    /// than `archive_entry_inline_threshold_bytes` and, for zip archives, for a
    /// copy of the archive kept while it downloads.
    #[serde(default, deserialize_with = "convert_optional_string_with_shellexpand")]
    pub temp_path: Option<String>,

    /// Maximum size, in bytes, of content downloaded from a single URI. A
    /// download whose `Content-Length` exceeds this is rejected up front, and
    /// one that streams more than this many bytes (including when the server
    /// omits or misreports `Content-Length`) is aborted. The URI is then treated
    /// as failed and the next one is tried; if none succeed the request fails
    /// with `RESOURCE_EXHAUSTED`. When unset, downloads are unbounded. For a
    /// directory fetch this limits the size of the (compressed) archive.
    #[serde(
        default,
        deserialize_with = "convert_optional_numeric_with_shellexpand"
    )]
    pub max_size_bytes: Option<u64>,

    /// Directory fetches expand an archive (zip, tar or tar.gz) as it downloads,
    /// uploading each file to the CAS as soon as it has been read. A file needs
    /// its digest before it can be uploaded, so it is first held either in
    /// memory or in a temporary file in `temp_path`. Files up to this many bytes
    /// are held in memory; larger files go through a temporary file. Raising it
    /// trades memory for fewer temporary files, lowering it does the reverse.
    /// Defaults to 1 MiB.
    #[serde(
        default,
        deserialize_with = "convert_optional_numeric_with_shellexpand"
    )]
    pub archive_entry_inline_threshold_bytes: Option<u64>,

    /// Maximum number of entries (files, directories and links) in an archive
    /// fetched by a directory fetch. An archive with more is aborted as it is
    /// read; the URI is then treated as failed and the next one is tried, and if
    /// none succeed the request fails with `RESOURCE_EXHAUSTED`. Counted as the
    /// archive is read rather than taken from any header, so a lying archive
    /// does not get past it. When unset, the number of entries is unbounded.
    #[serde(
        default,
        deserialize_with = "convert_optional_numeric_with_shellexpand"
    )]
    pub max_archive_entries: Option<usize>,

    /// Maximum total size, in bytes, of the decompressed file contents of an
    /// archive fetched by a directory fetch. Unlike `max_size_bytes`, which caps
    /// the compressed download, this guards against decompression bombs: a tiny
    /// archive that expands to a huge amount of data. It is counted on the bytes
    /// actually decompressed, never on sizes declared in the archive, so lying
    /// headers do not get past it. Exceeding it fails the URI as for
    /// `max_archive_entries`. When unset, the expanded size is unbounded.
    #[serde(
        default,
        deserialize_with = "convert_optional_numeric_with_shellexpand"
    )]
    pub max_archive_uncompressed_bytes: Option<u64>,

    /// Hard cap, in seconds, on the total duration of a single fetch: every
    /// URI attempt, the download, archive expansion, checksum verification and
    /// the CAS upload together. A fetch that runs out of time fails with
    /// `DEADLINE_EXCEEDED` in the response status, whatever else is going on.
    ///
    /// A request's own `timeout` can only shorten this. The effective budget is
    /// the smaller of the request's `timeout` (after any `min_timeout_s` and
    /// `max_timeout_s` clamp of a `background` fetcher) and this value, so a
    /// request with a larger `timeout`, or none at all, is still capped, and a
    /// slow origin cannot hold a fetch (or a `background` fetcher's concurrency
    /// slot) forever. It applies whether or not a client is still waiting for
    /// the result.
    ///
    /// The per-connection connect and idle-read timeouts (30 seconds each)
    /// always apply as well. Defaults to 3600 (one hour) when unset.
    #[serde(
        default,
        deserialize_with = "convert_optional_numeric_with_shellexpand"
    )]
    pub max_fetch_duration_s: Option<u64>,

    /// URL of an HTTP forward proxy to fetch through, for both `http://` and
    /// `https://` origins (HTTPS origins are reached with a `CONNECT` tunnel),
    /// such as `"http://proxy.internal:3128"`. May carry credentials
    /// (`"http://user:password@proxy.internal:3128"`), but a secret is better
    /// kept out of the config file: read it from the environment with
    /// `"${FETCH_PROXY_URL}"`, or use `http_proxy_secret_file`. The scheme must
    /// be `http` or `https` and the URL must name a host. A bad URL stops the
    /// server at startup, with an error that does not repeat the URL.
    ///
    /// Every request goes through the proxy except those to hosts matching
    /// `no_proxy`; there is no fallback to a direct connection if the proxy
    /// fails.
    ///
    /// Proxying comes only from this configuration. The fetcher ignores the
    /// `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` environment
    /// variables of the server process, which an earlier release honoured
    /// implicitly: a deployment that relied on them must now set `http_proxy`
    /// and `no_proxy` here. Setting both this and `http_proxy_secret_file` is
    /// an error. When neither is set, all fetches connect directly.
    #[serde(default, deserialize_with = "convert_optional_string_with_shellexpand")]
    pub http_proxy: Option<String>,

    /// Path to a file containing the proxy URL described under `http_proxy`,
    /// for a URL with credentials that should not be in the config file, such as
    /// a mounted Kubernetes secret. Leading and trailing whitespace, including
    /// the final newline, is removed. The file is read once at startup. Setting
    /// both this and `http_proxy` is an error.
    #[serde(default, deserialize_with = "convert_optional_string_with_shellexpand")]
    pub http_proxy_secret_file: Option<String>,

    /// Hosts that bypass the proxy and are fetched from directly. Each entry
    /// is a domain name, which matches that domain and all its subdomains
    /// (`"internal.example.com"` and `".internal.example.com"` are equivalent),
    /// an IP address, or an IP range in CIDR notation (`"10.0.0.0/8"`); `"*"`
    /// matches every host. This is the matching of the `NO_PROXY` environment
    /// variable as implemented by `reqwest`. Only has an effect when a proxy is
    /// configured. Defaults to empty, bypassing no host.
    #[serde(default, deserialize_with = "convert_vec_string_with_shellexpand")]
    pub no_proxy: Vec<String>,

    /// Refuse to download content that the request gives no checksum for: a
    /// blob request needs a `checksum.sri` qualifier, and a directory request
    /// that or a tree hash such as `checksum.h1`. A request without one fails
    /// with `INVALID_ARGUMENT` before any origin is contacted. Use it so that
    /// nothing unverified is ever fetched into the CAS.
    ///
    /// The check is part of fetching, so it applies only when content would be
    /// downloaded. A request that finds an asset already pushed with
    /// `Push*`, or fetched earlier and recorded in the fetch store, is answered
    /// from it whether or not the request has a checksum, because nothing is
    /// downloaded. Defaults to false.
    #[serde(default, deserialize_with = "convert_boolean_with_shellexpand")]
    pub require_checksum: bool,
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

    /// The CAS store (from the `stores` map) the fetched content lives in; the
    /// `cas_store` of the inner `url` fetcher. For a directory it is read to
    /// build the `Tree` stored with the metadata.
    #[serde(deserialize_with = "convert_string_with_shellexpand")]
    pub cas_store: StoreRefName,

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

    /// Lower bound (in seconds) applied to a request's `timeout`, the total
    /// time budget for the whole fetch, before it is passed to the inner
    /// fetcher. Only applies when the request sets a timeout; a request
    /// without one stays without one, and is then bounded only by the URL
    /// fetcher's `max_fetch_duration_s`. When unset, no lower bound is
    /// enforced.
    #[serde(
        default,
        deserialize_with = "convert_optional_numeric_with_shellexpand"
    )]
    pub min_timeout_s: Option<u64>,

    /// Upper bound (in seconds) applied to a request's `timeout`, the total
    /// time budget for the whole fetch, before it is passed to the inner
    /// fetcher. Only applies when the request sets a timeout. When unset, no
    /// upper bound is enforced (the URL fetcher's `max_fetch_duration_s` still
    /// is).
    #[serde(
        default,
        deserialize_with = "convert_optional_numeric_with_shellexpand"
    )]
    pub max_timeout_s: Option<u64>,
}
