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

use std::collections::HashMap;

#[cfg(feature = "dev-schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::serde_utils::{
    convert_boolean_with_shellexpand, convert_numeric_with_shellexpand,
    convert_optional_numeric_with_shellexpand, convert_optional_string_with_shellexpand,
    convert_string_with_shellexpand, convert_vec_string_with_shellexpand,
};
use crate::stores::StoreRefName;

/// Default for [`UrlFetcherSpec::max_size_bytes`]: 256 GiB. Generous on
/// purpose: it is there to stop an origin streaming forever, not to judge what
/// a reasonable asset is.
pub const DEFAULT_MAX_SIZE_BYTES: u64 = 256 * 1024 * 1024 * 1024;

/// Default for [`UrlFetcherSpec::max_archive_entries`]: four million, well
/// above any real source archive while keeping the in-memory listing of one
/// archive to hundreds of megabytes.
pub const DEFAULT_MAX_ARCHIVE_ENTRIES: usize = 4_000_000;

/// Default for [`UrlFetcherSpec::max_archive_uncompressed_bytes`]: 1 TiB.
pub const DEFAULT_MAX_ARCHIVE_UNCOMPRESSED_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

/// Default for [`CacheSpec::max_concurrent_fetches`].
pub const DEFAULT_MAX_CONCURRENT_FETCHES: usize = 64;

/// Name of a fetcher. Used to reference a fetcher defined in the
/// `CasConfig::fetchers` list, either from a `FetchConfig` or from another
/// fetcher that wraps it (e.g. `Cache` wrapping `Url`).
pub type FetcherRefName = String;

/// A composable fetcher. Fetchers form a chain via name references. A `Fetch`
/// service names a [`FetcherSpec::Cache`], which runs the rest of the chain in
/// the background and records what it fetches. Below it, the fetchers that
/// get content: [`FetcherSpec::Url`] downloads over HTTP,
/// [`FetcherSpec::Static`] serves content written in the config,
/// [`FetcherSpec::Route`] picks between fetchers by host, port and path, and
/// [`FetcherSpec::ActionVerify`] verifies the directory a fetcher below it
/// fetched. `ActionVerify` goes below `Cache`, so that a directory failing
/// verification is never recorded.
///
/// Referenced fetchers must be defined earlier in the `fetchers` list than the
/// fetchers that reference them.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "dev-schema", derive(JsonSchema))]
pub enum FetcherSpec {
    /// Downloads content over HTTP or HTTPS and uploads it to a CAS store.
    Url(UrlFetcherSpec),
    /// Runs a fetcher in the background, joining identical in-flight pinned
    /// fetches, and records what it fetches in an Action Cache store.
    Cache(CacheSpec),
    /// Verifies fetched directories by running the action a request names in
    /// its `checksum.action_digest` qualifier.
    ActionVerify(ActionVerifySpec),
    /// Sends each URI to a fetcher chosen by its host, scheme, port and path.
    /// Without `otherwise`, any other URI is refused: an allowlist.
    Route(RouteSpec),
    /// Serves a fixed set of URIs from content written in the config, with no
    /// network access. For tests, demos and trying out the fetcher chain.
    Static(StaticSpec),
}

/// A leaf fetcher that serves the URIs listed in `content`, with the text
/// given for each as its body, and fails every other URI with `NotFound`,
/// as a `url` fetcher does for a URI the origin does not have. It honours
/// the request's checksums (a mismatch is `Aborted`) and tries URIs in the
/// order the request lists them. It serves blobs only: `FetchDirectory`
/// fails with `Unimplemented`.
///
/// It is meant for tests, demos and diagrams, where running an origin is
/// more trouble than the thing being tried. It is not a way to serve
/// content to builds.
#[derive(Deserialize, Serialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "dev-schema", derive(JsonSchema))]
pub struct StaticSpec {
    /// The CAS store (from the `stores` map) the content is written to.
    #[serde(deserialize_with = "convert_string_with_shellexpand")]
    pub cas_store: StoreRefName,

    /// The URIs this fetcher serves, each with the exact text it serves for
    /// it. A URI is matched as a whole string, as written in the request.
    /// Not expanded for `${VAR}` references, so any text can be written.
    #[serde(default)]
    pub content: HashMap<String, String>,
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
    /// with `RESOURCE_EXHAUSTED`. For a directory fetch this limits the size of
    /// the (compressed) archive. Set it to 0 for no limit.
    ///
    /// Default: 274877906944 (256 GiB)
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
    /// does not get past it. Set it to 0 for no limit.
    ///
    /// Default: 4000000
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
    /// `max_archive_entries`. The compression ratio itself is not limited. Set
    /// it to 0 for no limit.
    ///
    /// Default: 1099511627776 (1 TiB)
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
    /// `max_timeout_s` clamp of a `cache` fetcher) and this value, so a
    /// request with a larger `timeout`, or none at all, is still capped, and a
    /// slow origin cannot hold a fetch (or a `cache` fetcher's concurrency
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

    /// Non-public IP ranges this fetcher may connect to, in CIDR notation
    /// (`"10.20.0.0/16"`, `"fd00:1234::/32"`) or as single addresses.
    ///
    /// Anyone who can call `Fetch` chooses the URL, and the content ends up in
    /// the CAS where they can read it, so by default the fetcher refuses every
    /// address that is not on the public internet: loopback, private networks
    /// (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`),
    /// link-local (`169.254.0.0/16`, where cloud metadata services answer, and
    /// `fe80::/10`), shared address space (`100.64.0.0/10`), multicast, and
    /// the reserved and documentation ranges. An IPv6 address that embeds an
    /// IPv4 one (`::ffff:a.b.c.d`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) is
    /// judged by the IPv4 address. Ranges listed here are let through.
    /// `["0.0.0.0/0", "::/0"]` turns the check off.
    ///
    /// Host names are checked on the addresses they resolve to, at connection
    /// time, so a name that resolves to a refused address is refused, however
    /// it was reached (directly, by redirect, or after its DNS answer changed).
    /// If a name resolves to some refused addresses and some allowed ones,
    /// only the allowed ones are tried. URLs with an IP address as their host
    /// are checked as given, including on every redirect. A refused fetch
    /// fails that URI with `PERMISSION_DENIED`.
    ///
    /// With a proxy, origins reached through it are resolved and connected to
    /// by the proxy, not by this server, so only IP-address URLs are checked
    /// for them: the proxy has to enforce what may be reached. The proxy
    /// itself is always allowed, whatever its address. Hosts in `no_proxy`
    /// are connected to directly and checked as usual.
    ///
    /// Default: empty (no non-public address is allowed)
    #[serde(default, deserialize_with = "convert_vec_string_with_shellexpand")]
    pub allowed_ip_ranges: Vec<String>,

    /// Refuse to download content that the request gives no checksum for. A
    /// blob request needs a `checksum.sri` or a hex `checksum.sha*` qualifier. A
    /// directory request needs a checksum of any kind: those, a tree hash such
    /// as `checksum.h1`, or a `checksum.action_digest` verified by an
    /// `action_verify` fetcher. A request without one fails with
    /// `INVALID_ARGUMENT` before any origin is contacted. Use it so that nothing
    /// unverified is ever fetched into the CAS.
    ///
    /// The check is part of fetching, so it applies only when content would be
    /// downloaded. A request that finds an asset already pushed with
    /// `Push*`, or fetched earlier and recorded in the fetch store, is answered
    /// from it whether or not the request has a checksum, because nothing is
    /// downloaded. Defaults to false.
    #[serde(default, deserialize_with = "convert_boolean_with_shellexpand")]
    pub require_checksum: bool,
}

/// Default for [`CacheSpec::unpinned_default_ttl_s`]: one day.
const fn default_unpinned_default_ttl_s() -> u64 {
    24 * 60 * 60
}

/// Default for [`CacheSpec::unpinned_min_ttl_s`]: five minutes.
const fn default_unpinned_min_ttl_s() -> u64 {
    5 * 60
}

/// Default for [`CacheSpec::unpinned_max_ttl_s`]: 30 days.
const fn default_unpinned_max_ttl_s() -> u64 {
    30 * 24 * 60 * 60
}

/// The fetcher a `Fetch` service names: it runs the fetcher below it in the
/// background and records what that fetcher fetches, so that the next `Fetch`
/// for the same asset is answered without downloading it again.
///
/// Background: identical pinned requests (ones that carry a checksum) share
/// one fetch; an unpinned request always runs its own, since it accepts only
/// what the origin serves now. A fetch keeps running after its client gives up,
/// so a retry of a pinned request joins it, or finds it recorded. A shared
/// fetch runs until the latest of its requests' timeouts (after
/// `min_timeout_s` and `max_timeout_s`), each counted from when its request
/// started or joined the fetch, so a request with a short timeout does not cut
/// it short for one with a longer timeout. Each request still gets
/// `DEADLINE_EXCEEDED` once its own timeout has passed with the download under
/// way. Time spent waiting for one of `max_concurrent_fetches` does not count
/// against a timeout; only the RPC deadline bounds it.
///
/// Recording: an entry for a *pinned* request, one with any checksum
/// qualifier (`checksum.sri`, `checksum.sha256`, `checksum.action_digest`, a
/// tree checksum such as `checksum.nar` or `checksum.git_tree`, ...), never
/// expires: its content cannot legitimately change. An entry for an
/// *unpinned* request, one with no checksum, takes whatever the origin served,
/// which can change, so it expires. Its lifetime is what the origin's HTTP
/// caching headers say, as a shared cache reads them (`s-maxage`, else
/// `max-age`, else `Expires` less `Date`, less `Age`), or
/// `unpinned_default_ttl_s` when they say nothing, then limited to between
/// `unpinned_min_ttl_s` and `unpinned_max_ttl_s`. `no-store`, `no-cache` and
/// `private` make the entry stale at once: it is still written, since its
/// content is in the CAS, but a later `Fetch` goes back to the origin. A
/// client's `oldest_content_accepted` applies as well as the expiry.
///
/// When an unpinned entry is stale and the origin gave an `ETag` or
/// `Last-Modified` with it, the `Fetch` service asks the origin whether the
/// content is still current (`If-None-Match`, `If-Modified-Since`) instead of
/// downloading it again. On `304 Not Modified` the entry is stored again with a
/// new expiry and no download happens.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "dev-schema", derive(JsonSchema))]
pub struct CacheSpec {
    /// The fetcher (from the `fetchers` list) that does the fetching: a
    /// `url`, `static`, `route` or `action_verify`.
    #[serde(deserialize_with = "convert_string_with_shellexpand")]
    pub fetcher: FetcherRefName,

    /// The Action Cache store (from the `stores` map) the fetched asset's
    /// URI+qualifiers -> digest mapping is written to, as an `ActionResult`.
    /// For lookups to hit, this should be the same store named by the
    /// `FetchConfig::fetch_store` of any service using this fetcher, or one
    /// backed by the same data. It may be a `grpc` store, to record metadata in
    /// a central cluster.
    #[serde(deserialize_with = "convert_string_with_shellexpand")]
    pub fetch_store: StoreRefName,

    /// The CAS store (from the `stores` map) the fetched content lives in; the
    /// `cas_store` of the fetchers below this one. For a directory it is read
    /// to build the `Tree` stored with the metadata.
    #[serde(deserialize_with = "convert_string_with_shellexpand")]
    pub cas_store: StoreRefName,

    /// Maximum number of fetches running at once. A request that would start
    /// another waits for a slot, and stops waiting if its client goes away;
    /// only a fetch that has a slot carries on in the background. Set it to 0
    /// for no limit.
    ///
    /// Default: 64
    #[serde(
        default,
        deserialize_with = "convert_optional_numeric_with_shellexpand"
    )]
    pub max_concurrent_fetches: Option<usize>,

    /// Lower bound (in seconds) applied to a request's `timeout`, the total
    /// time budget for the whole fetch, before it is passed to `fetcher`.
    /// Only applies when the request sets a timeout; a request without one
    /// stays without one, and is then bounded only by the URL fetcher's
    /// `max_fetch_duration_s`. When unset, no lower bound is enforced.
    #[serde(
        default,
        deserialize_with = "convert_optional_numeric_with_shellexpand"
    )]
    pub min_timeout_s: Option<u64>,

    /// Upper bound (in seconds) applied to a request's `timeout`, the total
    /// time budget for the whole fetch, before it is passed to `fetcher`.
    /// Only applies when the request sets a timeout. When unset, no upper
    /// bound is enforced (the URL fetcher's `max_fetch_duration_s` still is).
    #[serde(
        default,
        deserialize_with = "convert_optional_numeric_with_shellexpand"
    )]
    pub max_timeout_s: Option<u64>,

    /// Seconds an unpinned entry stays fresh when the origin's response says
    /// nothing about caching (no `Cache-Control` freshness directive and no
    /// `Expires`). Limited to `unpinned_min_ttl_s` and `unpinned_max_ttl_s`.
    /// Pinned entries do not expire and ignore this.
    ///
    /// Default: 86400 (one day)
    #[serde(
        default = "default_unpinned_default_ttl_s",
        deserialize_with = "convert_numeric_with_shellexpand"
    )]
    pub unpinned_default_ttl_s: u64,

    /// Shortest freshness, in seconds, given to an unpinned entry. An origin
    /// that says `max-age=10` gets this much instead, so a busy asset is not
    /// fetched again and again. It does not apply to a response that must not be
    /// reused (`no-store`, `no-cache`, `private`, or `max-age=0`), which is
    /// stale at once. Must not be more than `unpinned_max_ttl_s`.
    ///
    /// Default: 300 (five minutes)
    #[serde(
        default = "default_unpinned_min_ttl_s",
        deserialize_with = "convert_numeric_with_shellexpand"
    )]
    pub unpinned_min_ttl_s: u64,

    /// Longest freshness, in seconds, given to an unpinned entry. An origin
    /// that says `max-age=31536000` gets this much instead, so a URL whose
    /// content changes is looked at again within this time whatever it claims.
    ///
    /// Default: 2592000 (30 days)
    #[serde(
        default = "default_unpinned_max_ttl_s",
        deserialize_with = "convert_numeric_with_shellexpand"
    )]
    pub unpinned_max_ttl_s: u64,
}

/// A decorator that verifies a fetched directory by running an action against
/// it, for requests with a `checksum.action_digest` qualifier. The qualifier
/// names an `Action` the client uploaded to the CAS, with its `Command` and
/// input root. That action is run through `scheduler` with the fetched
/// directory in its input root: at the relative path given by the command's
/// `NATIVELINK_FETCHED_DIRECTORY` environment variable, or as the whole input
/// root when the variable is not set, in which case the uploaded input root
/// must be empty.
///
/// The command's exit code says what happened. Exit code 0 means the
/// directory is verified. Exit code 1 means its content does not match: the
/// next URI is tried, and the request fails with `ABORTED` if none verifies.
/// Any other exit code (127 for a missing tool, a crash, an out-of-memory kill,
/// death by signal) means the checker itself failed: the request fails at once
/// with `INTERNAL`, with the exit code and the start of stderr in the message,
/// and no further URI is tried.
///
/// Warning: enabling this fetcher lets anyone who can call `Fetch` run
/// arbitrary commands on the workers. The action is uploaded by the caller, so
/// its command is the caller's, and it runs under `instance_name`, not under
/// the instance the `Fetch` call named. Set `instance_name` to an instance in
/// the same trust domain as the `Fetch` clients: one whose Action Cache and
/// workers no wider a set of clients can write to or reach. No inbound request
/// is authenticated, so a network boundary has to be that domain.
///
/// Requests without the qualifier pass straight through. A request with it
/// that reaches a `url` fetcher without passing an `action_verify` fails.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "dev-schema", derive(JsonSchema))]
pub struct ActionVerifySpec {
    /// The inner fetcher (from the `fetchers` list) this decorates.
    #[serde(deserialize_with = "convert_string_with_shellexpand")]
    pub fetcher: FetcherRefName,

    /// The CAS store (from the `stores` map) the uploaded action is read from
    /// and the action that is run is written to. It must hold the fetched
    /// content, and the scheduler's workers must read from it.
    #[serde(deserialize_with = "convert_string_with_shellexpand")]
    pub cas_store: StoreRefName,

    /// The scheduler (from the `schedulers` list) that runs the action, in
    /// this process.
    #[serde(deserialize_with = "convert_string_with_shellexpand")]
    pub scheduler: String,

    /// The instance name the action runs under. Default: "".
    #[serde(default, deserialize_with = "convert_string_with_shellexpand")]
    pub instance_name: String,
}

/// A fetcher that sends each URI to another fetcher, chosen by the URI's host
/// and, optionally, its scheme, port and path. Use it to send some hosts
/// through a proxy and others directly, to let a `url` fetcher with internal
/// `allowed_ip_ranges` reach only the internal hosts (and ports) it is meant
/// for, or, leaving out `otherwise`, to fetch only from listed hosts or only
/// from listed paths on them, such as one organization's repositories.
///
/// Each URI goes to the fetcher of the first route that matches it, and to
/// `otherwise` if none does. Routes are tried in the order written, not by
/// how specific they are, so put a narrower route before a broader one to
/// the same host. When there is no `otherwise`, a URI that matches no route
/// is not fetched, and a request whose URIs all match none fails with
/// `PERMISSION_DENIED`, the Remote Asset API's code for an asset from a
/// disallowed origin. Pushed assets and cached fetches are served whatever
/// their URI: routing only decides what is downloaded.
///
/// A request lists mirrors of one asset. They are grouped by the fetcher they
/// go to, and each group is fetched as a request of its own, with its URIs in
/// their original order; the groups are tried in the order of their first
/// URI, until one produces the asset. The request's `timeout` covers all of
/// them. A request whose URIs all go to one fetcher, the usual case, is
/// passed on unchanged.
///
/// Routing matches the URI as the request names it, before any redirect: a
/// route to a `url` fetcher allows whatever that URI redirects to, on any
/// host or path. Redirect targets are still subject to the `url` fetcher's
/// `allowed_ip_ranges`, and are never followed from `https` to `http`.
///
/// Routes grant: a URI that a route misses goes to the next route or to
/// `otherwise`. So use a route to send URIs to a fetcher that may do more,
/// not to one that may do less, since a URI written to miss it (other case,
/// other encoding) falls through to the rest.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "dev-schema", derive(JsonSchema))]
pub struct RouteSpec {
    /// The routes, tried in order: a URI goes to the first that matches it.
    pub routes: Vec<FetchRouteSpec>,

    /// The fetcher (from the `fetchers` list) for URIs that match no route.
    /// When unset, those URIs are refused.
    #[serde(default, deserialize_with = "convert_optional_string_with_shellexpand")]
    pub otherwise: Option<FetcherRefName>,
}

/// One route of a [`RouteSpec`]. A URI matches it when its host matches one
/// of `hosts`, and its scheme, port and path each match one entry of
/// `schemes`, `ports` and `path_prefixes`. To match one combination or
/// another, write two routes to the same fetcher.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "dev-schema", derive(JsonSchema))]
pub struct FetchRouteSpec {
    /// The hosts this route takes. Each is a host name, matched exactly and
    /// ignoring case (`"github.com"` matches `github.com` but not
    /// `api.github.com`); `*.` and a host name, matching every subdomain of it
    /// but not the name itself (`"*.githubusercontent.com"`); or an IP
    /// address, matched exactly. No scheme, port or path. Must not be empty.
    #[serde(deserialize_with = "convert_vec_string_with_shellexpand")]
    pub hosts: Vec<String>,

    /// The schemes this route takes: `"http"`, `"https"` or both.
    /// Default: both.
    #[serde(default, deserialize_with = "convert_vec_string_with_shellexpand")]
    pub schemes: Vec<String>,

    /// The ports this route takes. Without it, a route takes only the
    /// scheme's own port (443 for `https`, 80 for `http`), so that a route to
    /// a host does not also reach the other services on it. Listing ports
    /// replaces that: `[443, 8443]` takes both, `[8443]` only `8443`.
    /// Default: the scheme's own port.
    #[serde(default)]
    pub ports: Vec<u16>,

    /// The paths this route takes, each a prefix matched by whole segments
    /// and case-sensitively: `"/bazelbuild"` (or `"/bazelbuild/"`) matches
    /// `/bazelbuild/rules_go/archive/v1.tar.gz` but not `/bazelbuild-evil/x`
    /// or `/BazelBuild/x`. Write each as a URL has it, percent-encoded
    /// (`"/my%20org"`), without dot segments, query or fragment. URIs are
    /// matched after resolving dot segments, so `/bazelbuild/../evil` is
    /// `/evil`, and a URI whose path a server could still resolve outside the
    /// prefix matches none: one with an encoded `/` or `\` (`..%2F`), a dot
    /// segment with a `;` parameter appended, or a double-encoded `%`.
    /// Default: every path.
    #[serde(default, deserialize_with = "convert_vec_string_with_shellexpand")]
    pub path_prefixes: Vec<String>,

    /// The fetcher (from the `fetchers` list) this route sends its URIs to.
    #[serde(deserialize_with = "convert_string_with_shellexpand")]
    pub fetcher: FetcherRefName,
}
