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

//! [`RouteFetcher`]: a [`Fetcher`] that sends each URI of a job to the fetcher
//! of the first [`Route`] matching it, on its host and, when the route says,
//! its scheme, port and path. Without an `otherwise` fetcher, a URI that
//! matches no route is refused, which makes the routes an allowlist.
//!
//! Routes are tried in order and the first match wins, rather than the most
//! specific route as in the Kubernetes Gateway API: an allowlist is easier to
//! audit when it reads top to bottom. A route matches the URL as the `url`
//! fetcher will request it, parsed (and its dot segments resolved) by the
//! same parser, before any redirect.
//!
//! A job's URIs are mirrors of one asset, so they are split by route. Given
//!
//! ```text
//! R1: github.com             -> backend 1
//! R2: artifacts.corp.example -> backend 2
//! no `otherwise`
//! ```
//!
//! a job
//!
//! ```text
//! FetchBlob(uris = [github.com/abc, artifacts.corp.example/abc,
//!                   github.com/def, random.example.org/abc])
//! ```
//!
//! becomes two calls, in the order each backend's first URI appears:
//!
//! ```text
//! -> backend 1: FetchBlob(uris = [github.com/abc, github.com/def])
//! -> backend 2: FetchBlob(uris = [artifacts.corp.example/abc])
//! ```
//!
//! `random.example.org/abc` matches no route and is not tried. Each call keeps
//! its URIs' headers and original order, and gets what is left of the job's
//! timeout. The first call to produce the asset wins, so `github.com/def` is
//! tried before the corp mirror even though it was listed after it. A call
//! that fails as a failed URI would moves on to the next. A job whose URIs all
//! take one route, the usual case, is passed on as it is.

use core::fmt;
use core::net::IpAddr;
use core::str::FromStr;
use core::time::Duration;
use std::sync::Arc;

use futures::future::BoxFuture;
use nativelink_error::{Code, Error, make_err, make_input_err};
use tokio::time::Instant;
use tonic::async_trait;
use tracing::debug;

use crate::fetcher::{FetchBlobTask, FetchDirectoryJob, FetchOutcome, Fetcher};

/// A host a route matches: one host name or IP address exactly, or, written
/// `*.example.com`, every subdomain of `example.com` (but not `example.com`
/// itself).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPattern {
    /// Lowercased, without a trailing dot, and for an IPv6 address without
    /// brackets.
    host: String,
    subdomains: bool,
}

impl HostPattern {
    /// Whether the pattern matches `host`, normalized as [`uri_host`] does.
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        if self.subdomains {
            host.strip_suffix(self.host.as_str())
                .and_then(|prefix| prefix.strip_suffix('.'))
                .is_some_and(|prefix| !prefix.is_empty())
        } else {
            host == self.host
        }
    }
}

impl FromStr for HostPattern {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let pattern = s.trim().to_ascii_lowercase();
        let (subdomains, host) = match pattern.strip_prefix("*.") {
            Some(host) => (true, host),
            None => (false, pattern.as_str()),
        };
        let host = host.trim_end_matches('.');
        let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = unbracketed.parse::<IpAddr>() {
            if subdomains {
                return Err(make_input_err!(
                    "Host pattern '{s}': an IP address has no subdomains"
                ));
            }
            return Ok(Self {
                host: ip.to_string(),
                subdomains: false,
            });
        }
        let valid = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_');
        if !valid {
            return Err(make_input_err!(
                "Host pattern '{s}' must be a host name, an IP address, or '*.' followed by a \
                 host name, with no scheme, port or path"
            ));
        }
        Ok(Self {
            host: host.to_owned(),
            subdomains,
        })
    }
}

/// The host of `url`, normalized for matching against a [`HostPattern`]:
/// lowercased (and IDNA-encoded) by URL parsing, without a trailing dot, and
/// for an IPv6 address without brackets.
fn url_host(url: &reqwest::Url) -> Option<String> {
    let host = url.host_str()?;
    Some(
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_owned(),
    )
}

/// The host of `uri`, as [`url_host`] has it. `None` if `uri` does not parse
/// or has no host.
fn uri_host(uri: &str) -> Option<String> {
    url_host(&reqwest::Url::parse(uri).ok()?)
}

/// A URL scheme a route matches: one the `url` fetcher fetches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

impl FromStr for Scheme {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s.trim().to_ascii_lowercase().as_str() {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            _ => Err(make_input_err!(
                "Scheme '{s}' must be 'http' or 'https', with no '://'"
            )),
        }
    }
}

/// A path prefix a route matches, segment by segment: `/bazelbuild` matches
/// `/bazelbuild` and `/bazelbuild/rules_go/...` but not `/bazelbuild-evil`. A
/// trailing slash is ignored, and `/` matches every path.
///
/// Segments are compared as the URL writes them, percent-encoding and case
/// included, so `/%62azelbuild` does not match `/bazelbuild`: a mismatch only
/// ever refuses. A path a server could read as other segments (see
/// [`path_segments`]) matches no prefix at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathPrefix {
    /// Without the empty segment a trailing slash leaves.
    segments: Vec<String>,
}

impl PathPrefix {
    /// Whether the prefix matches a path split by [`path_segments`].
    fn matches(&self, path: &[&str]) -> bool {
        path.len() >= self.segments.len()
            && self
                .segments
                .iter()
                .zip(path)
                .all(|(prefix, segment)| prefix == segment)
    }
}

impl FromStr for PathPrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let prefix = s.trim();
        if !prefix.starts_with('/') {
            return Err(make_input_err!("Path prefix '{s}' must start with '/'"));
        }
        // Parse the prefix as a URL's path, so that it is written the way the
        // paths it is compared with are.
        let url = reqwest::Url::parse(&format!("http://route.invalid{prefix}"))
            .map_err(|e| make_input_err!("Path prefix '{s}' is not a URL path: {e}"))?;
        if url.query().is_some() || url.fragment().is_some() {
            return Err(make_input_err!(
                "Path prefix '{s}' must not have a query or a fragment"
            ));
        }
        if url.path() != prefix {
            return Err(make_input_err!(
                "Path prefix '{s}' must be written as a URL has it: '{}'",
                url.path()
            ));
        }
        let mut segments = path_segments(&url).ok_or_else(|| {
            make_input_err!(
                "Path prefix '{s}' must not encode '/', '\\' or '%', nor hold dot segments"
            )
        })?;
        if segments.last() == Some(&"") {
            segments.pop();
        }
        Ok(Self {
            segments: segments.into_iter().map(str::to_owned).collect(),
        })
    }
}

/// The segments of `url`'s path, as it is sent. `None` if a server could read
/// the path as other segments than these, and so step outside a
/// [`PathPrefix`] that matched it: when a segment holds a percent-encoded `/`
/// or `\` (`..%2F`), decodes to a dot segment once a `;` parameter is cut
/// (`..;`, which Tomcat resolves), or still holds a `%` once decoded, for a
/// server that decodes twice (`%252e%252e`). Dot segments written plainly or
/// as `%2e` are resolved by URL parsing, before this sees them.
fn path_segments(url: &reqwest::Url) -> Option<Vec<&str>> {
    let segments: Vec<&str> = url.path_segments()?.collect();
    segments
        .iter()
        .all(|segment| is_plain_segment(segment))
        .then_some(segments)
}

/// See [`path_segments`].
fn is_plain_segment(segment: &str) -> bool {
    let decoded = percent_decode(segment);
    if decoded.iter().any(|b| matches!(b, b'/' | b'\\' | b'%')) {
        return false;
    }
    let name = decoded.split(|&b| b == b';').next().unwrap_or_default();
    name != b"." && name != b".."
}

/// `s` with each `%` and two hex digits replaced by the byte they encode.
fn percent_decode(s: &str) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(s.len());
    let mut rest = s.as_bytes();
    while let Some((&first, tail)) = rest.split_first() {
        if first == b'%'
            && let [hi, lo, after @ ..] = tail
            && let (Some(hi), Some(lo)) = (hex_value(*hi), hex_value(*lo))
        {
            decoded.push(hi << 4 | lo);
            rest = after;
        } else {
            decoded.push(first);
            rest = tail;
        }
    }
    decoded
}

const fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// A URI as routes match it.
struct Target<'a> {
    url: &'a reqwest::Url,
    host: String,
    /// `None` when a server could read the path otherwise; see
    /// [`path_segments`].
    path: Option<Vec<&'a str>>,
}

impl<'a> Target<'a> {
    fn new(url: &'a reqwest::Url) -> Option<Self> {
        Some(Self {
            host: url_host(url)?,
            path: path_segments(url),
            url,
        })
    }
}

/// What a URI must be to take a route: its host matches one of `hosts`, and
/// its scheme, port and path each match an entry of `schemes`, `ports` and
/// `path_prefixes`.
#[derive(Debug)]
pub struct RouteMatch {
    pub hosts: Vec<HostPattern>,
    /// Empty matches any scheme.
    pub schemes: Vec<Scheme>,
    /// Empty matches only the scheme's default port. Otherwise the default
    /// port matches only if listed.
    pub ports: Vec<u16>,
    /// Empty matches any path.
    pub path_prefixes: Vec<PathPrefix>,
}

impl RouteMatch {
    /// A match for `hosts`, on any scheme, the default port and any path.
    #[must_use]
    pub const fn hosts(hosts: Vec<HostPattern>) -> Self {
        Self {
            hosts,
            schemes: Vec::new(),
            ports: Vec::new(),
            path_prefixes: Vec::new(),
        }
    }

    fn accepts(&self, target: &Target<'_>) -> bool {
        let url = target.url;
        let port_matches = if self.ports.is_empty() {
            // URL parsing drops a port that is the scheme's default.
            url.port().is_none()
        } else {
            url.port_or_known_default()
                .is_some_and(|port| self.ports.contains(&port))
        };
        self.hosts
            .iter()
            .any(|pattern| pattern.matches(&target.host))
            && (self.schemes.is_empty()
                || self
                    .schemes
                    .iter()
                    .any(|scheme| scheme.as_str() == url.scheme()))
            && port_matches
            && (self.path_prefixes.is_empty()
                || target.path.as_deref().is_some_and(|path| {
                    self.path_prefixes.iter().any(|prefix| prefix.matches(path))
                }))
    }
}

/// The fetcher the URIs `matches` accepts go to. Several routes can share a
/// fetcher, to take one combination or another.
#[derive(Debug)]
pub struct Route {
    pub matches: RouteMatch,
    pub fetcher: Arc<dyn Fetcher>,
}

/// A [`Fetcher`] that sends each URI to the fetcher of the first route
/// matching it, or to `otherwise`. See the [module docs](self).
#[derive(Debug)]
pub struct RouteFetcher {
    routes: Vec<Route>,
    otherwise: Option<Arc<dyn Fetcher>>,
}

/// Which fetcher each URI of a job goes to.
struct Plan {
    /// Groups of URIs (indices into the job's) that go to the same fetcher
    /// (by index into [`RouteFetcher::routes`], or one past the end for
    /// `otherwise`), in the order the first URI of each appears in the job.
    groups: Vec<(usize, Vec<usize>)>,
    /// The hosts of the URIs no route takes, for error messages. Only the
    /// host: the rest of a URI can hold a credential.
    refused: Vec<String>,
}

impl RouteFetcher {
    /// A router over `routes`, sending URIs that match none of them to
    /// `otherwise`, or refusing them when it is `None`.
    #[must_use]
    pub fn new(routes: Vec<Route>, otherwise: Option<Arc<dyn Fetcher>>) -> Arc<Self> {
        Arc::new(Self { routes, otherwise })
    }

    /// The route `uri` takes: an index into `routes`, `routes.len()` for
    /// `otherwise`, or `None` if it is refused.
    fn route_of(&self, uri: &str) -> Option<usize> {
        let url = reqwest::Url::parse(uri).ok();
        let matched = url.as_ref().and_then(Target::new).and_then(|target| {
            self.routes
                .iter()
                .position(|route| route.matches.accepts(&target))
        });
        matched.or_else(|| self.otherwise.as_ref().map(|_| self.routes.len()))
    }

    fn fetcher(&self, route: usize) -> &dyn Fetcher {
        match self.routes.get(route) {
            Some(route) => route.fetcher.as_ref(),
            // `route_of` only returns `routes.len()` when there is one.
            None => self
                .otherwise
                .as_deref()
                .expect("the otherwise route exists"),
        }
    }

    fn plan(&self, uris: &[String]) -> Plan {
        let mut plan = Plan {
            groups: Vec::new(),
            refused: Vec::new(),
        };
        for (idx, uri) in uris.iter().enumerate() {
            let Some(route) = self.route_of(uri) else {
                let host = uri_host(uri).unwrap_or_else(|| "a URI with no host".to_owned());
                if !plan.refused.contains(&host) {
                    plan.refused.push(host);
                }
                continue;
            };
            match plan.groups.iter_mut().find(|(r, _)| *r == route) {
                Some((_, indices)) => indices.push(idx),
                None => plan.groups.push((route, vec![idx])),
            }
        }
        plan
    }

    /// Fetches `job`, one group of its URIs at a time.
    async fn dispatch<J: RoutedJob>(&self, job: &J) -> Result<FetchOutcome, Error> {
        let plan = self.plan(job.uris());
        if plan.groups.is_empty() {
            return Err(make_err!(
                Code::PermissionDenied,
                "This server does not fetch these URIs on {}: no route matches them, and \
                 there is no 'otherwise' fetcher",
                HostList(&plan.refused)
            ));
        }
        if let [(route, _)] = plan.groups.as_slice()
            && plan.refused.is_empty()
        {
            return job.fetch_with(self.fetcher(*route)).await;
        }
        // The job's timeout covers every group, not each.
        let deadline = job
            .timeout()
            .and_then(|timeout| Instant::now().checked_add(timeout));
        let mut last_err = None;
        for (route, indices) in &plan.groups {
            let timeout = match deadline {
                Some(deadline) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        last_err = Some(make_err!(
                            Code::DeadlineExceeded,
                            "The fetch ran out of time before every URI was tried"
                        ));
                        break;
                    }
                    Some(left)
                }
                None => None,
            };
            let group = job.select(indices, timeout);
            match group.fetch_with(self.fetcher(*route)).await {
                Ok(outcome) => return Ok(outcome),
                Err(err) if fails_only_these_uris(err.code) => {
                    debug!(code = ?err.code, "Routed fetch failed, trying the next route");
                    last_err = Some(err);
                }
                Err(err) => return Err(err),
            }
        }
        let err = last_err.expect("there is at least one group, and each failed");
        Err(if plan.refused.is_empty() {
            err
        } else {
            err.append(format!(
                "URIs on {} were not tried: no route matches them",
                HostList(&plan.refused)
            ))
        })
    }
}

/// Whether a group failing with `code` leaves the other groups worth trying:
/// the codes a fetcher reports when the URIs it was given could not produce
/// the asset (not found, unreachable, refused, mismatched, too large,
/// unverifiable). Anything else, such as a bad request (`InvalidArgument`), a
/// broken checker or CAS (`Internal`) or a spent budget (`DeadlineExceeded`),
/// would fail the other groups the same way, so it is returned at once.
const fn fails_only_these_uris(code: Code) -> bool {
    matches!(
        code,
        Code::NotFound
            | Code::Unavailable
            | Code::PermissionDenied
            | Code::Aborted
            | Code::ResourceExhausted
            | Code::FailedPrecondition
    )
}

/// Hosts for an error message: `'a', 'b'`.
struct HostList<'a>(&'a [String]);

impl fmt::Display for HostList<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, host) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "'{host}'")?;
        }
        Ok(())
    }
}

/// What [`RouteFetcher::dispatch`] needs of a job.
trait RoutedJob: Send + Sync {
    fn uris(&self) -> &[String];
    fn timeout(&self) -> Option<Duration>;
    /// The job for `uris[indices]` alone, in that order, with `timeout`.
    fn select(&self, indices: &[usize], timeout: Option<Duration>) -> Self;
    fn fetch_with<'a>(
        &'a self,
        fetcher: &'a dyn Fetcher,
    ) -> BoxFuture<'a, Result<FetchOutcome, Error>>;
}

/// `uris[indices]`, in that order.
fn select_uris(uris: &[String], indices: &[usize]) -> Vec<String> {
    indices.iter().map(|&idx| uris[idx].clone()).collect()
}

impl RoutedJob for FetchBlobTask {
    fn uris(&self) -> &[String] {
        &self.uris
    }

    fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    fn select(&self, indices: &[usize], timeout: Option<Duration>) -> Self {
        let uris = select_uris(&self.uris, indices);
        Self {
            headers: self.headers.select(indices),
            revalidate: self
                .revalidate
                .iter()
                .filter(|stale| uris.contains(&stale.uri))
                .cloned()
                .collect(),
            uris,
            timeout,
            ..self.clone()
        }
    }

    fn fetch_with<'a>(
        &'a self,
        fetcher: &'a dyn Fetcher,
    ) -> BoxFuture<'a, Result<FetchOutcome, Error>> {
        fetcher.fetch_blob(self)
    }
}

impl RoutedJob for FetchDirectoryJob {
    fn uris(&self) -> &[String] {
        &self.uris
    }

    fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    fn select(&self, indices: &[usize], timeout: Option<Duration>) -> Self {
        let uris = select_uris(&self.uris, indices);
        Self {
            headers: self.headers.select(indices),
            revalidate: self
                .revalidate
                .iter()
                .filter(|stale| uris.contains(&stale.uri))
                .cloned()
                .collect(),
            uris,
            timeout,
            ..self.clone()
        }
    }

    fn fetch_with<'a>(
        &'a self,
        fetcher: &'a dyn Fetcher,
    ) -> BoxFuture<'a, Result<FetchOutcome, Error>> {
        fetcher.fetch_directory(self)
    }
}

#[async_trait]
impl Fetcher for RouteFetcher {
    async fn fetch_blob(&self, job: &FetchBlobTask) -> Result<FetchOutcome, Error> {
        self.dispatch(job).await
    }

    async fn fetch_directory(&self, job: &FetchDirectoryJob) -> Result<FetchOutcome, Error> {
        self.dispatch(job).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(s: &str) -> HostPattern {
        s.parse().unwrap()
    }

    #[test]
    fn an_exact_pattern_matches_only_its_host() {
        let github = pattern("GitHub.com.");
        assert!(github.matches("github.com"));
        assert!(!github.matches("api.github.com"));
        assert!(!github.matches("notgithub.com"));
    }

    #[test]
    fn a_wildcard_pattern_matches_only_subdomains() {
        let wildcard = pattern("*.githubusercontent.com");
        assert!(wildcard.matches("objects.githubusercontent.com"));
        assert!(wildcard.matches("a.b.githubusercontent.com"));
        assert!(!wildcard.matches("githubusercontent.com"));
        assert!(!wildcard.matches("evilgithubusercontent.com"));
    }

    #[test]
    fn ip_patterns_match_normalized_addresses() {
        assert!(pattern("[::1]").matches(&uri_host("http://[::1]:8080/x").unwrap()));
        assert!(pattern("10.0.0.1").matches(&uri_host("http://10.0.0.1/x").unwrap()));
    }

    #[test]
    fn malformed_patterns_are_rejected() {
        for bad in [
            "",
            "*",
            "*.",
            "https://example.com",
            "example.com:443",
            "example.com/path",
            "a*.example.com",
            "*.10.0.0.1",
            "user@example.com",
        ] {
            assert!(
                bad.parse::<HostPattern>().is_err(),
                "'{bad}' should not parse"
            );
        }
    }

    /// Whether `route` accepts `uri`.
    fn takes(route: &RouteMatch, uri: &str) -> bool {
        let url = reqwest::Url::parse(uri).unwrap();
        route.accepts(&Target::new(&url).unwrap())
    }

    fn route(hosts: &[&str]) -> RouteMatch {
        RouteMatch::hosts(hosts.iter().map(|host| pattern(host)).collect())
    }

    fn with_prefixes(prefixes: &[&str]) -> RouteMatch {
        RouteMatch {
            path_prefixes: prefixes.iter().map(|p| p.parse().unwrap()).collect(),
            ..route(&["github.com"])
        }
    }

    #[test]
    fn a_path_prefix_matches_whole_segments() {
        for prefix in ["/bazelbuild", "/bazelbuild/"] {
            let route = with_prefixes(&[prefix]);
            for uri in [
                "https://github.com/bazelbuild",
                "https://github.com/bazelbuild/",
                "https://github.com/bazelbuild/rules_go/archive/v1.tar.gz",
                "https://github.com/bazelbuild/x?y=../../evil",
            ] {
                assert!(takes(&route, uri), "{prefix} should take {uri}");
            }
            for uri in [
                "https://github.com/",
                "https://github.com/bazelbuild-evil/x",
                "https://github.com/BazelBuild/x",
                "https://github.com/evil/bazelbuild/x",
                "https://github.com//bazelbuild/x",
                "https://api.github.com/bazelbuild/x",
            ] {
                assert!(!takes(&route, uri), "{prefix} should not take {uri}");
            }
        }
        assert!(takes(&with_prefixes(&["/"]), "https://github.com/anything"));
        assert!(takes(
            &with_prefixes(&["/a", "/b/c"]),
            "https://github.com/b/c/d"
        ));
    }

    #[test]
    fn a_path_prefix_cannot_be_escaped() {
        let route = with_prefixes(&["/bazelbuild"]);
        for uri in [
            // Resolved by URL parsing, before matching.
            "https://github.com/bazelbuild/../evil/x",
            "https://github.com/bazelbuild/%2e%2e/evil/x",
            "https://github.com/bazelbuild/%2E%2e/evil/x",
            "https://github.com/bazelbuild/.%2e/evil/x",
            "https://github.com/bazelbuild/..\\evil/x",
            "https://github.com/bazelbuild;x/../evil/x",
            // Left for a server to resolve, so refused.
            "https://github.com/bazelbuild/..%2Fevil/x",
            "https://github.com/bazelbuild/..%2fevil/x",
            "https://github.com/bazelbuild/..%5Cevil/x",
            "https://github.com/bazelbuild/%2e%2e%2fevil/x",
            "https://github.com/bazelbuild/..;/evil/x",
            "https://github.com/bazelbuild/%2e%2e;x/evil/x",
            "https://github.com/bazelbuild/%2e%2e%3b/evil/x",
            "https://github.com/bazelbuild/.;/x",
            "https://github.com/bazelbuild/%252e%252e/evil/x",
            "https://github.com/bazelbuild/%252fevil/x",
            // Encoded to look like the prefix.
            "https://github.com/%62azelbuild/x",
            "https://github.com/bazelbuild%2Fx",
        ] {
            assert!(!takes(&route, uri), "should not take {uri}");
        }
    }

    #[test]
    fn a_route_without_ports_takes_only_the_default_port() {
        let route = route(&["github.com"]);
        assert!(takes(&route, "https://github.com/a"));
        assert!(takes(&route, "https://github.com:443/a"));
        assert!(takes(&route, "http://github.com:80/a"));
        assert!(!takes(&route, "https://github.com:8443/a"));
        assert!(!takes(&route, "http://github.com:443/a"));
    }

    #[test]
    fn listed_ports_replace_the_default() {
        let route = RouteMatch {
            ports: vec![8443],
            ..route(&["artifacts.internal"])
        };
        assert!(takes(&route, "https://artifacts.internal:8443/a"));
        assert!(!takes(&route, "https://artifacts.internal/a"));
        assert!(!takes(&route, "https://artifacts.internal:6379/a"));
        let both = RouteMatch {
            ports: vec![443, 8443],
            ..route
        };
        assert!(takes(&both, "https://artifacts.internal/a"));
    }

    #[test]
    fn schemes_restrict_a_route() {
        let route = RouteMatch {
            schemes: vec![Scheme::Https],
            ..route(&["github.com"])
        };
        assert!(takes(&route, "HTTPS://github.com/a"));
        assert!(!takes(&route, "http://github.com/a"));
        assert!(!takes(&route, "ftp://github.com/a"));
    }

    #[test]
    fn malformed_path_prefixes_are_rejected() {
        for bad in [
            "",
            "bazelbuild",
            "https://github.com/bazelbuild",
            "/a/../b",
            "/a/./b",
            "/a/%2e%2e/b",
            "/a?b",
            "/a#b",
            "/a b",
            "/a\\b",
            "/a%2Fb",
            "/a/..;/b",
            "/a%25b",
        ] {
            assert!(
                bad.parse::<PathPrefix>().is_err(),
                "'{bad}' should not parse"
            );
        }
        assert_eq!(
            "/a/b/".parse::<PathPrefix>().unwrap(),
            "/a/b".parse::<PathPrefix>().unwrap()
        );
        assert!("/my%20org/".parse::<PathPrefix>().is_ok());
    }

    #[test]
    fn schemes_parse() {
        assert_eq!("HTTPS".parse::<Scheme>().unwrap(), Scheme::Https);
        for bad in ["https://", "ftp", "file", ""] {
            assert!(bad.parse::<Scheme>().is_err(), "'{bad}' should not parse");
        }
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%2Fb%2e%zz%4"), b"a/b.%zz%4");
        assert_eq!(percent_decode("%+f"), b"%+f");
    }

    #[test]
    fn uri_hosts_are_normalized() {
        assert_eq!(
            uri_host("https://USER:pw@Example.COM./x").as_deref(),
            Some("example.com")
        );
        assert_eq!(uri_host("not a uri"), None);
    }
}
