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

//! Which addresses a [`crate::url_fetcher::UrlFetcher`] may connect to.
//!
//! Anyone who can call `Fetch` can name any URL, and the fetcher downloads it
//! into the CAS, where the caller can read it back. Without a filter, that
//! hands every caller the server's network position: loopback services, the
//! cloud metadata endpoint (whose `Metadata-Flavor`/`Metadata` header checks a
//! caller satisfies with an `http_header:*` qualifier) and the rest of the
//! private network. So every address that is not plainly on the public
//! internet is refused unless an operator allows its range.
//!
//! The check is made on the addresses a host name resolves to, at connection
//! time (see [`FilteringResolver`]), so DNS rebinding and redirects to an
//! internal host are caught too, and on IP-address URLs, which never reach a
//! resolver (see [`IpFilter::check_uri`]).

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use core::str::FromStr;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use nativelink_error::{Code, Error, make_err, make_input_err};

/// An IP range in CIDR notation, such as `10.0.0.0/8` or `fd00::/8`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpRange {
    network: IpAddr,
    prefix_len: u8,
}

impl IpRange {
    const fn v4(a: u8, b: u8, c: u8, d: u8, prefix_len: u8) -> Self {
        Self {
            network: IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
            prefix_len,
        }
    }

    const fn v6(segments: [u16; 8], prefix_len: u8) -> Self {
        let mut bits: u128 = 0;
        let mut i = 0;
        while i < segments.len() {
            bits = (bits << 16) | segments[i] as u128;
            i += 1;
        }
        Self {
            network: IpAddr::V6(Ipv6Addr::from_bits(bits)),
            prefix_len,
        }
    }

    /// Whether `ip` is in the range. An IPv4 range never contains an IPv6
    /// address, nor the other way round.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => prefix_matches(
                network.to_bits().into(),
                ip.to_bits().into(),
                32,
                self.prefix_len,
            ),
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                prefix_matches(network.to_bits(), ip.to_bits(), 128, self.prefix_len)
            }
            _ => false,
        }
    }
}

/// Whether the top `prefix_len` of the `width` bits of `a` and `b` agree.
const fn prefix_matches(a: u128, b: u128, width: u8, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let shift = width - prefix_len;
    (a >> shift) == (b >> shift)
}

impl FromStr for IpRange {
    type Err = Error;

    /// Parses `address/prefix_len`, or a bare address as a range of one.
    /// Host bits set below the prefix are an error, since they usually mean
    /// the range is not the one intended.
    fn from_str(s: &str) -> Result<Self, Error> {
        let (address, prefix_len) = match s.split_once('/') {
            Some((address, prefix_len)) => (address, Some(prefix_len)),
            None => (s, None),
        };
        let network: IpAddr = address
            .trim()
            .parse()
            .map_err(|_| make_input_err!("'{s}' is not an IP address or CIDR range"))?;
        let width = if network.is_ipv4() { 32 } else { 128 };
        let prefix_len = match prefix_len {
            Some(prefix_len) => prefix_len
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|&len| len <= width)
                .ok_or_else(|| make_input_err!("'{s}' has a prefix length outside 0 to {width}"))?,
            None => width,
        };
        let range = Self {
            network,
            prefix_len,
        };
        let bits = match network {
            IpAddr::V4(ip) => u128::from(ip.to_bits()),
            IpAddr::V6(ip) => ip.to_bits(),
        };
        let host_bits = if prefix_len == width {
            0
        } else {
            bits & (u128::MAX >> (128 - u32::from(width - prefix_len)))
        };
        if host_bits != 0 {
            return Err(make_input_err!(
                "'{s}' has bits set below its /{prefix_len} prefix"
            ));
        }
        Ok(range)
    }
}

/// IPv4 ranges that are not plainly on the public internet: this host,
/// private and shared networks, link-local (cloud metadata services live at
/// `169.254.169.254`), benchmarking, documentation, multicast and reserved.
/// `100.64.0.0/10` (carrier-grade NAT) is here because it is used internally:
/// Alibaba Cloud's metadata service is `100.100.100.200`, and Tailscale nodes
/// live in it.
const BLOCKED_V4: &[IpRange] = &[
    IpRange::v4(0, 0, 0, 0, 8),
    IpRange::v4(10, 0, 0, 0, 8),
    IpRange::v4(100, 64, 0, 0, 10),
    IpRange::v4(127, 0, 0, 0, 8),
    IpRange::v4(169, 254, 0, 0, 16),
    IpRange::v4(172, 16, 0, 0, 12),
    IpRange::v4(192, 0, 0, 0, 24),
    IpRange::v4(192, 0, 2, 0, 24),
    IpRange::v4(192, 88, 99, 0, 24),
    IpRange::v4(192, 168, 0, 0, 16),
    IpRange::v4(198, 18, 0, 0, 15),
    IpRange::v4(198, 51, 100, 0, 24),
    IpRange::v4(203, 0, 113, 0, 24),
    IpRange::v4(224, 0, 0, 0, 4),
    IpRange::v4(240, 0, 0, 0, 4),
];

/// IPv6 ranges that are not plainly on the public internet. The ranges that
/// embed an IPv4 address (mapped, NAT64, 6to4) are not here: they are judged
/// by the address they embed (see [`embedded_v4`]).
const BLOCKED_V6: &[IpRange] = &[
    // Unspecified, loopback and the deprecated IPv4-compatible addresses.
    IpRange::v6([0, 0, 0, 0, 0, 0, 0, 0], 96),
    // NAT64 for local use (RFC 8215), whose IPv4 side is the operator's.
    IpRange::v6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48),
    // Discard-only.
    IpRange::v6([0x100, 0, 0, 0, 0, 0, 0, 0], 64),
    // IETF protocol assignments, Teredo among them.
    IpRange::v6([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
    // Documentation.
    IpRange::v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
    // Unique local: private networks, AWS's IPv6 metadata service among them.
    IpRange::v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
    // Link-local.
    IpRange::v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
    // Site-local (deprecated).
    IpRange::v6([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10),
    // Multicast.
    IpRange::v6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8),
];

/// The IPv4 address an IPv6 address stands for, if it embeds one: an
/// IPv4-mapped address (`::ffff:a.b.c.d`), the well-known NAT64 prefix
/// (`64:ff9b::a.b.c.d`), through which `64:ff9b::a9fe:a9fe` reaches
/// `169.254.169.254`, or 6to4 (`2002:aabb:ccdd::`).
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    let bits = ip.to_bits();
    if IpRange::v6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96).contains(IpAddr::V6(ip)) {
        // The low 32 bits.
        return Some(Ipv4Addr::from_bits(low_u32(bits)));
    }
    if IpRange::v6([0x2002, 0, 0, 0, 0, 0, 0, 0], 16).contains(IpAddr::V6(ip)) {
        // The 32 bits after the 16-bit prefix.
        return Some(Ipv4Addr::from_bits(low_u32(bits >> 80)));
    }
    None
}

/// The low 32 bits of `bits`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the truncation is the point"
)]
const fn low_u32(bits: u128) -> u32 {
    bits as u32
}

/// Whether `ip` is outside the public internet, as far as the fetcher is
/// concerned: in [`BLOCKED_V4`] or [`BLOCKED_V6`], or embedding an IPv4
/// address that is.
#[must_use]
pub fn is_non_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => BLOCKED_V4
            .iter()
            .any(|range| range.contains(IpAddr::V4(v4))),
        IpAddr::V6(v6) => match embedded_v4(v6) {
            Some(v4) => is_non_public(IpAddr::V4(v4)),
            None => BLOCKED_V6
                .iter()
                .any(|range| range.contains(IpAddr::V6(v6))),
        },
    }
}

/// The addresses a `url` fetcher may connect to: every public address, and the
/// non-public ones in `allowed`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpFilter {
    allowed: Vec<IpRange>,
}

impl IpFilter {
    /// A filter that also allows the non-public addresses in `allowed`, each a
    /// range in CIDR notation or a single address. `0.0.0.0/0` and `::/0`
    /// together turn the filter off.
    pub fn new(allowed: &[String]) -> Result<Self, Error> {
        let allowed = allowed
            .iter()
            .map(|range| {
                range
                    .parse()
                    .map_err(|err: Error| err.append("In 'allowed_ip_ranges'"))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { allowed })
    }

    /// Whether the fetcher may connect to `ip`. An address that embeds an
    /// IPv4 address is also allowed when that address is.
    #[must_use]
    pub fn permits(&self, ip: IpAddr) -> bool {
        let embedded = match ip {
            IpAddr::V6(v6) => embedded_v4(v6).map(IpAddr::V4),
            IpAddr::V4(_) => None,
        };
        let allowed = self
            .allowed
            .iter()
            .any(|range| range.contains(ip) || embedded.is_some_and(|ip| range.contains(ip)));
        allowed || !is_non_public(ip)
    }

    /// Checks the host of `url` when it is an IP address. Such a URL is
    /// connected to without resolving anything, so [`FilteringResolver`] never
    /// sees it. It is checked whether or not it would go through a proxy. A
    /// host name passes: its addresses are checked when it is resolved.
    pub fn check_url(&self, url: &reqwest::Url) -> Result<(), BlockedAddress> {
        let Some(host) = url.host_str() else {
            return Ok(());
        };
        let Ok(ip) = host.trim_start_matches('[').trim_end_matches(']').parse() else {
            return Ok(());
        };
        if self.permits(ip) {
            Ok(())
        } else {
            Err(BlockedAddress {
                host: host.to_owned(),
            })
        }
    }

    /// [`Self::check_url`] on a URL given as text, failing with
    /// `PERMISSION_DENIED`. A URL that does not parse passes: sending it fails
    /// anyway, with a clearer error.
    pub fn check_uri(&self, uri: &str) -> Result<(), Error> {
        match reqwest::Url::parse(uri) {
            Ok(url) => self
                .check_url(&url)
                .map_err(|blocked| make_err!(Code::PermissionDenied, "{blocked}")),
            Err(_) => Ok(()),
        }
    }
}

/// Why a connection to `host` is refused. Names the host only: never a
/// resolved address, which would tell a caller about the internal network.
fn refusal(host: &str) -> String {
    format!(
        "'{host}' is not a public address, and this fetcher is not allowed to connect to it \
         (see 'allowed_ip_ranges')"
    )
}

/// A connection refused by an [`IpFilter`]: what a [`FilteringResolver`]
/// fails with when every address a host resolves to is refused, and what the
/// redirect policy fails with on a redirect to a refused IP address, so the
/// fetcher can report either as `PERMISSION_DENIED` (see
/// [`is_blocked_address`]).
#[derive(Debug)]
pub struct BlockedAddress {
    host: String,
}

impl fmt::Display for BlockedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&refusal(&self.host))
    }
}

impl std::error::Error for BlockedAddress {}

/// Whether `err`, or anything in its chain of sources, is a [`BlockedAddress`].
#[must_use]
pub fn is_blocked_address(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(err);
    while let Some(err) = current {
        if err.is::<BlockedAddress>() {
            return true;
        }
        current = err.source();
    }
    false
}

/// A DNS resolver that leaves out the addresses an [`IpFilter`] refuses, and
/// fails when that leaves none. It resolves with the system resolver, as
/// reqwest's default does.
///
/// It resolves every host the client connects to itself: origins, and the
/// configured proxy. The proxy is trusted (an operator named it, and it
/// commonly has a private address), so its addresses are not filtered.
/// Origins reached through the proxy are never resolved here: the proxy
/// resolves them, and it is the proxy that has to enforce what may be reached.
#[derive(Debug)]
pub struct FilteringResolver {
    filter: Arc<IpFilter>,
    /// The host of the configured proxy, lowercased, if there is one.
    proxy_host: Option<String>,
}

impl FilteringResolver {
    #[must_use]
    pub fn new(filter: Arc<IpFilter>, proxy_host: Option<&str>) -> Self {
        Self {
            filter,
            proxy_host: proxy_host.map(str::to_ascii_lowercase),
        }
    }
}

impl reqwest::dns::Resolve for FilteringResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        let trusted = self
            .proxy_host
            .as_deref()
            .is_some_and(|proxy| proxy.eq_ignore_ascii_case(&host));
        let filter = self.filter.clone();
        Box::pin(async move {
            let lookup = host.clone();
            let addrs: Vec<SocketAddr> =
                nativelink_util::spawn_blocking!("fetch_resolve_host", move || {
                    (lookup.as_str(), 0).to_socket_addrs()
                })
                .await??
                .collect();
            let permitted: Vec<SocketAddr> = if trusted {
                addrs
            } else {
                addrs
                    .into_iter()
                    .filter(|addr| filter.permits(addr.ip()))
                    .collect()
            };
            if permitted.is_empty() && !trusted {
                let blocked: Box<dyn std::error::Error + Send + Sync> =
                    Box::new(BlockedAddress { host });
                return Err(blocked);
            }
            let permitted: reqwest::dns::Addrs = Box::new(permitted.into_iter());
            Ok(permitted)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn non_public_addresses_are_recognised() {
        for address in [
            "0.0.0.0",
            "10.1.2.3",
            "100.100.100.200",
            "127.0.0.1",
            "169.254.169.254",
            "172.31.255.255",
            "192.168.1.1",
            "198.18.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1::1",
            "2002:a9fe:a9fe::1",
            "2001:db8::1",
            "fd00:ec2::254",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(is_non_public(ip(address)), "{address} should be non-public");
        }
    }

    #[test]
    fn public_addresses_are_recognised() {
        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.0",
            "172.32.0.1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:808:808::1",
            "2606:4700:4700::1111",
        ] {
            assert!(!is_non_public(ip(address)), "{address} should be public");
        }
    }

    #[test]
    fn allowed_ranges_let_non_public_addresses_through() {
        let filter = IpFilter::new(&["10.0.0.0/8".to_owned(), "fd00::1".to_owned()]).unwrap();
        assert!(filter.permits(ip("10.2.3.4")));
        assert!(filter.permits(ip("::ffff:10.2.3.4")));
        assert!(filter.permits(ip("fd00::1")));
        assert!(!filter.permits(ip("fd00::2")));
        assert!(!filter.permits(ip("127.0.0.1")));
        assert!(filter.permits(ip("8.8.8.8")));
    }

    #[test]
    fn everything_allowed_turns_the_filter_off() {
        let filter = IpFilter::new(&["0.0.0.0/0".to_owned(), "::/0".to_owned()]).unwrap();
        assert!(filter.permits(ip("127.0.0.1")));
        assert!(filter.permits(ip("fe80::1")));
    }

    #[test]
    fn malformed_ranges_are_rejected() {
        for range in [
            "10.0.0.0/33",
            "10.0.0.1/8",
            "example.com",
            "fd00::/129",
            "10.0.0.0/x",
        ] {
            assert!(
                range.parse::<IpRange>().is_err(),
                "{range} should not parse"
            );
        }
    }

    #[test]
    fn ip_address_urls_are_checked() {
        let filter = IpFilter::default();
        for uri in [
            "http://127.0.0.1/x",
            "http://[::1]:8080/x",
            "http://169.254.169.254/latest/meta-data/",
            "http://2130706433/x",
            "http://0x7f.1/x",
        ] {
            let err = filter.check_uri(uri).unwrap_err();
            assert_eq!(err.code, Code::PermissionDenied, "{uri}");
        }
        filter.check_uri("https://8.8.8.8/x").unwrap();
        filter.check_uri("https://example.com/x").unwrap();
    }
}
