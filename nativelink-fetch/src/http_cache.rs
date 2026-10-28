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

//! How long an origin says a response stays fresh, read from its HTTP caching
//! headers as a shared cache reads them (RFC 9111, section 4.2).
//!
//! Only explicit freshness is used. There is no heuristic freshness (a fraction
//! of the age implied by `Last-Modified`): a response that says nothing gets
//! the lifetime the operator configured, see
//! [`crate::metadata_cache::MetadataCacheOptions`].

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::header::{AGE, CACHE_CONTROL, DATE, EXPIRES, HeaderMap};

/// What `delta-seconds` is taken to be when it is a number too large to
/// represent (RFC 9111, section 1.2.2): 2^31 seconds.
const OVERFLOWED_DELTA: Duration = Duration::from_secs(1 << 31);

/// Parses `delta-seconds`: one or more digits. Anything else (a sign, a
/// fraction, a unit, garbage) is invalid and gives `None`.
fn parse_delta_seconds(value: &str) -> Option<Duration> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(
        value
            .parse::<u64>()
            .map_or(OVERFLOWED_DELTA, Duration::from_secs)
            .min(OVERFLOWED_DELTA),
    )
}

/// Days from 1970-01-01 to the given proleptic Gregorian date.
const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let shifted_month = (month + 9) % 12;
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Parses an HTTP date in the preferred `IMF-fixdate` format,
/// `Sun, 06 Nov 1994 08:49:37 GMT`. The two obsolete formats are not accepted;
/// a header in one of them is treated as invalid, which for freshness errs
/// towards stale. Returns `None` for anything else.
pub fn parse_http_date(value: &str) -> Option<SystemTime> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    let mut parts = value.split_ascii_whitespace();
    let day_name = parts.next()?.strip_suffix(',')?;
    let day: i64 = parts.next()?.parse().ok()?;
    let month = parts.next()?;
    let year: i64 = parts.next()?.parse().ok()?;
    let time = parts.next()?;
    if parts.next()? != "GMT" || parts.next().is_some() || !DAYS.contains(&day_name) {
        return None;
    }
    let month = i64::try_from(MONTHS.iter().position(|m| *m == month)?).ok()? + 1;
    let mut clock = time.split(':');
    let hour: i64 = clock.next()?.parse().ok()?;
    let minute: i64 = clock.next()?.parse().ok()?;
    let second: i64 = clock.next()?.parse().ok()?;
    if clock.next().is_some()
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
        || year < 1970
        || time.len() != 8
    {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    Some(UNIX_EPOCH + Duration::from_secs(u64::try_from(seconds).ok()?))
}

/// The explicit freshness lifetime `headers` give a response received at
/// `received_at`, for a shared cache, less its `Age`:
///
/// 1. `Cache-Control: no-store`, `no-cache` or `private` (with or without a
///    field list) give [`Duration::ZERO`]: the response must not be reused
///    without checking. They win over every other header.
/// 2. Otherwise `s-maxage`, then `max-age`. A directive whose value is not
///    `delta-seconds` is ignored, and the next source is tried.
/// 3. Otherwise `Expires` minus `Date` (or minus `received_at` when `Date` is
///    absent or invalid). An `Expires` that is not a valid date, such as `0`,
///    means already expired and gives zero (RFC 9111, section 5.3).
/// 4. Otherwise `None`: the headers say nothing.
///
/// When one of 2 or 3 applies, `Age` (when valid) is then subtracted, to
/// zero at the least.
pub fn freshness_lifetime(headers: &HeaderMap, received_at: SystemTime) -> Option<Duration> {
    let mut s_maxage = None;
    let mut max_age = None;
    for value in headers.get_all(CACHE_CONTROL) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for directive in value.split(',') {
            let (name, argument) = match directive.split_once('=') {
                Some((name, argument)) => (name, Some(argument.trim().trim_matches('"'))),
                None => (directive, None),
            };
            match name.trim().to_ascii_lowercase().as_str() {
                "no-store" | "no-cache" | "private" => return Some(Duration::ZERO),
                "s-maxage" => {
                    s_maxage = s_maxage.or_else(|| argument.and_then(parse_delta_seconds));
                }
                "max-age" => {
                    max_age = max_age.or_else(|| argument.and_then(parse_delta_seconds));
                }
                _ => {}
            }
        }
    }
    let lifetime = s_maxage.or(max_age).or_else(|| {
        let expires = headers.get(EXPIRES)?;
        let Some(expires) = expires.to_str().ok().and_then(parse_http_date) else {
            return Some(Duration::ZERO);
        };
        let date = headers
            .get(DATE)
            .and_then(|date| date.to_str().ok())
            .and_then(parse_http_date)
            .unwrap_or(received_at);
        Some(expires.duration_since(date).unwrap_or(Duration::ZERO))
    })?;
    let age = headers
        .get(AGE)
        .and_then(|age| age.to_str().ok())
        .and_then(|age| parse_delta_seconds(age.trim()))
        .unwrap_or(Duration::ZERO);
    Some(lifetime.saturating_sub(age))
}

#[cfg(test)]
mod tests {
    use reqwest::header::HeaderValue;

    use super::*;

    const NOW: SystemTime = UNIX_EPOCH;
    // Sun, 06 Nov 1994 08:49:37 GMT
    const DATE_1994: u64 = 784_111_777;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                reqwest::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    fn lifetime(pairs: &[(&str, &str)]) -> Option<Duration> {
        freshness_lifetime(&headers(pairs), NOW)
    }

    const fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn parses_imf_fixdate() {
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(UNIX_EPOCH + Duration::from_secs(DATE_1994))
        );
        assert_eq!(
            parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"),
            Some(UNIX_EPOCH)
        );
        // Obsolete formats, and junk.
        assert_eq!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun Nov  6 08:49:37 1994"), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 PST"), None);
        assert_eq!(parse_http_date("Sun, 32 Nov 1994 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 25:49:37 GMT"), None);
        assert_eq!(parse_http_date("0"), None);
        assert_eq!(parse_http_date(""), None);
    }

    #[test]
    fn no_headers_say_nothing() {
        assert_eq!(lifetime(&[]), None);
        assert_eq!(
            lifetime(&[("Cache-Control", "public, must-revalidate")]),
            None
        );
        assert_eq!(
            lifetime(&[
                ("ETag", "\"x\""),
                ("Last-Modified", "Sun, 06 Nov 1994 08:49:37 GMT")
            ]),
            None
        );
    }

    #[test]
    fn max_age() {
        assert_eq!(
            lifetime(&[("Cache-Control", "max-age=600")]),
            Some(secs(600))
        );
        assert_eq!(
            lifetime(&[("Cache-Control", "public, MAX-AGE=\"600\", immutable")]),
            Some(secs(600))
        );
        assert_eq!(lifetime(&[("Cache-Control", "max-age=0")]), Some(secs(0)));
    }

    #[test]
    fn s_maxage_wins_over_max_age_in_any_order() {
        assert_eq!(
            lifetime(&[("Cache-Control", "max-age=600, s-maxage=60")]),
            Some(secs(60))
        );
        assert_eq!(
            lifetime(&[("Cache-Control", "s-maxage=60, max-age=600")]),
            Some(secs(60))
        );
        assert_eq!(
            lifetime(&[
                ("Cache-Control", "max-age=600"),
                ("Cache-Control", "s-maxage=60")
            ]),
            Some(secs(60))
        );
        assert_eq!(
            lifetime(&[("Cache-Control", "s-maxage=0, max-age=600")]),
            Some(secs(0))
        );
    }

    #[test]
    fn cache_control_wins_over_expires() {
        assert_eq!(
            lifetime(&[
                ("Cache-Control", "max-age=60"),
                ("Date", "Sun, 06 Nov 1994 08:49:37 GMT"),
                ("Expires", "Sun, 06 Nov 1994 09:49:37 GMT"),
            ]),
            Some(secs(60))
        );
    }

    #[test]
    fn expires_is_measured_from_date() {
        assert_eq!(
            lifetime(&[
                ("Date", "Sun, 06 Nov 1994 08:49:37 GMT"),
                ("Expires", "Sun, 06 Nov 1994 09:49:37 GMT"),
            ]),
            Some(secs(3600))
        );
        // Already expired when sent.
        assert_eq!(
            lifetime(&[
                ("Date", "Sun, 06 Nov 1994 09:49:37 GMT"),
                ("Expires", "Sun, 06 Nov 1994 08:49:37 GMT"),
            ]),
            Some(secs(0))
        );
    }

    #[test]
    fn expires_without_a_date_is_measured_from_receipt() {
        let received = UNIX_EPOCH + Duration::from_secs(DATE_1994);
        let map = headers(&[("Expires", "Sun, 06 Nov 1994 09:49:37 GMT")]);
        assert_eq!(freshness_lifetime(&map, received), Some(secs(3600)));
        let map = headers(&[
            ("Date", "garbage"),
            ("Expires", "Sun, 06 Nov 1994 09:49:37 GMT"),
        ]);
        assert_eq!(freshness_lifetime(&map, received), Some(secs(3600)));
    }

    #[test]
    fn age_is_subtracted() {
        assert_eq!(
            lifetime(&[("Cache-Control", "max-age=600"), ("Age", "100")]),
            Some(secs(500))
        );
        assert_eq!(
            lifetime(&[("Cache-Control", "s-maxage=60"), ("Age", "100")]),
            Some(secs(0))
        );
        assert_eq!(
            lifetime(&[
                ("Date", "Sun, 06 Nov 1994 08:49:37 GMT"),
                ("Expires", "Sun, 06 Nov 1994 09:49:37 GMT"),
                ("Age", "600"),
            ]),
            Some(secs(3000))
        );
        // Age alone says nothing about freshness, and a bad Age is ignored.
        assert_eq!(lifetime(&[("Age", "100")]), None);
        assert_eq!(
            lifetime(&[("Cache-Control", "max-age=600"), ("Age", "soon")]),
            Some(secs(600))
        );
        assert_eq!(
            lifetime(&[("Cache-Control", "max-age=600"), ("Age", "-5")]),
            Some(secs(600))
        );
    }

    #[test]
    fn no_store_no_cache_and_private_are_zero() {
        for directive in [
            "no-store",
            "no-cache",
            "private",
            "NO-CACHE",
            "private=\"set-cookie\"",
            "no-cache=\"x\"",
        ] {
            assert_eq!(
                lifetime(&[("Cache-Control", &format!("max-age=600, {directive}"))]),
                Some(secs(0)),
                "{directive}"
            );
        }
        assert_eq!(
            lifetime(&[
                ("Cache-Control", "s-maxage=600"),
                ("Cache-Control", "no-store")
            ]),
            Some(secs(0))
        );
        // `no-cache` as part of another name is not the directive.
        assert_eq!(
            lifetime(&[("Cache-Control", "x-no-cache, max-age=5")]),
            Some(secs(5))
        );
    }

    #[test]
    fn garbage_values_are_ignored_or_stale() {
        // Not delta-seconds: the directive is ignored.
        for bad in [
            "max-age=",
            "max-age=abc",
            "max-age=-1",
            "max-age=1.5",
            "max-age=10s",
            "max-age",
        ] {
            assert_eq!(lifetime(&[("Cache-Control", bad)]), None, "{bad}");
        }
        // A bad s-maxage falls back to a good max-age.
        assert_eq!(
            lifetime(&[("Cache-Control", "s-maxage=abc, max-age=30")]),
            Some(secs(30))
        );
        // An invalid Expires means already expired.
        assert_eq!(lifetime(&[("Expires", "0")]), Some(secs(0)));
        assert_eq!(lifetime(&[("Expires", "tomorrow")]), Some(secs(0)));
        // But a bad max-age does not hide a valid Expires.
        assert_eq!(
            lifetime(&[
                ("Cache-Control", "max-age=abc"),
                ("Date", "Sun, 06 Nov 1994 08:49:37 GMT"),
                ("Expires", "Sun, 06 Nov 1994 09:49:37 GMT"),
            ]),
            Some(secs(3600))
        );
        // A header that is not text is skipped.
        let mut map = HeaderMap::new();
        map.append(
            CACHE_CONTROL,
            HeaderValue::from_bytes(b"max-age=\xff").unwrap(),
        );
        map.append(CACHE_CONTROL, HeaderValue::from_static("max-age=7"));
        assert_eq!(freshness_lifetime(&map, NOW), Some(secs(7)));
    }

    #[test]
    fn huge_delta_seconds_saturates() {
        assert_eq!(
            lifetime(&[("Cache-Control", "max-age=99999999999999999999999")]),
            Some(OVERFLOWED_DELTA)
        );
    }
}
