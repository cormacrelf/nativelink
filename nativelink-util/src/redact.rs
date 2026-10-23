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

//! Redaction of credentials in URIs, for anything that is logged. A URI may
//! carry credentials in its userinfo (`https://user:pass@host`) or in signed-URL
//! query parameters (`X-Amz-Signature=...`, `token=...`).

/// What a redacted part of a URI is replaced with.
pub const REDACTED: &str = "REDACTED";

/// `uri` with its userinfo, query parameter values and fragment replaced by
/// [`REDACTED`]. The scheme, host, path and query parameter names are kept, so
/// that the result still says what was fetched.
#[must_use]
pub fn redact_uri(uri: &str) -> String {
    let (rest, has_fragment) = match uri.split_once('#') {
        Some((rest, _)) => (rest, true),
        None => (uri, false),
    };
    let (location, query) = match rest.split_once('?') {
        Some((location, query)) => (location, Some(query)),
        None => (rest, None),
    };
    let mut redacted = String::with_capacity(uri.len());
    match location.split_once("://") {
        Some((scheme, after_scheme)) => {
            let authority_len = after_scheme.find('/').unwrap_or(after_scheme.len());
            let (authority, path) = after_scheme.split_at(authority_len);
            redacted.push_str(scheme);
            redacted.push_str("://");
            if let Some((_userinfo, host)) = authority.rsplit_once('@') {
                redacted.push_str(REDACTED);
                redacted.push('@');
                redacted.push_str(host);
            } else {
                redacted.push_str(authority);
            }
            redacted.push_str(path);
        }
        None => redacted.push_str(location),
    }
    if let Some(query) = query {
        redacted.push('?');
        for (idx, pair) in query.split('&').enumerate() {
            if idx != 0 {
                redacted.push('&');
            }
            match pair.split_once('=') {
                Some((name, _value)) => {
                    redacted.push_str(name);
                    redacted.push('=');
                    redacted.push_str(REDACTED);
                }
                None => redacted.push_str(pair),
            }
        }
    }
    if has_fragment {
        redacted.push('#');
        redacted.push_str(REDACTED);
    }
    redacted
}

/// `text` with every `scheme://...` URI in it passed through [`redact_uri`].
/// For error messages, which embed the URIs they are about, and whose URIs
/// (e.g. as normalized by an HTTP client) may not be the string that was sent.
#[must_use]
pub fn redact_uris_in_text(text: &str) -> String {
    let mut redacted = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(scheme_end) = rest.find("://") {
        let scheme_start = rest[..scheme_end]
            .char_indices()
            .rev()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .map_or(0, |(idx, c)| idx + c.len_utf8());
        let uri_end = rest[scheme_end..]
            .find(|c: char| {
                c.is_whitespace() || matches!(c, '\'' | '"' | '`' | '(' | ')' | '<' | '>')
            })
            .map_or(rest.len(), |idx| scheme_end + idx);
        redacted.push_str(&rest[..scheme_start]);
        redacted.push_str(&redact_uri(&rest[scheme_start..uri_end]));
        rest = &rest[uri_end..];
    }
    redacted.push_str(rest);
    redacted
}
