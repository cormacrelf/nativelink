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

use nativelink_util::redact::{redact_uri, redact_uris_in_text};

#[test]
fn leaves_uris_without_credentials_alone() {
    for uri in [
        "https://example.com",
        "https://example.com/a/b.tar.gz",
        "http://127.0.0.1:8080/blob?download",
        "file.txt",
    ] {
        assert_eq!(redact_uri(uri), uri);
    }
}

#[test]
fn redacts_userinfo() {
    assert_eq!(
        redact_uri("https://user:pass@example.com:8443/a/b"),
        "https://REDACTED@example.com:8443/a/b"
    );
    assert_eq!(
        redact_uri("https://token@example.com"),
        "https://REDACTED@example.com"
    );
    // An `@` after the authority is not userinfo.
    assert_eq!(
        redact_uri("https://example.com/a@b"),
        "https://example.com/a@b"
    );
}

#[test]
fn redacts_query_values_but_keeps_names() {
    assert_eq!(
        redact_uri(
            "https://bucket.s3.amazonaws.com/key?X-Amz-Signature=abc123&token=s3cret&flag&empty="
        ),
        "https://bucket.s3.amazonaws.com/key?X-Amz-Signature=REDACTED&token=REDACTED&flag&empty=REDACTED"
    );
}

#[test]
fn redacts_fragment() {
    assert_eq!(
        redact_uri("https://example.com/a?x=1#access_token=abc"),
        "https://example.com/a?x=REDACTED#REDACTED"
    );
}

#[test]
fn redacts_everything_at_once() {
    let redacted = redact_uri("https://user:pass@example.com/p?sig=abc&n=1#frag");
    assert_eq!(
        redacted,
        "https://REDACTED@example.com/p?sig=REDACTED&n=REDACTED#REDACTED"
    );
    for secret in ["user", "pass", "abc", "frag"] {
        assert!(!redacted.contains(secret), "{redacted}");
    }
}

#[test]
fn redacts_uris_embedded_in_text() {
    assert_eq!(
        redact_uris_in_text(
            "Failed to fetch 'https://u:p@example.com/a?sig=abc': error sending request for url (http://u:p@example.com/a?sig=abc&b=2) twice"
        ),
        "Failed to fetch 'https://REDACTED@example.com/a?sig=REDACTED': error sending request for url (http://REDACTED@example.com/a?sig=REDACTED&b=REDACTED) twice"
    );
    assert_eq!(redact_uris_in_text("no uris here"), "no uris here");
    assert_eq!(redact_uris_in_text(""), "");
    assert_eq!(redact_uris_in_text("a :// b"), "a :// b");
}
