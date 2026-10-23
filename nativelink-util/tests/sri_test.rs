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

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use nativelink_error::Code;
use nativelink_util::sri::verify_sri_hash;
use sha2::{Digest, Sha384, Sha512};

#[test]
fn verifies_known_sha256_of_empty_input() {
    // The canonical SRI of the empty byte string.
    verify_sri_hash(b"", "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
        .expect("empty sha256 should verify");
}

#[test]
fn verifies_sha384_and_sha512() {
    let data = b"hello nativelink";
    let sri384 = format!("sha384-{}", BASE64_STANDARD.encode(Sha384::digest(data)));
    verify_sri_hash(data, &sri384).expect("sha384 should verify");

    let sri512 = format!("sha512-{}", BASE64_STANDARD.encode(Sha512::digest(data)));
    verify_sri_hash(data, &sri512).expect("sha512 should verify");
}

#[test]
fn checksum_mismatch_is_aborted() {
    // Valid SRI for empty input, but the data is not empty.
    let err = verify_sri_hash(
        b"not empty",
        "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
    )
    .expect_err("mismatch should error");
    assert_eq!(err.code, Code::Aborted);
}

#[test]
fn missing_algorithm_separator_is_invalid_argument() {
    let err = verify_sri_hash(b"data", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
        .expect_err("missing '-' should error");
    assert_eq!(err.code, Code::InvalidArgument);
}

#[test]
fn unsupported_algorithm_is_invalid_argument() {
    let err = verify_sri_hash(b"data", "md5-rL0Y20zC+Fzt72VPzMSk2A==")
        .expect_err("unsupported algorithm should error");
    assert_eq!(err.code, Code::InvalidArgument);
}

#[test]
fn invalid_base64_is_invalid_argument() {
    let err = verify_sri_hash(b"data", "sha256-not valid base64!!!")
        .expect_err("invalid base64 should error");
    assert_eq!(err.code, Code::InvalidArgument);
}

fn sri_of<D: Digest>(algorithm: &str, data: &[u8]) -> String {
    format!("{algorithm}-{}", BASE64_STANDARD.encode(D::digest(data)))
}

#[test]
fn uses_the_strongest_supported_expression() {
    let data = b"hello nativelink";
    let sha512 = sri_of::<Sha512>("sha512", data);
    let wrong_sha384 = sri_of::<Sha384>("sha384", b"other data");
    // `sha1` is not an SRI algorithm and is ignored; the weaker `sha384`
    // expression is not checked, whatever the order.
    for sri in [
        format!("sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA= {sha512}"),
        format!("{wrong_sha384} {sha512}"),
        format!("{sha512}\t{wrong_sha384}"),
    ] {
        verify_sri_hash(data, &sri).unwrap_or_else(|e| panic!("{sri}: {e:?}"));
    }
}

#[test]
fn the_strongest_expression_must_match() {
    let data = b"hello nativelink";
    let sri = format!(
        "{} {}",
        sri_of::<Sha384>("sha384", data),
        sri_of::<Sha512>("sha512", b"other data")
    );
    let err = verify_sri_hash(data, &sri).expect_err("sha512 mismatch should error");
    assert_eq!(err.code, Code::Aborted);
}

#[test]
fn any_expression_of_the_strongest_algorithm_may_match() {
    let data = b"hello nativelink";
    let sri = format!(
        "{} {}",
        sri_of::<Sha512>("sha512", b"other data"),
        sri_of::<Sha512>("sha512", data)
    );
    verify_sri_hash(data, &sri).expect("the second sha512 should verify");
}

#[test]
fn options_are_ignored() {
    let data = b"hello nativelink";
    let sri = format!("{}?ct=application/x-tar", sri_of::<Sha384>("sha384", data));
    verify_sri_hash(data, &sri).expect("options should be ignored");
}

#[test]
fn no_supported_expression_is_invalid_argument() {
    for sri in [
        "",
        " ",
        "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA= md5-rL0Y20zC+Fzt72VPzMSk2A==",
    ] {
        let err = verify_sri_hash(b"data", sri).expect_err(sri);
        assert_eq!(err.code, Code::InvalidArgument, "{sri}");
    }
}

#[test]
fn malformed_supported_expression_is_invalid_argument() {
    let data = b"hello nativelink";
    let sri = format!("sha256-!!! {}", sri_of::<Sha512>("sha512", data));
    let err = verify_sri_hash(data, &sri).expect_err("bad sha256 base64 should error");
    assert_eq!(err.code, Code::InvalidArgument);
}
