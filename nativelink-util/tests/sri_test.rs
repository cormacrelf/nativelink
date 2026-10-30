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
use nativelink_error::{Code, Error};
use nativelink_util::sri::{
    ByteChecksum, ChecksumVerifier, ContentHasher, ContentPin, HashAlgorithm,
    QUALIFIER_CHECKSUM_SHA1, QUALIFIER_CHECKSUM_SHA256, QUALIFIER_CHECKSUM_SHA384,
    QUALIFIER_CHECKSUM_SHA512, QUALIFIER_CHECKSUM_SRI, verify_byte_checksums, verify_sri_hash,
};
use sha2::{Digest, Sha256, Sha384, Sha512};

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

// Known vectors, each from `printf 'hello world' | <algo>sum`.
const HELLO_WORLD: &[u8] = b"hello world";
const SHA1: &str = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed";
const SHA256: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
const SHA384: &str = "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd";
const SHA512: &str = "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";

const HEX_VECTORS: [(&str, &str); 4] = [
    (QUALIFIER_CHECKSUM_SHA1, SHA1),
    (QUALIFIER_CHECKSUM_SHA256, SHA256),
    (QUALIFIER_CHECKSUM_SHA384, SHA384),
    (QUALIFIER_CHECKSUM_SHA512, SHA512),
];

fn verify_qualifier(data: &[u8], qualifier: &str, value: &str) -> Result<(), Error> {
    verify_byte_checksums(data, &ByteChecksum::from_qualifier(qualifier, value)?)
}

#[test]
fn hex_checksums_verify_each_algorithm() {
    for (qualifier, digest) in HEX_VECTORS {
        verify_qualifier(HELLO_WORLD, qualifier, digest).expect(qualifier);
    }
}

#[test]
fn hex_checksums_accept_either_case() {
    for (qualifier, digest) in HEX_VECTORS {
        verify_qualifier(HELLO_WORLD, qualifier, &digest.to_uppercase()).expect(qualifier);
        // Mixed case.
        let (head, tail) = digest.split_at(digest.len() / 2);
        let mixed = format!("{}{tail}", head.to_uppercase());
        verify_qualifier(HELLO_WORLD, qualifier, &mixed).expect(qualifier);
    }
}

#[test]
fn hex_checksums_accept_a_matching_algorithm_prefix() {
    for (qualifier, digest) in HEX_VECTORS {
        let algorithm = qualifier.strip_prefix("checksum.").unwrap();
        verify_qualifier(HELLO_WORLD, qualifier, &format!("{algorithm}:{digest}"))
            .expect(qualifier);
        verify_qualifier(
            HELLO_WORLD,
            qualifier,
            &format!("{}:{digest}", algorithm.to_uppercase()),
        )
        .expect(qualifier);
    }
}

#[test]
fn hex_checksum_mismatch_is_aborted() {
    for (qualifier, digest) in HEX_VECTORS {
        let err = verify_qualifier(b"not hello world", qualifier, digest)
            .expect_err("mismatch should error");
        assert_eq!(err.code, Code::Aborted, "{qualifier}");
    }
}

#[test]
fn hex_checksum_of_the_wrong_length_is_invalid_argument() {
    for (qualifier, digest) in HEX_VECTORS {
        for value in [
            &digest[..digest.len() - 1],
            &format!("{digest}0"),
            "",
            "sha1:",
        ] {
            let err = ByteChecksum::from_qualifier(qualifier, value)
                .expect_err("wrong length should error");
            assert_eq!(err.code, Code::InvalidArgument, "{qualifier}={value}");
        }
    }
    // A digest of one algorithm is the wrong length for another.
    let err = ByteChecksum::from_qualifier(QUALIFIER_CHECKSUM_SHA256, SHA1)
        .expect_err("a SHA-1 is not a SHA-256");
    assert_eq!(err.code, Code::InvalidArgument);
}

#[test]
fn hex_checksum_with_non_hex_characters_is_invalid_argument() {
    for (qualifier, digest) in HEX_VECTORS {
        for bad in ['g', ' ', '-', '+', '='] {
            let value = format!("{}{bad}", &digest[..digest.len() - 1]);
            let err =
                ByteChecksum::from_qualifier(qualifier, &value).expect_err("non-hex should error");
            assert_eq!(err.code, Code::InvalidArgument, "{qualifier}={value}");
        }
    }
}

#[test]
fn hex_checksum_with_a_different_algorithm_prefix_is_invalid_argument() {
    for (qualifier, digest) in HEX_VECTORS {
        for other in ["sha1", "sha256", "sha384", "sha512", "md5"] {
            if qualifier.ends_with(other) {
                continue;
            }
            let err = ByteChecksum::from_qualifier(qualifier, &format!("{other}:{digest}"))
                .expect_err("mismatched prefix should error");
            assert_eq!(err.code, Code::InvalidArgument, "{qualifier} with {other}:");
        }
    }
}

#[test]
fn unknown_qualifier_is_invalid_argument() {
    let err = ByteChecksum::from_qualifier("checksum.md5", "d41d8cd98f00b204e9800998ecf8427e")
        .expect_err("unknown qualifier should error");
    assert_eq!(err.code, Code::InvalidArgument);
}

#[test]
fn sri_and_hex_spellings_of_one_digest_are_the_same_checksum() {
    let sri = ByteChecksum::from_qualifier(
        QUALIFIER_CHECKSUM_SRI,
        "sha256-uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=",
    )
    .unwrap();
    let hex = ByteChecksum::from_qualifier(QUALIFIER_CHECKSUM_SHA256, SHA256).unwrap();
    assert_eq!(sri, hex);
}

#[test]
fn every_checksum_must_match() {
    let sha1 = ByteChecksum::from_qualifier(QUALIFIER_CHECKSUM_SHA1, SHA1).unwrap();
    let sha256 = ByteChecksum::from_qualifier(QUALIFIER_CHECKSUM_SHA256, SHA256).unwrap();
    let both = [sha1, sha256].concat();
    verify_byte_checksums(HELLO_WORLD, &both).expect("both match");
    let err = verify_byte_checksums(b"other", &both).expect_err("neither matches");
    assert_eq!(err.code, Code::Aborted);
}

#[test]
fn verifier_is_reusable_after_reset() {
    let checksum = ByteChecksum::from_qualifier(QUALIFIER_CHECKSUM_SHA1, SHA1).unwrap();
    let mut verifier = ChecksumVerifier::new(&checksum[0]);
    verifier.update(b"partial garbage");
    verifier.reset();
    verifier.update(b"hello ");
    verifier.update(b"world");
    verifier
        .finalize_and_verify()
        .expect("verifies after reset");
    // Finalizing also resets, so a failed attempt can follow.
    verifier.update(b"other");
    verifier
        .finalize_and_verify()
        .expect_err("different bytes mismatch");
}

fn sri_of<D: Digest>(algorithm: &str, data: &[u8]) -> String {
    format!("{algorithm}-{}", BASE64_STANDARD.encode(D::digest(data)))
}

#[test]
fn every_supported_algorithm_must_match() {
    let data = b"hello nativelink";
    let sha512 = sri_of::<Sha512>("sha512", data);
    let sha384 = sri_of::<Sha384>("sha384", data);
    let wrong_sha384 = sri_of::<Sha384>("sha384", b"other data");
    // `sha1` is not an SRI algorithm and is ignored.
    for sri in [
        format!("sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA= {sha512}"),
        format!("{sha384} {sha512}"),
        format!("{sha512}\t{sha384}"),
    ] {
        verify_sri_hash(data, &sri).unwrap_or_else(|e| panic!("{sri}: {e:?}"));
    }
    // A weaker algorithm is checked too, whatever the order.
    for sri in [
        format!("{wrong_sha384} {sha512}"),
        format!("{sha512} {wrong_sha384}"),
    ] {
        let err = verify_sri_hash(data, &sri).expect_err(&sri);
        assert_eq!(err.code, Code::Aborted, "{sri}");
    }
}

#[test]
fn spelling_does_not_change_the_pin() {
    let data = b"hello nativelink";
    let sha512 = sri_of::<Sha512>("sha512", data);
    let sha256 = sri_of::<Sha256>("sha256", data);
    let sha256_hex = hex::encode(Sha256::digest(data));
    let pin_of = |qualifiers: &[(&str, &str)]| {
        let checksums: Vec<ByteChecksum> = qualifiers
            .iter()
            .flat_map(|(name, value)| ByteChecksum::from_qualifier(name, value).unwrap())
            .collect();
        ContentPin::new(&checksums)
    };
    let pin = pin_of(&[(QUALIFIER_CHECKSUM_SRI, &format!("{sha256} {sha512}"))]);
    assert_eq!(
        pin,
        pin_of(&[(QUALIFIER_CHECKSUM_SRI, &format!(" {sha512}\n\t{sha256} "))])
    );
    assert_eq!(
        pin,
        pin_of(&[
            (QUALIFIER_CHECKSUM_SRI, &sha512),
            (QUALIFIER_CHECKSUM_SHA256, &sha256_hex)
        ])
    );
    let algorithms: Vec<&str> = pin.algorithms().map(|(a, _)| a.name()).collect();
    assert_eq!(algorithms, ["sha512", "sha256"]);
}

#[test]
fn a_pin_accepts_what_every_checksum_of_an_algorithm_allows() {
    let a = Sha256::digest(b"a").to_vec();
    let b = Sha256::digest(b"b").to_vec();
    let sri = format!(
        "{} {}",
        sri_of::<Sha256>("sha256", b"a"),
        sri_of::<Sha256>("sha256", b"b")
    );
    let checksums = [
        ByteChecksum::from_qualifier(QUALIFIER_CHECKSUM_SRI, &sri).unwrap(),
        ByteChecksum::from_qualifier(QUALIFIER_CHECKSUM_SHA256, &hex::encode(&b)).unwrap(),
    ]
    .concat();
    let pin = ContentPin::new(&checksums);
    assert!(pin.accepts(HashAlgorithm::Sha256, &b));
    assert!(!pin.accepts(HashAlgorithm::Sha256, &a));
    assert!(!pin.accepts(HashAlgorithm::Sha512, &b));
}

#[test]
fn a_content_hasher_computes_each_algorithm() {
    let mut hasher = ContentHasher::new([HashAlgorithm::Sha1, HashAlgorithm::Sha512]);
    hasher.update(b"hello ");
    hasher.update(b"world");
    let digests = hasher.finalize();
    assert_eq!(digests.len(), 2);
    assert_eq!(hex::encode(&digests[&HashAlgorithm::Sha1]), SHA1);
    assert_eq!(
        digests[&HashAlgorithm::Sha512],
        Sha512::digest(HELLO_WORLD).to_vec()
    );
}

#[test]
fn any_expression_of_an_algorithm_may_match() {
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
