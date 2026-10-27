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

//! Checksums over the raw bytes of a downloaded file.
//!
//! The Remote Asset API qualifiers handled here come in two spellings of the
//! same idea:
//!
//! - `checksum.sri`: a Subresource Integrity value, `{algorithm}-{base64}`,
//!   for example `sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=`, or
//!   several such expressions separated by whitespace.
//! - `checksum.sha1`, `checksum.sha256`, `checksum.sha384` and
//!   `checksum.sha512`: the digest as hex, as lockfiles and registries record
//!   it (Cargo, pip, Maven, Composer, ...), optionally prefixed with the
//!   algorithm (`sha256:...`).
//!
//! Both parse into a [`ByteChecksum`], which a [`ChecksumVerifier`] checks
//! incrementally as the bytes arrive.

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use nativelink_error::{Code, Error, make_err, make_input_err};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// The Remote Asset API qualifier name carrying an SRI checksum.
pub const QUALIFIER_CHECKSUM_SRI: &str = "checksum.sri";

/// The qualifier names carrying a hex digest, one per algorithm.
pub const QUALIFIER_CHECKSUM_SHA1: &str = "checksum.sha1";
pub const QUALIFIER_CHECKSUM_SHA256: &str = "checksum.sha256";
pub const QUALIFIER_CHECKSUM_SHA384: &str = "checksum.sha384";
pub const QUALIFIER_CHECKSUM_SHA512: &str = "checksum.sha512";

/// The qualifiers that carry a hex digest.
pub const HEX_CHECKSUM_QUALIFIERS: &[&str] = &[
    QUALIFIER_CHECKSUM_SHA1,
    QUALIFIER_CHECKSUM_SHA256,
    QUALIFIER_CHECKSUM_SHA384,
    QUALIFIER_CHECKSUM_SHA512,
];

/// Every qualifier that carries a [`ByteChecksum`].
pub const BYTE_CHECKSUM_QUALIFIERS: &[&str] = &[
    QUALIFIER_CHECKSUM_SRI,
    QUALIFIER_CHECKSUM_SHA1,
    QUALIFIER_CHECKSUM_SHA256,
    QUALIFIER_CHECKSUM_SHA384,
    QUALIFIER_CHECKSUM_SHA512,
];

/// A hash algorithm a byte checksum can use, weakest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    /// The algorithm's lowercase name, as used in SRI values and hex prefixes.
    const fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    /// The length of a digest in bytes.
    const fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// The algorithm named by an SRI value (SHA-1 is not valid SRI).
    fn from_sri_name(name: &str) -> Option<Self> {
        match name {
            "sha256" => Some(Self::Sha256),
            "sha384" => Some(Self::Sha384),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// The algorithm whose hex digest the qualifier `name` carries.
    fn from_hex_qualifier(name: &str) -> Option<Self> {
        match name {
            QUALIFIER_CHECKSUM_SHA1 => Some(Self::Sha1),
            QUALIFIER_CHECKSUM_SHA256 => Some(Self::Sha256),
            QUALIFIER_CHECKSUM_SHA384 => Some(Self::Sha384),
            QUALIFIER_CHECKSUM_SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    fn hasher(self) -> ByteHasher {
        match self {
            Self::Sha1 => ByteHasher::Sha1(Sha1::new()),
            Self::Sha256 => ByteHasher::Sha256(Sha256::new()),
            Self::Sha384 => ByteHasher::Sha384(Sha384::new()),
            Self::Sha512 => ByteHasher::Sha512(Sha512::new()),
        }
    }
}

/// An expected digest over the raw bytes of a download: the algorithm and the
/// digest bytes, however the request spelled them. An SRI value may give more
/// than one digest of its strongest algorithm, any of which the bytes may
/// match.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ByteChecksum {
    algorithm: HashAlgorithm,
    expected: Vec<Vec<u8>>,
}

impl ByteChecksum {
    /// Parses the value of any qualifier in [`BYTE_CHECKSUM_QUALIFIERS`].
    /// Returns `InvalidArgument` if the value is malformed or `qualifier` is
    /// not one of them.
    pub fn from_qualifier(qualifier: &str, value: &str) -> Result<Self, Error> {
        if qualifier == QUALIFIER_CHECKSUM_SRI {
            return Self::from_sri(value);
        }
        let algorithm = HashAlgorithm::from_hex_qualifier(qualifier)
            .ok_or_else(|| make_input_err!("'{qualifier}' is not a checksum qualifier"))?;
        Self::from_hex(algorithm, value).map_err(|e| e.append(format!("In '{qualifier}'")))
    }

    /// Parses an SRI value: whitespace-separated hash expressions
    /// `{algorithm}-{base64-digest}`, each optionally followed by `?options`.
    /// As the SRI spec has it, options are ignored, as are expressions whose
    /// algorithm is not one of `sha256`, `sha384` or `sha512`, and only the
    /// expressions of the strongest algorithm left count: the bytes must match
    /// one of them. Returns `InvalidArgument` if no expression has a supported
    /// algorithm, or if one that does has a digest that is not valid base64,
    /// even when a stronger one would be used: such a value is a mistake that
    /// should not go unnoticed.
    pub fn from_sri(sri_value: &str) -> Result<Self, Error> {
        let mut strongest: Option<Self> = None;
        for expression in sri_value.split_whitespace() {
            let hash = expression
                .split_once('?')
                .map_or(expression, |(hash, _options)| hash);
            let Some((name, expected_b64)) = hash.split_once('-') else {
                continue;
            };
            let Some(algorithm) = HashAlgorithm::from_sri_name(name) else {
                continue;
            };
            let expected = BASE64_STANDARD.decode(expected_b64).map_err(|e| {
                make_input_err!("Invalid base64 in SRI checksum '{sri_value}': {e}")
            })?;
            match &mut strongest {
                Some(current) if current.algorithm > algorithm => {}
                Some(current) if current.algorithm == algorithm => {
                    current.expected.push(expected);
                }
                _ => {
                    strongest = Some(Self {
                        algorithm,
                        expected: vec![expected],
                    });
                }
            }
        }
        strongest.ok_or_else(|| {
            make_input_err!(
                "No supported hash expression in SRI checksum '{sri_value}': expected sha256, sha384 or sha512"
            )
        })
    }

    /// Parses a hex digest of `algorithm`: exactly the digest's length in
    /// hex characters, in either case, optionally preceded by `{algorithm}:`
    /// (as in pip's `sha256:...`). Returns `InvalidArgument` otherwise,
    /// including when the prefix names a different algorithm.
    fn from_hex(algorithm: HashAlgorithm, value: &str) -> Result<Self, Error> {
        let name = algorithm.name();
        let digits = match value.split_once(':') {
            Some((prefix, digits)) if prefix.eq_ignore_ascii_case(name) => digits,
            Some((prefix, _)) => {
                return Err(make_input_err!(
                    "Expected a {name} digest but the value has prefix '{prefix}:'"
                ));
            }
            None => value,
        };
        let expected_chars = algorithm.digest_len() * 2;
        if digits.len() != expected_chars {
            return Err(make_input_err!(
                "A {name} digest is {expected_chars} hex characters, got {}",
                digits.len()
            ));
        }
        let expected = hex::decode(digits)
            .map_err(|e| make_input_err!("Invalid hex in {name} checksum '{value}': {e}"))?;
        Ok(Self {
            algorithm,
            expected: vec![expected],
        })
    }
}

/// The running hash state for a [`ChecksumVerifier`], one variant per
/// supported algorithm.
#[derive(Debug)]
enum ByteHasher {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

/// Incrementally verifies a stream of bytes against a [`ByteChecksum`].
///
/// This lets callers hash data as it arrives (for example while downloading a
/// file) instead of buffering the whole payload in memory before hashing.
/// Create one with [`ChecksumVerifier::new`], feed bytes with
/// [`ChecksumVerifier::update`], then check the result with
/// [`ChecksumVerifier::finalize_and_verify`].
#[derive(Debug)]
pub struct ChecksumVerifier {
    checksum: ByteChecksum,
    hasher: ByteHasher,
}

impl ChecksumVerifier {
    /// Prepares a hasher for `checksum`'s algorithm.
    #[must_use]
    pub fn new(checksum: &ByteChecksum) -> Self {
        Self {
            hasher: checksum.algorithm.hasher(),
            checksum: checksum.clone(),
        }
    }

    /// Feeds an additional chunk of data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.hasher {
            ByteHasher::Sha1(h) => Digest::update(h, data),
            ByteHasher::Sha256(h) => Digest::update(h, data),
            ByteHasher::Sha384(h) => Digest::update(h, data),
            ByteHasher::Sha512(h) => Digest::update(h, data),
        }
    }

    /// Resets the hasher to its initial state, discarding any data fed so far.
    /// Useful for reusing one verifier across multiple download attempts.
    pub fn reset(&mut self) {
        match &mut self.hasher {
            ByteHasher::Sha1(h) => Digest::reset(h),
            ByteHasher::Sha256(h) => Digest::reset(h),
            ByteHasher::Sha384(h) => Digest::reset(h),
            ByteHasher::Sha512(h) => Digest::reset(h),
        }
    }

    /// Finalizes the hash and compares it against the expected digest, then
    /// resets the hasher so it can be reused for another attempt. Returns
    /// `Aborted` if the computed hash does not match.
    pub fn finalize_and_verify(&mut self) -> Result<(), Error> {
        let actual = match &mut self.hasher {
            ByteHasher::Sha1(h) => h.finalize_reset().to_vec(),
            ByteHasher::Sha256(h) => h.finalize_reset().to_vec(),
            ByteHasher::Sha384(h) => h.finalize_reset().to_vec(),
            ByteHasher::Sha512(h) => h.finalize_reset().to_vec(),
        };

        if self.checksum.expected.contains(&actual) {
            Ok(())
        } else {
            let expected: Vec<String> = self.checksum.expected.iter().map(hex::encode).collect();
            Err(make_err!(
                Code::Aborted,
                "Checksum mismatch for algorithm '{}': expected '{}', got '{}'",
                self.checksum.algorithm.name(),
                expected.join("' or '"),
                hex::encode(&actual)
            ))
        }
    }
}

/// Verifies that `data` matches every checksum in `checksums`. Returns
/// `Aborted` if any computed hash does not match its expected digest.
///
/// This is a convenience for callers that already hold the entire payload in
/// memory.
pub fn verify_byte_checksums(data: &[u8], checksums: &[ByteChecksum]) -> Result<(), Error> {
    for checksum in checksums {
        let mut verifier = ChecksumVerifier::new(checksum);
        verifier.update(data);
        verifier.finalize_and_verify()?;
    }
    Ok(())
}

/// Verifies that `data` matches the given SRI checksum value.
///
/// The `sri_value` is parsed as [`ByteChecksum::from_sri`] describes. Returns
/// `InvalidArgument` if the value cannot be parsed and `Aborted` if the
/// computed hash does not match the expected digest.
pub fn verify_sri_hash(data: &[u8], sri_value: &str) -> Result<(), Error> {
    verify_byte_checksums(data, &[ByteChecksum::from_sri(sri_value)?])
}
