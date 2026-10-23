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
//! The Remote Asset API's `checksum.sri` qualifier carries a Subresource
//! Integrity value, `{algorithm}-{base64}`, for example
//! `sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=`, or several such
//! expressions separated by whitespace. It parses into a [`ByteChecksum`],
//! which a [`ChecksumVerifier`] checks incrementally as the bytes arrive.

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use nativelink_error::{Code, Error, make_err, make_input_err};
use sha2::{Digest, Sha256, Sha384, Sha512};

/// The Remote Asset API qualifier name carrying an SRI checksum.
pub const QUALIFIER_CHECKSUM_SRI: &str = "checksum.sri";

/// A hash algorithm a byte checksum can use, weakest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    /// The algorithm's lowercase name, as used in SRI values.
    const fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    /// The algorithm named by an SRI value.
    fn from_sri_name(name: &str) -> Option<Self> {
        match name {
            "sha256" => Some(Self::Sha256),
            "sha384" => Some(Self::Sha384),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    fn hasher(self) -> ByteHasher {
        match self {
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
}

/// The running hash state for a [`ChecksumVerifier`], one variant per
/// supported algorithm.
#[derive(Debug)]
enum ByteHasher {
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
            ByteHasher::Sha256(h) => Digest::update(h, data),
            ByteHasher::Sha384(h) => Digest::update(h, data),
            ByteHasher::Sha512(h) => Digest::update(h, data),
        }
    }

    /// Resets the hasher to its initial state, discarding any data fed so far.
    /// Useful for reusing one verifier across multiple download attempts.
    pub fn reset(&mut self) {
        match &mut self.hasher {
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
