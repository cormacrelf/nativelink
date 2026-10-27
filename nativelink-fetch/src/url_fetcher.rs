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

//! [`UrlFetcher`]: the leaf [`Fetcher`] that performs the actual HTTP(S)
//! download, checksum verification, and CAS upload.
//!
//! Blob downloads are streamed straight to a temp file while both the CAS
//! digest and the (optional) byte checksums are computed on the fly, so the full
//! payload is never buffered in memory. The temp file is then moved into the
//! CAS via `update_with_whole_file`.

use core::time::Duration;
use std::ffi::OsString;

use futures::StreamExt;
use nativelink_error::{Error, ResultExt, make_err};
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::{DigestHasher, DigestHasherFunc};
use nativelink_util::fs;
use nativelink_util::redact::{redact_uri, redact_uris_in_text};
use nativelink_util::sri::{ByteChecksum, ChecksumVerifier};
use nativelink_util::store_trait::{Store, StoreLike, UploadSizeInfo};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tonic::{Code, async_trait};
use tracing::{debug, info};

use crate::fetcher::{FetchBlobTask, FetchOutcome, Fetcher};

/// Default connect timeout applied to all origin fetches. Guards against
/// hanging forever on an unresponsive host when a request carries no explicit
/// `timeout`.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default per-read (idle) timeout applied to all origin fetches. Resets after
/// each successful read, so it bounds stalls during the response body rather
/// than total transfer time.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Maps a reqwest error to the appropriate gRPC code: a timeout becomes
/// `DeadlineExceeded` (per the Remote Asset API `timeout` semantics), anything
/// else becomes `NotFound`.
fn download_error_code(e: &reqwest::Error) -> Code {
    if e.is_timeout() {
        Code::DeadlineExceeded
    } else {
        Code::NotFound
    }
}

/// Sends `req` and waits for the response headers, applying `timeout` (when set)
/// to the header phase only -- `reqwest::RequestBuilder::send` resolves once the
/// response headers arrive, so streaming/reading the body afterwards is bounded
/// by the client's read (idle) timeout rather than this deadline. Also verifies
/// the HTTP status. A timeout is reported as `DeadlineExceeded`.
async fn send_awaiting_headers(
    req: reqwest::RequestBuilder,
    uri: &str,
    timeout: Option<Duration>,
) -> Result<reqwest::Response, Error> {
    let send = req.send();
    let result = match timeout {
        Some(timeout) => tokio::time::timeout(timeout, send).await.map_err(|_| {
            make_err!(
                Code::DeadlineExceeded,
                "Timed out waiting for response headers from '{uri}'"
            )
        })?,
        None => send.await,
    };
    result
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| make_err!(download_error_code(&e), "Failed to fetch '{uri}': {e}"))
}

/// Fails if `size` bytes exceed `max_size_bytes`. Called with the advertised
/// `Content-Length` to reject early, and again with the running total of bytes
/// received since a server can lie about or omit the header.
///
/// A too-large download is reported as `ResourceExhausted`: of the codes the
/// Remote Asset API documents for Fetch*, it is the one for "insufficient quota
/// of some resource", and the size cap is a server-side resource limit.
/// `InvalidArgument` would wrongly blame the request (the content's size is
/// unknown to the client) and `NotFound` would hide the real cause.
fn check_size_limit(uri: &str, size: u64, max_size_bytes: Option<u64>) -> Result<(), Error> {
    match max_size_bytes {
        Some(max) if size > max => Err(make_err!(
            Code::ResourceExhausted,
            "Download of '{uri}' exceeds the maximum allowed size of {max} bytes"
        )),
        _ => Ok(()),
    }
}

/// The outcome of attempting to download and hash a single URI.
enum FetchAttempt {
    /// The content was downloaded and its checksum (if any) verified: it was
    /// streamed to the temp file and its CAS digest computed, which this
    /// carries.
    Verified(DigestInfo),
    /// The downloaded content did not match the expected checksum. Like a
    /// download failure this is retried against the remaining URIs (a different
    /// mirror may serve correct content).
    ChecksumMismatch(Error),
    /// Downloading from this URI failed; the caller should try the next URI.
    DownloadFailed(Error),
}

/// Truncates `file` back to an empty file positioned at offset 0 so it can be
/// reused for another download attempt.
async fn reset_file(file: &mut fs::FileSlot) -> Result<(), Error> {
    file.as_ref()
        .set_len(0)
        .await
        .err_tip(|| "Failed to truncate temp file")?;
    file.rewind()
        .await
        .err_tip(|| "Failed to rewind temp file")?;
    Ok(())
}

/// One verifier per checksum, to be fed the downloaded bytes.
fn make_verifiers(checksums: &[ByteChecksum]) -> Vec<ChecksumVerifier> {
    checksums.iter().map(ChecksumVerifier::new).collect()
}

/// Discards the bytes fed to `verifiers` by a previous attempt.
fn reset_verifiers(verifiers: &mut [ChecksumVerifier]) {
    for verifier in verifiers {
        verifier.reset();
    }
}

/// Checks the bytes fed to every verifier, failing with `Aborted` on the
/// first checksum that does not match.
fn verify_all(verifiers: &mut [ChecksumVerifier]) -> Result<(), Error> {
    for verifier in verifiers {
        verifier.finalize_and_verify()?;
    }
    Ok(())
}

/// Streams `uri` into `file`, computing the CAS digest (and every checksum in
/// `verifiers`) as the bytes arrive so the full payload never has to be
/// buffered in memory.
///
/// `file` and `verifiers` are both reset before use, so the same temp file
/// and verifiers can be reused across retries against multiple URIs. On
/// `Verified` the file is left flushed and rewound to the start, ready to hand
/// to `update_with_whole_file`.
async fn stream_uri_to_file(
    req: reqwest::RequestBuilder,
    uri: &str,
    timeout: Option<Duration>,
    max_size_bytes: Option<u64>,
    verifiers: &mut [ChecksumVerifier],
    hasher_func: DigestHasherFunc,
    file: &mut fs::FileSlot,
) -> FetchAttempt {
    // Drop any bytes / hash state left over from a previous failed attempt.
    if let Err(err) = reset_file(file).await {
        return FetchAttempt::DownloadFailed(err);
    }
    reset_verifiers(verifiers);

    let response = match send_awaiting_headers(req, uri, timeout).await {
        Ok(response) => response,
        Err(err) => return FetchAttempt::DownloadFailed(err),
    };
    if let Err(err) = check_size_limit(uri, response.content_length().unwrap_or(0), max_size_bytes)
    {
        return FetchAttempt::DownloadFailed(err);
    }

    let mut received: u64 = 0;
    let mut cas_hasher = hasher_func.hasher();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(e) => {
                return FetchAttempt::DownloadFailed(make_err!(
                    download_error_code(&e),
                    "Failed to read body of '{uri}': {e}"
                ));
            }
        };
        received += chunk.len() as u64;
        if let Err(err) = check_size_limit(uri, received, max_size_bytes) {
            return FetchAttempt::DownloadFailed(err);
        }
        for verifier in verifiers.iter_mut() {
            verifier.update(chunk.as_ref());
        }
        cas_hasher.update(chunk.as_ref());
        if let Err(err) = file
            .write_all(chunk.as_ref())
            .await
            .err_tip(|| format!("Failed to write body of '{uri}' to temp file"))
        {
            return FetchAttempt::DownloadFailed(err);
        }
    }

    if let Err(err) = file
        .as_mut()
        .flush()
        .await
        .err_tip(|| "Failed to flush temp file")
    {
        return FetchAttempt::DownloadFailed(err);
    }

    // A checksum mismatch means this URI served corrupt or unexpected content.
    // A different mirror may still be correct, so report it as retryable.
    if let Err(err) = verify_all(verifiers) {
        return FetchAttempt::ChecksumMismatch(err);
    }

    let digest = cas_hasher.finalize_digest();

    // Rewind so `update_with_whole_file`'s streaming fallback (used by stores
    // that can't move the file by path) reads from the start.
    if let Err(err) = file.rewind().await.err_tip(|| "Failed to rewind temp file") {
        return FetchAttempt::DownloadFailed(err);
    }

    FetchAttempt::Verified(digest)
}

/// The leaf [`Fetcher`]: performs HTTP(S) downloads into `cas_store`.
#[derive(Debug)]
pub struct UrlFetcher {
    cas_store: Store,
    /// Directory for the temp file downloaded content is buffered to before
    /// being moved into `cas_store`. `None` uses the system temp dir.
    temp_path: Option<String>,
    /// Shared HTTP client carrying the default connect/read timeouts. Per-fetch
    /// header deadlines come from each job's `header_timeout`.
    client: reqwest::Client,
    /// Largest download accepted from any single URI. `None` is unbounded.
    max_size_bytes: Option<u64>,
}

/// Tuning for [`UrlFetcher`].
#[derive(Clone, Debug)]
pub struct UrlFetcherOptions {
    /// Directory for the temp file downloaded content is buffered to before
    /// being moved into the CAS. `None` uses the system temp dir.
    pub temp_path: Option<String>,
    /// Largest download accepted from any single URI. `None` is unbounded.
    pub max_size_bytes: Option<u64>,
    /// Connect timeout applied to all origin fetches.
    pub connect_timeout: Duration,
    /// Per-read (idle) timeout applied to all origin fetches.
    pub read_timeout: Duration,
}

impl Default for UrlFetcherOptions {
    fn default() -> Self {
        Self {
            temp_path: None,
            max_size_bytes: None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            read_timeout: DEFAULT_READ_TIMEOUT,
        }
    }
}

impl UrlFetcher {
    /// Builds a `UrlFetcher` that downloads into `cas_store`.
    pub fn new(cas_store: Store, options: UrlFetcherOptions) -> Result<Self, Error> {
        let UrlFetcherOptions {
            temp_path,
            max_size_bytes,
            connect_timeout,
            read_timeout,
        } = options;
        // Ensure the configured temp directory exists; `NamedTempFile::new_in`
        // does not create it. (The system temp dir, used when unset, always
        // exists.)
        if let Some(dir) = &temp_path {
            std::fs::create_dir_all(dir)
                .err_tip(|| format!("Could not create fetch temp_path '{dir}'"))?;
        }
        // reqwest is built without a TLS provider, so install the ring one as
        // the process default (a no-op if one is already installed).
        drop(rustls::crypto::ring::default_provider().install_default());
        let client = reqwest::Client::builder()
            .connect_timeout(connect_timeout)
            .read_timeout(read_timeout)
            .build()
            .err_tip(|| "Failed to build HTTP client in UrlFetcher")?;
        Ok(Self {
            cas_store,
            temp_path,
            client,
            max_size_bytes,
        })
    }
}

#[async_trait]
impl Fetcher for UrlFetcher {
    async fn fetch_blob(&self, job: &FetchBlobTask) -> Result<FetchOutcome, Error> {
        // One verifier per checksum; all of them must match.
        let mut verifiers = make_verifiers(&job.checksums);

        // Download into a single temp file, hashing as the bytes stream in so
        // we never hold the whole blob in memory. The same temp file is reused
        // (truncated) across URI retries.
        let temp_file = match &self.temp_path {
            Some(dir) => tempfile::NamedTempFile::new_in(dir),
            None => tempfile::NamedTempFile::new(),
        }
        .err_tip(|| "Could not create temp file for fetched blob")?;
        let temp_path = temp_file.into_temp_path();
        let path_os: OsString = temp_path.as_os_str().to_owned();
        let mut file = fs::create_file(&temp_path)
            .await
            .err_tip(|| "Could not open temp file for fetched blob")?;

        // Remembers the most recent failure so that, if every URI fails, we
        // return a meaningful error (e.g. `Aborted` on checksum mismatch,
        // `DeadlineExceeded` on timeout) rather than a generic not-found.
        let mut last_err: Option<Error> = None;
        for (idx, uri) in job.uris.iter().enumerate() {
            debug!(uri = %redact_uri(uri), idx, "Downloading fetch asset");
            let req = self.client.get(uri).headers(job.headers.for_uri(idx));
            match stream_uri_to_file(
                req,
                uri,
                job.header_timeout,
                self.max_size_bytes,
                &mut verifiers,
                job.hasher_func,
                &mut file,
            )
            .await
            {
                FetchAttempt::DownloadFailed(err) => {
                    info!(
                        uri = %redact_uri(uri),
                        code = ?err.code,
                        message = %redact_uris_in_text(&err.message_string()),
                        "Failed to download fetch asset, trying next uri"
                    );
                    last_err = Some(err);
                }
                // Corrupt content from this mirror; another URI may serve the
                // correct bytes, so try the rest before giving up.
                FetchAttempt::ChecksumMismatch(err) => {
                    info!(
                        uri = %redact_uri(uri),
                        code = ?err.code,
                        message = %redact_uris_in_text(&err.message_string()),
                        "Checksum mismatch, trying next uri"
                    );
                    last_err = Some(err);
                }
                FetchAttempt::Verified(digest) => {
                    self.cas_store
                        .update_with_whole_file(
                            digest,
                            path_os.clone(),
                            file,
                            UploadSizeInfo::ExactSize(digest.size_bytes()),
                        )
                        .await
                        .err_tip(|| "Uploading fetched blob to CAS")?;
                    debug!(
                        uri = %redact_uri(uri),
                        %digest,
                        "Downloaded fetch asset into the CAS"
                    );
                    return Ok(FetchOutcome {
                        uri: uri.clone(),
                        digest,
                    });
                }
            }
        }

        Err(last_err.unwrap_or_else(|| make_err!(Code::NotFound, "No URIs available to fetch")))
    }
}
