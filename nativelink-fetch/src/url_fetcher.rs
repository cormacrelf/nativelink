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
//!
//! Directory archives are never held or stored in full: the response body is
//! checksummed and size-capped as it is pulled through the archive expander,
//! which uploads each file to the CAS as it is read (see
//! [`crate::archive_expander`]).

use core::future::Future;
use core::time::Duration;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

use futures::StreamExt;
use nativelink_error::{Error, ResultExt, make_err, make_input_err};
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::{DigestHasher, DigestHasherFunc};
use nativelink_util::fs;
use nativelink_util::redact::{redact_uri, redact_uris_in_text};
use nativelink_util::sri::{ByteChecksum, ChecksumVerifier};
use nativelink_util::store_trait::{Store, StoreLike, UploadSizeInfo};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio_util::io::StreamReader;
use tonic::{Code, async_trait};
use tracing::{debug, info};

use crate::archive_expander::{
    ArchiveLimits, ArchiveOptions, DEFAULT_INLINE_THRESHOLD, extract_archive,
};
use crate::fetcher::{DirectoryChecksum, FetchBlobTask, FetchDirectoryJob, FetchOutcome, Fetcher};
use crate::tree_hash::{TreeHashContext, TreeHashFailure, TreeHashSet};

/// Default connect timeout applied to all origin fetches. Guards against
/// hanging forever on an unresponsive host when a request carries no explicit
/// `timeout`.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default per-read (idle) timeout applied to all origin fetches. Resets after
/// each successful read, so it bounds stalls during the response body rather
/// than total transfer time.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Most redirects followed for a single request. This is reqwest's own default,
/// stated here so the policy does not change under a dependency update.
pub const MAX_REDIRECTS: usize = 10;

/// Decides whether to follow a redirect to `next` after the hops in `previous`
/// (the requested URL first, the URL being redirected from last). Refuses
/// after [`MAX_REDIRECTS`] hops and refuses to leave https for http: a request
/// for a pinned or private asset must not be silently downgraded to a channel
/// anyone on the path can read or rewrite. Hosts are named in the message,
/// never full URLs, which may carry credentials in their query.
fn check_redirect(previous: &[reqwest::Url], next: &reqwest::Url) -> Result<(), String> {
    if previous.len() > MAX_REDIRECTS {
        return Err(format!("too many redirects (more than {MAX_REDIRECTS})"));
    }
    if let Some(from) = previous.last()
        && from.scheme() == "https"
        && next.scheme() != "https"
    {
        return Err(format!(
            "refusing to follow a redirect from https://{} to insecure {}://{}",
            from.host_str().unwrap_or(""),
            next.scheme(),
            next.host_str().unwrap_or(""),
        ));
    }
    Ok(())
}

/// The redirect policy of the HTTP client: follow up to [`MAX_REDIRECTS`]
/// redirects, but never from https to http. As with reqwest's default,
/// credentials (`Authorization`, `Cookie`, ...) are stripped when a redirect
/// goes to another origin: that happens in reqwest whatever the policy.
fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        match check_redirect(attempt.previous(), attempt.url()) {
            Ok(()) => attempt.follow(),
            Err(message) => attempt.error(message),
        }
    })
}

/// Describes a reqwest error. A redirect refused by our policy only names the
/// reason in its source, which `Display` leaves out, so it is appended.
fn describe_error(e: &reqwest::Error) -> String {
    use std::error::Error as _;
    match e.source() {
        Some(source) if e.is_redirect() => format!("{e}: {source}"),
        _ => e.to_string(),
    }
}

/// Default cap on the total duration of one fetch: all URI attempts, the
/// download, archive expansion, verification and the CAS upload. A request's
/// `timeout` can only shorten it.
pub const DEFAULT_MAX_FETCH_DURATION: Duration = Duration::from_hours(1);

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

/// Sends `req` and waits for the response headers, then verifies the HTTP
/// status. There is no deadline here beyond the client's connect timeout: the
/// time a whole fetch may take is bounded once, around the fetch, by
/// [`UrlFetcher`]. A reqwest timeout is reported as `DeadlineExceeded`.
async fn send_awaiting_headers(
    req: reqwest::RequestBuilder,
    uri: &str,
) -> Result<reqwest::Response, Error> {
    req.send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| {
            make_err!(
                download_error_code(&e),
                "Failed to fetch '{uri}': {}",
                describe_error(&e)
            )
        })
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
    /// The content was downloaded and its checksum (if any) verified. For a
    /// blob it was streamed to the temp file and its CAS digest computed; for a
    /// directory it was expanded into the CAS. Carries the CAS digest (of the
    /// blob, or of the root `Directory`).
    Verified(DigestInfo),
    /// The downloaded content did not match the expected checksum. Like a
    /// download failure this is retried against the remaining URIs (a different
    /// mirror may serve correct content).
    ChecksumMismatch(Error),
    /// Downloading (or, for a directory, expanding) from this URI failed; the
    /// caller should try the next URI.
    DownloadFailed(Error),
    /// A directory checksum cannot be checked against the archive this URI
    /// served (`FailedPrecondition`). Not a mismatch: it says nothing about
    /// the content. Another URI may serve an archive that can be checked.
    Unverifiable(Error),
}

/// Reports a malformed archive, which the expander calls `InvalidArgument`, as
/// `Aborted`. The origin served bad content, so it is not the request that is
/// invalid, and `InvalidArgument` is what a fetcher uses to reject a request,
/// which the server returns as an RPC error rather than in the response status.
/// `Aborted` is the Remote Asset API's code for an asset failing a consistency
/// check. Other codes are left as they are.
fn origin_content_fault(mut err: Error) -> Error {
    if err.code == Code::InvalidArgument {
        err.code = Code::Aborted;
    }
    err
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

    let response = match send_awaiting_headers(req, uri).await {
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

/// An explicit HTTP forward proxy for a [`UrlFetcher`] to send its requests
/// through, validated at construction.
///
/// The proxy URL may carry credentials, so it is kept out of every `Debug`
/// output and error message.
#[derive(Clone)]
pub struct ProxySettings {
    /// The proxy URL, parseable, `http` or `https`, with a host. A secret.
    url: String,
    /// Hosts that bypass the proxy, in `reqwest`'s `NO_PROXY` syntax.
    no_proxy: Vec<String>,
}

impl core::fmt::Debug for ProxySettings {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProxySettings")
            .field("url", &"<redacted>")
            .field("no_proxy", &self.no_proxy)
            .finish()
    }
}

impl ProxySettings {
    /// Resolves the proxy configuration of a `url` fetcher: the URL is
    /// `http_proxy`, or the whitespace-trimmed contents of
    /// `http_proxy_secret_file` (read now, once). Returns `None` when neither
    /// is set. Setting both, an unreadable or empty file and a URL that is not
    /// a plain `http`/`https` URL with a host are errors, none of which repeat
    /// the URL since it may contain a password.
    pub fn from_config(
        http_proxy: Option<&str>,
        http_proxy_secret_file: Option<&str>,
        no_proxy: &[String],
    ) -> Result<Option<Self>, Error> {
        let (url, source) = match (http_proxy, http_proxy_secret_file) {
            (Some(_), Some(_)) => {
                return Err(make_input_err!(
                    "'http_proxy' and 'http_proxy_secret_file' cannot both be set"
                ));
            }
            (None, None) => return Ok(None),
            (Some(url), None) => (url.trim().to_owned(), "'http_proxy'"),
            (None, Some(path)) => {
                let contents = std::fs::read_to_string(path).map_err(|e| {
                    make_input_err!("Could not read 'http_proxy_secret_file' '{path}': {e}")
                })?;
                (
                    contents.trim().to_owned(),
                    "the contents of 'http_proxy_secret_file'",
                )
            }
        };
        let parsed = reqwest::Url::parse(&url)
            .map_err(|_| make_input_err!("{source} is not a valid URL"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(make_input_err!(
                "{source} must be an http:// or https:// URL"
            ));
        }
        if parsed.host_str().is_none_or(str::is_empty) {
            return Err(make_input_err!("{source} must name a proxy host"));
        }
        Ok(Some(Self {
            url,
            no_proxy: no_proxy.to_vec(),
        }))
    }

    /// The reqwest proxy that sends all traffic through the proxy, except to
    /// the `no_proxy` hosts.
    fn to_reqwest(&self) -> Result<reqwest::Proxy, Error> {
        let proxy = reqwest::Proxy::all(self.url.as_str())
            .map_err(|_| make_input_err!("The fetch proxy URL is not usable as a proxy"))?;
        Ok(if self.no_proxy.is_empty() {
            proxy
        } else {
            proxy.no_proxy(reqwest::NoProxy::from_string(&self.no_proxy.join(",")))
        })
    }
}

/// The leaf [`Fetcher`]: performs HTTP(S) downloads into `cas_store`.
///
/// `Debug` is implemented by hand, leaving out the HTTP client, because the
/// client's `Debug` output lists its proxies, URL credentials included.
pub struct UrlFetcher {
    cas_store: Store,
    /// Directory for the temp file downloaded content is buffered to before
    /// being moved into `cas_store`. `None` uses the system temp dir.
    temp_path: Option<String>,
    /// Shared HTTP client carrying the default connect/read timeouts. The
    /// time a whole fetch may take is bounded separately, by `max_fetch_duration`
    /// and each job's `timeout`.
    client: reqwest::Client,
    /// Whether a job must carry a checksum for anything to be downloaded.
    require_checksum: bool,
    /// Whether `client` sends requests through a proxy (the URL is not kept).
    proxy_configured: bool,
    /// Cap on the total duration of any fetch, whatever the job asks for.
    max_fetch_duration: Duration,
    /// Largest download accepted from any single URI. `None` is unbounded.
    max_size_bytes: Option<u64>,
    /// Archive files up to this many bytes are held in memory while being
    /// uploaded; larger ones go through a temp file.
    archive_entry_inline_threshold: u64,
    /// Most entries accepted in an archive. `None` is unbounded.
    max_archive_entries: Option<usize>,
    /// Most decompressed bytes accepted from an archive. `None` is unbounded.
    max_archive_uncompressed_bytes: Option<u64>,
}

/// Tuning for [`UrlFetcher`].
#[derive(Clone, Debug)]
pub struct UrlFetcherOptions {
    /// Directory for the temp file downloaded content is buffered to before
    /// being moved into the CAS. `None` uses the system temp dir.
    pub temp_path: Option<String>,
    /// Largest download accepted from any single URI. `None` is unbounded.
    pub max_size_bytes: Option<u64>,
    /// Archive files up to this many bytes are held in memory while being
    /// uploaded; larger ones go through a temp file. `None` uses the default.
    pub archive_entry_inline_threshold_bytes: Option<u64>,
    /// Most entries accepted in an archive. `None` is unbounded.
    pub max_archive_entries: Option<usize>,
    /// Most decompressed bytes accepted from an archive. `None` is unbounded.
    pub max_archive_uncompressed_bytes: Option<u64>,
    /// Reject a job that has no checksum, before contacting any origin.
    pub require_checksum: bool,
    /// The forward proxy to fetch through. `None` connects directly. The
    /// `HTTP_PROXY`-style environment variables are never consulted.
    pub proxy: Option<ProxySettings>,
    /// Cap on the total duration of a fetch. A job's `timeout` can only
    /// shorten it. Must not be zero.
    pub max_fetch_duration: Duration,
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
            archive_entry_inline_threshold_bytes: None,
            max_archive_entries: None,
            max_archive_uncompressed_bytes: None,
            require_checksum: false,
            proxy: None,
            max_fetch_duration: DEFAULT_MAX_FETCH_DURATION,
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
            archive_entry_inline_threshold_bytes,
            max_archive_entries,
            max_archive_uncompressed_bytes,
            require_checksum,
            proxy,
            max_fetch_duration,
            connect_timeout,
            read_timeout,
        } = options;
        if max_fetch_duration.is_zero() {
            return Err(make_err!(
                Code::InvalidArgument,
                "'max_fetch_duration_s' must be greater than zero"
            ));
        }
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
        // `no_proxy()` first: it turns off reqwest's reading of the proxy
        // environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`,
        // `NO_PROXY`), so the only proxy is the configured one, if any.
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(connect_timeout)
            .redirect(redirect_policy())
            .read_timeout(read_timeout);
        if let Some(proxy) = &proxy {
            builder = builder.proxy(proxy.to_reqwest()?);
        }
        let client = builder.build().map_err(|e| {
            make_err!(
                Code::Internal,
                "Failed to build HTTP client in UrlFetcher: {}",
                redact_uris_in_text(&e.to_string())
            )
        })?;
        Ok(Self {
            cas_store,
            temp_path,
            client,
            require_checksum,
            proxy_configured: proxy.is_some(),
            max_fetch_duration,
            max_size_bytes,
            archive_entry_inline_threshold: archive_entry_inline_threshold_bytes
                .unwrap_or(DEFAULT_INLINE_THRESHOLD),
            max_archive_entries,
            max_archive_uncompressed_bytes,
        })
    }

    /// Fails a blob job that has no checksum when `require_checksum` is set.
    /// `InvalidArgument`: it is the request that is wrong, which the Remote
    /// Asset API reports as an RPC error, not in the response status.
    fn check_blob_checksum(&self, job: &FetchBlobTask) -> Result<(), Error> {
        if self.require_checksum && job.checksums.is_empty() {
            return Err(make_input_err!(
                "This server only fetches content the request gives a checksum for, and the \
                 request has none: set the checksum.sri qualifier or a hex checksum.sha* \
                 qualifier"
            ));
        }
        Ok(())
    }

    /// Fails a directory job that has no checksum of any kind when
    /// `require_checksum` is set. See [`Self::check_blob_checksum`].
    fn check_directory_checksum(&self, job: &FetchDirectoryJob) -> Result<(), Error> {
        if self.require_checksum && job.checksums.is_empty() {
            return Err(make_input_err!(
                "This server only fetches content the request gives a checksum for, and the \
                 request has none: set the checksum.sri qualifier, a hex checksum.sha* \
                 qualifier or a tree hash such as checksum.h1"
            ));
        }
        Ok(())
    }

    /// The time budget for a job with `job_timeout`: the smaller of it and the
    /// cap.
    fn budget(&self, job_timeout: Option<Duration>) -> Duration {
        job_timeout.map_or(self.max_fetch_duration, |timeout| {
            timeout.min(self.max_fetch_duration)
        })
    }

    /// Streams the archive at `uri` through the archive expander, which uploads its
    /// files to the CAS as they are read. Every byte of the response is counted
    /// against `max_size_bytes` and fed to `verifiers` on its way
    /// to the expander, which reads the response to its end. The tree hashes
    /// among `checksums` are computed in the same pass, as the expander
    /// reports each entry, and checked once it is done.
    ///
    /// `verifiers` are reset before use, so the same ones can be reused across
    /// retries against multiple URIs.
    async fn stream_uri_to_directory(
        &self,
        req: reqwest::RequestBuilder,
        uri: &str,
        verifiers: &mut [ChecksumVerifier],
        checksums: &[DirectoryChecksum],
        options: &ArchiveOptions,
    ) -> FetchAttempt {
        let max_size_bytes = self.max_size_bytes;
        reset_verifiers(verifiers);

        let response = match send_awaiting_headers(req, uri).await {
            Ok(response) => response,
            Err(err) => return FetchAttempt::DownloadFailed(err),
        };
        if let Err(err) =
            check_size_limit(uri, response.content_length().unwrap_or(0), max_size_bytes)
        {
            return FetchAttempt::DownloadFailed(err);
        }

        // The expander reports a failing body as a malformed archive, so remember
        // the real cause here.
        let mut source_err: Option<Error> = None;
        let mut received: u64 = 0;
        let body = Box::pin(response.bytes_stream().map(|chunk| {
            let chunk = chunk
                .map_err(|e| {
                    make_err!(
                        download_error_code(&e),
                        "Failed to read body of '{uri}': {e}"
                    )
                })
                .and_then(|chunk| {
                    received += chunk.len() as u64;
                    check_size_limit(uri, received, max_size_bytes)?;
                    Ok(chunk)
                });
            match chunk {
                Ok(chunk) => {
                    for verifier in verifiers.iter_mut() {
                        verifier.update(chunk.as_ref());
                    }
                    Ok(chunk)
                }
                Err(err) => {
                    let io_err = io::Error::other(err.message_string());
                    source_err = Some(err);
                    Err(io_err)
                }
            }
        }));
        let tree_checksums = checksums.iter().filter_map(|checksum| match checksum {
            DirectoryChecksum::Tree(checksum) => Some(checksum),
            DirectoryChecksum::Bytes(_) => None,
        });
        let context = TreeHashContext {
            hasher_func: options.hasher_func,
            temp_dir: options.temp_dir.clone(),
        };
        let mut tree_hashes = TreeHashSet::new(tree_checksums, &context);
        let mut reader = StreamReader::new(body);
        let result = extract_archive(
            &mut reader,
            self.cas_store.as_pin(),
            options,
            &mut tree_hashes,
        )
        .await;
        drop(reader);

        if let Some(err) = source_err {
            return FetchAttempt::DownloadFailed(err);
        }
        let tree = match result {
            Ok(tree) => tree,
            Err(err) => {
                return FetchAttempt::DownloadFailed(origin_content_fault(
                    err.append(format!("Expanding directory archive fetched from '{uri}'")),
                ));
            }
        };

        if let Err(err) = verify_all(verifiers) {
            return FetchAttempt::ChecksumMismatch(err);
        }
        match tree_hashes.finish(&tree.listing).await {
            Ok(()) => FetchAttempt::Verified(tree.root_digest),
            Err(TreeHashFailure::Mismatch(err)) => FetchAttempt::ChecksumMismatch(err),
            Err(TreeHashFailure::Unverifiable(err)) => FetchAttempt::Unverifiable(err),
            Err(TreeHashFailure::Failed(err)) => {
                FetchAttempt::DownloadFailed(origin_content_fault(
                    err.append(format!("Checking the directory fetched from '{uri}'")),
                ))
            }
        }
    }
}

/// Runs `fetch` for at most `budget`, failing with `DeadlineExceeded` when it
/// runs out. The future is dropped on expiry, which closes the connection and
/// deletes the temp files (they are `TempPath`s, removed on drop).
async fn within_budget(
    budget: Duration,
    what: &str,
    fetch: impl Future<Output = Result<FetchOutcome, Error>>,
) -> Result<FetchOutcome, Error> {
    tokio::time::timeout(budget, fetch).await.map_err(|_| {
        make_err!(
            Code::DeadlineExceeded,
            "Fetching the {what} did not finish within {budget:?}, the smaller of the request's \
             timeout and the fetcher's max_fetch_duration_s"
        )
    })?
}

impl core::fmt::Debug for UrlFetcher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The client is left out: its Debug output prints the proxy URL.
        f.debug_struct("UrlFetcher")
            .field("cas_store", &self.cas_store)
            .field("temp_path", &self.temp_path)
            .field("require_checksum", &self.require_checksum)
            .field("proxy_configured", &self.proxy_configured)
            .field("max_fetch_duration", &self.max_fetch_duration)
            .field("max_size_bytes", &self.max_size_bytes)
            .field(
                "archive_entry_inline_threshold",
                &self.archive_entry_inline_threshold,
            )
            .field("max_archive_entries", &self.max_archive_entries)
            .field(
                "max_archive_uncompressed_bytes",
                &self.max_archive_uncompressed_bytes,
            )
            .finish_non_exhaustive()
    }
}

impl UrlFetcher {
    async fn fetch_blob_unbounded(&self, job: &FetchBlobTask) -> Result<FetchOutcome, Error> {
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
                // correct bytes, so try the rest before giving up. (Only a
                // directory can be unverifiable.)
                FetchAttempt::ChecksumMismatch(err) | FetchAttempt::Unverifiable(err) => {
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

    async fn fetch_directory_unbounded(
        &self,
        job: &FetchDirectoryJob,
    ) -> Result<FetchOutcome, Error> {
        // As for blobs, one verifier per byte checksum. Those are over the
        // raw archive bytes; the tree checksums are over the files in it. All
        // of them must match.
        let byte_checksums: Vec<ByteChecksum> = job
            .checksums
            .iter()
            .filter_map(|checksum| match checksum {
                DirectoryChecksum::Bytes(checksum) => Some(checksum.clone()),
                DirectoryChecksum::Tree(_) => None,
            })
            .collect();
        let mut verifiers = make_verifiers(&byte_checksums);
        let mut options = ArchiveOptions::new(job.hasher_func);
        options.inline_threshold = self.archive_entry_inline_threshold;
        options.limits = ArchiveLimits {
            max_entries: self.max_archive_entries,
            max_total_uncompressed_bytes: self.max_archive_uncompressed_bytes,
        };
        options.temp_dir = self.temp_path.as_ref().map(PathBuf::from);

        // Remembers the most recent failure so that, if every URI fails, we
        // return a meaningful error rather than a generic not-found. An
        // archive whose checksum cannot be checked is reported only when no
        // URI failed in another way.
        let mut last_err: Option<Error> = None;
        let mut last_unverifiable: Option<Error> = None;
        for (idx, uri) in job.uris.iter().enumerate() {
            debug!(uri = %redact_uri(uri), idx, "Downloading fetch directory archive");
            let req = self.client.get(uri).headers(job.headers.for_uri(idx));
            match self
                .stream_uri_to_directory(req, uri, &mut verifiers, &job.checksums, &options)
                .await
            {
                FetchAttempt::Verified(digest) => {
                    return Ok(FetchOutcome {
                        uri: uri.clone(),
                        digest,
                    });
                }
                FetchAttempt::DownloadFailed(err) => {
                    info!(
                        uri = %redact_uri(uri),
                        code = ?err.code,
                        message = %redact_uris_in_text(&err.message_string()),
                        "Failed to fetch directory archive, trying next uri"
                    );
                    last_err = Some(err);
                }
                // Blobs the bad archive left in the CAS are simply unused and
                // age out of it.
                FetchAttempt::ChecksumMismatch(err) => {
                    info!(
                        uri = %redact_uri(uri),
                        code = ?err.code,
                        message = %redact_uris_in_text(&err.message_string()),
                        "Checksum mismatch, trying next uri"
                    );
                    last_err = Some(err);
                }
                FetchAttempt::Unverifiable(err) => {
                    info!(
                        uri = %redact_uri(uri),
                        code = ?err.code,
                        message = %redact_uris_in_text(&err.message_string()),
                        "Checksum cannot be checked against this archive, trying next uri"
                    );
                    last_unverifiable = Some(err);
                }
            }
        }

        Err(last_err
            .or(last_unverifiable)
            .unwrap_or_else(|| make_err!(Code::NotFound, "No URIs available to fetch")))
    }
}

#[async_trait]
impl Fetcher for UrlFetcher {
    async fn fetch_blob(&self, job: &FetchBlobTask) -> Result<FetchOutcome, Error> {
        self.check_blob_checksum(job)?;
        within_budget(
            self.budget(job.timeout),
            "blob",
            self.fetch_blob_unbounded(job),
        )
        .await
    }

    async fn fetch_directory(&self, job: &FetchDirectoryJob) -> Result<FetchOutcome, Error> {
        self.check_directory_checksum(job)?;
        within_budget(
            self.budget(job.timeout),
            "directory",
            self.fetch_directory_unbounded(job),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> reqwest::Url {
        reqwest::Url::parse(s).unwrap()
    }

    #[test]
    fn https_to_http_redirect_is_refused_with_a_clear_message() {
        let err = check_redirect(
            &[url("https://a.example/x?token=s3cret")],
            &url("http://b.example/y"),
        )
        .unwrap_err();
        assert_eq!(
            err,
            "refusing to follow a redirect from https://a.example to insecure http://b.example"
        );
    }

    #[test]
    fn upgrades_and_same_scheme_redirects_are_allowed() {
        assert!(check_redirect(&[url("http://a.example/")], &url("https://a.example/")).is_ok());
        assert!(check_redirect(&[url("http://a.example/")], &url("http://b.example/")).is_ok());
        assert!(check_redirect(&[url("https://a.example/")], &url("https://b.example/")).is_ok());
    }

    #[test]
    fn redirect_chain_is_bounded() {
        let hop = url("http://a.example/");
        let ok = vec![hop.clone(); MAX_REDIRECTS];
        assert!(check_redirect(&ok, &hop).is_ok());
        let too_many = vec![hop.clone(); MAX_REDIRECTS + 1];
        assert!(
            check_redirect(&too_many, &hop)
                .unwrap_err()
                .contains("too many redirects")
        );
    }
}
