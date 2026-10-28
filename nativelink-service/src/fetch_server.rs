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

use core::convert::Into;
use core::future::Future;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use nativelink_config::cas_server::{FetchConfig, WithInstanceName};
use nativelink_error::{Error, ResultExt, make_input_err};
use nativelink_fetch::action_verifier::{QUALIFIER_CHECKSUM_ACTION_DIGEST, parse_action_digest};
use nativelink_fetch::fetcher::{
    DirectoryChecksum, FetchBlobTask, FetchDirectoryJob, FetchHeaders, Fetcher,
};
use nativelink_fetch::remote_asset_proto::{
    AssetKind, QUALIFIER_BAZEL_CANONICAL_ID, QUALIFIER_HTTP_HEADER_PREFIX,
    QUALIFIER_HTTP_HEADER_URL_PREFIX, RemoteAssetEntry, RemoteAssetQuery, is_http_header_qualifier,
    now_timestamp, qualifier_names, read_remote_asset_entry, redacted_uris, timestamp_is_before,
};
use nativelink_fetch::tree_hash::{TREE_HASH_FORMATS, TreeChecksum};
use nativelink_proto::build::bazel::remote::asset::v1::fetch_server::{
    Fetch, FetchServer as Server,
};
use nativelink_proto::build::bazel::remote::asset::v1::{
    FetchBlobRequest, FetchBlobResponse, FetchDirectoryRequest, FetchDirectoryResponse, Qualifier,
};
use nativelink_proto::build::bazel::remote::execution::v2::Digest;
use nativelink_proto::google::rpc::bad_request::FieldViolation;
use nativelink_proto::google::rpc::{BadRequest, ErrorInfo, Status as GoogleStatus};
use nativelink_store::store_manager::StoreManager;
use nativelink_util::digest_hasher::{DigestHasherFunc, make_ctx_for_hash_func};
use nativelink_util::redact::{redact_uri, redact_uris_in_text};
use nativelink_util::sri::{
    BYTE_CHECKSUM_QUALIFIERS, ByteChecksum, HEX_CHECKSUM_QUALIFIERS, QUALIFIER_CHECKSUM_SRI,
};
use nativelink_util::store_trait::Store;
use opentelemetry::context::FutureExt;
use prost::Message;
use prost_types::Timestamp;
use tokio::time::{Instant as TokioInstant, timeout_at};
use tonic::metadata::MetadataMap;
use tonic::{Code, Request, Response, Status};
use tracing::{Instrument, Level, debug, error_span, info, instrument, warn};

/// Qualifiers `FetchBlob` honours, besides HTTP header qualifiers and the
/// byte checksums of [`BYTE_CHECKSUM_QUALIFIERS`] (see [`blob_qualifiers`]).
/// Others, such as `resource_type` and `vcs.*`, would change what must be
/// fetched and we only download plain HTTP(S) content, so they are rejected
/// rather than ignored.
const BLOB_QUALIFIERS: &[&str] = &[QUALIFIER_BAZEL_CANONICAL_ID];

/// Qualifiers `FetchDirectory` honours, besides HTTP header qualifiers, the
/// byte checksums of [`BYTE_CHECKSUM_QUALIFIERS`] and those of the
/// [`TREE_HASH_FORMATS`] (see [`directory_qualifiers`]).
const DIRECTORY_QUALIFIERS: &[&str] = &[
    QUALIFIER_BAZEL_CANONICAL_ID,
    QUALIFIER_CHECKSUM_ACTION_DIGEST,
];

/// Every qualifier `FetchBlob` honours, besides HTTP header qualifiers.
fn blob_qualifiers() -> Vec<&'static str> {
    BLOB_QUALIFIERS
        .iter()
        .chain(BYTE_CHECKSUM_QUALIFIERS)
        .copied()
        .collect()
}

/// Every qualifier `FetchDirectory` honours, besides HTTP header qualifiers.
fn directory_qualifiers() -> Vec<&'static str> {
    DIRECTORY_QUALIFIERS
        .iter()
        .chain(BYTE_CHECKSUM_QUALIFIERS)
        .copied()
        .chain(TREE_HASH_FORMATS.iter().map(|format| format.qualifier()))
        .collect()
}

/// The hex checksums (`checksum.sha1`, ...) a request asks for, over the
/// downloaded bytes. A malformed value is an `InvalidArgument` error.
fn hex_checksums(qualifiers: &[Qualifier]) -> Result<Vec<ByteChecksum>, Error> {
    let mut checksums = Vec::new();
    for &name in HEX_CHECKSUM_QUALIFIERS {
        if let Some(value) = find_qualifier(qualifiers, name) {
            checksums.push(ByteChecksum::from_qualifier(name, value)?);
        }
    }
    Ok(checksums)
}

/// The `checksum.sri` a request asks for, if any. It is parsed only once a
/// fetch is needed, so that an asset pushed under a qualifier set with an
/// unparsable SRI can still be found. A malformed value is an
/// `InvalidArgument` error.
fn sri_checksum(qualifiers: &[Qualifier]) -> Result<Option<ByteChecksum>, Error> {
    find_qualifier(qualifiers, QUALIFIER_CHECKSUM_SRI)
        .map(|value| ByteChecksum::from_qualifier(QUALIFIER_CHECKSUM_SRI, value))
        .transpose()
}

/// The hex, tree-hash and action checksums a `FetchDirectory` request asks
/// for, all of which the fetched directory must match. A malformed value is an
/// `InvalidArgument` error.
fn directory_checksums(qualifiers: &[Qualifier]) -> Result<Vec<DirectoryChecksum>, Error> {
    let mut checksums: Vec<_> = hex_checksums(qualifiers)?
        .into_iter()
        .map(DirectoryChecksum::Bytes)
        .collect();
    for &format in TREE_HASH_FORMATS {
        if let Some(value) = find_qualifier(qualifiers, format.qualifier()) {
            checksums.push(DirectoryChecksum::Tree(TreeChecksum::parse(format, value)?));
        }
    }
    if let Some(value) = find_qualifier(qualifiers, QUALIFIER_CHECKSUM_ACTION_DIGEST) {
        checksums.push(DirectoryChecksum::Action(parse_action_digest(value)?));
    }
    Ok(checksums)
}

/// `ErrorInfo.domain` of every error detail this server attaches.
const ERROR_DOMAIN: &str = "nativelink.com";

/// `ErrorInfo.reason`: a miss on an instance with no fetcher configured.
const REASON_NOT_CACHED_NO_FETCHER: &str = "NOT_CACHED_NO_FETCHER";
/// `ErrorInfo.reason`: the fetcher ran and failed.
const REASON_FETCH_FAILED: &str = "FETCH_FAILED";

const ERROR_INFO_TYPE_URL: &str = "type.googleapis.com/google.rpc.ErrorInfo";
const BAD_REQUEST_TYPE_URL: &str = "type.googleapis.com/google.rpc.BadRequest";

/// Wraps `message` into a `google.protobuf.Any` under `type_url`.
fn pack_any<M: Message>(type_url: &str, message: &M) -> prost_types::Any {
    prost_types::Any {
        type_url: type_url.to_owned(),
        value: message.encode_to_vec(),
    }
}

/// An `ErrorInfo` detail telling clients why the request failed, so that e.g.
/// "not cached" can be told apart from "fetch failed" without parsing messages.
fn error_info(reason: &str) -> prost_types::Any {
    pack_any(
        ERROR_INFO_TYPE_URL,
        &ErrorInfo {
            reason: reason.to_owned(),
            domain: ERROR_DOMAIN.to_owned(),
            metadata: HashMap::new(),
        },
    )
}

/// A `NOT_FOUND` status for a miss that was not, and could not be, fetched.
fn not_cached_status(reason: &str, message: &str) -> GoogleStatus {
    GoogleStatus {
        code: Code::NotFound.into(),
        message: message.to_owned(),
        details: vec![error_info(reason)],
    }
}

/// Converts a failed fetch into a response status that keeps the fetch error's
/// code and message and marks it as a fetch failure. An `InvalidArgument` is
/// not one: it is the request that is at fault, so it is returned as an RPC
/// error instead (see the callers). The URL fetcher makes sure of that by
/// reporting a malformed archive, which is the origin's fault, as `Aborted`.
fn fetch_failed_status(err: Error) -> GoogleStatus {
    let mut status = GoogleStatus::from(err);
    status.details.push(error_info(REASON_FETCH_FAILED));
    status
}

/// Appends `context` to the message of `status`, keeping its details. Mirrors
/// `err_tip` for statuses that cannot go through `Error`, which has no details.
fn status_tip(status: &Status, context: &str) -> Status {
    Status::with_details(
        status.code(),
        format!("{} : {context}", status.message()),
        Bytes::copy_from_slice(status.details()),
    )
}

/// The `InvalidArgument` status rejecting any qualifier that is neither in
/// `supported` nor an HTTP header qualifier, if there is one. It is checked only
/// before a download. The spec says servers "MUST ensure Fetch'd content
/// matches all the specified qualifiers except in the case of previously
/// Push'd resources, for which the server MAY trust the pushing client", so a
/// qualifier we cannot honour must fail a fetch rather than be ignored, while
/// a cached entry, only ever found under the exact qualifiers it was stored
/// with, is served whatever they are. The spec recommends a `BadRequest`
/// detail with one violation per unsupported qualifier.
fn unsupported_qualifiers_status(qualifiers: &[Qualifier], supported: &[&str]) -> Option<Status> {
    let unsupported: Vec<&str> = qualifiers
        .iter()
        .map(|qualifier| qualifier.name.as_str())
        .filter(|name| !supported.contains(name) && !is_http_header_qualifier(name))
        .collect();
    if unsupported.is_empty() {
        return None;
    }
    let message = format!(
        "Unsupported qualifiers: {}. Supported qualifiers: {}, {QUALIFIER_HTTP_HEADER_PREFIX}<name>, {QUALIFIER_HTTP_HEADER_URL_PREFIX}<idx>:<name>",
        unsupported.join(", "),
        supported.join(", "),
    );
    let bad_request = BadRequest {
        field_violations: unsupported
            .iter()
            .map(|name| FieldViolation {
                field: "qualifiers.name".to_owned(),
                description: format!("\"{name}\" not supported"),
                ..Default::default()
            })
            .collect(),
    };
    let status = GoogleStatus {
        code: Code::InvalidArgument.into(),
        message: message.clone(),
        details: vec![pack_any(BAD_REQUEST_TYPE_URL, &bad_request)],
    };
    Some(Status::with_details(
        Code::InvalidArgument,
        message,
        Bytes::from(status.encode_to_vec()),
    ))
}

/// Per-instance state: the Action Cache store holding the Remote Asset metadata
/// (mapping URI+qualifiers -> digest) the server reads, and the `Fetcher` used
/// to actively download content on a cache miss. `fetcher` is `None` when no
/// fetcher is configured for the instance, in which case only metadata lookups
/// are served. Whether a hit's content is still in the CAS is the store's
/// business: wrap it in a `completeness_checking` store to have such entries
/// read as misses.
#[derive(Clone, Debug)]
pub struct FetchStoreInfo {
    store: Store,
    fetcher: Option<Arc<dyn Fetcher>>,
}

/// Whether a cached entry may be served at `now`. An entry past its
/// `expire_at` is stale. When the request sets `oldest_content_accepted`, an
/// entry stored before it, or with no `stored_at` to compare, is too old.
fn is_current(
    expire_at: Option<&Timestamp>,
    stored_at: Option<&Timestamp>,
    oldest_content_accepted: Option<&Timestamp>,
    now: &Timestamp,
) -> bool {
    if expire_at.is_some_and(|expire_at| !timestamp_is_before(now, expire_at)) {
        return false;
    }
    match (oldest_content_accepted, stored_at) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(oldest), Some(stored_at)) => !timestamp_is_before(stored_at, oldest),
    }
}

/// Looks up the cached entry for `query` in `store`, returning it only if it
/// may be served at `now`. Anything else (no entry, an unreadable store, an
/// expired or too old entry) is a miss, not a reason to fail the request.
async fn lookup_entry(
    store: &Store,
    query: &RemoteAssetQuery,
    digest_function: i32,
    oldest_content_accepted: Option<&Timestamp>,
    now: &Timestamp,
) -> Option<RemoteAssetEntry> {
    let entry = match read_remote_asset_entry(store, query, digest_function).await {
        Ok(Some(entry)) => entry,
        Ok(None) => return None,
        Err(err) => {
            warn!(
                uri = %redact_uri(&query.uri),
                ?err,
                "Failed to read fetch asset metadata"
            );
            return None;
        }
    };
    if !is_current(
        entry.expire_at.as_ref(),
        entry.stored_at.as_ref(),
        oldest_content_accepted,
        now,
    ) {
        debug!(
            uri = %redact_uri(&query.uri),
            "Cached fetch asset is expired or too old"
        );
        return None;
    }
    Some(entry)
}

/// Returns the value of the qualifier named `name`, if present.
fn find_qualifier<'a>(qualifiers: &'a [Qualifier], name: &str) -> Option<&'a str> {
    qualifiers
        .iter()
        .find(|qualifier| qualifier.name == name)
        .map(|qualifier| qualifier.value.as_str())
}

/// Flattens proto qualifiers into the `(name, value)` pairs a fetch job carries,
/// leaving out HTTP header qualifiers (those travel separately as
/// `FetchHeaders` and must not be persisted or affect identity).
fn qualifier_pairs(qualifiers: &[Qualifier]) -> Vec<(String, String)> {
    qualifiers
        .iter()
        .filter(|qualifier| !is_http_header_qualifier(&qualifier.name))
        .map(|qualifier| (qualifier.name.clone(), qualifier.value.clone()))
        .collect()
}

/// Converts the request's `timeout` (a `google.protobuf.Duration`), the time
/// budget for the whole fetch, into a `Duration`, treating unset/zero/negative
/// values as "no explicit timeout".
fn request_timeout(timeout: Option<&prost_types::Duration>) -> Option<Duration> {
    let timeout = timeout?;
    if timeout.seconds <= 0 && timeout.nanos <= 0 {
        return None;
    }
    let seconds = u64::try_from(timeout.seconds).ok()?;
    let nanos = u32::try_from(timeout.nanos).unwrap_or(0);
    Some(Duration::new(seconds, nanos))
}

/// How long before the RPC deadline the server stops waiting for a fetch.
///
/// tonic's server enforces `grpc-timeout` itself and, when it expires, cancels
/// the handler and answers `CANCELLED` ("Timeout expired"). Its timer starts
/// before ours (it runs from the arrival of the request, we start counting in
/// the handler), so if we waited for exactly the deadline we would lose that
/// race on every request and the client would see a bare `CANCELLED` instead of
/// our `DEADLINE_EXCEEDED` explaining that the fetch continues. Giving up a
/// little early makes our response the one that goes out.
const RPC_DEADLINE_MARGIN: Duration = Duration::from_millis(100);

/// Parses a `grpc-timeout` header value: at most eight digits followed by a
/// unit of `H` (hours), `M` (minutes), `S` (seconds), `m` (milliseconds), `u`
/// (microseconds) or `n` (nanoseconds), as in the
/// [gRPC over HTTP/2 spec](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md).
/// tonic enforces the header but keeps its parser private, so this mirrors it.
/// Anything malformed is `None`, which is also what tonic treats it as.
#[must_use]
pub fn parse_grpc_timeout(value: &str) -> Option<Duration> {
    let unit = value.chars().next_back()?;
    let digits = value.get(..value.len() - unit.len_utf8())?;
    if digits.is_empty() || digits.len() > 8 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let amount: u64 = digits.parse().ok()?;
    match unit {
        'H' => Some(Duration::from_secs(amount * 60 * 60)),
        'M' => Some(Duration::from_secs(amount * 60)),
        'S' => Some(Duration::from_secs(amount)),
        'm' => Some(Duration::from_millis(amount)),
        'u' => Some(Duration::from_micros(amount)),
        'n' => Some(Duration::from_nanos(amount)),
        _ => None,
    }
}

/// The time at which to stop waiting for a fetch so as to answer before the
/// RPC deadline the client sent in `grpc-timeout` (see
/// [`RPC_DEADLINE_MARGIN`]), or `None` when the client sent none, in which case
/// the fetch is waited for.
fn rpc_wait_deadline(metadata: &MetadataMap) -> Option<TokioInstant> {
    let deadline = parse_grpc_timeout(metadata.get("grpc-timeout")?.to_str().ok()?)?;
    let margin = RPC_DEADLINE_MARGIN.min(deadline / 2);
    TokioInstant::now().checked_add(deadline.saturating_sub(margin))
}

/// Awaits `fetch` until `deadline`, if there is one. If the deadline comes
/// first, the RPC fails with `DEADLINE_EXCEEDED`, which the Remote Asset API
/// reserves for exactly this: the fetch could not be completed within the RPC
/// deadline, and the client should retry for at least as long as the request's
/// `timeout`.
///
/// Giving up only drops this call's wait. With a `background` fetcher in the
/// chain the fetch carries on and a retry of the same request joins it; without
/// one the fetch is dropped along with the wait and a retry starts afresh.
async fn until_rpc_deadline<T>(
    deadline: Option<TokioInstant>,
    fetch: impl Future<Output = Result<T, Error>>,
) -> Result<Result<T, Error>, Status> {
    let Some(deadline) = deadline else {
        return Ok(fetch.await);
    };
    timeout_at(deadline, fetch).await.map_err(|_| {
        Status::new(
            Code::DeadlineExceeded,
            "The fetch did not finish within the RPC deadline. A fetch run by a background \
             fetcher continues, and retrying the same request joins it; retry for at least \
             as long as the request's timeout",
        )
    })
}

#[derive(Debug, Clone)]
pub struct FetchServer {
    stores: HashMap<String, FetchStoreInfo>,
}

impl FetchServer {
    pub fn new(
        configs: &[WithInstanceName<FetchConfig>],
        fetchers: &HashMap<String, Arc<dyn Fetcher>>,
        store_manager: &StoreManager,
    ) -> Result<Self, Error> {
        let mut stores = HashMap::with_capacity(configs.len());
        for config in configs {
            let store = store_manager
                .get_store(&config.fetch_store)
                .ok_or_else(|| {
                    make_input_err!("'fetch_store': '{}' does not exist", config.fetch_store)
                })?;
            let fetcher: Option<Arc<dyn Fetcher>> = match &config.fetcher {
                Some(fetcher_name) => {
                    Some(fetchers.get(fetcher_name).cloned().ok_or_else(|| {
                        make_input_err!("'fetcher': '{fetcher_name}' does not exist")
                    })?)
                }
                None => None,
            };
            stores.insert(
                config.instance_name.clone(),
                FetchStoreInfo { store, fetcher },
            );
        }
        Ok(Self { stores })
    }

    pub fn into_service(self) -> Server<Self> {
        Server::new(self)
    }

    async fn inner_fetch_blob(
        &self,
        request: FetchBlobRequest,
        rpc_deadline: Option<TokioInstant>,
    ) -> Result<Response<FetchBlobResponse>, Status> {
        let instance_name = &request.instance_name;
        let store_info = self
            .stores
            .get(instance_name)
            .err_tip(|| format!("'instance_name' not configured for '{instance_name}'"))?;
        let start = Instant::now();

        if request.uris.is_empty() {
            return Err(
                Error::new(Code::InvalidArgument, "No uris in fetch request".to_owned()).into(),
            );
        }
        let now = now_timestamp();
        for uri in &request.uris {
            let query =
                RemoteAssetQuery::new(AssetKind::Blob, uri.clone(), request.qualifiers.clone());
            let entry = lookup_entry(
                &store_info.store,
                &query,
                request.digest_function,
                request.oldest_content_accepted.as_ref(),
                &now,
            )
            .await;
            debug!(
                uri = %redact_uri(uri),
                hit = entry.is_some(),
                "Looked up fetch asset"
            );
            if let Some(entry) = entry {
                info!(
                    uri = %redact_uri(uri),
                    digest = %entry.digest.hash,
                    size_bytes = entry.digest.size_bytes,
                    source = "cache",
                    duration = ?start.elapsed(),
                    "Fetched asset"
                );
                return Ok(Response::new(FetchBlobResponse {
                    status: Some(GoogleStatus {
                        code: Code::Ok.into(),
                        message: "Fetch object found".to_owned(),
                        details: vec![],
                    }),
                    uri: entry.query.uri,
                    qualifiers: entry.query.qualifiers,
                    expires_at: entry.expire_at,
                    blob_digest: Some(entry.digest),
                    digest_function: entry.digest_function,
                }));
            }
        }

        // No previously pushed asset matched. If a fetcher is configured (i.e.
        // a CAS store exists), actively download the content, verify it against
        // the checksum qualifiers when present, cache it, and return its
        // digest. A checksum is optional: when absent the content is still
        // downloaded and stored under its computed CAS digest, just unverified.
        if let Some(fetcher) = &store_info.fetcher {
            // Only a download needs the qualifiers checked: the content must
            // match all of them, so reject any we cannot honour, and malformed
            // ones, before sending anything to the origin.
            if let Some(status) =
                unsupported_qualifiers_status(&request.qualifiers, &blob_qualifiers())
            {
                return Err(status);
            }
            let headers = FetchHeaders::from_qualifiers(&request.qualifiers, request.uris.len())?;
            let mut checksums = hex_checksums(&request.qualifiers)?;
            let hasher_func = DigestHasherFunc::try_from(request.digest_function)
                .err_tip(|| "In FetchServer::inner_fetch_blob")?;
            checksums.extend(sri_checksum(&request.qualifiers)?);
            let job = FetchBlobTask {
                uris: request.uris.clone(),
                qualifiers: qualifier_pairs(&request.qualifiers),
                checksums,
                hasher_func,
                timeout: request_timeout(request.timeout.as_ref()),
                headers,
            };
            // The fetcher (via MetadataCache) caches the asset metadata itself;
            // here we only shape the response.
            info!("Asset is not cached, fetching it");
            match until_rpc_deadline(rpc_deadline, fetcher.fetch_blob(&job)).await? {
                Ok(outcome) => {
                    let proto_digest: Digest = outcome.digest.into();
                    info!(
                        uri = %redact_uri(&outcome.uri),
                        digest = %proto_digest.hash,
                        size_bytes = proto_digest.size_bytes,
                        source = "download",
                        duration = ?start.elapsed(),
                        "Fetched asset"
                    );
                    return Ok(Response::new(FetchBlobResponse {
                        status: Some(GoogleStatus {
                            code: Code::Ok.into(),
                            message: "Fetch object found".to_owned(),
                            details: vec![],
                        }),
                        uri: outcome.uri,
                        qualifiers: request.qualifiers.clone(),
                        expires_at: outcome.expire_at,
                        blob_digest: Some(proto_digest),
                        digest_function: hasher_func.proto_digest_func().into(),
                    }));
                }
                // The request itself is invalid (such as lacking a checksum a
                // fetcher requires), so, per the Remote Asset API, an
                // `INVALID_ARGUMENT` RPC error rather than a response status.
                Err(err) if err.code == Code::InvalidArgument => {
                    warn!(
                        message = %redact_uris_in_text(&err.message_string()),
                        "Fetch request rejected by the fetcher"
                    );
                    return Err(err.into());
                }
                // Fetch failures (checksum mismatch, timeout, no URI served the
                // content, ...) surface in the response status, not as a gRPC
                // error, per the Remote Asset API.
                Err(err) => {
                    warn!(
                        code = ?err.code,
                        message = %redact_uris_in_text(&err.message_string()),
                        duration = ?start.elapsed(),
                        "Failed to fetch asset from any uri"
                    );
                    return Ok(Response::new(FetchBlobResponse {
                        status: Some(fetch_failed_status(err)),
                        uri: request.uris.first().cloned().unwrap_or_default(),
                        qualifiers: request.qualifiers.clone(),
                        expires_at: None,
                        blob_digest: None,
                        digest_function: hasher_func.proto_digest_func().into(),
                    }));
                }
            }
        }

        Ok(Response::new(FetchBlobResponse {
            status: Some(not_cached_status(
                REASON_NOT_CACHED_NO_FETCHER,
                "not cached, and this instance has no fetcher configured",
            )),
            uri: request.uris.first().cloned().unwrap_or_default(),
            qualifiers: request.qualifiers,
            expires_at: None,
            blob_digest: None,
            digest_function: request.digest_function,
        }))
    }

    async fn inner_fetch_directory(
        &self,
        request: FetchDirectoryRequest,
        rpc_deadline: Option<TokioInstant>,
    ) -> Result<Response<FetchDirectoryResponse>, Status> {
        let instance_name = &request.instance_name;
        let store_info = self
            .stores
            .get(instance_name)
            .err_tip(|| format!("'instance_name' not configured for '{instance_name}'"))?;
        let start = Instant::now();

        if request.uris.is_empty() {
            return Err(
                Error::new(Code::InvalidArgument, "No uris in fetch request".to_owned()).into(),
            );
        }
        let now = now_timestamp();

        for uri in &request.uris {
            let query = RemoteAssetQuery::new(
                AssetKind::Directory,
                uri.clone(),
                request.qualifiers.clone(),
            );
            let entry = lookup_entry(
                &store_info.store,
                &query,
                request.digest_function,
                request.oldest_content_accepted.as_ref(),
                &now,
            )
            .await;
            debug!(
                uri = %redact_uri(uri),
                hit = entry.is_some(),
                "Looked up fetch directory asset"
            );
            if let Some(entry) = entry {
                info!(
                    uri = %redact_uri(uri),
                    digest = %entry.digest.hash,
                    size_bytes = entry.digest.size_bytes,
                    source = "cache",
                    duration = ?start.elapsed(),
                    "Fetched directory"
                );
                return Ok(Response::new(FetchDirectoryResponse {
                    status: Some(GoogleStatus {
                        code: Code::Ok.into(),
                        message: "Fetch directory found".to_owned(),
                        details: vec![],
                    }),
                    uri: entry.query.uri,
                    qualifiers: entry.query.qualifiers,
                    expires_at: entry.expire_at,
                    root_directory_digest: Some(entry.digest),
                    digest_function: entry.digest_function,
                }));
            }
        }

        // No previously cached directory matched. If a fetcher is configured,
        // actively download the archive, expand it into a Directory tree,
        // cache the metadata, and return the root directory digest.
        // The byte checksums (`checksum.sri`, `checksum.sha256`, ...) and the
        // tree hashes (such as `checksum.h1`, Go's directory hash) are all
        // accepted, and every one present must match. A checksum is optional:
        // when absent the archive is expanded unverified, as a blob without
        // a checksum is.
        let Some(fetcher) = &store_info.fetcher else {
            return Ok(Response::new(FetchDirectoryResponse {
                status: Some(not_cached_status(
                    REASON_NOT_CACHED_NO_FETCHER,
                    "not cached, and this instance has no fetcher configured",
                )),
                uri: request.uris.first().cloned().unwrap_or_default(),
                qualifiers: request.qualifiers,
                expires_at: None,
                root_directory_digest: None,
                digest_function: request.digest_function,
            }));
        };
        // Only a download needs the qualifiers checked: the content must
        // match all of them, so reject any we cannot honour, and malformed
        // ones, before sending anything to the origin.
        if let Some(status) =
            unsupported_qualifiers_status(&request.qualifiers, &directory_qualifiers())
        {
            return Err(status);
        }
        let headers = FetchHeaders::from_qualifiers(&request.qualifiers, request.uris.len())?;
        let mut checksums = directory_checksums(&request.qualifiers)?;
        let hasher_func = DigestHasherFunc::try_from(request.digest_function)
            .err_tip(|| "In FetchServer::inner_fetch_directory")?;
        checksums.extend(sri_checksum(&request.qualifiers)?.map(DirectoryChecksum::Bytes));
        let job = FetchDirectoryJob {
            verified_by_action: false,
            uris: request.uris.clone(),
            qualifiers: qualifier_pairs(&request.qualifiers),
            checksums,
            hasher_func,
            timeout: request_timeout(request.timeout.as_ref()),
            headers,
        };
        // The fetcher (via MetadataCache) caches the directory metadata
        // itself; here we only shape the response.
        info!("Directory is not cached, fetching it");
        match until_rpc_deadline(rpc_deadline, fetcher.fetch_directory(&job)).await? {
            Ok(outcome) => {
                let proto_digest: Digest = outcome.digest.into();
                info!(
                    uri = %redact_uri(&outcome.uri),
                    digest = %proto_digest.hash,
                    size_bytes = proto_digest.size_bytes,
                    source = "download",
                    duration = ?start.elapsed(),
                    "Fetched directory"
                );
                Ok(Response::new(FetchDirectoryResponse {
                    status: Some(GoogleStatus {
                        code: Code::Ok.into(),
                        message: "Fetch directory found".to_owned(),
                        details: vec![],
                    }),
                    uri: outcome.uri,
                    qualifiers: request.qualifiers.clone(),
                    expires_at: outcome.expire_at,
                    root_directory_digest: Some(proto_digest),
                    digest_function: hasher_func.proto_digest_func().into(),
                }))
            }
            // As for a blob: an invalid request is an RPC error.
            Err(err) if err.code == Code::InvalidArgument => {
                warn!(
                    message = %redact_uris_in_text(&err.message_string()),
                    "Fetch directory request rejected by the fetcher"
                );
                Err(err.into())
            }
            Err(err) => {
                warn!(
                    code = ?err.code,
                    message = %redact_uris_in_text(&err.message_string()),
                    duration = ?start.elapsed(),
                    "Failed to fetch directory from any uri"
                );
                Ok(Response::new(FetchDirectoryResponse {
                    status: Some(fetch_failed_status(err)),
                    uri: request.uris.first().cloned().unwrap_or_default(),
                    qualifiers: request.qualifiers.clone(),
                    expires_at: None,
                    root_directory_digest: None,
                    digest_function: hasher_func.proto_digest_func().into(),
                }))
            }
        }
    }
}

#[tonic::async_trait]
impl Fetch for FetchServer {
    #[allow(clippy::blocks_in_conditions)]
    // The response echoes the request's qualifiers, header values included, so
    // it is not logged either.
    #[instrument(
        err(level = Level::WARN),
        skip_all,
        fields(
            // Qualifier values and URI credentials must never be logged.
            request.instance_name = ?grpc_request.get_ref().instance_name,
            request.uris = ?redacted_uris(&grpc_request.get_ref().uris),
            request.qualifiers = ?qualifier_names(&grpc_request.get_ref().qualifiers),
            request.digest_function = ?grpc_request.get_ref().digest_function,
            request.has_timeout = grpc_request.get_ref().timeout.is_some(),
        )
    )]
    async fn fetch_blob(
        &self,
        grpc_request: Request<FetchBlobRequest>,
    ) -> Result<Response<FetchBlobResponse>, Status> {
        let rpc_deadline = rpc_wait_deadline(grpc_request.metadata());
        let request = grpc_request.into_inner();
        let digest_function = request.digest_function;
        self.inner_fetch_blob(request, rpc_deadline)
            .instrument(error_span!("fetch_server_fetch_blob"))
            .with_context(
                make_ctx_for_hash_func(digest_function).err_tip(|| "In FetchServer::fetch_blob")?,
            )
            .await
            .map_err(|status| status_tip(&status, "Failed on fetch_blob() command"))
    }

    #[allow(clippy::blocks_in_conditions)]
    // The response echoes the request's qualifiers, header values included, so
    // it is not logged either.
    #[instrument(
        err(level = Level::WARN),
        skip_all,
        fields(
            // Qualifier values and URI credentials must never be logged.
            request.instance_name = ?grpc_request.get_ref().instance_name,
            request.uris = ?redacted_uris(&grpc_request.get_ref().uris),
            request.qualifiers = ?qualifier_names(&grpc_request.get_ref().qualifiers),
            request.digest_function = ?grpc_request.get_ref().digest_function,
            request.has_timeout = grpc_request.get_ref().timeout.is_some(),
        )
    )]
    async fn fetch_directory(
        &self,
        grpc_request: Request<FetchDirectoryRequest>,
    ) -> Result<Response<FetchDirectoryResponse>, Status> {
        let rpc_deadline = rpc_wait_deadline(grpc_request.metadata());
        let request = grpc_request.into_inner();
        let digest_function = request.digest_function;
        self.inner_fetch_directory(request, rpc_deadline)
            .instrument(error_span!("fetch_server_fetch_directory"))
            .with_context(
                make_ctx_for_hash_func(digest_function)
                    .err_tip(|| "In FetchServer::fetch_directory")?,
            )
            .await
            .map_err(|status| status_tip(&status, "Failed on fetch_directory() command"))
    }
}
