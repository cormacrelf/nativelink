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
use std::collections::HashMap;
use std::time::Instant;

use nativelink_config::cas_server::{FetchConfig, WithInstanceName};
use nativelink_error::{Error, ResultExt, make_err, make_input_err};
use nativelink_fetch::remote_asset_proto::{
    AssetKind, RemoteAssetEntry, RemoteAssetQuery, now_timestamp, qualifier_names,
    read_remote_asset_entry, redacted_uris, timestamp_is_before,
};
use nativelink_proto::build::bazel::remote::asset::v1::fetch_server::{
    Fetch, FetchServer as Server,
};
use nativelink_proto::build::bazel::remote::asset::v1::{
    FetchBlobRequest, FetchBlobResponse, FetchDirectoryRequest, FetchDirectoryResponse,
};
use nativelink_proto::google::rpc::Status as GoogleStatus;
use nativelink_store::store_manager::StoreManager;
use nativelink_util::digest_hasher::make_ctx_for_hash_func;
use nativelink_util::redact::redact_uri;
use nativelink_util::store_trait::Store;
use opentelemetry::context::FutureExt;
use prost_types::Timestamp;
use tonic::{Code, Request, Response, Status};
use tracing::{Instrument, Level, debug, error_span, info, instrument, warn};

/// Per-instance state: the Action Cache store holding the Remote Asset metadata
/// (mapping URI+qualifiers -> digest) the server reads. Whether a hit's content
/// is still in the CAS is the store's business: wrap it in a
/// `completeness_checking` store to have such entries read as misses.
#[derive(Clone, Debug)]
pub struct FetchStoreInfo {
    store: Store,
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

#[derive(Debug, Clone)]
pub struct FetchServer {
    stores: HashMap<String, FetchStoreInfo>,
}

impl FetchServer {
    pub fn new(
        configs: &[WithInstanceName<FetchConfig>],
        store_manager: &StoreManager,
    ) -> Result<Self, Error> {
        let mut stores = HashMap::with_capacity(configs.len());
        for config in configs {
            let store = store_manager
                .get_store(&config.fetch_store)
                .ok_or_else(|| {
                    make_input_err!("'fetch_store': '{}' does not exist", config.fetch_store)
                })?;
            stores.insert(config.instance_name.clone(), FetchStoreInfo { store });
        }
        Ok(Self {
            stores: stores.clone(),
        })
    }

    pub fn into_service(self) -> Server<Self> {
        Server::new(self)
    }

    async fn inner_fetch_blob(
        &self,
        request: FetchBlobRequest,
    ) -> Result<Response<FetchBlobResponse>, Error> {
        let instance_name = &request.instance_name;
        let store_info = self
            .stores
            .get(instance_name)
            .err_tip(|| format!("'instance_name' not configured for '{instance_name}'"))?;
        let start = Instant::now();

        if request.uris.is_empty() {
            return Err(Error::new(
                Code::InvalidArgument,
                "No uris in fetch request".to_owned(),
            ));
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

        Ok(Response::new(FetchBlobResponse {
            status: Some(make_err!(Code::NotFound, "No item found").into()),
            uri: request.uris.first().cloned().unwrap_or_default(),
            qualifiers: request.qualifiers,
            expires_at: None,
            blob_digest: None,
            digest_function: request.digest_function,
        }))
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
        let request = grpc_request.into_inner();
        let digest_function = request.digest_function;
        self.inner_fetch_blob(request)
            .instrument(error_span!("fetch_server_fetch_blob"))
            .with_context(
                make_ctx_for_hash_func(digest_function).err_tip(|| "In FetchServer::fetch_blob")?,
            )
            .await
            .err_tip(|| "Failed on fetch_blob() command")
            .map_err(Into::into)
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(
        err(level = Level::WARN),
        ret(level = Level::INFO),
        skip_all,
        fields(request = ?_grpc_request.get_ref())
    )]
    async fn fetch_directory(
        &self,
        _grpc_request: Request<FetchDirectoryRequest>,
    ) -> Result<Response<FetchDirectoryResponse>, Status> {
        Err(Status::unimplemented("FetchDirectory not implemented"))
    }
}
