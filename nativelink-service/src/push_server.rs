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

use nativelink_config::cas_server::{PushConfig, WithInstanceName};
use nativelink_error::{Code, Error, ResultExt, make_err, make_input_err};
use nativelink_fetch::remote_asset_proto::{
    AssetKind, RemoteAssetEntry, RemoteAssetQuery, now_timestamp, qualifier_names, redacted_uris,
    write_remote_asset_entry,
};
use nativelink_proto::build::bazel::remote::asset::v1::push_server::{Push, PushServer as Server};
use nativelink_proto::build::bazel::remote::asset::v1::{
    PushBlobRequest, PushBlobResponse, PushDirectoryRequest, PushDirectoryResponse,
};
use nativelink_store::store_manager::StoreManager;
use nativelink_util::digest_hasher::make_ctx_for_hash_func;
use nativelink_util::redact::redact_uri;
use nativelink_util::store_trait::Store;
use opentelemetry::context::FutureExt;
use tonic::{Request, Response, Status};
use tracing::{Instrument, Level, error_span, info, instrument};

#[derive(Debug, Clone)]
pub struct PushStoreInfo {
    /// The Action Cache store the metadata is written to.
    store: Store,
    /// The CAS the pushed content lives in, used to build the `Tree` of a
    /// directory. `PushDirectory` is unavailable without it.
    cas_store: Option<Store>,
    read_only: bool,
}

#[derive(Debug, Clone)]
pub struct PushServer {
    stores: HashMap<String, PushStoreInfo>,
}

impl PushServer {
    pub fn new(
        configs: &[WithInstanceName<PushConfig>],
        store_manager: &StoreManager,
    ) -> Result<Self, Error> {
        let mut stores = HashMap::with_capacity(configs.len());
        for config in configs {
            let store = store_manager.get_store(&config.push_store).ok_or_else(|| {
                make_input_err!("'push_store': '{}' does not exist", config.push_store)
            })?;
            let cas_store = config
                .cas_store
                .as_ref()
                .map(|name| {
                    store_manager
                        .get_store(name)
                        .ok_or_else(|| make_input_err!("'cas_store': '{name}' does not exist"))
                })
                .transpose()?;
            stores.insert(
                config.instance_name.clone(),
                PushStoreInfo {
                    store,
                    cas_store,
                    read_only: config.read_only,
                },
            );
        }
        Ok(Self {
            stores: stores.clone(),
        })
    }

    pub fn into_service(self) -> Server<Self> {
        Server::new(self)
    }

    async fn inner_push_blob(
        &self,
        request: PushBlobRequest,
    ) -> Result<Response<PushBlobResponse>, Error> {
        let instance_name = &request.instance_name;
        let store_info = self
            .stores
            .get(instance_name)
            .err_tip(|| format!("'instance_name' not configured for '{instance_name}'"))?;

        if store_info.read_only {
            return Err(make_err!(
                Code::PermissionDenied,
                "The store '{instance_name}' is read only on this endpoint",
            ));
        }

        let blob_digest = request.blob_digest.ok_or_else(|| {
            Error::new(
                Code::InvalidArgument,
                "Missing blob digest in push".to_owned(),
            )
        })?;
        if request.uris.is_empty() {
            return Err(Error::new(
                Code::InvalidArgument,
                "No uris in push request".to_owned(),
            ));
        }
        let stored_at = now_timestamp();
        for uri in request.uris {
            // Header qualifiers are dropped here: they are often credentials
            // and are not part of an asset's identity.
            let entry = RemoteAssetEntry {
                query: RemoteAssetQuery::new(
                    AssetKind::Blob,
                    uri.clone(),
                    request.qualifiers.clone(),
                ),
                digest: blob_digest.clone(),
                expire_at: request.expire_at,
                stored_at: Some(stored_at),
                digest_function: request.digest_function,
                tree_digest: None,
            };
            write_remote_asset_entry(&store_info.store, None, &entry)
                .await
                .err_tip(|| "Failed to update in push server")?;
            info!(uri = %redact_uri(&uri), "Pushed asset metadata");
        }

        Ok(Response::new(PushBlobResponse {}))
    }

    async fn inner_push_directory(
        &self,
        request: PushDirectoryRequest,
    ) -> Result<Response<PushDirectoryResponse>, Error> {
        let instance_name = &request.instance_name;
        let store_info = self
            .stores
            .get(instance_name)
            .err_tip(|| format!("'instance_name' not configured for '{instance_name}'"))?;

        if store_info.read_only {
            return Err(make_err!(
                Code::PermissionDenied,
                "The store '{instance_name}' is read only on this endpoint",
            ));
        }

        let cas_store = store_info.cas_store.as_ref().ok_or_else(|| {
            make_err!(
                Code::FailedPrecondition,
                "PushDirectory needs 'cas_store' configured for '{instance_name}'",
            )
        })?;

        let root_directory_digest = request.root_directory_digest.ok_or_else(|| {
            Error::new(
                Code::InvalidArgument,
                "Missing root directory digest in push".to_owned(),
            )
        })?;
        if request.uris.is_empty() {
            return Err(Error::new(
                Code::InvalidArgument,
                "No uris in push request".to_owned(),
            ));
        }
        // `references_blobs` and `references_directories` are only hints, and
        // like `push_blob` we do not act on them.
        let stored_at = now_timestamp();
        for uri in request.uris {
            let entry = RemoteAssetEntry {
                query: RemoteAssetQuery::new(
                    AssetKind::Directory,
                    uri.clone(),
                    request.qualifiers.clone(),
                ),
                digest: root_directory_digest.clone(),
                expire_at: request.expire_at,
                stored_at: Some(stored_at),
                digest_function: request.digest_function,
                tree_digest: None,
            };
            // Fails if any `Directory` of the tree is missing from the CAS.
            write_remote_asset_entry(&store_info.store, Some(cas_store), &entry)
                .await
                .err_tip(|| "Failed to update in push server")?;
            info!(uri = %redact_uri(&uri), "Pushed directory asset metadata");
        }

        Ok(Response::new(PushDirectoryResponse {}))
    }
}

#[tonic::async_trait]
impl Push for PushServer {
    #[allow(clippy::blocks_in_conditions)]
    #[instrument(
        err(level = Level::WARN),
        ret(level = Level::INFO),
        skip_all,
        fields(
            // Qualifier values and URI credentials must never be logged.
            request.instance_name = ?grpc_request.get_ref().instance_name,
            request.uris = ?redacted_uris(&grpc_request.get_ref().uris),
            request.qualifiers = ?qualifier_names(&grpc_request.get_ref().qualifiers),
            request.digest_function = ?grpc_request.get_ref().digest_function,
        )
    )]
    async fn push_blob(
        &self,
        grpc_request: Request<PushBlobRequest>,
    ) -> Result<Response<PushBlobResponse>, Status> {
        let request = grpc_request.into_inner();
        let digest_function = request.digest_function;
        self.inner_push_blob(request)
            .instrument(error_span!("push_push_blob"))
            .with_context(
                make_ctx_for_hash_func(digest_function).err_tip(|| "In PushServer::push_blob")?,
            )
            .await
            .err_tip(|| "Failed on push_blob() command")
            .map_err(Into::into)
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(
        err(level = Level::WARN),
        ret(level = Level::INFO),
        skip_all,
        fields(
            // Qualifier values and URI credentials must never be logged.
            request.instance_name = ?grpc_request.get_ref().instance_name,
            request.uris = ?redacted_uris(&grpc_request.get_ref().uris),
            request.qualifiers = ?qualifier_names(&grpc_request.get_ref().qualifiers),
            request.digest_function = ?grpc_request.get_ref().digest_function,
        )
    )]
    async fn push_directory(
        &self,
        grpc_request: Request<PushDirectoryRequest>,
    ) -> Result<Response<PushDirectoryResponse>, Status> {
        let request = grpc_request.into_inner();
        let digest_function = request.digest_function;
        self.inner_push_directory(request)
            .instrument(error_span!("push_push_directory"))
            .with_context(
                make_ctx_for_hash_func(digest_function)
                    .err_tip(|| "In PushServer::push_directory")?,
            )
            .await
            .err_tip(|| "Failed on push_directory() command")
            .map_err(Into::into)
    }
}
