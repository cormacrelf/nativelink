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

//! Builds a [`Fetcher`] chain from its [`FetcherSpec`] configuration.

use core::hash::BuildHasher;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;

use nativelink_config::fetchers::FetcherSpec;
use nativelink_error::{Error, make_input_err};
use nativelink_store::store_manager::StoreManager;

use crate::background_fetcher::{BackgroundFetcher, BackgroundFetcherOpts};
use crate::fetcher::Fetcher;
use crate::metadata_cache::MetadataCache;
use crate::url_fetcher::{ProxySettings, UrlFetcher, UrlFetcherOptions};

/// Builds a single fetcher from `spec`, resolving store references against
/// `store_manager` and inner-fetcher references against `built` (fetchers
/// already constructed earlier in the `fetchers` list). Decorators reference
/// their inner fetcher by name, so a referenced fetcher must appear before the
/// fetcher that references it.
pub fn fetcher_factory<S: BuildHasher>(
    spec: &FetcherSpec,
    store_manager: &StoreManager,
    built: &HashMap<String, Arc<dyn Fetcher>, S>,
) -> Result<Arc<dyn Fetcher>, Error> {
    match spec {
        FetcherSpec::Url(spec) => {
            let cas_store = store_manager.get_store(&spec.cas_store).ok_or_else(|| {
                make_input_err!("'cas_store': '{}' does not exist", spec.cas_store)
            })?;
            let options = UrlFetcherOptions {
                temp_path: spec.temp_path.clone(),
                max_size_bytes: spec.max_size_bytes,
                proxy: ProxySettings::from_config(
                    spec.http_proxy.as_deref(),
                    spec.http_proxy_secret_file.as_deref(),
                    &spec.no_proxy,
                )?,
                ..UrlFetcherOptions::default()
            };
            let options = match spec.max_fetch_duration_s {
                Some(seconds) => UrlFetcherOptions {
                    max_fetch_duration: Duration::from_secs(seconds),
                    ..options
                },
                None => options,
            };
            Ok(Arc::new(UrlFetcher::new(cas_store, options)?))
        }
        FetcherSpec::MetadataCache(spec) => {
            let store = store_manager.get_store(&spec.fetch_store).ok_or_else(|| {
                make_input_err!("'fetch_store': '{}' does not exist", spec.fetch_store)
            })?;
            let inner = resolve(&spec.fetcher, built)?;
            Ok(MetadataCache::new(inner, store))
        }
        FetcherSpec::Background(spec) => {
            let inner = resolve(&spec.fetcher, built)?;
            let opts = BackgroundFetcherOpts {
                max_concurrent_fetches: spec.max_concurrent_fetches,
                min_timeout: spec.min_timeout_s.map(Duration::from_secs),
                max_timeout: spec.max_timeout_s.map(Duration::from_secs),
            };
            Ok(BackgroundFetcher::new(inner, opts))
        }
    }
}

/// Looks up an already-built fetcher by name.
fn resolve<S: BuildHasher>(
    name: &str,
    built: &HashMap<String, Arc<dyn Fetcher>, S>,
) -> Result<Arc<dyn Fetcher>, Error> {
    built.get(name).cloned().ok_or_else(|| {
        make_input_err!("'fetcher': '{name}' does not exist (it must be defined earlier)")
    })
}
