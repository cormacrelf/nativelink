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

use nativelink_config::fetchers::{
    DEFAULT_MAX_ARCHIVE_ENTRIES, DEFAULT_MAX_ARCHIVE_UNCOMPRESSED_BYTES,
    DEFAULT_MAX_CONCURRENT_FETCHES, DEFAULT_MAX_SIZE_BYTES, FetcherSpec,
};
use nativelink_error::{Error, make_input_err};
use nativelink_store::store_manager::StoreManager;
use nativelink_util::operation_state_manager::ClientStateManager;

use crate::action_verifier::ActionVerifier;
use crate::background_fetcher::{BackgroundFetcher, BackgroundFetcherOpts};
use crate::fetcher::Fetcher;
use crate::ip_filter::IpFilter;
use crate::metadata_cache::{MetadataCache, MetadataCacheOptions};
use crate::url_fetcher::{ProxySettings, UrlFetcher, UrlFetcherOptions};

/// Builds a single fetcher from `spec`, resolving store references against
/// `store_manager`, scheduler references against `schedulers`, and
/// inner-fetcher references against `built` (fetchers already constructed
/// earlier in the `fetchers` list). Decorators reference their inner fetcher by
/// name, so a referenced fetcher must appear before the fetcher that
/// references it.
pub fn fetcher_factory<S: BuildHasher, T: BuildHasher>(
    spec: &FetcherSpec,
    store_manager: &StoreManager,
    schedulers: &HashMap<String, Arc<dyn ClientStateManager>, T>,
    built: &HashMap<String, Arc<dyn Fetcher>, S>,
) -> Result<Arc<dyn Fetcher>, Error> {
    match spec {
        FetcherSpec::Url(spec) => {
            let cas_store = store_manager.get_store(&spec.cas_store).ok_or_else(|| {
                make_input_err!("'cas_store': '{}' does not exist", spec.cas_store)
            })?;
            let options = UrlFetcherOptions {
                temp_path: spec.temp_path.clone(),
                max_size_bytes: limit(spec.max_size_bytes, DEFAULT_MAX_SIZE_BYTES),
                archive_entry_inline_threshold_bytes: spec.archive_entry_inline_threshold_bytes,
                max_archive_entries: limit(spec.max_archive_entries, DEFAULT_MAX_ARCHIVE_ENTRIES),
                max_archive_uncompressed_bytes: limit(
                    spec.max_archive_uncompressed_bytes,
                    DEFAULT_MAX_ARCHIVE_UNCOMPRESSED_BYTES,
                ),
                require_checksum: spec.require_checksum,
                proxy: ProxySettings::from_config(
                    spec.http_proxy.as_deref(),
                    spec.http_proxy_secret_file.as_deref(),
                    &spec.no_proxy,
                )?,
                ip_filter: IpFilter::new(&spec.allowed_ip_ranges)?,
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
            let cas_store = store_manager.get_store(&spec.cas_store).ok_or_else(|| {
                make_input_err!("'cas_store': '{}' does not exist", spec.cas_store)
            })?;
            let inner = resolve(&spec.fetcher, built)?;
            let options = MetadataCacheOptions {
                unpinned_default_ttl: Duration::from_secs(spec.unpinned_default_ttl_s),
                unpinned_min_ttl: Duration::from_secs(spec.unpinned_min_ttl_s),
                unpinned_max_ttl: Duration::from_secs(spec.unpinned_max_ttl_s),
            };
            if options.unpinned_min_ttl > options.unpinned_max_ttl {
                return Err(make_input_err!(
                    "'unpinned_min_ttl_s' ({}) must not be more than 'unpinned_max_ttl_s' ({})",
                    spec.unpinned_min_ttl_s,
                    spec.unpinned_max_ttl_s
                ));
            }
            Ok(MetadataCache::with_options(
                inner, store, cas_store, options,
            ))
        }
        FetcherSpec::Background(spec) => {
            let inner = resolve(&spec.fetcher, built)?;
            let opts = BackgroundFetcherOpts {
                max_concurrent_fetches: limit(
                    spec.max_concurrent_fetches,
                    DEFAULT_MAX_CONCURRENT_FETCHES,
                ),
                min_timeout: spec.min_timeout_s.map(Duration::from_secs),
                max_timeout: spec.max_timeout_s.map(Duration::from_secs),
            };
            Ok(BackgroundFetcher::new(inner, opts))
        }
        FetcherSpec::ActionVerify(spec) => {
            let cas_store = store_manager.get_store(&spec.cas_store).ok_or_else(|| {
                make_input_err!("'cas_store': '{}' does not exist", spec.cas_store)
            })?;
            let scheduler = schedulers.get(&spec.scheduler).cloned().ok_or_else(|| {
                make_input_err!("'scheduler': '{}' does not exist", spec.scheduler)
            })?;
            let inner = resolve(&spec.fetcher, built)?;
            Ok(ActionVerifier::new(
                inner,
                cas_store,
                scheduler,
                spec.instance_name.clone(),
            ))
        }
    }
}

/// A configured resource limit: unset takes `default`, and 0 means no limit
/// (a zero limit would refuse everything, so it is free to mean "off").
fn limit<T: PartialEq + Default>(configured: Option<T>, default: T) -> Option<T> {
    match configured {
        None => Some(default),
        Some(value) if value == T::default() => None,
        Some(value) => Some(value),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_limit_takes_the_default_and_zero_turns_it_off() {
        assert_eq!(limit(None, 64_usize), Some(64));
        assert_eq!(limit(Some(0_usize), 64), None);
        assert_eq!(limit(Some(8_usize), 64), Some(8));
    }
}
