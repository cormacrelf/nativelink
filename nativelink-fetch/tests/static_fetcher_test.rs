// Copyright 2026 The NativeLink Authors. All rights reserved.
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

use std::sync::Arc;

use nativelink_config::stores::{MemorySpec, StoreSpec};
use nativelink_error::{Code, Error};
use nativelink_fetch::fetcher::{FetchBlobTask, FetchDirectoryJob, FetchHeaders, Fetcher};
use nativelink_fetch::static_fetcher::StaticFetcher;
use nativelink_macro::nativelink_test;
use nativelink_store::default_store_factory::store_factory;
use nativelink_store::store_manager::StoreManager;
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::DigestHasherFunc;
use nativelink_util::sri::ByteChecksum;
use nativelink_util::store_trait::{Store, StoreLike};
use sha2::{Digest, Sha256};

async fn memory_store() -> Store {
    store_factory(
        &StoreSpec::Memory(MemorySpec::default()),
        &Arc::new(StoreManager::new()),
        None,
    )
    .await
    .expect("failed to build memory store")
}

fn job(uris: &[&str], checksums: Vec<ByteChecksum>) -> FetchBlobTask {
    FetchBlobTask {
        uris: uris.iter().map(|&uri| uri.to_owned()).collect(),
        qualifiers: vec![],
        checksums,
        hasher_func: DigestHasherFunc::Sha256,
        timeout: None,
        headers: FetchHeaders::default(),
        revalidate: vec![],
        shared_deadline: None,
    }
}

fn sha256_hex(body: &str) -> String {
    Sha256::digest(body.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn fetcher(store: &Store) -> StaticFetcher {
    StaticFetcher::new(
        store.clone(),
        [
            ("https://a.example/one", "one"),
            ("https://b.example/two", "two"),
        ],
    )
}

#[nativelink_test]
async fn serves_a_listed_uri_into_the_cas() -> Result<(), Error> {
    let store = memory_store().await;
    let outcome = fetcher(&store)
        .await
        .fetch_blob(&job(&["https://a.example/one"], vec![]))
        .await?;

    assert_eq!(outcome.uri, "https://a.example/one");
    let expected = DigestInfo::try_new(&sha256_hex("one"), 3)?;
    assert_eq!(outcome.digest, expected);
    let stored = store.get_part_unchunked(expected, 0, None).await?;
    assert_eq!(&stored[..], b"one");
    Ok(())
}

#[nativelink_test]
async fn an_unlisted_uri_is_not_found() -> Result<(), Error> {
    let store = memory_store().await;
    let err = fetcher(&store)
        .await
        .fetch_blob(&job(&["https://c.example/three"], vec![]))
        .await
        .unwrap_err();

    assert_eq!(err.code, Code::NotFound);
    Ok(())
}

#[nativelink_test]
async fn uris_are_tried_in_the_order_listed() -> Result<(), Error> {
    let store = memory_store().await;
    let both = [
        "https://c.example/three",
        "https://b.example/two",
        "https://a.example/one",
    ];
    let outcome = fetcher(&store)
        .await
        .fetch_blob(&job(&both, vec![]))
        .await?;

    assert_eq!(outcome.uri, "https://b.example/two");
    Ok(())
}

#[nativelink_test]
async fn a_checksum_mismatch_moves_on_to_the_next_uri() -> Result<(), Error> {
    let store = memory_store().await;
    let checksum = ByteChecksum::from_qualifier("checksum.sha256", &sha256_hex("two"))?;
    let outcome = fetcher(&store)
        .await
        .fetch_blob(&job(
            &["https://a.example/one", "https://b.example/two"],
            vec![checksum],
        ))
        .await?;

    assert_eq!(outcome.uri, "https://b.example/two");
    Ok(())
}

#[nativelink_test]
async fn a_checksum_nothing_matches_is_aborted() -> Result<(), Error> {
    let store = memory_store().await;
    let checksum = ByteChecksum::from_qualifier("checksum.sha256", &sha256_hex("other"))?;
    let err = fetcher(&store)
        .await
        .fetch_blob(&job(&["https://a.example/one"], vec![checksum]))
        .await
        .unwrap_err();

    assert_eq!(err.code, Code::Aborted);
    Ok(())
}

#[nativelink_test]
async fn directories_are_unimplemented() -> Result<(), Error> {
    let store = memory_store().await;
    let directory = FetchDirectoryJob {
        uris: vec!["https://a.example/one".to_owned()],
        qualifiers: vec![],
        checksums: vec![],
        hasher_func: DigestHasherFunc::Sha256,
        verified_by_action: false,
        timeout: None,
        shared_deadline: None,
        headers: FetchHeaders::default(),
        revalidate: vec![],
    };
    let err = fetcher(&store)
        .await
        .fetch_directory(&directory)
        .await
        .unwrap_err();

    assert_eq!(err.code, Code::Unimplemented);
    Ok(())
}
