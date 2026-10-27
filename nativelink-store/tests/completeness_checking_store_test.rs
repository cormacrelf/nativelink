// Copyright 2024 The NativeLink Authors. All rights reserved.
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

use core::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use nativelink_config::stores::MemorySpec;
use nativelink_error::{Code, Error, make_err};
use nativelink_macro::nativelink_test;
use nativelink_metric::MetricsComponent;
use nativelink_proto::build::bazel::remote::execution::v2::{
    ActionResult as ProtoActionResult, Directory, DirectoryNode, FileNode, OutputDirectory,
    OutputFile, Tree,
};
use nativelink_store::ac_utils::serialize_and_upload_message;
use nativelink_store::completeness_checking_store::CompletenessCheckingStore;
use nativelink_store::memory_store::MemoryStore;
use nativelink_util::buf_channel::{DropCloserReadHalf, DropCloserWriteHalf};
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::DigestHasherFunc;
use nativelink_util::health_utils::{HealthStatusIndicator, default_health_status_indicator};
use nativelink_util::store_trait::{
    RemoveItemCallback, Store, StoreDriver, StoreKey, StoreLike, UploadSizeInfo,
};

const ROOT_FILE: DigestInfo = DigestInfo::new([0u8; 32], 0);
const ROOT_DIRECTORY: DigestInfo = DigestInfo::new([1u8; 32], 0);
const CHILD_FILE: DigestInfo = DigestInfo::new([2u8; 32], 0);
const OUTPUT_FILE: DigestInfo = DigestInfo::new([4u8; 32], 0);
const STDOUT: DigestInfo = DigestInfo::new([5u8; 32], 0);
const STDERR: DigestInfo = DigestInfo::new([6u8; 32], 0);

async fn setup() -> Result<(Arc<CompletenessCheckingStore>, Arc<MemoryStore>, DigestInfo), Error> {
    let backend_store = Store::new(MemoryStore::new(&MemorySpec::default()));
    let cas_store = MemoryStore::new(&MemorySpec::default());
    let ac_store =
        CompletenessCheckingStore::new(backend_store.clone(), Store::new(cas_store.clone()));

    cas_store.update_oneshot(ROOT_FILE, "".into()).await?;
    // Note: Explicitly not uploading `ROOT_DIRECTORY`. See: TraceMachina/nativelink#747.
    cas_store.update_oneshot(CHILD_FILE, "".into()).await?;
    cas_store.update_oneshot(OUTPUT_FILE, "".into()).await?;
    cas_store.update_oneshot(STDOUT, "".into()).await?;
    cas_store.update_oneshot(STDERR, "".into()).await?;

    let tree = Tree {
        root: Some(Directory {
            files: vec![FileNode {
                digest: Some(ROOT_FILE.into()),
                ..Default::default()
            }],
            directories: vec![DirectoryNode {
                digest: Some(ROOT_DIRECTORY.into()),
                ..Default::default()
            }],
            ..Default::default()
        }),
        children: vec![Directory {
            files: vec![FileNode {
                digest: Some(CHILD_FILE.into()),
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    let tree_digest = serialize_and_upload_message(
        &tree,
        cas_store.as_pin(),
        &mut DigestHasherFunc::Blake3.hasher(),
    )
    .await?;

    let output_directory = OutputDirectory {
        tree_digest: Some(tree_digest.into()),
        ..Default::default()
    };

    serialize_and_upload_message(
        &output_directory,
        cas_store.as_pin(),
        &mut DigestHasherFunc::Blake3.hasher(),
    )
    .await?;

    let action_result = ProtoActionResult {
        output_files: vec![OutputFile {
            digest: Some(OUTPUT_FILE.into()),
            ..Default::default()
        }],
        output_directories: vec![output_directory],
        stdout_digest: Some(STDOUT.into()),
        stderr_digest: Some(STDERR.into()),
        ..Default::default()
    };

    // The structure of the action result is not following the spec, but is simplified for testing purposes.
    let action_result_digest = serialize_and_upload_message(
        &action_result,
        ac_store.as_pin(),
        &mut DigestHasherFunc::Blake3.hasher(),
    )
    .await?;

    Ok((ac_store, cas_store, action_result_digest))
}

#[nativelink_test]
async fn verify_has_function_call_checks_cas() -> Result<(), Error> {
    {
        // Completeness check should succeed when all digests exist in CAS.

        let (ac_store, _cas_store, action_result_digest) = setup().await?;

        let res = ac_store
            .has_many(&[action_result_digest.into()])
            .await
            .unwrap();
        assert!(
            res[0].is_some(),
            "Results should be some with all items in CAS."
        );
    }

    {
        // Completeness check should fail when root file digest is missing.

        let (ac_store, cas_store, action_result_digest) = setup().await?;

        cas_store.remove_entry(ROOT_FILE.into()).await;

        let res = ac_store
            .has_many(&[action_result_digest.into()])
            .await
            .unwrap();
        assert!(
            res[0].is_none(),
            "Results should be none with missing root file."
        );
    }

    {
        // Completeness check should fail when child file digest is missing.

        let (ac_store, cas_store, action_result_digest) = setup().await?;

        cas_store.remove_entry(CHILD_FILE.into()).await;
        let res = ac_store
            .has_many(&[action_result_digest.into()])
            .await
            .unwrap();
        assert!(
            res[0].is_none(),
            "Results should be none with missing root file."
        );
    }

    {
        // Completeness check should fail when output file digest is missing.

        let (ac_store, cas_store, action_result_digest) = setup().await?;

        cas_store.remove_entry(OUTPUT_FILE.into()).await;
        let res = ac_store
            .has_many(&[action_result_digest.into()])
            .await
            .unwrap();
        assert!(
            res[0].is_none(),
            "Results should be none with missing root file."
        );
    }

    {
        // Completeness check should fail when stdout digest is missing.

        let (ac_store, cas_store, action_result_digest) = setup().await?;

        cas_store.remove_entry(STDOUT.into()).await;
        let res = ac_store
            .has_many(&[action_result_digest.into()])
            .await
            .unwrap();
        assert!(
            res[0].is_none(),
            "Results should be none with missing root file."
        );
    }

    {
        // Completeness check should fail when stderr digest is missing.

        let (ac_store, cas_store, action_result_digest) = setup().await?;

        cas_store.remove_entry(STDERR.into()).await;
        let res = ac_store
            .has_many(&[action_result_digest.into()])
            .await
            .unwrap();
        assert!(
            res[0].is_none(),
            "Results should be none with missing root file."
        );
    }

    Ok(())
}

#[nativelink_test]
async fn verify_completeness_get() -> Result<(), Error> {
    {
        // Completeness check in get call should succeed when all digests exist in CAS.

        let (ac_store, _cas_store, action_result_digest) = setup().await?;

        assert!(
            ac_store
                .get_part_unchunked(action_result_digest, 0, None)
                .await
                .is_ok(),
            ".get() should succeed with all items in CAS",
        );
    }

    {
        // Completeness check in get call should fail when digest is missing in CAS.

        let (ac_store, cas_store, action_result_digest) = setup().await?;

        cas_store.remove_entry(OUTPUT_FILE.into()).await;

        assert!(
            ac_store
                .get_part_unchunked(action_result_digest, 0, None)
                .await
                .is_err(),
            ".get() should fail with item missing in CAS",
        );
    }

    Ok(())
}

/// Like `setup`, but the output directory's `Directory` blobs are uploaded to
/// the CAS, and the `ActionResult` names them through `tree_digest`,
/// `root_directory_digest` or both. Returns the child `Directory`'s digest too.
async fn setup_with_directories(
    with_tree: bool,
    with_root_directory: bool,
) -> Result<
    (
        Arc<CompletenessCheckingStore>,
        Arc<MemoryStore>,
        DigestInfo,
        DigestInfo,
    ),
    Error,
> {
    let backend_store = Store::new(MemoryStore::new(&MemorySpec::default()));
    let cas_store = MemoryStore::new(&MemorySpec::default());
    let ac_store =
        CompletenessCheckingStore::new(backend_store.clone(), Store::new(cas_store.clone()));
    let hasher = || DigestHasherFunc::Blake3.hasher();

    cas_store.update_oneshot(ROOT_FILE, "".into()).await?;
    cas_store.update_oneshot(CHILD_FILE, "".into()).await?;

    let child = Directory {
        files: vec![FileNode {
            digest: Some(CHILD_FILE.into()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let child_digest =
        serialize_and_upload_message(&child, cas_store.as_pin(), &mut hasher()).await?;
    let root = Directory {
        files: vec![FileNode {
            digest: Some(ROOT_FILE.into()),
            ..Default::default()
        }],
        directories: vec![DirectoryNode {
            digest: Some(child_digest.into()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let root_digest =
        serialize_and_upload_message(&root, cas_store.as_pin(), &mut hasher()).await?;

    let mut output_directory = OutputDirectory::default();
    if with_tree {
        let tree = Tree {
            root: Some(root),
            children: vec![child],
        };
        let tree_digest =
            serialize_and_upload_message(&tree, cas_store.as_pin(), &mut hasher()).await?;
        output_directory.tree_digest = Some(tree_digest.into());
    }
    if with_root_directory {
        output_directory.root_directory_digest = Some(root_digest.into());
    }
    let action_result = ProtoActionResult {
        output_directories: vec![output_directory],
        ..Default::default()
    };
    let action_result_digest =
        serialize_and_upload_message(&action_result, ac_store.as_pin(), &mut hasher()).await?;

    Ok((ac_store, cas_store, action_result_digest, child_digest))
}

async fn is_complete(
    ac_store: &Arc<CompletenessCheckingStore>,
    action_result_digest: DigestInfo,
) -> bool {
    ac_store
        .has_many(&[action_result_digest.into()])
        .await
        .unwrap()[0]
        .is_some()
}

#[nativelink_test]
async fn tree_only_output_directory_ignores_directory_blobs() -> Result<(), Error> {
    let (ac_store, cas_store, action_result_digest, child_digest) =
        setup_with_directories(true, false).await?;
    assert!(is_complete(&ac_store, action_result_digest).await);

    // Nothing promised the `Directory` blobs, so their absence is fine.
    cas_store.remove_entry(child_digest.into()).await;
    assert!(is_complete(&ac_store, action_result_digest).await);
    Ok(())
}

#[nativelink_test]
async fn tree_and_directory_output_directory_checks_directory_blobs() -> Result<(), Error> {
    let (ac_store, cas_store, action_result_digest, child_digest) =
        setup_with_directories(true, true).await?;
    assert!(is_complete(&ac_store, action_result_digest).await);

    cas_store.remove_entry(child_digest.into()).await;
    assert!(
        !is_complete(&ac_store, action_result_digest).await,
        "A missing child Directory should make the entry incomplete"
    );
    Ok(())
}

#[nativelink_test]
async fn directory_only_output_directory_is_walked() -> Result<(), Error> {
    {
        let (ac_store, _cas_store, action_result_digest, _child_digest) =
            setup_with_directories(false, true).await?;
        assert!(is_complete(&ac_store, action_result_digest).await);
    }
    {
        let (ac_store, cas_store, action_result_digest, child_digest) =
            setup_with_directories(false, true).await?;
        cas_store.remove_entry(child_digest.into()).await;
        assert!(
            !is_complete(&ac_store, action_result_digest).await,
            "A missing child Directory should make the entry incomplete"
        );
    }
    {
        let (ac_store, cas_store, action_result_digest, _child_digest) =
            setup_with_directories(false, true).await?;
        cas_store.remove_entry(CHILD_FILE.into()).await;
        assert!(
            !is_complete(&ac_store, action_result_digest).await,
            "A missing file in a child Directory should make the entry incomplete"
        );
    }
    Ok(())
}

/// A store driver whose reads always fail with a configurable, non-`NotFound`
/// backend error. Used to prove that a genuine backend read failure on the
/// action-result record is surfaced with its real code rather than laundered
/// into a `NotFound` "miss".
#[derive(Debug, MetricsComponent)]
struct AlwaysErrStore {
    code: Code,
}

#[async_trait]
impl StoreDriver for AlwaysErrStore {
    async fn post_init(self: Arc<Self>) -> Result<(), Error> {
        Ok(())
    }

    async fn has_with_results(
        self: Pin<&Self>,
        _keys: &[StoreKey<'_>],
        _results: &mut [Option<u64>],
    ) -> Result<(), Error> {
        Err(make_err!(
            self.code,
            "injected backend failure in has_with_results"
        ))
    }

    async fn update(
        self: Pin<&Self>,
        _key: StoreKey<'_>,
        _reader: DropCloserReadHalf,
        _size_info: UploadSizeInfo,
    ) -> Result<u64, Error> {
        Err(make_err!(self.code, "injected backend failure in update"))
    }

    async fn get_part(
        self: Pin<&Self>,
        _key: StoreKey<'_>,
        _writer: &mut DropCloserWriteHalf,
        _offset: u64,
        _length: Option<u64>,
    ) -> Result<(), Error> {
        Err(make_err!(self.code, "injected backend failure in get_part"))
    }

    fn inner_store(&self, _key: Option<StoreKey>) -> &dyn StoreDriver {
        self
    }

    fn as_any(&self) -> &(dyn core::any::Any + Sync + Send + 'static) {
        self
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn core::any::Any + Sync + Send + 'static> {
        self
    }

    fn register_remove_callback(
        self: Arc<Self>,
        _callback: Arc<dyn RemoveItemCallback>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

default_health_status_indicator!(AlwaysErrStore);

/// Regression: a real backend read/decode failure on the action-result record
/// must propagate with its underlying, non-`NotFound` code — it must NOT be
/// collapsed into `Code::NotFound`. A `NotFound` miss tells the client the
/// result does not exist and to re-execute; a backend fault (unavailable
/// Redis, decode failure) is transient and retryable, and serving it as a
/// clean miss silently discards a valid cached result. The genuine
/// eviction-miss path (referent absent) is covered by
/// `verify_has_function_call_checks_cas` and stays `NotFound`.
#[nativelink_test]
async fn backend_error_on_record_propagates_as_non_not_found() -> Result<(), Error> {
    let make_store = || {
        let ac_store = Store::new(Arc::new(AlwaysErrStore {
            code: Code::Unavailable,
        }));
        let cas_store = Store::new(MemoryStore::new(&MemorySpec::default()));
        CompletenessCheckingStore::new(ac_store, cas_store)
    };
    let some_digest = DigestInfo::new([9u8; 32], 123);

    // get_part path (nix narinfo GET / Bazel AC get).
    let get_err = make_store()
        .get_part_unchunked(some_digest, 0, None)
        .await
        .expect_err("a backend read failure must not be swallowed into a hit");
    assert_ne!(
        get_err.code,
        Code::NotFound,
        "backend fault must not masquerade as a NotFound miss (would 404)"
    );
    assert_eq!(
        get_err.code,
        Code::Unavailable,
        "backend fault must propagate with its real code"
    );

    // has path (nix narinfo HEAD / Bazel AC has).
    let has_err = make_store()
        .has(some_digest)
        .await
        .expect_err("a backend read failure on has must not be swallowed into a miss");
    assert_ne!(
        has_err.code,
        Code::NotFound,
        "backend fault on has must not masquerade as a NotFound miss (would 404)"
    );
    assert_eq!(
        has_err.code,
        Code::Unavailable,
        "backend fault on has must propagate with its real code"
    );

    Ok(())
}
