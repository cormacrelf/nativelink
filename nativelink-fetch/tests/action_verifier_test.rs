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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use nativelink_config::stores::MemorySpec;
use nativelink_error::{Code, Error, make_err};
use nativelink_fetch::action_verifier::{
    ActionVerifier, FETCHED_DIRECTORY_ENV, parse_action_digest,
};
use nativelink_fetch::fetcher::{
    DirectoryChecksum, FetchBlobTask, FetchDirectoryJob, FetchHeaders, FetchOutcome, Fetcher,
};
use nativelink_macro::nativelink_test;
use nativelink_metric::{
    MetricFieldData, MetricKind, MetricPublishKnownKindData, MetricsComponent,
};
use nativelink_proto::build::bazel::remote::asset::v1::Qualifier;
use nativelink_proto::build::bazel::remote::execution::v2::command::EnvironmentVariable;
use nativelink_proto::build::bazel::remote::execution::v2::{
    Action, Command, Directory, DirectoryNode, FileNode,
};
use nativelink_store::ac_utils::{
    compute_buf_digest, get_and_decode_digest, serialize_and_upload_message,
};
use nativelink_store::memory_store::MemoryStore;
use nativelink_util::action_messages::{
    ActionInfo, ActionResult, ActionStage, ActionState, OperationId,
};
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::DigestHasherFunc;
use nativelink_util::operation_state_manager::{
    ActionStateResult, ActionStateResultStream, ClientStateManager, OperationFilter,
};
use nativelink_util::origin_event::OriginMetadata;
use nativelink_util::store_trait::{Store, StoreLike};
use parking_lot::Mutex;
use pretty_assertions::assert_eq;
use tonic::async_trait;

const HASHER: DigestHasherFunc = DigestHasherFunc::Sha256;

fn new_cas() -> Store {
    Store::new(MemoryStore::new(&MemorySpec::default()))
}

async fn put_bytes(cas: &Store, data: &[u8]) -> DigestInfo {
    let digest = compute_buf_digest(data, &mut HASHER.hasher());
    cas.update_oneshot(digest, Bytes::copy_from_slice(data))
        .await
        .unwrap();
    digest
}

async fn put<T: prost::Message>(cas: &Store, message: &T) -> DigestInfo {
    serialize_and_upload_message(message, cas.as_pin(), &mut HASHER.hasher())
        .await
        .unwrap()
}

/// Uploads a directory of `files` and `subdirs`, in name order.
async fn put_dir(
    cas: &Store,
    files: &[(&str, &[u8])],
    subdirs: &[(&str, DigestInfo)],
) -> DigestInfo {
    let mut dir = Directory::default();
    for (name, content) in files {
        dir.files.push(FileNode {
            name: (*name).to_owned(),
            digest: Some(put_bytes(cas, content).await.into()),
            ..Default::default()
        });
    }
    for (name, digest) in subdirs {
        dir.directories.push(DirectoryNode {
            name: (*name).to_owned(),
            digest: Some((*digest).into()),
        });
    }
    dir.files.sort_by(|a, b| a.name.cmp(&b.name));
    dir.directories.sort_by(|a, b| a.name.cmp(&b.name));
    put(cas, &dir).await
}

/// Uploads a verification action running `args`, with `env` and the input
/// root `root`.
async fn put_template(
    cas: &Store,
    args: &[&str],
    env: &[(&str, &str)],
    root: DigestInfo,
) -> DigestInfo {
    let command = Command {
        arguments: args.iter().map(|&arg| arg.to_owned()).collect(),
        environment_variables: env
            .iter()
            .map(|&(name, value)| EnvironmentVariable {
                name: name.to_owned(),
                value: value.to_owned(),
            })
            .collect(),
        ..Default::default()
    };
    let action = Action {
        command_digest: Some(put(cas, &command).await.into()),
        input_root_digest: Some(root.into()),
        ..Default::default()
    };
    put(cas, &action).await
}

/// Whether `path` (components joined by `/`) is in the tree `root`.
async fn exists(cas: &Store, root: DigestInfo, path: &str) -> bool {
    let mut dir: Directory = get_and_decode_digest(cas, root.into()).await.unwrap();
    let mut components = path.split('/').peekable();
    while let Some(name) = components.next() {
        let last = components.peek().is_none();
        if last && dir.files.iter().any(|file| file.name == name) {
            return true;
        }
        let Some(node) = dir.directories.iter().find(|node| node.name == name) else {
            return false;
        };
        if last {
            return true;
        }
        let digest = DigestInfo::try_from(node.digest.clone().unwrap()).unwrap();
        dir = get_and_decode_digest(cas, digest.into()).await.unwrap();
    }
    false
}

/// A fetcher serving a fixed tree per URI, trying the URIs in order, and
/// recording each job it is given.
#[derive(Debug, Default)]
struct Served {
    roots: HashMap<String, DigestInfo>,
    jobs: Mutex<Vec<FetchDirectoryJob>>,
}

#[async_trait]
impl Fetcher for Served {
    async fn fetch_blob(&self, _job: &FetchBlobTask) -> Result<FetchOutcome, Error> {
        Err(make_err!(Code::Unimplemented, "not part of this fixture"))
    }

    async fn fetch_directory(&self, job: &FetchDirectoryJob) -> Result<FetchOutcome, Error> {
        self.jobs.lock().push(job.clone());
        job.uris
            .iter()
            .find_map(|uri| {
                self.roots
                    .get(uri)
                    .map(|&digest| FetchOutcome::new(uri.clone(), digest))
            })
            .ok_or_else(|| make_err!(Code::NotFound, "no URI served anything"))
    }
}

/// A scheduler whose worker runs `check <path>...`: exit code 0 if every
/// path is in the input root, else 1 with the missing ones on stderr. It
/// also runs `crash <code>`, a checker that exits with `code` whatever the
/// input root holds.
#[derive(Debug)]
struct CheckingScheduler {
    cas: Store,
    actions: Mutex<Vec<Arc<ActionInfo>>>,
}

impl MetricsComponent for CheckingScheduler {
    fn publish(
        &self,
        _kind: MetricKind,
        _field_metadata: MetricFieldData,
    ) -> Result<MetricPublishKnownKindData, nativelink_metric::Error> {
        Ok(MetricPublishKnownKindData::Component)
    }
}

#[async_trait]
impl ClientStateManager for CheckingScheduler {
    async fn add_action(
        &self,
        _client_operation_id: OperationId,
        action_info: Arc<ActionInfo>,
    ) -> Result<Box<dyn ActionStateResult>, Error> {
        self.actions.lock().push(action_info.clone());
        let command: Command =
            get_and_decode_digest(&self.cas, action_info.command_digest.into()).await?;
        if command.arguments.first().map(String::as_str) == Some("crash") {
            let result = ActionResult {
                exit_code: command.arguments[1].parse().unwrap(),
                stderr_digest: put_bytes(&self.cas, b"sh: check-tool: not found").await,
                ..Default::default()
            };
            return Ok(done(result));
        }
        assert_eq!(command.arguments.first().map(String::as_str), Some("check"));
        let mut missing = Vec::new();
        for path in &command.arguments[1..] {
            if !exists(&self.cas, action_info.input_root_digest, path).await {
                missing.push(path.clone());
            }
        }
        let result = ActionResult {
            exit_code: i32::from(!missing.is_empty()),
            stderr_digest: put_bytes(&self.cas, format!("missing: {missing:?}").as_bytes()).await,
            ..Default::default()
        };
        Ok(done(result))
    }

    async fn filter_operations(
        &self,
        _filter: OperationFilter,
    ) -> Result<ActionStateResultStream, Error> {
        Err(make_err!(Code::Unimplemented, "not part of this fixture"))
    }
}

fn done(result: ActionResult) -> Box<dyn ActionStateResult> {
    Box::new(Done(Arc::new(ActionState {
        stage: ActionStage::Completed(result),
        last_transition_timestamp: SystemTime::now(),
        client_operation_id: OperationId::default(),
        action_digest: DigestInfo::zero_digest(),
    })))
}

struct Done(Arc<ActionState>);

#[async_trait]
impl ActionStateResult for Done {
    async fn as_state(&self) -> Result<(Arc<ActionState>, Option<OriginMetadata>), Error> {
        Ok((self.0.clone(), None))
    }

    async fn changed(&mut self) -> Result<(Arc<ActionState>, Option<OriginMetadata>), Error> {
        Ok((self.0.clone(), None))
    }

    async fn as_action_info(&self) -> Result<(Arc<ActionInfo>, Option<OriginMetadata>), Error> {
        Err(make_err!(Code::Unimplemented, "not part of this fixture"))
    }
}

struct Fixture {
    cas: Store,
    served: Arc<Served>,
    scheduler: Arc<CheckingScheduler>,
    verifier: Arc<ActionVerifier>,
}

impl Fixture {
    fn new(cas: Store, roots: &[(&str, DigestInfo)]) -> Self {
        let served = Arc::new(Served {
            roots: roots
                .iter()
                .map(|&(uri, digest)| (uri.to_owned(), digest))
                .collect(),
            ..Default::default()
        });
        let scheduler = Arc::new(CheckingScheduler {
            cas: cas.clone(),
            actions: Mutex::new(Vec::new()),
        });
        let verifier = ActionVerifier::new(
            served.clone(),
            cas.clone(),
            scheduler.clone(),
            "verify".to_owned(),
        );
        Self {
            cas,
            served,
            scheduler,
            verifier,
        }
    }

    fn calls(&self) -> usize {
        self.served.jobs.lock().len()
    }

    fn runs(&self) -> usize {
        self.scheduler.actions.lock().len()
    }
}

fn job(uris: &[&str], checksums: Vec<DirectoryChecksum>) -> FetchDirectoryJob {
    FetchDirectoryJob {
        verified_by_action: false,
        uris: uris.iter().map(|&uri| uri.to_owned()).collect(),
        qualifiers: vec![],
        checksums,
        hasher_func: HASHER,
        timeout: None,
        headers: FetchHeaders::default(),
    }
}

#[nativelink_test]
async fn fetched_tree_goes_where_the_command_says() -> Result<(), Error> {
    let cas = new_cas();
    let fetched = put_dir(&cas, &[("a.txt", b"alpha")], &[]).await;
    let tools = put_dir(&cas, &[("tool", b"#!/bin/sh")], &[]).await;
    let template_root = put_dir(&cas, &[], &[("bin", tools)]).await;
    let template = put_template(
        &cas,
        &["check", "bin/tool", "src/pkg/a.txt"],
        &[(FETCHED_DIRECTORY_ENV, "src/pkg")],
        template_root,
    )
    .await;
    let fixture = Fixture::new(cas, &[("https://a", fetched)]);

    let outcome = fixture
        .verifier
        .fetch_directory(&job(
            &["https://a"],
            vec![DirectoryChecksum::Action(template)],
        ))
        .await?;
    assert_eq!(
        outcome.digest, fetched,
        "the fetched tree, not the merged one"
    );
    let actions = fixture.scheduler.actions.lock();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].instance_name(), "verify");
    // The inner fetcher never sees the action checksum.
    assert_eq!(fixture.served.jobs.lock()[0].checksums, vec![]);
    Ok(())
}

#[nativelink_test]
async fn without_the_variable_the_fetched_tree_is_the_input_root() -> Result<(), Error> {
    let cas = new_cas();
    let fetched = put_dir(&cas, &[("a.txt", b"alpha")], &[]).await;
    let empty = put_dir(&cas, &[], &[]).await;
    let template = put_template(&cas, &["check", "a.txt"], &[], empty).await;
    let fixture = Fixture::new(cas, &[("https://a", fetched)]);

    fixture
        .verifier
        .fetch_directory(&job(
            &["https://a"],
            vec![DirectoryChecksum::Action(template)],
        ))
        .await?;
    let actions = fixture.scheduler.actions.lock();
    assert_eq!(actions[0].input_root_digest, fetched);
    Ok(())
}

#[nativelink_test]
async fn grafting_keeps_the_rest_of_an_existing_directory() -> Result<(), Error> {
    let cas = new_cas();
    let fetched = put_dir(&cas, &[("a.txt", b"alpha")], &[]).await;
    let b = put_dir(&cas, &[("tool", b"tool")], &[]).await;
    let a = put_dir(&cas, &[("readme", b"hi")], &[("b", b)]).await;
    let template_root = put_dir(&cas, &[], &[("a", a)]).await;
    let template = put_template(
        &cas,
        &["check", "a/readme", "a/b/tool", "a/c/a.txt"],
        &[(FETCHED_DIRECTORY_ENV, "a/c")],
        template_root,
    )
    .await;
    let fixture = Fixture::new(cas, &[("https://a", fetched)]);

    fixture
        .verifier
        .fetch_directory(&job(
            &["https://a"],
            vec![DirectoryChecksum::Action(template)],
        ))
        .await?;
    Ok(())
}

/// A URI whose content fails verification is like one whose bytes fail a
/// checksum: the next URI is tried, with the headers meant for it.
#[nativelink_test]
async fn a_failed_verification_falls_through_to_the_next_uri() -> Result<(), Error> {
    let cas = new_cas();
    let wrong = put_dir(&cas, &[("b.txt", b"beta")], &[]).await;
    let right = put_dir(&cas, &[("a.txt", b"alpha")], &[]).await;
    let empty = put_dir(&cas, &[], &[]).await;
    let template = put_template(&cas, &["check", "a.txt"], &[], empty).await;
    let fixture = Fixture::new(cas, &[("https://a", wrong), ("https://b", right)]);

    let mut fetch = job(
        &["https://a", "https://b"],
        vec![DirectoryChecksum::Action(template)],
    );
    let header = Qualifier {
        name: "http_header_url:1:x-for".to_owned(),
        value: "b".to_owned(),
    };
    fetch.headers = FetchHeaders::from_qualifiers(&[header], 2)?;
    let outcome = fixture.verifier.fetch_directory(&fetch).await?;
    assert_eq!(outcome.uri, "https://b");
    assert_eq!(outcome.digest, right);

    let jobs = fixture.served.jobs.lock();
    assert_eq!(jobs.len(), 2);
    assert_eq!(jobs[1].uris, vec!["https://b".to_owned()]);
    assert_eq!(
        jobs[1].headers.for_uri(0).get("x-for").unwrap(),
        "b",
        "the second URI's headers moved with it"
    );
    Ok(())
}

#[nativelink_test]
async fn every_uri_failing_verification_is_aborted() -> Result<(), Error> {
    let cas = new_cas();
    let wrong = put_dir(&cas, &[("b.txt", b"beta")], &[]).await;
    let empty = put_dir(&cas, &[], &[]).await;
    let template = put_template(&cas, &["check", "a.txt"], &[], empty).await;
    let fixture = Fixture::new(cas, &[("https://a", wrong), ("https://b", wrong)]);

    let err = fixture
        .verifier
        .fetch_directory(&job(
            &["https://a", "https://b"],
            vec![DirectoryChecksum::Action(template)],
        ))
        .await
        .expect_err("nothing passes");
    assert_eq!(err.code, Code::Aborted);
    let message = err.message_string();
    assert!(message.contains("exited with 1"), "{message}");
    assert!(
        message.contains("missing: [\"a.txt\"]"),
        "stderr: {message}"
    );
    assert!(message.contains("https://b"), "{message}");
    assert_eq!(fixture.runs(), 2);
    Ok(())
}

/// Exit code 1 is the checker's "no": the next URI is tried.
#[nativelink_test]
async fn exit_code_1_is_a_mismatch_and_the_next_uri_is_tried() -> Result<(), Error> {
    let cas = new_cas();
    let a = put_dir(&cas, &[("a.txt", b"alpha")], &[]).await;
    let b = put_dir(&cas, &[("b.txt", b"beta")], &[]).await;
    let empty = put_dir(&cas, &[], &[]).await;
    let template = put_template(&cas, &["crash", "1"], &[], empty).await;
    let fixture = Fixture::new(cas, &[("https://a", a), ("https://b", b)]);

    let err = fixture
        .verifier
        .fetch_directory(&job(
            &["https://a", "https://b"],
            vec![DirectoryChecksum::Action(template)],
        ))
        .await
        .expect_err("every URI is rejected");
    assert_eq!(err.code, Code::Aborted);
    assert_eq!(fixture.calls(), 2, "both URIs were tried");
    assert_eq!(fixture.runs(), 2);
    Ok(())
}

/// Any other exit code means the checker is broken: the request fails at
/// once, with the exit code and stderr, without fetching more URIs.
#[nativelink_test]
async fn any_other_exit_code_fails_the_request_without_trying_more_uris() -> Result<(), Error> {
    for code in [2, 127, 137, -1] {
        let cas = new_cas();
        let a = put_dir(&cas, &[("a.txt", b"alpha")], &[]).await;
        let b = put_dir(&cas, &[("b.txt", b"beta")], &[]).await;
        let empty = put_dir(&cas, &[], &[]).await;
        let template = put_template(&cas, &["crash", &code.to_string()], &[], empty).await;
        let fixture = Fixture::new(cas, &[("https://a", a), ("https://b", b)]);

        let err = fixture
            .verifier
            .fetch_directory(&job(
                &["https://a", "https://b"],
                vec![DirectoryChecksum::Action(template)],
            ))
            .await
            .expect_err("the checker is broken");
        assert_eq!(err.code, Code::Internal, "exit {code}: {err:?}");
        let message = err.message_string();
        assert!(
            message.contains(&format!("exited with {code}")),
            "{message}"
        );
        assert!(message.contains("check-tool: not found"), "{message}");
        assert_eq!(fixture.calls(), 1, "exit {code}: only the first URI");
        assert_eq!(fixture.runs(), 1, "exit {code}");
    }
    Ok(())
}

#[nativelink_test]
async fn a_missing_template_fails_before_fetching() -> Result<(), Error> {
    let cas = new_cas();
    let fetched = put_dir(&cas, &[("a.txt", b"alpha")], &[]).await;
    let fixture = Fixture::new(cas, &[("https://a", fetched)]);
    let absent = parse_action_digest(&format!("{}/42", "ab".repeat(32)))?;

    let err = fixture
        .verifier
        .fetch_directory(&job(
            &["https://a"],
            vec![DirectoryChecksum::Action(absent)],
        ))
        .await
        .expect_err("no template");
    assert_eq!(err.code, Code::FailedPrecondition);
    assert_eq!(fixture.calls(), 0, "nothing was fetched");

    // So is a template whose command is missing.
    let empty = put_dir(&fixture.cas, &[], &[]).await;
    let no_command = Action {
        command_digest: Some(compute_buf_digest(b"not in the CAS", &mut HASHER.hasher()).into()),
        input_root_digest: Some(empty.into()),
        ..Default::default()
    };
    let template = put(&fixture.cas, &no_command).await;
    let err = fixture
        .verifier
        .fetch_directory(&job(
            &["https://a"],
            vec![DirectoryChecksum::Action(template)],
        ))
        .await
        .expect_err("no command");
    assert_eq!(err.code, Code::FailedPrecondition);
    assert_eq!(fixture.calls(), 0, "nothing was fetched");
    Ok(())
}

#[nativelink_test]
async fn a_malformed_template_fails_before_fetching() -> Result<(), Error> {
    let cas = new_cas();
    let fetched = put_dir(&cas, &[("a.txt", b"alpha")], &[]).await;
    let tool = put_dir(&cas, &[("tool", b"tool")], &[]).await;
    let fixture = Fixture::new(cas.clone(), &[("https://a", fetched)]);

    let mut templates = vec![
        // Something in the input root, and nowhere said for the fetched tree.
        put_template(&cas, &["check", "a.txt"], &[], tool).await,
        // The path is taken.
        put_template(&cas, &["check"], &[(FETCHED_DIRECTORY_ENV, "tool")], tool).await,
    ];
    for path in ["", "/abs", "../up", "a/../b", "a//b", "."] {
        templates
            .push(put_template(&cas, &["check"], &[(FETCHED_DIRECTORY_ENV, path)], tool).await);
    }
    for template in templates {
        let err = fixture
            .verifier
            .fetch_directory(&job(
                &["https://a"],
                vec![DirectoryChecksum::Action(template)],
            ))
            .await
            .expect_err("malformed");
        assert_eq!(err.code, Code::InvalidArgument, "{err:?}");
    }
    assert_eq!(fixture.calls(), 0, "nothing was fetched");
    Ok(())
}

#[nativelink_test]
async fn fetches_without_an_action_checksum_pass_through() -> Result<(), Error> {
    let cas = new_cas();
    let fetched = put_dir(&cas, &[("a.txt", b"alpha")], &[]).await;
    let fixture = Fixture::new(cas, &[("https://a", fetched)]);

    let outcome = fixture
        .verifier
        .fetch_directory(&job(&["https://a"], vec![]))
        .await?;
    assert_eq!(outcome.digest, fetched);
    assert_eq!(fixture.runs(), 0);
    Ok(())
}

#[test]
fn action_digests_parse_as_hash_slash_size() {
    let hash = "ab".repeat(32);
    let digest = parse_action_digest(&format!("{hash}/42")).unwrap();
    assert_eq!(digest.size_bytes(), 42);
    for bad in [
        String::new(),
        hash.clone(),
        format!("{hash}/"),
        "xyz/1".to_owned(),
    ] {
        assert_eq!(
            parse_action_digest(&bad).unwrap_err().code,
            Code::InvalidArgument,
            "{bad}"
        );
    }
}
