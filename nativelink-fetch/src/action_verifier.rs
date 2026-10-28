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

//! Verifies a fetched directory by running an action on it: the
//! `checksum.action_digest` qualifier.
//!
//! The qualifier names an `Action` the client uploaded to the CAS, with its
//! `Command` and input root. It is a template: once the inner fetcher has
//! expanded an archive, the action runs with the fetched tree in its input
//! root, through a scheduler in this process. Where the tree goes is up to the
//! command: at the relative path in its [`FETCHED_DIRECTORY_ENV`] environment
//! variable, which the command can also read to find it, or, without that
//! variable, as the whole input root, which must then be empty in the
//! template.
//!
//! The command's exit code is the contract between it and the server:
//!
//! - [`EXIT_VERIFIED`] (0): the tree is verified.
//! - [`EXIT_MISMATCH`] (1): the content does not match what the command
//!   expects. The URI served the wrong content, so the next one is tried; if
//!   none verifies, the request fails with `Aborted`.
//! - Any other exit code (a shell's 127 for a missing tool, 2 for misuse, a
//!   crash, an out-of-memory kill, death by signal): the checker itself failed,
//!   so it says nothing about the content. The request fails at once with
//!   `Internal`, without trying the remaining URIs, and the error carries the
//!   exit code and the start of the command's stderr.
//!
//! A template that is malformed fails the request (`InvalidArgument`) before
//! anything is downloaded, and so does one with blobs missing from the CAS:
//! `FailedPrecondition`, with a `google.rpc.PreconditionFailure` detail that
//! has one `MISSING` violation, subject `blobs/<hash>/<size>`, for each blob
//! the client has to upload before it retries.
//!
//! The server knows nothing about the format being checked; the expected
//! value is part of the command. Since the qualifier is part of the asset's
//! key, so is that value.

use core::fmt;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use nativelink_error::{Code, Error, ErrorContext, ResultExt, make_err, make_input_err};
use nativelink_proto::build::bazel::remote::execution::v2::{
    Action, Command, Directory, DirectoryNode,
};
use nativelink_store::ac_utils::{get_and_decode_digest, serialize_and_upload_message};
use nativelink_util::action_messages::{
    ActionInfo, ActionStage, ActionUniqueKey, ActionUniqueQualifier, DEFAULT_EXECUTION_PRIORITY,
    OperationId,
};
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::DigestHasherFunc;
use nativelink_util::operation_state_manager::ClientStateManager;
use nativelink_util::redact::redact_uri;
use nativelink_util::store_trait::{Store, StoreLike};
use tonic::async_trait;
use tracing::{info, warn};

use crate::fetcher::{DirectoryChecksum, FetchBlobTask, FetchDirectoryJob, FetchOutcome, Fetcher};

/// The Remote Asset qualifier naming the verification action.
pub const QUALIFIER_CHECKSUM_ACTION_DIGEST: &str = "checksum.action_digest";

/// The environment variable of the template's `Command` that says where in
/// the input root the fetched tree goes, as a relative path.
pub const FETCHED_DIRECTORY_ENV: &str = "NATIVELINK_FETCHED_DIRECTORY";

/// The verification command's exit code for a verified tree.
pub const EXIT_VERIFIED: i32 = 0;

/// The verification command's exit code for content that does not match. Any
/// exit code other than this and [`EXIT_VERIFIED`] means the command itself
/// failed.
pub const EXIT_MISMATCH: i32 = 1;

/// How much of a failed action's stderr goes into the mismatch error.
const MAX_STDERR_IN_ERROR: u64 = 4096;

/// Parses a `checksum.action_digest` value, `<hash>/<size_bytes>`.
pub fn parse_action_digest(value: &str) -> Result<DigestInfo, Error> {
    let (hash, size) = value.split_once('/').ok_or_else(|| {
        make_input_err!(
            "Malformed {QUALIFIER_CHECKSUM_ACTION_DIGEST} '{value}': expected <hash>/<size_bytes>"
        )
    })?;
    let size: u64 = size.parse().map_err(|_| {
        make_input_err!("Malformed {QUALIFIER_CHECKSUM_ACTION_DIGEST} '{value}': bad size")
    })?;
    DigestInfo::try_new(hash, size)
        .err_tip(|| format!("Malformed {QUALIFIER_CHECKSUM_ACTION_DIGEST} '{value}'"))
}

/// A [`Fetcher`] decorator that checks the `checksum.action_digest`
/// checksums of a directory fetch by running their actions on what the inner
/// fetcher fetched. Blob fetches, and directory fetches without such a
/// checksum, pass straight through.
pub struct ActionVerifier {
    inner: Arc<dyn Fetcher>,
    cas_store: Store,
    scheduler: Arc<dyn ClientStateManager>,
    instance_name: String,
}

impl fmt::Debug for ActionVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActionVerifier")
            .field("inner", &self.inner)
            .field("instance_name", &self.instance_name)
            .finish_non_exhaustive()
    }
}

/// A verification action, read from the CAS before anything is fetched.
struct Template {
    digest: DigestInfo,
    action: Action,
    command_digest: DigestInfo,
    platform_properties: HashMap<String, String>,
    /// Where the fetched tree goes, or `None` for the whole input root.
    graft: Option<Graft>,
}

/// The place in the template's input root the fetched tree goes.
struct Graft {
    /// The path's components; never empty.
    path: Vec<String>,
    /// The template's directories along the path: `dirs[i]` is the one at
    /// `path[..i]`, so `dirs[0]` is the input root. Missing ones are empty.
    dirs: Vec<Directory>,
}

impl ActionVerifier {
    pub fn new(
        inner: Arc<dyn Fetcher>,
        cas_store: Store,
        scheduler: Arc<dyn ClientStateManager>,
        instance_name: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner,
            cas_store,
            scheduler,
            instance_name,
        })
    }

    /// Reads the action `digest` and what it refers to from the CAS. A
    /// missing blob is `FailedPrecondition`, so the client can upload it and
    /// retry; a malformed template is `InvalidArgument`.
    ///
    /// The error for a missing blob carries a `PreconditionFailure` detail
    /// naming every blob that could be found missing in one pass. Each blob
    /// can only be read once the ones that point at it are, so that is the
    /// action alone, then its command and input root together, then the first
    /// missing directory along the graft path.
    async fn load_template(&self, digest: DigestInfo) -> Result<Template, Error> {
        let action: Action = self.get(digest, "action").await?;
        let command_digest = required_digest(action.command_digest.as_ref(), "command_digest")?;
        let input_root_digest =
            required_digest(action.input_root_digest.as_ref(), "input_root_digest")?;
        let (command, root) = both(
            self.get::<Command>(command_digest, "command").await,
            self.get::<Directory>(input_root_digest, "input root").await,
        )?;

        // As the execution service does: the action's platform, else the
        // command's.
        let platform = action
            .platform
            .as_ref()
            .filter(|platform| !platform.properties.is_empty())
            .or(command.platform.as_ref());
        let platform_properties = platform
            .map(|platform| {
                platform
                    .properties
                    .iter()
                    .map(|property| (property.name.clone(), property.value.clone()))
                    .collect()
            })
            .unwrap_or_default();

        let graft = match command
            .environment_variables
            .iter()
            .find(|variable| variable.name == FETCHED_DIRECTORY_ENV)
        {
            Some(variable) => Some(self.plan_graft(root, &variable.value).await?),
            None if is_empty(&root) => None,
            None => {
                return Err(make_input_err!(
                    "Verification action {digest} has a non-empty input root but no \
                     {FETCHED_DIRECTORY_ENV} to say where the fetched directory goes"
                ));
            }
        };
        Ok(Template {
            digest,
            action,
            command_digest,
            platform_properties,
            graft,
        })
    }

    /// Checks that the fetched tree can go at `path` in `root`, reading the
    /// directories along the way.
    async fn plan_graft(&self, root: Directory, path: &str) -> Result<Graft, Error> {
        let components = parse_path(path)?;
        let mut dirs = vec![root];
        for (depth, name) in components.iter().enumerate() {
            let dir = &dirs[depth];
            let is_last = depth + 1 == components.len();
            let taken = dir.files.iter().any(|file| &file.name == name)
                || dir.symlinks.iter().any(|link| &link.name == name);
            let subdir = dir.directories.iter().find(|node| &node.name == name);
            if taken || (is_last && subdir.is_some()) {
                return Err(make_input_err!(
                    "{FETCHED_DIRECTORY_ENV}='{path}' names an entry the input root already has"
                ));
            }
            if is_last {
                break;
            }
            let next = match subdir {
                Some(node) => {
                    let digest = required_digest(node.digest.as_ref(), "directory digest")?;
                    self.get(digest, "input directory").await?
                }
                None => Directory::default(),
            };
            dirs.push(next);
        }
        Ok(Graft {
            path: components,
            dirs,
        })
    }

    async fn get<T: prost::Message + Default + 'static>(
        &self,
        digest: DigestInfo,
        what: &str,
    ) -> Result<T, Error> {
        get_and_decode_digest(&self.cas_store, digest.into())
            .await
            .map_err(|err| {
                if err.code == Code::NotFound {
                    make_err!(
                        Code::FailedPrecondition,
                        "The verification {what} {digest} is not in the CAS; upload the action, \
                         its command and its input root before fetching"
                    )
                    .with_context(ErrorContext::MissingDigests(vec![(
                        digest.packed_hash().to_string(),
                        i64::try_from(digest.size_bytes()).unwrap_or(i64::MAX),
                    )]))
                } else {
                    err
                }
            })
    }

    /// The input root to run `template` with: the template's, with the
    /// fetched tree `fetched` grafted in.
    async fn input_root(
        &self,
        template: &Template,
        fetched: DigestInfo,
        hasher_func: DigestHasherFunc,
    ) -> Result<DigestInfo, Error> {
        let Some(graft) = &template.graft else {
            return Ok(fetched);
        };
        let mut child = fetched;
        for (dir, name) in graft.dirs.iter().zip(&graft.path).rev() {
            let mut dir = dir.clone();
            dir.directories.retain(|node| &node.name != name);
            dir.directories.push(DirectoryNode {
                name: name.clone(),
                digest: Some(child.into()),
            });
            dir.directories.sort_by(|a, b| a.name.cmp(&b.name));
            child = serialize_and_upload_message(
                &dir,
                self.cas_store.as_pin(),
                &mut hasher_func.hasher(),
            )
            .await
            .err_tip(|| "Uploading the verification input root")?;
        }
        Ok(child)
    }

    /// Runs `template` on the fetched tree `fetched`. `Ok(None)` means it is
    /// verified, `Ok(Some(err))` that it is not (`Aborted`). `Err` is a
    /// failure to run the action, or of the command itself (see
    /// [`Self::verdict`]).
    async fn verify(
        &self,
        template: &Template,
        fetched: DigestInfo,
        hasher_func: DigestHasherFunc,
    ) -> Result<Option<Error>, Error> {
        let input_root = self.input_root(template, fetched, hasher_func).await?;
        let mut action = template.action.clone();
        action.input_root_digest = Some(input_root.into());
        let action_digest = serialize_and_upload_message(
            &action,
            self.cas_store.as_pin(),
            &mut hasher_func.hasher(),
        )
        .await
        .err_tip(|| "Uploading the verification action")?;

        let key = ActionUniqueKey {
            execution_scope: None,
            instance_name: self.instance_name.clone(),
            digest_function: hasher_func,
            digest: action_digest,
        };
        let action_info = ActionInfo {
            command_digest: template.command_digest,
            input_root_digest: input_root,
            timeout: action.timeout.map_or(Duration::MAX, |timeout| {
                Duration::new(
                    u64::try_from(timeout.seconds).unwrap_or(0),
                    u32::try_from(timeout.nanos).unwrap_or(0),
                )
            }),
            platform_properties: template.platform_properties.clone(),
            priority: DEFAULT_EXECUTION_PRIORITY,
            load_timestamp: UNIX_EPOCH,
            insert_timestamp: SystemTime::now(),
            unique_qualifier: if action.do_not_cache {
                ActionUniqueQualifier::Uncacheable(key)
            } else {
                ActionUniqueQualifier::Cacheable(key)
            },
        };
        let mut listener = self
            .scheduler
            .add_action(OperationId::default(), Arc::new(action_info))
            .await
            .err_tip(|| "Scheduling the verification action")?;
        let mut state = listener.as_state().await?.0;
        loop {
            match &state.stage {
                ActionStage::Completed(result) => {
                    if let Some(err) = &result.error {
                        return Err(err
                            .clone()
                            .append(format!("Running verification action {}", template.digest)));
                    }
                    return self
                        .verdict(template, result.exit_code, Some(result.stderr_digest))
                        .await;
                }
                ActionStage::CompletedFromCache(result) => {
                    let stderr_digest = result
                        .stderr_digest
                        .clone()
                        .and_then(|digest| DigestInfo::try_from(digest).ok());
                    return self
                        .verdict(template, result.exit_code, stderr_digest)
                        .await;
                }
                _ => {}
            }
            state = listener
                .changed()
                .await
                .err_tip(|| "Waiting for the verification action")?
                .0;
        }
    }

    /// `Ok(None)` if `exit_code` says the directory is verified, `Ok(Some)`
    /// with the mismatch if it says the content is wrong, and `Err` if it
    /// says the command failed, in each case with the start of the action's
    /// stderr.
    ///
    /// A failed command is `Internal`: it is a fault in the verification
    /// machinery (a broken or missing tool, a crash, a resource limit), not in
    /// the client's request (`InvalidArgument`, `FailedPrecondition`), not a
    /// verdict on the content (`Aborted`), and not known to be transient
    /// (`Unavailable`), so retrying the same request is not expected to help.
    async fn verdict(
        &self,
        template: &Template,
        exit_code: i32,
        stderr_digest: Option<DigestInfo>,
    ) -> Result<Option<Error>, Error> {
        if exit_code == EXIT_VERIFIED {
            return Ok(None);
        }
        let stderr = match stderr_digest {
            Some(digest) => self.stderr(digest).await,
            None => String::new(),
        };
        if exit_code == EXIT_MISMATCH {
            return Ok(Some(make_err!(
                Code::Aborted,
                "Verification action {} exited with {exit_code}, so the content does not match: \
                 {stderr}",
                template.digest
            )));
        }
        Err(make_err!(
            Code::Internal,
            "Verification action {} failed: it exited with {exit_code}, not \
             {EXIT_VERIFIED} (verified) or {EXIT_MISMATCH} (mismatch), so the checker itself is \
             broken and no more URIs are tried: {stderr}",
            template.digest
        ))
    }

    /// The start of an action's stderr, for an error message.
    async fn stderr(&self, digest: DigestInfo) -> String {
        if digest.size_bytes() == 0 {
            return String::new();
        }
        match self
            .cas_store
            .get_part_unchunked(digest, 0, Some(MAX_STDERR_IN_ERROR))
            .await
        {
            Ok(bytes) => String::from_utf8_lossy(&bytes).trim_end().to_owned(),
            Err(err) => format!("(stderr unavailable: {err})"),
        }
    }

    /// Runs every template on `fetched`, stopping at the first that fails.
    async fn verify_all(
        &self,
        templates: &[Template],
        fetched: DigestInfo,
        hasher_func: DigestHasherFunc,
    ) -> Result<Option<Error>, Error> {
        for template in templates {
            if let Some(mismatch) = self.verify(template, fetched, hasher_func).await? {
                return Ok(Some(mismatch));
            }
        }
        Ok(None)
    }
}

#[async_trait]
impl Fetcher for ActionVerifier {
    async fn fetch_blob(&self, job: &FetchBlobTask) -> Result<FetchOutcome, Error> {
        self.inner.fetch_blob(job).await
    }

    async fn fetch_directory(&self, job: &FetchDirectoryJob) -> Result<FetchOutcome, Error> {
        let action_digests: Vec<DigestInfo> = job
            .checksums
            .iter()
            .filter_map(|checksum| match checksum {
                DirectoryChecksum::Action(digest) => Some(*digest),
                DirectoryChecksum::Bytes(_) | DirectoryChecksum::Tree(_) => None,
            })
            .collect();
        if action_digests.is_empty() {
            return self.inner.fetch_directory(job).await;
        }
        // Read the templates first, so a missing or malformed one fails
        // before anything is downloaded.
        let mut templates = Vec::with_capacity(action_digests.len());
        for digest in action_digests {
            templates.push(self.load_template(digest).await?);
        }

        let mut inner_job = job.clone();
        inner_job.verified_by_action = true;
        inner_job
            .checksums
            .retain(|checksum| !matches!(checksum, DirectoryChecksum::Action(_)));
        // The inner fetcher tries the URIs in order. When the one it settles
        // on fails verification, ask it again from the URI after that one.
        let mut first = 0;
        let mut last_mismatch = None;
        while first < job.uris.len() {
            let mut attempt = inner_job.clone();
            attempt.uris = job.uris[first..].to_vec();
            attempt.headers = job.headers.from_uri(first);
            let outcome = match self.inner.fetch_directory(&attempt).await {
                Ok(outcome) => outcome,
                Err(err) => {
                    return Err(match last_mismatch {
                        Some(mismatch) => err.merge(mismatch),
                        None => err,
                    });
                }
            };
            let served = attempt
                .uris
                .iter()
                .position(|uri| *uri == outcome.uri)
                .map_or(job.uris.len(), |idx| first + idx);
            match self
                .verify_all(&templates, outcome.digest, job.hasher_func)
                .await?
            {
                None => {
                    info!(uri = %redact_uri(&outcome.uri), "Fetched directory passed its verification action");
                    return Ok(outcome);
                }
                Some(mismatch) => {
                    warn!(uri = %redact_uri(&outcome.uri), %mismatch, "Fetched directory failed its verification action");
                    last_mismatch = Some(mismatch.append(format!(
                        "For the directory fetched from '{}'",
                        redact_uri(&outcome.uri)
                    )));
                    first = served + 1;
                }
            }
        }
        Err(last_mismatch
            .unwrap_or_else(|| make_err!(Code::NotFound, "No URIs available to fetch")))
    }
}

/// Both results' values, or the error of a failed one. When both failed
/// because of missing blobs, one error names all of them.
fn both<A, B>(a: Result<A, Error>, b: Result<B, Error>) -> Result<(A, B), Error> {
    match (a, b) {
        (Ok(a), Ok(b)) => Ok((a, b)),
        (Err(err), Ok(_)) | (Ok(_), Err(err)) => Err(err),
        (Err(mut a), Err(b)) => {
            if let (ErrorContext::MissingDigests(mine), ErrorContext::MissingDigests(theirs)) =
                (&mut a.context, &b.context)
            {
                mine.extend(theirs.iter().cloned());
                a.messages.extend(b.messages);
            }
            Err(a)
        }
    }
}

fn required_digest(
    digest: Option<&nativelink_proto::build::bazel::remote::execution::v2::Digest>,
    field: &str,
) -> Result<DigestInfo, Error> {
    let digest = digest.ok_or_else(|| make_input_err!("Verification action has no {field}"))?;
    DigestInfo::try_from(digest.clone()).err_tip(|| format!("Verification action's {field}"))
}

const fn is_empty(dir: &Directory) -> bool {
    dir.files.is_empty() && dir.directories.is_empty() && dir.symlinks.is_empty()
}

/// Splits a relative path into components, rejecting anything that could
/// leave the input root or is not a plain name.
fn parse_path(path: &str) -> Result<Vec<String>, Error> {
    let components: Vec<String> = path
        .split('/')
        .filter(|component| *component != ".")
        .map(str::to_owned)
        .collect();
    let bad = path.starts_with('/')
        || components.is_empty()
        || components
            .iter()
            .any(|c| c.is_empty() || c == ".." || c.contains('\0'));
    if bad {
        return Err(make_input_err!(
            "{FETCHED_DIRECTORY_ENV}='{path}' must be a relative path of plain names"
        ));
    }
    Ok(components)
}
