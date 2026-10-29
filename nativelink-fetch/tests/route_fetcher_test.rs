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

//! Tests of [`RouteFetcher`] over recording test doubles.

use core::time::Duration;
use std::sync::Arc;

use nativelink_error::{Code, Error, make_err};
use nativelink_fetch::fetcher::{
    FetchBlobTask, FetchDirectoryJob, FetchHeaders, FetchOutcome, Fetcher,
};
use nativelink_fetch::route_fetcher::{Route, RouteFetcher, RouteMatch};
use nativelink_macro::nativelink_test;
use nativelink_proto::build::bazel::remote::asset::v1::Qualifier;
use nativelink_util::common::DigestInfo;
use nativelink_util::digest_hasher::DigestHasherFunc;
use parking_lot::Mutex;
use tonic::async_trait;

/// A job as a [`Recorder`] saw it.
#[derive(Clone, Debug)]
struct Seen {
    uris: Vec<String>,
    headers: FetchHeaders,
    timeout: Option<Duration>,
}

/// A `Fetcher` that records the jobs it gets and fails every one with `fail`,
/// or, when that is `None`, succeeds with the first URI.
#[derive(Debug)]
struct Recorder {
    seen: Mutex<Vec<Seen>>,
    fail: Option<Code>,
}

impl Recorder {
    fn succeeding() -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(Vec::new()),
            fail: None,
        })
    }

    fn failing(code: Code) -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(Vec::new()),
            fail: Some(code),
        })
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().clone()
    }

    fn record(
        &self,
        uris: &[String],
        headers: &FetchHeaders,
        timeout: Option<Duration>,
    ) -> Result<FetchOutcome, Error> {
        self.seen.lock().push(Seen {
            uris: uris.to_vec(),
            headers: headers.clone(),
            timeout,
        });
        match self.fail {
            Some(code) => Err(make_err!(code, "recorder failed")),
            None => Ok(FetchOutcome::new(
                uris[0].clone(),
                DigestInfo::zero_digest(),
            )),
        }
    }
}

#[async_trait]
impl Fetcher for Recorder {
    async fn fetch_blob(&self, job: &FetchBlobTask) -> Result<FetchOutcome, Error> {
        self.record(&job.uris, &job.headers, job.timeout)
    }

    async fn fetch_directory(&self, job: &FetchDirectoryJob) -> Result<FetchOutcome, Error> {
        self.record(&job.uris, &job.headers, job.timeout)
    }
}

fn route(hosts: &[&str], fetcher: Arc<Recorder>) -> Route {
    Route {
        matches: hosts_match(hosts),
        fetcher,
    }
}

fn hosts_match(hosts: &[&str]) -> RouteMatch {
    RouteMatch::hosts(hosts.iter().map(|host| host.parse().unwrap()).collect())
}

fn job(uris: &[&str]) -> FetchBlobTask {
    FetchBlobTask {
        uris: uris.iter().map(|&uri| uri.to_owned()).collect(),
        qualifiers: vec![],
        checksums: vec![],
        hasher_func: DigestHasherFunc::Sha256,
        timeout: None,
        headers: FetchHeaders::default(),
        revalidate: vec![],
        shared_deadline: None,
    }
}

#[nativelink_test]
async fn a_job_on_one_route_is_passed_on_unchanged() -> Result<(), Error> {
    let github = Recorder::succeeding();
    let other = Recorder::succeeding();
    let router = RouteFetcher::new(
        vec![route(&["github.com", "*.github.com"], github.clone())],
        Some(other.clone()),
    );

    let mut task = job(&[
        "https://github.com/a.tar.gz",
        "https://codeload.github.com/a",
    ]);
    task.timeout = Some(Duration::from_mins(1));
    router.fetch_blob(&task).await?;

    let seen = github.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].uris, task.uris);
    assert_eq!(seen[0].timeout, Some(Duration::from_mins(1)));
    assert!(other.seen().is_empty());
    Ok(())
}

#[nativelink_test]
async fn unmatched_hosts_go_to_otherwise() -> Result<(), Error> {
    let github = Recorder::succeeding();
    let other = Recorder::succeeding();
    let router = RouteFetcher::new(
        vec![route(&["github.com"], github.clone())],
        Some(other.clone()),
    );

    let outcome = router.fetch_blob(&job(&["https://example.com/a"])).await?;

    assert_eq!(outcome.uri, "https://example.com/a");
    assert!(github.seen().is_empty());
    assert_eq!(other.seen().len(), 1);
    Ok(())
}

#[nativelink_test]
async fn without_otherwise_unmatched_hosts_are_refused() -> Result<(), Error> {
    let github = Recorder::succeeding();
    let router = RouteFetcher::new(vec![route(&["github.com"], github.clone())], None);

    let err = router
        .fetch_blob(&job(&[
            "https://evil.example/a",
            "http://169.254.169.254/x",
        ]))
        .await
        .unwrap_err();

    assert_eq!(err.code, Code::PermissionDenied);
    let message = err.message_string();
    assert!(message.contains("'evil.example'"), "{message}");
    assert!(message.contains("'169.254.169.254'"), "{message}");
    assert!(github.seen().is_empty());
    Ok(())
}

#[nativelink_test]
async fn refused_mirrors_are_skipped_and_the_rest_fetched() -> Result<(), Error> {
    let github = Recorder::succeeding();
    let router = RouteFetcher::new(vec![route(&["github.com"], github.clone())], None);
    let mut task = job(&["https://evil.example/a", "https://github.com/a"]);
    // A header for the second URI must follow it to its new position.
    task.headers = FetchHeaders::from_qualifiers(
        &[Qualifier {
            name: "http_header_url:1:Authorization".to_owned(),
            value: "Bearer s3cret".to_owned(),
        }],
        2,
    )?;

    let outcome = router.fetch_blob(&task).await?;

    assert_eq!(outcome.uri, "https://github.com/a");
    let seen = github.seen();
    assert_eq!(seen[0].uris, vec!["https://github.com/a".to_owned()]);
    assert!(seen[0].headers.for_uri(0).contains_key("authorization"));
    Ok(())
}

#[nativelink_test]
async fn a_failing_route_falls_through_to_the_next() -> Result<(), Error> {
    let mirror = Recorder::failing(Code::NotFound);
    let other = Recorder::succeeding();
    let router = RouteFetcher::new(
        vec![route(&["mirror.example"], mirror.clone())],
        Some(other.clone()),
    );

    let outcome = router
        .fetch_blob(&job(&[
            "https://mirror.example/a",
            "https://origin.example/a",
            "https://mirror.example/b",
        ]))
        .await?;

    assert_eq!(outcome.uri, "https://origin.example/a");
    // The mirror's URIs went together, in their order, ahead of the origin.
    assert_eq!(
        mirror.seen()[0].uris,
        vec![
            "https://mirror.example/a".to_owned(),
            "https://mirror.example/b".to_owned()
        ]
    );
    Ok(())
}

#[nativelink_test]
async fn a_bad_request_is_not_retried_on_another_route() -> Result<(), Error> {
    let mirror = Recorder::failing(Code::InvalidArgument);
    let other = Recorder::succeeding();
    let router = RouteFetcher::new(
        vec![route(&["mirror.example"], mirror.clone())],
        Some(other.clone()),
    );

    let err = router
        .fetch_blob(&job(&[
            "https://mirror.example/a",
            "https://origin.example/a",
        ]))
        .await
        .unwrap_err();

    assert_eq!(err.code, Code::InvalidArgument);
    assert!(other.seen().is_empty());
    Ok(())
}

#[nativelink_test]
async fn the_last_failure_names_the_refused_hosts() -> Result<(), Error> {
    let mirror = Recorder::failing(Code::Unavailable);
    let router = RouteFetcher::new(vec![route(&["mirror.example"], mirror)], None);

    let err = router
        .fetch_blob(&job(&[
            "https://mirror.example/a",
            "https://other.example/a",
        ]))
        .await
        .unwrap_err();

    assert_eq!(err.code, Code::Unavailable);
    assert!(err.message_string().contains("'other.example'"), "{err:?}");
    Ok(())
}

#[nativelink_test]
async fn the_timeout_covers_every_route() -> Result<(), Error> {
    let mirror = Recorder::failing(Code::NotFound);
    let other = Recorder::succeeding();
    let router = RouteFetcher::new(
        vec![route(&["mirror.example"], mirror.clone())],
        Some(other.clone()),
    );
    let mut task = job(&["https://mirror.example/a", "https://origin.example/a"]);
    task.timeout = Some(Duration::from_mins(1));

    router.fetch_blob(&task).await?;

    // Each group gets what is left of the one budget, never more.
    for seen in mirror.seen().iter().chain(&other.seen()) {
        let timeout = seen.timeout.unwrap();
        assert!(timeout <= Duration::from_mins(1), "{timeout:?}");
    }
    Ok(())
}

#[nativelink_test]
async fn a_path_allowlist_refuses_other_paths_on_the_host() -> Result<(), Error> {
    let github = Recorder::succeeding();
    let router = RouteFetcher::new(
        vec![Route {
            matches: RouteMatch {
                schemes: vec!["https".parse()?],
                path_prefixes: vec!["/bazelbuild/".parse()?],
                ..hosts_match(&["github.com"])
            },
            fetcher: github.clone(),
        }],
        None,
    );

    for uri in [
        "https://github.com/evil/a.tar.gz",
        "https://github.com/bazelbuild/../evil/a.tar.gz",
        "https://github.com/bazelbuild/..%2Fevil/a.tar.gz",
        "https://github.com/bazelbuild/..;/evil/a.tar.gz",
        "https://github.com:8443/bazelbuild/a.tar.gz",
        "http://github.com/bazelbuild/a.tar.gz",
    ] {
        let err = router.fetch_blob(&job(&[uri])).await.unwrap_err();
        assert_eq!(err.code, Code::PermissionDenied, "{uri}");
    }
    assert!(github.seen().is_empty());

    let outcome = router
        .fetch_blob(&job(&[
            "https://github.com/evil/a.tar.gz",
            "https://github.com/bazelbuild/rules_go/a.tar.gz",
        ]))
        .await?;
    assert_eq!(
        outcome.uri,
        "https://github.com/bazelbuild/rules_go/a.tar.gz"
    );
    assert_eq!(github.seen()[0].uris, vec![outcome.uri]);
    Ok(())
}
