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

mod support;

use nativelink_error::{Code, Error};
use nativelink_fetch::tree_hash::git_tree::{GitTree, parse_git_tree_id};
use nativelink_fetch::tree_hash::nar::Nar;
use nativelink_fetch::tree_hash::{TreeChecksum, TreeHashFormat};
use nativelink_macro::nativelink_test;
use support::{
    FULL, Run, TarEntry, ZipEntry, expect_mismatch, tar, tar_under, values, verify_with, zip,
    zip_with_data_descriptors,
};

// Every expected value below was produced with git 2.55.0 by building the
// same tree on disk (with `printf`, `mkdir -p`, `chmod 755` for the
// executable, `ln -s` for symlinks, other files 0644) and running, in a fresh
// repository whose work tree is that directory,
//   git init --object-format=<sha1|sha256>
//   git -c core.filemode=true -c core.symlinks=true -c core.autocrlf=false add -A
//   git write-tree
// `git ls-tree -r -t` confirmed the modes and order. Julia 1.13.1's
// `Pkg.GitTools.tree_hash` (`SHA1_CTX` and `SHA256_CTX`) gives the same
// values, except for `GIT_FULL`: Julia sizes a symlink's blob by the number
// of characters in its target rather than bytes, so it disagrees with git
// about `lien`.

/// The NAR tests' `full` tree plus a directory holding only empty
/// directories, which git leaves out, and a symlink with a non-ASCII target.
/// Its root has the names `a` (a directory), `a-b` and `a.b`, which git
/// orders `a-b`, `a.b`, `a/` and a plain name order `a`, `a-b`, `a.b`.
fn git_full() -> Vec<TarEntry<'static>> {
    let mut entries = FULL.to_vec();
    entries.push(TarEntry::Dir("hollow/inner/deepest/"));
    entries.push(TarEntry::Link("lien", "café.txt"));
    entries
}

const GIT_FULL_SHA1: &str = "32afea5650bef7958d3b8a2c21e468a4d1f27744";
const GIT_FULL_SHA256: &str = "05f3e9d4cf535075b01c20a31bd92c77331186a399c47feb5540cc0ebe6c48e2";

/// A directory holding only `repo-1.0/`, the `git_full` tree.
const GIT_GITHUB_STYLE_SHA1: &str = "e974606c54045412686062cfd604c1a486f04c79";
const GIT_GITHUB_STYLE_SHA256: &str =
    "07f3674bf5510dfdf377be523cf259e005026d4c32c02775cf4339c26e174a85";

/// {a.txt: "alpha", dir/b.txt: "beta"}.
const ALPHA_BETA_SHA1: &str = "7b202b7775c7bfcdb392cc43bf9463fd13a19eac";
const ALPHA_BETA_SHA256: &str = "d56e1f038f1ca06fc27fe10f37f1377b40832c0ccd6e2782636e274a3606276a";

#[nativelink_test]
async fn git_tree_matches_git_write_tree() -> Result<(), Error> {
    let cases = [
        // An empty directory: git's empty tree.
        (
            zip(&[]),
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321",
        ),
        // A single regular file, "hello\n".
        (
            tar(&[TarEntry::File("hello.txt", b"hello\n", 0o644)]),
            "aaa96ced2d9a1c8e72c56b253a0e2fe78393feb7",
            "c7187e8fdb691b3a692e5f3f0bbcb6359e5046285225f18f9773d4fe54268c55",
        ),
        (
            tar(&[
                TarEntry::File("a.txt", b"alpha", 0o644),
                TarEntry::File("dir/b.txt", b"beta", 0o644),
            ]),
            ALPHA_BETA_SHA1,
            ALPHA_BETA_SHA256,
        ),
        // The NAR tests' tree, whose empty directory git leaves out.
        (
            tar(FULL),
            "5f9826c0f4c82dab9800ca2e0a49f6686301b34d",
            "3b0894a9b14b20aebb709deaaa6fadc41eb6b7f6cf1227eff676f8ab6645b454",
        ),
        (tar(&git_full()), GIT_FULL_SHA1, GIT_FULL_SHA256),
    ];
    for (archive, sha1, sha256) in cases {
        assert_eq!(values(&archive, &GitTree, sha1).await, [sha1]);
        assert_eq!(values(&archive, &GitTree, sha256).await, [sha256]);
    }
    Ok(())
}

#[nativelink_test]
async fn git_tree_of_the_single_top_level_directory_is_computed_too() -> Result<(), Error> {
    let archive = tar_under("repo-1.0/", &git_full());
    for (outer, inner) in [
        (GIT_GITHUB_STYLE_SHA1, GIT_FULL_SHA1),
        (GIT_GITHUB_STYLE_SHA256, GIT_FULL_SHA256),
    ] {
        assert_eq!(values(&archive, &GitTree, inner).await, [outer, inner]);
        for value in [outer, inner] {
            verify_with(&archive, &[(&GitTree, value)], Run::default())
                .await
                .unwrap();
        }
    }
    Ok(())
}

#[nativelink_test]
async fn git_tree_leaves_out_dot_git() -> Result<(), Error> {
    // git never tracks a `.git`, so a tree with some hashes as one without.
    let mut entries = git_full();
    entries.push(TarEntry::File(
        ".git/HEAD",
        b"ref: refs/heads/main\n",
        0o644,
    ));
    entries.push(TarEntry::File("sub/.git", b"gitdir: ../x\n", 0o644));
    assert_eq!(
        values(&tar(&entries), &GitTree, GIT_FULL_SHA1).await,
        [GIT_FULL_SHA1]
    );
    Ok(())
}

#[nativelink_test]
async fn git_tree_of_unknown_sizes_hashes_the_kept_bytes() -> Result<(), Error> {
    // A streaming zip writer's data descriptors: no size before the data, so
    // each blob is hashed once its entry is complete, from memory or, past
    // the inline threshold, from the expander's spill file.
    let archive = zip_with_data_descriptors(&[("a.txt", b"alpha"), ("dir/b.txt", b"beta")]);
    for inline_threshold in [None, Some(2)] {
        let run = Run {
            inline_threshold,
            ..Run::default()
        };
        for value in [ALPHA_BETA_SHA1, ALPHA_BETA_SHA256] {
            verify_with(&archive, &[(&GitTree, value)], run)
                .await
                .unwrap();
        }
    }
    Ok(())
}

#[nativelink_test]
async fn git_tree_takes_hard_links_and_zip_modes_from_the_listing() -> Result<(), Error> {
    // {f: "hello", h: "hello"}, with h a hard link, alongside checksum.nar.
    let archive = tar(&[
        TarEntry::File("f", b"hello", 0o644),
        TarEntry::Hard("h", "f"),
    ]);
    let both: [(&'static dyn TreeHashFormat, &str); 2] = [
        (&GitTree, "86280e4deb1946259aed6868a7ce059683ff44b0"),
        (&Nar, "sha256-gzT3jO65zlfxYQF+9Aei2Q3M/xwXwd8USUnnBHED75Q="),
    ];
    verify_with(&archive, &both, Run::default()).await.unwrap();
    assert_eq!(
        values(
            &archive,
            &GitTree,
            "7fd686fcf9dcf337c6bc587c49efdd9665ec9446fe287591fe517b99755fc3da"
        )
        .await,
        ["7fd686fcf9dcf337c6bc587c49efdd9665ec9446fe287591fe517b99755fc3da"]
    );

    // {data.txt: "d", run.sh: "#!/bin/sh\n" executable}, as a zip.
    let archive = zip(&[
        ZipEntry::File("data.txt", b"d", 0o644),
        ZipEntry::File("run.sh", b"#!/bin/sh\n", 0o755),
    ]);
    let both: [(&'static dyn TreeHashFormat, &str); 2] = [
        (&GitTree, "e3579f60426276e9da7d43a401edc319aeb1c1c4"),
        (&Nar, "sha256-gR+3NNFeyUjW0n16Yd7Z7ObyU4hq5JW4XqzhmxEd8tU="),
    ];
    verify_with(&archive, &both, Run::default()).await.unwrap();
    assert_eq!(
        values(
            &archive,
            &GitTree,
            "59b851f09a5be31921cec1e8d98916fc20d0b113515d16bb9afecc81b2a155b4"
        )
        .await,
        ["59b851f09a5be31921cec1e8d98916fc20d0b113515d16bb9afecc81b2a155b4"]
    );
    Ok(())
}

#[nativelink_test]
async fn git_tree_mismatch_reports_hex_ids() -> Result<(), Error> {
    let other = "0000000000000000000000000000000000000000";
    let message =
        expect_mismatch(verify_with(&tar(&git_full()), &[(&GitTree, other)], Run::default()).await);
    assert!(message.contains("checksum.git_tree mismatch"), "{message}");
    assert!(message.contains(other), "{message}");
    assert!(message.contains(GIT_FULL_SHA1), "{message}");
    Ok(())
}

#[nativelink_test]
async fn git_tree_ids_parse_in_either_case() -> Result<(), Error> {
    assert_eq!(parse_git_tree_id(GIT_FULL_SHA1)?.len(), 20);
    assert_eq!(parse_git_tree_id(GIT_FULL_SHA256)?.len(), 32);
    assert_eq!(
        parse_git_tree_id(&GIT_FULL_SHA1.to_uppercase())?,
        parse_git_tree_id(GIT_FULL_SHA1)?
    );
    assert_eq!(
        GitTree.parse(&GIT_FULL_SHA256.to_uppercase())?,
        GIT_FULL_SHA256
    );
    Ok(())
}

#[nativelink_test]
async fn malformed_git_tree_ids_are_invalid_arguments() {
    let malformed = [
        String::new(),
        // 39, 41 and 63 digits.
        GIT_FULL_SHA1[1..].to_owned(),
        format!("0{GIT_FULL_SHA1}"),
        GIT_FULL_SHA256[1..].to_owned(),
        format!("g{}", &GIT_FULL_SHA1[1..]),
        format!("sha1:{GIT_FULL_SHA1}"),
        // An abbreviated id.
        GIT_FULL_SHA1[..12].to_owned(),
    ];
    for value in malformed {
        let err = TreeChecksum::parse(&GitTree, &value).unwrap_err();
        assert_eq!(err.code, Code::InvalidArgument, "{value}");
        assert!(
            err.message_string().contains("checksum.git_tree"),
            "{value}: {err:?}"
        );
    }
}
