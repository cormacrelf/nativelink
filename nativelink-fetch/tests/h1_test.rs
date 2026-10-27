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

use nativelink_error::Error;
use nativelink_fetch::tree_hash::TreeHashFormat;
use nativelink_fetch::tree_hash::h1::{H1, h1_from_file_hashes};
use nativelink_macro::nativelink_test;
use nativelink_util::digest_hasher::DigestHasherFunc;
use sha2::{Digest, Sha256};
use support::{
    Run, TarEntry, ZipEntry, compute_with, expect_mismatch, gzip, tar, values, verify, verify_with,
    zip,
};

type Entries<'a> = &'a [(&'a str, &'a [u8])];

/// Hashes each `(name, content)` entry with SHA-256, as an archive reader
/// would, and builds the h1 hash from them.
fn h1_of(entries: Entries<'_>) -> String {
    h1_from_file_hashes(
        entries
            .iter()
            .map(|(name, content)| ((*name).to_string(), Sha256::digest(content).into()))
            .collect(),
    )
}

#[test]
fn matches_go_reference_values() {
    // Reference values produced by Go's `golang.org/x/mod/sumdb/dirhash`
    // `HashZip(path, Hash1)`. The h1 hash depends only on entry names and
    // contents (not on archive framing).
    let cases: &[(Entries<'_>, &str)] = &[
        (
            &[("a.txt", b"alpha")],
            "h1:UNTfYNEnUVk709c1M57MBKKXNRV1j4Uk1HAFOXz9AUA=",
        ),
        (
            &[("a.txt", b"alpha"), ("b.txt", b"beta")],
            "h1:al32vIYl/KOLm1qGvSyhYfkHuXVp/H8rdx8ogzAXQOg=",
        ),
        (
            &[("a.txt", b"alpha"), ("dir/b.txt", b"beta")],
            "h1:kWPMSjDeD3YBAlqkLvUUBaF7Df+ezNEEbcEAZ5PO8ks=",
        ),
        // Insertion order differs from sorted order; must still match.
        (
            &[("z.txt", b"zed"), ("a.txt", b"alpha")],
            "h1:XUS9MtLxqnZHOBk09/XUky3TwEWQu/fmFnNiDtGf6C0=",
        ),
        (
            &[("empty.txt", b"")],
            "h1:KS7Xz7M518w+MKzspUIoRNF7K86vLaIut2xOMZFV/tk=",
        ),
        // Reference value from Go's dirhash.HashDir on the tree
        // {dir/b.txt: "beta"}.
        (
            &[("dir/b.txt", b"beta")],
            "h1:lN+rQ2Hj/B4hKlSz26AHhIQXB6ib7zX74cQVOiYBU3s=",
        ),
    ];
    for (entries, expected) in cases {
        assert_eq!(
            &h1_of(entries),
            expected,
            "mismatch for entries {entries:?}"
        );
    }
}

#[test]
fn hash_is_order_independent() {
    // The hash sorts entries by name, so insertion order must not matter.
    let a = h1_of(&[("a.txt", b"alpha"), ("b.txt", b"beta")]);
    let b = h1_of(&[("b.txt", b"beta"), ("a.txt", b"alpha")]);
    assert_eq!(a, b);
}

const SAMPLE_TAR: &[TarEntry<'static>] = &[
    TarEntry::File("hello.txt", b"hello", 0o644),
    TarEntry::File("bin/run.sh", b"#!/bin/sh\n", 0o755),
    TarEntry::File("bin/lib/inner.txt", b"inner", 0o644),
];

const SAMPLE_ZIP: &[ZipEntry<'static>] = &[
    ZipEntry::File("hello.txt", b"hello", 0o644),
    ZipEntry::File("bin/run.sh", b"#!/bin/sh\n", 0o755),
    ZipEntry::File("bin/lib/inner.txt", b"inner", 0o644),
];

/// Go's golang.org/x/mod/sumdb/dirhash Hash1 of the sample tree.
const SAMPLE_H1: &str = "h1:eaKXeVt14JAer3tWAksDUojfomDBytAf5Rowqv8PNtE=";

#[nativelink_test]
async fn h1_matches_go_reference_for_every_format() -> Result<(), Error> {
    let tar_data = tar(SAMPLE_TAR);
    for data in [zip(SAMPLE_ZIP), gzip(&tar_data), tar_data] {
        assert_eq!(values(&data, &H1, SAMPLE_H1).await, [SAMPLE_H1]);
        verify(&data, &H1, SAMPLE_H1).await.unwrap();
    }
    Ok(())
}

#[nativelink_test]
async fn h1_takes_file_hashes_from_the_pass_under_any_digest_function() -> Result<(), Error> {
    // Under BLAKE3 the CAS digest is not the SHA-256 h1 needs, so the set
    // computes it as the content streams past, including for spilled files.
    let tar_data = tar(SAMPLE_TAR);
    for inline_threshold in [None, Some(0)] {
        let run = Run {
            hasher_func: DigestHasherFunc::Blake3,
            inline_threshold,
        };
        verify_with(&tar_data, &[(&H1, SAMPLE_H1)], run)
            .await
            .unwrap();
    }
    Ok(())
}

#[nativelink_test]
async fn h1_skips_explicit_directory_entries_like_hashdir() -> Result<(), Error> {
    // Go's HashZip erroneously includes directory entries while HashDir does
    // not (https://github.com/golang/go/issues/53448); we match HashDir. So an
    // archive with an explicit "dir/" entry hashes the same as one without it.
    // Reference value from Go's dirhash.HashDir on the tree
    // {dir/b.txt: "beta"}.
    const GO_H1: &str = "h1:lN+rQ2Hj/B4hKlSz26AHhIQXB6ib7zX74cQVOiYBU3s=";
    let zip_data = zip(&[
        ZipEntry::Dir("dir/"),
        ZipEntry::File("dir/b.txt", b"beta", 0o644),
    ]);
    let tar_data = tar(&[
        TarEntry::Dir("dir/"),
        TarEntry::File("dir/b.txt", b"beta", 0o644),
    ]);
    for data in [zip_data, tar_data] {
        verify(&data, &H1, GO_H1).await.unwrap();
    }
    Ok(())
}

#[nativelink_test]
async fn h1_of_a_module_zip_covers_its_top_level_directory() -> Result<(), Error> {
    // A Go module zip puts every file under `<module>@<version>/`, and the h1
    // Go records covers that prefix. The same files without it hash
    // differently, and only the hash with the prefix matches.
    let archive = zip(&[ZipEntry::File("m@v1.0.0/a.txt", b"alpha", 0o644)]);
    let with_prefix = h1_of(&[("m@v1.0.0/a.txt", b"alpha")]);
    let without_prefix = h1_of(&[("a.txt", b"alpha")]);
    assert_ne!(with_prefix, without_prefix);
    assert_eq!(
        values(&archive, &H1, "").await,
        core::slice::from_ref(&with_prefix)
    );
    verify(&archive, &H1, &with_prefix).await.unwrap();
    let message = expect_mismatch(verify(&archive, &H1, &without_prefix).await);
    assert!(message.contains("checksum.h1 mismatch"), "{message}");
    assert!(message.contains(&with_prefix), "{message}");
    Ok(())
}

#[nativelink_test]
async fn h1_counts_only_the_last_of_a_repeated_tar_path() -> Result<(), Error> {
    // As in the expanded tree, and Go's HashDir of it.
    let archive = tar(&[
        TarEntry::File("a.txt", b"first", 0o644),
        TarEntry::File("a.txt", b"alpha", 0o644),
    ]);
    verify(&archive, &H1, &h1_of(&[("a.txt", b"alpha")]))
        .await
        .unwrap();
    Ok(())
}

#[nativelink_test]
async fn every_checksum_must_match_in_one_pass() -> Result<(), Error> {
    let archive = tar(SAMPLE_TAR);
    let other = h1_of(&[("a.txt", b"alpha")]);
    // The same checksum twice is computed once.
    let computed = compute_with(
        &archive,
        &[(&H1, SAMPLE_H1), (&H1, SAMPLE_H1)],
        Run::default(),
    )
    .await?;
    assert_eq!(computed.len(), 1);
    verify_with(
        &archive,
        &[(&H1, SAMPLE_H1), (&H1, SAMPLE_H1)],
        Run::default(),
    )
    .await
    .unwrap();
    // Two different values cannot both match, in either order.
    let one: [(&'static dyn TreeHashFormat, &str); 2] = [(&H1, SAMPLE_H1), (&H1, &other)];
    expect_mismatch(verify_with(&archive, &one, Run::default()).await);
    let two: [(&'static dyn TreeHashFormat, &str); 2] = [(&H1, &other), (&H1, SAMPLE_H1)];
    expect_mismatch(verify_with(&archive, &two, Run::default()).await);
    Ok(())
}
