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
use nativelink_fetch::tree_hash::h1::H1;
use nativelink_fetch::tree_hash::nar::{Nar, nix32_encode, parse_nar_hash};
use nativelink_fetch::tree_hash::{TreeChecksum, TreeHashFormat};
use nativelink_macro::nativelink_test;
use support::{
    FULL, Run, TarEntry, ZipEntry, compute_with, expect_mismatch, gzip, tar, tar_under, values,
    verify_with, zip, zip_with_data_descriptors,
};

// Every expected value below was produced by building the same tree on disk
// (with `printf`, `mkdir`, `ln -s` for a symlink, `chmod 755` for an
// executable and 0644 for other files) and running Nix 2.35.3:
//   nix hash path --type sha256 <dir>                  (the SRI form)
//   nix hash convert --hash-algo sha256 --to nix32 <sri>
//   nix hash convert --hash-algo sha256 --to base16 <sri>

/// The `full` tree in no particular order.
const FULL_SHUFFLED: &[TarEntry<'static>] = &[
    TarEntry::File("pad8", b"12345678", 0o644),
    TarEntry::File("bin/run.sh", b"#!/bin/sh\necho hi\n", 0o755),
    TarEntry::Dir("empty/"),
    TarEntry::Link("link", "bin/run.sh"),
    TarEntry::File("nested/deeper/f", b"deep", 0o644),
    TarEntry::File("café.txt", b"unicode", 0o644),
    TarEntry::File("B", b"upper", 0o644),
    TarEntry::File("a/x", b"in a", 0o644),
    TarEntry::File("a-b", b"dash", 0o644),
    TarEntry::File("a.b", b"dot", 0o644),
    TarEntry::File("zero", b"", 0o644),
    TarEntry::File("pad7", b"1234567", 0o644),
];

/// `nix hash path` of the `full` tree, in each notation.
const NAR_FULL: &str = "sha256-CD7RjZWP2Wwdf1cvg37MXDGv/B/+cZ8c3FZ2dlJs3xk=";
const NAR_FULL_NIX32: &str = "06fzdi97cxjnvhf9ywgy3zyaycawriz86bspgwfnrncgjn6x2gh8";
const NAR_FULL_HEX: &str = "083ed18d958fd96c1d7f572f837ecc5c31affc1ffe719f1cdc567676526cdf19";

/// `nix hash path` of a directory holding only `repo-1.0/`, the `full` tree.
const NAR_GITHUB_STYLE: &str = "sha256-PAAUcXu152QthcT2Pz9ix+/YnLyjxYzkuSG5mEbXufk=";

/// `nix hash path` of {a.txt: "alpha", dir/b.txt: "beta"}.
const NAR_ALPHA_BETA: &str = "sha256-CsoZjhXuorHhbAO4sSoI+rDGBTK8qjwbH58H0hD8vNo=";

/// The log line of a NAR computed again from the expanded tree.
const REPLAYED: &str = "Computing the NAR hash again from the expanded tree";

async fn nar_values(archive: &[u8]) -> Vec<String> {
    values(archive, &Nar, NAR_FULL).await
}

#[nativelink_test]
async fn nar_matches_nix_in_one_pass() -> Result<(), Error> {
    let cases = [
        // An empty directory.
        (
            zip(&[]),
            "sha256-pQpattmS9VmO3ZIQUFn66az8GSmB4IvYhTTCFn6SUmo=",
        ),
        // A single regular file, "hello\n".
        (
            tar(&[TarEntry::File("hello.txt", b"hello\n", 0o644)]),
            "sha256-i9jJgC+rnkiRG+QQ31i/KRlnOwbAnAZM/cvj73cukwU=",
        ),
        (tar(FULL), NAR_FULL),
        (gzip(&tar(FULL)), NAR_FULL),
        (
            tar(&[
                TarEntry::File("a.txt", b"alpha", 0o644),
                TarEntry::File("dir/b.txt", b"beta", 0o644),
            ]),
            NAR_ALPHA_BETA,
        ),
        // A zip of regular files streams too; the modes are checked at the end.
        (
            zip(&[
                ZipEntry::File("a.txt", b"alpha", 0o644),
                ZipEntry::Dir("dir/"),
                ZipEntry::File("dir/b.txt", b"beta", 0o644),
            ]),
            NAR_ALPHA_BETA,
        ),
    ];
    for (archive, expected) in cases {
        assert_eq!(nar_values(&archive).await, [expected]);
    }
    assert!(!logs_contain(REPLAYED));
    Ok(())
}

#[nativelink_test]
async fn nar_of_the_single_top_level_directory_is_computed_too() -> Result<(), Error> {
    // As GitHub serves a tarball: everything under one `<repo>-<rev>/`.
    let archive = tar_under("repo-1.0/", FULL);
    assert_eq!(nar_values(&archive).await, [NAR_GITHUB_STYLE, NAR_FULL]);
    // Either matches.
    for value in [NAR_GITHUB_STYLE, NAR_FULL] {
        verify_with(&archive, &[(&Nar, value)], Run::default())
            .await
            .unwrap();
    }
    // With an explicit entry for the top-level directory too.
    let mut entries = vec![TarEntry::Dir("")];
    entries.extend_from_slice(FULL);
    assert_eq!(
        nar_values(&tar_under("repo-1.0/", &entries)).await,
        [NAR_GITHUB_STYLE, NAR_FULL]
    );
    assert!(!logs_contain(REPLAYED));
    Ok(())
}

#[nativelink_test]
async fn nar_hash_accepts_the_notations_nix_prints() -> Result<(), Error> {
    let expected = parse_nar_hash(NAR_FULL)?;
    assert_eq!(expected.len(), 32);
    for value in [
        format!("sha256:{NAR_FULL_NIX32}"),
        NAR_FULL_NIX32.to_owned(),
        format!("sha256:{NAR_FULL_HEX}"),
        NAR_FULL_HEX.to_owned(),
        NAR_FULL_HEX.to_uppercase(),
    ] {
        assert_eq!(parse_nar_hash(&value)?, expected, "{value}");
        // Every notation is checked as SRI.
        assert_eq!(Nar.parse(&value)?, NAR_FULL, "{value}");
    }
    assert_eq!(nix32_encode(&expected), NAR_FULL_NIX32);
    Ok(())
}

#[nativelink_test]
async fn malformed_nar_hashes_are_invalid_arguments() {
    let malformed = [
        String::new(),
        "sha256-".to_owned(),
        "sha256-not base64".to_owned(),
        // Valid base64, but of 31 bytes.
        "sha256-CD7RjZWP2Wwdf1cvg37MXDGv/B/+cZ8c3FZ2dlJs3w==".to_owned(),
        // Only SHA-256 is supported.
        "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
            .to_owned(),
        format!("md5:{NAR_FULL_NIX32}"),
        // 51 and 53 characters.
        NAR_FULL_NIX32[1..].to_owned(),
        format!("0{NAR_FULL_NIX32}"),
        // `e` is not in Nix's alphabet.
        format!("e{}", &NAR_FULL_NIX32[1..]),
        // The first digit carries bits past the 256th.
        format!("z{}", &NAR_FULL_NIX32[1..]),
        format!("g{}", &NAR_FULL_HEX[1..]),
    ];
    for value in malformed {
        let err = TreeChecksum::parse(&Nar, &value).unwrap_err();
        assert_eq!(err.code, Code::InvalidArgument, "{value}");
        assert!(
            err.message_string().contains("checksum.nar"),
            "{value}: {err:?}"
        );
    }
}

#[nativelink_test]
async fn nar_of_a_git_ordered_archive_is_computed_again() -> Result<(), Error> {
    // `git archive` sorts a directory as if its name ended in `/`, so it puts
    // `foo-x` and `foo.rs` before `foo/`, where a NAR has them after.
    // `nix hash path` of {foo-x, foo.rs, foo/bar.rs, foo/sub/z, zzz}, and of
    // the same under `repo-abc/`.
    const NAR_GIT_ORDER: &str = "sha256-yZWOCm1M493qYScZuhHicLRdChJQZdDW2Nz8Zcm5nD4=";
    const NAR_GIT_ORDER_WRAPPED: &str = "sha256-X7kgeRHr/t3Pll/iq2xNOIICgOHIu/1h0vYLQi5XCrU=";
    let entries = [
        TarEntry::File("foo-x", b"x\n", 0o644),
        TarEntry::File("foo.rs", b"rs\n", 0o644),
        TarEntry::Dir("foo/"),
        TarEntry::File("foo/bar.rs", b"bar\n", 0o644),
        TarEntry::File("foo/sub/z", b"z\n", 0o644),
        TarEntry::File("zzz", b"end\n", 0o644),
    ];
    assert_eq!(nar_values(&tar(&entries)).await, [NAR_GIT_ORDER]);
    assert_eq!(
        nar_values(&gzip(&tar_under("repo-abc/", &entries))).await,
        [NAR_GIT_ORDER_WRAPPED, NAR_GIT_ORDER]
    );
    // Large files are read again from the expander's spill files.
    let run = Run {
        inline_threshold: Some(1),
        ..Run::default()
    };
    verify_with(&tar(&entries), &[(&Nar, NAR_GIT_ORDER)], run)
        .await
        .unwrap();
    assert!(logs_contain("'foo/' after 'foo.rs'"));
    assert!(logs_contain(REPLAYED));
    Ok(())
}

#[nativelink_test]
async fn nar_of_an_archive_out_of_order_is_computed_again() -> Result<(), Error> {
    assert_eq!(nar_values(&tar(FULL_SHUFFLED)).await, [NAR_FULL]);
    assert_eq!(
        nar_values(&tar_under("repo-1.0/", FULL_SHUFFLED)).await,
        [NAR_GITHUB_STYLE, NAR_FULL]
    );
    assert!(logs_contain(REPLAYED));
    Ok(())
}

#[nativelink_test]
async fn nar_of_a_repeated_tar_path_has_the_last_entry() -> Result<(), Error> {
    // As the expanded tree does, and Nix's hash of it: {a.txt: "second", b.txt: "b"}.
    let archive = tar(&[
        TarEntry::File("a.txt", b"first", 0o644),
        TarEntry::File("b.txt", b"b", 0o644),
        TarEntry::File("a.txt", b"second", 0o644),
    ]);
    assert_eq!(
        nar_values(&archive).await,
        ["sha256-tJ+6VAHEjle/qq0XBvQFWiFtdgXxJAM2L/ijpE0/yXA="]
    );
    // Straight after itself, too.
    let archive = tar(&[
        TarEntry::File("a.txt", b"first", 0o644),
        TarEntry::File("a.txt", b"second", 0o644),
        TarEntry::File("b.txt", b"b", 0o644),
    ]);
    assert_eq!(
        nar_values(&archive).await,
        ["sha256-tJ+6VAHEjle/qq0XBvQFWiFtdgXxJAM2L/ijpE0/yXA="]
    );
    assert!(logs_contain("'a.txt' after 'a.txt'"));
    Ok(())
}

#[nativelink_test]
async fn nar_of_a_directory_entered_again_is_computed_again() -> Result<(), Error> {
    // {a/x: "x", a/y: "y", b: "b"}.
    let archive = tar(&[
        TarEntry::File("a/x", b"x", 0o644),
        TarEntry::File("b", b"b", 0o644),
        TarEntry::File("a/y", b"y", 0o644),
    ]);
    assert_eq!(
        nar_values(&archive).await,
        ["sha256-d9Zrg9qQ9y5ttFKcLdM15Yl+l+TVgUCN0zP0pZiIWZ0="]
    );
    assert!(logs_contain("'a/' after 'b'"));
    Ok(())
}

#[nativelink_test]
async fn nar_of_a_directory_entry_after_its_first_child_streams() -> Result<(), Error> {
    // {a/x: "x", b: "b"}.
    let archive = tar(&[
        TarEntry::File("a/x", b"x", 0o644),
        TarEntry::Dir("a/"),
        TarEntry::File("b", b"b", 0o644),
    ]);
    assert_eq!(
        nar_values(&archive).await,
        ["sha256-BRiBB+56O5TLKgEgdzNQZGu6uK4hOVqsq8qbbdEDmkE="]
    );
    assert!(!logs_contain(REPLAYED));
    Ok(())
}

#[nativelink_test]
async fn nar_of_a_hard_link_is_computed_again() -> Result<(), Error> {
    // Nix hashes a hard link as the regular file it is: {f: "hello", h: "hello"}.
    const NAR_HARD: &str = "sha256-gzT3jO65zlfxYQF+9Aei2Q3M/xwXwd8USUnnBHED75Q=";
    let archive = tar(&[
        TarEntry::File("f", b"hello", 0o644),
        TarEntry::Hard("h", "f"),
    ]);
    assert_eq!(nar_values(&archive).await, [NAR_HARD]);
    assert!(logs_contain("a hard link"));
    Ok(())
}

#[nativelink_test]
async fn nar_of_a_zip_with_an_executable_or_a_symlink_is_computed_again() -> Result<(), Error> {
    // A zip's modes are only known at its end, so the stream guessed wrong.
    // {data.txt: "d", run.sh: "#!/bin/sh\n" executable}.
    let archive = zip(&[
        ZipEntry::File("data.txt", b"d", 0o644),
        ZipEntry::File("run.sh", b"#!/bin/sh\n", 0o755),
    ]);
    assert_eq!(
        nar_values(&archive).await,
        ["sha256-gR+3NNFeyUjW0n16Yd7Z7ObyU4hq5JW4XqzhmxEd8tU="]
    );
    // {f.txt: "data", link -> f.txt}.
    let archive = zip(&[
        ZipEntry::File("f.txt", b"data", 0o644),
        ZipEntry::Link("link", "f.txt"),
    ]);
    assert_eq!(
        nar_values(&archive).await,
        ["sha256-eocSZItrdNm7HzG7vVDezGyqxC3+/UAsvNLqwgFY1CE="]
    );
    assert!(logs_contain("a zip entry is executable or a symlink"));
    Ok(())
}

#[nativelink_test]
async fn nar_of_zip_entries_of_unknown_size_is_computed_again() -> Result<(), Error> {
    // A streaming zip writer's data descriptors, and files spilled to disk.
    let archive = zip_with_data_descriptors(&[("a.txt", b"alpha"), ("dir/b.txt", b"beta")]);
    for inline_threshold in [None, Some(2)] {
        let run = Run {
            inline_threshold,
            ..Run::default()
        };
        verify_with(&archive, &[(&Nar, NAR_ALPHA_BETA)], run)
            .await
            .unwrap();
    }
    assert!(logs_contain("size is not known"));
    Ok(())
}

#[nativelink_test]
async fn nar_and_other_checksums_are_checked_in_one_pass() -> Result<(), Error> {
    // {f: "hello", h: "hello"}, as a hard link.
    const NAR_HARD: &str = "sha256-gzT3jO65zlfxYQF+9Aei2Q3M/xwXwd8USUnnBHED75Q=";
    let archive = tar(&[
        TarEntry::File("f", b"hello", 0o644),
        TarEntry::Hard("h", "f"),
    ]);
    let h1 = values(&archive, &H1, "").await.remove(0);
    let both: [(&'static dyn TreeHashFormat, &str); 2] = [(&Nar, NAR_HARD), (&H1, &h1)];
    let computed = compute_with(&archive, &both, Run::default()).await?;
    assert_eq!(computed.len(), 2);
    verify_with(&archive, &both, Run::default()).await.unwrap();

    let wrong: [(&'static dyn TreeHashFormat, &str); 2] = [(&Nar, NAR_FULL), (&H1, &h1)];
    let message = expect_mismatch(verify_with(&archive, &wrong, Run::default()).await);
    assert!(message.contains("checksum.nar mismatch"), "{message}");
    assert!(message.contains(NAR_FULL), "{message}");
    assert!(message.contains(NAR_HARD), "{message}");
    Ok(())
}
