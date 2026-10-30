# Pinned Remote Asset cache model

`PinnedAssetCache.tla` models the metadata cache for requests that pin their
content with checksums: one entry per (algorithm, digest), each pointing at
the CAS digest of what the content was stored as, and a lookup that hits only
when every algorithm the request names has an entry and all of them agree on
the CAS digest.

The checksums are over the content as downloaded; the CAS digest names what
was stored, `Expand[content]`. For a blob those are the same bytes, so
`Expand` is injective (`Injective = TRUE`). For a directory the content is an
archive and the CAS digest is of the `Directory` it unpacked to, which
several archives can share, so `Expand` is any function
(`Injective = FALSE`).

Every configuration uses the same instance: two algorithms (`sha1`,
`sha256`), two contents (`abc`, `def`), two stored digests and two hash
digests, so every hash function and every expansion TLC tries can collide.
Two writers run concurrently with one reader, and entries and blobs are
evicted independently.

| Config | Checks | Expected |
| --- | --- | --- |
| `MC.cfg` | Blobs, from an empty cache: `TypeOK`, `Inv`, `HitsSatisfy`, `OneAnswer` | holds |
| `Ind.cfg` | Blobs, from every state satisfying `Inv`: `Inv` again, so `Inv` is inductive | holds |
| `Dir.cfg` | Directories, from an empty cache: `HitsSatisfy` | violated |
| `DirInd.cfg` | Directories, from every state satisfying `Inv`: `Inv`, `HitsSatisfyEach`, `OneAnswer` | holds |
| `Broken.cfg` | `HitsSatisfy` when a lookup takes the first entry it finds | violated |
| `Sanity.cfg` | `NoDoubleHit`: a hit on a query naming two algorithms is reachable | violated |

`Dir.cfg` fails in nine steps: `abc` and `def` both expand to `s1`; a fetch of
`abc` pinned by sha256 writes `(sha256, d1) -> s1`, a fetch of `def` pinned by
sha1 writes `(sha1, d2) -> s1`; a request for sha256 `d1` and sha1 `d2`, which
no content has, finds both entries agreeing on `s1` and hits. `DirInd.cfg`
shows what does hold for directories: each named algorithm is satisfied by
*some* archive that unpacked to the hit, not one archive by all of them.
`test_fetch_directory_pinned_hit_needs_one_archive_with_every_checksum` in
`nativelink-service/tests/fetch_server_test.rs` is the same trace against the
server, with two zips of the same files.

Run one with `tlc -config MC.cfg PinnedAssetCache.tla -workers auto`.
