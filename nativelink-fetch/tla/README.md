# Pinned Remote Asset cache model

`PinnedAssetCache.tla` models the metadata cache for requests that pin their
content with checksums: one entry per (algorithm, digest), each pointing at a
CAS digest, and a lookup that hits only when every algorithm the request names
has an entry and all of them agree on the CAS digest.

Every configuration uses the same instance: two algorithms (`sha1`, `sha256`),
two contents (`abc`, `def`) and two digests, so every hash function TLC tries
can collide. Two writers run concurrently with one reader, and entries and
blobs are evicted independently.

| Config | Checks | Expected |
| --- | --- | --- |
| `MC.cfg` | From an empty cache: `TypeOK`, `Inv`, `HitsSatisfy`, `OneAnswer` | holds |
| `Ind.cfg` | From every state satisfying `Inv`: `Inv` again, so `Inv` is inductive | holds |
| `Broken.cfg` | `HitsSatisfy` when a lookup takes the first entry it finds | violated |
| `Sanity.cfg` | `NoDoubleHit`: a hit on a query naming two algorithms is reachable | violated |
