-------------------------- MODULE PinnedAssetCache --------------------------
(***************************************************************************)
(* The Remote Asset metadata cache for pinned requests, keyed per hash.    *)
(*                                                                         *)
(* An entry's key is one (algorithm, digest) pair, plus the request's      *)
(* other qualifiers (left out here: they only partition the key space).    *)
(* Its value is a digest naming the content, Expand[content]. The named    *)
(* hashes are over the content as downloaded, and the reader compares the  *)
(* values, so the scheme needs Expand injective (Injective = TRUE: digests *)
(* are assumed not to collide). For a blob the value is its CAS digest.    *)
(* For a directory the content is an archive, and the value the server     *)
(* compares is the archive's own digest, recorded with the entry; the      *)
(* Directory it unpacked to would not do, as several archives share one.   *)
(* Injective = FALSE is that mistake: comparing the Directory. The named   *)
(* hashes are allowed to collide freely: Digests is smaller than Contents, *)
(* and TLC tries every hash function.                                      *)
(*                                                                         *)
(* A writer (a fetch, or a push of a blob already in the CAS) verifies the *)
(* content against every algorithm the request names, then writes one     *)
(* entry per named algorithm, one key at a time. It may crash between      *)
(* writes. It hashes only what the request names: entries carry no other   *)
(* hashes.                                                                 *)
(*                                                                         *)
(* A reader hits only when it finds, for every named algorithm, an entry   *)
(* under one of that algorithm's accepted digests, all pointing at the     *)
(* same CAS digest, and that blob is in the CAS. It reads one key per      *)
(* step, in any order, interleaved with writes and evictions.              *)
(*                                                                         *)
(* CheckAll = FALSE is the scheme that takes the first entry it finds.     *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Algs, Contents, Stored, Digests, Writers, Readers, None,
          CheckAll, Injective

Keys == Algs \X Digests

\* What a request accepts, per algorithm; {} when it does not name it.
Queries == {q \in [Algs -> SUBSET Digests] : \E a \in Algs : q[a] # {}}
Named(q) == {a \in Algs : q[a] # {}}

\* Content c satisfies q: each named algorithm matches one of its digests.
Sat(h, c, q) == \A a \in Named(q) : h[a][c] \in q[a]

Phases == {"idle", "probe", "check", "final", "hit", "miss"}

VARIABLES
    H,      \* the hash functions, chosen once
    Expand, \* content -> CAS digest of what it stores as, chosen once
    cache,  \* key -> CAS digest, or None
    cas,    \* the blobs in the CAS
    ws,     \* writers: the content being recorded and the keys left to write
    rs      \* readers: the query, the candidate and the algorithms left

vars == <<H, Expand, cache, cas, ws, rs>>

Expansions ==
    {e \in [Contents -> Stored] :
        Injective => \A c1, c2 \in Contents : e[c1] = e[c2] => c1 = c2}

WriterState == [c : Contents \cup {None}, todo : SUBSET Keys]
ReaderState == [phase : Phases, q : Queries, cand : Stored \cup {None},
                todo : SUBSET Algs]

TypeOK ==
    /\ H \in [Algs -> [Contents -> Digests]]
    /\ Expand \in Expansions
    /\ cache \in [Keys -> Stored \cup {None}]
    /\ cas \subseteq Stored
    /\ ws \in [Writers -> WriterState]
    /\ rs \in [Readers -> ReaderState]

Init ==
    /\ H \in [Algs -> [Contents -> Digests]]
    /\ Expand \in Expansions
    /\ cache = [k \in Keys |-> None]
    /\ cas = {}
    /\ ws = [w \in Writers |-> [c |-> None, todo |-> {}]]
    /\ rs = [r \in Readers |->
                [phase |-> "idle", q |-> CHOOSE q \in Queries : TRUE,
                 cand |-> None, todo |-> {}]]

---------------------------------------------------------------------------
(* Writers *)

\* Download c from any mirror (they may serve anything) and verify it.
\* A download that fails verification writes nothing, so it is not a step.
Fetch(w) ==
    /\ ws[w].todo = {}
    /\ \E q \in Queries, c \in Contents :
        /\ Sat(H, c, q)
        /\ cas' = cas \cup {Expand[c]}
        /\ ws' = [ws EXCEPT ![w] =
                    [c |-> c, todo |-> {<<a, H[a][c]>> : a \in Named(q)}]]
    /\ UNCHANGED <<H, Expand, cache, rs>>

\* PushBlob: the blob must already be in the CAS, and is verified the same
\* way. Only for blobs: a directory's archive is not there to verify, so
\* PushDirectory with a byte checksum is rejected.
Push(w) ==
    /\ Injective
    /\ ws[w].todo = {}
    /\ \E q \in Queries, c \in Contents :
        /\ Expand[c] \in cas
        /\ Sat(H, c, q)
        /\ ws' = [ws EXCEPT ![w] =
                    [c |-> c, todo |-> {<<a, H[a][c]>> : a \in Named(q)}]]
    /\ UNCHANGED <<H, Expand, cache, cas, rs>>

WriteKey(w) ==
    /\ \E k \in ws[w].todo :
        /\ cache' = [cache EXCEPT ![k] = Expand[ws[w].c]]
        /\ ws' = [ws EXCEPT ![w].todo = @ \ {k}]
    /\ UNCHANGED <<H, Expand, cas, rs>>

Crash(w) ==
    /\ ws[w].todo # {}
    /\ ws' = [ws EXCEPT ![w].todo = {}]
    /\ UNCHANGED <<H, Expand, cache, cas, rs>>

---------------------------------------------------------------------------
(* Eviction, of entries and blobs independently *)

EvictKey ==
    /\ \E k \in Keys : cache[k] # None /\ cache' = [cache EXCEPT ![k] = None]
    /\ UNCHANGED <<H, Expand, cas, ws, rs>>

EvictBlob ==
    /\ \E s \in cas : cas' = cas \ {s}
    /\ UNCHANGED <<H, Expand, cache, ws, rs>>

---------------------------------------------------------------------------
(* Readers *)

Start(r) ==
    /\ rs[r].phase \in {"idle", "hit", "miss"}
    /\ \E q \in Queries :
        rs' = [rs EXCEPT ![r] =
                [phase |-> "probe", q |-> q, cand |-> None, todo |-> Named(q)]]
    /\ UNCHANGED <<H, Expand, cache, cas, ws>>

\* Read any key of any named algorithm: strongest first is one such order.
\* Reading a missing key changes nothing, so it is not a step either.
Probe(r) ==
    LET s == rs[r] IN
    /\ s.phase = "probe"
    /\ \E a \in s.todo : \E d \in s.q[a] :
        /\ cache[<<a, d>>] # None
        /\ rs' = [rs EXCEPT ![r] =
                    [s EXCEPT !.cand = cache[<<a, d>>],
                              !.todo = IF CheckAll THEN s.todo \ {a} ELSE {},
                              !.phase = IF CheckAll /\ s.todo \ {a} # {}
                                        THEN "check" ELSE "final"]]
    /\ UNCHANGED <<H, Expand, cache, cas, ws>>

\* Find an entry for another named algorithm that agrees on the CAS digest.
Check(r) ==
    LET s == rs[r] IN
    /\ s.phase = "check"
    /\ \E a \in s.todo : \E d \in s.q[a] :
        /\ cache[<<a, d>>] = s.cand
        /\ rs' = [rs EXCEPT ![r] =
                    [s EXCEPT !.todo = s.todo \ {a},
                              !.phase = IF s.todo \ {a} = {}
                                        THEN "final" ELSE "check"]]
    /\ UNCHANGED <<H, Expand, cache, cas, ws>>

Final(r) ==
    /\ rs[r].phase = "final"
    /\ rs' = [rs EXCEPT ![r].phase = IF rs[r].cand \in cas THEN "hit" ELSE "miss"]
    /\ UNCHANGED <<H, Expand, cache, cas, ws>>

GiveUp(r) ==
    /\ rs[r].phase \in {"probe", "check", "final"}
    /\ rs' = [rs EXCEPT ![r].phase = "miss"]
    /\ UNCHANGED <<H, Expand, cache, cas, ws>>

---------------------------------------------------------------------------

Next ==
    \/ \E w \in Writers : Fetch(w) \/ Push(w) \/ WriteKey(w) \/ Crash(w)
    \/ EvictKey \/ EvictBlob
    \/ \E r \in Readers : Start(r) \/ Probe(r) \/ Check(r) \/ Final(r) \/ GiveUp(r)

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* Properties *)

\* The theorem: a hit is the expansion of one content that satisfies every
\* hash its query names. What a fetch of the same request would have had
\* to download.
HitsSatisfy ==
    \A r \in Readers : rs[r].phase = "hit" =>
        \E c \in Contents : Expand[c] = rs[r].cand /\ Sat(H, c, rs[r].q)

\* The weaker claim that survives a lossy Expand: for every named algorithm,
\* *some* content with an accepted digest expands to the hit.
HitsSatisfyEach ==
    \A r \in Readers : rs[r].phase = "hit" =>
        \A a \in Named(rs[r].q) :
            \E c \in Contents : Expand[c] = rs[r].cand /\ H[a][c] \in rs[r].q[a]

\* The contents a query could hit in this state, whatever order it reads in.
HitSet(q) ==
    {s \in cas : \A a \in Named(q) : \E d \in q[a] : cache[<<a, d>>] = s}

\* With one digest per named algorithm, there is at most one answer: the
\* order a reader goes through the algorithms cannot change what it gets.
OneAnswer ==
    \A q \in Queries :
        (\A a \in Algs : Cardinality(q[a]) <= 1) => Cardinality(HitSet(q)) <= 1

(* The inductive invariant. *)

\* Every entry is true of some content it stores: that content has the
\* digest in the key. With Expand injective that content is unique.
EntriesTrue ==
    \A k \in Keys : cache[k] # None =>
        \E c \in Contents : Expand[c] = cache[k] /\ H[k[1]][c] = k[2]

\* A writer only holds keys that are true of its content.
WritersTrue ==
    \A w \in Writers :
        ws[w].todo # {} =>
            /\ ws[w].c \in Contents
            /\ \A k \in ws[w].todo : H[k[1]][ws[w].c] = k[2]

\* A probing reader has ticked nothing off yet, and a reader with a candidate
\* has, for every algorithm it has ticked off, some content expanding to the
\* candidate with an accepted digest. One witness per algorithm: this is all
\* the entries can say, and with a lossy Expand it is not one witness for
\* all of them.
ReadersTrue ==
    \A r \in Readers :
        LET s == rs[r] IN
        /\ s.phase = "probe" => s.todo = Named(s.q)
        /\ s.phase \in {"check", "final", "hit"} =>
            /\ s.cand \in Stored
            /\ s.todo \subseteq Named(s.q)
            /\ s.phase # "check" => s.todo = {}
            /\ \A a \in Named(s.q) \ s.todo :
                \E c \in Contents : Expand[c] = s.cand /\ H[a][c] \in s.q[a]

Inv == TypeOK /\ EntriesTrue /\ WritersTrue /\ ReadersTrue

\* Every state that satisfies Inv, built conjunct by conjunct so TLC prunes
\* as it goes. Checking Inv from here checks that Inv is inductive.
IndInit ==
    /\ H \in [Algs -> [Contents -> Digests]]
    /\ Expand \in Expansions
    /\ cache \in [Keys -> Stored \cup {None}]
    /\ EntriesTrue
    /\ cas \in SUBSET Stored
    /\ ws \in [Writers -> WriterState]
    /\ WritersTrue
    /\ rs \in [Readers -> ReaderState]
    /\ ReadersTrue

IndSpec == IndInit /\ [][Next]_vars

(* Sanity: these should be violated, showing the hits are reachable. *)

NoHit == \A r \in Readers : rs[r].phase # "hit"
NoDoubleHit ==
    \A r \in Readers : ~(rs[r].phase = "hit" /\ Cardinality(Named(rs[r].q)) > 1)

=============================================================================
