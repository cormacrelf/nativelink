-------------------------- MODULE PinnedAssetCache --------------------------
(***************************************************************************)
(* The Remote Asset metadata cache for pinned requests, keyed per hash.    *)
(*                                                                         *)
(* An entry's key is one (algorithm, digest) pair, plus the request's      *)
(* other qualifiers (left out here: they only partition the key space).    *)
(* Its value is the CAS digest of the content, which stands in for the     *)
(* content itself: CAS digests are assumed not to collide. The named       *)
(* hashes are allowed to collide freely: Digests is smaller than Contents, *)
(* and TLC tries every hash function.                                      *)
(*                                                                         *)
(* A writer (a fetch, or a push of a blob already in the CAS) verifies the *)
(* content against every algorithm the request names, then writes one     *)
(* entry per named algorithm, one key at a time. It may crash between     *)
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

CONSTANTS Algs, Contents, Digests, Writers, Readers, None, CheckAll

Keys == Algs \X Digests

\* What a request accepts, per algorithm; {} when it does not name it.
Queries == {q \in [Algs -> SUBSET Digests] : \E a \in Algs : q[a] # {}}
Named(q) == {a \in Algs : q[a] # {}}

\* Content c satisfies q: each named algorithm matches one of its digests.
Sat(h, c, q) == \A a \in Named(q) : h[a][c] \in q[a]

Phases == {"idle", "probe", "check", "final", "hit", "miss"}

VARIABLES
    H,      \* the hash functions, chosen once
    cache,  \* key -> CAS digest, or None
    cas,    \* the blobs in the CAS
    ws,     \* writers: the content being recorded and the keys left to write
    rs      \* readers: the query, the candidate and the algorithms left

vars == <<H, cache, cas, ws, rs>>

WriterState == [c : Contents \cup {None}, todo : SUBSET Keys]
ReaderState == [phase : Phases, q : Queries, cand : Contents \cup {None},
                todo : SUBSET Algs]

TypeOK ==
    /\ H \in [Algs -> [Contents -> Digests]]
    /\ cache \in [Keys -> Contents \cup {None}]
    /\ cas \subseteq Contents
    /\ ws \in [Writers -> WriterState]
    /\ rs \in [Readers -> ReaderState]

Init ==
    /\ H \in [Algs -> [Contents -> Digests]]
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
        /\ cas' = cas \cup {c}
        /\ ws' = [ws EXCEPT ![w] =
                    [c |-> c, todo |-> {<<a, H[a][c]>> : a \in Named(q)}]]
    /\ UNCHANGED <<H, cache, rs>>

\* PushBlob: the blob must already be in the CAS, and is verified the same way.
Push(w) ==
    /\ ws[w].todo = {}
    /\ \E q \in Queries, c \in cas :
        /\ Sat(H, c, q)
        /\ ws' = [ws EXCEPT ![w] =
                    [c |-> c, todo |-> {<<a, H[a][c]>> : a \in Named(q)}]]
    /\ UNCHANGED <<H, cache, cas, rs>>

WriteKey(w) ==
    /\ \E k \in ws[w].todo :
        /\ cache' = [cache EXCEPT ![k] = ws[w].c]
        /\ ws' = [ws EXCEPT ![w].todo = @ \ {k}]
    /\ UNCHANGED <<H, cas, rs>>

Crash(w) ==
    /\ ws[w].todo # {}
    /\ ws' = [ws EXCEPT ![w].todo = {}]
    /\ UNCHANGED <<H, cache, cas, rs>>

---------------------------------------------------------------------------
(* Eviction, of entries and blobs independently *)

EvictKey ==
    /\ \E k \in Keys : cache[k] # None /\ cache' = [cache EXCEPT ![k] = None]
    /\ UNCHANGED <<H, cas, ws, rs>>

EvictBlob ==
    /\ \E c \in cas : cas' = cas \ {c}
    /\ UNCHANGED <<H, cache, ws, rs>>

---------------------------------------------------------------------------
(* Readers *)

Start(r) ==
    /\ rs[r].phase \in {"idle", "hit", "miss"}
    /\ \E q \in Queries :
        rs' = [rs EXCEPT ![r] =
                [phase |-> "probe", q |-> q, cand |-> None, todo |-> Named(q)]]
    /\ UNCHANGED <<H, cache, cas, ws>>

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
    /\ UNCHANGED <<H, cache, cas, ws>>

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
    /\ UNCHANGED <<H, cache, cas, ws>>

Final(r) ==
    /\ rs[r].phase = "final"
    /\ rs' = [rs EXCEPT ![r].phase = IF rs[r].cand \in cas THEN "hit" ELSE "miss"]
    /\ UNCHANGED <<H, cache, cas, ws>>

GiveUp(r) ==
    /\ rs[r].phase \in {"probe", "check", "final"}
    /\ rs' = [rs EXCEPT ![r].phase = "miss"]
    /\ UNCHANGED <<H, cache, cas, ws>>

---------------------------------------------------------------------------

Next ==
    \/ \E w \in Writers : Fetch(w) \/ Push(w) \/ WriteKey(w) \/ Crash(w)
    \/ EvictKey \/ EvictBlob
    \/ \E r \in Readers : Start(r) \/ Probe(r) \/ Check(r) \/ Final(r) \/ GiveUp(r)

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* Properties *)

\* The theorem: every hit satisfies every hash its query names.
HitsSatisfy ==
    \A r \in Readers : rs[r].phase = "hit" => Sat(H, rs[r].cand, rs[r].q)

\* The contents a query could hit in this state, whatever order it reads in.
HitSet(q) ==
    {c \in cas : \A a \in Named(q) : \E d \in q[a] : cache[<<a, d>>] = c}

\* With one digest per named algorithm, there is at most one answer: the
\* order a reader goes through the algorithms cannot change what it gets.
OneAnswer ==
    \A q \in Queries :
        (\A a \in Algs : Cardinality(q[a]) <= 1) => Cardinality(HitSet(q)) <= 1

(* The inductive invariant. *)

\* Every entry is true of its content.
EntriesTrue ==
    \A k \in Keys : cache[k] # None => H[k[1]][cache[k]] = k[2]

\* A writer only holds keys that are true of its content.
WritersTrue ==
    \A w \in Writers :
        ws[w].todo # {} =>
            /\ ws[w].c \in Contents
            /\ \A k \in ws[w].todo : H[k[1]][ws[w].c] = k[2]

\* A probing reader has ticked nothing off yet, and a reader with a candidate
\* has a candidate that satisfies every algorithm it has ticked off.
ReadersTrue ==
    \A r \in Readers :
        LET s == rs[r] IN
        /\ s.phase = "probe" => s.todo = Named(s.q)
        /\ s.phase \in {"check", "final", "hit"} =>
            /\ s.cand \in Contents
            /\ s.todo \subseteq Named(s.q)
            /\ s.phase # "check" => s.todo = {}
            /\ \A a \in Named(s.q) \ s.todo : H[a][s.cand] \in s.q[a]

Inv == TypeOK /\ EntriesTrue /\ WritersTrue /\ ReadersTrue

\* Every state that satisfies Inv, built conjunct by conjunct so TLC prunes
\* as it goes. Checking Inv from here checks that Inv is inductive.
IndInit ==
    /\ H \in [Algs -> [Contents -> Digests]]
    /\ cache \in [Keys -> Contents \cup {None}]
    /\ EntriesTrue
    /\ cas \in SUBSET Contents
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
