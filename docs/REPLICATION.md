# Replication and data integrity

This document describes how a gossip cluster (`cluster.bind` set: every node has its own database and the nodes
replicate to each other) keeps its data consistent, which rules every node follows, and what an operator does after
failures. The code that implements it is `internal/cluster` (node states, sync, the quorum compare-and-swap in
`cas.go`, gossip handlers), `internal/store` (the merge order `Newer`, the generation stamp `StampLocal`, the unique
rule `KeepsUnique`) and the storage backends. The shared-database mode (no gossip) is covered at the end.

**Pre-release data format.** Quisora has not been released: there is no migration from, and no compatibility with,
data written by earlier builds. A store written by an earlier build is refused when it is opened (BadgerDB and Valkey
carry a format marker, SQL tables must have the `epoch` and `created_v` columns), backups must be format version 1 (as this build writes them),
and a `cluster-state.json` must name its store (`self`). **Wipe and start clean** (restore from a backup made by this
build if needed).

## Guarantees

1. **A confirmed write is never lost to a concurrent or stale write.** Security-sensitive records (users and their
   sign-in records, passkeys, API tokens, OAuth clients, upstream providers, organizations and their settings,
   tenants, tenant access, groups and their memberships, refresh grants, invitation and reset links, single-use values
   seen, cluster locks) are written with a **quorum compare-and-swap**: a write
   based on a copy that is no longer the newest is refused by the majority that holds the newer one, and of two
   concurrent writes from the same copy at most one takes effect anywhere.
2. **A deletion is never undone by a write that had not seen it.** Only an explicit re-creation by a writer that had
   seen the deletion brings an id back, and a deletion that writer had not seen still wins — whatever the clocks say.
   For the quorum kinds this is the quorum's doing: a confirmed deletion is held by a majority, which refuses every
   later write of the generation it deleted. A deletion that was only partly applied (its commit reached fewer than
   a quorum, and was reported as failed) gives way to a later confirmed write, like any partial write.
3. **Nothing is deleted to resolve a conflict.** Of two records claiming one unique value (an email address, a name)
   the one created first keeps it; the other is kept, without the value, flagged and audited.
4. **A node that cannot know its data is current does not act on it.** A node that is copying the cluster's data,
   catching up after a start, cut off from the majority, out of date or misconfigured serves nothing but its health
   probes (`/readyz` answers 503), makes no replicated write, takes no part in quorum writes, owns no rate-limit
   counter and seeds no new node. The token, userinfo and introspection endpoints alone keep answering, for a bounded
   grace, on a node that was serving and got cut off.
5. **Every automatic recovery is safe by construction; every operator override is explicit**, one-shot, logged and
   audited (`quisora force-start`). Nothing is ever wiped or emptied automatically.
6. These rules are enforced by tests that model the failures (`internal/cluster/*_test.go`, notably
   `quorum_test.go`, `integrity_test.go` and `dataloss_test.go`; `internal/service/consistency_test.go`; the store
   conformance suite), run with `-race`.

## Cluster size and quorum

`cluster.size` is **required** with `cluster.bind` (flag `--size`, `QUISORA_CLUSTER_SIZE`, TOML `cluster.size`; no
default): the number of nodes the cluster is made of. It must equal the number of nodes `cluster.peers` names (this
node included, however the list names it), or the node refuses to start. The **quorum** is `size/2+1`: 2 of 3, 3 of
4, 3 of 5.

- The size is **authoritative**: it decides how many nodes must confirm a write, how many nodes a node must see to be
  ready and writable, how many peers it must catch up with, and when it is cut off (and the minority grace starts).
  It **never shrinks** when nodes leave, stop or restart (the leader election's baseline is pinned to it —
  `ExpectedClusterSize`, auto-shrink disabled), so a minority can never reach "quorum" on its own. It changes only
  when the operator changes it in the configuration and reloads it, **one node at a time** (see
  [Changing the cluster size](#changing-the-cluster-size)).
- **Every node must agree.** Each node publishes its size in gossip metadata (`quisora.size`); a node that sees an alive
  member with another size refuses to serve (not ready, not writable, no tokens) until they agree.
- **Scaling is a planned change, made while the cluster runs**: see [Changing the cluster size](#changing-the-cluster-size).

## Records, versions and generations

Every record carries:

- **Version**: a hybrid logical clock (HLC) timestamp minted by the writer (the gossip library's `hlc.Clock`:
  microseconds since 1 January 2025 plus a 10-bit counter that carries into the time field, so every version a node
  mints is strictly greater than every version it minted or witnessed before).
- **Origin**: the node that minted the version (breaks ties).
- **Epoch**: the *generation* of a live record: 0 for a record created once, or — for a record created again after a
  deletion — the version of the tombstone its writer had seen and superseded. Updates keep it.
- **Created**: the version of the write that created this generation; updates keep it. It decides unique clashes.
- **Deleted**: a tombstone, kept for replication until purged.

### Merge order (the causal convention)

Every apply path (local commit, broadcast, durable push, anti-entropy, read repair) keeps the record of the higher
**rank** = (epoch, version), where a tombstone's epoch is its own version — except for a quorum kind, whose rank is
its version alone (`store.Head.Rank`, `store.Newer`; at equal rank a tombstone wins, then the higher origin). It is a total order, so every node that receives the same records, in any order, ends
with the same one. Consequences:

- A tombstone with version *T* outranks every live record of an earlier generation (epoch < *T*), however new its
  version: an update made on a copy that had not seen the deletion (replication lag, a partition, a node catching
  up, a clock an hour ahead) can never bring the record back.
- A quorum kind ranks by version alone. There the voters order a record's versions as its writes are granted (any
  two grants share a voter, whose high-water mark forces the later one higher; no voter grants a version more than
  10 s ahead of its clock; a restarted voter starts above everything it granted), and a confirmed deletion is held
  by a majority that refuses any later write that had not seen it. So the rank only settles partial writes (a commit
  that reached fewer than a quorum), and the later write wins — a deletion or not, of whatever generation: a
  confirmed create of an id outranks an earlier partial deletion of it, as a confirmed update outranks an earlier
  partial deletion. Generations still decide what the voters refuse, only not the merge.
- A re-creation takes the version of the tombstone its writer saw as its epoch: it outranks that tombstone (same
  epoch, newer version) but **not a deletion its writer had not seen** (that tombstone's epoch is its own, later
  version). A revocation made later in real time therefore beats an earlier re-addition even when the re-adding
  node's clock is ahead: wall-clock order never decides between a deletion and a re-creation.

### Local writes (`store.StampLocal`)

- `Put` of a live record over a live one continues its generation; over a tombstone it is **refused with
  `store.ErrDeleted`** (which matches `ErrNotFound`).
- `CompareAndPut` with `expect != 0` (an update) needs a live record at exactly that version (`ErrNotFound` /
  `ErrStale` otherwise) and continues its generation.
- `CompareAndPut` with `expect == 0` (a create) over nothing starts generation 0; over a tombstone it starts a
  generation whose epoch is that tombstone's version; over an expired record it keeps the generation.
- Node-local state (`KindEphemeral`: leases, markers, short-lived sign-in state) is never replicated and may be
  written over its tombstones.
- Audit events (`KindAudit`) are node-local too: each node keeps its own (never broadcast, never in its change
  feed, dropped if one arrives), and an audit page asks every node over `msgAudit` and merges the answers
  (`Node.AuditQuery`). They do not count as data when deciding whether a node is empty.

### Re-using an id

Most ids are random UUIDs and are never re-used. Deterministic ids — group memberships (`group:user`), tenant access
(`tenant:subject`), sign-in records (the user's id), locks — are re-created with a create, which is causal as above.
The fixed bootstrap ids (primary organization, its default tenant, the first administrator) are written by
`quisora bootstrap` with the oldest possible version (`model.BootstrapVersion`, 1) and only with a create; records of a
separately bootstrapped cluster are refused by comparing the records' own creation times (`otherBootstrap`).

## Quorum compare-and-swap

Writes of the kinds listed in `model.QuorumCAS` (user, sign-in, passkey, API token, client, provider, organization, group,
tenant, tenant access, group membership, lock, refresh grant, replay record, invitation and reset link) are two-phase
commits validated by a majority
(`internal/cluster/cas.go`). Nothing is applied before a quorum has granted the write, so a write that fails in
prepare has no effect anywhere and there is no compensation step to race with.

### Wire messages

| message | type | content | answer |
|---|---|---|---|
| prepare | `UserMsg+6`, request/response | `prepareReq{Op, Rec, Mode, BaseEpoch, BaseVersion}` | `prepareResp{St, Floor, Cur}` |
| commit | `UserMsg+7`, request/response | `commitReq{Op, Rec}` | `commitResp{St}` |
| abort | `UserMsg+8`, one way | `abortReq{Op, Version}` | — |
| quorum read | `UserMsg+9`, request/response | `readReq{Kind, IDs}` | `readResp{NotReady, Failed, Recs}` |

`Op` is the write's identity (a retry keeps it, so it supersedes its own earlier intent; an abort names the stamp it
aborts, so a late abort of one attempt never releases the next attempt's intent); `Rec` is the encoded,
stamped record; the base is the rank of the copy the writer based the write on (0, 0: none). Modes: **match** (an
update or create: `CompareAndPut`, `Table.Update`, `Table.Create`), **upsert** (a whole-record `Put` over whatever
the writer holds) and **blind** (a deletion; a conditional deletion, `DeleteIf`, is a match against the version the
caller read).

### Steps

1. **Stamp** on the writer: its local precondition must hold (the version the caller read is still the one it holds;
   no live record for a create; an upsert is refused over a tombstone), unique values must be free locally
   (`ErrConflict`), then a fresh version is minted and Epoch/Created are set (`StampLocal`).
2. **Prepare**: the writer votes first, then every alive peer in parallel. A voter answers:
   - **stale** when its copy ranks above the writer's base, or when the write is of an older generation than its
     live copy. It sends its copy back: the writer applies it (read repair), so a retry from fresh data works at once;
   - **deleted** for a live write onto a tombstone of a later generation (a deletion the writer had not seen);
   - **low** when the version does not exceed what it holds or has granted for the record (its high-water mark, or
     its floor): the writer moves its clock past that value — up to 11 s ahead of its own clock (the 10 s a voter
     may grant ahead of its clock, plus a second for NTP); further, the write fails as a clock problem — and retries
     with a new stamp;
   - **busy** when another write holds an intent on the record;
   - **not ready** when it is copying, catching up, out of date or misconfigured (it takes no part);
   - otherwise it **grants**: it records an intent on the record (exclusive, expiring after 5 s) and raises its
     high-water mark. Nothing is written.

   A voter that lags behind the writer's base grants (its copy is older): mutual exclusion comes from quorum
   intersection — of two writes from one base, the voter both quorums share grants one and refuses the other (busy
   while the first holds its intent, stale once it has applied it).
3. **Decide**: grants from a quorum (the writer included) commit the write. A stale or deleted answer received before
   that fails it with `store.ErrStale` / `store.ErrDeleted` — the caller re-reads and retries from fresh data; an
   upsert re-bases by itself (up to 8 times: of two concurrent whole-record writes the later commit wins, by design).
   Busy, low and not-ready answers make the writer retry with a new stamp after a short random pause, for at most
   6 s (the intent lifetime plus 1 s); anything else (too few nodes answering) fails with `store.ErrUnconfirmed`.
   Intents of a write that does not commit are released (abort); grants that arrive after the decision are released
   too.
4. **Commit** to every voter that granted, the writer first. Each applies the record **only while it still holds the
   intent** — "applied this exact version over the base" — then releases it. **The write succeeds once a quorum (the
   writer included) has applied it.** The record is then broadcast to every node; anti-entropy heals anything
   missed.

### What success and failure mean

- **Success**: a majority holds exactly this version. Every later write of the record must prepare at a quorum that
  includes one of them, which refuses a write based on anything older.
- **`ErrStale` / `ErrDeleted`**: the write was applied nowhere. The service layer re-reads and retries where that is
  safe (sign-in stamps, TOTP steps, locks, unique-clash resolution) and otherwise reports a conflict (HTTP 409,
  "changed by someone else, reload and try again").
- **`ErrUnconfirmed` before the commit** (no quorum granted): applied nowhere (HTTP 503).
- **`ErrUnconfirmed` after the commit** (a voter failed mid-commit and fewer than a quorum applied): the write *may* be
  in effect on some nodes; it is counted (`unconfirmed`) and logged. A later conflicting write must prepare at a
  quorum that shares a voter with this write's grants, whose high-water mark forces the later write to a higher
  version, so the later write ranks above the partial one everywhere (a partial deletion too: quorum kinds rank by
  version alone).

A voter keeps nothing on disk: its intents and high-water marks live in memory (after a minute the marks are folded
into a per-node floor). A restart, however abrupt, is made safe by the clocks, which must be synchronised
([Clocks](#clocks)): a voter grants no version more than 10 s (twice `store.MaxSkew`) ahead of its own clock, and a
voter that starts sets its floor 10 s past its clock and takes part in no quorum write for 11 s. Every version it
granted before the restart is below that floor, so every write it grants afterwards outranks every write — or
deletion — it granted before, whether or not that one was applied anywhere. Its peers form the quorum meanwhile, and
the node reports not ready (`/readyz`) until the pause is over, so no traffic reaches it before it can vote.

A **whole cluster started at once** (every node restarted together) accepts no quorum write for its first 11 s: no
voter votes yet, and a writer retries for 6 s before it gives up. Load balancers that route on `/readyz` send nothing
until then. A client that reaches a node directly in that window gets 503 `temporarily_unavailable` for anything
that writes a quorum kind — a sign-in (its sign-in record), a code exchange or rotating refresh (refresh grants), a
client assertion or DPoP proof (replay records), an administrative change — and retries. Restart nodes one at a time
to avoid the window altogether.

A quorum read counts only voters that answered with every copy asked for: a voter that cannot read one says so
(`Failed`) and is not counted, rather than answering as if it held none.

### Sign-in stamps

A user's last sign-in and last accepted TOTP time step live in a separate per-user **sign-in record**
(`model.SignIn`, id = the user's id), never on the user: a sign-in can neither erase nor be erased by an
administrator's change of the user. The TOTP step is recorded with a create-once / compare-and-swap of that record
before the code is accepted, so a code is accepted once on any node: the same code presented on two nodes at once is
accepted by exactly one, and a node that has not yet received a use is refused by the majority that has. When the
step cannot be recorded the code is refused (fails closed). Failed attempts and lockouts are counted in short-lived
state (below), not in records.

### The last-administrator guard

Changes that can remove an organization's last usable administrator — one who is active and not past an end date —
(demoting, disabling, deleting or end-dating an administrator; an administrator without an end date may go only
while another one without an end date remains) take the organization's **admin lock** — the lock record `admins/<org id>`, written with a
quorum compare-and-swap, held for at most 30 s and waited for up to 10 s — and count the administrators from **a
quorum's copies** (quorum read): a demotion confirmed by a majority anywhere is counted even before it has reached
this node. Two demotions on two nodes are therefore serialised, and the second sees the first.

### Groups and their members

A change of a group and its members (a SCIM PATCH or PUT, an admin console change, a creation with members, a
deletion) touches several records: the group, and one membership record per user added or removed. **The group's
record is the single commit point.** Every change is committed by one compare-and-swap of that record (a quorum one
in a gossip cluster), on the version the change was made from: it writes the group's fields and appends a *change
entry* — the operation id, the users added and removed, a per-group sequence number — to the record's pending log
(`model.Group.Pending`). If that write fails nothing has happened; once it succeeds the change is committed and is
never rolled back. There is no lock and no compensating write.

The membership records are a **materialized view** of the committed entries. After the commit the writer applies
the record's entries in sequence order: each membership record stores the sequence of the change that last wrote
it, and a write carrying an older sequence is refused (the record is read, compared and written with a
compare-and-swap on its version), so a writer that stalled — for any length of time, on any node — can never
overwrite what a later change wrote. That is the fence; it needs no clock. A removal does not delete the membership
record: the record is marked removed, leaves the `group_id` and `user_id` indexes (so it is never listed) and is kept
for 7 days (`model.RemovedMemberRetention`, as long as tombstones are) to fence stalled writers before it expires.
The writer then removes the applied entries from the group's record with another compare-and-swap. A writer that
dies after the commit leaves its entry in the record; the next change of the group applies it first, and the
housekeeping leader finishes entries older than 30 s (`service.FinishGroupChanges`, found by the indexed `pending`
field, so it costs nothing when there are none). A change that cannot be materialized (a store refusing the
membership writes) stays pending and is carried forward by later commits; a record with 8 such entries refuses
further changes (`ErrUnavailable`) until they are applied.

Field changes (a rename, tags, the external id) commit on the same record with the same compare-and-swap, so they
serialise with changes of the members without a lock and preserve the pending log. A deletion first commits an entry
removing every member (`Clear`) — from that moment nobody is a member of the group, whatever is materialized — then
materializes it and removes the group's record with a compare-and-swap on the version that commit gave it (then
tombstones the membership records); a deleter that dies in between leaves an empty group, never memberships of a
group that is gone. Creating a group with members
creates the record carrying the first entry: the group exists with every member or not at all. One change may add
and remove at most 1,000 memberships (`service.MaxMembersPerChange`), which keeps the log small; SCIM refuses a
larger PATCH or PUT with 413 (RFC 7644 §3.12) and the client splits it.

**What readers see.** Every reader of memberships (the groups of a user for tokens and tenant access, a group's
members, member counts, SCIM resources) reads the group's record and applies its pending entries over the
membership records, so it observes exactly the committed changes: never one that failed (nothing of it was written)
and never a committed one in part. A committed removal is in force the moment the commit succeeds, materialized or
not; a committed addition is seen the same way (a user's groups include the organization's groups with pending
entries, one indexed read, normally empty). A membership of a group that no longer exists names no group and grants
nothing. The group's version, its SCIM ETag, moves at the commit and once more when the entry is cleared (normally
within the same request, which returns the final version); a change made from a copy that is no longer the newest
is refused (`ErrStale`, HTTP 412 with `If-Match`). A deleted user's memberships are tombstoned outside this protocol
(they are those of a user who no longer exists, harmless and removable by anyone).

### Refresh grants and single-use values

Refresh grants are quorum writes because rotating a refresh token advances the grant's counter: a node that had not
yet received the advance must not accept the old token. Replay records (`model.Replay`, `service.UseOnce`) hold the
single-use values seen — client assertion and DPoP proof `jti`s — until they expire, so a value accepted once is
refused on every node, whichever nodes stop, restart or leave meanwhile. Invitation and reset links are quorum
writes too, and an account has at most one of each (a new one replaces the record, and every try of the write judges
the record it replaces). One is used up by the commit of the change it makes, a quorum compare-and-swap of the user
record that moves the account's security generation on (`service.UseSignInLink`): a link presented to two nodes at
once is used once, and a failure before the commit leaves it usable.

The user record is also the one commit point for which of an account's credentials count. Every passkey, connected
provider, API token, session and refresh grant carries the account's **credential epoch** it was made in
(`model.User.CredEpoch`), and works only while that is the account's. An accepted invitation (or a reset of the
account's sign-in) gives the account a new random epoch in its commit: every earlier credential stops at that write,
on every node that has it, and the passkey the invitation stored for the new epoch beforehand starts. Of two
acceptances racing, only the winner's epoch is committed; the loser's passkey never counts, and is tidied away.
Removing the old credentials' records afterwards is tidying (the orphan sweep finishes it after a crash).

## Other writes

Records of other kinds (sessions, upstream identities, signing keys, audit entries) are applied locally, broadcast, and replicated by anti-entropy. Security-relevant ones are
**durable** (`store.WithDurable`): the writer pushes the record to every alive peer and waits until enough peers to
make a majority with it **have applied exactly that version**. A peer that holds something newer does not apply it
and answers "superseded": that is not an acknowledgement, and it is counted in `refused`. A peer that has not caught
up (copying, catching up) applies the record but does not acknowledge it either. If a majority does not
confirm in time the write stands on this node, is counted in `unconfirmed` and logged; with
`cluster.strict_durability = true` it fails with `store.ErrUnconfirmed` instead and is undone where possible (a
created record is deleted, an updated one gets its previous content back; a deletion stands).

## Unique values

Of two different live records of one kind claiming one unique value (two nodes accepted the same email address,
group name or provider name at once), **the record created first keeps it** (lower `Created`, then lower id:
`store.KeepsUnique`): a long-standing record never loses its value to one created concurrently elsewhere, however
recently it was updated or signed in. The other record is **kept** — never deleted — but is not found by that value.
Every node that sees the clash reports it (`Node.OnConflict`) and the application resolves it
(`service.ResolveUniqueClash`, a compare-and-swap, so one node makes the change and the others find it done): the
value is removed from the later record (an email address or external id is cleared, a name gets the record's short
id appended, a passkey whose credential id clashes is disabled), the record is flagged for administrators (the
`conflict` field in the API, `model.Meta.Conflict`) and the change is audited (`unique.conflict`).

## Node states

| state | when | ready / tokens | replicated writes | votes in quorum writes | seeds a new node | purges |
|---|---|---|---|---|---|---|
| **copying** | empty at start (or resuming an interrupted first copy) until its first full copy | no / no | none | no | no ("new") | no |
| **catching up** | every start, until caught up (below) | no / no | none | no | no | no |
| **ready** | caught up, a quorum in view, every node agrees on the size | yes / yes | all | yes | yes | yes |
| **cut off** | fewer than a quorum in view | no / for `cluster.minority_grace` (default 300 s) | none | yes | no | yes |
| **out of date** | sync point older than `maxDowntime`, or data of unknown age | no / no | none | no | no | no |
| **misconfigured** | database shared with another gossip node, owned by another node id, mixed with non-gossip nodes, restored into a cluster that has data, prefix collision, **size disagreement** | no / no | none | no | no | — |

Only node-local records (`KindEphemeral`, and audit events) are written on a node that is not ready. A refused write returns
`store.ErrNotWritable` (HTTP 503) and has no effect anywhere. A node never leads unless it is writable, so
housekeeping (key rotation, user end dates) runs only where the data is current.

### Catching up

Every start catches up before serving. A node that **started with its own data** has caught up once it has pulled
everything from `quorum − 1` peers that are not copying their own first data: with itself they make a majority,
which shares a node with every majority that confirmed a write. A node that **started empty** holds no write of its
own, so it needs `size − quorum + 1` peers (**the quorum, for odd sizes**: 2 of 3, 3 of 5) that have themselves
caught up — it never counts itself. A replacement node therefore cannot serve after copying from a single node that
lacks a write the others confirmed.

One exception applies **only while a cluster is forming** around one node's data, all its other nodes starting empty
(a new cluster's first node after `quisora bootstrap --new-cluster`, a node forced with `quisora force-start`, a node
restored from a backup, or a node that copied from one of these): such a node, once caught up and with a quorum
alive, holds every write there is — no write can be confirmed before a quorum of nodes is ready — and says so in its
feed (`Origin`); an empty node that has copied everything from it has caught up. As soon as a node has seen a quorum
of nodes ready, has caught up as a member of an already formed cluster, or has completed a quorum write that a
quorum applied (proof the cluster has formed even when gossip readiness lags), it records that its cluster has formed
(`formed` in `cluster-state.json`, kept across restarts) and is never an origin again — not after losing the quorum,
not after a restart — until an operator starts a new formation (force-start, restore). A node cut off from the
majority never seeds anyone: it refuses new nodes' copies outright. The empty nodes of a formed cluster need
`size − quorum + 1` caught-up peers, which the ready nodes provide.

### Serving while not ready

Until a node is ready, **every path except `/healthz`, `/readyz`, `/assets/…`, `/branding/…` and `/favicon.ico`
answers 503** with `Retry-After: 5` (JSON `temporarily_unavailable` for `/oauth/…` and `/.well-known/…`, JSON
`{"error": …}` for `/api/…` and `/scim/…`, plain text otherwise): management and SCIM reads, the authorization and
sign-in pages, discovery and JWKS alike, so a client that bypasses the load balancer never receives partial, stale or
deleted data (`web.Server.serveGate`). On a node that **was serving and got cut off**, `/oauth/token`,
`/oauth/userinfo` and `/oauth/introspect` keep answering for `cluster.minority_grace`; as no replicated write is
allowed without a quorum, only requests that need none succeed there (client credentials, a refresh of a client that
does not rotate refresh tokens, userinfo, introspection), and a code exchange or a rotating refresh answers 503
`temporarily_unavailable`. A restarting node issues no tokens until it has caught up.

### Short-lived state

Sign-in steps, codes and challenges stay in the memory of the node that made them (their ids carry its prefix) and
the others forward to it. Hash-routed state — rate-limit and lockout counters — lives on the rendezvous-hash owner
**among the nodes that are ready** (each publishes `quisora.ready` in gossip metadata). It **fails closed**: when no
ready node is in view, or the owner cannot be reached, the operation fails (the rate limit or lockout refuses)
instead of counting on one node. It is in the owner's memory only: when the owner changes (a node stops serving,
restarts or leaves) the new owner starts from nothing, so a counter's window starts again. Nothing whose safety
depends on it surviving that is kept there: single-use values are replay records (quorum compare-and-swap, above).

## Sync point and ageing

Tombstones are purged after the **retention** (7 days). A node that missed a deletion would hand the record back once
the tombstone is gone, so a node must not serve data older than the retention allows. Each node keeps a **sync
point** in `cluster-state.json`:

- **LastSync** moves forward when the node has completed pulls from `quorum − 1` peers, each started with a quorum in
  view (`recomputeSync`); every write a majority held before then is on this node. Nodes cut off together keep
  pulling from each other, but that is no sync: their sync point ages.
- **CopiedAt** is the age of data copied while the node had no LastSync yet (a first copy): the earlier of the
  copy's start and the source's own sync point.

`maxDowntime` is the retention less a margin (one day, or a quarter of a shorter retention): 6 days. A running node
whose sync point is older stops (out of date); a starting node refuses when its sync point is older, when it holds
data but its cluster state is missing, when its database was replaced (the store's feed id differs from the state's
`self`), or when it holds data but has no sync point. It keeps its data in every case.

## Clocks

Versions come from the writers' clocks; keep every node's clock synchronised (NTP).

- A node **refuses to start** when its clock reads before 1 January 2025 (the version clock's epoch).
- A version read or received is witnessed into the node's clock only when it is at most `store.MaxSkew` (5 s) ahead
  of the machine's clock (`hlc.Clock.WitnessBounded`); one further ahead is applied by the merge rules but not
  followed (counted as `skew_refused`), so one bad clock cannot drag every node's versions — and age-based cut-offs —
  into the future. A later local write of such a record fails as stale until the clocks agree.
- Received versions more than 5 s ahead are logged (hourly per origin) and counted (`clock_skewed`), and a voter
  refuses to grant a quorum write whose version is more than 10 s ahead of its clock (see "What success and failure
  mean": that is what makes a voter's restart safe without anything on disk). With NTP the nodes are milliseconds
  apart; a node further out is broken, and its quorum writes fail until its clock is fixed.
- Deletions of replicated kinds are safe under any skew (generations), and so are quorum writes and deletions (voters
  force versions above what they hold, within the 10 s bound). Between concurrent upserts the later commit wins.
- **Every node checks its clock against the others'** (`internal/cluster/clock.go`). Each change-feed reply carries
  the responder's time; the asker reads its offset from each peer as NTP does (against the midpoint of the request)
  and keeps each peer's latest reading in memory, nothing on disk. The cluster's clock is the **median** of its own
  (offset 0) and the readings of the last 30 s, taken only once it has heard from enough peers to make a quorum with
  itself. If its clock is more than 5 s from that, the node refuses to serve (not ready, no votes, no writes, no
  tokens) and logs why; it serves again once it is within 2.5 s. A minority of bad clocks is outvoted: in three nodes,
  one with a bad clock stops only itself, and the two healthy ones agree. Feeds are pulled from every peer every 5 s, so a node whose time synchronisation fails while it runs is
  caught within seconds, and a restarting node is checked during catch-up, before it votes. `/readyz` reports the
  offset (`clock_offset_ms`).
- A restarting voter also takes its start floor from the cluster's time: until it votes, the floor it starts with
  (10 s past its clock at start) is moved by the measured offset, to 10 s past the cluster's clock at that moment. So
  a clock stepped back across a restart (a VM restored from a snapshot, a manual correction) cannot let it grant a version below one it granted before; and stepped back by more than 5 s, the node
  refuses to serve at all until it is fixed.
- In a two-node cluster each node has only the other to compare with, and the median lies halfway: if they disagree
  by more than 10 s, both refuse (quorum writes would fail between them anyway). If every node's clock is wrong by the same amount (a whole cluster
  restored from one snapshot), they agree, and writes of records stored with later versions fail as stale until the
  clocks catch up.

## Cluster status

`/readyz` (unauthenticated) reports, ready or not, `{"status": "ready" | "unavailable", "cluster": {"size", "quorum",
"alive", "unconfirmed", "refused", "clock_skewed", "skew_refused", "clock_offset_ms"}}` — counts only; the reason for not being ready
stays in the log. `GET /api/cluster` (super administrators) returns the full status (node id, members, leader,
ready, writable, catching up, sync point, forced start), and the console's organization settings page shows it to
super administrators. The Docker `HEALTHCHECK` (`quisora healthcheck`) is a **liveness** probe (`/healthz`): a node that
is catching up or cut off is alive and must not be restarted for it. Point load balancers at `/readyz`
(`quisora healthcheck --ready` checks it from the host). The load shedder (`limits.max_in_flight`) never refuses
`/healthz`, `/readyz`, discovery or JWKS.

## Operator procedures

Every refusal says why and what to do.

**A node was down, or cut off, for less than six days.** Start it (or heal the network). It catches up and serves.

**A node was away for longer, or its data is of unknown age.** It refuses and keeps its data. If the other nodes hold
the cluster's data, stop it, empty its database and start it: it copies everything. Do not force it.

**Replacing a node** (lost disk, new machine). Start the replacement with an empty database and the same
`cluster.size` and `cluster.peers`. It copies everything and serves once it has caught up with enough peers that have
caught up themselves (2 of a 3-node cluster); while another node is down as well, it waits.

**Whole-cluster outage, shorter than six days.** Start every node. They merge and each serves once it has caught up.

**Whole-cluster outage, longer than six days.** Every node refuses. Pick the node with the newest data (each refusal
logs the time of its last sync). Run `quisora force-start` on it and start it; then empty the others and start them:
they copy from it.

**The only node with data restarts next to new, empty nodes**, within six days: run `quisora force-start` on it and
start it again; it serves, and the empty nodes copy from it.

**Restoring a backup.** Restore into one node with an empty database (`quisora serve --restore-from`), start it, then
start the others with empty databases: they copy from it. A restored node that meets peers holding data refuses.

### Changing the cluster size

The size changes while the cluster runs, **by one node at a time**: 3 → 4 → 5, or 7 → 6 → 5. Any majority of the old
size and any majority of the new one then share a node, so every write a majority confirmed before the change is seen
by every majority after it, and the cluster stays writable throughout (a one-step change keeps a majority of the new
size among the nodes in view: growing, the nodes already running; shrinking, those that stay). A larger change is a
series of steps, each completed before the next.

Each step edits every node's configuration, then has every node re-read it at once: **Reload configuration** on the
admin console's System page (Cluster), or `POST /api/cluster/reload` (super admin, after a recent re-authentication;
audited as `cluster.reload`). Every node in view first reads and checks its configuration; only if all of them can
apply it and all name the same `cluster.size` does each one apply it. Otherwise nothing changes, and the answer has
each node's report. A node that is down is not asked: it reads its configuration when it starts. SIGHUP reloads a
single node the same way, but the nodes then disagree on the size, and none of them serves until the last one has
reloaded. Keys kept in Vault or 1Password are read again by the same reload ([secret stores](secret-stores.md)).
Nodes sharing a database (no gossip) run the same two-phase reload over `cluster.notify`; without it each node
reloads on its own (SIGHUP).

**Adding a node** (N → N+1):

1. Check that every node reports ready (`/readyz`).
2. On every running node set `cluster.size` to N+1 and add the new node to `cluster.peers`.
3. Reload. Every node now needs a majority of N+1 (3 of 4, 3 of 5); the N running nodes still make one. A reload is
   refused while too few nodes are in view for that.
4. Start the new node with an empty database and the same `cluster.size` and `cluster.peers`. It copies from the
   others and serves once it has caught up with enough of them.

**Removing a node** (N → N−1):

1. Check that every node reports ready (`/readyz`).
2. Stop the node that leaves. The others carry on with the old size, on their majority (N−1 is at least a majority of
   N for any N of 2 or more).
3. On every remaining node set `cluster.size` to N−1 and remove the node from `cluster.peers`.
4. Reload. A reload that would shrink the size is refused while more nodes than the new size are in view: stop the
   leaving node first. Retire its data directory; it must not rejoin (with its old configuration it would refuse
   anyway: its size disagrees).

A step of more than one node, a `cluster.peers` that does not name `cluster.size` nodes, or nodes whose
configurations name different sizes are refused before anything changes. A reload changes nothing when the sizes
already match, so after a partial reload (a node that did not answer) reload again.

### `quisora force-start`

- Writes a marker file in the data directory; the **next start only** consumes it (the file is removed at start,
  whatever the outcome).
- On that start the node's data becomes the cluster's: its sync point is now, and it counts new, empty peers towards
  catching up, so they copy from it.
- It is **logged** at start, and written to the primary organization's **audit log** (`cluster.force_start`) as soon
  as the node is writable; until then it stays pending in the node's cluster state.
- It is ignored (logged) on a node with an empty database, a node restored from a backup, and a node whose first copy
  was interrupted.
- A node forced **while out of date** refuses after all if a peer serves the cluster's data and synced more recently.

## Backups

`quisora backup` and `GET /api/backup` write every live record with its version, generation and origin. Where the
backend offers a point-in-time view — BadgerDB (one read transaction), SQLite, PostgreSQL, MySQL and MariaDB (one
read-only repeatable-read transaction) — the backup is a **consistent snapshot**; on Valkey it pages through the live
store. A backup is encrypted with a password by default (AES-256-GCM in authenticated chunks, the key derived from the
password with argon2id; `--plain` writes it unencrypted, with secrets still sealed by the master key): a truncated,
reordered or altered file is refused before anything is restored. A remote download is checked for completeness as it
arrives. The remote download needs a super administrator's API token with the **`backup`** scope. Passwords, the
schedule and restoring: [RUNNING.md](RUNNING.md#backup-and-restore).

## Shared-database mode (no gossip)

Several nodes on one PostgreSQL, MySQL, MariaDB or Valkey database: the database is the only copy, nothing is
replicated, and compare-and-swap is the database's own. Tombstones are kept for one hour. The nodes must use the same
master key (a check value of it is kept in the database).

A **lease** in the database picks the node that runs housekeeping (key rotation, purge, user end dates): TTL 30 s,
renewed every 10 s, and a holder counts itself leader only until 10 s before its lease ends. Every takeover creates
the lease record anew, so its creation version is a **fencing token** unique to that tenure: housekeeping runs with
it, and each housekeeping write (and each purge) first checks that the lease record still names this node with that
token. A node that lost the lease — paused, cut off from the database, or with a clock so far off that it believes an
expired lease is still its own — has its housekeeping writes refused instead of racing the new holder's. Between that
check and the write itself two housekeepers are harmless: key rotation at worst publishes a spare key, end dates are
compare-and-swap updates and purging is idempotent. Keep clock skew between the nodes well under 10 s.

## Known limits

- The retention (7 days) and margin are fixed.
- Of two concurrent whole-record writes (upserts) of one record, the later commit wins; of two concurrent updates
  from one copy, one fails as stale.
- A quorum write whose commit reached fewer than a quorum is reported as failed but may be in effect on some nodes.
- Intents are in memory: a voter that restarts mid-write no longer holds the intent, and that write's commit fails
  there (its restart pause still forces any later conflicting write above it).
- A voter's restart relies on the clocks: it granted nothing more than 10 s ahead of its clock, and starts with its
  floor 10 s past the later of its clock and the other nodes' (Clocks), sitting out 11 s. A clock stepped back across
  the restart is caught by the peer clock check; a whole cluster restarted with every clock stepped back alike is
  not (nothing then disagrees), but its records' later versions make writes of them fail as stale, not reorder.
- A whole cluster restarted at once accepts no quorum writes for its first 11 s (see "What success and failure
  mean").
- Two records created concurrently on two nodes with the same unique value both exist until the clash is resolved
  (normally within seconds); the later one is then stripped of the value.
- The admin lock is held for at most 30 s; a holder stalled for longer could overlap the next holder.
- A group change's sequence fence rests on the removed membership record being kept: a writer stalled for longer than
  7 days (`model.RemovedMemberRetention`) could re-create a membership removed since, as any write that old could
  undo a purged tombstone. A membership a stalled writer materializes for a group or user deleted meanwhile is inert
  (readers resolve the group and user) but stays until its removal expires.
- Membership comes from the gossip library's failure detector; a node that is alive but cannot exchange data still
  counts as in view (writes then fail rather than being lost).
