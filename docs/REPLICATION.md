# Replication and data integrity

This document describes how a gossip cluster (`cluster.bind` set: every node has its own database) keeps its data
consistent, what each node does, and what an operator does after failures. The code that implements it is
`internal/cluster` (the cluster store `store.go`, the node's side of the protocol `partition.go`, node states
`node.go`, `state.go`, gossip handlers) on top of the gossip library's `partition` package
(`github.com/paularlott/gossip/partition`: its `README.md` is the user's guide and its `DESIGN.md` the protocol and the
argument for its safety), `internal/store` (the per-partition operations every node-local backend implements,
`partition.go`) and the storage backends. The design and the reasons for it are in
[design/partitioned-replication.md](design/partitioned-replication.md). The shared-database mode (no gossip) is
covered at the end.

**Pre-release data format.** Quisora has not been released: there is no migration from, and no compatibility with,
data written by earlier builds, and an earlier build's gossip mode (a leaderless quorum compare-and-swap with change
feeds) cannot take part in this one (the compatibility version differs: a node of either refuses the other). A store
written by an earlier build is refused when it is opened (a gossip node whose database holds records that no partition
write made says so and serves nothing), backups must be format version 1 (as this build writes them), and a
`cluster-state.json` must name its store (`self`). **Wipe and start clean** (restore from a backup made by this build if needed).

## The model in one paragraph

The data is split into **64 partitions**, a constant of the format. Every record has a **partition key**: the
organization's id for everything an organization owns, a record's own id for the independent single-record kinds
(locks, replay values, reservations), and nothing (partition 0, the global data) for organizations, signing keys and
the like. The key is hashed to a partition (`partition.PartitionOf`: partition 0 for no key, else 1 to 63). Every
partition has one **owner** node at a time, chosen by the library from the nodes that are ready (rendezvous hashing,
with the next ranks as fallbacks). **Every change to a record goes to the owner of its partition**, which checks it
against its committed data, gives it the partition's next sequence number, sends it to every node, and **commits** it
(applies it, answers, makes it visible) once a **majority of the configured cluster** has stored it durably. Every
node keeps a copy of every partition and reads from it. When an owner is lost, another node asks a majority to
promise it the partition (an *epoch*), which fences the old owner and tells the new one about every write that may
have been committed; a write whose outcome nobody knows is settled one way or the other, exactly once.

Because there is exactly one writer per partition at a time, and a write is visible only once a majority has it, there
are no conflicting writes to merge: nothing here depends on clocks for ordering, and nothing is resolved after the
fact.

## Guarantees

1. **A confirmed write is never lost, and never lost to a concurrent or stale write.** A write returns once a majority
   of the configured cluster has stored it durably; any later owner's promise round meets one of those nodes, finds the
   write and settles it, so a confirmed write survives the loss of any minority, the owner included. A write based on a
   copy that is no longer the newest (every `Update`, `Create` and `DeleteIf` is a compare-and-swap on the version the
   caller read) is refused by the owner, which compares it with its committed data: of two concurrent writes from the
   same copy at most one takes effect, on every kind of record.
2. **A deletion is never undone by a write that had not seen it.** A deletion is a tombstone, a write like any other:
   a live write over one is refused (`store.ErrDeleted`, which matches `store.ErrNotFound`); an id comes back only by
   an explicit create (`CompareAndPut` with expected version 0) that the owner orders after the deletion.
3. **Of two records claiming one unique value, one claim is refused.** The owner checks unique values against its
   committed data, within the partition, as part of the write: the second claim fails with `store.ErrConflict`. A value
   that must be unique across organizations is reserved first (below). Nothing is created, flagged or stripped
   afterwards.
4. **A node that cannot know its data is current does not act on it.** A node that is copying the cluster's data
   (a new node, a lost disk), catching up after a start, cut off from the majority or misconfigured serves nothing but
   its health probes (`/readyz` answers 503), makes no replicated write and owns no rate-limit counter. Readiness is the
   single gate: the token, userinfo and introspection endpoints refuse too (503 `temporarily_unavailable`), and clients
   retry on another node.
5. **Every automatic recovery is safe by construction; every operator override is explicit**, one-shot, logged and
   audited (`quisora force-start`). Nothing is ever wiped or emptied automatically.
6. **A write whose outcome is not known says so.** When the owner is lost or a reply times out after the write was sent,
   the caller gets `store.ErrUnconfirmed` (HTTP 503): the write may or may not be in effect; the next owner settles it,
   committed once or never. The service layer treats it as it treats a lost reply from a database server.
7. These rules are enforced by tests that model the failures, run with `-race`. The partition protocol itself (ownership,
   failover and hand-over, majority commit, pending writes and their settlement, catch-up and resync, splits and
   minorities, cluster ids and sizes) is tested in the gossip library (`partition/`, with its fault-injection tests).
   Quisora's own tests in `internal/cluster/*_test.go` cover what it builds on it: the scenarios in which the cluster
   drives a backend's durable state run on every backend (replication of writes, the store's errors, whole-cluster
   restart, the lost-disk resync and global reservations on BadgerDB, SQLite, and PostgreSQL, MySQL and MariaDB when
   their test DSNs are set: `scripts/test-dbs.sh`; purges, a node restored from its own snapshot and seeding on BadgerDB
   and SQLite); the others (one end-to-end owner loss, concurrent updates and claims, force-start, lagging and diverged
   partitions, unconfirmed and slow writes, resizes, membership, clocks, key rotation and compatibility) each run on
   one of BadgerDB and SQLite, the two about evenly. The store conformance suite, with the partition operations every
   backend implements, runs on every backend (`internal/service/consistency_test.go` covers the service's rules).

## Cluster size

`cluster.size` is **required** with `cluster.bind` (flag `--size`, `QUISORA_CLUSTER_SIZE`, TOML `cluster.size`; no
default): the number of nodes the cluster is made of. It must equal the number of nodes `cluster.peers` names (this
node included, however the list names it), or the node refuses to start. A write needs **a majority of that number**,
`size/2+1`: 2 of 3, 3 of 4, 3 of 5. **Run an odd number of nodes**: three tolerate one failure, five tolerate two, and
a fourth node adds a node to lose without letting any more fail. A cluster of two tolerates no failure at all.

- The size is **authoritative**: it decides how many nodes must store a write, how many a node must see to be ready and
  writable, and when it is cut off. It **never shrinks** when nodes leave, stop or
  restart, so a minority can never form a majority on its own. It changes only when the operator changes it in the
  configuration and reloads it, **one node at a time** (see [Changing the cluster size](#changing-the-cluster-size)).
- **Every node must agree.** Each node publishes its size in gossip metadata (`quisora.size`) and the partition
  protocol carries it in every message, and ignores messages from a node configured differently. A node whose size
  fewer than a majority of that size share (itself included) while an alive member publishes another one is the node
  configured apart (a reload that reached it alone, a node started with an old configuration): it refuses to serve (not
  ready, not writable, no tokens) until they agree. The nodes of the majority carry on and log the stranger once. So a
  single node with a wrong size stops only itself, and during a size change made one node at a time the nodes that have
  not reloaded yet keep serving while they are a majority of their size.

## Partitions, keys and ownership

### The partition key of a record

`model.Index.Partition` (carried by `store.Record.Partition`, stored by every backend, kept by tombstones):

| records | key | partition |
|---|---|---|
| everything scoped to an organization: users, groups, memberships, tenants, access, clients, providers, passkeys, identities, sessions, grants, API tokens, link tokens, sign-in records | the organization's id | one of 1 to 63, the same for all of an organization's records |
| organizations, signing keys, an entity with no organization (a self-registered client) | none | 0 |
| locks, replay values (`KindLock`, `KindReplay`) | the record's own id | spread over 1 to 63 |
| reservations (`KindReservation`, below) | the reservation's id | spread over 1 to 63 |
| short-lived state (`KindEphemeral`) and audit events (`KindAudit`) | never replicated: each node's own | none |

An organization's records, and every unique value scoped to it, are therefore in one partition: the owner checks them
together. A record **never changes partition** (its organization never changes). A busy organization stays on one
owner; that is accepted: an owner commits several hundred writes a second per partition, and password hashing, the
real CPU cost of a sign-in, stays on the node that took the request.

### Ownership

The owner of a partition is the ready node with the highest rendezvous hash of (partition, node id), computed by every
node from its own view of the membership; when a node leaves or joins, only the partitions whose highest hash was or
becomes that node move. A node is a candidate once it has caught up and a hold-down has passed
(`ReadyHoldDown`, 3 s by default: slept once, after the start-up catch-up and before the node publishes that it is ready,
so a node that crash-loops does not claim partitions between its starts; it does not apply when a running node loses and
regains a majority). Readiness gates
**ownership only**: a node that is not ready but holds its data still promises, stores writes and serves catch-up, or a
three-node cluster could not write while one node restarts.

Owners tell every node about once per `HeartbeatInterval` (500 ms) which partitions they own, at which epoch and
position. A node refuses to promise a partition to a challenger while it has heard from the current owner within the
owner timeout (three heartbeats: 1.5 s), and a node that thinks it should own a partition waits a random backoff
first: so two nodes that can each reach a majority but not each other do not take a partition back and forth. A
partition whose owner is lost is taken over after the owner timeout, the rank delay (1 s per rank) and the backoff (up
to 1.5 s) plus one promise round: **about 3.5 seconds** after an owner crashes (3.75 s measured at full scale), during
which writes to it fail with `store.ErrNotWritable` or wait for it, up to the 5 s write timeout. An owner that is
stopped (`SIGTERM`) hands its partitions back at once, and a partition handed back to a node that returns is taken
over at once (the claim's fast path), not after the timeouts. Views can disagree about who should own a partition;
that costs refused or delayed writes on the partitions involved, never a lost or
conflicting write.

## The write path

`cluster.Store.Put` and `CompareAndPut` (every kind but `KindEphemeral`) send one **change** to the owner of the
record's partition (`partition.Manager.Write`) and return when it has committed:

1. **The landing node** (the one that took the request) does the work that does not need the owner: it parses the
   request, checks the password (argon2) and builds the record. It sends the change to the owner it believes in; a node
   that is not the owner answers with the one it believes in and the landing node tries that once. The change is the
   encoded record, how to check it (**match**: the live version it must have, 0 for a create; **upsert**: whole-record
   put, refused over a tombstone; **blind**: a deletion that needs no particular version) and nothing else.
2. **The owner's `Prepare`** (`pstore.Prepare`), serialised per partition and against the committed data only:
   compares the version (`store.ErrStale`, `ErrNotFound`, `ErrDeleted`), checks the unique values the record lists
   within the partition (`store.ErrConflict`), stamps the new version (the owner's hybrid logical clock, and always above
   the version it replaces, whatever the clocks say) and the generation (`store.StampLocal`), and returns the stamped
   record as the write's data and its version as the reply. Refusals travel back as codes (`stale`, `conflict`,
   `deleted`, `not-found`) that the cluster store turns into the store's own errors.
3. **Replication**: the owner assigns the next sequence number and sends the write to every node, storing it as its
   own *pending* write at the same time (durable); a follower stores it as its pending write (durable) and
   acknowledges. The write is **committed** once a majority of the configured size, the owner included, has
   acknowledged. The owner then applies it to its records (`pstore.Commit`: the records and the partition's committed
   position in one transaction) and answers; followers apply it when the owner's commit notice arrives (one message
   after the commit) or at the latest with the next write or heartbeat.
4. **The writer reads its own write**: `Store.Put` waits until this node has applied the write (bounded, 5 s) before it
   returns, so `Get` after `Put` sees it on the same node. Other nodes see it a message later.
5. **A refusal is read after what caused it.** When the owner refuses a change (a stale version, a unique value in use,
   a record gone), its refusal carries the owner's committed position; the landing node waits (bounded by the
   partition's staleness bound, `StaleAfter`, 1.5 s) until it has applied that position before it returns `store.ErrStale`
   (or the other refusal), so the caller's re-read sees what made the change stale instead of the same old copy. A node
   that cannot catch up in that time fails closed: it returns `store.ErrNotWritable` (503, retry), never a refusal the
   caller would judge by a copy it cannot trust. A refresh token presented again after its rotation, on a node
   whose copy of the grant is a message behind, is therefore detected as reuse (the grant ends and it is audited), while
   a client retrying, within the grace, the token whose answer it lost is given the token it missed.

**The transport's deadline.** A node that is not the owner sends the change to the owner and waits for the answer for up
to the protocol's write timeout (5 s). The gossip transport must let it: Quisora sets gossip's `TCPDeadline` to the write
timeout plus a heartbeat and a second to spare (6.5 s), and a node whose configuration would make it shorter than the
protocol needs (`partition.Manager.MinTransportDeadline`) refuses to start. With a shorter deadline a change that takes
longer (an owner waiting for its partition, a slow follower) would be reported unknown while the owner commits it. Quisora's
own requests over the cluster bound themselves with shorter contexts: an ephemeral operation 2 s, a clock reading 3 s, an
audit page `auditWait`, a configuration reload the transport's deadline per phase, and fresh reads the protocol's write timeout.

One write at a time is in flight per partition (several hundred a second on a LAN with a fast disk, times 64
partitions); an owner holds at most 32 forwarded changes of one partition at once and 256 in all, and answers more
"busy" (the landing node sends them again after a pause of a few milliseconds: nothing was run). A node runs at most 4
catch-ups at once in the background, matching the exports a node serves at once. These are the library's defaults,
which Quisora keeps. A write is not abandoned when its caller goes away: it is seen through, within the library's write
timeout. Writes are checked on the owner against committed data, so **every check that must not run on a stale copy
runs there**: the compare-and-swap on the version the caller read, the unique values, and the reservations below.

The owner's `Commit` applies exactly what `Prepare` decided, deterministically, on every node; the change hooks
(`Node.OnChange`: cache eviction, live admin pages) run for every applied record, local or replicated, on every node.

### Durability

`partition.Store` is implemented over the node's own database (BadgerDB, SQLite, PostgreSQL, MySQL, MariaDB) with a
row per partition for the protocol state (`promised`, `committed`, `pending`) next to the data. The library's `Store`
contract is that `Commit`, `Import`, `SetPromised` and `SetPending` are all durable before they return. Deferring the
durability of `Commit` and `Import` is an optional optimisation, allowed only for a store that guarantees the ordering
rule (a durable promise or pending write also makes everything committed or imported before it durable); it works
because a commit that a crash loses is redone from the pending write. Which contract each backend meets:
**BadgerDB** and **MySQL/MariaDB** meet the simple one (a synced Badger commit; a transaction commit that flushes the redo log),
and **SQLite** and **PostgreSQL** use the optimisation for commits and imports (an unsynced transaction) and rely on the ordering
rule, which their write-ahead log gives: a later synced commit (a promise or a pending write) flushes the log up to itself,
the earlier unsynced ones included. The protocol's safety rests on this, so **BadgerDB must be opened
with `storage.badgerdb.sync_writes = true`** (the default; a gossip node refuses to start with it off): Badger syncs every
commit, the commits that need not be durable included (an option to leave those unsynced was built and removed). The same holds for the servers: **PostgreSQL must run with `synchronous_commit = on`** (its
default; `remote_write` and `remote_apply` are stronger; with `off` a crash can lose a promise or a pending write, and
nothing checks the setting): the promise and the pending write are ordinary commits that rely on it, while the commits and imports,
which need not be durable, set `synchronous_commit = off` for their own transaction only (a later synchronous commit
flushes the log up to itself, theirs included). MySQL and MariaDB need `innodb_flush_log_at_trx_commit = 1` (the default),
and SQLite's writer runs with `synchronous = FULL`. A node whose database cannot be written steps down from its
partitions.

## Reads

- **Most reads are local**, on whichever node took the request, and see only committed data: listings, loading a client,
  checking a session or an API token. They lag the owner by a message after a write, a heartbeat at the worst.
- **Fresh reads** (`store.QuorumReader`, `cluster.Store.Fresh`: the last-administrator check, the users a guard counts,
  `service.FreshUser`) go through the owners (`partition.Manager.Read`): the owner confirms with a majority that it still
  owns the partition and answers from its committed data, so the read returns every write committed before it was
  called, on any node, and never a state from before a write that had returned. The ids are grouped by partition from
  this node's copy of each record (a record's partition never changes); an id this node does not hold is asked of every
  partition's owner (kinds whose partition follows from the id are asked of one), unless the caller knows the
  organization, which names the partition: `cluster.Store.FreshIn` (`store.PartitionReader`) asks that one owner, and the
  service passes the organization wherever it has it (passkey and link sign-in, the orphan sweep, the guards that count
  an organization's users). Tombstones are returned too. A reply
  that would not fit one message is refused and the read asked again in halves.
- **The staleness gate.** A node serves a record from its own copy only while it can vouch for its copy of the record's
  partition (`partition.Manager.CanRead`): it has heard the partition's owner within the protocol's `StaleAfter` (or,
  owning it, a majority), it has not trailed what the owner reported committed for that long (a follower whose catch-up
  keeps failing), the partition has not diverged here, and the node is not copying its data (resync). Otherwise the
  single-record reads of the cluster store (`Get`, `GetByUnique`, `GetMany`, `Lookup`) refuse with `store.ErrNotWritable`
  (HTTP 503), so a revoked session, a disabled user or a rotated secret is never served from a copy that stopped following
  the cluster, however long it stays behind; the other nodes serve it. A node's own audit events and short-lived state are
  not in a partition and are exempt; a reservation follows the partition of its own id. Listings and counts are not
  gated (they are not decisions about one record), except listings of organizations and signing keys, which live only in
  the global partition: a node that trails it refuses them, so it never publishes a key set the majority has changed (a
  revoked key). Its JWKS then answers 503 rather than the keys it last loaded. A follower keeps serving a partition while its owner hands it over
  (freshness counts from the last owner heard, within the staleness limit, as between heartbeats); a partition whose owner
  crashed is refused once that limit passes, until its new owner is heard (writes to it fail meanwhile too).
  A node that is cut off from the majority hears no owner, so its partitions are unreadable, and it is not ready.
- **Readiness follows divergence, not unreadability.** A node is not ready while a partition has diverged on it (only an
  operator can clear that); `GET /api/cluster` says which and why, and the log has it (a divergence at warn level, once per
  partition). A partition that is merely unreadable on a node (an owner that cannot be replaced, a catch-up that keeps
  failing) does not take the node out of rotation: its records answer 503 one by one while every other partition keeps
  working, and an unreadable partition is usually unreadable on every node, which would otherwise turn the loss of one
  partition (1/64 of the organizations) into a total outage. `partitions_unreadable` in `GET /api/cluster` and
  `quisora_partitions_unreadable` stay: alert on them.
- **Bounded staleness.** A node that cannot see a majority is not ready: `/readyz` says 503 and so does everything else but
  the probes, the token endpoints included, so a node cut off serves no revoked session or disabled account.
- **Hot records.** A sign-in's stamps (the last sign-in, the last TOTP step) are in a record of their own
  (`model.SignIn`), and failed attempts and lockouts in short-lived state, so sign-ins do not make an administrator's change
  of the user fail on the user's expected version.

## Unique values

A unique value is checked by the owner, against its committed data, in the partition of the record. Every unique value
is either prefixed by the organization or by an id of one organization's record (users, groups, tenant names,
providers, identities, link tokens) and so lives in one partition, or must hold across organizations. Two values must
hold across organizations (`model.GlobalUnique`), because they are looked up with no organization at hand: a tenant's
**resource indicator** (`res/<canonical uri>`, in an authorization request) and a **passkey's credential id** (a
discoverable sign-in from the landing page).

A global value is held by a **reservation**, a record of its own kind (`model.KindReservation`, `model.Reservation`:
the kind and id of the record that holds it). Its id is the kind and the value (hashed, deterministically, when that
would not fit the 191-character id column of the SQL backends) and its partition key is that id, so the claims spread
over the partitions and one owner decides each. Writing a record that lists a global value:

1. **claims** it first: a change to the reservation's partition that creates the reservation for this record (the
   owner refuses with a conflict if another record holds it; claiming a value the record holds already changes
   nothing). The claim is skipped when the write is a compare-and-swap on the very version of the record this node holds,
   that version lists the value, and this node's committed reservation names the record (every passkey sign-in's count,
   every tenant update): if the compare-and-swap succeeds the record still lists the value when the write commits, and a
   reservation is released or taken over only after a later version of its holder without the value, which the
   compare-and-swap rules out;
2. writes the record **without** that value in its unique list (it is reserved, not indexed): a reservation is released
   if this write fails for certain, and kept if its outcome is unknown;
3. afterwards **releases** the reservations of values the record held before and no longer lists (an update that drops
   a resource, a deletion): best effort, because
4. a reservation whose holder no longer lists the value or was deleted (a lost release) is **taken over by the next
   claim**, once it is older than a minute (`reservationGrace`), and only on positive evidence: the owner of the
   reservation takes it over when its own copy of the holder is a tombstone or a live record that does not list the value,
   **written after the reservation** (its version is later). A holder the owner does not have, or has only as it was
   before the reservation, proves nothing (its copy of the holder's partition may lag behind the update that added the
   value), so the reservation stays and is left to the sweep (5). The holder is written after the claim, so a young reservation whose holder does not hold the value yet is never
   taken from under a record that is about to be written;
5. a reservation whose holder never came (a crash between the two writes) or is gone, which no claim will take over, is
   released by the **housekeeping leader's sweep** (`Node.SweepReservations`, a batch each minute, a pass over every
   reservation taking as long as the orphan sweep): for each reservation older than a minute whose holder this node does
   not see holding it, the holder is read through the owner of its own partition (a linearizable read), and if it does not
   exist, is deleted or does not list the value, the reservation is released with a compare-and-swap on the version read.

`GetByUnique` for a global value reads the reservation, then the record it names, and returns the record only if it
still lists the value. A crash can leave a value reserved with no record until the sweep reaches it (a few minutes at the
least: the minute of grace and the next pass); a retry of the same creation (a new record id) is refused as a conflict
until then.

## Records, versions and generations

Every record carries a **version** (a hybrid logical clock timestamp: microseconds since 1 January 2025 plus a counter),
**Origin** (the node that wrote it), **Epoch** (the *generation* of a live record: 0 for one created once, or, for a
record created again after a deletion, the version of the tombstone it superseded), **Created** (the version of the write
that created the generation), **Deleted** (a tombstone) and its **partition key**. Versions are stamped by the owner and
are used for the compare-and-swap (the caller's expected version), tombstone age and display; **order comes from the
partition's (epoch, sequence), never from clocks**. A new version of a record is always above the one it replaces
(`max(clock, old+1)`), so a clock stepped back changes nothing.

- `Put` of a live record over a live one continues its generation; over a tombstone it is **refused with
  `store.ErrDeleted`**.
- `CompareAndPut` with `expect != 0` (an update) needs a live record at exactly that version (`ErrNotFound` / `ErrStale`
  otherwise) and continues its generation; with `expect == 0` (a create) over nothing it starts generation 0, over a
  tombstone a generation whose epoch is that tombstone's version, over an expired record it keeps the generation.
- A deletion (`Put` of a tombstone, or `DeleteIf` against a version) carries the partition key and scope of the record it
  deletes (the landing node looks it up, asking the owners if it does not hold the record). Deleting what is not there
  changes nothing.
- Node-local state (`KindEphemeral`: leases, markers, short-lived sign-in state) is never replicated.
- **Audit events** (`KindAudit`), in the database audit mode, are **never replicated**: every node writes the events it
  records to its own database, a local write that needs no owner, no majority and no readiness (a node cut off from the
  others still records its own). They are never part of a partition write, a catch-up export or import, or the seeding of
  a new cluster, and a full copy of a partition leaves a node's own events untouched. An audit page (`GET /api/audit`,
  the console) asks every alive node of the same data set for its newest matching events (`UserMsg+10`, at most 5,000
  per node, encrypted and authenticated with the cluster key like every message; a node's answer is cut to what fits one
  message, 3 MB, and asked for again from where it ended, so a page of large events is complete), merges them in the page's order and
  says how many nodes answered within 3 seconds: a node that is down or slow is missing from the page, not an error.
  Each node purges its own events after `audit.retention_days`. With VictoriaLogs configured (production), every node
  sends its events there instead, and the pages read them from it.

### Re-using an id

Most ids are random UUIDs and are never re-used. Deterministic ids (group memberships, tenant access, sign-in records, locks)
are re-created with a create, which the owner orders after the deletion. The fixed bootstrap ids (primary organization, its default tenant, the first
administrator) are written by `quisora bootstrap`, which seeds the partitions (below); a node set up apart from the
cluster it meets is refused (below).

### Housekeeping

Key rotation, user end dates, orphan and reservation sweeps and re-sealing run on **one node: the owner of partition 0**
(the global data), as long as it can read partition 0 and is writable (`Node.IsLeader`; `leader` in the status, and
`quisora_leader`, say which node that is). There is no separate election: partition 0's owner is the node every other node
already agrees on, and a hand-back (a restart, a resize, a clock that is off) or a crash moves housekeeping with it. A new
housekeeper runs a pass at once and then every interval; every task is idempotent, so a pass interrupted by a move is simply
run again by the next owner.

Housekeeping is **fenced** by the same tenure. A pass starts with a context carrying the epoch under which this node owns
partition 0 (`Node.fence`), and each write made with it first checks that this node still owns partition 0 at that epoch
(`Node.fenced`); a node that was deposed in the middle of a pass (paused, cut off, handed partition 0 back) has the rest of
that pass's writes refused (`store.ErrNotWritable`) instead of racing the new housekeeper's. What remains is the moment
between the check and the write, in which two housekeepers are harmless for the same reason as in the shared-database mode
(below). A node that becomes housekeeper again later starts a new pass under the new epoch.

There is no `cluster` setting for any of this: the timing is the partition protocol's (`HeartbeatInterval`, `OwnerTimeout`).
Earlier builds ran a separate gossip leader election for housekeeping; it is gone, with its tuning, and nothing needs
changing in a configuration for it.

### Tombstones and their purge

Tombstones are kept for the retention (7 days) so that a node that was away catches up by sequence number, which is cheap.
**A purge is a write of the partition**: the owner's housekeeping scans a partition for its tombstones about once an
hour (reading only the tombstones, from an index every backend keeps of them by sequence, and within the same limit on
long reads as a catch-up export: a node serves at most four at once, so a scan that finds none free waits for the next
round), chooses a sequence number below which every tombstone is older than the retention, and writes "purge below
sequence N"; every node purges the same tombstones at the same position, whatever its clock (`pstore.Commit`
purges first, then applies, so a crash between the two is repeated harmlessly). A node whose committed position is
below a partition's purge point cannot catch up by sequence and **copies the partition whole**, which replaces its data
(a record deleted meanwhile does not come back). So the retention is a matter of cost, never of safety. Records that
expired are removed by every node from its own copy.

## Catching up, joining and returning

- **By sequence, per partition, of committed writes only.** A node behind a committed position (from a heartbeat, a write
  or the exchange at start) asks a node that has it for the changes after its own committed sequence; the owner is the
  preferred source, and any node is a safe source up to its own commit point because committed data is the same on every
  node that has it. Nobody ever serves a pending write as data. The stream is a frame per record and an end marker. It is
  produced as it is sent (the sender holds a snapshot of its database, reads it a page at a time and writes nothing to disk;
  the snapshot is released when the stream ends or the receiver goes away) and applied as it arrives, a thousand records at a
  time, so memory is bounded by a batch whatever the size of the partition. **The committed position moves only when the end
  marker has been read**: a stream cut short leaves the position where it was, with the batches before the cut already
  stored (committed data of the source, each record carrying the sequence of the write that made it, which an export does
  not show above the position); the next catch-up asks for the same changes again and completes it. Until it has, the
  node serves no catch-up of that partition (its export would leave out the records the unfinished import replaced). A
  node serves at most four catch-ups at once (half its database's reader connections, on SQLite, at most): each holds a
  snapshot, and a connection, for its whole stream. A request it refuses fails, and the asker tries again.
- **Whole**, when the source purged the history needed (above), or for a node that has none.
- **At start** a node asks every node in view for its state; once a majority including itself has answered (a **majority
  of the other nodes** for a node whose data is not intact) it catches every partition up and, after the hold-down,
  becomes ready. A node with data serves catch-up whether or not it is ready, so a whole-cluster restart always proceeds.
- **A node whose data is not intact** (new, or its database was lost, replaced or restored) is in **resync mode**: it
  promises nothing, stores nothing and serves nothing until it has copied every partition from a majority of the other
  nodes and raised its promises to the highest they report: a node that forgot its promises could otherwise help a
  lower epoch win, and one that lost an acknowledged write could let it be overwritten. It also adopts the pending
  write of the highest epoch that the others hold. In a cluster of three both others must be reachable; of five, three
  of the four. When the resync completes, its database is intact from then on (`cluster-state.json`: `intact`), so its next
  restart needs none.
- **Intact** is decided at start from `cluster-state.json` (`intact`, and `self` naming this very database: a replaced or
  restored database is not): true for a node that has run, for the first node of a new cluster (`quisora bootstrap` and
  `quisora restore` seed its partitions: below), false for everything else. A database that holds records no partition
  write made (an earlier build's, or loaded by hand) is refused outright, not served and not copied from.
- **Formation.** Only nodes whose data is intact count, so a new cluster (one seeded node, the others empty) could not
  start by the rules above alone. A node *forms* (`cluster-state.json`: `formed`, called `established` in older files,
  which are still read; set durably through the protocol's `Config.SetFormed` before its first promise is stored, or when it
  has synchronised with an intact majority); until then it is *unformed*, and says so in its answers. A node copying a data
  set counts only intact answers from formed nodes toward its quorum, except in formation: when it is unformed itself and
  every other node of the cluster answered unformed too (intact or not), at least one intact (the founder), it copies from
  the founder alone, because no write can have been committed without an unformed node (every commit needs a takeover,
  every takeover a majority of promises, and a promise forms its giver). One formed answer rules that out, and so does a
  node that does not answer (it may have formed with another): a new cluster forms once every node has started. The founder is the node seeded
  by `StartNewCluster` (bootstrap, restore, the load test's seed); it and every node that adopts its data set start
  unformed, and from then on every node is formed and the quorum applies again. A formed node holds a data set and is never
  made the first node of another (`CheckNewCluster`), nor is one that adopted a data set and is still copying it (not
  intact); a state `StartNewCluster` wrote for a node that has not run yet (unformed) does not count. A node whose state
  file is trusted keeps its flag across restarts. Losing the disks of a majority of the nodes loses the writes only they held;
  recovery is from backup. (If the only node left is one that never formed, it may form the data set again from its own
  copy without `ForceResync`.)
- **Never restore a gossip node in place from its own snapshot** (a VM or disk snapshot, a database restored to a point in
  time, a database file copied back): it keeps its node id and its database's identity, so it would pass as intact while
  it has forgotten the promises it gave and the writes it acknowledged since the snapshot. Replace it instead (an empty
  database: it copies everything), or restore a backup as a new data set. Quisora detects it where it can: every start is
  counted, durably, before the protocol starts, in `cluster-state.json` and in the database (`starts`); every node publishes
  its count (`quisora.starts`) and remembers, persisted, the highest count it has seen of each peer, and publishes that
  too. A database older than its state file (a database restored alone), or a peer of the data set remembering a start of
  this node at least as recent as this one (the whole node restored), makes the node not intact: it resyncs, and says
  why in its log. A peer that reveals it only after the protocol has started makes the node refuse to serve and leave the
  protocol until it is restarted (and then resyncs). A node restored while every peer that saw its later starts is down
  goes unnoticed.
- **Seeding.** `quisora bootstrap`, `quisora restore` and the load test's seed on a gossip node write the records they
  create or restore as writes of their partitions (`cluster.StartNewCluster`), a page of one kind at a time: the records of
  a page that belong to one partition are one write with the partition's next sequence number (so memory is bounded by a
  page, and a record written after an earlier run is stamped too), turn the global unique values they list into
  reservations and create a new **data set** (below) whose data is this node's; the other nodes start with empty databases
  and copy everything from it. A restore needs an empty database (the first node of a new cluster), never over data. Until
  the node has run it can be run again (the data set stays the same); **it is refused on a node that already holds a data
  set** (its `cluster-state.json`, saved for this very database, says it took part in a cluster or adopted one's data set):
  its partitions share their sequence numbers with the cluster's.
- **The data set, and who may create one.** Every cluster's data has an identity, its *data set* (a random id, the
  *genesis*), kept in `cluster-state.json` and published in gossip metadata. **Only `quisora bootstrap --new-cluster` and a
  restore create one**; nothing else does, and nodes never invent one. The partition protocol carries it in every message
  (the library's `ClusterID`): **nodes of different data sets ignore each other completely** (no promises, writes,
  heartbeats, state or catch-up), however they come to meet, so a node bootstrapped or restored by mistake can never send
  its data to the cluster nor receive the cluster's, and two data sets are never merged by sequence number.
  - A node with **no data set** (it started with an empty database) does not start the partition protocol until it sees
    alive nodes publishing one. If all of them publish the same, it adopts it (and keeps it) and copies everything from them
    (it starts not intact, in resync mode); if they publish different ones, it joins none (not ready, logged) until they
    agree. Nodes that all have none (started before anyone bootstrapped) wait, saying so: "no data set: run quisora
    bootstrap --new-cluster on one node".
  - A data set is trusted only for the database it was saved for (`self` in `cluster-state.json`): a data directory kept
    while its database was wiped or replaced keeps no identity; the node joins as an empty node would, and a new bootstrap
    there makes a new data set.
  - A node that meets nodes of another data set says so: when fewer than a majority of the cluster share its own, it
    refuses to serve ("another data set is in view": it was set up apart; start it with an empty database and it adopts the
    cluster's); the nodes of the majority log the stranger and carry on. That check is for the operator: the protocol does
    not depend on it.
  - Housekeeping follows partition 0, whose owner is chosen among the nodes of one data set only (a node ignores the
    others'), and a node owns partitions only once it holds a data set: a node set up apart, or one still waiting for a
    data set, never runs the cluster's housekeeping.

## What keeps working, without an operator

With 3 nodes (with 5, read "up to two"):

| Situation | What happens |
| --- | --- |
| One node down | The other two are a majority: they take over its partitions and keep writing and serving. |
| It returns with its data | It catches up by sequence and rejoins on its own. |
| It returns with its data lost (a new disk) | It copies from the other two and rejoins on its own. |
| It was away longer than tombstones are kept | It copies the partitions it cannot catch up by sequence, on its own. |
| Every node restarts | They promise and catch up among themselves: no `force-start`. |
| Two nodes impaired at once (one down, another lost its data) | The survivor cannot know whether it misses committed writes: an operator accepts that with `quisora force-start`. |
| Losing the data of two nodes at once | What only they held is gone; restore from a backup. |

## Node states

| state | when | ready / tokens | replicated writes |
|---|---|---|---|
| **resyncing** | its data is not intact (new, lost, restored, forced) until it has copied from the others | no / no | none |
| **catching up** | every start, until caught up and the hold-down has passed | no / no | none |
| **ready** | caught up, a majority in view, every node agrees on the size and runs a compatible build | yes / yes | all |
| **cut off** | fewer than a majority in view | no / no | none |
| **partition diverged** | a partition diverged here | no / no | none |
| **partition unreadable** | a partition cannot be read here (no owner heard, catch-up failing); `partitions_unreadable` counts them | yes / yes, except that partition's records | all |
| **misconfigured** | database shared with another gossip node, owned by another node id, mixed with non-gossip nodes, holding records no partition write made, set up apart from the cluster, prefix collision, **size or build disagreement**, clock off | no / no | none |

Only node-local records (`KindEphemeral`) are written on a node that is not ready. A refused write returns
`store.ErrNotWritable` (HTTP 503) and has no effect anywhere. A node never leads unless it is writable, so
housekeeping (key rotation, user end dates, orphan sweeps, purges) runs only where the data is current (see
"Housekeeping" below). The status
(`GET /api/cluster`) shows each node's state and why it is not ready, and every partition's owner, epoch, committed
position, lag, catch-up and divergence.

A change whose outcome is not known (`store.ErrUnconfirmed`, the service's `ErrOutcomeUnknown`) is audited as the change
would be, with outcome `unknown`: it may have been made, and the audit log must not miss a change that took effect.

## What the service builds on this

The rules below are the service layer's (`internal/service`): they use the store's compare-and-swap, unique values and fresh reads and are the same in every mode except where noted.

### Sign-in stamps

A user's last sign-in and last accepted TOTP time step live in a separate per-user **sign-in record**
(`model.SignIn`, id = the user's id), never on the user: a sign-in can neither erase nor be erased by an
administrator's change of the user. The TOTP step is recorded with a create-once / compare-and-swap of that record
before the code is accepted, so a code is accepted once on any node: the same code presented on two nodes at once is
accepted by exactly one, and a node that has not yet received a use is refused by the owner, which has committed it. When the
step cannot be recorded the code is refused (fails closed). Failed attempts and lockouts are counted in short-lived
state (below), not in records.

### Super admins are protected by rank, not by a count

There is no cluster-wide guarantee that a usable super admin always remains. What holds instead, on every node and in
every mode, are rules about who may act on whom, none of which needs a lock or another node's answer:

- nobody demotes, disables, locks out, end-dates or deletes **themselves** (nor changes their own end date);
- only a **super admin** demotes, disables, locks out, end-dates or deletes a super admin (an administrator, a manager or a
  provisioning client such as SCIM cannot);
- the **system** (housekeeping, the end-date sweep, commands acting as the system) never does either: the sweep that
  disables accounts past their end date leaves super admins alone (their end date still stops their sign-in).

A deletion is one compare-and-swap on the version the rules were judged on, checked by the owner, so a user promoted
to super admin meanwhile is not deleted on the strength of the older copy. What the rules cannot prevent: **two super
admins removing each other at the same moment** (on different nodes, or one disabling the other while the other
disables them) can leave none, and so can a super admin's end date passing. The recovery is outside the service, with the
master key: `quisora invite --break-glass --super-admin <primary org> <email>` (see SECURITY.md, incident response).

### The last way in

A user removing one of their own ways to sign in (a passkey, a connected provider, the authenticator app) may not
remove the last one, nor their last second factor where one is required. A removal is one compare-and-swap of the
user record, checked by the owner against the version the caller read, decided on the credentials read through the
owners (their contents: a key disabled, a provider turned off, a link of a passed epoch count for nothing). The write lists
the passkeys and links removed (`model.User.Removed`: they stop counting at that write, on every node), clears the
authenticator app, drops the recovery codes with the last second factor and moves the security generation on. Two
removals at once, however long either stalls, cannot both commit on the copy they decided on: the second is refused
(`ErrStale`), decides again on the account as the first left it, and is refused as the last way in. The records are
deleted after the commit, as tidying (the orphan sweep removes any left); an entry leaves the list once its record
has been gone for the tombstone retention, and a new credential epoch clears it. No lock is involved, so nothing
depends on a lease outliving a stalled request.

### Groups and their members

A change of a group and its members (a SCIM PATCH or PUT, an admin console change, a creation with members, a
deletion) touches several records: the group, and one membership record per user added or removed. **The group's
record is the single commit point.** Every change is committed by one compare-and-swap of that record, checked by the owner, on the version the change was made from: it writes the group's fields and appends a *change
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
serialise with changes of the members without a lock and preserve the pending log. A deletion is one conditional
removal of the group's record: its memberships stand on it, so from that moment nobody is a member of the group,
and the orphan sweep marks their records removed later ("Deletion" below). Creating a group with members
creates the record carrying the first entry: the group exists with every member or not at all. One change may add
and remove at most 1,000 memberships (`service.MaxMembersPerChange`), which keeps the log small; SCIM refuses a
larger PATCH or PUT with 413 (RFC 7644 §3.12) and the client splits it.

Whose membership an actor may change depends on the user's rank (an administrator never reaches a super admin; a
manager or a provisioning client changes plain users' memberships only), so a change by anyone but a super admin
judges each user it touches on the newer of this node's copy and **the owners'** (one fresh read for the whole
change, `membersToJudge`): a promotion committed anywhere counts before it has reached this node. A user who
cannot be read refuses the change; a rank that could not be read is never taken as plain.

**What readers see.** Every reader of memberships (the groups of a user for tokens and tenant access, a group's
members, member counts, SCIM resources) reads the group's record and applies its pending entries over the
membership records, so it observes exactly the committed changes: never one that failed (nothing of it was written)
and never a committed one in part. A user's groups for tokens are read group by group, each matched with the user's
membership at the same moment by the group's change numbers (a membership record carries the number of the change
that wrote it): a membership older than the group read is read again through the owner, and a group older than the
membership read is read again through the owner, until they agree, so a user never gets a group's tags from a moment they
were not its member. A committed removal is in force the moment the commit succeeds, materialized or
not; a committed addition is seen the same way (a user's groups include the organization's groups with pending
entries, one indexed read, normally empty). A membership of a group that no longer exists names no group and grants
nothing. The group's version, its SCIM ETag, moves at the commit and once more when the entry is cleared (normally
within the same request, which returns the final version); a change made from a copy that is no longer the newest
is refused (`ErrStale`, HTTP 412 with `If-Match`). A deleted user's memberships are left to the orphan sweep: they
name a user who no longer exists, and member lists leave them out.

### Refresh grants and single-use values

Refresh grants are compare-and-swaps checked by the owner because rotating a refresh token advances the grant's counter: a node that had not
yet received the advance cannot make the owner accept the old token (it is refused as stale). Replay records (`model.Replay`, `service.UseOnce`) hold the
single-use values seen — client assertion and DPoP proof `jti`s — until they expire, so a value accepted once is
refused on every node, whichever nodes stop, restart or leave meanwhile. Invitation and reset links are
compare-and-swaps too, and an account has at most one of each (a new one replaces the record, and every try of the write judges
the record it replaces). One is used up by the commit of the change it makes, a compare-and-swap of the user
record that moves the account's security generation on (`service.UseSignInLink`): a link presented to two nodes at
once is used once, and a failure before the commit leaves it usable.

The user record is also the one commit point for which of an account's credentials and sign-ins count. Every
passkey, connected provider and API token carries the account's **credential epoch** it was made in
(`model.User.CredEpoch`); every session carries its **session epoch** (`SessionEpoch`). Each works only while its
epoch is the account's. A password reset gives the account a new session epoch in its commit; an accepted invitation
(or a reset of the account's sign-in) new epochs of both: every earlier session or credential stops at that write, on
every node that has it, and the passkey an invitation stored for its new epoch beforehand starts. Of two acceptances
racing, only the winner's epoch is committed; the loser's passkey never counts. "At that write" means where the
write has landed: a check reads the node's own copy of the account (the token endpoints cache it for up to 5 s), so
on a node the commit has not reached yet the old ones work until it arrives. The commit is held by a majority when it
returns; the other nodes apply it when the owner's commit notice reaches them, a message later. A refresh grant carries the session
epoch and the sign-out stamp of the session it was granted in, never the current ones: an authorization code or
device sign-in is redeemed only while its session still signs the user in (`service.SessionUsable`, the one test of
a session, also for browsers), so a code cannot outlive, or renew, what its session lost. Removing old records after a
change is tidying of the epochs that change replaced and of no other, so a late tidying never touches what a later
change made (the orphan sweep finishes it after a crash, and removes a losing acceptance's passkey).

## Deletion

Deleting an organization, user, group, tenant or provider deletes that one record. Everything that was its stands on
it and stops counting at that write, on every node that has it: a user stands on its organization
(`service.UserUsable`, checked for every session, refresh grant, access token and API token), a credential or session
on its user and epoch, a membership on its group and user, an access entry on its tenant and subject, a connected
provider on its user and provider, an application on its organization. Readers apply this test; nothing else has
to be written for it.

**The orphan sweep is the one cascade.** The housekeeping leader reads every record of the kinds that do not expire,
20,000 a minute, owners before what they own (`service.SweepOrphans`): a record whose owner is gone — missing here and,
read through the owners, there too — is removed (a membership is marked removed, fencing stalled group writers), and so is a
credential, session or refresh grant of an epoch its account has moved past. Only records at least an hour old are
judged, so an owner created on another node has time to arrive. A pass takes about a day at five million users. It
also removes what any interrupted write left, so there is no other clean-up path to keep correct.

Deleting an organization sends no back-channel logout: a user signs in only to applications of their own
organization, and those are deleted with it (their tokens stop working at once), so the deletion is one write
whatever the organization's size. Deleting a user tells the applications at once. Their memberships stand on them:
every reader of a group's members (lists, counts, SCIM) keeps only members that are users of the organization, by
merging the member ids with the organization's user ids read from its index a page at a time (no user record is
read), so a deleted user is never a member, whatever the clean-up has done (a pending addition that materializes
after the deletion included). A manager reference is cleared through the sparse `manager_id` index: only the
deleted user's reports are read.

A unique value held by such a record (a provider identity's subject, a passkey's credential id) does not wait for the
sweep: a create that finds it taken asks `service.ReleaseUnique`, which removes the holder if, read through its owner, it
counts for nothing, and the create is tried once more. Deleting an account never blocks linking its provider
identity, or registering its authenticator, to another.

### Serving while not ready

Until a node is ready, **every path except `/healthz`, `/readyz`, `/assets/…`, `/branding/…` and `/favicon.ico`
answers 503** with `Retry-After: 5` (JSON `temporarily_unavailable` for `/oauth/…` and `/.well-known/…`, JSON
`{"error": …}` for `/api/…` and `/scim/…`, plain text otherwise): management and SCIM reads, the authorization and
sign-in pages, discovery and JWKS alike, so a client that bypasses the load balancer never receives partial, stale or
deleted data (`web.Server.serveGate`), the token, userinfo and introspection endpoints included: a node cut off from the
majority issues no tokens and answers no introspection, and clients retry on another node. A restarting node issues no
tokens until it has caught up.

### Short-lived state

Sign-in steps, codes and challenges stay in the memory of the node that made them (their ids carry its prefix) and
the others forward to it. Hash-routed state — rate-limit and lockout counters — lives on the rendezvous-hash owner
**among the nodes that are ready and alive** (each publishes `quisora.ready` in gossip metadata; a node gossip
suspects owns nothing, so its counters move at once rather than every request waiting on it). It **fails closed**:
when no ready node is in view, or the owner cannot be reached, the operation fails (the rate limit or lockout
refuses) instead of counting on one node. It is in the owner's memory only: when the owner changes (a node stops
serving, restarts, leaves or is suspected) the new owner starts from nothing, so a counter's window starts again.
A limit checked before anything else (client authentication, a bearer token) reads the counter from the owner's
last answer to this node when that is under a second old, so the requests that pass a limit cost no round trip;
every attempt that counts goes to the owner and refreshes it, so a node lets at most one attempt past a limit reached
through other nodes before it refuses too. Nothing whose safety
depends on it surviving that is kept there: single-use values are replay records (compare-and-swap checked by the owner, above).

## Wire messages

Every message is authenticated and encrypted by the cluster key (gossip's AES-GCM, with a packet-age check); nothing
here is an unauthenticated surface. The gossip transport carries them; the cluster runs with 32 incoming and 16
sending workers (`NumIncomingWorkers`, `NumSendWorkers`), and the partition protocol answers on goroutines of its own,
so a request waiting for a disk or a majority never holds a worker.

**The partition protocol** (the library's: `gossip.PartHeartbeatMsg` to `PartReadMsg`, `ReservedMsgsStart+30..39`; every
message carries the sender's `ClusterSize`, and a receiver configured differently answers "size mismatch"):

| message | kind | content |
|---|---|---|
| Heartbeat | request | the partitions the sender owns with epoch and committed position → which it accepts, which it fences |
| Promise | request | partition, proposed epoch → OK, the responder's promise, committed position and pending write |
| Write | request | the write (epoch, sequence, previous position, data) and the owner's committed position → OK, promise, committed, "need catch-up" |
| Change | request | partition, the change → committed (position, reply), refused (code), unknown, not the owner (the owner it believes in), unavailable, busy |
| Read | request | partition, request → the owner's answer after it confirmed with a majority that it owns the partition |
| State | request | → committed, promised and pending of every partition |
| CatchUp | stream | partition, after → header, then the changed records (a frame each) and an end marker |
| Commit | one way | partition, epoch, committed position (the owner's commit notice) |
| Claim, Relinquish | request, one way | a higher-ranked node asks the owner to hand a partition back; an owner says it stepped down |

**Quisora's own** (`UserMsg+n`): `+5` an ephemeral operation on the node that owns the state; `+11` a change notice
(shared-database `cluster.notify` gossip only); `+12` a configuration reload (check, or apply); `+14` this node's clock
(the peer clock check); `+10` an audit page (this node's own events, answered only to a node of the same data set).
`+1` to `+4`, `+6` to `+9` and `+13` were the earlier gossip mode's (record broadcast, push, change feed, quorum
compare-and-swap, quorum read) and are not reused. The compatibility version published in gossip
metadata (`quisora.compat`) is 2: a node of the earlier mode, which publishes 1, and this one refuse each other.

The **change** a node sends is `change{Op, Mode, Expect, Rec, Kind, ID, Key, Before}` (msgpack): a record write, a
reservation claim or release, or a purge point; the **write's data** is `writeData{Recs, Purge}`: the stamped records every
node applies, and the purge point to apply first. Both stay under the cluster's packet limit (4 MB by default), so a
record must too; a fresh read's reply is asked again in halves when it would not fit.

## Clocks

Versions come from the owners' clocks and are always above the one they replace, and order comes from sequence numbers, so
clock skew cannot reorder or lose a write. Clocks still decide when a session, a grant, an invitation or an end date
expires, on each node by its own clock, and the age of a tombstone for its purge: keep every node's clock synchronised (NTP).

- A node **refuses to start** when its clock reads before 1 January 2025 (the version clock's epoch).
- A version read or received is witnessed into the node's clock only when it is at most `store.MaxSkew` (5 s) ahead of the
  machine's clock (`hlc.Clock.WitnessBounded`); one further ahead is applied but not followed (counted as `skew_refused`),
  so one bad clock cannot drag every node's versions into the future. Received versions more than 5 s ahead are logged
  (hourly per origin) and counted (`clock_skewed`). A new version of a record is `max(clock, old version + 1)`, so a
  record written under a clock that ran ahead can still be written.
- **Every node checks its clock against the others'** (`internal/cluster/clock.go`). Every 5 s a node asks each peer for its
  time (`UserMsg+14`); it reads the offset as NTP does (against the midpoint of the request) and keeps each peer's latest
  reading in memory, nothing on disk. The cluster's clock is the **median** of its own (offset 0) and the readings of the last
  30 s, taken only once it has heard from enough peers to make a majority with itself. If its clock is more than 5 s from that,
  the node refuses to serve (not ready, no writes, no tokens) and logs why; it serves again once it is within 2.5 s. A
  minority of bad clocks is outvoted: in three nodes, one with a bad clock stops only itself. `/readyz` reports the offset
  (`clock_offset_ms`).
- **A node whose clock is off owns no partition** (`partition.Manager.SetEligible(false)`): it steps down from every
  partition it owns at once (the others take them over without waiting for a timeout) and takes none over, so it never
  decides whether a record is live, or how long an owner has been silent, by a clock the cluster does not keep. It still
  follows the owners, stores their writes and serves catch-up. The same holds while a peer runs an incompatible build.
  It becomes eligible again when the clock agrees.
- In a two-node cluster each node has only the other to compare with, and the median lies halfway: if they disagree by more than
  10 s, both refuse. If every node's clock is wrong by the same amount they agree, and nothing notices.

## Cluster status

`/readyz` (unauthenticated) reports, ready or not, `{"status": "ready" | "unavailable", "cluster": {"size", "quorum",
"alive", "partitions_owned", "unconfirmed", "refused", "clock_skewed", "skew_refused", "clock_offset_ms",
"partitions_unreadable", "partitions_diverged"}}`: counts only; the reason for not being ready stays in the log and in
`GET /api/cluster`. `GET /api/cluster` (super administrators) returns the full status: node id, members, leader, ready
and why not (`reason`), writable, catching up / resyncing, the forced start, the counters (changes committed, refused,
unknown, unavailable; fresh reads and failed ones; partitions taken over; divergences found), the number of partitions
this node owns and of those it cannot read or that diverged, and for each of the 64 partitions its owner as this node
believes it, the owner's epoch counter, this node's committed sequence and promised epoch counter, whether this node can
read it (`readable`), how long it has trailed the owner (`lag_ms`), whether a catch-up runs (`catching_up`) and whether it
diverged here. The console's System page shows it to super administrators. **Metrics** (`/metrics`, with the metrics
token): `quisora_partitions_owned`, `quisora_partition_writes_total`, `_writes_refused_total`, `_writes_unknown_total`,
`_writes_unavailable_total`, `_reads_total`, `_reads_failed_total`, `_takeovers_total` (since the node started),
`quisora_partitions_unreadable`, `quisora_partitions_diverged`, `quisora_partition_divergences_total`, and per partition
(label `partition`) `quisora_partition_lag_seconds`, `quisora_partition_catching_up`, `quisora_partition_diverged`, next to
`quisora_ready`, `quisora_writable`, `quisora_leader`, `quisora_cluster_alive_nodes`, `quisora_cluster_size`.
The Docker `HEALTHCHECK` (`quisora healthcheck`) is a **liveness** probe (`/healthz`): a node that is catching up or cut off is
alive and must not be restarted for it. Point load balancers at `/readyz` (`quisora healthcheck --ready` checks it from the
host). The load shedder (`limits.max_in_flight`) never refuses `/healthz`, `/readyz`, discovery or JWKS.

## Operator procedures

Every refusal says why and what to do.

**A node was down, or cut off, for any time.** Start it (or heal the network). It catches up (by sequence, or by copying the
partitions whose history was purged meanwhile) and serves. Nothing else is needed.

**Replacing a node** (lost disk, new machine). Start the replacement with an empty database and the same `cluster.size` and
`cluster.peers`. It copies everything from the others and serves once it has copied from a majority of the other nodes
(both others of a three-node cluster); while another node is down as well, it waits in the resyncing state (see
`quisora force-start`). The old node's id is dead in gossip and is forgotten.

**Whole-cluster outage.** Start every node. They promise and catch up among themselves and each serves as soon as a majority is
up and it has been stable for a few seconds. No `force-start`.

**A database that lost its node id** (the data directory was not kept, the database was): the node refuses ("this database belongs
to node ..."): set `cluster.node_id` to the owner or keep its data directory. It wipes nothing.

**Two nodes impaired at once** (one down and another with a new disk, or two new nodes): the node that needs to hear from enough of
the others cannot: run `quisora force-start` on it and start it (below).

**Restoring a backup.** Restore into one node with an empty database (`quisora serve --restore-from`, or `quisora restore`):
its records become the first writes of their partitions, of a new data set. Start it, and start the others with empty databases
(before or after it): they adopt its data set and copy from it. A restore never goes over data, and never on a node that already
holds a data set (refused before anything is written). A restored (or bootstrapped) node that meets a cluster of another data set
exchanges nothing with it and refuses to serve ("another data set is in view"): start it with an empty database instead.

**Bootstrapping.** `quisora bootstrap --new-cluster` on one node of a new cluster, with an empty database. The others start with
empty databases, before or after it: until a node publishes a data set they wait ("no data set"), then they adopt it and copy from
it. A node that joins a cluster needs no bootstrap.

### Changing the cluster size

The size changes **one node at a time**: 3 → 4 → 5, or 7 → 6 → 5. Any majority of the old size and any majority of the new
one then share a node, and a new node can only join once the old nodes make a majority of the new size. A larger change is a
series of steps, each completed before the next. **Writes pause while the nodes disagree about the size** (a node ignores
messages from one configured differently), for as long as the reload takes on every node: seconds if every node reloads at
once; the partition protocol stops and starts again with the new size on each node (the data stays).

Each step edits every node's configuration, then has every node re-read it at once: **Reload configuration** on the admin
console's System page (Cluster), or `POST /api/cluster/reload` (super admin, after a recent re-authentication; audited as
`cluster.reload`). Every node in view first reads and checks its configuration; only if all of them can apply it and all name the
same `cluster.size` does each one apply it. Otherwise nothing changes, and the answer has each node's report. A node that is down
is not asked: it reads its configuration when it starts. SIGHUP reloads a single node the same way, but the nodes then disagree
on the size, and none of them writes until the last one has reloaded: reload every node, one after the other, quickly. Keys kept
in Vault or 1Password are read again by the same reload ([secret stores](secret-stores.md)). Nodes sharing a database (no gossip)
run the same two-phase reload over `cluster.notify`; without it each node reloads on its own (SIGHUP).

**Adding a node** (N → N+1):

1. Check that every node reports ready (`/readyz`).
2. On every running node set `cluster.size` to N+1 and add the new node to `cluster.peers`.
3. Reload. Every node now needs a majority of N+1 (3 of 4, 3 of 5); the N running nodes still make one. A reload is refused while
   too few nodes are in view for that.
4. Start the new node with an empty database and the same `cluster.size` and `cluster.peers`. It copies from the others (it needs
   enough of them that every majority includes one: `size − majority + 1`, so two of the three others in a 4-node cluster,
   three of the four in a 5-node one) and serves once it has.

**Removing a node** (N → N−1):

1. Check that every node reports ready (`/readyz`).
2. Stop the node that leaves. The others carry on with the old size, on their majority (N−1 is at least a majority of N for any N
   of 2 or more).
3. On every remaining node set `cluster.size` to N−1 and remove the node from `cluster.peers`.
4. Reload. A reload that would shrink the size is refused while more nodes than the new size are in view: stop the leaving node
   first. Retire its data directory; it must not rejoin (with its old configuration it would refuse anyway: its size disagrees).

A step of more than one node, a `cluster.peers` that does not name `cluster.size` nodes, or nodes whose configurations name
different sizes are refused before anything changes. A reload changes nothing when the sizes already match, so after a partial
reload (a node that did not answer) reload again.

**A partition diverged on a node** ("partition N diverged on this node": its copy holds writes the partition's owner does
not have, which only lost or wrongly restored data explains, here or on a majority elsewhere). The node serves nothing of
that partition and is not ready. Resync it: stop it, empty its database and start it again; it copies everything from the
others. Look for how its data came back (a snapshot restored in place, above).

**A node restored from its own snapshot** ("this node was restored from a snapshot of itself", or "its database is older
than its cluster state"): it resyncs by itself at that start; if it says it no longer takes part, restart it.

### `quisora force-start`

For a node whose data is not intact (a new disk, a restored database) when too few other nodes are up for it to copy from enough
of them that every majority includes one (both others of three): two of three impaired at once. It is the operator accepting that the cluster cannot tell
whether the node that is up holds every acknowledged write.

- Writes a marker file in the data directory; the **next start only** consumes it (the file is removed at start, whatever the
  outcome). That start treats the node's data as not intact whatever its state says, and resyncs from **whichever other nodes
  answer, even one**. A write that only the nodes it could not reach held is lost.
- It is **logged** at start, and written to the primary organization's **audit log** (`cluster.force_start`) as soon as the node
  is writable; until then it stays pending in the node's cluster state, across restarts.
- It is not needed after any restart, whole-cluster restarts included, nor to replace a node while the other nodes are up.

## Backups

`quisora backup` and `GET /api/backup` write every live record with its version, generation and origin. Where the backend offers a
point-in-time view (BadgerDB: one read transaction; SQLite, PostgreSQL, MySQL and MariaDB: one read-only repeatable-read
transaction) the backup is a **consistent snapshot**. A backup is encrypted with a password by default (AES-256-GCM in
authenticated chunks, the key derived from the password with argon2id; `--plain` writes it unencrypted, with secrets still sealed by
the master key): a truncated, reordered or altered file is refused before anything is restored. A remote download is checked for
completeness as it arrives. The remote download needs a super administrator's API token with the **`backup`** scope. Passwords,
the schedule and restoring: [RUNNING.md](RUNNING.md#backup-and-restore).

## Shared-database mode (no gossip)

Several nodes on one PostgreSQL, MySQL or MariaDB database: the database is the only copy, nothing is replicated, and
compare-and-swap is the database's own. Tombstones are kept for one hour. The nodes must use the same master key (a check value of it
is kept in the database). Nothing in this document but the service-level rules (the last-administrator guard, groups, sign-in
stamps) applies to it.

A **lease** in the database picks the node that runs housekeeping (key rotation, purge, user end dates): TTL 30 s, renewed every 10 s,
and a holder counts itself leader only until 10 s before its lease ends. Every takeover creates the lease record anew, so its creation
version is a **fencing token** unique to that tenure: housekeeping runs with it, and each housekeeping write (and each purge) first
checks that the lease record still names this node with that token. A node that lost the lease (paused, cut off from the database, or
with a clock so far off that it believes an expired lease is still its own) has its housekeeping writes refused instead of racing the
new holder's. Between that check and the write itself two housekeepers are harmless: key rotation at worst publishes a spare key, end
dates are compare-and-swap updates and purging is idempotent. Keep clock skew between the nodes well under 10 s.

## Known limits

- **A partition without a majority is unavailable** for writes and fresh reads; a lost owner takes about 3.5 seconds to replace
  (writes to its partitions wait for it, up to the 5 s write timeout, then fail with 503). A node stopped with `SIGTERM` hands over
  at once.
- **One write at a time per partition**: an organization's sign-ins and token grants all go through its one owner (audit
  events do not: they are each node's own). Several hundred writes a second per partition with a fast disk; a very busy organization is bounded by that.
- **A node whose data is not intact needs enough of the other nodes that every majority includes one of them** (`size − majority +
  1`) to copy from: both others of three, the other one of two, two of the three others of four, three of the four others of five.
  Use three or five nodes.
- **A write's outcome can be unknown** (`store.ErrUnconfirmed`, HTTP 503): the owner was lost or a reply timed out after the write
  was sent. The next owner settles it, committed once or never; callers re-read before they retry what is not idempotent.
- **Local reads are a message behind a write** made on another node, a heartbeat at the worst; `Store.Put` waits for the writer's own
  node, and the checks that must see the latest state read through the owner.
- **A global unique value** can stay reserved after a creation whose second write never happened, until the housekeeping
  leader's sweep releases it (the minute of grace plus the wait for the next pass; claims never take over a reservation
  whose holder their node does not have).
- **A data set is chosen by the operator.** A node with no data set adopts the one the nodes it sees publish; one bootstrapped
  or restored by mistake while it is the only node up with a data set is the one the empty nodes adopt. Nodes of different data
  sets never exchange data, but an empty node that sees two of them joins neither until one is gone: bootstrap one node of a new
  cluster only.
- **A node of another data set is still a gossip member**: the clock check and the routing of short-lived state see it (it is
  never ready, so nothing is routed to it). It never runs housekeeping: it owns no partition of the
  cluster's (the protocol ignores nodes of other data sets), so partition 0's owner is always a node of the cluster's data
  set.
- **Losing the data of a majority at once** (two disks of three) loses what only they held; restore from a backup.
- **Membership comes from the gossip library's failure detector**; a node that is alive but cannot exchange data still counts as in
  view for gossip (the partition protocol then refuses its writes rather than losing them).
- The retention (7 days) is fixed; it only decides how far behind a node may be to catch up without copying a partition whole.
- Two super admins removing each other at the same moment on different nodes can leave none (see "Super admins are protected by
  rank"): `quisora invite --break-glass --super-admin` recovers.
- A group change's sequence fence rests on the removed membership record being kept: a writer stalled for longer than 7 days
  (`model.RemovedMemberRetention`) could re-create a membership removed since, as any write that old could undo a purged tombstone. A
  membership a stalled writer materializes for a group or user deleted meanwhile is inert (readers resolve the group and user) but
  stays until its removal expires.
