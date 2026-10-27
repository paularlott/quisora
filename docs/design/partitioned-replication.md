# Partitioned replication for gossip mode (design draft)

Status: built. The protocol is in the gossip library (`partition` package) and Quisora's gossip mode runs on it; what runs
today, and how an operator uses it, is in [../REPLICATION.md](../REPLICATION.md). This document is the design it was built
from (revised after an adversarial review, whose findings are folded in; see "Review findings" at the end); where the
build chose something the design left open, REPLICATION.md says what.

## Why

Shared-database mode (one database server, Galera, or a primary with replicas) is functionally where we want it.
Gossip mode, where each node has its own database, is where the serious bugs keep coming from. Its write path is
leaderless: any node writes any record through a quorum compare-and-swap (prepare, commit, abort across a majority),
with HLC versions and last-writer-wins. That spreads consistency logic over every write, and the last review rounds
found bugs there (a quorum read reply larger than a
packet).

This design replaces the write path with a simpler model: **every record has exactly one node that writes it, and a
write becomes visible only once a majority has it**. It keeps gossip for membership and events, and leaves the
shared-database mode untouched.

## The model in one paragraph

Data is split into 64 partitions. Partition 0 holds the global data; each organization hashes to one of partitions 1
to 63. Every partition has one **owner** node, chosen by rendezvous hashing over the cluster's ready nodes. The owner
is the only node that writes the partition, one write at a time: each write gets the partition's next **sequence
number** and is sent to every node, and it is **committed** (applied, visible, answered) once a majority of the
cluster has stored it. Until then it sits in a one-entry **pending slot**, never in the visible data. Reads are local
on any node and see only committed data. When ownership moves, the new owner gets a majority to **promise** it the
partition, which fences the old owner and tells the new one about every write that may have been committed.

## Partitions

- **64 partitions, fixed.** Partition 0 is global data. An organization's records go to `1 + hash(orgID) mod 63`.
  The count is a constant of the format: changing it is a data migration.
- **Global data (partition 0):** organizations and their names, cluster-wide settings, signing keys, master key
  reports, and any value that must be unique across organizations (two: tenant resource indicators and passkey credential ids,
  held by reservations; see "Unique values must not cross partitions").
- **Org data:** users and their sign-in records, sessions, grants, groups, memberships, clients, tenants, providers,
  and everything else scoped to one organization, including the primary organization's super admins. Database audit
  events are not replicated: each node keeps its own (an audit page asks every node).
- A busy organization stays on one partition and one owner. Accepted: an owner commits hundreds of writes a second
  per partition (below), far more than one organization's sign-ins produce, and password hashing (the real CPU cost)
  stays on the node that took the request.

## Ownership

- **Rendezvous hashing:** the owner of partition `p` is the ready node with the highest `hash(p, nodeID)`, computed by
  every node from its own view of membership. When a node leaves or joins, only the partitions whose highest hash was
  or becomes that node move.
- **Ready nodes only:** a node is eligible to own partitions once it has caught up (below) and has passed a
  hold-down (slept once at start-up, after the catch-up). Readiness is gossiped in node metadata.
  Readiness gates **ownership only**: a node that is not ready but holds its data still promises, stores writes and
  serves catch-up, or a 3-node cluster could not write while one node restarts.
- **Owner heartbeats:** each owner tells every node, about once a second, which partitions it owns, at which epoch,
  and their committed sequence (one message per node, not per partition).
- **Stickiness:** a node refuses a promise for `p` while it has heard from `p`'s current owner within the owner
  timeout (a few heartbeats). A node whose view says it should own `p` waits a randomised backoff before proposing,
  and again after being superseded. Together these stop two nodes that can each reach a majority, but not each other,
  from taking a partition back and forth for as long as the network is asymmetric.
- **Views can disagree.** Rendezvous hashing only decides who **tries** to own a partition. Safety comes from the
  rules below, which make it impossible for two owners to both commit writes; disagreement costs refused writes on
  the partitions involved, never a lost or conflicting write.

## State per partition, on every node (durable)

- `promised`: the highest epoch it has promised. An epoch is (counter, node ID), ordered by counter then node ID, so
  two nodes never choose the same one.
- `committed`: the (epoch, sequence) of the last committed write it has applied. Its visible records are exactly the
  committed writes up to that point.
- **Counters never wrap.** The sequence is a 64-bit counter per partition that never resets, across epochs included;
  the epoch counter is 64-bit too. At a million writes a second a sequence lasts about 580,000 years. The code refuses
  a write (or a promise) at the maximum rather than wrap, so wrapping cannot happen even in a corrupted state.
- `pending`: at most one write it has stored but not yet seen committed: (epoch, sequence, the records it changes).
- the cluster size it runs with (below), carried in every message of the protocol.

Each record keeps an HLC timestamp too, for tombstone age and display only: order comes from (epoch, sequence), never
from clocks.

## Taking ownership

A node whose view makes it the owner of `p`, after its backoff:

1. Picks `e = (highest counter it has seen for p + 1, own ID)` and records `promised = e` durably before counting
   itself.
2. Sends `Promise(p, e)` to every node. A node whose `promised < e`, and that has not heard from a live owner of `p`
   within the owner timeout, records `promised = e` durably and answers with its `committed` and its `pending`. Any
   other node refuses, and every answer, refusal or not, carries the responder's `promised`. A proposer that is refused
   raises its "highest counter seen" to match, backs off, and may try again higher.
3. Once a **majority** of the cluster (itself included) has promised, it settles the partition:
   - it brings itself up to the highest `committed` among the promisers (catch-up below);
   - of the promisers' `pending` writes beyond that point, it takes the one with the highest epoch, if any, and
     commits it again under `e` as its first write. That write may have been committed by the old owner (a majority
     stored it before the old owner died); re-committing it is the only safe choice and is harmless if it was not.
   This is the rule of Paxos and Raft for a value that may have been chosen.
4. Only then does it accept writes for `p`. Writes that reach it during steps 1 to 3 wait, up to the library's write
   timeout (5 s), then fail.

## The write path

1. **The landing node does the work that does not need the owner:** it parses the request, checks the password
   (argon2), and builds the change. It sends the change for partition `p` to the owner it believes in. A node that
   gets a change for a partition it does not own answers with the owner and epoch it believes in, and the landing
   node retries there once; no node forwards a forward.
2. **The owner checks the change against its committed state.** A change carries the expected version of every record
   its decision depended on (not only those it writes): the landing node read them locally, possibly a moment stale,
   and the owner refuses the change if any has moved since. Checks that must not run on stale data (an account
   disabled, an organization deleted) are made by the owner itself as part of the change.
   Unique values within the partition are checked here too.
3. **The owner writes one change at a time per partition.** It confirms its own `promised` is still its epoch, assigns
   the next sequence, and sends `Write(p, e, seq, records, committed)` to every node, `committed` being its own commit
   point (so followers learn what is committed). A follower accepts when `promised <= e` (raising `promised` to `e`),
   its `committed` is the write's predecessor, and it stores the write as its `pending` durably (fsync). Its previous
   `pending`, if any, is now known committed (the owner would not send the next write otherwise) and is applied first.
   A follower whose `committed` is behind catches up from the owner, then accepts; one whose `pending` is from an
   older epoch drops it (that write was not committed under this owner: step 3 of taking ownership settled it).
4. **Once a majority has stored it, the write is committed:** the owner applies it to its visible records, answers,
   and moves to the next change. Followers apply it when the next write, or the next heartbeat, tells them it is
   committed.
5. **Not built: followers acknowledging to the landing node too.** The first draft had every follower acknowledge to the
   landing node as well as to the owner, so that a forwarded write would commit in one round trip as the landing node
   sees it. The build does not: the owner is told by a majority, answers the landing node once it has committed, and the
   landing node then waits until it has applied the write itself (the owner's commit notice, one message after the
   commit) so that it reads its own write. A write that lands on a follower therefore costs one more hop than one that
   lands on the owner. Nothing in the protocol depends on the difference; it is a latency that was not worth a second
   acknowledgement path.

**Why the landing node does not write to the other nodes itself:** two landing nodes would then claim the same
sequence at the same time, which is today's leaderless quorum compare-and-swap and its conflicts again. The owner is
what puts a partition's writes in one order.

Outcomes the caller sees: **done** (committed), **refused** (an expected version moved, or a check failed: nothing
written), or **unknown** (a timeout, or the owner lost mid-write: the write may be re-committed by the next owner, or
not). The last is the same as a lost reply from a database server today.

**Serialised, so simple:** with one write in flight per partition, a follower holds at most one pending write, and
"which writes may be committed" is always one write. Throughput per partition is one write per round trip and fsync
(several hundred a second on a LAN), times 64 partitions. If that ever limits, one write can carry a batch of changes
(group commit) without changing any rule. Neither is built: a write carries one change (one record), and **pipelining**
(several writes in flight per partition) was never designed: the one pending write a follower holds, and the settling
of "which write may have been committed" at a takeover, rest on there being one.

**Cross-partition changes** (creating an organization writes the organization in partition 0 and its first
administrator in its own partition) have no transaction across partitions: each is a sequence of single-partition
writes, ordered so that a crash between them leaves something harmless and repeatable, as today. The inventory is in
the build ("Implementation in Quisora" and docs/REPLICATION.md): creating an organization, global unique values (claim, write, release) and deleting an organization (one write;
the rest is the orphan sweep).

## Reads

- **Most reads are local**, on whichever node took the request, and see only committed data: listing users, loading a
  client, checking a session or an API token. They lag the owner by the time until the follower learns of the commit
  (the next write or heartbeat: about a second at most).
- **Reads that must see the latest state happen in the owner's change** (step 2 of the write path): redeeming an
  authorization code or a one-time link, rotating a refresh token, counting a failed password. An owner replaced without knowing it cannot commit (the nodes promised a newer epoch), so nothing stale is
  acted on.
- **Bounded staleness:** a node that has not heard from `p`'s owner within the owner timeout, and cannot see a
  majority, stops serving `p`'s reads (as today's cluster stops serving past its downtime bound). A node cut off from
  the cluster does not serve revoked sessions or disabled accounts for longer than that.
- **Hot records:** a failed password updates the user's sign-in record, not the user, so concurrent sign-ins do not
  make each other's changes fail on the user's expected version.

## Catching up, joining and returning

- **Catch-up is by sequence, per partition, of committed writes only.** A node asks for the committed writes of `p`
  after its own `committed`. Committed writes are the same on every node that has them, in the same order, so any node
  is a safe source up to its own commit point; nobody ever serves a pending write as data. The owner is the preferred
  source; a node whose promise is newer than a stream's source drops the stream.
- **This needs a per-partition sequence index,** which is new: today's change feed is per node, not per partition.
- **Tombstones and their purge are writes of the partition.** The owner purges old tombstones with a committed write
  ("purge before sequence N"), so every node purges the same ones at the same point, whatever its clock. A node whose
  `committed` is below a partition's purge point cannot catch up by sequence and copies the partition whole.
- **Any node with data serves catch-up**, ready or not, so a whole-cluster restart can always proceed.
- **A node that lost its data** (a new disk, a restore) must not promise or store writes until it has caught up every
  partition from a majority of the **other** nodes, and its `promised` is raised to the highest they report. A node
  that forgot its promises could otherwise help a lower epoch win. With the other nodes up this is automatic; only when
  too few are left to make a majority without it (two of three impaired) does it need an operator (see the table
  below).

## What keeps working, without an operator

With 3 nodes (with 5, read "up to two"):

| Situation | What happens |
| --- | --- |
| One node down | The other two are a majority: they take over its partitions and keep writing and serving. |
| It returns with its data | It catches up by sequence and rejoins on its own. |
| It returns with its data lost (a new disk) | It copies from the other two and rejoins on its own. |
| It was away longer than tombstones are kept | It copies the partitions it cannot catch up by sequence, on its own. |
| Every node restarts | They promise and catch up among themselves: no `force-start` (today one is needed). |
| Two nodes impaired at once (one down, another lost its data) | The survivor cannot know whether it misses committed writes: an operator accepts that with `quisora force-start`. |

## Cluster size

- **Majorities are of the configured cluster size,** never of the nodes visible: a majority of what each side of a
  split can see would let both sides write. With 3 nodes the cluster writes while any 2 are up; with 5, while any 3 are.
- **The size is part of the protocol:** it is gossiped, carried in every promise and write, and a node refuses either
  from a node configured with a different size. Two nodes that disagree about the size never form a majority together.
- **Changing the size** (3 to 5, say) needs every old majority to overlap every new one throughout the change. It is
  done one node at a time (3 to 4 to 5): any majority of the old size and any majority of the new one then share a node.
  The procedure, with the reload that makes every node change at once, is in docs/REPLICATION.md ("Changing the cluster
  size"); writes pause while the sizes disagree.

## The gossip library package

Nothing in the protocol is Quisora-specific, so it goes in the gossip library as a new package (working name
`partition`), beside `lock` and `kv` (and the `leader` election package, which Quisora no longer uses), changing nothing existing.

It provides: `Owner(p)`, `IsOwner(p)`, ownership events and readiness; `Write(ctx, p, change)`, which routes to the
owner, runs the change's check there, commits it and returns done, refused or unknown; and the promise, heartbeat,
write, commit and catch-up protocol.

The application implements a small interface: check and apply a change against its committed state; store and load
the per-partition `promised`, `committed` and `pending`; stream committed writes of a partition after a sequence, and
take such a stream; copy a partition whole.

An example application (a partitioned key-value store, in `examples/`) shows the use and is what the fault tests
drive.

## In Quisora

- **Stays:** gossip membership, events and notices; tombstones; the shared-database mode.
- **Goes:** the quorum compare-and-swap write path (prepare, commit, abort, intents), quorum reads, the pooled small
  read, anti-entropy pulls, HLC last-writer-wins between nodes, and the conflict resolution of two nodes writing one
  record.
- **New:** a per-partition sequence index and the per-partition protocol state in each store backend that gossip mode
  uses (BadgerDB, SQLite, and the others when they run node-local).
- **Changes:** the cluster store sends changes through `partition.Write`; fresh reads move into owner-side checks;
  housekeeping becomes per partition on its owner (purges are writes of the partition anyway); ephemeral state (rate
  limits, counters), already routed to an owner by hash, can use partition ownership so there is one notion of owner.

## Testing to destruction (the gate)

Built and tested in the gossip library first; Quisora moves to it only if this holds.

- **A fault-injecting transport:** drop, delay, duplicate and reorder messages between chosen nodes; one-way cuts
  (asymmetric reachability); splits into two sides; heal.
- **Node faults:** kill a node mid-write, mid-promise and mid-catch-up; restart it with its data; restart it with its
  data lost.
- **Clock faults:** skew a node's clock forward and back (order no longer depends on clocks; tombstone age still
  does).
- **Scenarios,** including every sequence in the review: an owner dies after a minority stored a write; an owner is
  cut off and keeps trying; two nodes believe they own one partition; asymmetric reachability between two candidates;
  a node returns with a pending write from an old epoch; a node returns with its data lost while another is down; all
  nodes restart; a node joins empty; nodes configured with different sizes.
- **Invariants checked after every run:**
  1. no committed write is lost: every write answered "done" is present, in order, on every node after healing;
  2. per partition and sequence, at most one write is ever committed, and every node that applied a sequence applied
     the same write;
  3. after healing, every node holds the same committed records;
  4. a change sees every write committed before it (a read through a change is never stale);
  5. no node serves a partition's reads past the staleness bound while cut off.
- **Randomised soak runs:** random changes and random faults for minutes, then heal and check, with the seed printed
  so any failure replays.
- **Real network:** the example on 3 and 5 machines with delay and loss added (tc netem).

## Performance

- **Writes:** one round trip and an fsync as the landing node sees it when it is the owner, and one hop more when it
  is not (step 5 of the write path was not built). The write it replaced was a prepare round and a commit round, plus
  retries when two writers collided; there are no collisions here.
- **Reads:** local, as today, lagging by up to a heartbeat. The fresh reads that were quorum reads move into the
  owner's change.
- **Ownership changes** cost one promise round, a catch-up and at most one re-committed write per moved partition, and
  refuse that partition's writes for that time (a few seconds, plus backoff).

## Open items of the draft, and where they were settled

1. *The inventory of global data and of values unique across organizations:* partition 0 holds organizations, signing
   keys and the like; two values are global (`model.GlobalUnique`) and held by reservations ("Unique values must not
   cross partitions").
2. *The inventory of changes that span partitions:* in the build; docs/REPLICATION.md says each one's order and what a
   crash between its writes leaves.
3. *Changing the cluster size:* one node at a time, with a reload that applies it on every node together
   (docs/REPLICATION.md, "Changing the cluster size").
4. *How long a write waits for an ownership change:* the library's write timeout, 5 s.
5. *The owner timeout, heartbeat interval, backoff and staleness bound:* a heartbeat every 500 ms, an owner timeout of
   three heartbeats, a rank delay of 1 s and a random backoff of up to 1.5 s (a takeover about 3.5 s after a crash), and
   a node that cannot see a majority stops being ready at once and serves nothing (the token endpoints included).

## Plan (done)

1. Settle this document.
2. Build the `partition` package and the fault-injecting test transport in the gossip library, with the example
   application.
3. Test it to destruction (above).
4. Move Quisora's gossip mode onto it, then remove the quorum compare-and-swap code.

## Review findings (and where they went)

An adversarial review of the first draft found:

1. **Uncommitted writes indistinguishable from committed ones** (records ordered by HLC, no epoch): a write stored on a
   minority could survive an ownership change and become authoritative, or leave a node diverged or unable to accept
   writes. Fixed by (epoch, sequence) order, commit-before-visible, one write in flight per partition, and the pending
   slot settled at takeover.
2. **Promises not restored after data loss, nor raised by accepted writes,** so a lower epoch could win a majority.
   Fixed: every answer carries `promised`, accepting a write raises it, a restored node adopts the highest reported.
3. **Catch-up not fenced by epoch.** Fixed: only committed writes are ever streamed, and a stream from a source older
   than the node's promise is dropped.
4. **Duelling owners under asymmetric reachability.** Fixed by heartbeats, stickiness and randomised backoff.
5. **Cluster size taken from each node's own configuration.** Fixed: the size is carried in the protocol and checked.
6. **A cut-off node serving local reads indefinitely.** Fixed by the staleness bound.
7. **Readiness traps** (whole-cluster restart; a node that lost its data with another down). Fixed: readiness gates
   ownership only, any node with data serves catch-up; the data-loss case is stated with its operator path.
8. **An invariant a benign race would trip.** Restated around committed writes.
9. **Under-specified points** (refusal contents, an owner checking its own promise, pipelining, a follower ahead,
   unbounded witnessing, the feed being per node, version ties, forwarding loops, readiness and promising, tombstone
   purge clocks). Each is now pinned down above.
10. **Landing-node decisions on stale reads.** Fixed: changes carry the expected version of everything they depended
    on, and checks that must be fresh run on the owner; failed sign-ins update the separate sign-in record.

## Implementation in Quisora (build plan)

The protocol is built and tested in the gossip library (`github.com/paularlott/gossip/partition`, with its own
DESIGN.md and README). This section says how Quisora's gossip mode moves onto it. Shared-database mode and standalone
are untouched. Pre-release: no data migration; a store written by the old gossip mode is refused at start (wipe it).

### Partition key of a record

- `model.Index` gains `Partition string`, the record's partition key, and `store.Record` carries it (so replicated
  and exported records keep it). Rules:
  - organization data (every entity with an `OrgID`): the organization's ID, so an organization's records, and every
    unique value scoped to it, live in one partition;
  - `KindOrg` and `KindKey` (signing keys), and anything else that is global by nature: "" (partition 0);
  - kinds with no organization whose records are independent (`KindReplay`, `KindLock`): the record's own ID, so they
    spread over the partitions instead of loading partition 0 (a lock or a replay value is a compare-and-swap on one
    record: its partition does not matter as long as it is always the same).
- Partition number: 0 for "", else `partition.PartitionOf(key, 64)`.
- A record never changes partition (its organization never changes).

### Unique values must not cross partitions

The owner checks unique values in its partition only, and a follower applying a committed write must never hit a
unique conflict with another partition's record (it would diverge). Every unique value is therefore either prefixed
by the organization (users, groups, tenant names, providers: already so) or lives in partition 0. Two are global today
and must change:

- **Global unique values** (two today: tenant resource identifiers, `TenantResourceKey` `res/<uri>`; and passkey
  credential IDs, `PasskeyCredentialKey`, which must stay global because a discoverable passkey sign-in from the
  landing page looks the credential up with no organization): handled by one mechanism in the cluster store, so the
  service does not change. `model` declares which unique keys are global. In gossip mode such a value is claimed
  through a **reservation record** (a new kind; ID = the unique key; partition = a hash of the key, so the load
  spreads; data = the kind and ID of the record holding it), created with a compare-and-swap on its owner before the
  record is written; the record itself is written without that value in its unique list. `GetByUnique` for a global
  key reads the reservation, then the record it names. A reservation whose record no longer exists or no longer holds
  the value (a crash between the two writes, or a deleted record) is free: the next claim takes it over when the owner's own
  copy of the holder is a tombstone or a live record that does not list the value, written after the reservation (a holder
  the owner does not have, or has only from before the reservation, is no evidence: its copy may lag), and the
  housekeeping leader's sweep releases the rest after reading the holder through its own partition's owner; deleting or
  changing the record releases its reservation afterwards.
- `IdentityKey` (provider ID + subject: the provider belongs to one organization) and `LinkTokenKey` (a random hash)
  are safe; confirm, and check every other `Unique:` in the model the same way.

### The cluster store in gossip mode

- `cluster.Store.Put` / `CompareAndPut` (every kind, not only `model.QuorumCAS` kinds) become `partition.Write` on the
  record's partition. The change is the encoded record with its mode (upsert or match) and expected version; the
  owner's `Store.Prepare` stamps the version (the owner's HLC, as today's stamp does), checks the compare-and-swap and
  the partition's unique values against its committed data, and returns the record to write as the write's data and
  its new version as the reply. Deletes are tombstone writes, as today.
- `partition.Store` is implemented over the node's inner store (BadgerDB, SQLite, or another backend running
  node-local) per the package README's "A Store on a database": a per-partition state row (promised, committed,
  pending) in the same database; `Commit` applies the write's records and the committed position in one transaction
  (unsynced where the database allows it: SQLite, PostgreSQL; not built for Badger); `SetPromised`/`SetPending` synced; `State` from memory; each record stamped with the `Seq` of
  the write that last changed it, indexed per partition, which `Export(p, after)` selects on; tombstones carry their
  `Seq`. This needs a small addition to each node-local backend: a transactional "apply these records and set this
  partition state" call and a per-partition seq index. Shared-database backends do not need it (that mode does not use
  partitions), but the interface may be implemented generically if simpler.
- `Fresh(kind, ids)` (the service's fresh reads, `store.QuorumReader`) reads on the owner: the ids are grouped by
  partition (from this node's copy of each record: its partition key never changes; an id this node does not hold is
  asked of every partition's owner), and each group is read with the library's owner read (below).
- Hooks: `OnChange` fires for records applied by `Commit` and `Import` (local or replicated alike), so caches are
  evicted on every node as today.
- `ErrUnavailable` from the library maps to the store's "not writable / not confirmed" errors the service already
  handles; `ErrUnknown` likewise to "not confirmed"; `RefusedError` codes map to `store.ErrStale`, `ErrConflict`,
  `ErrDeleted` and `ErrNotFound` as the inner store would have returned them.

### What goes, what stays

- **Goes** (gossip mode only): the quorum compare-and-swap (`cas.go`: prepare, commit, abort, intents, votes), quorum
  reads and the pooled small read, the per-node change feed pulls and anti-entropy (`sync.go`), the maxDowntime /
  sync-point machinery and its start-up refusals (replaced by the library's resync), the unique-clash resolution of
  two nodes writing one value (`OnConflict`, `ResolveUniqueClash`) for gossip mode.
- **Stays:** gossip membership, notices and the cluster key; the node-local audit log of the database audit mode (each
  node writes its own events locally, never through a partition, and an audit page asks every node of the data set and
  merges: `AuditQuery`); the ephemeral store (hash-routed owners, already
  separate); housekeeping, which now runs on the owner of partition 0 (fenced by its epoch; the separate gossip leader election is gone; its writes go through partitions like any other); `force-start` (now:
  a node whose disk was lost while too few others are up resyncs from the nodes there are, an operator's decision);
  `cluster.size` (the library's ClusterSize; SIGHUP resize restarts the partition manager with the new size, and the
  docs give the procedure: change every node, one at a time, accepting that writes pause while the sizes disagree).
- **Configuration:** the gossip cluster runs with `NumIncomingWorkers = 32` and `NumSendWorkers = 16`.

### Testing and acceptance

- Every existing test passes on every backend (`task test-all`), with the gossip-mode cluster tests rewritten where
  they tested removed machinery, and the review regression tests kept where their behaviour still applies.
- Gossip-mode cluster tests over the library's fault scenarios: owner crash, split, a node returning with an old
  pending write, a lost disk, whole-cluster restart; with Quisora's real store backends (BadgerDB, SQLite).
- Performance at the target scale (5,000 organizations × 1,000 users, 3 nodes, BadgerDB), against the current build
  as a baseline: seeding, sign-in and token throughput and latency (p50/p99), replication lag (write on one node,
  visible on another), takeover time after an owner crash, memory and disk per node.
- A compliance and security review of the change: SOC 2 controls (audit events of every change still recorded; the
  cluster's message authentication and encryption cover the new messages; no new unauthenticated surface), the
  REPLICATION, RUNNING, SECURITY and SOC2 docs updated, and the README.
