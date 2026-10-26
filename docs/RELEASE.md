# Releasing

## Before the first release

- **Freeze the data format.** Until the first release, stores, backups and the cluster state are wiped between builds
  ([RUNNING.md](RUNNING.md#changing-a-stored-format-for-developers)). From the first release on, every format change
  needs a migration, a backup upgrade or a raised `compat`, as that section describes.
- **An independent penetration test** of the release candidate.
- **A load test of a gossip cluster** of 3 and of 5 nodes on separate machines, across real network latency
  (`tools/loadtest`, see [RUNNING.md](RUNNING.md)). This measures write latency (landing on the owner and not), takeover time after an owner crash,
  catch-up of a node and replication lag (a write on one node, visible on another) outside a single machine; and the
  figures in the sizing section of RUNNING.md that were measured on the build before the partition protocol.

## Every release

- **The OpenID conformance suite**, run on the release commit, with the results recorded in
  [conformance.md](conformance.md).
- **The full test suite** on every storage backend, with the race detector: `task test-all`. Also run the
  accessibility and keyboard tests with `task test-ui`.
- **Coverage** at or above the floor in `scripts/coverage-floor`: `task cover`.
- **Timing in the cluster tests:** they run real clusters on one machine with shortened heartbeats and timeouts. On a heavily
  loaded runner (every database server and the race detector at once) a takeover can take longer than a test waits; run a
  failing `internal/cluster` test again on its own before treating it as a bug.
