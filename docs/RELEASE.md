# Releasing

## Before the first release

- **Freeze the data format.** Until the first release, stores, backups and the cluster state are wiped between builds
  ([RUNNING.md](RUNNING.md#changing-a-stored-format-for-developers)). From the first release on, every format change
  needs a migration, a backup upgrade or a raised `compat`, as that section describes.
- **An independent penetration test** of the release candidate.
- **A load test of a gossip cluster** of 3 and of 5 nodes on separate machines, across real network latency
  (`tools/loadtest`, see [RUNNING.md](RUNNING.md)). This measures quorum write latency, the counter cache and anti-entropy
  outside a single machine.

## Every release

- **The OpenID conformance suite**, run on the release commit, with the results recorded in
  [conformance.md](conformance.md).
- **The full test suite** on every storage backend, with the race detector: `task test-all`. Also run the
  accessibility and keyboard tests with `task test-ui`.
- **Coverage** at or above the floor in `scripts/coverage-floor`: `task cover`.
- **A flaky test to watch:** `TestReplacedDatabaseRefusedUnlessForced` (`internal/cluster`) failed once with every
  database server under heavy load. It checks four conditions with fixed sleeps, and under load the forced node's
  refusal can come late. A failure there on a loaded CI runner is most likely that; run it again on its own.
