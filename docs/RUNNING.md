# Running Quisora

How to run Quisora on each storage backend, alone or as a cluster, with or without VictoriaLogs. The replication rules
and the cluster recovery procedures are in [REPLICATION.md](REPLICATION.md).

## Settings

Every setting is a flag, an `QUISORA_*` environment variable or a key in a TOML file; a flag beats the environment,
which beats the file. The public URL, for example, is `--public-url`, `QUISORA_PUBLIC_URL` or `server.public_url`.

- The file is `--config` (`QUISORA_CONFIG`), else `quisora.toml` in the current directory, `~/.config/quisora/` or
  `/etc/quisora/`. Unknown keys are refused.
- `quisora serve --help` lists every setting with its variable and key; [quisora.toml.example](../quisora.toml.example) is
  an annotated file.
- `quisora genkey` prints a key for `server.master_key` and `cluster.key`.

Settings every deployment sets:

| Setting                             | Flag                      | Notes                                                                                                                                                              |
| ----------------------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `server.public_url`                 | `--public-url`            | The issuer and the address users reach. https only.                                                                                                                |
| `server.listen`                     | `--listen`                | Default `:8443`. HTTPS only; there is no plain-HTTP listener.                                                                                                      |
| `server.data_dir`                   | `--data-dir`              | Node id, TLS files, cluster state, and the BadgerDB/SQLite store.                                                                                                  |
| `server.master_key`                 | `--master-key`            | Seals secrets at rest. Required in a cluster (identical on every node); a standalone node generates `<data-dir>/master.key` when unset. Keep it with your backups. |
| `server.tls_cert`, `server.tls_key` | `--tls-cert`, `--tls-key` | PEM files. Without them a self-signed certificate is generated in `<data-dir>/tls`.                                                                                |

## First start

`quisora serve` never creates anything. Set a new server up once with `quisora bootstrap`:

```bash
quisora bootstrap --data-dir /var/lib/quisora --public-url https://id.example.com
quisora serve --data-dir /var/lib/quisora --public-url https://id.example.com
```

- `bootstrap` creates the `primary` organization (second factor required) and a super admin without a password,
  `server.bootstrap_admin` (default `admin@example.com`).
- It prints a single-use invitation link (7 days). Open it, set a password or create a passkey, then a second factor.
- A second run changes nothing. `quisora invite primary admin@example.com` issues a new link (on BadgerDB and SQLite stop
  the server first; on a shared database it works while the server runs).
- Until the server is set up, `/readyz` reports not ready.

## Signing keys

Tokens are signed with ES256 by default (`tokens.signing_alg`; `EdDSA` is a little faster where every relying party
supports it). A new key is made every `tokens.key_rotation_days` (30 by default; 0 rotates by hand only) by the
housekeeping leader. It is published in the JWKS at once and signs 15 minutes later, so relying parties already know
it; the previous key stays published until the tokens it signed have expired, then it is removed.

Super admins see the keys under **Signing keys** in the primary organization's admin pages: each key's state
(signing, next, previous) and when it starts signing, stops and is removed. **Rotate now** makes a key that signs at
once (when a key may have been exposed); tokens signed before keep working until they expire. The same is
`GET /api/v1/keys` and `POST /api/v1/keys/rotate`.

## Changing the primary organization

The primary organization is the one super admins belong to. To make another organization primary:

```bash
quisora set-primary acme --super-admin alice@acme.example
```

- `alice@acme.example` (a user of `acme`) becomes its super admin; the previous primary organization's super admins
  become administrators of that organization. The change is audited in both.
- On a shared database it works while the servers run; they follow within seconds. On BadgerDB or SQLite stop the
  server first. In a gossip cluster stop one node, run it there and start the node again: the others receive the
  change from it.

## Storage backends

Pick one with `storage.backend` (`--storage`). The tables or keys are created on first start; the database itself
must exist.

| Backend            | Use                                                            | Settings                                                                                         |
| ------------------ | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `badgerdb` (default) | One node, or each node of a gossip cluster. Embedded.          | `storage.badgerdb.path` (default `<data-dir>/badgerdb`), `storage.badgerdb.sync_writes` (default true) |
| `sqlite`           | One node, or each node of a gossip cluster. Embedded, pure Go. | `storage.sqlite.path` (default `<data-dir>/quisora.db`)                                            |
| `postgres`         | A shared database for several nodes, or one node.              | `storage.postgres.dsn`, `max_open_conns`, `max_idle_conns`                                       |
| `mysql`, `mariadb` | As PostgreSQL.                                                 | `storage.mysql.dsn` / `storage.mariadb.dsn`, connection limits                                   |
| `valkey`           | As PostgreSQL.                                                 | `storage.valkey.addrs`, `username`, `password`, `db`, `key_prefix`, `tls`                        |

```bash
# PostgreSQL
quisora serve --storage postgres --postgres-dsn 'postgres://quisora:secret@db:5432/quisora?sslmode=require'

# MySQL / MariaDB (the collation is set by Quisora)
quisora serve --storage mysql --mysql-dsn 'quisora:secret@tcp(db:3306)/quisora'
quisora serve --storage mariadb --mariadb-dsn 'quisora:secret@tcp(db:3306)/quisora'

# Valkey
quisora serve --storage valkey --valkey-addrs valkey:6379 --valkey-password secret --valkey-key-prefix quisora:

# SQLite
quisora serve --storage sqlite --sqlite-path /var/lib/quisora/quisora.db
```

Every backend passes the same store conformance suite. BadgerDB is the fastest; see [Sizing](#sizing).

## Clustering

Two modes. Do not mix them.

### Shared database (no gossip)

Several nodes on one PostgreSQL, MySQL, MariaDB or Valkey database, which is the only copy. Leave `cluster.bind`
empty.

- Short-lived sign-in state (codes, sign-in steps, rate limits) lives in the database too: any node serves any
  request, and the load balancer needs no sticky sessions.
- A lease in the database picks the node that runs housekeeping (key rotation, purges, user end dates).
- A change made on one node applies on the others within 5 seconds (caches).
- Every node has the same `server.master_key`. A node with a different key refuses to start.
- High availability is the database's: run it as your own HA cluster.

```bash
quisora serve --public-url https://id.example.com --master-key "$KEY" \
  --storage postgres --postgres-dsn 'postgres://quisora:secret@db:5432/quisora'
```

Run `quisora bootstrap` once, against the database, before the first node starts.

### Replicated (gossip)

Every node has its own database (BadgerDB is the usual choice) and the nodes replicate every write.

```toml
[server]
public_url = "https://id.example.com"
master_key = "…"          # identical on every node

[cluster]
bind = "0.0.0.0:7946"
advertise = "10.0.0.11:7946"
peers = ["10.0.0.11:7946", "10.0.0.12:7946", "10.0.0.13:7946"]   # every node lists every node
size = 3                  # required, identical on every node; quorum = size/2+1
key = "…"                 # quisora genkey, identical on every node
```

- **Quorum.** It is fixed by `cluster.size` and never shrinks. Three nodes tolerate one down.
- **Starting.** A node serves only `/healthz` and `/readyz` until it has caught up with the cluster.
- **Without a quorum** a node makes no replicated write. The token, userinfo and introspection endpoints keep answering
  for `cluster.minority_grace` (300 s).
- **Security-sensitive records** (users, credentials, clients, providers, organizations, tenants, access, memberships)
  are quorum compare-and-swaps: a change made from an outdated copy fails instead of overwriting.
- **Short-lived state** stays on the node that made it; the others forward to it.
- **Each node keeps its id** in its data directory (or set `cluster.node_id`). Keep the data directory with the
  database. A node that finds another node's database, or one shared with another node, refuses to serve. It never
  wipes it.
- **Clocks** must be synchronised (NTP).

New cluster:

1. `quisora bootstrap --new-cluster` on one node, before any node starts.
2. Start every node. The others start with empty databases and copy from the first.

Replacing a node: start the replacement with an empty database and the same configuration. It copies everything.

Changing the size: stop every node, set the new `cluster.size` and `cluster.peers` everywhere, start the nodes that
hold data, then the new ones.

**Long outages.** Deletions are kept as tombstones for seven days. A node that has not synced with a majority for six
days, or whose data is of unknown age, stops or refuses to start, and keeps its data:

- If the others hold the data, start it with an empty database. It copies everything.
- After a whole-cluster outage every node refuses. Run `quisora force-start` on the node with the newest data and start
  it (one start only, audited), then start the others with empty databases.

Every procedure and what each refusal means: [REPLICATION.md](REPLICATION.md#operator-procedures).

## Audit log

Every audit event is written to the structured log (`log.format = "json"` for log shippers). The admin console's audit
pages read it from one of two places:

|                           | Database (default)                                                                            | VictoriaLogs                                  |
| ------------------------- | --------------------------------------------------------------------------------------------- | --------------------------------------------- |
| For                       | Development, home labs, testing                                                               | Production; required for SOC 2                |
| Kept                      | `audit.retention_days` (7)                                                                    | VictoriaLogs' `-retentionPeriod`              |
| One node, shared database | In the database                                                                               | Sent to VictoriaLogs; nothing in the database |
| Gossip cluster            | Each node keeps its own; a page asks every node and merges, and says if a node did not answer | Every node sends; any node reads              |

Admins see their own organization's events. Super admins also see every organization (`/admin/audit`,
`GET /api/v1/audit?org=<name>`).

**Production, and any deployment that needs SOC 2, must use VictoriaLogs.** The database audit trail keeps events for
days, not the year or more an audit period needs; in a gossip cluster each node holds only its own slice, so a lost
node loses its events; and it has no protection against someone with write access to the database. With
VictoriaLogs:

- set its retention to cover the audit period (`-retentionPeriod=1y` or more), and restrict who can delete there;
- turn on the spool (below) on every node;
- ship Quisora's structured log too, and alert on `audit.undelivered`: each such line is an event VictoriaLogs will
  never receive, logged in full so it can still be captured from the log.

### With VictoriaLogs

```bash
docker run -d --name victorialogs -p 9428:9428 -v vldata:/victoria-logs-data \
  victoriametrics/victoria-logs -retentionPeriod=1y
```

```toml
[audit]
victorialogs_url = "http://victorialogs:9428"   # user:password@ in the URL is sent as basic authentication
```

- Every node sends events in batches, and so do `bootstrap` and `invite`. A sign-in never waits for VictoriaLogs:
  events are queued and sent in the background.
- Without a spool, a batch VictoriaLogs does not take is retried a few times and then given up; so is an event that
  finds the queue full.
- An event VictoriaLogs will never receive is written to the structured log in full, at error level, with the message
  `audit.undelivered`, a `reason`, and the event under `event` (the same fields VictoriaLogs would have stored). That
  is the last place it goes: ship the structured log, or such events are lost.

### Spool

```toml
[audit]
victorialogs_spool_dir = "/var/lib/quisora/audit-spool"
victorialogs_spool_max_mb = 256          # default 256
```

With a spool, a batch VictoriaLogs does not take (unreachable, or answering an error) is written to disk at once, and
sent when VictoriaLogs answers again, oldest first; a restart keeps it. So an outage of VictoriaLogs loses no events
while the spool has room.

- The directory is created (mode 0700) if missing, and Quisora refuses to start if it cannot write there.
- **One directory per node**, on that node's own disk: never a directory two nodes (or two processes) share.
- Past `victorialogs_spool_max_mb` the oldest events leave the spool first, each logged as `audit.undelivered`. Size
  it for the longest outage you must ride out; each event takes roughly 300–500 bytes. So does a batch the spool
  cannot be written to (a full or failing disk).
- The log says when spooling starts (`VictoriaLogs is not taking audit events: spooling them to disk`) and when the
  backlog has been sent (`spooled audit events sent to VictoriaLogs`).
- Delivery is at least once: a crash just after VictoriaLogs took a batch, before it left the spool, sends it again.
  Every event has a unique `id` for removing duplicates when reading.
- Commands (`bootstrap`, `invite`, offline `restore`) do not use the spool: they retry, then log `audit.undelivered`,
  as without one.
- Each event has the stream fields `app` (`quisora`) and `org` (organization id), and the fields `action`, `actor`,
  `actor_id`, `target`, `ip`, `node`, `id` and `detail.<name>`.

```bash
curl http://victorialogs:9428/select/logsql/query \
  --data-urlencode 'query=app:="quisora" action:="user.delete" | sort by (_time desc) | limit 20'
```

## Docker

The [Dockerfile](../Dockerfile) builds a static binary on a distroless base (non-root, data in `/data`). Settings are
`QUISORA_*` variables.

```bash
docker build -t quisora .
export QUISORA_MASTER_KEY="$(docker run --rm quisora genkey)"   # keep it

docker run --rm -v quisora-data:/data -e QUISORA_MASTER_KEY -e QUISORA_PUBLIC_URL=https://localhost:8443 quisora bootstrap
docker run -d -p 8443:8443 -v quisora-data:/data -e QUISORA_MASTER_KEY -e QUISORA_PUBLIC_URL=https://localhost:8443 quisora
```

- `quisora healthcheck` is the container health check (liveness, `/healthz`). Don't restart a node for being unready:
  a cluster node catching up is alive. `quisora healthcheck --ready` checks `/readyz`.
- Compose: [deploy/compose.yml](../deploy/compose.yml) (one node), [deploy/compose.cluster.yml](../deploy/compose.cluster.yml)
  (three nodes on PostgreSQL).

## Backup and restore

A backup is one compressed file of every record. Secrets stay sealed, and the file has an integrity check made with
the master key. A restore needs the same key, and refuses an altered file before writing anything.

Back up a running server (any backend; the token is a super admin's API token with the `backup` scope):

```bash
QUISORA_ADMIN_TOKEN=qsr_… quisora backup --server https://id.example.com --encrypt quisora.bak
```

- `--encrypt` encrypts the whole file with a key derived from the master key.
- The same is available as `GET /api/v1/backup`.
- `quisora backup quisora.bak` without `--server` reads the configured store directly. On BadgerDB and SQLite, stop the node
  first.
- BadgerDB, SQLite, PostgreSQL, MySQL and MariaDB give a point-in-time snapshot. Valkey gives every record that
  existed throughout the backup.

Restore into an empty store:

```bash
quisora serve --restore-from quisora.bak      # or QUISORA_RESTORE_FROM; ignored once the store holds data
quisora restore quisora.bak                   # into the configured store, without serving
```

- Ids and versions are kept, into any backend (a BadgerDB backup can go into PostgreSQL).
- A restore that fails part-way leaves `restore-incomplete` in the data directory. Empty the store before trying again.
- **Clusters always restore into an empty cluster.**
  - Shared database: restore into the empty database, then start the nodes.
  - Gossip: restore one node and start it, then start the others with empty databases.
  - A restored node that meets peers holding data refuses.

## Health and monitoring

- `/healthz`: liveness.
- `/readyz`: readiness, cluster-aware. Route load balancers on it. It reports size, quorum and counts of unconfirmed
  writes, refusals and clock skew.
- `GET /api/v1/cluster` (super admins) and the console's settings page: the node's cluster status.
- The probes, discovery and JWKS are never shed under load (`limits.max_in_flight`, default 4096 per node).

## Sizing

One Apple M5 Pro (15 cores) with the load generator on the same machine; real deployments do better.

| One node, 64 concurrent clients | BadgerDB |   SQLite | PostgreSQL |
| ------------------------------- | -------: | -------: | ---------: |
| Refresh token                   | 55,900/s | 50,500/s |   30,400/s |
| Client credentials              | 59,400/s | 54,800/s |   55,000/s |
| Token introspection             | 48,800/s | 48,500/s |   48,100/s |
| Password sign-in                |    487/s |    473/s |      516/s |

- A password sign-in costs ~26 ms of CPU (argon2id, 19 MiB). Plan ~30 cores for 1,000 password sign-ins/s. A
  passkey sign-in costs ~0.15 ms.
- Tested at 5,000 organizations × 1,000 users (6M records); lookups and token traffic do not slow down at that size.
- A new gossip node catches up at ~86,000 records/s.
- The load test tool reproduces these. It is a development tool, not part of the `quisora` binary: build it with
  `task loadtest` (or `go build -o bin/loadtest ./tools/loadtest`), then use `bin/loadtest seed` and
  `bin/loadtest run`. The seeder needs `QUISORA_LOADTEST=1`, as it writes test data straight into the store.
