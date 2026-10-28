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
- `quisora genkey` prints a key for `server.master_key`, `cluster.key` and `storage.badgerdb.encryption_key`.
- Secrets (the master key and previous master keys, `cluster.key` and `cluster.previous_keys`, database DSNs and passwords, the SMTP password,
  `storage.badgerdb.encryption_key`, `server.restore_password`, a VictoriaLogs URL with credentials) belong in the config
  file or the environment. Given as flags they are accepted, but anyone on the machine can read them in the process
  list (`ps`), so every command prints a warning naming the variable and key to use instead. (The Taskfile's
  development tasks pass a development key as a flag on purpose.) Any of them can instead name a value in HashiCorp
  Vault or 1Password: [secret stores](secret-stores.md).

Settings every deployment sets:

| Setting                             | Flag                      | Notes                                                                                                                                                              |
| ----------------------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `server.public_url`                 | `--public-url`            | The address users reach, and the base of every organization's issuer (`<public_url>/o/<org id>`). https only.                                                                                                                |
| `server.listen`                     | `--listen`                | Default `:8443`. HTTPS only; there is no plain-HTTP listener.                                                                                                      |
| `server.data_dir`                   | `--data-dir`              | Everything the node keeps on disk ([layout](#the-data-directory)). Required; default `data`. One per node.                                                         |
| `server.master_key`                 | `--master-key`            | Seals secrets at rest. Required (identical on every node of a cluster); nothing is generated or kept in the data directory. Keep it safe, apart from the data and the backups. |
| `server.previous_master_keys`       | `--previous-master-keys`  | Earlier master keys, only while [rotating the master key](#rotating-the-master-key). Identical on every node.                                                     |
| `server.tls_cert`, `server.tls_key` | `--tls-cert`, `--tls-key` | PEM files. Without them a self-signed certificate is generated in `<data-dir>/tls`. A renewed certificate is used without a restart ([TLS certificates](#tls-certificates)). |

### The data directory

`server.data_dir` is the one place a node keeps files; nothing is written anywhere else. Put it on persistent storage,
readable only by the user Quisora runs as (it is created with mode 0700). Each node of a cluster has its own: never
share one between nodes or processes.

| In `<data-dir>`      | What                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------ |
| `badgerdb/`          | The store, with `storage.backend = "badgerdb"` (the default).                                          |
| `quisora.db`         | The store, with `storage.backend = "sqlite"`.                                                          |
| `tls/`               | The self-signed certificate, when `server.tls_cert` is not set.                                        |
| `auditspool/`        | Audit events VictoriaLogs has not taken yet, with `audit.victorialogs_url` set ([Spool](#spool)).       |
| `node_id`, `cluster-state.json`, markers | The node's identity (made at its first start in every mode, unless `cluster.node_id` sets it: its queued emails and back-channel logouts are its own by it, [Queued work](#queued-work)) and cluster bookkeeping: whether its database's partition state can be trusted, which data set it holds (its genesis: trusted only for the database it was saved for), whether it has formed in its cluster, a forced start not yet audited (`cluster-state.json`); the one-shot markers `force-start` and `restore-incomplete`; `restore-audit.json` (restores not yet in the audit log). |

Nothing else is written there. In particular a gossip node does not spool what it sends another node that is catching up:
the stream goes from the database to the other node's database with no file in between (an `export-*.tmp` file here is left by an older build
that crashed during a catch-up: nothing reads or deletes it, and it can be removed by hand).

Backups do not need the data directory (they come from the store: [Backup and restore](#backup-and-restore)), but
restoring a node without it gives it a new identity, and audit events still spooled in it are lost; so are the emails
and back-channel logouts its store holds queued for it (they are its own by its id: no other node, nor the node under
its new id, sends them).

### Queued work

Email ([Email](#email)) and the back-channel logouts an application did not take are queued in the store, as records of
the node that queued them: sealed with the master key, written before the request answers, and kept across restarts
and crashes. Only that node sends them; nothing else reads them. They are never backed up or replicated: with gossip
each node's are in its own database, and on a shared database every node holds its own there, apart from the others'.
A node that is gone for good leaves its items unsent: each is discarded (it expires, and the purge removes it) a day
after its last retry would have been, by when it is worth nothing (its retries are over, and an invitation it carries
lasts 7 days). Each node's caps (10,000 emails; 10,000 logouts, 2,500 of one organization) and gauges count its own
items only.

### TLS certificates

With `server.tls_cert` and `server.tls_key` set, Quisora looks at the two files every hour and switches to a renewed
certificate (certbot, cert-manager or a script replacing them): new connections get the new certificate, open ones
carry on. `kill -HUP` loads it at once; make it the renewal hook to switch straight away. A pair that does not load, such as a certificate
written before its key, or a key that does not match, leaves the current certificate in use, is logged
(`TLS certificate not reloaded`) and is tried again at the next check. Without them, the self-signed certificate in
`<data-dir>/tls` is replaced before it expires.

### Stopping

On SIGTERM or SIGINT a node stops taking new requests, lets those in flight finish, then closes. When something has
been polling `/readyz` in the last two minutes (a load balancer, an orchestrator), `/readyz` first answers 503
(`"status": "draining"`) for `server.shutdown_drain` seconds (default 10) while the node still serves, so traffic
moves to other nodes before it goes. Then requests in flight get `server.shutdown_timeout` seconds (default 30). Make
the orchestrator's stop timeout longer than the two together. A node nobody polls stops without the wait.

## First start

`quisora serve` never creates anything. Set a new server up once with `quisora bootstrap`:

```bash
quisora bootstrap --data-dir /var/lib/quisora --public-url https://id.example.com
quisora serve --data-dir /var/lib/quisora --public-url https://id.example.com
```

- `bootstrap` creates the `primary` organization (second factor required) and a super admin without a password,
  `server.bootstrap_admin` (default `admin@example.com`).
- It prints a single-use invitation link (7 days). Open it, set a password or create a passkey, then a second factor.
- A second run changes nothing. `quisora invite primary admin@example.com` issues a new link while the server runs
  (it asks the running server, signing the request with the master key). Locked out of the console:
  [break-glass](SECURITY.md#incident-response).
- Until the server is set up, `/readyz` reports not ready.

## Signing keys

Tokens are signed with ES256 by default (`tokens.signing_alg`; `EdDSA` is a little faster where every relying party
supports it). A new key is made every `tokens.key_rotation_days` (30 by default; 0 rotates by hand only) by the
housekeeping leader (in a cluster, the node that owns partition 0: `leader` in `GET /api/cluster`; housekeeping moves with it,
see [REPLICATION.md](REPLICATION.md), "Housekeeping"). It is published in the JWKS at once and signs 15 minutes later, so relying parties already know
it; the previous key stays published until the tokens it signed have expired, then it is removed.

Super admins see the keys on the **System overview**: each key's state (signing, next, previous) and when it
starts signing, stops and is removed. **Rotate now** makes a key that signs at once; tokens signed before keep working
until they expire. When a key may have been exposed, rotate, then **Remove** on the old key: the tokens it signed
stop verifying here at once, and in applications once they fetch the key set again (applications get new tokens
through their refresh tokens; nobody is signed out). The key that signs now cannot be removed. The same is
`GET /api/keys`, `POST /api/keys/rotate` and `DELETE /api/keys/{id}`.

## The system overview

Super admins have **System overview** at the bottom of the console's menu: one page for the server as a whole. It
shows the counts of organizations, users and sessions; the cluster, when nodes replicate over gossip (every node with
its state and role, the quorum, and this node's own view, refreshed every 5 seconds); the signing keys (rotate, and
remove an old one); whether a master key rotation is in progress (with a link to where it stands); and the
server-wide [emergency sign-out](emergency-sign-out.md). The menu keeps the organization you were last administering,
so it is one click back. `GET /api/system`, `GET /api/cluster` and `GET /api/keys` have the same figures. Each
organization has an **Overview** page too, for its administrators and super admins, with its own emergency sign-out.

## Sign-in, applications and incidents

These have guides of their own:

- **How people sign in**, and the rules that protect accounts (session lifetimes, re-authentication for sensitive
  changes, protecting administrators): [sign-in/](sign-in/README.md), with [passkeys](sign-in/passkeys.md),
  [upstream providers](sign-in/providers.md), [recovery codes](sign-in/recovery-codes.md) and
  [codes by email](sign-in/email-codes.md).
- **Applications** (OAuth 2 and OpenID Connect): [oauth/](oauth/README.md).
- **Emergency sign-out and lock-out**: [emergency-sign-out.md](emergency-sign-out.md).
- **Secrets in Vault or 1Password**: [secret-stores.md](secret-stores.md).
- **Personal API tokens**: [API-TOKENS.md](API-TOKENS.md).

Settings the guides refer to: `session.ttl`, `session.idle`, `session.privileged_ttl` and `session.privileged_idle`
(session lifetimes); `session.upstream_check_minutes` (leaver detection); `tokens.*` (token lifetimes and signing);
`tokens.api_token_max_days`; `[secrets.vault]` and `[secrets.onepassword]`. TLS 1.2 connections are offered only the
forward-secret AES-GCM cipher suites (RFC 9325, as FAPI 2.0 requires); TLS 1.3 is unaffected. Behind a proxy that ends
TLS, the proxy's configuration decides.

## Rotating the master key

The master key seals every secret Quisora stores: authenticator (TOTP) secrets, sign-in providers' client secrets,
the signing keys' private keys, upstream refresh tokens and the keys relying parties' refresh tokens are made from.
Rotate it on a schedule, and at once if it may have been exposed. A rotation re-seals every one of those secrets with
the new key, without anyone noticing: users keep their authenticators, applications keep their refresh tokens. Then
the old key is removed, and from that moment it opens nothing the server holds.

Each key has an id (8 characters, derived from the key, revealing nothing about it): sealed values name the key that
sealed them, and the log names keys by it (`key`).

### Changing the keys: reload or restart

Each step below changes `server.master_key` and `server.previous_master_keys` in a node's config file, then either
restarts the node or tells it to reload them, without a restart. On a gossip cluster every node reloads at once with
**Reload configuration** on the admin console's System page (or `POST /api/cluster/reload`, see
[REPLICATION.md](REPLICATION.md#changing-the-cluster-size)); a single node reloads with SIGHUP:

```bash
kill -HUP <pid>                          # systemd: systemctl reload quisora (ExecReload=/bin/kill -HUP $MAINPID)
docker kill --signal HUP quisora         # Kubernetes: kubectl exec <pod> -- kill -HUP 1, once the mounted file has changed
```

- A reload reads only these two settings (and, on a gossip cluster, `cluster.key` and `cluster.previous_keys`: see
  [rotating the cluster key](#rotating-the-cluster-key); and `cluster.size` and `cluster.peers`: see
  [changing the cluster size](REPLICATION.md#changing-the-cluster-size)), from the config file and the `QUISORA_*`
  environment variables as at start-up. Nothing else is reloaded.
- Settings given on the command line (`--master-key`) cannot change while the server runs, so a reload leaves them
  alone and says so (the log, and the console's report): put them in the config file. Settings from environment
  variables cannot change either, since a running process keeps its environment; use the config file, or restart.
- A reload is refused, and the keys in use stay, when the new keys do not include the key in use: a typo or the
  wrong file cannot make a node seal with a key the others cannot open. The log says `master keys reloaded` or
  `master keys not reloaded` with the reason.

### Is it done? When can the old key go?

Super admins see that a rotation is in progress on the **System overview**, which links to its status. The
same status is `GET /api/master-key` (super admin). It shows:

- the key every node seals with, and the previous keys every node holds;
- how many stored secrets are still sealed with a previous key, and how many open with no configured key;
- a state: `waiting_for_nodes`, `resealing`, `unopenable`, `complete` (with
  `previous_keys_removable: true`: remove them now) or `none` (no rotation in progress).

The housekeeping leader also logs `master key rotation complete … remove server.previous_master_keys now`, and repeats
it every hour until they are removed.

### One node

1. Make a new key: `quisora genkey`.
2. Set the new key as `server.master_key` and the old one in `server.previous_master_keys`, then reload or restart:

   ```toml
   [server]
   master_key = "<new>"
   previous_master_keys = ["<old>"]
   ```

3. Within minutes the status says `complete`. Remove `previous_master_keys`, and reload or restart.

### Several nodes (shared database or gossip)

Every node must be able to open what any other node seals, so the new key is first added everywhere as a previous key,
and only then made active. Do each step on every node, one node at a time, before starting the next step.

1. `quisora genkey`.
2. Every node: `master_key = "<old>"`, `previous_master_keys = ["<new>"]`; reload or restart. Nothing changes yet;
   every node can now open what the new key seals.
3. Every node: `master_key = "<new>"`, `previous_master_keys = ["<old>"]`; reload or restart. New secrets are sealed
   with the new key. While some nodes still seal with the old one, the status says `waiting_for_nodes` and names
   them, and nothing is re-sealed. Once all do, the housekeeping leader re-seals every stored secret, and the status
   says `complete`. A node reports its keys when it starts, before it serves, and serves only while its report counts
   (renewed every 5 minutes, good for 15): one whose report lapsed (its store refused the renewals) is not ready until
   it reports again, so every node that may seal anything is in the status.
4. Every node: remove `previous_master_keys`; reload or restart.

On a shared database the first node with the new key active also moves the database's key check to it: from then on
a node started with only the old key refuses to start.

### After the rotation

- Nothing the server holds needs the old key. Keep it only with the **backups made before the rotation**: a backup
  is verified, decrypted and restored with the key it was made with. To restore one, put its key in
  `previous_master_keys` for the restore (the restored secrets are then re-sealed with the active key as above), and
  remove it again afterwards. Make a new backup once the rotation is complete.
- Device cookies (which let a browser that signed in before skip the per-address sign-in limit) are made with the
  active key only: each browser earns a new one at its next sign-in.
- If the old key was exposed, so is everything it ever sealed: a copy of the database or a backup from before the
  rotation can be opened with it. Rotating the master key does not change the secrets themselves. Also rotate the
  signing keys (**Signing keys → Rotate now**), the sign-in providers' client secrets (at each provider, then in
  Quisora), end the relying parties' refresh tokens (a rotation keeps them working: the emergency sign-out, `quisora
  sign-out --all`, ends every session and refresh grant), and have users with an authenticator app set it up again.
- A secret that no configured key opens (the old key removed before the rotation completed, or a damaged value) is
  logged at error level (`secrets that no configured master key opens`); put the missing key back in
  `previous_master_keys`.
- Queued emails and back-channel logouts ([Queued work](#queued-work)) are sealed too, and re-sealed by their node
  (each node its own). One sealed with a key that is no longer configured (removed too early) stays queued, to be
  delivered once its key is back: the node logs `items sealed with a master key that is not configured`, and `GET
  /api/master-key` counts them (`queued_items_lost`) with a warning in its `detail`. They need none of the configured
  keys, so they do not hold the rotation back. They are discarded a day after their last retry would have been, as
  every queued item is: by then they are worthless even if the key comes back.

## The primary organization

The primary organization is the first one, made by `quisora bootstrap`, and it never changes. Its id is
`00000000-0000-7000-8000-000000000001`, so its sign-in page is `/o/00000000-0000-7000-8000-000000000001/login` (what
`https://<public_url>/` redirects to) and its issuer `<public_url>/o/00000000-0000-7000-8000-000000000001`. Super
admins belong to it, and the server's emergency sign-out counters are kept on it. When its super admins are all gone, `quisora invite
--break-glass --super-admin` (above) recovers access.

## Storage backends

Pick one with `storage.backend` (`--storage`). The tables or keys are created on first start; the database itself
must exist.

| Backend            | Use                                                            | Settings                                                                                         |
| ------------------ | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `badgerdb` (default) | One node, or each node of a gossip cluster. Embedded, in `<data-dir>/badgerdb`. | `storage.badgerdb.sync_writes` (default true), `sync_interval_ms`, `encryption_key` |
| `sqlite`           | One node, or each node of a gossip cluster. Embedded, pure Go, in `<data-dir>/quisora.db`. | none                                                                   |
| `postgres`         | A shared database for several nodes, or one node.              | `storage.postgres.dsn`, `max_open_conns`, `max_idle_conns`                                       |
| `mysql`, `mariadb` | As PostgreSQL. MySQL 8.0.17 or later (its binary NO PAD collation `utf8mb4_0900_bin`). | `storage.mysql.dsn` / `storage.mariadb.dsn`, connection limits                                   |

Every backend keeps to the same contract, so what one accepts every other accepts. A record's id and scope are at most
191 characters (the width of a server database's key columns), a string field 255 (the tags field `model.MaxTagsText`);
a longer one is refused before anything is written, and unique values (a resource address, a provider's subject) may be
any length. Deleting a record that is not live writes nothing. A write never moves a record to another partition. A call
whose context has ended, or on a store that is closed, answers "unavailable" (HTTP 503 where a request met it).

**Durability and write speed (one BadgerDB node).** With `sync_writes = true` (the default) every acknowledged write is
on disk; concurrent writes share one sync, so a fast disk (an NVMe drive with power-loss protection) loses little to
it. On a disk whose sync is slow (most cloud volumes, around a millisecond or more), `sync_writes = false` with
`sync_interval_ms = 100` acknowledges writes from memory and syncs every 100 ms: measured at 6 to 25 times the write
throughput at 16 to 64 writers on such a disk, and around 1.2 to 1.9 times on a fast local SSD. A crash of the process
loses nothing; a power cut or a kernel panic loses up to the interval of acknowledged writes. A gossip node refuses it
(its acknowledged writes must survive a power cut). For PostgreSQL and MySQL the same trade is the server's own setting
(`synchronous_commit = off`, `innodb_flush_log_at_trx_commit = 2`), not Quisora's.

```bash
# PostgreSQL (connection strings carry the password: environment or config file, not flags)
export QUISORA_POSTGRES_DSN='postgres://quisora:secret@db:5432/quisora?sslmode=verify-full'
quisora serve --storage postgres

# MySQL / MariaDB (the collation is set by Quisora)
export QUISORA_MYSQL_DSN='quisora:secret@tcp(db:3306)/quisora?tls=true'
quisora serve --storage mysql

# SQLite (in <data-dir>/quisora.db)
quisora serve --storage sqlite --data-dir /var/lib/quisora
```

Every backend passes the same store conformance suite. BadgerDB is the fastest; see [Sizing](#sizing).

**Bounds on a statement (SQL backends).** Every connection Quisora opens limits how long one statement may run and how
long it may wait for a lock:

| Database   | Statement                                     | Lock wait                      |
| ---------- | --------------------------------------------- | ------------------------------ |
| PostgreSQL | `statement_timeout` 10 s                      | `lock_timeout` 5 s             |
| MySQL      | `max_execution_time` 10 s (bounds SELECTs only) | `innodb_lock_wait_timeout` 5 s |
| MariaDB    | `max_statement_time` 10 s                     | `innodb_lock_wait_timeout` 5 s |
| SQLite     | none (a cancelled request interrupts its reads) | `busy_timeout` 5 s           |

Every statement Quisora runs is short: a read of a record or a page, the writes of one change, a batch of 500 rows of a
purge, of a partition's export or of the reset before a partition is copied whole, take milliseconds, and a count or a
search over a large organization well under a second. Locks are held by transactions of milliseconds. So the bounds
only stop a runaway query, or a lock held by a stuck client, from holding a connection (on SQLite, the one writer every
change waits for) indefinitely: the statement fails, and the request that met it answers 503 (try again), without
retrying a lock wait that has already run out. A server's bounds can be changed in its DSN, which Quisora then leaves
as they are (PostgreSQL: `?statement_timeout=30000&lock_timeout=10000`, in milliseconds; MySQL:
`?max_execution_time=30000&innodb_lock_wait_timeout=10`; MariaDB: `?max_statement_time=30&innodb_lock_wait_timeout=10`,
in seconds). The PostgreSQL bounds are sent when a connection starts: a pooler between Quisora and PostgreSQL must
accept them (PgBouncer refuses startup parameters it does not track; with them in its `ignore_startup_parameters`, set
them on the role instead: `ALTER ROLE quisora SET statement_timeout = '10s'`). The schema migration at start-up runs
without the bounds: building an index over a large table may take longer.

### TLS to the database

Off this machine, use TLS that verifies the server: the connection carries the database password and every sealed
record. Nothing is refused (local and development set-ups work as they are), but `serve` logs a warning at start-up
for each connection that leaves the machine unencrypted or unverified, and for an SMTP password sent without TLS.
Connections to `localhost`, a loopback address or a Unix socket are never warned about.

| Backend            | Verified TLS                                                                                                 |
| ------------------ | ------------------------------------------------------------------------------------------------------------ |
| PostgreSQL         | `sslmode=verify-full` in the DSN; a private CA in `storage.postgres.ca_file` (or `sslrootcert` in the DSN)   |
| MySQL / MariaDB    | `tls=true` in the DSN; a private CA in `storage.mysql.ca_file` / `storage.mariadb.ca_file` (which also turns TLS on) |

### Encryption at rest

Sealed secrets (TOTP secrets, password hashes, provider and signing keys, upstream tokens) are encrypted with the
master key on every backend. The rest of the data (names, email addresses, sessions, the audit log in the database) is
protected at rest by the storage:

- **BadgerDB** encrypts its files when `storage.badgerdb.encryption_key` is set (`quisora genkey`; AES-256; not the
  master key, and kept apart from the data like it). It is chosen when the store is created: a store made without it
  cannot be opened with it, and the reverse. To encrypt an existing store, back it up, then restore into a new store
  with the key set. Every node of a gossip cluster has its own store and may have its own key.
  To change the key: in a gossip cluster, one node at a time, stop it, set its new key, empty its data directory's
  `badgerdb` and start it: it copies everything back from the others, encrypted with the new key; wait until it is
  ready before the next. A single node: back up, then restore into a new store with the new key.
- **SQLite**: put the data directory on an encrypted volume (LUKS, FileVault, BitLocker, an encrypted cloud disk), or
  accept plain files for local use.
- **PostgreSQL, MySQL, MariaDB**: encryption at rest is the database's, set up by its administrator: encrypted
  tablespaces or tables (MySQL and MariaDB InnoDB encryption), the provider's encrypted storage, or an encrypted
  volume.

## Clustering

Two modes. Do not mix them.

### Shared database

Several nodes on one PostgreSQL, MySQL or MariaDB database, which is the only copy. Leave `cluster.bind`
empty (that is the replicated mode below).

- Short-lived sign-in state (codes, sign-in steps, rate limits) lives in the database too: any node serves any
  request, and the load balancer needs no sticky sessions.
- A lease in the database picks the node that runs housekeeping (key rotation, purges, user end dates).
- **With `cluster.notify`** (recommended): the nodes form a small gossip network of their own that carries only change
  notices (what changed, never the data). A change made on one node clears the others' caches and updates their open
  admin and account pages within moments. A lost notice only waits for a cache to expire.
- **Without it**, a node learns of another's change when its cache expires, within 5 seconds (a disabled user or a
  revoked client keeps working that long on the other nodes), and its pages do not follow other nodes' changes live.
- Every node has the same `server.master_key`. A node with a different key refuses to start.
- High availability is the database's: run it as your own HA cluster, with **one writer at a time**: every Quisora
  node writes to the same primary (PostgreSQL, MySQL or MariaDB, with a standby taking over on failure). A
  multi-primary cluster (MariaDB or MySQL **Galera**, or any setup that certifies only the rows a transaction writes)
  must be used the same way, with every Quisora node writing to one of its nodes (a proxy such as HAProxy or ProxySQL
  that sends all writes to one) and the others standing by. Quisora relies on a transaction's shared-locked read (it
  keeps an organization that is being deleted from gaining a user at the same moment): Galera certifies only a
  transaction's writes, so such a read does not stop a write on another node, and both commit. `wsrep_sync_wait` does
  not change that: it makes a read wait for the cluster, it locks nothing.

```bash
quisora serve --public-url https://id.example.com --master-key "$KEY" \
  --storage postgres --postgres-dsn 'postgres://quisora:secret@db:5432/quisora' \
  --cluster-notify-bind 0.0.0.0:7947 --cluster-notify-advertise node1:7947 \
  --cluster-notify-peers node1:7947 --cluster-notify-peers node2:7947 --cluster-notify-peers node3:7947 \
  --cluster-notify-key "$NOTIFY_KEY"
```

`cluster.notify` takes `bind`, `advertise` (required when `bind` is a wildcard), `peers` (every node; listing itself
is fine; on the command line repeat the flag, in `QUISORA_CLUSTER_NOTIFY_PEERS` separate them with commas) and `key` (`quisora genkey`, the same on every node, apart from `cluster.key`). Open its port (TCP and UDP)
between the nodes only. With `cluster.bind` set, `cluster.notify` is ignored with a warning: replication carries
every change already. It is refused with a node-local database (BadgerDB, SQLite).

Run `quisora bootstrap` once, against the database, before the first node starts.

### Replicated (gossip)

Every node has its own database (BadgerDB is the usual choice). The data is split into 64 partitions; each partition has one
owner node that orders its writes and commits each on a majority of the nodes before it is visible, and every node keeps a copy
of everything and reads from it.
As in every mode, super admins are protected by rank: nobody removes their own access, only a super admin removes a super
admin, and the system never does (see [protecting administrators](sign-in/README.md#protecting-administrators)). That is
not a guarantee that one always remains: two super admins removing each other at the same moment on different nodes can
leave none, and `quisora invite --break-glass --super-admin primary <email>` recovers. Keep a second super admin anyway,
so that losing one account never needs the break-glass procedure.

```toml
[server]
public_url = "https://id.example.com"
master_key = "…"          # identical on every node

[cluster]
bind = "0.0.0.0:7946"
advertise = "10.0.0.11:7946"
peers = ["10.0.0.11:7946", "10.0.0.12:7946", "10.0.0.13:7946"]   # every node lists every node
size = 3                  # required, identical on every node; a write needs size/2+1 nodes
key = "…"                 # quisora genkey, identical on every node
```

How the cluster behaves is in [REPLICATION.md](REPLICATION.md); what an operator needs from it:

- **Run three or five nodes.** A write needs a majority of `cluster.size` (it never shrinks): three nodes tolerate one down,
  five tolerate two. Without a majority a node is not ready: it makes no replicated write and refuses everything but its health
  probes, the token endpoints included. ([Cluster size](REPLICATION.md#cluster-size))
- **When a node is lost, its partitions move within a few seconds**: writes to them wait for that (up to 5 s) and then fail with
  503; reads of what the node already has go on. A node you stop with SIGTERM hands over at once.
- **A starting node** serves only `/healthz` and `/readyz` until it has caught up and been stable for a few seconds. Restart
  nodes one at a time; restarting all of them at once needs nothing special. ([Node states](REPLICATION.md#node-states))
- **A node with a new or restored database copies everything** from a majority of the *other* nodes before it takes part (both
  others of three). While another node is down as well it waits, resynchronising; `quisora force-start` (see below) is the
  operator accepting that it copies from whichever nodes answer. (A cluster of two needs only the other node.)
- **BadgerDB needs `storage.badgerdb.sync_writes = true`** (the default): a node's promises and the writes it acknowledges must
  survive a power cut, and a gossip node refuses to start with it off.
- **Keep the data directory with the database**: it holds the node's id (or set `cluster.node_id`) and `cluster-state.json`
  (whether the database can be trusted), and a node that finds another node's database refuses to serve (it never wipes it).
- **Clocks** must be in sync (NTP); more than 5 s apart is a broken node, and gossip refuses packets more than two minutes off
  the receiver's clock. ([Clocks](REPLICATION.md#clocks))
- **Open the gossip port** (`cluster.bind`, TCP and UDP) between the nodes only: the partition protocol's messages (writes, promises,
  catch-up streams) use it, encrypted and authenticated by `cluster.key`.
- **`quisora invite` and `quisora sign-out` go through a running node** in a gossip cluster (they sign the
  request with the master key); `quisora bootstrap --new-cluster` and `quisora restore` are for the first node of a new cluster,
  with an empty database: they alone create a cluster's data set.

New cluster:

1. `quisora bootstrap --new-cluster` on one node, with an empty database.
2. Start every node. The others start with empty databases, adopt the first node's data set and copy from it (started before it,
   they wait: "no data set"). The data set forms once every node has started: until then a new node copies from the first
   node alone; after that, replacements copy from a majority of the others as above.

Replacing a node: start the replacement with an empty database and the same configuration. It copies everything.

After a lost disk with another node also down (`quisora force-start`), changing the size, and what each refusal means:
[REPLICATION.md, Operator procedures](REPLICATION.md#operator-procedures).

### Rotating the cluster key

`cluster.key` encrypts and authenticates gossip between the nodes. Each node derives a fresh traffic key from it every
hour, so it does not wear out; rotate it on a schedule, and at once if it may have been exposed (anyone holding it on
the network path can read and inject gossip). The cluster keeps running throughout.

Three rounds, each on every node before the next round starts. Each round edits every node's config file and then
reloads them all at once (**Reload configuration**, as for the [master key](#changing-the-keys-reload-or-restart)),
reloads each with SIGHUP, or restarts the nodes:

1. `quisora genkey`, then on every node: `key = "<old>"`, `previous_keys = ["<new>"]`. Every node now also reads
   gossip encrypted with the new key.
2. Every node: `key = "<new>"`, `previous_keys = ["<old>"]`. Each node now encrypts with the new key; the others read
   it, and it still reads those that have not switched yet.
3. Every node: `key = "<new>"`, remove `previous_keys`.

```toml
[cluster]
key = "<new>"
previous_keys = ["<old>"]     # rounds 1 and 2 only
```

- The log says `cluster keys reloaded` (with the key ids: 8 characters derived from each key, revealing nothing) or
  `cluster keys not reloaded` with the reason. The system overview (and `GET /api/cluster`) lists each node's key ids
  under `cluster_keys`, the one that encrypts first.
- A reload is refused when the new keys do not include the key in use: a typo cannot cut a node off. Keys given on the
  command line cannot be reloaded.
- A node started (or restarted) during a rotation must be given that round's keys; one that misses a round cannot
  talk to the others until it is given them, and comes back by itself once it is.

## Audit log

Every audit event is written to the structured log (`log.format = "json"` for log shippers). The admin console's audit
pages read it from one of two places:

|                           | Database (default)                                                                            | VictoriaLogs                                  |
| ------------------------- | --------------------------------------------------------------------------------------------- | --------------------------------------------- |
| For                       | Development, home labs, testing                                                               | Production; required for SOC 2                |
| Kept                      | `audit.retention_days` (7)                                                                    | VictoriaLogs' `-retentionPeriod`              |
| One node, shared database | In the database                                                                               | Sent to VictoriaLogs; nothing in the database |
| Gossip cluster            | Each node keeps its own events (never replicated, purged by that node); a page asks every node of the cluster and merges their answers, and says which did not answer | Every node sends; any node reads              |

Admins see their own organization's events, except those that name a super admin as actor or target user (a sign-in, a
change made to one, a super admin's work in the organization): super admins are invisible below them everywhere, so the
page, its count and its search leave those events out. Super admins also see every organization, and all of it
(`/admin/audit`, `GET /api/audit?org=<name>`). The same holds when the events are read from VictoriaLogs through
Quisora; reading them in VictoriaLogs itself is for the operators who run it.

Which events those are is decided when each is written: an event names its actor and its target user by id
(`actor_id`, `target_id`) as well as by name, and carries a `super_admin` mark when either was a super admin at the
time. An admin's page is the organization's events without the mark, one indexed filter: it reads no other
organization's data and no list of super admins, and costs what any page costs. So the mark follows the account, not
the name: a super admin renamed keeps their past hidden. It is never changed afterwards (the log is not rewritten): a
user's events from before they were made a super admin stay visible to the admins who could see them then, and a super
admin's from before a demotion stay hidden. An event whose target is known only by an id that cannot be read when it
is written is marked, not shown on a guess. An event that names a super admin only in its detail (such as a group
membership change) is not marked.

In a gossip cluster with the database trail, an event is on the node that recorded it only: a node that is down, or slow to
answer (3 s), is missing from a page (the page says how many nodes answered), and a node whose disk is lost takes its events
with it.

**Production, and any deployment that needs SOC 2, must use VictoriaLogs.** The database audit trail keeps events for
days, not the year or more an audit period needs; it is per node in a gossip cluster; and it has no protection against
someone with write access to the database. With
VictoriaLogs:

- set its retention to cover the audit period (`-retentionPeriod=1y` or more);
- make it the protected copy: only Quisora may write to that VictoriaLogs, nobody may delete from or rewrite it during
  the retention period, and its storage is backed up to write-once (immutable) storage. [SOC2.md](SOC2.md) shows how
  (vmauth in front of it) and how to check that no event is missing (every event is numbered per node: `boot`,
  `seq`);
- give every node room for the spool (below) in its data directory;
- ship Quisora's structured log too, and alert on `audit.undelivered`: each such line is an event VictoriaLogs will
  never receive, logged in full so it can still be captured from the log.

### What is recorded

| Area | Events |
| --- | --- |
| Sign-in | `login.success` (default on; `audit.logins = false` turns it off), `login.failure`, `login.lockout`, `login.limited` (a sign-in rate limit started refusing: once per limit and minute), `logout`, `passkey.clone` (a copied authenticator, at sign-in or while confirming it is the user), `login.recovery_code`, `login.email_code.sent`, `password.forgot`, `password.reset`, `invite.accept` |
| OAuth / OpenID Connect | `oauth.consent` (allow or deny), `oauth.grant` (every code exchange), `oauth.token_exchange` (every token exchange), `oauth.device.approve` (a device sign-in approved), `oauth.revoke`, `oauth.code.replay` and `oauth.refresh.reuse` (a code or refresh token presented again: its grant is revoked), `oauth.client_auth.limited` (a client's failed authentications reached the limit); with `audit.tokens = true` also `oauth.refresh` and `oauth.client_credentials` for every token issued, and `oauth.device.start` for every device sign-in started |
| Administration | users, groups, organizations, tenants, access, clients, providers, API tokens, invitations, `user.locked_out`, `keys.rotate`, `keys.create` (every signing key made, scheduled ones too), `keys.remove`, `backup.download`, `backup.restore`, `cluster.force_start`, `cluster.reload` (and `cluster.reload.failure`, with each node's report) |
| API access | `api.request.refused` (a management API or SCIM request refused for an authenticated caller: a token without the scope, a request without the CSRF header, a console session without a second factor, a SCIM token whose owner lost the role; with the method, path and reason), `apitoken.refused` (a token that exists presented with a wrong secret, or after an emergency sign-out, or after its owner was disabled or demoted). Both at most once a minute per token or caller and reason on each node, with `detail.suppressed` counting the repeats held back: anyone can repeat a refusal, and the audit log must not be the thing they flood |
| Emergency sign-out | `org.signout` and `server.signout` (with the reason, and whether API tokens ended too), then `signout.sweep` (how many sessions, grants and API tokens were deleted) |
| Account self-service | `account.*`: passkeys, authenticator app, recovery codes, sessions, applications, connected providers, email verification |

Updates record what changed, field by field, as `changed.<field>` = `old → new` (`changed.role`, `changed.email`,
`changed.email_verified`, `changed.settings.require_mfa`, …). Fields that hold secrets never appear; a replaced
provider secret shows as `client_secret` = `replaced`.

Every event has:

- `outcome`: `failure` for refusals (`*.failure`, `*.refused`, `*.lockout`, `*.limited`, `*.replay`, `*.reuse`,
  `*.clone`), `success` otherwise;
- `request_id`: the request's id, also sent as the `X-Request-ID` response header (a trusted proxy's
  `X-Request-ID` is kept, so its logs and the audit log name a request alike);
- `user_agent` and `session_id` (the browser session the request was made in, or the one a sign-in created);
- `detail.token_id` when a personal API token made the change (or was refused);
- `ip`;
- with VictoriaLogs, `node`, `boot` and `seq`: the node that recorded it, that process start's random id, and the
  event's number in that start's sequence (1, 2, 3…), so a gap is an event VictoriaLogs does not hold
  ([SOC2.md](SOC2.md#completeness)).

`quisora invite` and `quisora sign-out` carried out by a running node (a gossip cluster, or a node-local
store that a server holds) are recorded with the actor `command:invite` or `command:sign-out`, the address the request came from in `ip`, and
`detail.command` and `detail.authenticated` (a request signed with the master key); the forced start `cluster.force_start` is
`command:force-start`. The system's own work (housekeeping, key rotation) keeps the actor `system`. Commands that run in
their own process against a store (`bootstrap`, `restore`, and `invite` or `sign-out` against a shared database or
a stopped node that does not replicate) record who ran them: the actor is
`cli:<os user>@<host>`, with `detail.os_user`, `detail.host`, `detail.pid` and `detail.command`. A restore (offline,
or `server.restore_from` at start-up) is written to the primary organization's log as `backup.restore` once the
node can write.

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
  events are sent in the background (on a node, from the spool below; a sign-in waits only for its event to reach the
  local disk).
- An event that finds the queue full, because the node writes faster than the spool's disk keeps up, is given up.
- An event VictoriaLogs will never receive is written to the structured log in full, at error level, with the message
  `audit.undelivered`, a `reason`, and the event under `event` (the same fields VictoriaLogs would have stored). That
  is the last place it goes: ship the structured log, or such events are lost.

### Spool

```toml
[audit]
victorialogs_spool_max_mb = 256          # default 256
```

With VictoriaLogs, every event is written to the spool, `<data-dir>/auditspool`, and synced to disk before the action
that recorded it goes on (events recorded at the same moment share one sync). A separate sender posts the spool to
VictoriaLogs about once a second, and an event leaves the spool only once VictoriaLogs has taken it; what VictoriaLogs
does not take (unreachable, a server error, or refused credentials: 401, 403) stays there and is sent when
VictoriaLogs answers again, oldest first. A shutdown does not wait for VictoriaLogs, and the next start sends what is
spooled.

What is guaranteed: **an event whose write to the spool succeeded is on disk, complete, and is sent to
VictoriaLogs**, through an outage of VictoriaLogs and through a restart or crash of the node, while the spool has
room. The spool is append-only segment files of JSON lines, and only ever appends after its last complete line: a
write that fails part-way (a full or failing disk) is cut back off the segment and the batch reported failed; a
write a crash cut short, or that was written but not yet synced, stays as the last line of its segment, which is
never appended to again after a restart. Replay keeps every complete line (terminated and valid JSON) and leaves a
torn one out by itself, so a torn line can never take a complete event with it.

When the structured log is the fallback (`audit.undelivered`, the event in full — ship the log and alert on it):

- The spool disk did not answer within 2 seconds. The action goes on, the event is logged, and it is still spooled
  once the disk answers, so it then reaches VictoriaLogs as well (a duplicate, by `id`; never a loss).
- The spool could not be written (a full or failing disk, a failed sync of the file or of the directory). The failed
  write is undone, so the log is that event's only copy; a crash before the log is shipped loses it from VictoriaLogs.
- The spool had to make room (below), or the spool queue was full.
- VictoriaLogs refused a batch for what is in it (400, 413, 422): it would never take it, so it leaves the spool
  (logged with VictoriaLogs' answer) rather than hold back everything after it.
- A line in a spool segment is complete but not JSON (the disk changed it): it can never be sent.

Delivery is at least once: a batch VictoriaLogs took is sent again if the node crashed before the batch left the
spool. Every event has a unique `id`; the audit pages show and count each once.

- The directory is created (mode 0700) if missing, and Quisora refuses to start if it cannot write there.
- It is part of the node's data directory, so it is one per node, on that node's own disk.
- Past `victorialogs_spool_max_mb` the oldest events leave the spool first, each logged as `audit.undelivered` (a
  segment being sent at that moment may also reach VictoriaLogs). Size it for the longest outage you must ride out;
  each event takes roughly 300–500 bytes.
- The log says when spooling starts (`VictoriaLogs is not taking audit events: spooling them to disk`) and when the
  backlog has been sent (`spooled audit events sent to VictoriaLogs`).
- Commands (`bootstrap`, `invite`, offline `restore`) do not use the spool: they retry, then log `audit.undelivered`,
  as without one.
- Each event has the stream fields `app` (`quisora`) and `org` (organization id), and the fields `action`, `outcome`,
  `actor`, `actor_id`, `target`, `target_id` (a target user's id), `super_admin` (`true` for an event of a super admin,
  [above](#audit-log)), `ip`, `node`, `id`, `request_id`, `user_agent`, `session_id` and `detail.<name>`.

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

- The container's data directory is `/data`: mount a volume there; it holds the store (BadgerDB or SQLite), the node's
  id and the audit spool.
- `quisora healthcheck` is the container health check (liveness, `/healthz`). Don't restart a node for being unready:
  a cluster node catching up is alive. `quisora healthcheck --ready` checks `/readyz`.
- Compose: [deploy/compose.yml](../deploy/compose.yml) (one node), [deploy/compose.cluster.yml](../deploy/compose.cluster.yml)
  (three nodes on PostgreSQL with the notice gossip, a lab example: it needs `POSTGRES_PASSWORD` and `QUISORA_NOTIFY_KEY`
  as well as `QUISORA_MASTER_KEY`).

## Backup and restore

A backup is one compressed file of every record. Secrets stay sealed, and the file has an integrity check made with
the master key. A restore needs the key it was made with (the active one, or, for a backup from before a
[master key rotation](#rotating-the-master-key), the old one put in `server.previous_master_keys` for the restore), and
refuses an altered file before writing anything.

A backup is encrypted with a password (AES-256-GCM, the key derived by argon2id), not with the master key: a
master key exposure does not open old backups, and a stolen backup needs its password. Keep the password apart from
the backups.

A backup is refused (try again shortly) while the database holds a partition part-way through a copy from another
node, whether the server is running or not: a copy of a whole partition empties it first, and a catch-up cut short has
changed some of a write's records and not yet the others, so a backup of either would verify and restore without being
data the cluster ever held.

Back up a running server (any backend; the token is a super admin's API token with the `backup` scope):

```bash
QUISORA_ADMIN_TOKEN=qsr_… quisora backup --server https://id.example.com quisora.bak    # asks for the password twice
```

- The password (at least 12 characters) comes from `--password-file` (its first line), else from standard input when
  it is a pipe, else from the terminal. It is never a flag.

  ```bash
  quisora backup --server https://id.example.com --password-file /run/secrets/backup-password quisora.bak
  printf '%s\n' "$BACKUP_PASSWORD" | quisora backup --server https://id.example.com - > quisora.bak
  ```

- `--plain` writes it unencrypted (secrets inside stay sealed with the master key).
- `--server` downloads the backup unencrypted over TLS and encrypts it on your machine: the password never reaches the
  server.
- `GET /api/backup` needs either the password in the `X-Backup-Password` header (encrypted) or `?plain=1`
  (unencrypted); without one of them it answers 400.
- `quisora backup quisora.bak` without `--server` reads the configured store directly. On BadgerDB and SQLite, stop the node
  first.
- Every backend gives a point-in-time snapshot: the backup is consistent.

Quisora has no backup schedule of its own: run `quisora backup --server` from cron (or a systemd timer, or a
Kubernetes CronJob) on a machine that keeps the files away from the node, and alert when it fails. For example,
nightly at 02:30 with 30 days kept:

```bash
# /etc/cron.d/quisora-backup: the token and password files are readable by the backup user only
30 2 * * * backup QUISORA_ADMIN_TOKEN="$(cat /etc/quisora/backup-token)" quisora backup --server https://id.example.com --password-file /etc/quisora/backup-password /srv/backups/quisora-$(date +\%F).bak && find /srv/backups -name 'quisora-*.bak' -mtime +30 -delete
```

- The token is a super admin's API token with only the `backup` scope; give it an expiry and renew it.
- Try a restore now and then (into a scratch node, `quisora restore` on an empty data directory): a backup nobody has
  restored is a hope, not a backup.

Restore into an empty store:

```bash
quisora serve --restore-from quisora.bak      # or QUISORA_RESTORE_FROM; ignored once the store holds data
quisora restore quisora.bak                   # into the configured store, without serving
```

- An encrypted backup needs its password: `quisora restore` reads it as `quisora backup` does (`--password-file`, a
  pipe, or the terminal); `serve --restore-from` takes it from `server.restore_password` (`QUISORA_RESTORE_PASSWORD`).
- Backups encrypted with the master key by earlier builds still restore, with no password, given that master key.

- Ids and versions are kept, into any backend (a BadgerDB backup can go into PostgreSQL).
- A restore that fails part-way leaves `restore-incomplete` in the data directory. Empty the store before trying again.
- **Clusters always restore into an empty cluster.**
  - Shared database: restore into the empty database, then start the nodes.
  - Gossip: restore into one node with an empty database (a restore never goes over data, nor on a node that already holds a
    data set) and start it, and start the others with empty databases. The restore writes the records as the first writes of
    their partitions, of a new data set, which the other nodes adopt and copy.
  - A restored node that meets a cluster of another data set exchanges nothing with it and refuses to serve ("another data set
    is in view").

## Upgrading

Settings removed: `storage.badgerdb.path`, `storage.sqlite.path` and `audit.victorialogs_spool_dir` (the store and
the spool are always in `server.data_dir`, [The data directory](#the-data-directory)). A configuration that still has
them is refused at start-up; take them out, and move an existing store or spool into the data directory first.

**Before the first release** there is no upgrade path: a store written by an older pre-release build is refused at
start-up. Wipe it and start clean (or restore a backup made by the new build). What has to happen before that
release: [RELEASE.md](RELEASE.md).

**From the first release:**

- **Back up first.** Upgrades go forward only. A store or database written by a newer build is refused, so going
  back means restoring the backup.
- **One release at a time.** Each release works with the previous one: a cluster can be upgraded one node at a time
  while it keeps serving. Nodes publish their compatibility, and a node more than one release apart is refused: the
  others log `refusing to serve … upgrade one release at a time` and stop serving until it is upgraded or gone.
- **Storage is migrated at the first start of the new build**, step by step, each step recorded as it completes (an
  interrupted upgrade resumes). Nodes that share a database do it once, under a lock; with gossip, every
  node migrates its own store.
- **Backups** made by the previous release restore into the new one.

### Changing a stored format (for developers)

Until the first release, formats change in place. From then on:

- A record field that can be added with a sensible zero value needs nothing: older records read as the zero value.
  Renaming, removing or re-interpreting one needs a migration, on every backend:
  - BadgerDB: append to `formatMigrations` (`internal/store/kvstore/kvstore.go`);
  - SQL: append to `migrations()` (`internal/store/sqlstore/migrate.go`): statements, and Go code for data.
- A backup format change: raise `version`, add `upgrades[old]`, and keep `minVersion` at the previous release's
  version (`internal/backup/backup.go`).
- What nodes send each other changes (a change or a write's data in `internal/cluster/partition.go`, the record encoding in
  `wire.go`, an ephemeral operation): raise `compat`; raise `minCompat` only when this build stops understanding the previous
  release (`internal/cluster/node.go`). A node that does not speak the same version is refused, so a change that the previous
  release cannot read means every node changes at once.
- **The partition layout is a data format.** The number of partitions (64), a kind's partition key (`model.Index.Partition`),
  the partition numbering (`partition.PartitionOf`), the encoding of what `Prepare` and `Commit` exchange and the protocol state
  kept in the databases move records between partitions or change what a stored write means: a running cluster cannot do that
  in place. Changing any of them is a migration with the cluster stopped (backup, restore into a new cluster).
- Never edit or remove a released migration or upgrade: append.

## Email

With `mail.smtp_host` set, invitations, password resets and address confirmations are emailed. Without it nothing is
emailed: administrators share invitation links themselves, and there is no self-service password reset.

Email is queued in the store before the request that sends it answers, as the sending node's own ([Queued work](#queued-work)),
sealed with the master key (messages carry single-use links). A message SMTP does not take is retried after 1, 5, 30
and 120 minutes, then given up and logged (`mail delivery failed, giving up`). A restart, or a crash, keeps the queue:
the node sends what is left when it is back (a message whose sending was cut short by the crash may go out twice).
When the master keys change (a start with new keys, or a reload) each node re-seals its own queue with the active key
before it reports that key, so a rotation reported complete leaves no queued message needing the old key. A message
sealed under a key that is not configured (one removed too early, or a node that was down during the rotation started
without it) is kept and logged, and sent once that key is put back in `previous_master_keys`. Each node holds at most
10,000 messages; past that, new ones are refused with an error. Watch `quisora_mail_queued`: growing means SMTP is not
taking mail.

## Health and monitoring

- `/healthz`: liveness.
- `/readyz`: readiness, cluster-aware. Route load balancers on it. It reports size, quorum, the partitions this node owns and
  counts of writes whose outcome is unknown, refusals and clock skew.
- `GET /api/cluster` (super admins) and the console's settings page: the node's cluster status.
- The probes, metrics, discovery and JWKS are never shed under load (`limits.max_in_flight`, default 4096 per node).
- Short-lived sign-in state (flows, codes, pushed requests, challenges) is held in each node's memory up to
  `limits.ephemeral_mb` (default 1024 MiB); past it, requests that would add to it get 503 until expiries make room.
  Rate-limit counters are never refused. With a shared database this state lives in the database instead.

### Metrics

`GET /metrics` serves Prometheus metrics when `metrics.token` is set (`QUISORA_METRICS_TOKEN`); Prometheus sends it
as a bearer token (`authorization: { credentials: … }` in the scrape config). Without a token there is no such
endpoint. Every node serves its own.

| Metric | What |
| --- | --- |
| `quisora_http_requests_total{code}` | Requests by status class (`2xx` … `5xx`) |
| `quisora_http_request_duration_seconds` | Time to answer (histogram) |
| `quisora_http_shed_total` | Requests refused because too many were in progress |
| `quisora_audit_events_total{action,outcome}` | Every audit event: `login.failure`, `login.lockout`, `login.limited`, `oauth.refresh.reuse`, `oauth.code.replay`, `oauth.client_auth.limited`, `passkey.clone` and the rest ([what is recorded](#what-is-recorded)) |
| `quisora_audit_undelivered_total` | Audit events VictoriaLogs will never receive |
| `quisora_audit_spool_bytes` | Disk the VictoriaLogs spool uses (growing: VictoriaLogs is not taking events) |
| `quisora_mail_queued` | Emails this node has waiting to be sent |
| `quisora_backchannel_logout_queued` | Back-channel logouts this node has waiting to be retried (growing: an application is not taking them) |
| `quisora_backchannel_logout_failed_total` | Back-channel logouts given up on after every retry, or dropped because the queue was full (an organization holds at most 2,500 of a node's 10,000 retries, so only its own are dropped) |
| `quisora_ready`, `quisora_writable`, `quisora_leader` | This node serves; accepts changes; runs housekeeping |
| `quisora_cluster_alive_nodes`, `quisora_cluster_size`, `quisora_cluster_quorum` | Cluster membership |
| `quisora_partitions_owned` | Partitions this node owns (the 64 are shared by the ready nodes) |
| `quisora_partition_writes_total`, `quisora_partition_writes_refused_total`, `quisora_partition_writes_unknown_total`, `quisora_partition_writes_unavailable_total` | Changes this node made since it started: committed; refused by an owner (a version had moved, a unique value was in use); outcome not known (an owner lost mid-write); no owner or majority found |
| `quisora_partition_reads_total`, `quisora_partition_reads_failed_total`, `quisora_partition_takeovers_total` | Fresh reads asked of owners and those that failed; partitions this node became the owner of |
| `quisora_partitions_unreadable` | Partitions this node cannot serve from its copy now (no owner heard, trailing it, diverged): their records answer 503 |
| `quisora_partitions_importing` | Partitions being copied whole to this node (none of such a partition is served, and a backup is refused, until the copy finishes) |
| `quisora_partitions_diverged`, `quisora_partition_divergences_total` | Partitions whose copy here holds writes their owner does not have (the node is not ready: resync it); divergences found since the node started |
| `quisora_partition_lag_seconds{partition}`, `quisora_partition_catching_up{partition}`, `quisora_partition_diverged{partition}` | Per partition: how long this node has trailed a position its owner reported committed (0: not behind); 1 while it catches up; 1 if it diverged |
| `quisora_master_key_rotation` | 1 while previous master keys are configured |
| `quisora_build_info{version}`, `quisora_uptime_seconds`, `quisora_goroutines`, `quisora_memory_heap_bytes` | The process |

Alerts worth having:

- `quisora_ready == 0` or `quisora_writable == 0` for more than a few minutes; `quisora_cluster_alive_nodes <
  quisora_cluster_quorum`; `sum(quisora_partitions_owned) != 64` across the nodes (a partition nobody owns), or a steady
  `rate(quisora_partition_takeovers_total[10m])` (ownership flapping).
- `quisora_partitions_unreadable > 0` for more than a few minutes (some organizations get 503: a node does not leave the
  load balancer for it), `quisora_partitions_diverged > 0` (resync the node), or a `quisora_partition_lag_seconds` that
  keeps growing (a catch-up that keeps failing).
- `increase(quisora_audit_undelivered_total[5m]) > 0`, or `quisora_audit_spool_bytes` growing: audit events at risk.
- Bursts of `quisora_audit_events_total{outcome="failure"}`, by action: password guessing (`login.failure`,
  `login.lockout`), floods (`login.limited`, `oauth.client_auth.limited`), stolen tokens (`oauth.refresh.reuse`,
  `oauth.code.replay`), a cloned passkey (`passkey.clone`).
- Any `quisora_audit_events_total{action=~"keys.rotate|cluster.force_start|backup.download|backup.restore"}`:
  rare, privileged events someone should know about.
- `rate(quisora_http_shed_total[5m]) > 0`: the node is overloaded.

### Access log

The access log is on by default (`log.access`, `QUISORA_LOG_ACCESS`; set it to false to turn it off). It logs every
request: method, path, status, duration, size, client address
and request id (the `X-Request-ID` response header, also in the audit events the request made). The query string is
never logged: it carries authorization codes, states and link tokens. Probes, scrapes and static files are not
logged.

## Sizing

One Apple M5 Pro (15 cores) with the load generator on the same machine; real deployments do better.

| One node, 64 concurrent clients | BadgerDB |   SQLite | PostgreSQL |
| ------------------------------- | -------: | -------: | ---------: |
| Refresh token                   | 55,900/s | 50,500/s |   30,400/s |
| Client credentials              | 59,400/s | 54,800/s |   55,000/s |
| Token introspection             | 48,800/s | 48,500/s |   48,100/s |
| Password sign-in                |    487/s |    473/s |      516/s |

- A gossip cluster of three BadgerDB nodes (all on that one machine, every write committed on two of them before it
  is visible) keeps these rates with the load spread over its nodes: refresh token 52,000/s, client credentials
  48,000/s, introspection 46,600/s, password sign-in 434/s.

- A password sign-in costs ~26 ms of CPU (argon2id, 19 MiB; m=19456, t=2, p=1). Stored hashes are sealed with the
  master key, and one made with other settings is re-hashed at the user's next sign-in; a stored hash naming settings
  far outside these (over 256 MiB, 10 passes or 16 threads) is refused without hashing. Plan ~30 cores for 1,000 password sign-ins/s. A
  passkey sign-in costs ~0.15 ms.
- Tested at 5,000 organizations × 1,000 users with 500,000 refresh grants (6.5M records, BadgerDB, 10.3 GB per node on disk);
  lookups and token traffic do not slow down at that size. Memory per node (measured at 100 organizations × 1,000
  users): about 150–250 MB of Go heap idle and at most
  about 400 MB under full load without password sign-ins (every other scenario at once, 64 concurrent clients each),
  plus 19 MiB for each password being hashed (at most `limits.password_workers`, one per CPU by default: about 900 MB
  in all with every scenario at once on 15 cores), plus the store's own caches (BadgerDB: about
  0.5 GB of block, index and memtable memory), plus `limits.ephemeral_mb` at most for short-lived sign-in state (1 GiB
  by default, a few MB in normal use). Plan 2 GB per node. BadgerDB also maps its files into memory: the operating
  system shows them as resident (several GB at this size), but they are file pages it can drop at any time, not
  allocations. Housekeeping never reads a whole collection: the end-date sweep and filtered queries on large kinds
  use indexes (`model.Due`, `model.Field.Index`).
- At this size send audit events to VictoriaLogs ([Audit log](#audit-log)): the built-in trail's pages read through
  every event they search.
- A new gossip node catches up at ~16,000 records/s.
- Both of the figures above (10.3 GB per node on disk, ~16,000 records/s for an empty node to catch up) were measured on the
  build before the partition protocol, and are to be measured again on this one: it keeps more per record (the position of the
  write that last changed it) and copies a node by partition. (A quick run on one machine, three nodes, 400-byte records and
  BadgerDB without fsync, copied a node at about 70,000 records/s, SQLite at about 23,000: not comparable with the figures above.)
- The load test tool reproduces these. It is a development tool, not part of the `quisora` binary: build it with
  `task loadtest` (or `go build -o bin/loadtest ./tools/loadtest`), then use `bin/loadtest seed` and
  `bin/loadtest run`. The seeder needs `QUISORA_LOADTEST=1`, as it writes test data straight into the store.
