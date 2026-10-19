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
- Secrets (the master key and previous master keys, `cluster.key`, database DSNs and passwords, the SMTP password,
  `storage.badgerdb.encryption_key`, `server.restore_password`, a VictoriaLogs URL with credentials) belong in the config
  file or the environment. Given as flags they are accepted, but anyone on the machine can read them in the process
  list (`ps`), so every command prints a warning naming the variable and key to use instead. (The Taskfile's
  development tasks pass a development key as a flag on purpose.)

Settings every deployment sets:

| Setting                             | Flag                      | Notes                                                                                                                                                              |
| ----------------------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `server.public_url`                 | `--public-url`            | The issuer and the address users reach. https only.                                                                                                                |
| `server.listen`                     | `--listen`                | Default `:8443`. HTTPS only; there is no plain-HTTP listener.                                                                                                      |
| `server.data_dir`                   | `--data-dir`              | Node id, TLS files, cluster state, and the BadgerDB/SQLite store.                                                                                                  |
| `server.master_key`                 | `--master-key`            | Seals secrets at rest. Required (identical on every node of a cluster); nothing is generated or kept in the data directory. Keep it safe, apart from the data and the backups. |
| `server.previous_master_keys`       | `--previous-master-keys`  | Earlier master keys, only while [rotating the master key](#rotating-the-master-key). Identical on every node.                                                     |
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
restarts the node or tells it to reload them, without a restart, with SIGHUP:

```bash
kill -HUP <pid>                          # systemd: systemctl reload quisora (ExecReload=/bin/kill -HUP $MAINPID)
docker kill --signal HUP quisora         # Kubernetes: kubectl exec <pod> -- kill -HUP 1, once the mounted file has changed
```

- SIGHUP reloads only these two settings, read from the config file and the `QUISORA_*` environment variables as at
  start-up. Nothing else is reloaded.
- Keys given on the command line (`--master-key`) cannot change while the server runs, so a reload refuses with an
  error: put them in the config file. Keys from environment variables cannot change either, since a running
  process keeps its environment; use the config file, or restart.
- A reload is refused, and the keys in use stay, when the new keys do not include the key in use: a typo or the
  wrong file cannot make a node seal with a key the others cannot open. The log says `master keys reloaded` or
  `master keys not reloaded` with the reason.

### Is it done? When can the old key go?

Super admins see **Master key rotation** at the bottom of the admin menu while previous keys are configured. The
same status is `GET /api/v1/master-key` (super admin). It shows:

- the key every node seals with, and the previous keys every node holds;
- how many stored secrets are still sealed with a previous key, how many open with no configured key, and how many
  refresh grants from an earlier version still depend on one;
- a state: `waiting_for_nodes`, `resealing`, `unopenable`, `legacy_grants`, `complete` (with
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
   says `complete`.
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
  Quisora), revoke the relying parties' refresh tokens, and have users with an authenticator app set it up again.
- A secret that no configured key opens (the old key removed before the rotation completed, or a damaged value) is
  logged at error level (`secrets that no configured master key opens`); put the missing key back in
  `previous_master_keys`.
- Refresh grants made by a version from before refresh grants had their own key are converted by the re-seal. During
  a rotation started straight after upgrading, they are converted only when next used, and the log counts the rest
  (`refresh grants from an earlier version`); removing the old key ends those, and their users sign in again. Upgrade,
  let the server run a few minutes, then rotate.

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
| `valkey`           | As PostgreSQL.                                                 | `storage.valkey.addrs`, `username`, `password`, `db`, `key_prefix`, `tls`, `ca_file`, `server_name`, `cert_file`, `key_file` |

```bash
# PostgreSQL (connection strings carry the password: environment or config file, not flags)
export QUISORA_POSTGRES_DSN='postgres://quisora:secret@db:5432/quisora?sslmode=verify-full'
quisora serve --storage postgres

# MySQL / MariaDB (the collation is set by Quisora)
export QUISORA_MYSQL_DSN='quisora:secret@tcp(db:3306)/quisora?tls=true'
quisora serve --storage mysql

# Valkey
export QUISORA_VALKEY_PASSWORD=secret
quisora serve --storage valkey --valkey-addrs valkey:6379 --valkey-tls --valkey-key-prefix quisora:

# SQLite
quisora serve --storage sqlite --sqlite-path /var/lib/quisora/quisora.db
```

Every backend passes the same store conformance suite. BadgerDB is the fastest; see [Sizing](#sizing).

### TLS to the database

Off this machine, use TLS that verifies the server: the connection carries the database password and every sealed
record. Nothing is refused (local and development set-ups work as they are), but `serve` logs a warning at start-up
for each connection that leaves the machine unencrypted or unverified, and for an SMTP password sent without TLS.
Connections to `localhost`, a loopback address or a Unix socket are never warned about.

| Backend            | Verified TLS                                                                                                 |
| ------------------ | ------------------------------------------------------------------------------------------------------------ |
| PostgreSQL         | `sslmode=verify-full` in the DSN; a private CA in `storage.postgres.ca_file` (or `sslrootcert` in the DSN)   |
| MySQL / MariaDB    | `tls=true` in the DSN; a private CA in `storage.mysql.ca_file` / `storage.mariadb.ca_file` (which also turns TLS on) |
| Valkey             | `storage.valkey.tls = true`; a private CA in `ca_file`, the name to verify in `server_name`, a client certificate for mutual TLS in `cert_file` / `key_file` |

### Encryption at rest

Sealed secrets (TOTP secrets, provider and signing keys, upstream tokens) are encrypted with the master key on every
backend. The rest of the data (names, email addresses, password hashes, sessions, the audit log in the database) is
protected at rest by the storage:

- **BadgerDB** encrypts its files when `storage.badgerdb.encryption_key` is set (`quisora genkey`; AES-256; not the
  master key, and kept apart from the data like it). It is chosen when the store is created: a store made without it
  cannot be opened with it, and the reverse. To encrypt an existing store, back it up, then restore into a new store
  with the key set. Every node of a gossip cluster has its own store and may have its own key.
- **SQLite**: put the data directory on an encrypted volume (LUKS, FileVault, BitLocker, an encrypted cloud disk), or
  accept plain files for local use.
- **PostgreSQL, MySQL, MariaDB, Valkey**: encryption at rest is the database's, set up by its administrator: encrypted
  tablespaces or tables (MySQL and MariaDB InnoDB encryption), the provider's encrypted storage, or an encrypted
  volume.

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

- set its retention to cover the audit period (`-retentionPeriod=1y` or more);
- make it the tamper-evident copy: Quisora does not sign or chain its events, so only Quisora may write to that
  VictoriaLogs, nobody may delete from or rewrite it during the retention period, and its storage is backed up to
  write-once (immutable) storage;
- turn on the spool (below) on every node;
- ship Quisora's structured log too, and alert on `audit.undelivered`: each such line is an event VictoriaLogs will
  never receive, logged in full so it can still be captured from the log.

### What is recorded

| Area | Events |
| --- | --- |
| Sign-in | `login.success` (default on; `audit.logins = false` turns it off), `login.failure`, `login.lockout`, `login.limited` (a sign-in rate limit started refusing: once per limit and minute), `logout`, `passkey.clone`, `password.forgot`, `password.reset`, `invite.accept` |
| OAuth / OpenID Connect | `oauth.consent` (allow or deny), `oauth.grant` (every code exchange), `oauth.revoke`, `oauth.code.replay` and `oauth.refresh.reuse` (a code or refresh token presented again: its grant is revoked), `oauth.client_auth.limited` (a client's failed authentications reached the limit); with `audit.tokens = true` also `oauth.refresh` and `oauth.client_credentials` for every token issued |
| Administration | users, groups, organizations, tenants, access, clients, providers, API tokens, invitations, `keys.rotate`, `keys.create` (every signing key made, scheduled ones too), `backup.download`, `backup.restore`, `cluster.force_start`, `org.primary` |
| Account self-service | `account.*`: passkeys, authenticator app, sessions, applications, connected providers, email verification |

Updates record what changed, field by field, as `changed.<field>` = `old → new` (`changed.role`, `changed.email`,
`changed.email_verified`, `changed.settings.require_mfa`, …). Fields that hold secrets never appear; a replaced
provider secret shows as `client_secret` = `replaced`.

Every event has:

- `outcome`: `failure` for refusals (`*.failure`, `*.refused`, `*.lockout`, `*.limited`, `*.replay`, `*.reuse`,
  `*.clone`), `success` otherwise;
- `request_id`: the request's id, also sent as the `X-Request-ID` response header (a trusted proxy's
  `X-Request-ID` is kept, so its logs and the audit log name a request alike);
- `user_agent` and `session_id` (the browser session the request was made in, or the one a sign-in created);
- `ip`.

Commands (`bootstrap`, `invite`, `set-primary`, `restore`) record who ran them: the actor is
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
- Each event has the stream fields `app` (`quisora`) and `org` (organization id), and the fields `action`, `outcome`,
  `actor`, `actor_id`, `target`, `ip`, `node`, `id`, `request_id`, `user_agent`, `session_id` and `detail.<name>`.

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
the master key. A restore needs the key it was made with (the active one, or, for a backup from before a
[master key rotation](#rotating-the-master-key), the old one put in `server.previous_master_keys` for the restore), and
refuses an altered file before writing anything.

A backup is encrypted with a password (AES-256-GCM, the key derived by argon2id), not with the master key: a
master key exposure does not open old backups, and a stolen backup needs its password. Keep the password apart from
the backups.

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
- `GET /api/v1/backup` needs either the password in the `X-Backup-Password` header (encrypted) or `?plain=1`
  (unencrypted); without one of them it answers 400.
- `quisora backup quisora.bak` without `--server` reads the configured store directly. On BadgerDB and SQLite, stop the node
  first.
- BadgerDB, SQLite, PostgreSQL, MySQL and MariaDB give a point-in-time snapshot. Valkey gives every record that
  existed throughout the backup.

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
