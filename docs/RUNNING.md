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
- The other commands take as flags only the settings they use (`quisora <command> --help`), and refuse the rest on the
  command line. `--config`, `--log-level` and `--log-format` are taken by every command. Every command reads the same
  config file and environment as serve, whole, and checks it the same way.
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
lasts 7 days). Each node's caps (10,000 emails and 10,000 logouts, 2,500 of each of one organization, and no more
than the room left for the other organizations, so a few at 2,500 cannot fill a queue between them) and gauges count
its own items only. Being the only node that writes its items, a node keeps an index of them in memory, read from the
store once at start: choosing what to send next and checking the caps cost no reads of the store, however many sent
items it still holds until its purge. A message or logout that was sent but whose end the store did not record (a
full disk, a database turned read-only) is not sent again: the node records its end again every minute until the
store takes it (only a restart before then sends it once more).

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
- **Service accounts** (automation that belongs to no person): [SERVICE-ACCOUNTS.md](SERVICE-ACCOUNTS.md).

Settings the guides refer to: `session.ttl`, `session.idle`, `session.privileged_ttl` and `session.privileged_idle`
(session lifetimes); `session.upstream_check_minutes` (leaver detection); `tokens.*` (token lifetimes and signing);
`tokens.api_token_max_days`; `[secrets.vault]` and `[secrets.onepassword]`.

Some settings are only the server's defaults: an organization can set its own in the console (**Organizations**, edit,
for super admins), and the server's applies wherever it has not. They are `limits.password_min_length`,
`limits.lockout_attempts`, `limits.lockout_minutes`, `limits.grants_per_user`, `tokens.api_token_max_days`,
`session.privileged_ttl` and `session.privileged_idle`. `ui.footer` is the default footer: an organization's administrators can set its own on its
overview's branding card, and an organization without one shows the primary organization's, else `ui.footer`. The primary organization's footer and skin,
which other organizations inherit, are changed by super admins only. TLS 1.2 connections are offered only the
forward-secret AES-GCM cipher suites (RFC 9325, as FAPI 2.0 requires); TLS 1.3 is unaffected. Behind a proxy that ends
TLS, the proxy's configuration decides.

## Limits and denied addresses

| Setting                       | Default | What                                                                                                   | On a reload          |
| ----------------------------- | ------- | ------------------------------------------------------------------------------------------------------ | -------------------- |
| `limits.max_in_flight`        | 4096    | Requests in progress on a node before it answers 503 (never the probes, metrics, discovery, JWKS or the console's event stream) | Next request         |
| `limits.max_in_flight_per_ip` | 0       | Of those, how many one address (an IPv6 /64) may have before its next gets 429 (0: a sixteenth of `limits.max_in_flight`, 256 by default), and an IPv6 /48 four times that, so one address (or the /64s of one allocation) sending slow request bodies cannot hold every place | Next request         |
| `limits.login_per_ip_min`     | 300     | Sign-in attempts per organization and address per minute (three times it per address across organizations; a browser that signed in to the account before counts against the account's own) | Next attempt         |
| `limits.lockout_attempts`     | 10      | Failed passwords before an account is locked (0: never)                                                | Next attempt         |
| `limits.lockout_minutes`      | 15      | How long the lock lasts                                                                                | Next attempt         |
| `limits.flows_per_ip`         | 50      | Sign-ins (authorization and device flows) one address may hold unfinished at once (0: no cap)           | Next sign-in         |
| `limits.held_kb`              | 2048    | Short-lived sign-in state, in KiB, one address (an IPv6 /64; its /48 sixteen times as much, its /32 sixty-four times) or one signed-in user may have the server hold at once (0: no cap; otherwise at least 64, and used as at most 1/128 of `limits.ephemeral_mb`, 8 KiB for each MiB, but never below 64: a larger value is lowered to that, not refused): see [health and monitoring](#health-and-monitoring) | Next request         |
| `limits.org_failures_per_minute` | 100  | Failed passwords per organization per minute before it counts as [under a spray](SECURITY.md#lockout-and-password-spraying) and limits failures per address too (0: never) | Next attempt         |
| `limits.password_min_length`  | 15      | Shortest password accepted (8 to 64)                                                                   | Next password set    |
| `limits.grants_per_user`      | 1000    | Refresh grants one user may hold                                                                       | Next grant           |
| `limits.sessions_per_user`    | 100     | Browser sessions one user may hold (1 to 10000); past it the least recently used end, never refusing a sign-in ([sessions](sign-in/README.md#sessions)) | Next sign-in         |
| `limits.password_workers`     | CPUs    | Passwords hashed at once                                                                               | Restart only         |
| `limits.ephemeral_mb`         | 1024    | Memory for short-lived sign-in state (with a shared database: the bytes of it each node writes there)  | Restart only         |
| `server.deny_networks`        | none    | Client addresses refused, below                                                                        | Next request         |

`server.deny_networks` lists IP addresses and CIDR ranges (`["203.0.113.7", "198.51.100.0/24", "2001:db8:bad::/48"]`)
whose requests get a bare 403 before anything else is done: no session or store read, no body read, no access log line
and no audit event, so a flood from them costs the node little and fills no log. The address is the client's as the
rest of the server sees it: behind `server.trust_proxy`, the one the proxies name in `X-Forwarded-For`; anyone else's
`X-Forwarded-For` is ignored. `/healthz`, `/readyz` and `/metrics` (which has its own token) answer every address, so a
load balancer or Prometheus in a denied network still sees the node. Each refusal counts in `quisora_http_denied_total`
(and not in `quisora_http_requests_total`); the counter has no address label (an address per label value would let an
attacker fill the metrics), and a refusal writes no log line, so a flood stays cheap. To find the addresses to deny, read
the client addresses (`ip`) in the request log (`log.access`) of the 429s and the other refusals, and in the audit log's
`login.failure`, `login.lockout` and `login.limited` entries. A range of every address (`0.0.0.0/0`, `::/0`) is refused as a mistake. The
list is checked one entry after another: it is for a handful of networks. A request is refused only after its TLS
handshake, so for many addresses (a botnet), or to save the handshakes, block them in a firewall or the proxy in front.

### Changing them without a restart

A reload reads the limits and `server.deny_networks` again from the config file and applies them to the running node:
SIGHUP (`kill -HUP <pid>`, see [reload or restart](#changing-the-keys-reload-or-restart)), or, on a gossip cluster or
nodes linked by `cluster.notify`, **Reload configuration** on the System page or `POST /api/cluster/reload`, which
reloads every node at once. **Each node reads its own file**: edit every node's file, then SIGHUP every node (or reload
them all at once).

- Nothing counted so far is reset: sign-in attempts in the current minute, an account's failed passwords, requests in
  flight. Tightening a limit applies to the next request against what has been counted already. A restart, by contrast,
  starts counters again: with gossip they live in the memory of the node that owns them
  ([REPLICATION.md](REPLICATION.md#short-lived-state)), so restarting nodes mid-attack hands the attacker fresh budgets.
- The file is checked first: one that does not parse, or a bad network or limit, fails the reload and nothing changes.
  The log says `configuration not (fully) reloaded` with `error` (such as `server.deny_networks: …` or `limits: …`).
  A reload that applies logs `configuration reloaded` with `changed`, for example `limits.login_per_ip_min 300 to 60`
  and `server.deny_networks [203.0.113.0/24]`; the console's report lists the same.
- `limits.password_workers` and `limits.ephemeral_mb` size the node when it starts: a reload that changes them keeps
  the old value, says so (`changed limits apply only after a restart`), and the new one applies at the next restart.
- As for the keys, values given on the command line or in `QUISORA_*` environment variables cannot change while the
  server runs: set limits and `server.deny_networks` in the config file to change them with a reload.

### Under attack

1. Find the source: the audit events (`login.limited`, `login.failure`, `oauth.client_auth.limited`,
   `api.request.refused`) and the access log name the address (`ip`); `quisora_audit_events_total`,
   `quisora_http_shed_total` and `quisora_http_shed_address_total` show the rate.
2. Deny it: add the address or its network to `server.deny_networks` in every node's file and reload every node.
   `quisora_http_denied_total` should start counting on each.
3. If it moves around, tighten the limits the same way: a lower `limits.login_per_ip_min`, `limits.lockout_attempts`,
   `limits.max_in_flight`, or `limits.held_kb` and `limits.flows_per_ip` when it is short-lived state being filled
   (`quisora_ephemeral_refused_total`). Reload rather than restart, so the counters keep what they have.
4. For more addresses than a short list, block them upstream (a firewall, the proxy or CDN in front).
5. Once it is over, take the entries out and reload again. The account steps (locking, signing out) are in
   [SECURITY.md](SECURITY.md).

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
  [rotating the cluster key](#rotating-the-cluster-key); `cluster.size` and `cluster.peers`: see
  [changing the cluster size](REPLICATION.md#changing-the-cluster-size); and on every node the limits and
  `server.deny_networks`: see [limits and denied addresses](#changing-them-without-a-restart)), from the config file
  and the `QUISORA_*` environment variables as at start-up. Nothing else is reloaded.
- Settings given on the command line (`--master-key`) cannot change while the server runs, so a reload leaves them
  alone and says so (the log, and the console's report): put them in the config file. Settings from environment
  variables cannot change either, since a running process keeps its environment; use the config file, or restart.
- A reload is refused, and the keys in use stay, when the new keys do not include the key in use: a typo or the
  wrong file cannot make a node seal with a key the others cannot open. The log says `master keys reloaded` (with
  the key ids), or `configuration not (fully) reloaded` with `error` `master keys: <the reason>` and `applied` the
  changes made before it.

### Is it done? When can the old key go?

Super admins see that a rotation is in progress on the **System overview**, which links to its status. The
same status is `GET /api/master-key` (super admin). It shows:

- the key every node seals with, and the previous keys every node holds;
- how many secrets the housekeeping leader has re-sealed so far (`resealed_secrets`), and when it last finished a
  walk over every stored record (`checked_at`, null until the first walk ends); `stale_secrets` (still sealed with a
  previous key) and `unopenable_secrets` (no configured key opens them) are what that walk found, so they say nothing
  until `checked_at` is set;
- a state: `waiting_for_nodes`, `resealing`, `unopenable`, `complete` (with
  `previous_keys_removable: true`: remove them now) or `none` (no rotation in progress).

The status is cheap: it reads the leader's last report (any node answers it), not the stored secrets, so the console
may poll it. A reload that removes a key is refused until a walk that began after the keys changed has ended with
nothing left and every node seals with the active key (the error says so).

**How long it takes.** The leader re-seals in passes, each for at most a third of its minute-long housekeeping tick
(20 seconds), and the next pass goes on where the last one stopped; a walk that finds nothing left ends the work, and
nothing is read again until the keys change. Measured on one BadgerDB node, a re-seal runs at about 3,000 users per
second (a user's authenticator secret and password hash are re-sealed in one write: about 6,500 secrets per second),
so a million users take about 5 minutes of writing, which at 20 seconds in every 60 is about **15 minutes**; add
about as much again for each million upstream identities and grants. A gossip cluster or a shared SQL database writes
more slowly (every write is replicated, or a network round trip), and each pass then gets through fewer records: that
was not measured, so watch it.
Watch it in `resealed_secrets` (status page, API) and the leader's log line `master key: secrets re-sealed with the
active key`, which gives each pass's count (`resealed`) and the total since the keys changed (`resealed_total`); the
state turns `complete` when the walk ends. A leader that changes, or restarts, begins its walk again; what it finds
already re-sealed it only reads (about 300,000 users per second).

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

3. When the status says `complete` (a few seconds for a small installation: [how long it takes](#is-it-done-when-can-the-old-key-go)), remove `previous_master_keys`, and reload or restart.

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
- If the old key was exposed, rotating it is not enough: a copy of the database or a backup from before the rotation
  still opens with it, and the secrets it sealed are unchanged. Follow the list in
  [incident response](SECURITY.md#incident-response) ("The master key may be exposed").
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

The primary organization is the first one, made by `quisora bootstrap`, and it never changes. Its id is made at that
bootstrap, like any other (each installation's is its own), and kept in its record, which marks it as the primary one:
every node reads it from the database it shares or the data set it copies, and a backup carries it, so a restored
server keeps the same primary organization, with the same id. A node that does not know it yet (not set up, or a new
gossip node still copying) is not ready. Its sign-in page is `/o/<id>/login` (what `https://<public_url>/` redirects
to; `/o/primary/login` by its name works too, until it is renamed) and its issuer `<public_url>/o/<id>`. Super
admins belong to it, and the server's emergency sign-out counters are kept on it. When its super admins are all gone, `quisora invite
--break-glass --super-admin` (above) recovers access.

## Storage backends

Pick one with `storage.backend` (`--storage`). The tables or keys are created on first start; the database itself
must exist. [DATABASE.md](DATABASE.md) lists the tables and what each one holds.

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
| ---------- | ----------------------------------------------- | ------------------------------ |
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
  admin console pages within moments. A lost notice only waits for a cache to expire.
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
- **Every node has its own id**: a data directory or machine image copied to a second node carries the first's `node_id`
  (so does one `cluster.node_id` in a configuration both read), and the two would each deliver every queued email and
  logout and share the per-organization caps. Delete `node_id` from the copy (a new one is made at its start) or set
  `cluster.node_id`. Nodes that share one database without gossip notice: each keeps a record of its id in the database,
  renewed every 10 seconds, and a node that finds its id held by another running node refuses to start (after waiting
  up to 40 seconds for the record of a node that was killed to run out) or, already running, reports itself not ready
  until that has passed. A node that shuts down cleanly releases its id at once. A gossip node does not use the record:
  each has its own database (queued items are in it), and a database two gossip nodes share is refused (above).
- **Clocks** must be in sync (NTP); more than 5 s apart is a broken node, and gossip refuses packets more than two minutes off
  the receiver's clock. ([Clocks](REPLICATION.md#clocks))
  Nodes that share one database without gossip have no peers to compare with, but they stamp expiries (a 60 s
  `request_uri`, a 60 s code, short-lived state, the housekeeping lease) with their own clocks, so a node whose clock is
  off sees them expire early or late: sign-ins fail on one node and work on another. Each therefore reads the database
  server's clock every 10 seconds and, when its own is more than 5 s off, reports itself not ready (`/readyz` 503) and
  logs `refusing to serve` with the offset, until it is within 2.5 s again; `/readyz` shows `clock_offset_ms`. Fix the
  node's time synchronisation (NTP), and the database server's own.
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

A node that has not formed the cluster (it has no data set yet, or sees fewer than a majority of the nodes) logs
`cluster peers not in view` a minute after starting and every minute after, with the `peers` of `cluster.peers` it
cannot see. Each is not started, not reachable on its cluster address, or has another `cluster.key`: nodes with
different keys drop each other's packets as undecryptable and never meet: compare the key ids each node lists under
`cluster_keys` (system overview, `GET /api/cluster`).

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

- The log says `cluster keys reloaded` (with the key ids: 8 characters derived from each key, revealing nothing), or
  `configuration not (fully) reloaded` with `error` `cluster keys: <the reason>`. The system overview (and `GET /api/cluster`) lists each node's key ids
  under `cluster_keys`, the one that encrypts first.
- A reload is refused when the new keys do not include the key in use: a typo cannot cut a node off. Keys given on the
  command line cannot be reloaded.
- A node started (or restarted) during a rotation must be given that round's keys; one that misses a round cannot
  talk to the others until it is given them, and comes back by itself once it is.

## Audit log

Every audit event is written to the structured log (`log.format = "json"` for log shippers). The admin console's audit
pages read it from one of two places:

|                           | Database (default)                                                                            | VictoriaLogs                                    |
| ------------------------- | --------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| For                       | Development, home labs, testing                                                               | Production; required for a retained audit trail |
| Kept                      | `audit.retention_days` (90)                                                                   | VictoriaLogs' `-retentionPeriod`                |
| One node, shared database | In the database                                                                               | Sent to VictoriaLogs; nothing in the database   |
| Gossip cluster            | Each node keeps its own events (never replicated, purged by that node); a page asks every node of the cluster and merges their answers, and says which did not answer | Every node sends; any node reads                |

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

Every organization's pages read the same log (VictoriaLogs, or every node's database), so they are read on budgets: an
organization's administrators share 120 pages a minute across the cluster (the console, the management API and the
MCP server's `query_audit_log` together; a search as you type counts each page it loads), of which each
administrator (through the console or any token of theirs) or service account may read 60, so one of them cannot
spend the whole budget and hold the others out of their own log; two of them reading flat out still can. Each super
admin has 120 of their own. Each node also reads at most 2 pages of one budget at once, and 16 in all, of which 4 are
kept for the super admins: the organizations' pages together take at most 12, so however many organizations search
slowly at once, the operators can still read any log. A page that takes longer than 15 seconds to read (or to count
against its budget) is given up (503 with `Retry-After`; try a shorter time range), so a place is held that long at
most (the database trail ends the read when the database notices). In a gossip cluster without VictoriaLogs a page
also asks every other node for its events, outside that node's places: each node answers another within the
asker's 3-second wait (4 seconds at most, then the query is ended) and at most 8 such requests at once, 4 of one
organization's log, answering the rest busy at once (the page then says that node did not answer), so pages
abandoned at the wait cannot pile up as queries on the other nodes. Past a limit the page is refused at once with 429 and `Retry-After` (60 seconds for the
budget or an administrator's share of it, 2 for the node's places), rather than add to the load on a log that every
organization shares. Only a page that is read is counted: one refused for want of a place, as not permitted (a
manager's) or by its administrator's own share spends nothing of the organization's budget.

What remains: six organizations each running two slow searches at once on a node hold the organizations' 12 places
there, and the other organizations' pages on that node are answered 429 until one ends (15 seconds at most; the
console tries again every 2 seconds, and the refusals cost nothing). A budget whose count cannot be read (the store
is unreachable) answers 503, as with the other rate limits. Unlike them, a count that cannot be kept because the
node's rate-limit counters are at their cap (`quisora_ephemeral_refused_total{reason="counters"}`: a flood of
requests from many addresses) does not refuse the page: a flood on the sign-in pages must not take the audit log
away from the administrators who need it then, and the places and the 15 seconds still bound the load.

**Production, and any deployment whose compliance standard or security policy requires a retained audit trail, must
use VictoriaLogs.** The database audit trail keeps events for
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
  never receive, or one logged because the spool's disk did not answer in time (the `reason` says which), in full so
  it can still be captured from the log.

### What is recorded

| Area | Events |
| --- | --- |
| Sign-in | `login.success` (default on; `audit.logins = false` turns it off), `login.failure` (a wrong credential, reasons `bad password`, `unknown user`, `inactive`, `totp`, `recovery_code` and `email_code`; an attempt refused as locked, reasons `locked` and `address locked`; and the passkey and provider refusals of [passkeys](sign-in/passkeys.md) and [providers](sign-in/providers.md)), `login.lockout` (an account locked by the failure that tripped it: always recorded, even when that failure is held back), `login.limited` (a sign-in rate limit started refusing: once per limit and minute), `org.spray.start` and `org.spray.end` (an organization's sign-in came under a password spray, and when it was over: [lockout](SECURITY.md#lockout-and-password-spraying)), `logout`, `login.session.evict` (a session ended because its user held more than `limits.sessions_per_user`: the least recently used), `passkey.clone` (a copied authenticator, at sign-in or while confirming it is the user), `login.recovery_code`, `mfa.import` (an authenticator secret imported with a new user: [API-TOKENS.md](API-TOKENS.md#importing-users-with-their-passwords-authenticator-apps-and-provider-links-import)), `login.email_code.sent`, `password.forgot`, `password.reset`, `invite.accept` |
| OAuth / OpenID Connect | `oauth.consent` (allow or deny), `oauth.grant` (every code exchange), `oauth.token_exchange` (every token exchange), `oauth.device.approve` (a device sign-in approved), `oauth.revoke`, `oauth.grant.evict` (a grant ended because its user held too many: [how many](oauth/sign-in.md#refreshing)), `oauth.code.replay` and `oauth.refresh.reuse` (a code or refresh token presented again: its grant is revoked), `oauth.client_auth.limited` (a client's failed authentications reached the limit); with `audit.tokens = true` also `oauth.refresh` and `oauth.client_credentials` for every token issued, and `oauth.device.start` for every device sign-in started |
| Administration | users, groups, organizations, tenants, access, clients, providers, API tokens, service accounts (`service_account.create`, `.update`, `.secret.rotate`, `.delete`), invitations, `user.locked_out`, `keys.rotate`, `keys.create` (every signing key made, scheduled ones too), `keys.remove`, tenants' SSH certificate authorities (`ssh.settings.update`, `ssh.ca.create`, `ssh.ca.rotate`, `ssh.ca.remove`, `ssh.cert.issue`, `ssh.cert.revoke`, `ssh.cert.refused`, `ssh.host.issue`, `ssh.host.refused`: [SSH certificates](ssh/README.md#what-is-recorded)), `backup.download`, `backup.restore`, `cluster.force_start`, `cluster.reload` (and `cluster.reload.failure`, with each node's report), `config.reload` (and `config.reload.failure`: one node's SIGHUP reload, with the node and what changed; compare nodes after an incident) |
| API access | `api.request.refused` (a management API or SCIM request refused for an authenticated caller: a token without the scope, a request without the CSRF header, a console session without a second factor, a SCIM token whose owner lost the role; with the method, path and reason), `apitoken.refused` (a token that exists presented with a wrong secret, or after an emergency sign-out, or after its owner was disabled or demoted). Both at most once a minute per token or caller and reason on each node, with `detail.suppressed` counting the repeats held back (refusals held back because the node was already tracking 10,000 refusing keys at once, or 2,500 of one organization, are counted in `quisora_audit_refusals_dropped_total`, and logged at most once a minute): anyone can repeat a refusal, and the audit log must not be the thing they flood |
| Emergency sign-out | `org.signout` and `server.signout` (with the reason, and whether API tokens ended too), then `signout.sweep` (how many sessions, grants and API tokens were deleted) |
| Account self-service | `account.*`: passkeys, authenticator app, recovery codes, sessions, applications, connected providers, email verification |

Wrong credentials and lockout refusals can be repeated at will (with `limits.lockout_attempts = 0` nothing locks), so
each node records at most one a minute per key, sign-in step (password, authenticator code, recovery code, emailed
code) and client address (an IPv6 /64 counts as one address), the next with `detail.suppressed` counting the repeats
held back. The key is an account (a browser it signed in from before counts apart from strangers'), a login that
names no account, or, for `address locked`, the address in that organization; nothing else a request can vary (the
organization's name spelled in another case, the email address typed in another case) makes another key for the same
account. The address is part of what is counted so that **every address that sends a wrong credential or is refused
is named by an event in that minute**: an address that sends one wrong password first does not take the account's
only event and leave the address that sends the rest unnamed.

What one address can have recorded is bounded in turn, in each organization and on each node: 20 events a minute
about existing accounts and 5 about logins that name no account (those are made up by whoever sends them, so the
events are a sample of what the address tries), wrong credentials and lockout refusals each. An IPv6 address counts
by its /48 here (its events still name the /64): a provider hands out a /48 as readily as a /64. The event after
those names the address once more and says so (`detail.address_limit`), and then none until the minute is over; the
address's next event says how many were held back (`detail.address_suppressed`). An organization's allowance is
bounded the same way: **at most 200 events a minute naming addresses in each of the four kinds below, per
organization, per node**, however many addresses send them.

An event that cannot name its address (the address's allowance is spent, or the organization's, or the node's
limiter is full) is recorded once a minute without it: **an existing account's once a minute per sign-in step**,
naming whichever address came first, with `detail.suppressed` counting the rest, so an address cannot spend its
allowance on decoy accounts (its own, say) and then guess at its target unseen; and the events that name no account
once a minute per organization and step (a provider's callback with a state that is not valid, a real provider's
`upstream not_linked`, a passkey nobody holds: each step its own), so a flood of made-up logins cannot hide a real
provider's failures. That event says how many addresses the organization's allowance left unnamed in the minute so
far (`detail.addresses_unnamed`, as many as the node could tell apart).

So the worst case scales with the addresses and the real accounts, never with the attempts:

- **Per client address, per organization it tries, per node: at most 54 events a minute naming it** (27
  wrong-credential events: 20 + 1 for accounts and 5 + 1 for other logins; and 27 lockout refusals, the same way),
  and an account is named in at most 20 + 1 of them per address that tries it, however many sign-in steps it tries.
  Past that, the address can still be the one named by an account's event without its address, once a minute per
  account and step it tries, if it gets there first.
- **Per organization, per node, a minute**: 200 events naming addresses in each of the four kinds (wrong credentials
  and lockout refusals, of existing accounts and of the rest: 800), one per sign-in step without an address for the
  logins that name no account, and one per existing account and step without an address (at most 2,500 a kind:
  a guess at every account of a large organization from addresses past their allowance costs one event per account
  and step).
- **Per node, a minute**: each of the four kinds holds at most 10,000 keys and 10,000 addresses at once, and one
  organization at most 2,500 of each, so one organization's flood leaves the others' events as they were. That is
  at most 10,000 events naming addresses and 10,000 without, a kind, and only with 50 organizations flooded at once.

A cluster records as many times that as it has nodes. An attacker with many addresses (a botnet, or many /48s) has
them named until the organization's 200 events a minute are spent; past that they are counted, not named, and
`server.deny_networks` takes a range. Every wrong credential and every lockout refusal is still counted in
`quisora_audit_events_total{action="login.failure"}`, held back or not.

A real account's events are kept apart from those of logins that name no account and of addresses, and wrong
credentials apart from lockout refusals, so a flood of one kind cannot crowd out another. Past the caps above, a
kind's events of new addresses are counted in `quisora_audit_refusals_dropped_total` and logged at most once a minute
(naming the limiter and the organization); an existing account's events are still recorded once a minute per
sign-in step, naming one of the addresses, not all of them. The other sign-in
failures anyone can repeat are recorded the same way (per client address too), by a fixed step name: a provider's callback with a state that is
not valid (per organization and address, whatever state, code or provider the request names), a provider sign-in
that failed after a valid state (per organization and kind of failure, or per account once one is known), a passkey
that did not verify (per account, or per organization for a credential that names none: the event is then in the
organization whose sign-in page was used), and a second factor that can no longer be used or set up.

An audit event's detail values are bounded: each at 4 KiB and all of them at 16 KiB; past that the longest values are
cut to one length (a short value is never cut to make room for a long one), end in `…`, and the event's
`detail.clipped` names each one cut with its full length and the start of its SHA-256, so a cut is never silent and
can be matched against the value itself. No event of the server's own comes near the caps: they bound what a request
could make an event hold, since some events anyone can cause and each is kept for the retention.

Updates record what changed, field by field, as `changed.<field>` = `old → new` (`changed.role`, `changed.email`,
`changed.email_verified`, `changed.settings.require_mfa`, …). Fields that hold secrets never appear; a replaced
provider secret shows as `client_secret` = `replaced`.

Every event has:

- `outcome`: `failure` for refusals (`*.failure`, `*.refused`, `*.lockout`, `*.limited`, `*.replay`, `*.reuse`,
  `*.clone`) and a password spray (`org.spray.*`), `success` otherwise;
- `request_id`: the request's id, also sent as the `X-Request-ID` response header (a trusted proxy's
  `X-Request-ID` is kept, so its logs and the audit log name a request alike);
- `user_agent` and `session_id` (the browser session the request was made in, or the one a sign-in created);
- `detail.token_id` when a personal API token made the change (or was refused); a service account's changes name it as the
  actor, `service:<name>` ([SERVICE-ACCOUNTS.md](SERVICE-ACCOUNTS.md#auditing));
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
  is the last place it goes: ship the structured log, or such events are lost. (An event logged because the spool's
  disk did not answer in time is written the same way and reaches VictoriaLogs as well once the disk answers: its
  `reason` says so.)

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
  once the disk answers, so it then reaches VictoriaLogs as well (a duplicate, by `id`; never a loss). One such wait is
  enough to know the disk is hung: until it has an event on disk within 2 seconds of the event being queued again,
  the events after it go the same way without the wait (queued for the spool, while the queue has room, and logged at
  once), so a hung disk slows one request, not every one. The log says when this starts (`the audit spool disk did
  not answer in time`) and ends (`the audit spool disk answers again`). A disk that answers but keeps events waiting
  longer than 2 seconds (each write a second or more, under load) stays in this state until it keeps up again, rather
  than going in and out of it. These events are counted in `quisora_audit_undelivered_total` like the others, though
  they are delivered as well.
- The spool could not be written (a full or failing disk, a failed sync of the file or of the directory). The failed
  write is undone, so the log is that event's only copy; a crash before the log is shipped loses it from VictoriaLogs.
- The spool had to make room (below), or the spool queue was full.
- VictoriaLogs refused an event for what is in it (400, 413, 422): it would never take it, so it leaves the spool
  (logged with VictoriaLogs' answer) rather than hold back everything after it. A batch it refuses is sent again in
  halves, and the halves it refuses in halves again, so the events it takes are delivered and only those it refuses
  are logged. The requests are bounded: a batch starts with 64 and earns 2 for every part VictoriaLogs takes, up to
  512, which finds up to 33 refused events wherever they lie in a full segment (2,000 to 3,500 events) and loses no
  other. Once they are spent, each part left is sent once more and logged as refused if VictoriaLogs still refuses
  it, good events in it included (a batch refused for something every event in it has earns nothing, and is not sent
  event by event: about 75 requests, then logged). VictoriaLogs being unreachable or failing part-way is an outage:
  the batch stays in the spool and is sent again later.
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

- A backup is always encrypted: there is no unencrypted form. A stolen backup holds every account and audit event,
  and its secrets are only as safe as the master key that seals them, which is often kept nearby.
- `--server` sends the password over TLS and the server encrypts the stream; the download is checked with the
  password as it arrives.
- `GET /api/backup` needs the password in the `X-Backup-Password` header; without it, it answers 400.
- `quisora backup quisora.bak` without `--server` reads the configured store directly. On BadgerDB and SQLite, stop the node
  first.
- Every backend gives a point-in-time snapshot: the backup is consistent.
- **A backup holds one database snapshot open for its whole run**, and `--server` streams it to the client as it reads, so
  a large store or a slow downloader makes the run last minutes. For all that time the database cannot clean up what
  changed since: PostgreSQL keeps the old row versions (table and index bloat, until the snapshot ends and vacuum
  catches up), MySQL and MariaDB keep their undo log growing (history list length), and SQLite's WAL cannot be
  checkpointed past the snapshot, so the `-wal` file grows with every write. So:
  - take backups when traffic is lowest (the cron example below is at 02:30);
  - over a slow link (a backup machine far from the server, a throttled download), do not stream it: run
    `quisora backup quisora.bak` without `--server` on a host close to the database (it needs the same configuration,
    and on BadgerDB and SQLite the node stopped), then copy the finished file;
  - watch the database while one runs, and alert on it: the size of SQLite's `-wal` file, PostgreSQL's oldest
    transaction (`pg_stat_activity.xact_start`) and dead tuples, MySQL's history list length. A backup that takes
    noticeably longer than it used to is the first sign.

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
- Unencrypted backups from pre-release builds (written with `--plain`) are refused: every backup is encrypted.

- Ids and versions are kept, into any backend (a BadgerDB backup can go into PostgreSQL).
- The backup is checked as it is copied to a private file in the data directory (`quisora-restore-…`, as large as the
  backup file, removed when the restore ends; not `TMPDIR`, which may be a `tmpfs` held in memory), and the records are
  written from that copy: a file changed after the check is never what is restored. Leave room for it there. A copy an
  interrupted restore left is removed when the next one starts.
- A restore that fails part-way leaves `restore-incomplete` in the data directory. Empty the store before trying again.
- **A restore brings back the state of the backup's time**: refresh tokens and grants revoked since, sessions and
  API tokens ended since (the [emergency sign-out](emergency-sign-out.md) counters go back too), passwords, second
  factors and passkeys changed or removed since, and accounts disabled since. Only an audit note (`backup.restore`)
  says it happened. After restoring a backup that is not from moments ago, sign everyone out
  ([`quisora sign-out --all --api-tokens`](emergency-sign-out.md#from-the-command-line), or **System overview** →
  **Sign everyone out…** once it serves), and review the accounts and credentials changed since the backup was made.
  A forced restore over data (`--force`) brings back each record the store holds an older version of or no longer
  holds at all (a deletion whose tombstone has been purged included), so the same applies to it.
- **Clusters always restore into an empty cluster.**
  - Shared database: restore into the empty database, then start the nodes.
  - Gossip: restore into one node with an empty database (a restore never goes over data, nor on a node that already holds a
    data set) and start it, and start the others with empty databases. The restore writes the records as the first writes of
    their partitions, of a new data set, which the other nodes adopt and copy.
  - A restored node that meets a cluster of another data set exchanges nothing with it and refuses to serve ("another data set
    is in view").
- **Tenants that use [SSH certificates](ssh/README.md) need steps after a restore from an older backup.** The backup holds
  the CA keys, certificate records and revocations as they were then, so a restore can republish a CA key that was removed
  since (and its private half), undo revocations made since, and know nothing of the certificates issued after the backup,
  which then cannot be revoked by serial. For each such tenant: rotate the user CA key (and the host key) immediately,
  remove the old keys, which makes the revocation list revoke them outright on every server that fetches it, re-revoke
  what was revoked since, and have everyone sign in again ([Backup and restore](ssh/README.md#backup-and-restore)).

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
- **Brute-force windows restart.** With gossip, sign-in rate-limit and lockout counters live in the memory of the
  node that owns them ([REPLICATION.md](REPLICATION.md#short-lived-state)); every node that stops during a rolling upgrade
  hands its counters' windows to a new owner, which starts them from nothing. An attacker who watched the upgrade
  could try again sooner than `limits.lockout_minutes` allows. Watch `login.limited` and `login.lockout` across an
  upgrade, and keep upgrades short. To change a limit, reload instead: that keeps every counter
  ([limits and denied addresses](#changing-them-without-a-restart)).

### Changing a stored format (for developers)

Until the first release, formats change in place. From then on:

- A record field that can be added with a sensible zero value needs nothing: older records read as the zero value.
  Renaming, removing or re-interpreting one needs a migration, on every backend:
  - BadgerDB: append to `formatMigrations` (`internal/store/kvstore/kvstore.go`);
  - SQL: append to `migrations()` (`internal/store/sqlstore/migrate.go`): statements, and Go code for data.
- **Making an existing field a column or an index (something a list can filter or sort by) needs a data migration that
  backfills it.** The SQL stores add a new column to existing tables with its zero value and never fill it in from the
  stored records (`reconcile` in `internal/store/sqlstore/reconcile.go`; the real value stays in the record's data
  until the record is next written), so a SQL listing that filters on it silently misses every old record. BadgerDB
  misses them too: it keeps each record's index fields as they were computed when the record was written, and filters
  and indexes by those, so an old record has neither the field nor its index entries until it is written again. Nothing
  reports an error. Put the backfill in the same migration as the change, in both places above: on SQL a `data` step
  of `migrations()` that reads each record and writes the column (and, for a unique value, its row in the unique
  table); on BadgerDB a `formatMigrations` step that calls `rewriteRecords` for the kind, which recomputes the stored
  index fields and entries from each record's data. Test it by creating records with the old build's schema, opening the store with the new one,
  and listing by the new field on every backend.
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
emailed: administrators share invitation links themselves, and there is no self-service password reset. What the emails
say and look like is set per organization, over the primary organization's defaults: [EMAILS.md](EMAILS.md). An
organization's administration (its administrators, managers and service accounts) has it email at most 300 invitations
and verification links an hour to the addresses it enters, then 429 ([EMAILS.md](EMAILS.md#limits)). "Forgot your
password?" sends an account at most 5 reset emails an hour for the requests of one address, and 20 an hour in all,
then 3 more an hour for addresses that have not asked for it in the hour, one each: anyone who knows the address can
ask for a reset, but cannot use up the owner's own requests from another address (a few addresses spending the 20
leave the owner's first request from where they are its place), nor flood the inbox (23 an hour at most). The form
answers the same either way.

Email is queued in the store before the request that sends it answers, as the sending node's own ([Queued work](#queued-work)),
sealed with the master key (messages carry single-use links). A message SMTP does not take is retried after 1, 5, 30
and 120 minutes, then given up and logged (`mail delivery failed, giving up`). A restart, or a crash, keeps the queue:
the node sends what is left when it is back (a message whose sending was cut short by the crash may go out twice).
When the master keys change (a start with new keys, or a reload) each node re-seals its own queue with the active key
before it reports that key, so a rotation reported complete leaves no queued message needing the old key. A message
sealed under a key that is not configured (one removed too early, or a node that was down during the rotation started
without it) is kept and logged, and sent once that key is put back in `previous_master_keys`. Each node holds at most
10,000 messages, of which one organization may have 2,500, and no more than the room left for the others: the
organizations busy at once leave each new one at least half of the room they left, so it takes many of them, not four,
to refuse everyone's mail; past that, new ones (of that organization) are refused with an error. Messages go out 8 at a
time, at most 2 of them for one organization, each over a connection of its own, and a free sender goes first to an
organization with none of its mail being sent: an organization's burst (thousands of invitations, or password resets
asked for address after address) fills only its share, and the other organizations' messages go out beside the
backlogs rather than behind them. All organizations share
the one SMTP server, though: when it is slow or down every organization's mail waits alike. A message whose sign-in
code or link has expired by the time its turn comes is dropped, not sent (`mail not sent: what it carries expired while
it was queued`), so mail SMTP takes again after an outage is what still works. Watch `quisora_mail_queued`: growing
means SMTP is not taking mail.

## Health and monitoring

- `/healthz`: liveness.
- `/readyz`: readiness, cluster-aware. Route load balancers on it. It reports size, quorum, the partitions this node owns and
  counts of writes whose outcome is unknown, refusals and clock skew.
- `GET /api/cluster` (super admins) and the console's settings page: the node's cluster status.
- The probes, metrics, discovery and JWKS are never shed under load (`limits.max_in_flight`, default 4096 per node).
  One address (an IPv6 /64) may have at most `limits.max_in_flight_per_ip` of those requests in progress (a sixteenth
  of them by default), and one IPv6 /48 four times that, whatever /64s of it they come from; its next gets 429 with
  `Retry-After` (`quisora_http_shed_address_total`). A request holds its
  place before its body is read, so without this an address sending bodies a byte at a time could hold every place
  until the read timeout (30 s) and keep everyone else out. Behind a proxy, set `server.trust_proxy`, or every client
  counts as the proxy's address.
- Short-lived sign-in state (flows, codes, challenges) is held in each node's memory up to
  `limits.ephemeral_mb` (default 1024 MiB); past it, requests that would add to it get 503 with `Retry-After` (a
  page, or `temporarily_unavailable` from the OAuth endpoints) until expiries make room, and the node logs a warning
  (`this node's short-lived state is full`) at most once a minute. Rate-limit counters are kept apart: they never
  count against that limit (however many there are, they cannot refuse a sign-in its state) and are never refused
  because sign-in state filled it. But whoever is limited often chooses their keys, so their memory has a cap of its
  own, `limits.ephemeral_mb` again, or 16 MiB if that is more (so a node holds at most `limits.ephemeral_mb` of
  sign-in state plus that much of counters, and the caches' cap below). Past the cap a new counter is not made and
  its limit refuses (it fails closed; counters already held go on counting), counted as
  `quisora_ephemeral_refused_total{reason="counters"}` and logged at most once a minute. Short-lived caches (client
  metadata documents read in the last minute, [MCP.md](MCP.md)) are kept apart too, under a cap of their own: a
  sixteenth of `limits.ephemeral_mb`, at least 4 MiB (`quisora_ephemeral_cache_bytes` against
  `quisora_ephemeral_cache_limit_bytes`). At it a new entry takes the room of the oldest ones, which go (nothing is
  refused: an entry evicted only saves a read, which the next request that needs it does again, within its limits),
  and the node logs that at most once a minute; only an entry larger than the whole cap is not kept, counted as
  `quisora_ephemeral_refused_total{reason="cache"}`. The records protections rest on (that an authorization code was used, so that
  its replay ends what it issued; when a device last polled, for `slow_down`; that an organization is under a
  password spray) are kept apart in the same way, under a quarter of `limits.ephemeral_mb` (at least 16 MiB): sign-in
  state that fills the node never switches those protections off. Past their own cap they fail closed (a code is not
  redeemed: 503 `temporarily_unavailable`, and is still there for the retry; a poll is told to slow down), counted as
  `quisora_ephemeral_refused_total{reason="guard"}` and logged at most once a minute. A spray whose record cannot be
  kept there is remembered by a counter instead, so the spray limit holds (for a lockout time from the minute over
  the limit whose record could not be kept, and again from the next; its end is then not audited). What one requester may keep among these records is
  bounded apart from the rest of what it holds, at a sixteenth of `limits.held_kb` (at least 32 KiB): the records of
  a code's use are charged to the code's user when the code is redeemed, and kept for 20 minutes (every code has
  expired by then: `tokens.code_ttl` is at most ten), and a device sign-in's poll record to the address that started
  it. Past it a code is not redeemed (429 `temporarily_unavailable` with `Retry-After`, the code still there) or a
  device sign-in not started (429 `slow_down`): about 170 redemptions per user in 20 minutes by default, some 40 at
  the smallest `limits.held_kb`. So filling these records' room, which would refuse every redemption on the node,
  takes about a thousand accounts redeeming codes as fast as they are allowed at the defaults, and never fewer than
  about 250 however the two limits are set, not a few dozen. With a shared database this state lives in the database instead, a row each until it
  expires, and the same budgets apply to the rows each node writes there: `limits.ephemeral_mb` for sign-in state,
  the counters' cap, the caches' cap and the guard records' cap, with the same refusals, warnings and metrics (a
  full cache there makes room too: the oldest rows the node wrote are deleted for a new one). Each node counts what it wrote
  itself (its size and expiry, as it would count its memory), so the nodes together may write up to their number times
  the budgets, and a row another node takes or deletes stays counted by the node that wrote it until it expires. A
  pushed authorization request (PAR) holds nothing: its request_uri carries the request, sealed (docs/oauth/par.md).
- What one requester can have a node hold is bounded in bytes, not only by how fast it may ask. Everything kept for
  a request nobody has signed in for (a sign-in flow, the state of a sign-in under way at a provider, a passkey
  challenge, the ticket of a second sign-in step, a device sign-in waiting to be approved) is charged to the client
  address, and what a signed-in user has kept (authorization codes, a sign-out waiting for its confirmation,
  challenges and provider connections begun from the account page) to the user: at most `limits.held_kb` each
  (default 2048 KiB, 0 turns it off). Past it the request that would add more gets 429 with `Retry-After` (a page, a JSON error, or
  `slow_down` from the device authorization endpoint) set to the seconds until the window that refused it turns
  (below), when the requester may hold more again, counted as
  `quisora_ephemeral_refused_total{reason="held_bytes"}`; nobody else is refused anything. A charge whose counter
  could not be updated (too contended, or past the counters' cap) says nothing of what the requester holds: that
  request gets 503 with a short `Retry-After`, counted where the counter was refused (`counters` or `contended`). An IPv6 /64 counts as one
  address, its /48 may hold sixteen times `limits.held_kb` in all and its /32 sixty-four times, so one allocation's
  65,536 /64s do not bring a budget each, nor a provider's 65,536 /48s. The count is kept in 20-minute windows (the
  longest any of this lives), and what ends early (a sign-in finished or cancelled, a challenge answered, a second
  factor given, a device's tokens collected, a sign-out confirmed) gives its bytes back to the window it was counted
  in, so a requester holds at most twice the budget, across the turn of a window, and an office behind one address
  that finishes its sign-ins is never near it: a sign-in in progress is about 1 KiB, so the default is some two
  thousand of them at once. What is abandoned stays counted until its window turns. That is the price of a budget
  per address where many people share one (an office, a mobile provider's address translation, one provider's IPv6
  /32): they share the budget, and whoever among them starts sign-ins and leaves them unfinished can use it up for
  the others, for up to 20 minutes after they stop (429 for new sign-ins from that address; nobody elsewhere is
  refused). Raise `limits.held_kb` where that many people sign in from one address. Authorization codes are counted
  apart, in windows of their own lifetime (`tokens.code_ttl`), and given back when redeemed: any page can send a
  signed-in browser to an application its user allowed before and have a code issued, so codes nobody redeems come
  back to their user within two code lifetimes instead of holding the user's sign-ins up for 20 minutes. The count
  is the cluster's, not each node's (it lives on the node that owns the requester's counter, or in the shared
  database); with gossip, each time that owner changes within a window (a node stops serving or starts) the
  requester may hold up to one more budget until the window's entries expire, since the new owner counts from
  nothing. The requester's own parameters are kept at their own length (no escaping that would make each `<`, `>`
  or `&` six bytes), and the caps on them (`state` 2048, `nonce` 1024, `login_hint` 256, a path to return to 2048)
  are on what they take stored. A session has one sign-out confirmation waiting at a time, whatever asks for it.
- A sign-in started at an authorization endpoint (or a device code's verification page) holds a flow for up to 20
  minutes from its start, until it finishes (the steps in between do not extend it). One client address holds at
  most `limits.flows_per_ip` (default 50; an IPv6 /64 counts as one address, its /48 may hold sixteen times as many
  and its /32 sixty-four times; 0 turns it off) at once, within its `limits.held_kb`; past it new ones get 429 until one finishes or expires, so a few addresses cannot fill
  `limits.ephemeral_mb` with sign-ins they never finish. Starting them is limited too, to 300 a minute per address
  (and per IPv6 /48 sixty-four times that: see below). It is counted as `limits.held_kb` is (an address may hold up to twice it across the turn of a 20-minute window, and
  ending old flows never buys room for more than the limit). Behind a proxy set `server.trust_proxy`, or every user
  shares the proxy's address, its flows and its `limits.held_kb`.
- The OAuth endpoints' limits per address that anyone can spend before signing in count an IPv6 address by its /64
  and its /48 as well, so the 65,536 /64s of one allocation do not each bring a share of their own. The /48's share
  is a factor of the address's: **four times** for what is rare or holds state (self-registrations, 40 a minute;
  metadata documents read for apps not stored yet, 80 a minute; device sign-ins started, 120 a minute; wrong device
  codes, 80 per 15 minutes; a public client's pushed authorization requests, 240 a minute), and **sixty-four times**
  for request rates already high per address that hold nothing (authorization requests, 19,200 a minute; failed
  client authentications and public clients' failed token requests, 19,200 a minute before public clients are
  refused, 192,000 before nothing is looked at). A /48 is often a whole organization's network (a university, a
  company): everyone on it shares the /48's shares, whatever /64s they have, which these limits leave room for. An
  IPv4 address has no /48 and is counted as itself alone. A /48 past its share gets the same 429 as an address
  past its own.
- What this does not stop: these budgets are per address, so an attacker with many addresses scales with them. At
  the defaults one IPv4 address or IPv6 /64 holds at most 4 MiB (twice 2 MiB, across a window), one IPv6 /48 at
  most 64 MiB and one IPv6 /32 (what a provider is allocated) at most 256 MiB, so filling the default
  `limits.ephemeral_mb` takes some 256 to 512 IPv4 addresses, or 4 to 8 IPv6 /32s, each kept busy; a botnet has
  that. `limits.held_kb` is used as at most 1/128 of `limits.ephemeral_mb` (a larger value, the default on a small node included, is lowered to that), so that however the two are set one address
  or user holds at most a 64th of the node, a /48 a quarter, and it takes a whole /32 to fill it. The node's memory
  limit is then the backstop: the state is refused at `limits.ephemeral_mb` (503 for new sign-ins on that node, until
  expiries make room within 20 minutes) rather than the node running out of memory, and
  `quisora_ephemeral_refused_total{reason="held_bytes"}` and `{reason="full"}` show it happening. Lower
  `limits.held_kb` (a sign-in holds about 1 KiB, so 256 still lets one address hold some two hundred at once), raise
  `limits.ephemeral_mb`, and block the sources upstream.

### Metrics

`GET /metrics` serves Prometheus metrics when `metrics.token` is set (`QUISORA_METRICS_TOKEN`); Prometheus sends it
as a bearer token (`authorization: { credentials: … }` in the scrape config). Without a token there is no such
endpoint. Every node serves its own.

| Metric | What |
| --- | --- |
| `quisora_http_requests_total{code}` | Requests by status class (`2xx` … `5xx`) |
| `quisora_http_request_duration_seconds` | Time to answer (histogram) |
| `quisora_http_shed_total` | Requests refused because too many were in progress |
| `quisora_http_shed_address_total` | Requests refused with 429 because their address had its share (`limits.max_in_flight_per_ip`) in progress |
| `quisora_http_denied_total` | Requests refused with 403 because the client's address is in `server.deny_networks` ([denied addresses](#limits-and-denied-addresses)); not counted in `quisora_http_requests_total` |
| `quisora_audit_events_total{action,outcome}` | Every audit event: `login.failure`, `login.lockout`, `login.limited`, `oauth.refresh.reuse`, `oauth.code.replay`, `oauth.client_auth.limited`, `passkey.clone` and the rest ([what is recorded](#what-is-recorded)). `login.failure` counts every wrong password or code, the repeats the audit log holds back too |
| `quisora_audit_undelivered_total` | Audit events logged in full as `audit.undelivered`: those VictoriaLogs will never receive, and those logged because the spool's disk did not answer within 2 seconds, which reach VictoriaLogs as well once it does (the `reason` in the log tells them apart) |
| `quisora_audit_spool_bytes` | Disk the VictoriaLogs spool uses (growing: VictoriaLogs is not taking events) |
| `quisora_mail_queued` | Emails this node has waiting to be sent |
| `quisora_mail_failed_total{reason}` | Emails that never reached the mail server: `given_up` (every retry failed; the log names the recipient), `dropped` (kept past the queue's discard horizon, or unreadable) and `expired` (the sign-in code or link in it had expired while it waited) |
| `quisora_authorize_refused_total{error}` | Authorization requests from a known application sent back with an error before anyone signed in, by error: `invalid_scope` (it asked for a scope its settings do not allow), `unauthorized_client` (a grant type it may not use), `invalid_request` and the others. Each is also logged as a warning (`oidc: authorization request refused`) naming the application, the error and why; not an audit event, as nobody has signed in and anyone who knows a client ID can cause one. A rise after an application's settings were changed is usually that change (its `client.update` audit event shows what changed) |
| `quisora_ephemeral_bytes`, `quisora_ephemeral_budget_bytes`, `quisora_ephemeral_counter_bytes`, `quisora_ephemeral_counter_limit_bytes`, `quisora_ephemeral_cache_bytes`, `quisora_ephemeral_cache_limit_bytes`, `quisora_ephemeral_entries` | This node's short-lived state: the memory its sign-in flows, codes and challenges take, by the estimate checked against `limits.ephemeral_mb`; that limit in bytes; the memory its rate-limit counters take, checked against their own cap; that cap in bytes (`limits.ephemeral_mb`, at least 16 MiB); the memory its short-lived caches (client metadata documents read in the last minute) take, checked against their own cap; that cap in bytes (a sixteenth of `limits.ephemeral_mb`, at least 4 MiB: at it the oldest entries make room); how many entries it holds (counters and cache entries included). With a shared database, the same for the rows this node wrote there |
| `quisora_audit_refusals_dropped_total{limiter}` | Refusal audit events (`apitoken.refused`, `api.request.refused`, SSH refusals, sign-in lockout refusals and wrong credentials) not recorded because the node already tracked 10,000 keys (or, for the sign-in events, 10,000 client addresses) at once in their limiter, or one organization 2,500 of them, or (sign-in events) because the organization already had 200 events naming addresses recorded in the minute ([what is recorded](#what-is-recorded)), by limiter: `refusals`, `login` (lockout refusals of sign-in keys that name no account, and of addresses), `login_accounts` (existing accounts' lockout refusals), `login_failures` (wrong passwords for logins that name no account) `login_account_failures` (existing accounts' wrong passwords and codes) and `device_starts` (the device sign-ins public clients started, `oauth.device.start`). For the sign-in limiters it counts events whose address went unnamed: the account's event of that minute and sign-in step is still recorded (`login_accounts`, `login_account_failures`), or the organization's of that step (`login`, `login_failures`), naming one of the addresses. Above 0: a flood of refused requests; the node also logs it at most once a minute |
| `quisora_ephemeral_refused_total{reason}` | Requests refused for short-lived state, by reason: `full` (this node's short-lived state at `limits.ephemeral_mb`: 503), `counters` (a new rate-limit counter past the counters' cap: the limit refuses), `contended` (a counter in the shared database too contended to update after its retries: the limit refuses, and a held budget answers 503), `flows_per_ip` (an address holding `limits.flows_per_ip` sign-ins in progress: 429), `held_bytes` (an address or a signed-in user holding `limits.held_kb` of short-lived state: 429, with `Retry-After` the seconds until the 20-minute window that refused it ends, when it may hold more again; a budget whose counter could not be updated is not this but 503, counted as `counters` or `contended`), `guard` (a record of a used code, a device poll or a password spray past those records' cap: the code is not redeemed, the poll is told to slow down, the spray is remembered by a counter) and `cache` (a short-lived cache entry larger than the caches' whole cap, not kept: nothing refused; a full cache evicts its oldest entries instead, which is not counted here) |
| `quisora_backchannel_logout_queued` | Back-channel logouts this node has waiting to be retried (growing: an application is not taking them) |
| `quisora_backchannel_logout_failed_total` | Back-channel logouts given up on after every retry, dropped because the queue was full (an organization holds at most 2,500 of a node's 10,000 retries, and no more than the room left for the others, so only its own are dropped), or dropped unsent past the queue's discard horizon |
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

- `increase(quisora_authorize_refused_total{error=~"invalid_scope|unauthorized_client"}[15m]) > 0`: an application asks
  for what its settings do not allow, so its users cannot sign in (the log names the application).
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
- `increase(quisora_mail_failed_total[1h]) > 0`: mail is being lost (invitations, password resets, sign-in codes): the mail
  server is down or refusing it, or the queue is not keeping up. `quisora_mail_queued` growing says the same earlier.
  Likewise `increase(quisora_backchannel_logout_failed_total[1h]) > 0` for applications that are not told of a sign-out.
- `rate(quisora_http_shed_total[5m]) > 0`: the node is overloaded ([under attack](#under-attack)).
- `quisora_ephemeral_bytes / quisora_ephemeral_budget_bytes > 0.8` for 5 minutes, or any
  `increase(quisora_ephemeral_refused_total{reason="full"}[5m]) > 0`: the node's short-lived state is (nearly) full and
  new sign-ins get 503: a flood of unfinished sign-ins, or `limits.ephemeral_mb` too small for the load. A steady
  `rate(quisora_ephemeral_refused_total{reason="flows_per_ip"}[5m])` is addresses starting sign-ins they do not finish
  (or many users behind one address: see `server.trust_proxy`), and `{reason="held_bytes"}` the same measured in
  bytes (`limits.held_kb`): a few addresses refused is an attack held off, many at once with `{reason="full"}` rising
  is one with enough addresses to fill the node. Refusals for `flows_per_ip` and `held_bytes` are counted only: no audit
  event or log line is written for each, so a flood of them cannot fill the audit log; the request log (`log.access`)
  shows the address of each 429.
- For tenants that use SSH certificates: a log line `oidc: making an SSH revocation list` at error level (the tenant's
  revocation list could not be made; its address answers 503 and servers keep their old list), and, on every server that
  fetches it, the fetch unit failing or the revocation list file older than 5 minutes ([SSH monitoring](ssh/README.md#monitoring)).

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

- A gossip cluster of three BadgerDB nodes (all on that one machine with the load generator, every write committed on
  two of them before it is visible), at 5,000 organizations × 1,000 users with the load spread over its nodes: refresh
  token 51,500/s, client credentials 57,400/s, introspection 57,500/s, password sign-in 290/s (a sign-in's writes are
  committed on two nodes, and the three nodes share the machine's 15 cores).

- A password sign-in costs ~26 ms of CPU (argon2id, 19 MiB; m=19456, t=2, p=1). Stored hashes are sealed with the
  master key, and one made with other settings is re-hashed at the user's next sign-in; a stored hash naming settings
  far outside these (over 64 MiB, 10 passes or 16 threads) is refused without hashing. Plan ~30 cores for 1,000 password sign-ins/s. A
  passkey sign-in costs ~0.15 ms.
- Tested at 5,000 organizations × 1,000 users with 500,000 refresh grants (6.56M records, BadgerDB, 8.4 to 9.2 GB per
  node on disk);
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
- Profile pictures are stored in the database, one record each: a 256 × 256 JPEG or PNG, about 10–20 KB (a flat
  graphic less, a transparent photo more). Every node holds them all: at 5,000 organizations × 1,000 users with a
  picture each that is about 50–100 GB more per node, on disk and in backups, so size the disks for the share of users
  who will have one. Uploads are decoded one at a time per node; one at the largest allowed size (8192 × 8192 pixels)
  takes up to about 512 MB while it is, so leave that much room above the figures here where pictures are set.
- Set `GOMEMLIMIT` (read by the Go runtime, for example `GOMEMLIMIT=1536MiB` for a 2 GB node). Each password hash
  leaves 19 MiB of garbage, and without a limit the runtime lets the heap grow to twice what is live before collecting:
  a burst of password sign-ins (64 concurrent clients, 15 cores) took the process to about 1.2 GB resident, and with
  `GOMEMLIMIT=512MiB` to about 640 MB at the same rate. The runtime keeps freed pages until the system needs them, so
  resident memory after a burst stays near its peak; the Go heap returns to its idle size (`quisora_memory_heap_bytes`).
- At this size send audit events to VictoriaLogs ([Audit log](#audit-log)): the built-in trail's pages read through
  every event they search.
- A new gossip node catches up at about 16,800 records/s (all 6.56M records in 6.5 minutes, from the two others);
  two empty nodes at once, from the one that has the data, at about 12,700 records/s each. While it copies, a node's
  Go heap reaches about 1.7 GB, and settles at 150 to 250 MB. The operating system shows it with some 11 GB resident
  after: BadgerDB's files, mapped into memory, which it can drop at any time. `scripts/scale-cluster.sh` reproduces
  this (with `GRANTS=500000` for these figures).
- The load test tool reproduces these. It is a development tool, not part of the `quisora` binary: build it with
  `task loadtest` (or `go build -o bin/loadtest ./tools/loadtest`), then use `bin/loadtest seed` and
  `bin/loadtest run`. The seeder needs `QUISORA_LOADTEST=1`, as it writes test data straight into the store.
