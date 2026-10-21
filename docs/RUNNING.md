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
server-wide [emergency sign-out](#emergency-sign-out). The menu keeps the organization you were last administering,
so it is one click back. `GET /api/system`, `GET /api/cluster` and `GET /api/keys` have the same figures. Each
organization has an **Overview** page too, for its administrators and super admins, with its own emergency sign-out.

## Sessions, tokens and sensitive changes

**Browser sessions** last `session.ttl` from sign-in (7 days) and end after `session.idle` unused (24 hours). An
organization may set shorter ones on its settings page, never longer. Managers and above get
`session.privileged_ttl` (12 hours) and `session.privileged_idle` (1 hour) when those are shorter. The primary
organization's sign-in settings (methods, second factor, session lifetimes) cover the super admins, so only super
admins change them.

**Refresh tokens** of a new confidential client rotate (one use each): a copy used after the client has used the
token is detected, and the whole grant ends (`oauth.refresh.reuse` in the audit log). A client that cannot keep the
latest token can turn it off ("Rotate refresh tokens"). Public clients always rotate.

**Introspection** answers `active` for an access token only to a client the token was issued for (its audience).
A resource server that serves several applications of the organization needs "May introspect every token of the
organization" on its client; so does one that applications name as a resource (RFC 8707), since a resource is in a
token's audience as its URI, not as a client.

**Pushed authorization requests** (RFC 9126, `POST /oauth/par`): a client posts its authorization request there,
authenticated as at the token endpoint, and sends the browser to `/oauth/authorize` with only `client_id` and the
`request_uri` it got back. The request is checked before the user sees anything, its parameters never pass through
the browser, and the `request_uri` works once, for 60 seconds. "Require pushed authorization requests" on a client
refuses its authorization requests made any other way. Request objects (JAR) are still not supported, pushed or not.

**Token exchange** (RFC 8693, grant type `urn:ietf:params:oauth:grant-type:token-exchange`, confidential clients
only): a client trades a user's access token (`subject_token`, type `urn:ietf:params:oauth:token-type:access_token`)
for an access token of its own that acts for the user, to call another API with the user's identity. The client must
be in the subject token's audience, or have "May introspect every token of the organization"; the user must have
access to the client, as for a sign-in. The new token has at most the subject token's scopes (and the client's), only
resources registered for the client (`resource` or `audience`), the subject token's expiry at the latest, and an
`act` claim naming the client (and any actor before it, up to four). It is bound to the user's original grant:
signing out ends it, but revoking it does not end that grant. There is no refresh or ID token, and no `actor_token`.
Every exchange is audited (`oauth.token_exchange`).

**DPoP** (RFC 9449, sender-constrained tokens): a client that sends a DPoP proof (header `DPoP`) with a token request
gets an access token bound to the proof's key (`token_type` `DPoP`, `cnf.jkt` in the token and in introspection),
accepted at userinfo and SCIM only with the `DPoP` authorization scheme and a fresh proof of that key. Proofs at the
token and PAR endpoints need a nonce from this server: the first request fails with `use_dpop_nonce`, and every
response carries the nonce for the next one in `DPoP-Nonce` (nonces last two to three minutes, on every node). Each
proof works once. A public client's refresh tokens are bound to the key it first used; a confidential client's stay
bound to its client authentication. An authorization request can name the key in advance (`dpop_jkt`, or a proof
sent with a pushed request), and its code is then redeemed only with that key. "Require DPoP-bound tokens" on a
client (`dpop_bound_access_tokens`) refuses its token requests without a proof. APIs that verify Quisora's access
tokens themselves must check `cnf.jkt` against the request's proof; introspection reports it.

**`acr`**: the values a request names (an `acr` claim request first, then `acr_values`) are in order of preference,
and the first one Quisora knows (`urn:quisora:acr:basic`, `urn:quisora:acr:mfa`) decides whether a second factor is a
condition of the sign-in. An `acr` claim requested as essential with values none of which Quisora knows fails with
`unmet_authentication_requirements`; requested as essential without values, it is simply returned.

**Sensitive changes** need a recent re-authentication (signed in or confirmed within 5 minutes; the console asks
with its "Confirm it is you" dialog), and an API token can never make them, through the management API or SCIM:

- deleting an organization;
- rotating the signing keys;
- changing the primary organization's sign-in settings;
- making someone an administrator or super admin, or creating one;
- removing another user's password;
- issuing an invitation for a manager or administrator (an accepted invitation replaces every way they sign in).

Resetting the sign-in of an established manager or administrator (an invitation, removing their password, lowering
their role, or changing their primary email address, where password resets go) is a super admin's change. A manager
or administrator who has not signed in yet gets the next invitation only from whoever issued the current one, or from
a super admin.

**Super admins the server keeps.** Demoting, disabling, deleting or end-dating a super admin is refused when fewer
usable super admins than the server needs would remain: one on a single node or nodes sharing a database, two in a
gossip cluster (a change one node made but the majority has not confirmed yet must never leave none). Make someone
else a super admin first. Organizations need no administrator of their own: super admins administer every one, so an
organization's last administrator can be demoted or removed.

**Account changes** (a passkey, the authenticator app, the primary address, connecting a sign-in provider, an API
token) need a re-authentication too, or a sign-in within 5 minutes that used the account's own second factor: a
sign-in through a provider trusted as a second factor does not count when the account has one of its own.

**Personal API tokens** never expire unless their owner gives a lifetime when making one (at most 10 years). Set
`tokens.api_token_max_days` to require one: tokens then last at most that many days, and a token made without a
lifetime gets the maximum. Tokens with the backup scope always expire within 30 days. Its owner can give a token a new secret from the
account page (after confirming): the old secret stops working at once, and the name, access and expiry stay the same,
so a new secret never extends a token's life.

## Emergency sign-out

Break glass: end every session of an organization, or of every organization, at once, on every node, when an attacker
may hold sessions or tokens and you do not know whose.

- **Console:** an organization's **Overview** page (its administrators and super admins), or the **System overview**
  for every organization (super admins: **System overview**). It asks for a reason and for the organization's name (or `everyone`) to be
  typed, and a re-authentication if you have not signed in or confirmed it is you in the last 5 minutes.
- **API:** `POST /api/orgs/{org}/sign-out` or `POST /api/sign-out` with `{"reason": "…", "api_tokens": false}`, from a
  browser session (an API token cannot pull it).
- **Command line**, when the console cannot be used: `quisora sign-out --org acme --reason "…"` or
  `quisora sign-out --all --reason "…"` (add `--api-tokens` to end personal API tokens too). It needs the master key and
  the same settings as `serve`. On a shared database it works while the servers run; on BadgerDB or SQLite stop the
  server first; in a gossip cluster stop one node, run it there and start the node again.

What ends: every browser session and refresh grant (so the access tokens issued from them stop working through
userinfo and introspection), and with the option every personal API token. The session you pulled it from stays.
Applications are told (back-channel logout), and the ended records are deleted in the background. Signing in again
works at once. Not ended: tokens of applications acting for themselves (client credentials; rotate the client's
secret or disable the client), and access tokens already in the hands of applications that check them themselves
rather than through introspection, until they expire (`tokens.access_ttl`, 10 minutes by default).

How it works: each organization, and the server, keep sign-out counters, and every session, grant and API token is
stamped with them when it is made. Pulling the lever increments a counter in one write, which the cluster confirms
like any other; from then on everything stamped before it is refused. It does not depend on the nodes' clocks, and it
cannot be half done. The counters are part of backups, and move with the primary organization (`quisora
set-primary`), so nothing a sign-out ended comes back.

To lock out one person instead (a compromised account, or a leaver), use **Lock out** on their user page
(`POST /api/orgs/{org}/users/{id}/lock-out`): it disables the account, signs them out everywhere and removes every way
they had to sign in. Enabling the account again brings none of that back; send a new invitation.

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
  become administrators of that organization. The change is audited in both. The server's emergency sign-out
  counters move with it.
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

Sealed secrets (TOTP secrets, password hashes, provider and signing keys, upstream tokens) are encrypted with the
master key on every backend. The rest of the data (names, email addresses, sessions, the audit log in the database) is
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

### Shared database

Several nodes on one PostgreSQL, MySQL, MariaDB or Valkey database, which is the only copy. Leave `cluster.bind`
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
- High availability is the database's: run it as your own HA cluster.

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

Every node has its own database (BadgerDB is the usual choice) and the nodes replicate every write.
A gossip cluster keeps at least two super admins: make a second one before you rely on the cluster (see
[sensitive changes](#sessions-tokens-and-sensitive-changes)).

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
- **Clocks** must be synchronised (NTP). Gossip refuses packets more than two minutes off the receiver's clock.

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
| Gossip cluster            | Each node keeps its own; a page asks every node and merges, and says if a node did not answer | Every node sends; any node reads              |

Admins see their own organization's events. Super admins also see every organization (`/admin/audit`,
`GET /api/audit?org=<name>`).

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
| OAuth / OpenID Connect | `oauth.consent` (allow or deny), `oauth.grant` (every code exchange), `oauth.token_exchange` (every token exchange), `oauth.revoke`, `oauth.code.replay` and `oauth.refresh.reuse` (a code or refresh token presented again: its grant is revoked), `oauth.client_auth.limited` (a client's failed authentications reached the limit); with `audit.tokens = true` also `oauth.refresh` and `oauth.client_credentials` for every token issued |
| Administration | users, groups, organizations, tenants, access, clients, providers, API tokens, invitations, `user.locked_out`, `keys.rotate`, `keys.create` (every signing key made, scheduled ones too), `keys.remove`, `backup.download`, `backup.restore`, `cluster.force_start`, `cluster.reload` (and `cluster.reload.failure`, with each node's report), `org.primary` |
| Emergency sign-out | `org.signout` and `server.signout` (with the reason, and whether API tokens ended too), then `signout.sweep` (how many sessions, grants and API tokens were deleted) |
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

Commands (`bootstrap`, `invite`, `set-primary`, `sign-out`, `restore`) record who ran them: the actor is
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

## Upgrading

**Before the first release** there is no upgrade path: a store written by an older pre-release build is refused at
start-up. Wipe it and start clean (or restore a backup made by the new build).

**From the first release:**

- **Back up first.** Upgrades go forward only. A store or database written by a newer build is refused, so going
  back means restoring the backup.
- **One release at a time.** Each release works with the previous one: a cluster can be upgraded one node at a time
  while it keeps serving. Nodes publish their compatibility, and a node more than one release apart is refused: the
  others log `refusing to serve … upgrade one release at a time` and stop serving until it is upgraded or gone.
- **Storage is migrated at the first start of the new build**, step by step, each step recorded as it completes (an
  interrupted upgrade resumes). Nodes that share a database or Valkey do it once, under a lock; with gossip, every
  node migrates its own store.
- **Backups** made by the previous release restore into the new one.

### Changing a stored format (for developers)

Until the first release, formats change in place. From then on:

- A record field that can be added with a sensible zero value needs nothing: older records read as the zero value.
  Renaming, removing or re-interpreting one needs a migration, on every backend:
  - BadgerDB and Valkey: append to `formatMigrations` (`internal/store/kvstore/kvstore.go`);
  - SQL: append to `migrations()` (`internal/store/sqlstore/migrate.go`): statements, and Go code for data.
- A backup format change: raise `version`, add `upgrades[old]`, and keep `minVersion` at the previous release's
  version (`internal/backup/backup.go`).
- What nodes send each other changes: raise `compat`; raise `minCompat` only when this build stops understanding the
  previous release (`internal/cluster/node.go`).
- Never edit or remove a released migration or upgrade: append.

## Health and monitoring

- `/healthz`: liveness.
- `/readyz`: readiness, cluster-aware. Route load balancers on it. It reports size, quorum and counts of unconfirmed
  writes, refusals and clock skew.
- `GET /api/cluster` (super admins) and the console's settings page: the node's cluster status.
- The probes, metrics, discovery and JWKS are never shed under load (`limits.max_in_flight`, default 4096 per node).

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
| `quisora_mail_queued` | Emails waiting to be sent |
| `quisora_ready`, `quisora_writable`, `quisora_leader` | This node serves; accepts changes; runs housekeeping |
| `quisora_cluster_alive_nodes`, `quisora_cluster_size`, `quisora_cluster_quorum` | Cluster membership |
| `quisora_master_key_rotation` | 1 while previous master keys are configured |
| `quisora_build_info{version}`, `quisora_uptime_seconds`, `quisora_goroutines`, `quisora_memory_heap_bytes` | The process |

Alerts worth having:

- `quisora_ready == 0` or `quisora_writable == 0` for more than a few minutes; `quisora_cluster_alive_nodes <
  quisora_cluster_quorum`.
- `increase(quisora_audit_undelivered_total[5m]) > 0`, or `quisora_audit_spool_bytes` growing: audit events at risk.
- Bursts of `quisora_audit_events_total{outcome="failure"}`, by action: password guessing (`login.failure`,
  `login.lockout`), floods (`login.limited`, `oauth.client_auth.limited`), stolen tokens (`oauth.refresh.reuse`,
  `oauth.code.replay`), a cloned passkey (`passkey.clone`).
- Any `quisora_audit_events_total{action=~"keys.rotate|org.primary|cluster.force_start|backup.download|backup.restore"}`:
  rare, privileged events someone should know about.
- `rate(quisora_http_shed_total[5m]) > 0`: the node is overloaded.

### Access log

`log.access = true` (`QUISORA_LOG_ACCESS`) logs every request: method, path, status, duration, size, client address
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

- A password sign-in costs ~26 ms of CPU (argon2id, 19 MiB; m=19456, t=2, p=1). Stored hashes are sealed with the
  master key, and one made with other settings is re-hashed at the user's next sign-in; a stored hash naming settings
  far outside these (over 256 MiB, 10 passes or 16 threads) is refused without hashing. Plan ~30 cores for 1,000 password sign-ins/s. A
  passkey sign-in costs ~0.15 ms.
- Tested at 5,000 organizations × 1,000 users (6M records); lookups and token traffic do not slow down at that size.
- A new gossip node catches up at ~86,000 records/s.
- The load test tool reproduces these. It is a development tool, not part of the `quisora` binary: build it with
  `task loadtest` (or `go build -o bin/loadtest ./tools/loadtest`), then use `bin/loadtest seed` and
  `bin/loadtest run`. The seeder needs `QUISORA_LOADTEST=1`, as it writes test data straight into the store.
