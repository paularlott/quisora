# Quisora

> Quisora (pronounced "kwih-SOR-ah") comes from the Latin *quis? ōrā*, meaning "who? speak", a sentry's challenge at the gate.

Quisora is a clustered identity provider in one binary: OpenID Connect and OAuth 2 for your applications, passkeys and
multi-factor sign-in for your users, SCIM 2.0 and a REST API for automation, and a multi-organization admin console.
It runs on Linux, macOS and Windows. Licensed under the [Apache License 2.0](LICENSE).

## Features

- **Organizations, tenants, applications.** Any number of organizations, each with its own users, groups, sign-in
  providers and policies. Tenants group applications that share sign-in rules and access lists (users and groups,
  application roles, end dates). Organizations are self-contained: each has its own address space (`/o/<org>/…`: its
  sign-in pages, account page, invitations and OAuth endpoints), its own OAuth issuer and its own browser session.
- **Sign-in.** Passkeys (as the whole sign-in or a second factor), password plus authenticator app (TOTP), recovery
  codes for a lost second factor, codes by email as a second factor for users without an app or passkey where an organization allows it, and upstream providers per organization: Google, Microsoft, GitHub, GitLab, Auth0
  and any OpenID Connect provider. Invitation links instead of admin-set passwords. Per-organization and per-tenant
  MFA. Guides: [docs/sign-in](docs/sign-in/README.md).
- **OpenID Connect and OAuth 2.** Authorization code with PKCE, refresh tokens, client credentials, introspection,
  revocation, userinfo, RP-initiated and back-channel logout, resource indicators, pushed authorization requests
  (RFC 9126), token exchange (RFC 8693), device sign-in for CLIs and TVs (RFC 8628), DPoP-bound tokens (RFC 9449), `claims` and `acr_values`, and for MCP servers and AI clients
  dynamic client registration (RFC 7591) and Client ID Metadata Documents ([docs/MCP.md](docs/MCP.md)). JWT
  access tokens signed with ES256, EdDSA, RS256 or PS256, and keys rotate automatically. The FAPI 2.0 Security
  Profile can be turned on per application. Passes the OpenID Foundation
  certification test plans in local runs of the conformance suite (not a formal certification; the results name the
  commit they were run on: [docs/conformance.md](docs/conformance.md)). A guide for each, with curl examples:
  [docs/oauth](docs/oauth/README.md).
- **Automation.** SCIM 2.0 per organization (Entra ID and Okta dialects), a versioned management API with an OpenAPI
  document, personal API tokens with scopes, and service accounts for automation that belongs to no person. Keys and passwords can be read from HashiCorp Vault or 1Password
  (Connect, or a service account in the 1Password build) and rotated without a restart.
- **Roles.** Super admin, admin, manager and user. Managers look after plain users: they create and change them and
  add them to groups and take them out, but create, rename, retag or delete no group, and change nothing for a
  manager or administrator. Managers and above always use a second factor. Only a super admin
  can reset a manager's or administrator's sign-in (a new invitation, removing the password, an authenticator app,
  a passkey or a provider link) or lower their role, so one administrator cannot take over another's account, and
  only a super admin can sign out the primary organization, which holds the super admins.
- **Admin console.** Light and dark themes, live updates across nodes, WCAG 2.2 AA, no CDNs.
- **Storage.** BadgerDB, SQLite, PostgreSQL, MySQL or MariaDB.
- **Clustering.** Several nodes on one shared database, or nodes with their own databases replicating over gossip: the data
  is split into partitions, each owned by one node that commits every write on a majority of the cluster.
- **Audit log.** In the database, or in VictoriaLogs for real deployments. Every event also goes to the structured log.
- **Backups.** Online, encrypted with a password by default, verified before restore, into any backend.

## Requirements

**Every node's clock must be synchronised with NTP** (chrony, systemd-timesyncd, or the cloud provider's time
service), keeping the nodes within milliseconds of each other. SOC 2 requires it anyway (consistent audit
timestamps), and Quisora relies on it: record versions come from the writers' clocks, and a cluster stays consistent
across restarts because no node's clock is more than 5 seconds off (`store.MaxSkew`). Every node compares its clock
with the others' every few seconds: one more than 5 seconds off refuses to serve, and logs why, until its clock is
fixed (`clock_offset_ms` in `/readyz` shows the offset). Details: [docs/REPLICATION.md](docs/REPLICATION.md#clocks).

## Install

Build from source (Go 1.27, Node 24 and [Task](https://taskfile.dev)):

```bash
task build        # bin/quisora
```

Or build the container image:

```bash
docker build -t quisora .
```

## Run a single node

```bash
export QUISORA_MASTER_KEY="$(bin/quisora genkey)"            # keep it: it seals every secret in the store
bin/quisora bootstrap --public-url https://localhost:8443   # once: prints the first admin's invitation link
bin/quisora serve --public-url https://localhost:8443
```

1. `bootstrap` creates the `primary` organization and a super admin (`admin@example.com`) with no password, and
   prints a single-use invitation link.
2. Open the link (accept the self-signed certificate), set a password or create a passkey, then a second factor.
3. The admin console is at `https://localhost:8443/admin`. `https://localhost:8443/` takes users to the primary organization's sign-in page;
   an organization's own is `/o/<org id or name>/login`.

This runs on BadgerDB in `./data` with a self-signed certificate. For a real deployment, set:

- `--public-url` to your address,
- `--tls-cert` / `--tls-key`,
- `--data-dir`,
- the master key (`quisora genkey`) from a secret store, as `QUISORA_MASTER_KEY` or in the config file.

Every flag is also an `QUISORA_*` variable and a TOML key: see `quisora serve --help` and
[quisora.toml.example](quisora.toml.example).

## Clusters

- **Shared database:** point every node at the same PostgreSQL, MySQL or MariaDB database and give them the
  same master key (`QUISORA_MASTER_KEY` or `server.master_key`, from a secret store: not a flag, which shows in `ps`). Nothing is replicated: the database is the only copy. Optional `cluster.notify` gossip only
  tells the other nodes what changed, so their caches update at once.
- **Replicated:** every node has its own database (any backend, e.g. BadgerDB) and sets `cluster.bind`, `cluster.peers` (every node), `cluster.size` and `cluster.key`. Run `quisora bootstrap --new-cluster` on one node first; start three or five nodes.

Both modes, every storage backend, Docker, backups and recovery: [docs/RUNNING.md](docs/RUNNING.md). Replication rules
and outage procedures: [docs/REPLICATION.md](docs/REPLICATION.md). Running it securely (threat model, hardening checklist, incident
response): [docs/SECURITY.md](docs/SECURITY.md). Personal data and data subject requests: [docs/PRIVACY.md](docs/PRIVACY.md). Scripts and tools with personal API tokens:
[docs/API-TOKENS.md](docs/API-TOKENS.md). Automation with service accounts (SCIM provisioning, importers, deploying
organizations): [docs/SERVICE-ACCOUNTS.md](docs/SERVICE-ACCOUNTS.md). MCP servers and AI clients that register themselves:
[docs/MCP.md](docs/MCP.md).
Connecting applications (sign-in, client credentials, device sign-in, token exchange, PAR, DPoP, FAPI 2.0):
[docs/oauth](docs/oauth/README.md). How people sign in (passkeys, upstream providers, recovery codes, codes by email):
[docs/sign-in](docs/sign-in/README.md). Emergency sign-out and lock-out: [docs/emergency-sign-out.md](docs/emergency-sign-out.md).
Keys and passwords in Vault or 1Password: [docs/secret-stores.md](docs/secret-stores.md). What to check before a
release: [docs/RELEASE.md](docs/RELEASE.md). Reporting a vulnerability:
[SECURITY.md](SECURITY.md).

## Operating it

| | |
| --- | --- |
| `quisora invite <org> <email>` | A new invitation link for a user (`--break-glass`: get back into a server nobody can sign in to, even as a disabled super admin; with `--super-admin`, also make the account a super admin of the primary organization) |
| `quisora sign-out` | Emergency sign-out of an organization or every organization ([docs/emergency-sign-out.md](docs/emergency-sign-out.md)) |
| `quisora backup`, `quisora restore` | Online backups, encrypted with a password, of the whole store; a restore is verified before anything is written ([Backup and restore](docs/RUNNING.md#backup-and-restore)) |
| `quisora force-start` | Start a gossip node whose disk was lost once by copying from whichever nodes answer, when too few others are up for a majority ([docs/REPLICATION.md](docs/REPLICATION.md)) |
| `quisora healthcheck [--ready]` | Exit 0 when this node is alive (or ready): for container health checks |
| `quisora genkey` | A new master key, cluster key or BadgerDB encryption key |
| `/healthz`, `/readyz` | Liveness, and readiness for load balancers (with the clock offset and cluster state) |
| `/metrics` | Prometheus metrics, with `metrics.token` as a bearer token ([Metrics](docs/RUNNING.md#metrics)) |
| `/api-docs`, `/api/openapi.json` | The management API's reference and its OpenAPI document |
| SIGHUP | Reload the master keys and, in a gossip cluster, the cluster key and size (read from the secret store again where they name one), and the TLS certificate, without a restart ([Rotating the master key](docs/RUNNING.md#rotating-the-master-key)) |

Behind a load balancer set `server.trust_proxy` to its addresses (the per-address limits and the audit log's
addresses come from `X-Forwarded-For` only then), and `server.shutdown_drain` to how long it takes to stop sending
traffic to a node that is stopping. `server.allowed_networks` lists the private networks sign-in providers and applications
may be on (calls to other private addresses are refused; `server.allow_private_networks` allows them all, for a home
lab), and `server.extra_ca_file` adds private CA roots for them; `server.restore_from` restores a backup at the first start of an empty node. The console's look is a
skin (`ui.skin`, with a logo and a footer: [web/skins](web/skins/README.md)). Every setting:
[quisora.toml.example](quisora.toml.example) and `quisora serve --help`.

## Audit log and VictoriaLogs

By default audit events are kept in the database for 7 days (`audit.retention_days`). In a gossip cluster they are
not replicated: each node keeps the events it records in its own database, and the audit page asks every node and merges
what they answer (a node that is down is missing from the page, which says so). That built-in audit trail is for development, home labs and testing:
its pages read through every event they search (fine for thousands of users, not for millions).

**Production, and any deployment that needs SOC 2, must send audit events to VictoriaLogs**, with retention set there
(typically a year or more). Each node writes every event to a disk spool in its data directory, synced before the
action that recorded it completes, and removes it once VictoriaLogs has taken it. The guarantee: an event whose
write to the spool succeeded is on disk, complete, and will reach VictoriaLogs, through an outage of VictoriaLogs, a
restart or a crash (a write a crash or disk error cuts short is undone or left as a segment's last line, so it can
never corrupt an event written after it), unless an outage outlasts the spool's space (the oldest events then leave
it, each written in full to the structured log). The structured log (`audit.undelivered`, the event in full) is the
fallback whenever the spool does not take an event: the disk did not answer within 2 seconds (the event is still
spooled once it does, and then reaches VictoriaLogs as well), or the write failed (a full or failing disk: the log is
then its only copy). Delivery is at least once — VictoriaLogs may hold an event twice, by `id`, never not at all — so
ship the structured log and alert on `audit.undelivered`.
Every node's audit page then reads from VictoriaLogs:

```toml
[audit]
victorialogs_url = "http://victorialogs:9428"
victorialogs_spool_max_mb = 256           # the spool is <data_dir>/auditspool, one per node
```

Details: [docs/RUNNING.md](docs/RUNNING.md#audit-log). Controls, evidence and the VictoriaLogs set-up for SOC 2 (vmauth,
retention, the completeness check): [docs/SOC2.md](docs/SOC2.md).

## Development

```bash
task test         # go vet + every test with the race detector, but the cluster package's (the everyday loop)
task test-cluster # the cluster package, the conformance suite against it, and the -tags faults tests (slow)
task test-all     # also against PostgreSQL, MySQL and MariaDB in Docker
task test-ui      # accessibility (axe) and keyboard tests in Chromium
task bench        # Go benchmarks
```
