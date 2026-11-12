# Quisora

> **Quisora** (kwih-SOR-ah) is a coined name inspired by Latin *quis*, “who?”, and *ōrā*, “speak!”—evoking a sentry’s challenge at the gate.

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
- **SSH certificate authority.** Per tenant, Quisora signs short-lived OpenSSH certificates for people who signed in with
  a second factor (from `quisora ssh login` or their account page), and host certificates for servers. Servers trust the
  tenant's CA key instead of a list of user keys, who may log in as which account follows the people's groups, and a
  revocation list ends access within a minute or two. Guide: [docs/ssh](docs/ssh/README.md).
- **Roles.** Super admin, admin, manager and user. Managers look after plain users: they create and change them and
  add them to groups and take them out, but create, rename, retag or delete no group, and change nothing for a
  manager or administrator. Managers and above always use a second factor. Only a super admin
  can reset a manager's or administrator's sign-in (a new invitation, removing the password, an authenticator app,
  a passkey or a provider link) or lower their role, so one administrator cannot take over another's account, and
  only a super admin can sign out the primary organization, which holds the super admins.
- **Admin console.** Light and dark themes, live updates across nodes (one connection per browser, shared by its
  tabs), WCAG 2.2 AA, no CDNs. Skins chosen per organization (built-in
  ones, and custom ones super admins add in the console), and a logo, colour and footer of their own for each
  organization ([web/skins](web/skins/README.md)).
- **Storage.** BadgerDB, SQLite, PostgreSQL, MySQL or MariaDB.
- **Clustering.** Several nodes on one shared database, or nodes with their own databases replicating over gossip: the data
  is split into partitions, each owned by one node that commits every write on a majority of the cluster.
- **Audit log.** In the database, or in VictoriaLogs for real deployments. Every event also goes to the structured log.
- **Backups.** Online, always encrypted with a password, verified before restore, into any backend.

## Requirements

**Every node's clock must be synchronised with NTP** (chrony, systemd-timesyncd, or the cloud provider's time
service), keeping the nodes within milliseconds of each other. Compliance standards expect it anyway (consistent audit
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

The version is kept in `internal/build/version.go` (`quisora --version` shows it); a build stamps the git commit and
the date. To release, raise `Version` there, commit, and run `task release`: it tags the commit `v<version>` and pushes
the tag (`task tag` does only that), builds every platform, and creates the GitHub release with the binaries and their
SHA-256 checksums. Both refuse while the working tree has uncommitted changes.

## Run a single node

```bash
export QUISORA_MASTER_KEY="$(bin/quisora genkey)"            # keep it: it seals every secret in the store
bin/quisora bootstrap --public-url https://localhost:8443   # once: prints the first admin's invitation link
bin/quisora serve --public-url https://localhost:8443
```

1. `bootstrap` creates the `primary` organization and a super admin (`admin@example.com`) with no password, and
   prints a single-use invitation link.
2. Open the link (accept the self-signed certificate), set a password or create a passkey, then a second factor.
3. The admin console is at `https://localhost:8443/admin`. Users sign in through their application, or their organization's sign-in
   page, `/o/<org id or name>/login`; `https://localhost:8443/` tells them so.

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
organizations): [docs/SERVICE-ACCOUNTS.md](docs/SERVICE-ACCOUNTS.md). MCP servers and AI clients that register themselves, and
Quisora's own MCP server for managing users and groups from an AI client: [docs/MCP.md](docs/MCP.md).
Connecting applications (sign-in, client credentials, device sign-in, token exchange, PAR, DPoP, FAPI 2.0):
[docs/oauth](docs/oauth/README.md). How people sign in (passkeys, upstream providers, recovery codes, codes by email):
[docs/sign-in](docs/sign-in/README.md). SSH certificates for servers: [docs/ssh](docs/ssh/README.md). Emergency sign-out and lock-out: [docs/emergency-sign-out.md](docs/emergency-sign-out.md). Email templates per organization: [docs/EMAILS.md](docs/EMAILS.md).
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
| `quisora ssh login`, `status`, `logout`, `host-sign`, `fetch` | Get SSH certificates from a tenant's certificate authority, and keep a server's trusted CA keys and revocation list current; a plain client that needs no configuration or master key ([docs/ssh](docs/ssh/README.md)) |
| `quisora genkey` | A new master key, cluster key or BadgerDB encryption key |
| `/healthz`, `/readyz` | Liveness, and readiness for load balancers (with the clock offset and cluster state) |
| `/metrics` | Prometheus metrics, with `metrics.token` as a bearer token ([Metrics](docs/RUNNING.md#metrics)) |
| `/api-docs`, `/api/openapi.json` | The management API's reference and its OpenAPI document |
| SIGHUP | Reload the limits and `server.deny_networks` without resetting any counter ([Limits and denied addresses](docs/RUNNING.md#limits-and-denied-addresses)), the master keys and, in a gossip cluster, the cluster key and size (read from the secret store again where they name one), and the TLS certificate, without a restart ([Rotating the master key](docs/RUNNING.md#rotating-the-master-key)). Each node reads its own file: signal every node |

Behind a load balancer set `server.trust_proxy` to its addresses (the per-address limits and the audit log's
addresses come from `X-Forwarded-For` only then), and `server.shutdown_drain` to how long it takes to stop sending
traffic to a node that is stopping. `server.allowed_networks` lists the private networks sign-in providers and applications
may be on (calls to other private addresses are refused; `server.allow_private_networks` allows them all, for a home
lab), and `server.extra_ca_file` adds private CA roots for them; `server.restore_from` restores a backup at the first start of an empty node. The console's look is a
skin, chosen per organization in the console (with the server's logo, `ui.logo_light`, and footer, `ui.footer`:
[web/skins](web/skins/README.md)), in a light or dark theme that follows
the device's unless `ui.default_theme` says otherwise ([light, dark or system](web/skins/README.md#light-dark-or-system)). Every setting:
[quisora.toml.example](quisora.toml.example) and `quisora serve --help`.

## Audit log and VictoriaLogs

By default audit events are kept in the database for 90 days (`audit.retention_days`), which is for development, home
labs and testing. **Production, and any deployment whose compliance standard or security policy requires a retained
audit trail, must send audit events to VictoriaLogs** (`audit.victorialogs_url`), with retention set there: each node
spools every event to disk before the action that recorded it completes, and it reaches VictoriaLogs through an
outage, a restart or a crash.
How it works, the delivery guarantee and what to alert on: [docs/RUNNING.md](docs/RUNNING.md#audit-log). Controls,
evidence and the VictoriaLogs set-up for SOC 2 (vmauth, retention, the completeness check): [docs/SOC2.md](docs/SOC2.md).

## Development

```bash
task test         # go vet + every test with the race detector, but the cluster package's (the everyday loop)
task test-cluster # the cluster package, the conformance suite against it, and the -tags faults tests (slow)
task test-all     # also against PostgreSQL, MySQL and MariaDB in Docker
task test-ui      # accessibility (axe) and keyboard tests in Chromium
task bench        # Go benchmarks
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute and how to sign the Contributor License Agreement.
