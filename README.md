# Quisora

**This Software is Pre-release:** there is no upgrade path between development builds. Start each build with an empty database.

> Quisora (pronounced "kwih-SOR-ah") comes from the Latin *quis? ōrā*, meaning "who? speak", a sentry's challenge at the gate.

Quisora is a clustered identity provider in one binary: OpenID Connect and OAuth 2 for your applications, passkeys and
multi-factor sign-in for your users, SCIM 2.0 and a REST API for automation, and a multi-organization admin console.
It runs on Linux, macOS and Windows. Licensed under the [Apache License 2.0](LICENSE).

## Features

- **Organizations, tenants, applications.** Any number of organizations, each with its own users, groups, sign-in
  providers and policies. Tenants group applications that share sign-in rules and access lists (users and groups,
  application roles, end dates).
- **Sign-in.** Passkeys (as the whole sign-in or a second factor), password plus authenticator app (TOTP), recovery
  codes for a lost second factor, codes by email as a second factor where an organization allows it, and upstream providers per organization: Google, Microsoft, GitHub, GitLab, Auth0
  and any OpenID Connect provider. Invitation links instead of admin-set passwords. Per-organization and per-tenant
  MFA.
- **OpenID Connect and OAuth 2.** Authorization code with PKCE, refresh tokens, client credentials, introspection,
  revocation, userinfo, RP-initiated and back-channel logout, resource indicators, pushed authorization requests
  (RFC 9126), token exchange (RFC 8693), DPoP-bound tokens (RFC 9449), `claims` and `acr_values`. JWT
  access tokens signed with ES256, EdDSA, RS256 or PS256, and keys rotate automatically. The FAPI 2.0 Security
  Profile can be turned on per application. Passes the OpenID Foundation
  certification plans ([docs/conformance.md](docs/conformance.md)).
- **Automation.** SCIM 2.0 per organization (Entra ID and Okta dialects), a versioned management API with an OpenAPI
  document, and personal API tokens with scopes. Keys and passwords can be read from HashiCorp Vault or 1Password
  (Connect, or a service account in the 1Password build) and rotated without a restart.
- **Roles.** Super admin, admin, manager and user. Managers and above always use a second factor. Only a super admin
  can reset a manager's or administrator's sign-in (a new invitation, removing the password) or lower their role, so
  one administrator cannot take over another's account.
- **Admin console.** Light and dark themes, live updates across nodes, WCAG 2.2 AA, no CDNs.
- **Storage.** BadgerDB, SQLite, PostgreSQL, MySQL, MariaDB or Valkey.
- **Clustering.** Several nodes on one shared database, or nodes with their own databases replicating over gossip,
  with quorum writes for security-sensitive records.
- **Audit log.** In the database, or in VictoriaLogs for real deployments. Every event also goes to the structured log.
- **Backups.** Online, encrypted with a password by default, verified before restore, into any backend.

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
3. The admin console is at `https://localhost:8443/admin`.

This runs on BadgerDB in `./data` with a self-signed certificate. For a real deployment, set:

- `--public-url` to your address,
- `--tls-cert` / `--tls-key`,
- `--data-dir`,
- the master key (`quisora genkey`) from a secret store, as `QUISORA_MASTER_KEY` or in the config file.

Every flag is also an `QUISORA_*` variable and a TOML key: see `quisora serve --help` and
[quisora.toml.example](quisora.toml.example).

## Clusters

- **Shared database:** point every node at the same PostgreSQL, MySQL, MariaDB or Valkey database and give them the
  same `--master-key`. There's no gossip; the database is the only copy.
- **Replicated:** every node has its own database (any backend, e.g. BadgerDB) and sets `cluster.bind`, `cluster.peers` (every node), `cluster.size` and `cluster.key`. Run `quisora bootstrap --new-cluster` on one node first.

Both modes, every storage backend, Docker, backups and recovery: [docs/RUNNING.md](docs/RUNNING.md). Replication rules
and outage procedures: [docs/REPLICATION.md](docs/REPLICATION.md). Running it securely (threat model, hardening checklist, incident
response): [docs/SECURITY.md](docs/SECURITY.md). Personal data and data subject requests: [docs/PRIVACY.md](docs/PRIVACY.md). Scripts and tools with personal API tokens:
[docs/API-TOKENS.md](docs/API-TOKENS.md). MCP servers and AI clients that register themselves:
[docs/MCP.md](docs/MCP.md).
Reporting a vulnerability: [SECURITY.md](SECURITY.md).

## Audit log and VictoriaLogs

By default audit events are kept in the database for 7 days (`audit.retention_days`). In a gossip cluster each node
keeps its own, and the audit page merges them. That built-in audit trail is for development, home labs and testing.

**Production, and any deployment that needs SOC 2, must send audit events to VictoriaLogs**, with retention set there
(typically a year or more); a disk spool in each node's data directory keeps an outage of VictoriaLogs from losing
anything. Every node's
audit page then reads from VictoriaLogs:

```toml
[audit]
victorialogs_url = "http://victorialogs:9428"
victorialogs_spool_max_mb = 256           # the spool is <data_dir>/auditspool, one per node
```

Details: [docs/RUNNING.md](docs/RUNNING.md#audit-log).

## Development

```bash
task test         # go vet + all tests with the race detector
task test-all     # also against PostgreSQL, MySQL, MariaDB and Valkey in Docker
task test-ui      # accessibility (axe) and keyboard tests in Chromium
task bench        # Go benchmarks
```
