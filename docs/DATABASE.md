# Database tables

The tables Quisora creates in a SQL database (`postgres`, `mysql`, `mariadb`, `sqlite`), and what each one is for.
BadgerDB keeps the same records under keys instead of tables. Quisora creates and upgrades the schema itself at
start-up ([Storage backends](RUNNING.md#storage-backends)). The database is Quisora's alone, so the tables have no
prefix. No table name is a reserved word in any of the four databases.

Read these tables for diagnosis only. Every record also lives in a `data` column in a binary encoding. A change made
in SQL skips Quisora's own checks, audit events and replication, and the next write of the record overwrites it. To
copy or move data, use `quisora backup` and `quisora restore` ([Backup and restore](RUNNING.md#backup-and-restore)).

## Record tables

There is one table per kind of record. They all share one layout: the record's `id`, its `version`, its `scope`
(usually the organization it belongs to), `expires`, a `deleted` flag (a tombstone, kept for a while so that
replication and caches see the delete), the encoded record in `data`, and the partition columns (`part`, `pnum`,
`pseq`) used by [replication](REPLICATION.md). After those come the record's queryable fields (its own columns, with
indexes), so that lists and filters run without decoding `data`.

| Table                | Holds                                                                                                                              |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `organizations`      | Organizations and their settings.                                                                                                  |
| `organization_logos` | An organization's logos (light and dark) and their image types: a record of their own, so that the organization's record stays small. Served by Quisora at `/o/<org>/branding/`. |
| `users`              | User accounts, including service accounts.                                                                                         |
| `user_groups`        | Groups of users. A group's record is also the commit point for changes to its member list.                                         |
| `group_members`      | Group memberships, one row per user per group. A removed membership is kept for a while, then expires.                             |
| `tenants`            | Tenants: an organization's applications grouped under shared sign-in rules, with the tenant's SSH certificate settings. Its `ssh_enabled` column (indexed) is true while SSH certificates are on: housekeeping lists the tenants with SSH on by it. |
| `tenant_access`      | Who may use a tenant's applications: a user or a group, for all of them or for listed ones, with the roles and tags its tokens carry. |
| `clients`            | Applications: OAuth 2 / OpenID Connect clients.                                                                                    |
| `identity_providers` | Upstream identity providers an organization signs in with (OIDC, Google, Microsoft, GitHub, GitLab, Auth0, another organization). Client secrets are sealed with the master key. |
| `passkeys`           | Users' WebAuthn passkeys.                                                                                                          |
| `linked_identities`  | A user's accounts at upstream identity providers, linked to the user.                                                              |
| `sessions`           | Browser sign-in sessions.                                                                                                          |
| `refresh_grants`     | Refresh-token grants: what an application was granted in a sign-in, valid while the session it came from is.                      |
| `app_consents`       | What each user allowed each application on its consent screen, one row per user and application, kept until the user or an administrator removes the application's access. Indexed by `client_id`. |
| `api_tokens`         | API tokens (`qsr_…`) for the management API and SCIM.                                                                              |
| `signing_keys`       | Token signing keys, with private keys sealed by the master key. Kept until they are no longer published.                          |
| `ssh_ca_keys`        | Tenants' SSH certificate authority keys, with private keys sealed by the master key; indexed by `tenant_id`. Kept until they are no longer published. A key removed by hand stays as a tombstone (`Removed` set, private key dropped) until every certificate it could have signed has expired (24 hours and 10 minutes for a user key, 365 days and 10 minutes for a host key): the tenant's revocation list revokes the key itself meanwhile. |
| `ssh_certificates`   | SSH certificates issued, until they expire: what a tenant's revocation list and the certificate lists are made from. Indexed by `user_id` and `revoked` (and sortable by `created`), and by the tenant under `tenant_id` for a user certificate and under `host_tenant_id` for a host certificate (so the revocation list reads a tenant's user certificates without its host certificates). |
| `audit_events`       | The audit log, kept for its retention period.                                                                                      |
| `link_tokens`        | Single-use emailed links (invitation, password reset, email verification). Only a hash of each link is stored.                    |
| `sign_ins`           | A user's sign-in stamps (last sign-in, the TOTP step last used), kept apart from the user so that a sign-in never overwrites an administrator's change. |
| `leases`             | Leases with a holder and an end time, for example each node's report of its master keys and an organization's deletion guard.     |
| `single_use_values`  | Single-use values seen (a client assertion's or a DPoP proof's `jti`), kept until they expire so that a value is refused a second time. |
| `ephemeral_state`    | Short-lived sign-in state (codes, flows, challenges, rate-limit counters), shared by the nodes of a shared database. Not backed up or replicated. |
| `retry_queue`        | Each node's retry queue (emails waiting for SMTP, back-channel logouts waiting for their application). Node-local: not backed up or replicated. |

## Other tables

| Table              | Holds                                                                                                                                  |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| `unique_values`    | Values that must be unique, such as an organization's name or a user's email address. Each maps a kind and value to the record that holds it. |
| `store_identity`   | One row: the database's random id, created with the database and replaced by a restore. A node uses it to tell that its database was wiped, replaced or restored, so the cluster state it saved no longer applies. |
| `schema_version`   | One row: the schema version, which start-up migrations bring up to date.                                                               |
| `partition_state`  | One row per replication partition: its protocol state ([REPLICATION.md](REPLICATION.md)). Empty without gossip replication.          |
| `partition_import` | Marks a partition that is being copied whole from another node. Empty except during such a copy.                                     |

On MySQL and MariaDB, nodes that share the database also take a server-wide lock named `quisora_schema` while they
migrate, so only one of them does it.
