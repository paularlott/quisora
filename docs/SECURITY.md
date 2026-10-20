# Running Quisora securely

The threat model Quisora is built for, what the operator must provide, and what to do when something goes wrong.
How to report a vulnerability: [SECURITY.md](../SECURITY.md).

## Threat model

Quisora is an identity provider: whoever controls it controls every application that trusts it. It is built to
withstand attackers on the internet (no credentials, or a user's own), users of one organization trying to reach
another, applications trying to exceed what they were granted, and someone who obtains a copy of the database or a
backup. It does not defend against someone who controls a node's host, its process memory or its configuration.

| Boundary | Protected by | The operator provides |
| --- | --- | --- |
| Internet → HTTPS | TLS 1.2+ only; strict CSP and HSTS; `__Host-` cookies; CSRF tokens plus Origin checks; rate limits and lockouts; load shedding | A real certificate (or a TLS proxy), `server.trust_proxy` behind a load balancer |
| Applications (OAuth clients) | Exact redirect URIs, PKCE, single-use codes, rotating refresh tokens with reuse detection, audience-bound introspection | Least-privilege clients: scopes, tenants, `introspect_org` only for resource servers |
| Organizations and tenants | One authorization layer in the service; organization checked on every read and write | Few super admins; reviewed access |
| Database and backups | Secrets sealed with the master key (TOTP secrets, signing and provider keys, upstream tokens); passwords hashed (argon2id); bearer secrets stored as hashes; backups encrypted with a password | Encryption at rest of the storage (or BadgerDB's `encryption_key`); verified TLS to a database server |
| Node ↔ node (gossip) | Messages encrypted and authenticated with `cluster.key`; incompatible builds refused | `cluster.key` kept like the master key; the gossip port reachable by cluster members only |
| Outbound (providers, JWKS, back-channel logout) | The address actually dialled is checked: no private, loopback or metadata addresses unless `allow_private_networks` | — |
| Operator (CLI, configuration) | Fully trusted; CLI actions audited with the OS user and host | Who can log in to the hosts and read the configuration |

## Hardening checklist

Before production:

1. **Master key** (`server.master_key`): from a secret store, as an environment variable or in a config file only root
   can read, never on the command line or in the data directory. Kept apart from the data and from the backups.
   [Rotate it](RUNNING.md#rotating-the-master-key) on a schedule.
2. **TLS**: a real certificate; behind a load balancer, `server.trust_proxy` set to its addresses, so rate limits see
   real client addresses.
3. **Database**: verified TLS (no start-up warning about it); encryption at rest (RUNNING.md,
   [Encryption at rest](RUNNING.md#encryption-at-rest)).
4. **Cluster**: `cluster.key` from a secret store; the gossip port (7946) reachable by the other nodes only.
5. **Audit**: VictoriaLogs with the spool turned on, retention covering your audit period, and nobody able to delete
   from it; the structured log shipped too, with an alert on `audit.undelivered` (RUNNING.md, [Audit log](RUNNING.md#audit-log)).
6. **Monitoring**: `metrics.token` set and the [suggested alerts](RUNNING.md#metrics) in place.
7. **Backups**: on a schedule, encrypted (the default), the password kept apart from them; a restore tested regularly.
8. **People**: as few super admins as possible; every administrator with a passkey or authenticator app; API tokens
   with short lifetimes (set `tokens.api_token_max_days`: there is no limit by default); access reviewed
   periodically from the user lists.
9. **Mail**: `mail.tls` `starttls` or `tls`.

## Incident response

Every step below is in the audit log. Where it says "the audit log", search it (the console's audit page, or LogsQL in
VictoriaLogs) by target, actor, action or `request_id`.

**An administrator's account may be compromised.**
1. Disable the account (it ends every session and refresh grant at once), or remove its password and send a new
   invitation.
2. Revoke its API tokens (`DELETE /api/v1/orgs/{org}/users/{id}/tokens/{token}`).
3. Review what it did: the audit log with that actor. Look for new administrators, new clients or providers, changed
   organization settings, invitations, and backups downloaded.
4. If it was a super admin, also consider the steps for the master key and the signing keys below.

**A user's account may be compromised.** Revoke its sessions (`DELETE /api/v1/orgs/{org}/users/{id}/sessions`), remove
its password and send a new invitation (it resets the second factor too), and review the applications it consented
to (`oauth.consent`, `oauth.grant`).

**A client secret leaked.** Rotate it (`POST /api/v1/orgs/{org}/clients/{id}/secret`); the old one stops working at
once. Revoke the client's grants by disabling the client if tokens may have been issued with it.

**Signing keys may be exposed.** Rotate now (the console's Signing keys page, or `POST /api/v1/keys/rotate`). The new
key signs at once; tokens signed with the old one keep working until they expire (`tokens.access_ttl`, 10 minutes by
default).

**The master key may be exposed.** [Rotate it](RUNNING.md#rotating-the-master-key) and remove the old key as soon as the
re-seal is done; relying parties' refresh tokens from before then stop working and their users sign in again. Treat
the backups made with the old key as exposed only if their passwords may be too: a backup's encryption does not use
the master key.

**A backup or the database leaked.** Passwords are argon2id hashes and secrets are sealed: without the master key they
are of no use. Rotate the master key anyway, and reset passwords if you cannot rule out offline guessing of weak ones.

**`cluster.key` leaked.** Anyone on the network path can read and inject gossip. Rotate it on every node while the
cluster runs ([rotating the cluster key](RUNNING.md#rotating-the-cluster-key)), finish the last round promptly, and
check who could reach the gossip port.

**Signs of an attack in the metrics or the audit log** (bursts of `login.failure`, `login.limited`,
`oauth.client_auth.limited`; any `oauth.refresh.reuse`, `oauth.code.replay` or `passkey.clone`): the event names the
target and the address. Reuse and replay have already revoked the grant concerned; a cloned passkey has already been
disabled and its sessions ended. Block the address upstream if the attack continues, and follow the account steps
above for the targets.

Keep the evidence: export the relevant audit events before their retention ends.
