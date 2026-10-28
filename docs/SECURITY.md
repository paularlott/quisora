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
| Internet → HTTPS | TLS 1.2+ only; strict CSP and HSTS; `__Host-` cookies (one session cookie per organization); CSRF tokens plus Origin checks; rate limits and lockouts; load shedding; passwords of at least `limits.password_min_length` characters (15 by default), refused when they are a common word dressed up, a keyboard or alphabet run, a repeated pattern, or built on the person's name, email or organization (offline checks, nothing is looked up elsewhere; there is no list of breached passwords) | A real certificate (or a TLS proxy), `server.trust_proxy` behind a load balancer |
| Applications (OAuth clients) | Exact redirect URIs, PKCE, single-use codes, rotating refresh tokens with reuse detection, audience-bound introspection; every organization is its own authorization server (its own issuer and endpoints: a client of another organization is unknown, and a token of one is not valid at another's) | Least-privilege clients: scopes, tenants, `introspect_org` only for resource servers |
| Organizations and tenants | One authorization layer in the service; organization checked on every read and write; each organization has its own address space, `/o/<org>/…`, and its own browser session, and its unique values are its own | Few super admins; reviewed access |
| Database and backups | Secrets sealed with the master key (TOTP secrets, signing and provider keys, upstream tokens); passwords hashed (argon2id) and the hashes sealed with the master key too (the pepper); bearer secrets stored as hashes; backups encrypted with a password | Encryption at rest of the storage (or BadgerDB's `encryption_key`); verified TLS to a database server |
| Node ↔ node (gossip) | Messages encrypted and authenticated with `cluster.key`; incompatible builds refused; a catch-up stream goes from the database to the other node's database without touching the disk in between | `cluster.key` kept like the master key; the gossip port reachable by cluster members only; BadgerDB with `storage.badgerdb.sync_writes = true` |
| Outbound (providers, JWKS, back-channel logout) | The address actually dialled is checked: no private or loopback addresses but the networks in `allowed_networks` (or all of them with `allow_private_networks`), and never metadata, link-local or special-purpose addresses | — |
| Operator (CLI, configuration) | Fully trusted; CLI actions audited with the OS user and host | Who can log in to the hosts and read the configuration |

In a gossip cluster (`cluster.bind`): **BadgerDB must run with `storage.badgerdb.sync_writes = true`** (the default; a gossip
node refuses to start without it), because a node's promises and the writes it acknowledges to the owner of a partition
must be on disk when it answers (RUNNING.md, [Choosing a store](RUNNING.md#replicated-gossip)). And **a node writes no
export files**: another node's catch-up is streamed from the database as it is read and never spooled to the data
directory, so nothing a node holds sits outside the store's own encryption at rest (BadgerDB's `encryption_key`, or the
encrypted volume). An older build left `export-*.tmp` files there when it crashed during a catch-up; this one neither reads nor
deletes them, so remove any that remain by hand.

Accepted: usernames, email addresses and external ids are unique within an organization, so a manager or
administrator creating or editing a user learns that a value is taken even when the account holding it is one they do
not see (an administrator to a manager, a super admin to everyone below them). Only that the value is in use, not who
holds it; reads, listings and searches still withhold the account.

The audit log follows the same rule: an organization's administrators read its events without those whose actor or
target user is a super admin (their sign-ins, with address and methods, and the changes made to them), and the page,
its total and its search leave them out. Each event is marked when it is written, by the accounts it names (their ids,
not their names: a rename reveals nothing), and never re-marked: what a user did before they were made a super admin
stays visible to the admins who saw it then. An event names a user in its actor, target and detail; only the first two
are judged, so a super admin named only in an event's detail (a group membership change) is still shown by id.

## Hardening checklist

Before production:

1. **Master key** (`server.master_key`): best read from Vault or 1Password ([references](secret-stores.md),
   with read access to Quisora's items only), else an environment variable or a config file only Quisora's user can
   read; never on the command line or in the data directory. Kept apart from the data and from the backups.
   [Rotate it](RUNNING.md#rotating-the-master-key) on a schedule.
2. **TLS**: a real certificate; behind a load balancer, `server.trust_proxy` set to its addresses, so rate limits see
   real client addresses.
3. **Database**: verified TLS (no start-up warning about it); encryption at rest (RUNNING.md,
   [Encryption at rest](RUNNING.md#encryption-at-rest)).
4. **Cluster**: `cluster.key` from a secret store; the gossip port (7946) reachable by the other nodes only.
5. **Audit**: VictoriaLogs, which every production deployment needs (the database trail is for development and
   testing; each start without VictoriaLogs logs a warning). Its spool is always on, in each node's data directory:
   give it room. Retention covering your audit period, and nobody able to delete
   from it; the structured log shipped too, with an alert on `audit.undelivered` (RUNNING.md, [Audit log](RUNNING.md#audit-log)).
6. **Monitoring**: `metrics.token` set and the [suggested alerts](RUNNING.md#metrics) in place.
7. **Backups**: on a schedule, encrypted (the default), the password kept apart from them; a restore tested regularly.
8. **People**: as few super admins as possible; every administrator with a passkey or authenticator app; API tokens
   with short lifetimes (`tokens.api_token_max_days`: 365 by default; lower it to what your scripts need); access reviewed
   periodically from the user lists.
9. **Mail**: `mail.tls` `starttls` or `tls`. Codes by email as a second factor stay off (the default) unless
   the mailboxes are at least as well protected as the passwords.

## Incident response

Every step below is in the audit log. Where it says "the audit log", search it (the console's audit page, or LogsQL in
VictoriaLogs) by target, actor, action or `request_id`.

**Everyone must be signed out now** (an attacker may hold sessions or tokens, and you do not know whose). Pull the
emergency sign-out: an organization's **Overview** page (its administrators and super admins), the **System overview**
for every organization (super admins), `POST /api/orgs/{org}/sign-out` or `POST /api/sign-out`, or, when the console
cannot be used, `quisora sign-out --org <name>` / `--all` on a server with the master key. Every browser session and
refresh grant stops at once on every node (so do the access tokens issued from them, through userinfo and
introspection), and with the API-token option every personal API token too. Your own session stays. Applications are
told (back-channel logout); ones that check access tokens themselves accept those already issued until they expire
(`tokens.access_ttl`, 10 minutes by default). Applications acting for themselves (client credentials) are not
affected: rotate their secrets, and disable a client to end the tokens it already holds. It is audited as `org.signout` / `server.signout`, then `signout.sweep`. See
[emergency sign-out](emergency-sign-out.md).

**An administrator's account may be compromised.**
1. Lock it out: the user's page, **Lock out** (`POST /api/orgs/{org}/users/{id}/lock-out`). It disables the account,
   ends every session and refresh grant at once, and removes its password, authenticator app, passkeys, linked
   providers, API tokens and unused invitation and reset links, so enabling it again brings none of that back. An
   established manager's or administrator's account is locked out by a super admin.
2. Review what it did: the audit log with that actor. Look for new administrators, new clients or providers, changed
   organization settings, invitations, and backups downloaded.
3. If it was a super admin, also consider the steps for the master key and the signing keys below.

**A user's account may be compromised, or someone has left.** Lock it out (as above), then, to let the right person
back in, enable it and send a new invitation. Review the applications it consented to (`oauth.consent`,
`oauth.grant`).

**A client secret leaked.** Rotate it (`POST /api/orgs/{org}/clients/{id}/secret`); the old one stops working at
once. Revoke the client's grants by disabling the client if tokens may have been issued with it.

**Signing keys may be exposed.** Rotate now (the console's **System overview**, or `POST /api/keys/rotate`),
then **Remove** on the old key (`DELETE /api/keys/{id}`). The new key signs at once; the tokens the old one signed
stop verifying here at once, and in applications once they fetch the key set again. Applications get new tokens
through their refresh tokens: nobody is signed out. Without the removal they keep working until they expire.

**The master key may be exposed.** [Rotate it](RUNNING.md#rotating-the-master-key) and remove the old key as soon as the
re-seal is done. A rotation re-seals what the key seals without changing it: sessions and relying parties' refresh
tokens keep working (each grant's key is re-sealed, not replaced), and so does any refresh token that whoever holds a
copy of the database from before the rotation, and the old key, makes from it. So pull the [emergency sign-out](emergency-sign-out.md) for every
organization too (`quisora sign-out --all`, with `--api-tokens`: it ends every session and refresh grant), rotate the
signing keys (above), and have users with an authenticator app set it up again; the list under
[the rotation](RUNNING.md#rotating-the-master-key) has the rest. Treat the backups made with the old key as exposed only if their
passwords may be too: a backup's encryption does not use the master key.

**A backup or the database leaked.** Password hashes and secrets are sealed with the master key: without it they are
of no use, and there is nothing to guess passwords against offline. If the master key may have leaked as well, the
hashes are argon2id: do everything under the master key above, and reset passwords if you cannot rule out offline guessing of weak ones.

**`cluster.key` leaked.** Anyone on the network path can read and inject gossip. Rotate it on every node while the
cluster runs ([rotating the cluster key](RUNNING.md#rotating-the-cluster-key)), finish the last round promptly, and
check who could reach the gossip port.

**A user lost their authenticator app or passkey.** With recovery codes they sign in with one of those and set up a
new factor; without, an administrator sends them an invitation (which replaces every credential). A
`login.recovery_code` they did not make means someone has their password and their codes: lock the account out.
Where the organization allows codes by email, a `login.email_code.sent` the user did not ask for means someone has
their password: reset it, and check who can read their mailbox.

**A user approved a device sign-in they did not start** (they entered a code someone sent them). Find the
`oauth.device.approve` and the `oauth.grant` after it, revoke that grant (the user's **Applications**, or sign the
user out everywhere), and consider whether the application needs device sign-in at all. Managers and administrators
cannot be caught this way unless the client allows them to approve device sign-ins.

**Nobody can get into the console** (break-glass: the last super admin lost their password, authenticator and
passkeys, left, or their account ended). Recovery needs a server's configuration and the master key, not the console,
and the servers keep running:

1. On a node (or any machine with its configuration file or `QUISORA_*` environment, including the master key),
   issue a break-glass invitation for a super admin of the primary organization:

   ```bash
   quisora invite primary admin@example.com --break-glass
   ```

   The command asks the running server at `server.public_url` (or `--server https://…`) to issue it, signing the
   request with the master key: no sign-in or API token is involved, and the request is good for two minutes and
   once. The server's certificate is checked against the system roots, `server.extra_ca_file`, `--ca-file` and the
   node's own self-signed certificate; `--insecure` skips the check. With a shared database, or when no server
   answers, the command writes the invitation to the store itself.
2. It prints a single-use link, valid for 24 hours. Earlier unused invitations of that user stop working. Open it, set
   a new password or create a passkey, and enrol a second factor (super admins always need one).
3. It works even when the account is disabled (locked out, or past its end date), and using it enables the account
   again (its end date is cleared if it had passed). Like any invitation, accepting it removes the account's old
   password, authenticator app and passkeys and ends its sessions and API tokens: whoever held the old ones is out.
4. Check the audit log: `user.invite.break_glass` (recorded with the actor `command:invite`, the address the request came
   from, and `detail.command` and `detail.authenticated`, so it is told from what the system does by itself), the
   account enabled again, and the sign-ins after it. Then give a second person super admin so this is not needed again.

   If no super admin is left at all (two removed each other at the same moment on different nodes, or the last one's end
   date passed: the service protects super admins by rank, not by a count), add `--super-admin`:

   ```bash
   quisora invite --break-glass --super-admin primary admin@example.com
   ```

   The account becomes an enabled super admin at once (its end date is cleared if it had passed), and the command still
   prints the invitation link for step 2. It needs `--break-glass`, and refuses a user who is not in the primary
   organization. It is audited as `user.update` (the role and status change) and `user.invite.break_glass`
   (`detail.super_admin=granted`), both by `command:invite`.

Without `--break-glass`, `quisora invite` issues an ordinary invitation (7 days) the same way, and refuses a disabled
account. `quisora sign-out` (the emergency sign-out) is the same kind of request, **signed with the master key and
sent to a running node** (in a gossip cluster the data is changed only through a node: a write to a stopped node's
database would belong to no partition write and reach no other node); it is recorded as `org.signout` or
`server.signout` by `command:sign-out`. The primary organization never changes (the first one, made by `quisora
bootstrap`), so there is no command to move it. `quisora force-start`, which makes a
node copy its data from fewer nodes than a majority, is recorded as `cluster.force_start` by `command:force-start`.
Whoever runs any of these commands holds the master key (or the node's data directory), and with it everything the server protects: keep the
configuration and the key as protected as the break-glass step they enable. A user who is only locked out by failed
attempts needs nothing: the count of failures is a fixed window that starts at the first failure, so the lock ends
`limits.lockout_minutes` (default 15) after that one, not after the failure that tripped it.

**Signs of an attack in the metrics or the audit log** (bursts of `login.failure`, `login.limited`,
`oauth.client_auth.limited`, `api.request.refused`; any `apitoken.refused` with reason `wrong secret`,
`oauth.refresh.reuse`, `oauth.code.replay` or `passkey.clone`): the event names the
target and the address. Reuse and replay have already revoked the grant concerned; a cloned passkey has already been
disabled and its sessions ended. Block the address upstream if the attack continues, and follow the account steps
above for the targets.

Keep the evidence: export the relevant audit events before their retention ends.
