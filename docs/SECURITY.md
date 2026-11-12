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
| Internet → HTTPS | TLS 1.2+ only; strict CSP and HSTS; `__Host-` cookies (one session cookie per organization); CSRF tokens plus Origin checks; rate limits and lockouts; load shedding; passwords of at least the organization's shortest, else `limits.password_min_length` characters (15 by default), refused when they are a common word dressed up, a keyboard or alphabet run, a repeated pattern, or built on the person's name, email or organization (offline checks, nothing is looked up elsewhere; there is no list of breached passwords) | A real certificate (or a TLS proxy), `server.trust_proxy` behind a load balancer |
| Applications (OAuth clients) | Exact redirect URIs, PKCE, single-use codes, rotating refresh tokens with reuse detection, audience-bound introspection; every organization is its own authorization server (its own issuer and endpoints: a client of another organization is unknown, and a token of one is not valid at another's) | Least-privilege clients: scopes, tenants, `introspect_org` only for resource servers; `accepts_api_tokens` only for applications that check personal API tokens |
| Organizations and tenants | One authorization layer in the service; organization checked on every read and write; each organization has its own address space, `/o/<org>/…`, and its own browser session, and its unique values are its own | Few super admins; reviewed access |
| SSH certificates | Certificates only after a second-factor sign-in, short-lived, with principals from the user's username, `group:` groups and `role:` roles (a username holds no colon, so none can be named like a group); a revocation list worked out from the user's state, which also revokes CA keys outright; the CA keys sealed with the master key | `AuthorizedPrincipalsFile` on every server, privileged accounts mapped by group and never by username; the fetch timer and its [monitoring](ssh/README.md#monitoring); `RevokedHostKeys` on clients and short host certificates; a login that works while Quisora does not ([guide](ssh/README.md#if-quisora-is-not-reachable)) |
| Database and backups | Secrets sealed with the master key (TOTP secrets, signing and provider keys, tenants' SSH CA keys, upstream tokens); passwords hashed (argon2id) and the hashes sealed with the master key too (the pepper); bearer secrets stored as hashes; backups encrypted with a password | Encryption at rest of the storage (or BadgerDB's `encryption_key`); verified TLS to a database server |
| Node ↔ node (gossip) | Messages encrypted and authenticated with `cluster.key`; incompatible builds refused; a catch-up stream goes from the database to the other node's database without touching the disk in between | `cluster.key` kept like the master key; the gossip port reachable by cluster members only; BadgerDB with `storage.badgerdb.sync_writes = true` |
| Outbound (providers, JWKS, back-channel logout, pictures given by URL) | The address actually dialled is checked: no private or loopback addresses but the networks in `allowed_networks` (or all of them with `allow_private_networks`), and never metadata, link-local or special-purpose addresses | — |
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

**Profile pictures are public to whoever has their URL.** A user's picture is served without authentication at
`/o/<org id>/pictures/<id>`, because applications show it in an `<img>` on their own pages; the id is 128 random bits,
new for every picture and unrelated to the user's id, and is the only thing that keeps the picture from others (anyone
an application or a token shows it to can pass it on). Only a user's current picture is served: a replaced or removed
one, or a deleted user's, answers 404 at once and is removed from the store. Each upload is decoded and encoded afresh
(JPEG, PNG and WebP in; nothing else, no SVG, no GIF), so no metadata (a phone photo's location), no script and no
second file format hidden in it reaches what is stored, and it is served as an image that cannot be anything else
(`Content-Security-Policy: default-src 'none'; sandbox`, `nosniff`). An upload is at most 5 MB and 8192 pixels a side
(the size it decodes to, not its bytes, is what it costs: one is decoded at a time per node, at most four more wait
their turn, as long as their requests do, and any more are refused at once with `503`), and one user's picture
changes at most 20 times an hour. A picture given by URL (SCIM, a sign-in provider) is fetched once through the
outbound guard and never linked to: applications never reach another site through Quisora's pictures. An
organization that wants none sets `settings.pictures` to `off`: nothing is uploaded, copied, served or sent, and the
pictures it held are deleted. A server that wants none for any organization starts with `--disable-pictures`
(`server.disable_pictures = true`): every organization behaves as if its setting were `off`.

**SSH certificates: known limits.** The [guide](ssh/README.md#known-limits) has the detail.

- Open sessions on a server stay open unless it runs `quisora ssh fetch --end-revoked` (Linux with journald; it ends
  connections of revoked certificates and any open longer than `cert_ttl`, with their whole login session where
  systemd-logind made one, `tmux` and `nohup` included; processes started outside it, such as with `systemd-run
  --user`, are not ended), and sshd's `RevokedKeys` covers user logins only: a host certificate that is
  revoked, or whose CA key is removed or SSH is turned off, is refused only by clients that fetch the revocation list and set
  `RevokedHostKeys`. Keep host certificates short.
- The SSH application uses bearer access tokens, not DPoP-bound ones: a token that leaks in the minutes it lives
  (`tokens.access_ttl`) can be used to ask for a certificate for another key.
- CA key rotation is not atomic across nodes: two nodes acting in the same instant can each make a key, and both are
  published. After a rotation, check the tenant's CA keys and remove an extra one.
- An emailed one-time code counts as a second factor. Where that is too weak for servers, limit the tenant's sign-in methods
  (to passkeys, say).
- A username principal is a login name, and managers can create and rename users and add people to groups: always match
  certificates to accounts with `AuthorizedPrincipalsFile`, and do not map privileged accounts by username.
- Certificates already issued outlast a Quisora outage, but no new one is signed during it.
- Restoring an older backup can republish a removed CA key, undo revocations, and forget certificates issued after it.

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
   with short lifetimes (`tokens.api_token_max_days`: 365 by default; lower it to what your scripts need); the
   organization's setting for who may make `api` tokens left off (the default) or limited to the groups that need them;
   access reviewed periodically from the user lists. Quisora's own MCP server ([MCP.md](MCP.md#quisoras-own-mcp-server))
   left off unless AI assistants are to manage users (it is off for every organization until a super admin switches it
   on, and accepts only managers and up who signed in with a second factor), or turned off for the whole server with
   `--disable-mcp`; where it is on, its approved clients reviewed under **Self-registered apps**.
9. **Mail**: `mail.tls` `starttls` or `tls`. Codes by email as a second factor stay off (the default) unless
   the mailboxes are at least as well protected as the passwords.
10. **SSH certificates** (if you use them): `AuthorizedPrincipalsFile` on every server, with `group:` principals for
    privileged accounts; the fetch timer, with `--end-revoked` on Linux, alerting on failure and on a revocation list older
    than 5 minutes; a break-glass
    login that does not depend on Quisora; host certificates of a few weeks, with `RevokedHostKeys` on the clients;
    the CA key fingerprints checked against the console on first use ([SSH certificates](ssh/README.md)).

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

**A person's SSH access must end, or an SSH certificate may be stolen.** Lock the person out or disable them, sign them
out everywhere, or revoke the certificate (the tenant's **SSH certificates** card, or
`POST /api/orgs/{org}/tenants/{id}/ssh/certificates/{cert}/revoke`): the certificates go on the tenant's revocation
list and servers refuse them when they next fetch it, in a minute or two. Signing out one session, or revoking one
application's grant, is **not** enough: it leaves the certificates asked for under it valid. An
[emergency sign-out](emergency-sign-out.md) revokes every certificate issued before it the same way. Sessions already
open on a server stay open: end them there. Look in the audit log for `ssh.cert.issue` by that person and in sshd's log
for the certificate's key id and serial ([SSH certificates](ssh/README.md#revocation)).

**An SSH CA key may be exposed.** Anyone holding it can sign a certificate for any principal, and no list of serials names
such a certificate. In the tenant's **SSH certificates** card (or `POST /api/orgs/{org}/tenants/{id}/ssh/rotate` with
`{"purpose": "user", "immediate": true}`, from the console or a service account: a personal API token cannot) rotate
the key **immediately**, then **remove** the old key. Rotating alone leaves the old key published and trusted; removing it
makes the revocation list revoke the key itself, so every server that fetches the list distrusts the key and everything
it signed, forged certificates included, whether or not its CA file changed. Everyone signs in again for a new
certificate. For a host key, also re-sign the hosts and refresh the clients' `known_hosts`; clients refuse the old host key
only if they fetch the list and set `RevokedHostKeys` ([CA key rotation](ssh/README.md#ca-key-rotation)). The CA keys
are sealed with the master key, so a leaked master key together with a copy of the database exposes them too: rotate and
remove them for every tenant that uses SSH. After a restore from backup do the same
([Backup and restore](ssh/README.md#backup-and-restore)).

**A tenant's SSH access must stop altogether.** Turn SSH **off** (not delete the SSH application, which Quisora makes again
within a minute): the revocation list then revokes every certificate and every CA key of the tenant. Delete the tenant only
after the servers have fetched that list ([turning it off](ssh/README.md#turning-it-off-and-removing-a-tenant)).

**The master key may be exposed.** Whoever holds it and a copy of the database, or a backup, from before the rotation
can open everything it sealed, and a rotation re-seals those secrets without changing them. This is the whole list:

1. [Rotate the master key](RUNNING.md#rotating-the-master-key), and remove the old key as soon as the re-seal is done.
2. Pull the [emergency sign-out](emergency-sign-out.md) for every organization: `quisora sign-out --all --api-tokens`.
   A rotation keeps sessions and relying parties' refresh tokens working (each grant's key is re-sealed, not
   replaced), including any refresh token made with the old key from an old copy of the database; the sign-out ends
   every session, refresh grant and personal API token.
3. Rotate and remove the signing keys (above).
4. Rotate and remove the SSH CA keys of every tenant that uses SSH (above).
5. Rotate each sign-in provider's client secret, at the provider and then in Quisora: with the old one, the upstream
   refresh tokens sealed beside it can be used at the provider.
6. Have users with an authenticator app set it up again: the rotation leaves its secret as it was.

Treat the backups made with the old key as exposed only if their passwords may be too: a backup's encryption does not
use the master key. Keep the old key only with those backups, to restore them
([after the rotation](RUNNING.md#after-the-rotation)).

**A backup or the database leaked.** Password hashes and secrets are sealed with the master key: without it they are
of no use, and there is nothing to guess passwords against offline. If the master key may have leaked as well, the
hashes are argon2id: do everything under the master key above, and reset passwords if you cannot rule out offline guessing of weak ones.

**`cluster.key` leaked.** Anyone on the network path can read and inject gossip. Rotate it on every node while the
cluster runs ([rotating the cluster key](RUNNING.md#rotating-the-cluster-key)), finish the last round promptly, and
check who could reach the gossip port.

**A user lost their authenticator app or passkey.** With recovery codes they sign in with one of those (or, still
signed in, confirm a change with one) and set up a new factor; without, an administrator removes the authenticator app
on the user's page (**Remove authenticator app**: they keep their password) or a lost passkey from its list, or sends
them an invitation (which replaces every credential). A
`login.recovery_code` they did not make means someone has their password and their codes: lock the account out.
Where the organization allows codes by email, a `login.email_code.sent` the user did not ask for means someone has
their password: reset it, and check who can read their mailbox.

**A user approved a device sign-in they did not start** (they entered a code someone sent them). Find the
`oauth.device.approve` and the `oauth.grant` after it, revoke that grant (the user's **Applications**, or sign the
user out everywhere), and consider whether the application needs device sign-in at all. For a tenant's SSH application (`quisora ssh login --device`)
the attacker may already hold a certificate: revoke the person's certificates too (above). Managers and administrators
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
the organization's lockout time, else `limits.lockout_minutes` (default 15), after that one, not after the failure that
tripped it. An organization may set its own number of attempts and lockout time; the server's apply where it has not.

**Signs of an attack in the metrics or the audit log** (bursts of `login.failure`, `login.limited`,
`org.spray.start` ([password spraying](#lockout-and-password-spraying)), `oauth.client_auth.limited`,
`api.request.refused`; any `apitoken.refused` with reason `wrong secret`,
`oauth.refresh.reuse`, `oauth.code.replay` or `passkey.clone`): the event names the
target and the address. Reuse and replay have already revoked the grant concerned; a cloned passkey has already been
disabled and its sessions ended. If the attack continues, deny the address: add it to `server.deny_networks` in every
node's config file and reload every node (SIGHUP, or **Reload configuration**), which refuses it with a bare 403 before
any other work and keeps every rate-limit and lockout counter; tighten the limits the same way, by a reload rather than
a restart ([under attack](RUNNING.md#under-attack)). Block many addresses upstream (a firewall, the proxy in front).
Follow the account steps above for the targets.

Keep the evidence: export the relevant audit events before their retention ends.

## Lockout and password spraying

A wrong password (or authenticator code) counts against the account: after the organization's lockout attempts
(`limits.lockout_attempts`, default 10) within its lockout time (`limits.lockout_minutes`, default 15) the account is
refused until the time is up, whoever tries and from wherever, so no password can be guessed more often than that. A
successful sign-in gives back its attempt. An email address with no account is locked the same way, so the lockout does
not tell which accounts exist. A browser that has signed in to the account before (its device cookie) counts its own failures
instead, so someone who locks the account does not lock out its owner's browsers.

Whoever knows an organization's email addresses could spend every account's attempts and keep everyone out of
signing in from a new browser. The per-address request limit (`limits.login_per_ip_min`) does not stop that from many
addresses. So an organization whose sign-in takes more than `limits.org_failures_per_minute` failed passwords
(default 100, `0` turns it off) in a minute is **under a password spray** until a lockout time has passed without
such a minute. While it is, a password attempt from a browser that has not signed in to the account before is charged
to its client address as well as to the account: each address may fail as often as one account may (the lockout attempts in
the lockout time), across the whole organization, and past that it is refused, even the right password (`login.failure`
with reason `address locked`), without the account being charged. An address can then lock at most one account per
lockout time instead of every account it has names for, and the people at other addresses, and everyone on a browser
they signed in from before, sign in as usual.

The account is still charged and locked as before: charging the address instead, or merely slowing a locked account,
would let a botnet guess each password once per address. Charging both keeps each account at its lockout attempts
whatever the number of addresses, while the address budget only ever refuses more. An attacker with at least one
address per account can still lock every account (no server can tell their wrong passwords from its users' own);
the audit log then shows `org.spray.start` (with the failures in the minute that started it) and, at the first
sign-in after it is over, `org.spray.end` (when it started and ended), both with outcome `failure`. Block the
addresses upstream (`login.failure` events name them), and tell people to sign in from a browser they have used
before or with a passkey. Raise the limit for an organization whose people mistype more than 100 passwords a minute
on a busy morning: below it nothing changes.
