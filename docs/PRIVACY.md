# Personal data in Quisora

What Quisora stores about people, for how long, and how to answer a data subject's request (access, correction,
erasure). The organization running Quisora is the controller of this data; this page is the information it needs for
its records of processing and its privacy notice.

## What is stored

| Where | Personal data | Kept |
| --- | --- | --- |
| User | Username, email address and linked addresses (with whether each is verified), given and family name, phone number, locale, time zone, user type, work details (title, department, organization, division, cost centre, employee number, manager), tags, external id, role, status and the reason for its last change, end date, when the password and authenticator were last set | Until the user is deleted |
| Credentials | Password (argon2id hash, sealed), authenticator secret (sealed), passkeys (public key, name, authenticator model id, sign-in counter, when last used) | Until removed, or the user is deleted |
| Sign-ins | Last sign-in time; failed-attempt counters | Counters expire within minutes |
| Sessions | Client IP address, browser user agent, sign-in time and methods | Until the session ends (`session.ttl`, `session.idle`) |
| Applications | Consents and refresh grants: application, scopes, times | Until revoked or expired (`tokens.refresh_ttl`) |
| Connected providers | The provider's subject id and email address; its refresh token (sealed) | Until disconnected, or the user is deleted |
| API tokens | Name, scopes, times (the token itself only as a hash) | Until revoked or expired |
| Audit events | Actor and target (usernames, ids), IP address, user agent, session id, what changed | `audit.retention_days` in the database; in VictoriaLogs, its retention |
| Structured log | Every audit event; with `log.access`, every request's path and client address; recipients of email that could not be delivered | The log pipeline's retention |
| Backups | All of the above, as stored | As long as the backups are kept |

Tokens issued to applications carry the claims the user consented to (names, email address, groups, roles, tags):
those copies are the applications' responsibility.

## Requests from data subjects

**Access.** An administrator of the user's organization has it all:

- the user's record, its sessions, applications, tokens and connected providers (the console's user page, or
  `GET /api/orgs/{org}/users/{id}` and the `/sessions`, `/apps`, `/tokens` and `/providers` sub-resources);
- the audit events about the user (search by username, or by id in VictoriaLogs).

There is no one-click export yet: gather these into the answer.

**Correction.** Administrators edit every field; users edit their own profile on the account page (name, locale, time
zone, phone, addresses).

**Erasure.** Deleting the user (`DELETE /api/orgs/{org}/users/{id}`) removes the user record, ends their sessions
and refresh grants (applications are told through back-channel logout) and clears them as manager of others.
Everything else that belonged to them (passkeys, connected providers with the address each gave, API tokens, group
memberships, sign-in records, access entries) stops working at once, since it stands on the user record, and is removed by
the orphan sweep, which reaches every record within about a day at five million users (`docs/REPLICATION.md`,
"Deletion"). Deleting an organization does the same for everything in it.

What remains:

- **Audit events** naming the user, until their retention ends. They are the security record of what happened, and
  are usually kept under a legal obligation or legitimate interest; state that in your privacy notice.
- **Backups**, until they expire. A restore brings the user back: delete them again after restoring.
- **Deletion markers** (the record's id, no personal data), for 7 days, so every node of a cluster learns of the
  deletion.
- **Logs**, for the log pipeline's retention.

## Choices that reduce what is kept

- `audit.logins = false` stops recording successful sign-ins (failures are always recorded). A deployment that needs
  an audit trail, for SOC 2 or another standard, keeps it on: successful sign-ins are the evidence of access reviews ([SOC2.md](SOC2.md)).
- `log.access = false` keeps request paths and client addresses out of the log (it is on by default; query strings
  are never logged).
- Short `audit.retention_days`, and a VictoriaLogs retention no longer than your audit period needs.
- Backups kept no longer than your recovery policy needs.
