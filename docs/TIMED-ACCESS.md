# Time-limited access

A tenant's access list (members-only tenants) can give a user or group access **until a set time**: three hours to deal
with an incident, a day to help a customer. Quisora does not decide who should have it. An administrator gives it in the
console, or an external tool that approves requests its own way (a ticketing system, a chat bot, a CRM) gives it through
the management API, and Quisora enforces the end.

## Giving it

**Console:** the tenant's page → **Access** → **Add access** (or edit an entry) → **Access ends**. The date and time are
your own: the form names your time zone (say `Australia/Perth, UTC+08:00`) and sends the instant to the server, which
keeps it in UTC. Lists show it in each viewer's own time zone. An end set through the API, to the second, is kept as it
is when someone edits the entry's roles in the console.

**API:** the access endpoints, as an administrator or a [service account](SERVICE-ACCOUNTS.md) with the `access` scope:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$QUISORA/api/orgs/acme/tenants/$TENANT_ID/access" \
  -d '{"subject_type": "user", "subject_id": "034yW…", "expires": "2026-11-17T15:00:00+08:00",
       "roles": ["support"], "reason": "SUP-4211 approved by sam@acme.example"}'
```

- `expires` is an RFC 3339 time **with its offset** (`+08:00`, or `Z` for UTC); a date alone, or a time without an
  offset, is refused, so an end is never a guess about whose time zone was meant. It comes back in UTC. A new end must
  be in the future: to end access now, remove the entry. `""` takes the end off.
- `reason` (at most 500 characters) is recorded in the audit log with the change; it is not stored on the entry.
- Longer access is the same entry with a later end (`PATCH`); there is one entry per user or group in a tenant.

## How it ends

Nothing has to run for access to stop: every access decision (sign-in, refresh, introspection, userinfo, SSH
certificates) reads the entries again, on every node, so at the end the user is refused at once.

- **Access tokens** issued while only entries with an end let the user in expire by the latest of those ends; so do
  **SSH certificates** of the tenant. With an entry without an end too (their own or a group's), tokens last as usual.
- **Within a minute** the housekeeping leader removes the entry (`tenant.access.expire` in the audit log, as the
  system), and signs the people it let in out of each application they no longer have: back-channel logout to the
  application, their refresh tokens and SSH certificates for it revoked. Someone another entry (or a group's) still lets
  in is left alone.
- **Removing or narrowing** an entry (fewer applications, an earlier end) does the same at once.
- A guest who came into another organization through an [organization provider](sign-in/providers.md#only-some-of-ss-users-for-a-time-a-members-only-tenant)
  whose sign-in application is in this tenant is out of that organization at the same moment for every check Quisora
  makes (their session there, refresh, userinfo and introspection), and their sessions there are signed out with the
  rest. Access tokens already issued to that organization's applications are not shortened: an application that
  checks them only by their signature accepts them until they expire (minutes, the access token lifetime), and the
  guest's SSH certificates there count until servers next fetch the revocation list.

An application that keeps its own session for hours without refreshing or introspecting its tokens hears of the end
through back-channel logout; register a back-channel logout URI for it.

## Audit

`tenant.access.add`, `tenant.access.update` and `tenant.access.remove` (by the actor, with `expires` in UTC and the
`reason` given) and `tenant.access.expire` (by the system), in the organization's audit log.
