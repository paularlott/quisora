# Personal API tokens

A personal API token lets a script or a tool call Quisora as you, without a browser. You make tokens on **Your
account → API tokens → New token**, choose what each one may do (its scopes) and, optionally, when it expires: left
empty, it never expires (unless the server sets a maximum lifetime, which it then gets). The token is shown once,
in the form `qsr_<id>_<secret>`: copy it then. Quisora keeps only a hash of the secret.

For automation that should not depend on a person, use a [service account](SERVICE-ACCOUNTS.md): it belongs to the
organization, holds only the scopes it was granted, and its access tokens are accepted by the same APIs.

A token never has more access than you have: every call is checked against your role and organization at the time it
is made, so if you are demoted or your account is disabled, the token loses that access too.

## Scopes and endpoints

| Scope | Who can choose it | What the token is accepted by |
| --- | --- | --- |
| `admin` | managers and up | The management API, `/api/…` (what the admin console uses), including the live event stream `/api/events` |
| `scim` | managers and up | The SCIM 2.0 API, `/scim/v2/…`, for provisioning tools |
| `backup` | super admins | `GET /api/backup` only; such a token expires within 30 days |
| `import` | super admins | With `admin`: creating users with the password hash, authenticator secret and provider links they had in another system (`password_hash`, `totp_secret`, `identities`) |
| `api` | whoever the organization allows ([below](#who-may-make-api-tokens)) | Nothing in Quisora itself: it is for **your own applications**, which check it through token introspection |

A token with the `api` scope cannot also have `admin`, `scim`, `backup` or `import`: applications that see an `api` token
must never be able to administer Quisora with it. Make a separate token for each purpose.

Send the token as a bearer token on every request:

```bash
export QUISORA=https://id.example.com
export TOKEN=qsr_…
curl -H "Authorization: Bearer $TOKEN" "$QUISORA/api/orgs/acme/users?limit=10"
```

## The management API (`admin`)

Organizations are named in the path (`acme` below). Lists answer `{"items": [...], "total": n}` and take
`?q=` (search: a case-insensitive prefix of a user's username, email address, full name or family name, or of a
group's or organization's name), `sort=`, `desc=1`, `offset=` and `limit=` (at most 100). The full reference is the OpenAPI document
at `/api/openapi.json` (SCIM is in it too), which every server also renders as a browsable reference at `/api-docs/`
(it works without internet access: nothing loads from outside the server). An `Api-Version: 2026-10-20` header
pins the version; without it you get the oldest supported version. Versions are dates: the release that introduced
them, and a new one comes only with a change that would break existing callers.

Every audit event of a change made with a token names it (`token_id`), so a misused token can be found and deleted.
A token that exists but is refused (a wrong secret, or used after an emergency sign-out, or after its owner was
disabled or lost the role its scopes need) is audited as `apitoken.refused` in its organization; a request a valid
token may not make is audited as `api.request.refused`. Both are recorded at most once a minute per token (or
caller) and reason on each node, with `suppressed` counting the repeats held back since the last one: a refusal can be
repeated at will, and must not flood the audit log. Failed bearer authentications (management API and SCIM
together) are limited to 60 per address and organization (the one the path names) and minute: past that, every bearer
request from the address for that organization gets `429 Too Many Requests` with `Retry-After` for the rest of the
minute, before its token is looked at. The organization is looked up first, and one that does not exist is answered
`404` without looking at the token or counting anything. One organization's stale token, retried from the shared
addresses of an identity provider's provisioning service, does not stop other organizations' provisioning from those
addresses, however many organizations have stale tokens. Successful requests never count, so a busy
integration is not slowed; behind a proxy set `server.trust_proxy`, or every caller shares the proxy's address.

```bash
# find a user
curl -H "Authorization: Bearer $TOKEN" "$QUISORA/api/orgs/acme/users?q=alan"

# create one, then send them an invitation link to set up their sign-in
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"username":"grace","email":"grace@acme.example","given_name":"Grace","family_name":"Hopper","role":"user"}' \
  "$QUISORA/api/orgs/acme/users"
curl -X POST -H "Authorization: Bearer $TOKEN" "$QUISORA/api/orgs/acme/users/<user id>/invite"

# read back what the console edits: scopes, tags and groups are JSON arrays
curl -H "Authorization: Bearer $TOKEN" "$QUISORA/api/orgs/acme/clients/<client id>"     # "scopes": ["openid", "orders:read"]
curl -H "Authorization: Bearer $TOKEN" "$QUISORA/api/orgs/acme/providers/<provider id>" # "scopes": ["openid", "profile", "email"]
curl -H "Authorization: Bearer $TOKEN" "$QUISORA/api/orgs/acme/users/<user id>"         # "tags": [...], "groups": [{"id", "display_name"}]
curl -H "Authorization: Bearer $TOKEN" "$QUISORA/api/orgs/acme/groups/<group id>"       # "tags": [...]

# sign a user out everywhere
curl -X DELETE -H "Authorization: Bearer $TOKEN" "$QUISORA/api/orgs/acme/users/<user id>/sessions"

# follow changes in your organization as they happen (server-sent events; -N turns off curl's buffering);
# a super admin can add ?org=<name> to watch another organization
curl -N -H "Authorization: Bearer $TOKEN" "$QUISORA/api/events"
```

## SCIM (`scim`)

The token provisions users and groups in its owner's organization (a super admin's, in any organization). A manager's
token changes plain users and their group memberships. Creating, renaming, retagging or deleting a group, and anything
done to a manager or administrator, needs an administrator's token. The base URL for a provisioning tool is `/scim/v2/<org>`; the operations and their bodies are
in the OpenAPI document under the SCIM tag, and the server describes itself at `/scim/v2/<org>/ServiceProviderConfig`
and `/scim/v2/<org>/Schemas`.

```bash
curl -H "Authorization: Bearer $TOKEN" "$QUISORA/scim/v2/acme/Users?count=10"
curl -H "Authorization: Bearer $TOKEN" "$QUISORA/scim/v2/acme/Users?filter=userName%20eq%20%22alan%22"
```

A provisioning service that supports OAuth uses a [service account](SERVICE-ACCOUNTS.md) with the `scim` scope instead:
it gets short-lived tokens with the client credentials grant, and no person's token is involved.

### Listing and filters

A page of `GET /Users` or `GET /Groups` is read from the store and costs the page, however many there are, with the
exact `totalResults`, when the filter is absent or one of these (alone, or `and`ed for users): for users `active eq`
and the role of the Quisora extension, for groups `displayName sw`. They can be ordered by `userName`, `displayName`,
`emails`, `active`, `meta.created` or `id` (groups: `displayName`, `meta.created`, `id`), also descending. Finding one
resource is as cheap: `id`, `userName`, `externalId` or `emails.value eq` for users, `displayName` or `externalId eq`
for groups. A group's members are listed in full, so a client that lists many groups should ask for
`excludedAttributes=members`. A page of users with their `groups` costs one read of each user's memberships, plus one
of the organization's groups with changes not yet written to the memberships and one of the groups themselves, however
many users the page holds (1,000 users: about 1,010 store reads); a client that does not need a user's groups saves
the memberships with `excludedAttributes=groups`.

Any other filter or sort is evaluated in memory over the resources the rest of the filter leaves, and a request that
leaves more than 50,000 is answered `400` with `scimType` `tooMany` (RFC 7644 section 3.4.2.2): narrow it with one of
the filters above.

### Where SCIM is lenient

Entra ID and Okta send requests that a strict reading of RFC 7644 would refuse. Quisora accepts them:

- A `replace` through a value filter that matches nothing creates the element, for example
  `emails[type eq "work"].value` on a user with no work address.
- Unknown attributes are dropped silently, not refused.
- `emails.value` with no filter sets the first address only.
- `phoneNumbers[type eq "mobile"]` keeps only one number: the primary one, or else the first. Quisora stores one
  phone number per user.
- A PUT of a user without `phoneNumbers` leaves the number as it was.

## Backups (`backup`)

```bash
QUISORA_ADMIN_TOKEN=$TOKEN quisora backup --server "$QUISORA" quisora.bak
```

See [RUNNING.md](RUNNING.md#backup-and-restore) for the backup format, encryption and restore.

## Importing users with their passwords, authenticator apps and provider links (`import`)

Moving people from another system without asking them all to set a new password, set up a new authenticator app or
link their provider again: create each user with what that system stored, using a super admin's token with the `admin`
and `import` scopes. Everything below is accepted only when a user is created, never on an update (it would take over
an existing account), and only from super admins and from [service accounts](SERVICE-ACCOUNTS.md) holding the `import`
scope (with `users`; only super admins grant it): an organization's admins cannot import.

```bash
curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$QUISORA/api/orgs/acme/users" \
  -d '{"email": "alan@acme.example", "given_name": "Alan", "email_verified": true,
       "password_hash": "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
       "totp_secret": "JBSWY3DPEHPK3PXP",
       "identities": [{"provider": "Corp SSO", "subject": "freedom3-42"}]}'
```

### Passwords (`password_hash`)

- `password_hash` is bcrypt (`$2a$`, `$2b$` or `$2y$`, cost 4 to 14), SHA-512 crypt (`$6$`, as PHP's `crypt()` and Linux
  `/etc/shadow` make; at most 1,000,000 rounds, 5,000 when none is named) or argon2id (at most 64 MiB of memory, which
  covers PHP, libsodium's interactive limit and OWASP's settings). Anything else is refused (422).
- SHA-512 crypt and argon2id hashes are checked against the password as typed and in its normalised form (Unicode NFKC),
  so a password the old system stored in either form still works.
- It is stored sealed with the master key like every password. The user's first sign-in checks it and re-hashes the
  password with Quisora's own argon2id settings; from then on the old hash is gone.
- bcrypt reads only the first 72 bytes of a password: someone whose old password was longer cannot sign in with it and
  needs an invitation.
  A password of more than 256 bytes likewise never matches a SHA-512 crypt hash (checking one would hold a hashing
  worker for seconds); it is a wrong password, answered without hashing.
- The import is audited on `user.create` (`password` = `imported bcrypt`, `imported sha512-crypt` or `imported argon2id`).

### Authenticator apps (`totp_secret`)

- `totp_secret` is the base32 secret behind the user's authenticator app. Quisora checks codes the way apps make them
  by default (SHA-1, 6 digits, every 30 seconds, one step of drift either way), so the user **keeps their app**: their
  next code works at their first sign-in, with nothing to scan.
- Letters in either case, spaces between groups and `=` padding are accepted. The secret must be 16 to 128 base32
  characters (80 to 640 bits): the 16-character secrets that Google Authenticator and Freedom3 make are fine, anything
  shorter or not base32 is refused with a 422 on `totp_secret`. The value is never repeated in an error.
- It is stored sealed to the user, and the user is enrolled as if they had set the app up here. It is never returned,
  logged or audited: the audit log has `mfa.import` on the user (`method` = `totp`), without the secret.
- Imported users have **no recovery codes**. After they sign in, the account page marks **Recovery codes** with a warning and asks them
  to make some (their account page is where a sign-in without a destination lands), so that a lost phone is not a call
  to an administrator. Tell them to.
- Do not send an invitation to a user imported this way: accepting one replaces everything they sign in with, the
  imported authenticator app and links included.
- The secrets are the keys to the second factor and sit **in plaintext** in the system you export from. Run the export
  and this import server to server over TLS, from one process to the other, and never write the secrets to a file, a ticket or a chat.
  Anyone who holds a secret and the password can sign in.

### Provider links (`identities`)

For an organization whose users sign in through one of its sign-in providers, `identities` makes each user's link in
the same write that creates the user, so their first sign-in through the provider finds this account without matching
by email address or creating a second one:

- Each entry is `{"provider": ..., "subject": ...}`: the provider's id or its name in this organization, and the subject
  that provider asserts for the person (its `sub` claim; a GitHub user id), 1 to 255 characters, kept exactly as given.
  Up to 10 entries, one per provider.
- A provider of another organization is refused like one that does not exist (422 on `identities`). A subject already
  linked to another user at that provider is a 409 on `identities`, and nothing is created.
- The links are marked as made by an administrator (`admin`). As with every link the user did not connect themselves,
  they are dropped if the user is promoted to manager or above. The user's own connected providers are unaffected.
- The user create is the only place for this: there is no separate endpoint to link an existing user.
- The audit event `user.create` lists the providers (`providers`).

## Your own applications (`api`)

An `api` token is for your own scripts calling **your applications**, not Quisora. Two choices decide whether one
works: the organization decides [who may make them](#who-may-make-api-tokens), and each application decides whether
it [accepts them](#which-applications-accept-them). The application checks each token
it receives with the introspection endpoint of its own organization (`/o/<org id>/oauth/introspect`), authenticating as
its own confidential client (RFC 7662). Clients use `client_secret_post` unless they were set up otherwise, so the
credentials go in the form:

```bash
curl -d "client_id=$CLIENT_ID" -d "client_secret=$CLIENT_SECRET" -d "token=$TOKEN" "$QUISORA/o/<org id>/oauth/introspect"
```

A client set to `client_secret_basic` sends them as HTTP Basic instead (`curl -u "$CLIENT_ID:$CLIENT_SECRET" …`).

```json
{"active": true, "token_type": "Bearer", "token_kind": "api_token", "sub": "<user id>", "username": "alan",
 "scope": "api", "org": "<org id>", "org_name": "acme", "role": "user", "roles": ["approver"],
 "tags": ["dept:finance", "region:eu", "vpn"], "iat": 1760000000, "exp": 1790000000}
```

One call gives the application everything it needs about the person behind the token, as it applies to **that
application** (the client making the call):

- who: `sub` (user id), `username`, `org`, `org_name`, and `role`, the user's Quisora role.
- `roles`: the user's application roles for this application, from their own access entry and their groups' entries
  in its tenant (see [Application roles](#application-roles)). Absent when there are none, and always for an
  application in a tenant open to everyone.
- `tags`: one list, merged, without duplicates and sorted: the user's own tags, the tags of every group they belong
  to, and the tags of the access entries that gave them this application. Absent when there are none.
- `scope` is `api`, then the application scopes the token is limited to, for example `api orders:read`. Just `api`
  means the token is not limited: it acts with the user's full access (their `roles`) in this application. Limited
  or not, the application should allow only what both the user's roles and the token's scopes allow.
- `exp` is absent for a token that never expires. Group names are not included.

If the application is in a members-only tenant and the user has no access to it (they could not sign in to it
either), the token is `{"active": false}` for that application.

Tags are stored apart: in the management API a user's `tags` are their own, and each group's are on the group
(`GET …/groups/<group id>`). Only what applications receive merges them.

### Application roles

Roles are given per tenant, to a user or to a group, on the tenant's **Access** tab (members-only tenants). Read them
back with the management API; each entry is one user or one group, with its own `roles` and `tags`:

```bash
curl -H "Authorization: Bearer $TOKEN" "$QUISORA/api/orgs/acme/tenants/<tenant name or id>/access"
#   {"items": [{"subject_type": "group", "subject_id": "<group id>", "name": "Finance", "roles": ["approver"],
#               "tags": ["region:eu"], "all_clients": true, ...}], "total": 1}
curl -H "Authorization: Bearer $TOKEN" "$QUISORA/api/orgs/acme/tenants/<tenant name or id>/access/<tenant id>:<user or group id>"
```

Applications receive them as `roles`: the union of the user's own entry and their groups' entries that cover that
application, with those entries' tags added to `tags`. A sign-in's access token (and its introspection, and
userinfo) carries them, and so does the introspection of a personal `api` token, for the application that asks.

The token is active only to clients of the owner's organization (at that organization's introspection endpoint), and, if you chose applications when making it,
only to those. A token limited to some scopes is active only to the applications that declare at least one of them:
another application would otherwise see `api` alone and take it for full access. Anything else (another
organization's client, a token without the `api` scope, a revoked or expired token) answers `{"active": false}`.

### Who may make `api` tokens

Whether an `api` token may exist is the organization's decision, because every application that accepts one sees a
person's identity, roles and tags without that person signing in. A super admin sets it in the organization's dialog on
the **Organizations** page (**API tokens for applications**), or with `settings.api_tokens` of
`PATCH /api/orgs/<org>`:

| `api_tokens` | Who may make `api` tokens |
| --- | --- |
| `off` (the default, also when absent) | Nobody |
| `groups` | The members of the groups in `api_token_groups` (ids of groups of the organization; 1 to 20) |
| `everyone` | Every user of the organization |

There is no per-user switch: a group of one person does the same. A group that is deleted stops counting (its members
are no longer allowed), but stays in the list until the setting is saved again. The role does not matter here (an administrator who
is not in a chosen group may not make one either), and the `admin`, `scim`, `backup` and `import` scopes are not
affected: their owner's role alone decides, as above.

The setting is checked **every time a token is used**, not only when it is made. Turn it off, or take the owner out of
the chosen groups, and their `api` tokens stop working at once: introspection answers `{"active": false}` for them
(and the refusal is audited as `apitoken.refused`, with the reason). The tokens are **kept**, so turning the setting
back on, or putting the owner back in a group, brings the unexpired ones back; to end them for good, use the
organization's [emergency sign-out](emergency-sign-out.md) with **End personal API tokens too**, or delete them. A
person who may not make `api` tokens is not offered the option on their account page, and a request to make one is
refused (422 on `scopes`). If Quisora cannot read the setting or the person's groups when a token is used, the answer
is 503 (introspection: `temporarily_unavailable`), never a refusal.

**Upgrading from a version without this setting:** an organization has the setting `off`, so ordinary users' existing
`api` tokens **stop working** until an administrator turns the setting on, and then only for the applications that
accept them (below). Tokens with the other scopes are not affected.

### Which applications accept them

An application sees `api` tokens only when its administrator has turned on **Accepts personal API tokens** in its
settings (`accepts_api_tokens` in the management API; off by default; never for a public client). Until then
introspection answers `{"active": false}` to it for every `api` token, whatever its audience, and it is not offered when
someone makes a token. Turning it off ends the tokens made for the application at once.

### Choosing applications and scopes

When you make an `api` token (or edit one), you can choose:

- **Applications**: which of your organization's applications may accept it. None ticked: every application you can
  use that accepts `api` tokens. The list shows only the applications that accept them and that you have access to.
- **Limit to these scopes**: shown once applications are ticked, with only their own scopes (each application's
  "Scopes for your own APIs", such as `orders:read`). None ticked: the token has your full access in each of them. Tick some to let a
  script do only those things, for example read orders but not change them. A scope never gives you more than your
  roles allow: it only narrows.

Through the account page's own API (under `/api-internal/`: the console's, for a browser session, not versioned):
`POST /api-internal/account/tokens` takes `audience` (application ids) and `app_scopes` (which need an `audience`),
and `GET /api-internal/account/tokens` lists the `apps` you can choose from, each with its `scopes`.

## Errors

| Answer | Meaning |
| --- | --- |
| `401` with `WWW-Authenticate: Bearer error="invalid_token"` | The token is wrong, revoked or expired, or its owner is disabled |
| `403` with `error="insufficient_scope", scope="admin"` | The token is valid but lacks the scope this endpoint needs |
| `403` or `404` from an endpoint | Your role or organization does not allow that call (the same answer the console gets) |

## Replacing and revoking

- **Edit**: the pencil button changes a token's name, applications and scopes; the secret, its Quisora scopes and its
  expiry stay. Editing asks you to confirm it is you, as making a token does (`PATCH /api-internal/account/tokens/<id>` with
  `name`, `audience`, `app_scopes`).
- **A new secret**: on Your account, the refresh button next to a token makes a new secret after you confirm. The old
  secret stops working at once; the name, scopes and expiry stay the same.
- **Revoke**: delete the token on Your account. Administrators can revoke a user's tokens on the user's page or with
  `DELETE /api/orgs/{org}/users/{id}/tokens/{token}`.
- The OAuth revocation endpoint (`/o/<org id>/oauth/revoke`) does not revoke personal API tokens: it answers
  `unsupported_token_type`.
- **How long they last**: at most `tokens.api_token_max_days` (365 by default); a token made without a lifetime gets
  the maximum. Set it to 0 to allow tokens that never expire (a lifetime typed in is then at most 10 years). Tokens with the `backup` scope always expire within 30 days. A new secret never extends a
  token's life.
