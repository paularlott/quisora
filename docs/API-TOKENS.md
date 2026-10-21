# Personal API tokens

A personal API token lets a script or a tool call Quisora as you, without a browser. You make tokens on **Your
account → API tokens → New token**, choose what each one may do (its scopes) and, optionally, when it expires: left
empty, it never expires (unless the server sets a maximum lifetime, which it then gets). The token is shown once,
in the form `qsr_<id>_<secret>`: copy it then. Quisora keeps only a hash of the secret.

A token never has more access than you have: every call is checked against your role and organization at the time it
is made, so if you are demoted or your account is disabled, the token loses that access too.

## Scopes and endpoints

| Scope | Who can choose it | What the token is accepted by |
| --- | --- | --- |
| `admin` | managers and up | The management API, `/api/…` (what the admin console uses), including the live event stream `/api/events` |
| `scim` | managers and up | The SCIM 2.0 API, `/scim/v2/…`, for provisioning tools |
| `backup` | super admins | `GET /api/backup` only; such a token expires within 30 days |
| `import` | super admins | With `admin`: creating users with a password hash from another system (`password_hash`) |
| `api` | everyone | Nothing in Quisora itself: it is for **your own applications**, which check it through token introspection |

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
`?q=` (search), `sort=`, `desc=1`, `offset=` and `limit=` (at most 100). The full reference is the OpenAPI document
at `/api/openapi.json` (SCIM is in it too), which every server also renders as a browsable reference at `/api-docs/`
(it works without internet access: nothing loads from outside the server). An `Api-Version: 2026-10-20` header
pins the version; without it you get the oldest supported version. Versions are dates: the release that introduced
them, and a new one comes only with a change that would break existing callers.

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

The token provisions users and groups in its owner's organization (a super admin's, in any organization). Groups need
an administrator's token. The base URL for a provisioning tool is `/scim/v2/<org>`; the operations and their bodies are
in the OpenAPI document under the SCIM tag, and the server describes itself at `/scim/v2/<org>/ServiceProviderConfig`
and `/scim/v2/<org>/Schemas`.

```bash
curl -H "Authorization: Bearer $TOKEN" "$QUISORA/scim/v2/acme/Users?count=10"
curl -H "Authorization: Bearer $TOKEN" "$QUISORA/scim/v2/acme/Users?filter=userName%20eq%20%22alan%22"
```

A provisioning service that supports OAuth can use a client instead: a confidential client with SCIM provisioning
turned on gets short-lived tokens with the client credentials grant, and no person's token is involved.

## Backups (`backup`)

```bash
QUISORA_ADMIN_TOKEN=$TOKEN quisora backup --server "$QUISORA" quisora.bak
```

See [RUNNING.md](RUNNING.md#backup-and-restore) for the backup format, encryption and restore.

## Importing users with their passwords (`import`)

Moving people from another system without asking them all to set a new password: create each user with the hash that
system stored, using a super admin's token with the `admin` and `import` scopes.

```bash
curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$QUISORA/api/orgs/acme/users" \
  -d '{"email": "alan@acme.example", "given_name": "Alan", "email_verified": true,
       "password_hash": "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"}'
```

- `password_hash` is bcrypt (`$2a$`, `$2b$` or `$2y$`, cost 4 to 14) or argon2id. Anything else is refused (422).
- It is accepted only when a user is created, never on an update: setting a hash sets a password someone may know,
  so an existing account cannot be taken over this way. Only super admins can do it; an organization's admins cannot.
- It is stored sealed with the master key like every password. The user's first sign-in checks it and re-hashes the
  password with Quisora's own argon2id settings; from then on the old hash is gone.
- bcrypt reads only the first 72 bytes of a password: someone whose old password was longer cannot sign in with it and
  needs an invitation.
- The import is audited on `user.create` (`password` = `imported bcrypt` or `imported argon2id`).
- Imported users have no second factor: where the organization requires one, they set it up at their first sign-in.

## Your own applications (`api`)

An `api` token is for your own scripts calling **your applications**, not Quisora. The application checks each token
it receives with Quisora's introspection endpoint, authenticating as its own confidential client (RFC 7662). Clients
use `client_secret_post` unless they were set up otherwise, so the credentials go in the form:

```bash
curl -d "client_id=$CLIENT_ID" -d "client_secret=$CLIENT_SECRET" -d "token=$TOKEN" "$QUISORA/oauth/introspect"
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

The token is active only to clients of the owner's organization, and, if you chose applications when making it,
only to those. A token limited to some scopes is active only to the applications that declare at least one of them:
another application would otherwise see `api` alone and take it for full access. Anything else (another
organization's client, a token without the `api` scope, a revoked or expired token) answers `{"active": false}`.

### Choosing applications and scopes

When you make an `api` token (or edit one), you can choose:

- **Applications**: which of your organization's applications may accept it. None ticked: every application you can
  use. The list shows the applications you have access to.
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
- The OAuth revocation endpoint (`/oauth/revoke`) does not revoke personal API tokens: it answers
  `unsupported_token_type`.
- How long tokens may last is set by `tokens.api_token_max_days` ([RUNNING.md](RUNNING.md)).
