# Quisora for Scriptling

A [Scriptling](https://github.com/paularlott/scriptling) library for the Quisora management API (`/api/…`), and
example scripts that use it.

- `lib/quisora/`: the library (`import quisora`)
- `examples/`: scripts for common jobs

## Credentials

The scripts read the server and credentials from the environment (`quisora.from_env()`):

| Variable | |
| --- | --- |
| `QUISORA_URL` | The server, e.g. `https://id.example.com` |
| `QUISORA_TOKEN` | A [personal API token](../docs/API-TOKENS.md) with the `admin` scope, **or** |
| `QUISORA_CLIENT_ID`, `QUISORA_CLIENT_SECRET` | a [service account](../docs/SERVICE-ACCOUNTS.md)'s credentials, and |
| `QUISORA_ORG` | its organization (name or id), or `QUISORA_TOKEN_ENDPOINT` |
| `QUISORA_INSECURE` | `1` skips checking the server's TLS certificate: a development server's self-signed one only, never in production |

A service account gets access tokens with the client credentials grant; the library fetches a new one shortly before
the current one expires.

## Running the examples

From this folder, with `-L lib` so the scripts find the library:

```bash
export QUISORA_URL=https://id.example.com QUISORA_TOKEN=qsr_…
scriptling -L lib examples/list_orgs.py
scriptling -L lib examples/list_users.py acme
scriptling -L lib examples/list_users.py acme al --role admin
scriptling -L lib examples/create_org.py contoso "Contoso Ltd" --service-account setup users,groups
scriptling -L lib examples/setup_org.py contoso "Contoso Ltd" --admin boss@contoso.example Bo --guests primary <group id>
scriptling -L lib examples/create_user.py acme grace@acme.example Grace Hopper --username grace --invite
scriptling -L lib examples/add_to_group.py acme Engineers grace alan
scriptling -L lib examples/timed_access.py acme give support grace 3 "SUP-4211 approved by sam" --roles support
QUISORA_APP_CLIENT_ID=… QUISORA_APP_CLIENT_SECRET=… scriptling -L lib examples/guest_token.py acme <access token>
```

`create_org.py` needs a super admin's token, or a service account of the primary organization with `orgs:create`.
`setup_org.py` needs a service account of the primary organization with `orgs:create` and `orgs:manage` (and `access`
for `--guests`, to give the groups access to the provider's own tenant in the primary organization), which then
owns the organization it creates and configures it as a super admin would ([owning organizations](../docs/SERVICE-ACCOUNTS.md#owning-organizations-orgsmanage)).
`list_orgs.py` needs a personal token: service accounts cannot list organizations. As a service account,
`create_user.py` needs the `users` scope (and `manage_admins` for `--role admin`), and `add_to_group.py` needs
`users` and `groups`; `timed_access.py` needs `access`, `tenants` and `users` ([time-limited access](../docs/TIMED-ACCESS.md)).
`guest_token.py` is an application's side, not the management API's: it asks with the application's own client id and
secret, and names a guest's home organization and tenant when the application asked for the `idp` scope.

## Using the library

```python
import quisora

qs = quisora.from_env()          # or quisora.Client(url, token=...) / Client(url, client_id=..., client_secret=..., org=...)

page = qs.list_users("acme", q="al", limit=10)     # one page: {"items": [...], "total": n}
for user in qs.iter_users("acme", role="manager"): # every page
    print(user["username"])

user = qs.create_user("acme", "grace@acme.example", "Grace", family_name="Hopper", invite={"email": True})
qs.update_user("acme", user["id"], tags=["dept:eng"])

try:
    qs.get_user("acme", "missing")
except quisora.QuisoraError as e:
    print(e.status, e.message, e.field)       # 404 Not found. None
```

It covers organizations, sign-in providers, tenants and their access lists (with an end: `give_access(..., hours=3)`),
users (invitations, sign-out, lock-out), groups and their members, service accounts and the audit log. Anything else is one call away with `qs.request(method, path, params=..., body=...)`, and
`qs.paginate(path, params)` walks any list.

For an application rather than an administrator, `quisora.introspect(url, org, token, client_id, client_secret)` asks
what an access token is, as the application, and `quisora.guest_of(claims)` reads where a guest from another
organization came from (`org`, `org_name`, `tenant`, `tenant_name`, `user`, `login`), or `None` for anyone else. The full API is in the OpenAPI document every server serves at
`/api/openapi.json` (browsable at `/api-docs/`). The library sends `Api-Version: 2026-10-20`.

## As a package

`manifest.toml` makes this folder a Scriptling package:

```bash
scriptling pack . -o quisora.zip
scriptling -p quisora.zip my_script.py
```
