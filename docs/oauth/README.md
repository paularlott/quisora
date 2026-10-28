# Connecting applications: OAuth 2 and OpenID Connect

Quisora is an OpenID Connect provider and OAuth 2 authorization server. Applications sign users in through it, APIs
check the tokens it issues, and services get tokens of their own. Each organization is its own authorization server,
with an issuer of its own: your server's public address followed by `/o/` and the organization's id (22 characters,
for example `https://id.example.com/o/034nmRmWuXazwvCcdrmRxu`), and every
endpoint is under it. Any certified OpenID Connect library works: give it the organization's issuer and it reads the
rest from discovery:

```bash
curl -s https://id.example.com/o/<org id>/.well-known/openid-configuration | jq .
```

Discovery is also served as `/o/<org id>/.well-known/oauth-authorization-server` and, the way RFC 8414 inserts the
well-known segment between the host and the issuer's path (which is how MCP clients look for it), as
`/.well-known/oauth-authorization-server/o/<org id>` and `/.well-known/openid-configuration/o/<org id>`. Asked for by
the organization's name (`/o/acme/…`) the discovery document answers with a permanent redirect (308) to the id form,
because the issuer in a document must be the address it was fetched from. An organization's name works in every other
address under `/o/` too, but its id is the canonical form: the issuer, the `iss` of its tokens and every generated
link use it.

## The guides

Each guide explains one feature, with curl examples you can run against a server.

| I want to… | Guide |
| --- | --- |
| Sign users in to a web, mobile or desktop app | [Authorization code with PKCE](sign-in.md): the sign-in, tokens, scopes and claims, userinfo, refresh, introspection, revocation, sign-out, resource indicators |
| Choose how a client proves who it is | [Client authentication](client-authentication.md): secrets, private key JWT, public clients |
| Call an API from a job or a service, with no user | [Client credentials](client-credentials.md) |
| Sign in on a CLI, a TV or another device without a browser | [Device sign-in](device.md) |
| Call another API for the user, from an API | [Token exchange](token-exchange.md) |
| Keep sign-in parameters out of the browser | [Pushed authorization requests](par.md) |
| Make stolen tokens useless | [DPoP](dpop.md) |
| Meet the FAPI 2.0 Security Profile (open banking and the like) | [FAPI 2.0](fapi2.md) |
| Let AI clients register themselves with an MCP server | [MCP servers and self-registered apps](../MCP.md) |
| Let users' scripts call your API with their own tokens | [Personal API tokens](../API-TOKENS.md#your-own-applications-api) |

The examples need `curl`, `jq` and, for the guides that sign JWTs, OpenSSL 3 with the helpers in [jwt.sh](jwt.sh).
They set `QUISORA` to your server's address (the management API is there), `ISSUER` to the organization's issuer (the
OAuth endpoints are under it) and use the client's ID and secret from the console:

```bash
export QUISORA=https://id.example.com
export ISSUER=$QUISORA/o/<org id>
export CLIENT_ID=c_…
export CLIENT_SECRET=qsrs_…
```

## Clients, tenants and organizations

An application is a **client**. Clients belong to a **tenant** of an organization, and so to that organization's
authorization server: a client is known only at its own organization's endpoints (to any other it is an unknown
client), and a token of one organization is not valid at another's. Signing keys are shared, but the tokens differ by
`iss`, so check it. The tenant decides who may sign in
to its applications (everyone in the organization, or only the people and groups on its access list) and how
(passwords, passkeys, which upstream providers, whether a second factor is required). So the first question when
adding an application is which tenant it belongs in.

Make a client in the console: the organization → **Tenants** → the tenant → **Clients** → **New client**. Choose:

- **Authentication**: a secret for a server-side app, **Public** for one that cannot keep a secret (a single-page app,
  a mobile or desktop app, a CLI), or **Private key JWT** ([client authentication](client-authentication.md)).
- **Redirect URIs**: where the sign-in result goes (https; `http://localhost` for desktop apps; a private scheme such
  as `com.example.app:/callback` for mobile apps).
- **Grant types**: authorization code (sign users in), refresh token, client credentials, token exchange, device
  sign-in.
- **Allowed scopes**: the standard ones it may ask users for, and scopes for your own APIs.
- **Resources**: the APIs it may ask tokens for ([resource indicators](sign-in.md#tokens-for-an-api-resource-indicators)).

The client ID is on the client's row; a secret is shown once, when the client is made or its secret rotated. The same
through the management API, with a [personal API token](../API-TOKENS.md) that has the `admin` scope:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"tenant_id":"<tenant id>","name":"Orders web","grant_types":["authorization_code","refresh_token"],
       "scopes":["openid","profile","email","offline_access"],"redirect_uris":["https://app.example.com/callback"]}' \
  "$QUISORA/api/orgs/acme/clients"
```

The answer is the client, with its `id` and, once, its `secret`. Every field is in the API reference at
`/api-docs/`.

**Consent.** Users approve what an application asks for the first time; a confidential client's approval is
remembered while its grant lives, a public client's never is. **First-party application** (super admins only) skips
the screen, for applications you run yourselves.

## Endpoints

All of them are under the organization's issuer, `/o/<org id>` (or `/o/<org name>`; see above):

| Endpoint | |
| --- | --- |
| `/o/<org id>/.well-known/openid-configuration` | Discovery (also `/o/<org id>/.well-known/oauth-authorization-server`, and the RFC 8414 forms `/.well-known/openid-configuration/o/<org id>` and `/.well-known/oauth-authorization-server/o/<org id>`) |
| `/o/<org id>/oauth/authorize` | Authorization (the browser) |
| `/o/<org id>/oauth/token` | Token |
| `/o/<org id>/oauth/userinfo` | Userinfo |
| `/o/<org id>/oauth/jwks` | Signing keys |
| `/o/<org id>/oauth/introspect` | Introspection (RFC 7662) |
| `/o/<org id>/oauth/revoke` | Revocation (RFC 7009) |
| `/o/<org id>/oauth/logout` | End session (RP-initiated logout) |
| `/o/<org id>/oauth/par` | Pushed authorization requests (RFC 9126) |
| `/o/<org id>/oauth/device_authorization`, `/o/<org id>/device` | Device sign-in (RFC 8628) |
| `/o/<org id>/oauth/register` | Dynamic client registration (RFC 7591), for [self-registered apps](../MCP.md) |

An authorization request costs a lookup of its client, and one that starts a sign-in holds a little state for up to
20 minutes, so each address may make at most 300 a minute, whatever they name; past that it gets a `429 Too Many
Requests` page for the rest of the minute. Behind a proxy set `server.trust_proxy`, or every user shares the proxy's
address and its budget.

## Tokens

| Token | Lifetime (setting) |
| --- | --- |
| Authorization code | 60 seconds (`tokens.code_ttl`, at most 600) |
| Access token | 10 minutes (`tokens.access_ttl`) |
| ID token | 10 minutes (`tokens.id_token_ttl`) |
| Refresh token | 30 days (`tokens.refresh_ttl`), and only as long as the user's session without `offline_access` |

Access and ID tokens are JWTs signed with the server's keys (ES256 by default; EdDSA, RS256 or PS256 per client),
which rotate automatically: verify them against the organization's `/o/<org id>/oauth/jwks` (the keys are the same for every organization; `iss` says which organization a token is from, and an API must check it) and refresh the keys when a token names a `kid` you do
not have. Signing users out, locking them out, removing their access or an
[emergency sign-out](../emergency-sign-out.md) ends their grants: refresh tokens stop at once, and access
tokens through introspection and userinfo (an API that only checks signatures accepts them until they expire).

## Not supported

The implicit and hybrid flows, the password grant, request objects (JAR), mTLS client authentication and
certificate-bound tokens, and front-channel logout. Discovery says so.
