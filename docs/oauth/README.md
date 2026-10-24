# Connecting applications: OAuth 2 and OpenID Connect

Quisora is an OpenID Connect provider and OAuth 2 authorization server. Applications sign users in through it, APIs
check the tokens it issues, and services get tokens of their own. Any certified OpenID Connect library works: give it
the issuer, your server's public address (`https://id.example.com`), and it reads the rest from discovery:

```bash
curl -s https://id.example.com/.well-known/openid-configuration | jq .
```

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
They set `QUISORA` to your server's address and use the client's ID and secret from the console:

```bash
export QUISORA=https://id.example.com
export CLIENT_ID=c_…
export CLIENT_SECRET=qsrs_…
```

## Clients, tenants and organizations

An application is a **client**. Clients belong to a **tenant** of an organization: the tenant decides who may sign in
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

| Endpoint | |
| --- | --- |
| `/.well-known/openid-configuration` | Discovery (also `/.well-known/oauth-authorization-server`) |
| `/oauth/authorize` | Authorization (the browser) |
| `/oauth/token` | Token |
| `/oauth/userinfo` | Userinfo |
| `/oauth/jwks` | Signing keys |
| `/oauth/introspect` | Introspection (RFC 7662) |
| `/oauth/revoke` | Revocation (RFC 7009) |
| `/oauth/logout` | End session (RP-initiated logout) |
| `/oauth/par` | Pushed authorization requests (RFC 9126) |
| `/oauth/device_authorization`, `/device` | Device sign-in (RFC 8628) |
| `/oauth/register` | Dynamic client registration (RFC 7591), for [self-registered apps](../MCP.md) |

## Tokens

| Token | Lifetime (setting) |
| --- | --- |
| Authorization code | 60 seconds (`tokens.code_ttl`, at most 600) |
| Access token | 10 minutes (`tokens.access_ttl`) |
| ID token | 10 minutes (`tokens.id_token_ttl`) |
| Refresh token | 30 days (`tokens.refresh_ttl`), and only as long as the user's session without `offline_access` |

Access and ID tokens are JWTs signed with the server's keys (ES256 by default; EdDSA, RS256 or PS256 per client),
which rotate automatically: verify them against `/oauth/jwks` and refresh the keys when a token names a `kid` you do
not have. Signing users out, locking them out, removing their access or an
[emergency sign-out](../emergency-sign-out.md) ends their grants: refresh tokens stop at once, and access
tokens through introspection and userinfo (an API that only checks signatures accepts them until they expire).

## Not supported

The implicit and hybrid flows, the password grant, request objects (JAR), mTLS client authentication and
certificate-bound tokens, and front-channel logout. Discovery says so.
