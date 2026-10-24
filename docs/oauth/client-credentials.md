# Client credentials: an application acting as itself

A background job, a service calling another service, a provisioning tool: no user is involved, so the application
signs in as itself with its own credentials and gets an access token for its own scopes (the client credentials
grant, RFC 6749 §4.4).

## Setting up the client

A confidential client (with a secret or [private key JWT](client-authentication.md#private-key-jwt): public clients
cannot use this grant) with **Client credentials** ticked under **Grant types**. Its **scopes for your own APIs**
(`reports:read`, `orders:write`…) are what its tokens can carry; the user scopes (`openid`, `profile`, `email`,
`groups`, `org`…) mean nothing without a user and are never given. Register the APIs it calls under **Resources**
to have tokens for them ([resource indicators](sign-in.md#tokens-for-an-api-resource-indicators)).

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"tenant_id":"<tenant id>","name":"Nightly reports","grant_types":["client_credentials"],
       "scopes":["reports:read"],"resources":["https://reports.example.com/"]}' \
  "$QUISORA/api/orgs/acme/clients"
```

The answer has the client's `id` and its `secret` (shown once).

## Getting a token

```bash
curl -s "$QUISORA/oauth/token" -d grant_type=client_credentials \
  -d client_id="$CLIENT_ID" -d client_secret="$CLIENT_SECRET"
```

```json
{"access_token": "eyJhbGciOiJFUzI1NiIs…", "token_type": "Bearer", "expires_in": 600, "scope": "reports:read"}
```

- `scope`: fewer scopes than the client has (space-separated); without it, all of them. Asking for one it does not
  have fails with `invalid_scope`.
- `resource`: an API registered on the client, which becomes the token's `aud` with the client ID:
  `-d resource=https://reports.example.com/`.

The token's `sub` and `client_id` are the client, its `org` claims are the client's organization, and there is no
refresh token: ask for a new access token when the old one is about to expire (`expires_in`, 10 minutes by default).
An API tells these tokens from users' tokens by `sub` being the client ID.

To bind the tokens to a key the client holds, so a copied token is useless, send a [DPoP](dpop.md) proof with the
request.

## SCIM provisioning

A client with **May provision users with SCIM** (super admins set it) also gets the `scim` scope, and its tokens can
call its organization's SCIM API (`/scim/v2/<org>/…`): ask for `scope=scim`. That is how Entra ID and Okta
provision users; see [the SCIM section](../API-TOKENS.md#scim-scim) for the endpoints, which accept these tokens and
personal API tokens alike.

## What it cannot reach

Client credentials tokens are not accepted by userinfo (there is no user) and are not sessions or grants: signing
users out, even an [emergency sign-out](../emergency-sign-out.md), does not end them. To stop a client,
rotate its secret or disable it; tokens already issued work until they expire, or until an API asks through
introspection, which then answers `active: false` once the client is disabled.

With `audit.tokens = true`, every token issued is audited (`oauth.client_credentials`).
