# Token exchange: calling another API for the user

An API that a user's application calls sometimes has to call another API for the same user: the orders service
asking billing for the user's invoices. Forwarding the user's token would hand billing a token that was never meant
for it (and the orders service's own power along with it). With token exchange (RFC 8693) the orders service trades
the user's token for a new one of its own: for billing only, with no more than the user's scopes, acting for the
user, and naming the orders service as the actor.

```
User's app ──(token for orders)──▶ Orders API ──token exchange──▶ Quisora
                                         │ ◀── token for billing, sub = user, act = orders API
                                         └──(token for billing)──▶ Billing API
```

## Setting up

- **The calling API** (orders) has its own confidential client with **Token exchange** ticked under **Grant types**,
  the scopes it may pass on, and the APIs it may call registered under **Resources** (`https://billing.example.com/`).
- It must be allowed to exchange the user's token: either the token was issued for it (its client ID is in the
  token's `aud`), or, the usual case for an API that applications name as a resource, its client has **May introspect
  every token of the organization**.
- The user must have access to the calling API's client, as for a sign-in to it (its tenant's access list).

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"tenant_id":"<tenant id>","name":"Orders API","introspect_org":true,
       "grant_types":["urn:ietf:params:oauth:grant-type:token-exchange"],
       "scopes":["openid","profile","orders:read"],"resources":["https://billing.example.com/"]}' \
  "$QUISORA/api/orgs/acme/clients"
```

## Exchanging

The orders API received the user's access token (`$USER_TOKEN`) from the application and checked it. It now asks
for a token for billing:

```bash
curl -s "$QUISORA/oauth/token" -d client_id="$ORDERS_ID" -d client_secret="$ORDERS_SECRET" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$USER_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d resource=https://billing.example.com/ \
  -d scope="openid profile"
```

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIs…",
  "token_type": "Bearer",
  "expires_in": 412,
  "scope": "openid profile",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
}
```

The new token's claims:

```jsonc
{
  "sub": "01a16bdd-…",                                   // still the user
  "aud": ["c_orders…", "https://billing.example.com/"],
  "client_id": "c_orders…",
  "scope": "openid profile",
  "act": {"sub": "c_orders…", "client_id": "c_orders…"}, // who is acting for them
  …
}
```

| Parameter | |
| --- | --- |
| `subject_token` | The user's access token, issued by this Quisora. Not a refresh token, not a client credentials token. |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:access_token` (or `…:jwt`). |
| `resource` or `audience` | The APIs the new token is for: only those registered on the calling client. |
| `scope` | Optional: at most the subject token's scopes that the calling client also has. Without it, all of those. `offline_access` is dropped. |
| `requested_token_type` | Optional; only access tokens are issued. |
| `actor_token` | Not supported: the authenticated client is the actor. |

## What the new token is

- **No more than what came in.** At most the subject token's scopes (and the calling client's), only the resources
  registered for the calling client, and it expires no later than the subject token (so `expires_in` can be less
  than usual).
- **The user's, acted on by the client.** `sub` and the user's claims are the user's; `act` names the calling client.
  An API exchanging a token that already has an `act` nests it (`act.act` …), up to four actors deep. A client
  narrowing a token issued to itself adds no actor.
- **Tied to the user's sign-in.** It belongs to the same grant as the subject token: signing the user out or revoking
  their grant ends it (through introspection). Revoking the exchanged token does not end the user's grant.
- **Only an access token.** No refresh token or ID token: exchange again when it expires, with a fresh subject token.

An API receiving an exchanged token authorizes on `sub` (the user), and can see from `act` that another service
asked for it.

## Errors

| Error | Why |
| --- | --- |
| `invalid_grant`: *the subject token is invalid, expired or revoked* | It is not a valid access token from this server, or the user's sign-in has ended. |
| `invalid_grant`: *the subject token was not issued for this client* | The calling client is not in the token's `aud` and cannot introspect the organization's tokens. |
| `invalid_grant`: *the subject token must be a user's token* | A client credentials token cannot be exchanged. |
| `invalid_grant`: *the user has no access to this application* | The user cannot use the calling client. |
| `invalid_target` | A `resource` or `audience` not registered on the calling client. |
| `invalid_scope` | A scope beyond the subject token's or the calling client's. |
| `unauthorized_client` | The client lacks the grant, or is a public client (token exchange is for confidential clients only). |
| `temporarily_unavailable` (503) | A check the exchange depends on could not be made (a store read failed). The subject token is not known to be bad: keep it and retry. |

Every exchange is audited (`oauth.token_exchange`, with the user, the subject token's client, scopes and resources).
