# Client authentication

Every request a client makes to Quisora's back-channel endpoints (token, introspection, revocation, pushed
authorization requests, device authorization) says which client it is, and a confidential client proves it. A
client is registered with one method (**Authentication** in the client dialog, `token_endpoint_auth_method` in the
API) and must use that one.

| Method | For | How |
| --- | --- | --- |
| `client_secret_post` (the default) | Server-side applications | `client_id` and `client_secret` in the form body |
| `client_secret_basic` | Libraries that only do this | HTTP Basic: `client_id:client_secret`, each URL-encoded first |
| `private_key_jwt` | Higher assurance, and FAPI 2.0 | A short-lived JWT signed with the client's private key; Quisora holds only the public key |
| `none` | Public clients: single-page apps, mobile and desktop apps, CLIs | `client_id` only; PKCE protects the sign-in, refresh tokens always rotate |

```bash
export ISSUER=https://id.example.com/o/<org id>      # the organization's issuer
```

## Client secrets

The secret is shown once, when the client is made (or its secret is rotated): copy it then; Quisora keeps only a
hash. Secrets look like `qsrs_…`.

```bash
# client_secret_post
curl -s "$ISSUER/oauth/token" -d grant_type=client_credentials \
  -d client_id="$CLIENT_ID" -d client_secret="$CLIENT_SECRET"

# client_secret_basic (curl's -u does the Basic header; IDs and secrets need no escaping, as they use no special characters)
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" "$ISSUER/oauth/token" -d grant_type=client_credentials
```

**Rotating a secret.** **Rotate secret** on the client (or `POST /api/orgs/{org}/clients/{id}/secret`) makes a new
one, and the old one stops working at once: update the application straight after. The secrets of first-party
clients are rotated by super admins only. A [service account](../SERVICE-ACCOUNTS.md)'s secret is rotated on its own page
(`POST /api/orgs/{org}/service-accounts/{id}/secret`) by its organization's administrators.

**Wrong secrets** are limited: after 30 failures a minute for one client from one address (300 from one address for
any client, and from one IPv6 /48 sixty-four times that, whatever /64s they come from), every attempt is refused for the rest of the minute, the right secret included, and the client's
organization gets an `oauth.client_auth.limited` audit event. The address's 300 are also spent by a public client's
token requests that fail on what they present (an unknown or used code or refresh token, a refused DPoP proof): anyone
can name a public client, so past them every request from the address that is not a confidential client proving its
secret gets `429 temporarily_unavailable` with `Retry-After`. A confidential client that authenticates is not held
back by what others behind its address have failed (an office or a carrier's shared address after a revocation); its
own limits apply. From an address that has failed 3,000 times in a minute (guessing client ids or secrets) nothing is
looked at, the right secret included.

**Failing token requests of a confidential client** (`invalid_grant`, `invalid_dpop_proof`) are counted against that
client and grant type alone, whatever its address: after 3,000 a minute of one grant type it gets `429
temporarily_unavailable` with `Retry-After` for that grant type for the rest of the minute. A backend that refreshes
tokens for thousands of users whose sessions were just revoked is held back only itself, its users' code exchanges still
work, and other clients behind the same address are not held back.

## Private key JWT

The client signs a short JWT (a **client assertion**, RFC 7523) with its private key for each request; Quisora checks
it against the public keys registered on the client. Nothing secret is stored at Quisora, and an assertion is useless
after a minute or once used.

The examples use the helpers in [jwt.sh](jwt.sh) (bash, OpenSSL 3 and jq) and an Ed25519 key; ES256, PS256 and
RS256 keys work too (not RS256 with FAPI 2.0).

```bash
source docs/oauth/jwt.sh
new_key client.key                                  # keep this one private
echo "{\"keys\":[$(jwk client.key k1)]}"            # the public keys to register
```

**Register the public keys** on the client: **Authentication** → **Private key JWT**, then paste the JSON into
**Public keys (JWKS)**, or give a **JWKS URI** where the application publishes its keys (an https URL; Quisora
reads it again when it meets a key ID it does not know, so keys can be rolled over by publishing the new one first).
Through the API, `"token_endpoint_auth_method":"private_key_jwt"` with `"jwks":"<the JSON as a string>"` or
`"jwks_uri":"https://…"`.

**Send an assertion** instead of a secret:

```bash
curl -s "$ISSUER/oauth/token" -d grant_type=client_credentials \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$(client_assertion client.key "$CLIENT_ID" "$ISSUER")"
```

`client_id` may be sent too; it must then match. The assertion's claims, as `client_assertion` makes them:

```json
{"iss": "c_…", "sub": "c_…", "aud": "https://id.example.com/o/<org id>", "jti": "5f0c…", "iat": 1792811000, "exp": 1792811060}
```

| Claim | Rule |
| --- | --- |
| `iss`, `sub` | Both the client ID. |
| `aud` | The organization's issuer (`https://id.example.com/o/<org id>`), its token endpoint (`https://id.example.com/o/<org id>/oauth/token`), or the endpoint the assertion is sent to (PAR, introspection, revocation; RFC 9126 §2), at any of the endpoints above. A FAPI 2.0 client must use the issuer alone, as a string. |
| `exp` | Required, at most 5 minutes ahead. |
| `iat`, `nbf` | Optional; not in the future. |
| `jti` | Required, unique: each assertion is accepted once. |
| Header `alg` | `EdDSA`, `ES256`, `PS256` or `RS256` (no RS256 for FAPI 2.0); `kid` picks the key when there are several. |

A wrong assertion answers `invalid_client` with what was wrong (`assertion expired or valid for too long`,
`assertion already used`, `assertion audience must be the issuer, the token endpoint or the endpoint called`…).

## Public clients

A public client (`none`) has no secret: an application anyone can download cannot keep one. It sends `client_id`
alone. It cannot use client credentials or token exchange, cannot introspect, must use PKCE, and its refresh tokens
always rotate. Its consent is never remembered: anyone can claim to be a public client, so the user always confirms.
To bind its tokens to a key it holds, use [DPoP](dpop.md).
