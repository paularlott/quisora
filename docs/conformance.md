# OpenID conformance results

Quisora run against the OpenID Foundation conformance suite (built from source, October 2026) with the harness in
[conformance/](../conformance/README.md). Static clients, discovery, authorization code flow with PKCE S256.

The suite's test logic is unmodified. Its OIDC client sends no PKCE, so the seeded confidential clients have
**Require PKCE** turned off (a per-client setting, on by default; public clients always need PKCE). The only local
change (`conformance/suite.patch`) moves the suite to port 8453 so it does not collide with `task run-server`; it
does not affect the tests. A formal certification is run on the OpenID Foundation's hosted suite; these runs are the
same plans locally.

| Plan | Modules | Failures | Warnings |
|---|---|---|---|
| `oidcc-config-certification-test-plan` | 1 | 0 | 0 |
| `oidcc-basic-certification-test-plan` (discovery, static client) | 35 | 0 | 3 |
| `oidcc-rp-initiated-logout-certification-test-plan` (static client, code) | 11 | 0 | 0 |
| `oidcc-backchannel-rp-initiated-logout-certification-test-plan` (static client, code) | 2 | 0 | 0 |

Beyond certification, the comprehensive plan (`oidcc-test-plan`, code flow, static clients) with other client
authentication methods. It adds the refresh token, userinfo POST, PKCE, `display`, `ui_locales`, `claims_locales`
and client assertion modules to the basic plan's:

| Plan | Modules | Failures | Warnings |
|---|---|---|---|
| `oidcc-test-plan` with `client_secret_post` | 36 | 0 (rotate-keys: see below) | 3 |
| `oidcc-test-plan` with `private_key_jwt` (ES256 client keys) | 37 | 0 (rotate-keys: see below) | 3 |

The same three expected warnings as the basic plan. One module of these plans, `oidcc-server-rotate-keys`, compares
the JWKS before and after a rotation that the tester triggers between the module's set-up and its start;
`run-test-plan.py` starts it at once, so it always fails unattended. `conformance/rotate-keys.py` runs it properly
(it rotates through `POST /api/v1/keys/rotate` in between) and it passes; the run found that the endpoint did not
actually rotate (fixed below).

## Changes since these runs

Security fixes made after the runs above touch flows the plans exercise; the plans have not been run again yet.
None is meant to change a result:

- **Re-authentication** (`oidcc-prompt-login`, `oidcc-max-age-1`): signing in again as the same user now upgrades the
  browser's session instead of replacing it. `auth_time` is the new sign-in, as before; the session id (`sid`) stays
  the same across the re-authentication (it used to change), and the browser gets a new cookie value. Refresh
  tokens other applications hold on the session keep working. Signing in as a different user still ends the session.
- **Resource indicators** (RFC 8707, not in the plans): a client may name only the resources registered for it.
- **Back-channel logout URIs** must be https; the harness relay already is.
- The seed (`conformance/seed`) mints its API token as an interactive actor (`service.ActorForUser`), as actors
  without one now hold no scope.

## Not covered by the suite

- **Public clients.** The suite's OIDC client never sends PKCE, and Quisora requires PKCE of every public client (it
  cannot be turned off for them), so a `client_auth_type=none` run fails at the first authorization request by
  design. Public clients are covered by the Go end-to-end tests (PKCE, CORS, rotating refresh tokens, revocation).
- **Introspection (RFC 7662) and revocation (RFC 7009)** have no OpenID Foundation plan outside FAPI; the Go tests
  cover them, including cross-organization confinement and disabled clients.
- Dynamic registration, implicit and hybrid flows and request objects are not supported, and discovery says so.

## Expected warnings (basic plan)

- `oidcc-scope-profile`: userinfo leaves out profile claims the user does not have (picture, website, birthdate…).
  OpenID Connect returns claims only when they are available.
- `oidcc-scope-email`, `oidcc-alternate-happy-flow`: the ID token carries `email` and `email_verified` for the
  `email` scope as well as userinfo. Allowed, and most providers do it; many applications read the address from the
  ID token.

All three are allowed by the specification. Leaving `email` out of the ID token when an access token is issued
would follow the suite's reading more closely, but many applications and client libraries read the address from
the ID token, and an application can always ask for exactly what it wants with the `claims` parameter. The profile
warning goes only when every user has every standard profile claim, which Quisora does not hold (pictures, birth
dates and the like).

## Skipped

`oidcc-scope-address` and `oidcc-scope-all` (Quisora has no address claim) and the unsigned request object module (request objects are not supported and the server says so in discovery).

## Review items

These finish as REVIEW: the suite screenshots a page for a person to confirm. The harness waits for the expected
text before each screenshot.

- `oidcc-prompt-login`, `oidcc-max-age-1`: the sign-in page appears again (forced re-authentication).
- `oidcc-ensure-registered-redirect-uri`, `oidcc-ensure-request-object-with-redirect-uri`: "This request cannot be
  completed" (an unregistered `redirect_uri` is never redirected to).
- RP-initiated logout with a bad, modified or missing `id_token_hint`, or an unregistered or altered
  `post_logout_redirect_uri`: "The sign-out request is not valid".
- RP-initiated logout without parameters, without `post_logout_redirect_uri`, or with only `state`: the "Sign out?"
  confirmation, then "You have been signed out".

## Fixed because of the runs

- `acr_values` were ignored (a warning). Discovery now lists `acr_values_supported` (`urn:quisora:acr:basic`,
  `urn:quisora:acr:mfa`); a request naming only the MFA value, through `acr_values` or an `acr` claim request, makes a
  second factor a condition of that sign-in, and the ID token's `acr` is always one of the requested known values.
- The `claims` request parameter was not supported (a warning in `oidcc-claims-essential`). It is now: single claims
  for the ID token or userinfo, each only when the client may use the scope that holds it, shown on the consent
  screen, and kept across refreshes.
- The phone scope (`phone_number`, `phone_number_verified`) was added, so `oidcc-scope-phone` runs and passes.

- `POST /api/v1/keys/rotate` returned success but rotated nothing unless a scheduled rotation was due. It now
  creates a key that signs at once; the previous keys stay published until their tokens expire.
- The ID token named the organization, tenant and Quisora role (`org`, `org_name`, `tenant`, `tenant_name`, `role`)
  whatever the scopes. They now need the `org` scope, as at userinfo; access tokens still always carry them.
- The sign-out confirmation page needed JavaScript and, outside the session middleware, rendered the anonymous CSRF
  token, so confirming without the page's script failed. It is now a plain form (`POST /oauth/logout/confirm`) with
  the session's token.
- Outbound HTTPS can trust extra CA certificates (`server.extra_ca_file`), so a provider, client JWKS or back-channel
  endpoint on a private CA works without weakening TLS checks (the fake provider uses it).
