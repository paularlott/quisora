# OpenID conformance results

Quisora run against the OpenID Foundation conformance suite (built from source, October 2026) with the harness in
[conformance/](../conformance/README.md). Static clients, discovery, authorization code flow with PKCE S256. The
results below are from commit `34f6c44` (the review rounds through the nineteenth, the siege defences, always-encrypted
backups), run on 12 November 2026, against a freshly seeded node; the counts are the same as at `527d185`.

The suite's test logic is unmodified. Its OIDC client sends no PKCE, so the seeded confidential clients have
**Require PKCE** turned off (a per-client setting, on by default; public clients always need PKCE). The only local
change (`conformance/suite.patch`) moves the suite to port 8453 so it does not collide with `task run-server`; it
does not affect the tests. A formal certification is run on the OpenID Foundation's hosted suite; these runs are the
same plans locally. They are evidence about the commits named, not a certification: run them again on the build you
release.

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
| `oidcc-test-plan` with `client_secret_post` | 36 | 0 | 3 |
| `oidcc-test-plan` with `private_key_jwt` (ES256 client keys) | 37 | 0 | 3 |

The same three expected warnings as the basic plan.

## FAPI 2.0 Security Profile

`fapi2-security-profile-final-test-plan` (the certifiable FAPI 2.0 plan) with OpenID Connect, `private_key_jwt`
client authentication and DPoP sender-constrained tokens, `plain_fapi`, run on 11 November 2026 on the same build as
the plans above. The seeded FAPI clients have the
FAPI 2.0 Security Profile turned on and nothing else changed from their defaults. It runs twice: with ES256 client
keys, and with PS256 (RSA) client keys, which the module refusing RS256 client assertions needs.

| Plan | Client keys | Modules | Passed | Failures | Warnings | Review | Skipped |
|---|---|---|---|---|---|---|---|
| `fapi2-security-profile-final-test-plan` | ES256 | 52 | 48 | 0 | 1 | 2 | 1 |
| `fapi2-security-profile-final-test-plan` | PS256 | 52 | 49 | 0 | 1 | 2 | 0 |
| `fapi2-security-profile-final-test-plan`, client credentials | ES256 | 15 | 14 | 0 | 0 | 0 | 1 |

The client credentials run (`fapi_profile=fapi_client_credentials_grant`, `openid=plain_oauth`) has no user, so its
protected resource is SCIM (`/scim/v2/acme/Users`), the API that takes client tokens: its clients are service accounts
with the profile on and only the `scim` scope. Its first run found that discovery's `scopes_supported` did not
list `scim` (a warning); it does now. Its one skip is the RS256 module again, covered by the PS256 run above.

- **Warning** (`test-claims-parameter-identity-claims`): the ID token carries `sid`, the session id of OpenID
  Connect back-channel logout, which the module does not know. Quisora supports back-channel logout, so it stays.
- **Review** (`par-attempt-to-use-expired-request_uri`, `par-attempt-to-use-request_uri-for-different-client`):
  neither request can be sent back to the client (an expired request_uri is gone, and one presented by another client
  belongs to the client that pushed it, so nothing in it can be trusted for this one), so Quisora shows its error page. The suite asks for a
  screenshot of it, which the harness takes; a person confirms it shows the request was refused.
- **Skipped** (ES256 run only): `ensure-signed-client-assertion-with-RS256-fails` needs RSA client keys; the PS256 run
  covers it, and it passes.

The first runs found two things, both fixed before the results above:

- **A pushed request_uri was used up by the first visit** to the authorization endpoint, so a browser that reloaded
  the sign-in page could not carry on (`par-ensure-reused-request-uri-prior-to-auth-completion-succeeds`, FAPI 2.0
  §5.3.2.2 note 3). It is now used up when the request is decided (a code, a denial or a cancel). Presented again
  after that, it goes back to the client as `invalid_request_uri` (`par-attempt-reuse-request_uri`) instead of an
  error page.
- **The sign-in page had no way to decline** an application's request (`user-rejects-authentication` needs the user
  to cancel or deny consent, and first-party applications have no consent page). It now has "Cancel and return to
  the application", which sends `access_denied` back. One module of these plans, `oidcc-server-rotate-keys`, compares
the JWKS before and after a rotation that the tester triggers between the module's set-up and its start. The suite's
`run-test-plan.py` starts it at once, so run alone it always fails. The harness runs the suite's runner unmodified
through `conformance/run-plan.py`, which rotates Quisora's signing key (`POST /api/keys/rotate`, as the seeded super
admin) just before that module starts, once no other module of the plan is in flight. The rotation is part of the
same unattended plan run, and the module passes in the plan's own export. Its first runs found that the endpoint did
not actually rotate (fixed below).

## Changes covered by these runs

Security fixes made after the previous runs touch flows the plans exercise. The runs above include all of them, and
none changed a result:

- **Re-authentication** (`oidcc-prompt-login`, `oidcc-max-age-1`): signing in again as the same user now upgrades the
  browser's session instead of replacing it. `auth_time` is the new sign-in, as before; the session id (`sid`) stays
  the same across the re-authentication (it used to change), and the browser gets a new cookie value. Refresh
  tokens other applications hold on the session keep working. Signing in as a different user still ends the session.
- **Resource indicators** (RFC 8707, not in the plans): a client may name only the resources registered for it.
- **Back-channel logout URIs** must be https; the harness relay already is.
- The seed (`conformance/seed`) mints its API token as an interactive actor (`service.ActorForUser`), as actors
  without one now hold no scope.
- **First-party clients** (no consent screen) are set up and managed by super admins only; the seed creates them as
  the super admin.
- **Invitations** are checked again, against their issuer, when used (not exercised by the plans).

## Not covered by the suite

- **Public clients.** The suite's OIDC client never sends PKCE, and Quisora requires PKCE of every public client (it
  cannot be turned off for them), so a `client_auth_type=none` run fails at the first authorization request by
  design. Public clients are covered by the Go end-to-end tests (PKCE, CORS, rotating refresh tokens, revocation).
- **Introspection (RFC 7662) and revocation (RFC 7009)** have no OpenID Foundation plan outside FAPI; the Go tests
  cover them, including cross-organization confinement and disabled clients.
- **Token exchange (RFC 8693)** and **device sign-in (RFC 8628)** are in no plan; the Go end-to-end tests cover them. PAR and DPoP are covered by the
  FAPI 2.0 plan above, and by the Go tests for clients without the profile.
- **FAPI 2.0 with mTLS** (client authentication or sender-constrained tokens) is not supported, so those variants are
  not run.
- **Dynamic registration (RFC 7591)** is supported for self-registering clients such as MCP servers and AI clients
  ([MCP.md](MCP.md)), with Client ID Metadata Documents, but only where a tenant allows it; the suite's
  dynamic-client plans are not run. The Go end-to-end tests cover both.
- Implicit and hybrid flows and request objects are not supported, and discovery says so.

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
- `oidcc-ensure-registered-redirect-uri`, `oidcc-ensure-request-object-with-redirect-uri`, and in the comprehensive
  plan `oidcc-redirect-uri-query-added`: "This request cannot be completed" (an unregistered `redirect_uri` is never
  redirected to).
- RP-initiated logout with a bad, modified or missing `id_token_hint`, or an unregistered or altered
  `post_logout_redirect_uri`: "The sign-out request is not valid".
- RP-initiated logout without parameters, without `post_logout_redirect_uri`, or with only `state`: the "Sign out?"
  confirmation, then "You have been signed out".

## Fixed because of the runs

- **An expired request_uri could be used for up to a second.** A pushed request recorded its expiry in whole seconds
  and was refused only after that second had passed, so it worked up to a second past the `expires_in` the client was
  told; `par-attempt-to-use-expired-request_uri` visits the moment `expires_in` is up, and went on to the sign-in page.
  The expiry is now kept to the millisecond and the request_uri refused from it.
- **The ID token carried `idp` unasked** (a warning in `oidcc-server` and FAPI 2.0's `happy-flow`): the type of
  upstream provider the user signed in through was in every token. It is now a claim of the `idp` scope, with the
  account there (`idp_sub`, `idp_tenant`, `idp_login`), and can be asked for by name.
- **The harness followed the per-organization address spaces.** Since each organization moved to `/o/<id>`, the
  sign-in page is `/o/<id>/login?…` and the sign-out form posts to `/o/<id>/oauth/logout/confirm`; the browser steps
  in `conformance/config/` now match both. SCIM stays at the server's root (`/scim/v2/<org>`), so the client
  credentials plan's protected resource is named with `@PUBLIC_URL@`, which the seed fills in.

- `acr_values` were ignored (a warning). Discovery now lists `acr_values_supported` (`urn:quisora:acr:basic`,
  `urn:quisora:acr:mfa`); the requested values are taken in order of preference, and when the first known one is the
  MFA value a second factor is a condition of that sign-in. An essential `acr` claim with no known value fails with
  `unmet_authentication_requirements`. The ID token's `acr` is always one of the requested known values.
- The `claims` request parameter was not supported (a warning in `oidcc-claims-essential`). It is now: single claims
  for the ID token or userinfo, each only when the client may use the scope that holds it, shown on the consent
  screen, and kept across refreshes.
- The phone scope (`phone_number`, `phone_number_verified`) was added, so `oidcc-scope-phone` runs and passes.

- `POST /api/keys/rotate` returned success but rotated nothing unless a scheduled rotation was due. It now
  creates a key that signs at once; the previous keys stay published until their tokens expire.
- The ID token named the organization, tenant and Quisora role (`org`, `org_name`, `tenant`, `tenant_name`, `role`, since
  renamed `org_role`) whatever the scopes. They now need the `org` scope, as at userinfo; access tokens still always carry them.
- The sign-out confirmation page needed JavaScript and, outside the session middleware, rendered the anonymous CSRF
  token, so confirming without the page's script failed. It is now a plain form (`POST /o/<org id>/oauth/logout/confirm`) with
  the session's token.
- Outbound HTTPS can trust extra CA certificates (`server.extra_ca_file`), so a provider, client JWKS or back-channel
  endpoint on a private CA works without weakening TLS checks (the fake provider uses it).
