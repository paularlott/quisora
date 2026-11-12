# Signing users in: authorization code with PKCE

The usual way an application signs a user in. The application sends the browser to Quisora; the user signs in
there (password, passkey, a second factor, an upstream provider: whatever the application's tenant allows) and, the
first time, approves what the application asks for; Quisora sends the browser back to the application with a
one-time **code**, which the application exchanges for tokens. PKCE ties the code to the application instance that
asked for it, so a code intercepted on the way back is useless. Quisora requires PKCE (S256) of every public client,
and of confidential ones unless they turn it off.

Use your OAuth or OpenID Connect library for this in a real application: point it at the organization's issuer
(`https://id.example.com/o/<org id>`), and it reads everything else from discovery. The steps below are what the library does,
with curl, to see it work or to debug it.

```bash
export ISSUER=https://id.example.com/o/<org id>      # the organization's issuer
export CLIENT_ID=c_…                     # from the client's page in the console
export CLIENT_SECRET=…                   # confidential clients only: shown once, when the client is made
export REDIRECT_URI=https://app.example.com/callback   # registered on the client
```

## 1. Send the browser to Quisora

Make a PKCE verifier (a random string the application keeps) and its challenge (its SHA-256, which goes in the URL),
plus a `state` to match the answer to the request and a `nonce` to match the ID token to it:

```bash
VERIFIER=$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n')
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
STATE=$(openssl rand -hex 16); NONCE=$(openssl rand -hex 16)

echo "$ISSUER/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$(jq -rn --arg u "$REDIRECT_URI" '$u|@uri')&scope=openid%20profile%20email%20offline_access&state=$STATE&nonce=$NONCE&code_challenge=$CHALLENGE&code_challenge_method=S256"
```

Open the printed address in a browser and sign in. Quisora sends the browser back to the redirect URI:

```
https://app.example.com/callback?code=a1.Xk3…&state=<your state>&iss=https%3A%2F%2Fid.example.com%2Fo%2F<org id>
```

Check that `state` is yours and `iss` is the organization's issuer, then take the `code`. It works once, for 60 seconds
(`tokens.code_ttl`). The application's page there need not exist to try this: copy the code from the address bar.

If something is wrong with the request, the answer comes back the same way with `error` and `error_description`
instead of `code` (`access_denied` when the user chose Deny or Cancel, `invalid_scope`, `login_required` for
`prompt=none` without a session…). A request that cannot be trusted to go back (an unknown `client_id`, a
`redirect_uri` that is not registered) stops on an error page instead. A `client_id` belongs to one organization: at another
organization's endpoints it is unknown.

**Parameters**

| Parameter | |
| --- | --- |
| `response_type` | `code`, always. |
| `client_id`, `redirect_uri` | The redirect URI must be registered on the client exactly (an `http://localhost`, `127.0.0.1` or `[::1]` one may use any port, for desktop apps). |
| `scope` | Space-separated; at most the scopes the client is allowed. Without it, all of them. See [scopes and claims](#scopes-and-claims). |
| `state`, `nonce` | Up to 2048 and 1024 characters. Recommended: always. |
| `code_challenge`, `code_challenge_method` | PKCE; the method is `S256`. |
| `prompt` | `login` (sign in again), `consent` (ask again), `select_account` (sign in again), or `none` (never show a page: `login_required` or `consent_required` instead). A public client that is not first-party asks for consent at every sign-in (anyone can claim its `client_id`), so `prompt=none` always answers `consent_required` for it: silent renewal needs a first-party or confidential client, or a refresh token. |
| `max_age` | Seconds: sign in again if the last sign-in is older. |
| `login_hint` | An email address to fill in on the sign-in page. |
| `acr_values` | `urn:quisora:acr:mfa` to require a second factor for this sign-in (`urn:quisora:acr:basic`: no requirement). The ID token's `acr` says which was met. |
| `claims` | Individual claims (OIDC Core §5.5), for the ID token or userinfo, within the client's scopes. |
| `resource` | The API the access token is for ([resource indicators](#tokens-for-an-api-resource-indicators)). |
| `response_mode` | `query` (default) or `form_post` (the answer is posted to the redirect URI). |
| `dpop_jkt` | Bind the code to a [DPoP](dpop.md) key. |

An application that wants its request parameters kept out of the browser pushes them first:
[pushed authorization requests](par.md).

## 2. Exchange the code for tokens

The client authenticates as it is registered to ([client authentication](client-authentication.md)); a public
client sends only its `client_id`. `redirect_uri` must be the one in the request, and `code_verifier` the verifier
whose challenge was in it.

```bash
curl -s "$ISSUER/oauth/token" \
  -d grant_type=authorization_code -d code="$CODE" -d redirect_uri="$REDIRECT_URI" -d code_verifier="$VERIFIER" \
  -d client_id="$CLIENT_ID" -d client_secret="$CLIENT_SECRET" | tee tokens.json
```

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIs…",
  "token_type": "Bearer",
  "expires_in": 600,
  "scope": "openid profile email offline_access",
  "refresh_token": "-Ox7Lm2qT….Hk2…",
  "id_token": "eyJhbGciOiJFUzI1NiIs…"
}
```

- **Access token**: a JWT for APIs, 10 minutes by default (`tokens.access_ttl`). Its `aud` is the client (and any
  [resources](#tokens-for-an-api-resource-indicators)).
- **ID token**: who signed in, for the application itself (with `openid`). Check its signature against
  the organization's `/oauth/jwks`, `iss` (the organization's issuer), `aud` (your client ID), `exp` and `nonce`. `amr` says how the user signed in (`pwd`, `hwk`
  or `swk` for a passkey with `user` when it verified the user, `otp`, `mfa` when two factors were used, `fed` for an
  upstream provider, followed by the provider's own `amr` values when it sent any, but never its `mfa`:
  [providers](../sign-in/providers.md)) and `acr` whether Quisora verified or trusts a second factor. `mfa` in `amr`
  and `urn:quisora:acr:mfa` say the same thing.
  `fed` in `amr` says the user signed in through an upstream provider; the `idp` scope says which one and which
  account there ([below](#which-upstream-account-the-idp-scope)).
- **Refresh token**: with the refresh grant on the client. See [refreshing](#refreshing).

A code presented a second time fails, and everything issued from it the first time is revoked: someone else had it.

Read a JWT's claims (without verifying it), with the helpers in [jwt.sh](jwt.sh):

```bash
source docs/oauth/jwt.sh
jwt_claims "$(jq -r .id_token tokens.json)"
```

## Scopes and claims

| Scope | Claims (ID token and userinfo) |
| --- | --- |
| `openid` | `sub` (the user's ID, which never changes), and makes it an OpenID Connect sign-in: an ID token. |
| `profile` | `name`, `preferred_username`, `given_name`, `family_name`, `picture` ([below](#profile-pictures)), `locale`, `zoneinfo`, `updated_at` |
| `email` | `email`, `email_verified` |
| `phone` | `phone_number`, `phone_number_verified` |
| `groups` | `groups`: the names of the user's groups |
| `org` | `org`, `org_name`, `tenant`, `tenant_name`, `org_role` (the user's Quisora role: `user`, `manager`, `admin`, `super_admin`) |
| `roles` | `roles`: the application roles the user's access to this application gives them, and `tags` |
| `enterprise` | `enterprise`: job title, department, manager, employee number and the like |
| `idp` | `idp`, `idp_sub`, `idp_tenant`, `idp_login`: the upstream provider the user signed in with and the account there ([below](#which-upstream-account-the-idp-scope)) |
| `offline_access` | No claims: the refresh tokens outlive the user's browser session ([refreshing](#refreshing)). |

Access tokens carry what APIs authorize on whatever the scopes: `org`, `org_name`, `tenant`, `tenant_name`, `org_role`,
`tags` and `roles`, plus `groups`, `enterprise` and the `idp` scope's claims with those scopes, and `acr`, `amr` and
`auth_time`. Besides those, an access token carries `jti`, `sid` (the
browser session), `gid` (the refresh grant it was issued from) and, when claims were requested by name for userinfo,
`userinfo_claims`.
Scopes of your own (`orders:read`) are listed on the client and simply passed through in `scope`: your API decides
what they mean. The [application roles](../API-TOKENS.md#application-roles) an administrator gives users on a tenant's
access list arrive in `roles`, and the [authorization details](authorization-details.md) given there (RFC 9396), for
applications registered for their types, in `authorization_details`.

### Profile pictures

`picture` is the absolute URL of the user's profile picture, `https://<server>/o/<org id>/pictures/<random id>`, and
is left out when the user has none. It is an image, never a page: a 256 × 256 pixel JPEG or PNG that Quisora made
itself from what was uploaded, and serves to anyone holding the URL with no sign-in, so put it straight in an
`<img>` (it is served with `Cross-Origin-Resource-Policy: cross-origin`). The random part of the URL is what keeps it
private to those given it; a new picture always has a new URL (each is cached for a year, as it never changes), and
an old URL answers 404 once the picture is replaced or removed or the user is deleted. Compare `picture`, not the
image, to see whether it changed.

Who sets pictures is the organization's choice, `settings.pictures` (the organization editor's "Profile pictures"):

- `everyone` (the default): people set their own on their account page; managers and administrators set them in the
  console or through the management API (`PUT /api/orgs/{org}/users/{id}/picture`), provisioning systems through
  SCIM's `photos`, and an account a sign-in provider creates or links takes the provider's picture (GitHub's avatar, an
  OpenID provider's `picture`) once, when it has none;
- `admins`: the same, except that people cannot change their own;
- `off`: no pictures at all. Nobody can upload one (`403`), SCIM's `photos` are ignored when written and left out when
  read, nothing is copied from sign-in providers, no `picture` claim is sent, the user JSON of the APIs has none, and
  every picture URL of the organization answers 404 at once. **Turning pictures off deletes those held**: housekeeping
  removes them, and turning pictures on again starts with none.

To have none in any organization, start the server with `--disable-pictures` (`server.disable_pictures = true`,
`QUISORA_DISABLE_PICTURES=true`). Every organization then behaves as if it had `off`: the same refusals, no `picture`
claim (it leaves `claims_supported` and the `profile` scope's consent text), 404 for every picture URL, pictures held
deleted by housekeeping, and the console no longer shows the "Profile pictures" setting; the API refuses to change
`settings.pictures` to `admins` or `off`. Pictures are on by default.

Each is a JPEG, PNG or WebP image of at most 5 MB and 8192 pixels a side, cropped to its centre square. A server
makes one picture at a time and lets a few more wait their turn; past that an upload is refused at once with `503` and
`Retry-After` (try again in a few seconds).

### Which upstream account: the idp scope

A user can have several accounts at upstream providers linked to theirs, a Microsoft and a Google one say. The `idp`
scope says which kind of provider a sign-in went through and which account there, as the provider itself names it, so
an application that calls the provider's own APIs (Microsoft Graph, Google's) can tell it is the same account:

| Claim | Microsoft | Google, GitLab, Auth0, OpenID Connect | GitHub | Another organization |
| --- | --- | --- | --- | --- |
| `idp` | `microsoft` | `google`, `gitlab`, `auth0`, `oidc` | `github` | `organization` |
| `idp_sub` | the object ID (`oid`), as Graph's `/me` `id`; Microsoft's `sub` differs for each application | the provider's `sub` | the user ID | the user's ID there |
| `idp_tenant` | the directory (`tid`) | absent | absent | that organization's ID |
| `idp_login` | the user principal name (`preferred_username`) | the email address | the username | the email address, only when that organization verified it |

Match on `idp_sub` (with `idp_tenant` for Microsoft): it never changes. `idp_login` is for `login_hint`, so the
provider's own sign-in starts at the right account; it can change, and another account can come to have it, so it is
never an identity.

For a guest from another organization, `idp_tenant` and `idp_login` together say that organization vouches for the
address: someone in this organization cannot set them, as they can the user's own `email`. An application that already
has accounts for people of that organization can link a guest's first sign-in to the account with that address, when
it trusts that organization with the address's domain; afterwards it matches on `sub` like any other user. All four are
absent without the scope and when the user signed in another way (a password, a passkey), and the last three when the
provider has since been removed; the consent screen names the scope. Refreshed tokens keep the account of the sign-in
they came from.

## Userinfo

```bash
curl -s "$ISSUER/oauth/userinfo" -H "Authorization: Bearer $(jq -r .access_token tokens.json)"
```

The same claims as the ID token, read fresh: a name changed since the sign-in shows here. A token whose user lost
access to the application since is refused (401 `invalid_token`), as it is at introspection: the two make the same
decision. When Quisora cannot make it (a store read failed), the answer is 503 `temporarily_unavailable` with
`Retry-After` and no `WWW-Authenticate` challenge: the token is not known to be bad, so keep it and try again; the
profile is never released on an undecided check.

## Refreshing

```bash
curl -s "$ISSUER/oauth/token" -d grant_type=refresh_token -d refresh_token="$(jq -r .refresh_token tokens.json)" \
  -d client_id="$CLIENT_ID" -d client_secret="$CLIENT_SECRET"
```

`scope` may ask for fewer scopes than were granted, `resource` for fewer resources. Every refresh checks again that
the user is enabled and still has access. `invalid_grant` means the grant has ended (revoked, signed out, access
taken away): discard the token and sign the user in again. A check Quisora could not make (a store read failed)
answers 503 `temporarily_unavailable` instead: the token may be good, keep it and retry.

- **Rotation.** By default each refresh returns a new refresh token and the old one stops working; presenting an old
  one again ends the whole grant (`oauth.refresh.reuse` in the audit log), since only a copy would do that. One
  exception keeps a lost response from signing the user out: within 30 seconds of a refresh, the token just before
  the current one gets the current one again, with nothing rotated, when the caller also proves who it is (a
  confidential client's credentials, or the DPoP key the grant is bound to). A public client without DPoP has only
  the token, so for it any old token is reuse. Public clients always rotate; a confidential client that cannot keep
  the latest token can turn **Rotate refresh tokens** off.
- **How long.** Without `offline_access`, the grant lasts as long as the user's browser session at Quisora: signing
  out there ends it. With it, refresh tokens outlive the session, for `tokens.refresh_ttl` (30 days by default).
  Either way, ending the session from another session or by an administrator, signing the user out everywhere, locking
  them out or an emergency sign-out ends it ([signing out and ending a session](../sign-in/README.md#sessions)).
- **How many.** Each code exchange makes a new grant, so an application that signs in again (even silently, with
  `prompt=none`) instead of refreshing piles them up. A user keeps at most 1,000 by default
  (`limits.grants_per_user`; a super admin can set an organization's own, from 10 to 100,000, for example where many
  machines sign in as one user with `offline_access`): past that, Quisora ends the excess, down to 90% of the cap,
  those without `offline_access` first, then those with it, the least recently used first
  (`oauth.grant.evict` in the audit log). An ended grant's refresh token is refused (`invalid_grant`) and the SSH
  certificates issued under it are revoked; the user stays signed in. Refresh the tokens you have rather than signing
  in again.

## Introspection

An API that receives an access token can verify it itself (signature against the organization's `/oauth/jwks`, `iss`, `aud`, `exp`) or
ask Quisora, which also knows whether the grant has been revoked or the user signed out since:

```bash
curl -s "$ISSUER/oauth/introspect" -d token="$ACCESS_TOKEN" \
  -d client_id="$API_CLIENT_ID" -d client_secret="$API_CLIENT_SECRET"
```

```json
{"active": true, "sub": "-Ox7Lm2qT…", "client_id": "c_…", "scope": "openid profile", "exp": 1792812000, …}
```

Only confidential clients introspect, and a client sees `active: true` only for tokens issued for it (its ID in
`aud`). An API with its own client that serves several applications, or that applications name as a resource, turns
on **May introspect every token of the organization** on its client. Refresh tokens can be introspected by the client
they belong to; [personal API tokens](../API-TOKENS.md#your-own-applications-api) with the `api` scope too, for a client
that has **Accepts personal API tokens** turned on, and while the organization lets the token's owner use them.

A user's token is `active` only while the user may still use the application: the same checks as userinfo (user
enabled, grant not revoked or signed out, access to a members-only tenant's application still held, a
self-registered application's resource still accepting it). `active: false` is a verdict; when Quisora cannot reach
one (a store read failed) it answers 503 `temporarily_unavailable` rather than either, so an API neither serves a
token that may have been revoked nor refuses a user whose token is fine.

## Revoking tokens

```bash
curl -s "$ISSUER/oauth/revoke" -d token="$(jq -r .refresh_token tokens.json)" \
  -d client_id="$CLIENT_ID" -d client_secret="$CLIENT_SECRET"
```

Revoking a refresh token, or one of the client's access tokens, ends the grant: every token from that sign-in stops
working (access tokens through introspection and userinfo; an API checking signatures itself accepts them until they
expire). The answer is 200 whether or not the token was valid (RFC 7009). When the grant could not be ended (the
deletion did not persist), the answer is 503 `temporarily_unavailable` with `Retry-After` (RFC 7009 §2.2.1): the
token still works, nothing is recorded as revoked, and the client retries.

## Signing out

To sign the user out of Quisora too, send the browser to the end-session endpoint:

```
https://id.example.com/o/<org id>/oauth/logout?id_token_hint=<the ID token>&post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fsigned-out&state=…
```

With a valid `id_token_hint` for the user signed in, Quisora signs them out at once; without one it asks them to
confirm. It then returns to `post_logout_redirect_uri` (which must be registered on the client as a post-logout
redirect URI) with your `state`.

**Back-channel logout.** Give a client a back-channel logout URI and Quisora posts a signed `logout_token` (with `sid`)
to it whenever one of its users' sessions ends: sign-out, a session revoked, a password reset, an account disabled
or deleted, an emergency sign-out. The application ends its own session for that `sid` or `sub`. A logout your
application does not take (unreachable, or answering with an error) is retried after 5 s, 30 s, 5 min, 15 min and
1 h, then given up on and logged; the retries wait in the store, as the node's own, so a restart does not lose them. Organizations do not
hold each other up: each has its own share of the senders (8 at a time) and of the queue (2,500 logouts), and the
senders serve the organizations in turn, so an application that is slow or never answers delays only the notices of
its own organization. A logout that finds its organization's share full goes straight to the retry queue instead.
The retry queue is fair the same way: it sends 8 at a time, at most 2 of them for one organization, and sends each
retry as soon as one of those is free, so retries to an application that never answers (8 s each, at most) hold back
only the retries of its own organization, and a new retry of another one does not wait for them. Each node's retry
queue holds at most 10,000 logouts, of which one organization may have 2,500: an organization whose applications never answer (or that
signs out thousands of sessions at once) can only fill its own share, and its logouts beyond it are dropped with a
warning, while the failures of the other organizations are still queued.
Answer quickly and idempotently: the same logout can arrive twice.

## Tokens for an API (resource indicators)

A token meant for one of your APIs names it (RFC 8707): register the API's URI on the client under **Resources**, and
ask for it with `resource` in the authorization request (and optionally again, the same or fewer, at the token
request):

```
…&resource=https%3A%2F%2Fapi.example.com%2F
```

The access token's `aud` then holds the client ID and `https://api.example.com/`; the API checks that its own URI is
there. A request naming a resource not registered on the client fails with `invalid_target`.

## Requiring a second factor

A tenant (or organization) can require a second factor for every sign-in. An application can also ask for one for a
particular sign-in, with `acr_values=urn:quisora:acr:mfa` (or a `claims` request for `acr` with that value): a user
whose session has no second factor is asked for it. The ID token's `acr` is then `urn:quisora:acr:mfa` and `amr`
includes `mfa`.

## Reference

| | |
| --- | --- |
| Issuer | `https://id.example.com/o/<org id>`; every endpoint below is under it |
| Discovery | `/o/<org id>/.well-known/openid-configuration` (also `/o/<org id>/.well-known/oauth-authorization-server`, and `/.well-known/openid-configuration/o/<org id>`) |
| Authorization | `GET` or `POST /o/<org id>/oauth/authorize` |
| Token | `POST /o/<org id>/oauth/token` |
| Userinfo | `GET` or `POST /o/<org id>/oauth/userinfo` |
| Keys | `GET /o/<org id>/oauth/jwks` |
| Introspection | `POST /o/<org id>/oauth/introspect` (RFC 7662) |
| Revocation | `POST /o/<org id>/oauth/revoke` (RFC 7009) |
| End session | `GET` or `POST /o/<org id>/oauth/logout` |
| Lifetimes | codes 60 s, access and ID tokens 600 s, refresh tokens 30 days (`tokens.*` settings) |
