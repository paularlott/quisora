# Device sign-in

Device sign-in (the OAuth device authorization grant, RFC 8628) signs a user in on something that cannot show a
sign-in page: a command-line tool, a TV, a kiosk, a lab instrument. The device shows a short code; the user opens
the organization's `/device` page on their phone or computer, enters the code, signs in there as they always do, and approves.
The device, which has been asking Quisora in the background, then gets its tokens.

```
Device                                   Quisora                                  The user's phone
  │ POST /oauth/device_authorization ──▶ │                                              │
  │ ◀── device_code, user_code WDJB-MJHT │                                              │
  │ shows "Go to /device, enter WDJB-MJHT"                                              │
  │ POST /oauth/token (device_code) ───▶ │ ◀────── /device, the code, sign-in, Allow ── │
  │ ◀──────────── authorization_pending  │                                              │
  │ POST /oauth/token (device_code) ───▶ │                                              │
  │ ◀──── access, ID and refresh tokens  │                                              │
```

Every address here is under the organization's issuer, `https://id.example.com/o/<org id>`.

**The risk to know about.** Someone can start a device sign-in on their own machine and send a victim the code ("enter
this code to verify your account"). If the victim enters it and approves, the attacker's device is signed in as them.
Quisora makes this hard: device sign-in is off until you turn it on for an application, the `/device` page and the
consent screen both warn about codes from someone else, consent is always asked (even for first-party applications),
codes last 10 minutes and work once, and managers and administrators cannot approve unless you allow it for the
application. Turn it on only for applications that need it.

## Turning it on for an application

In the console: the tenant's **Clients** page → the client (or **New client**) → under **Grant types**, tick **Device
sign-in**. The client can be public (no secret: the usual choice for a CLI installed on people's machines) or
confidential; it cannot use the FAPI 2.0 profile. It needs no redirect URIs. Tick **Refresh token** too if the device
should stay signed in, and allow the `offline_access` scope (see [How long it stays signed in](#how-long-it-stays-signed-in)).

**Managers and administrators may approve device sign-ins** appears once the grant is ticked. It is off by default, so
only users without an administrative role can sign in on a device with this application: a code an attacker talks
someone into entering never gives a device an administrator's access. Turn it on for an administrators' tool that
needs it.

Through the management API (a [personal API token](../API-TOKENS.md) with the `admin` scope):

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"tenant_id":"<tenant id>","name":"acme CLI","token_endpoint_auth_method":"none",
       "grant_types":["refresh_token","urn:ietf:params:oauth:grant-type:device_code"],
       "scopes":["openid","profile","offline_access"],
       "device_privileged_users":false}' \
  "$QUISORA/api/orgs/acme/clients"
```

The answer's `id` is the client ID the device uses. (Quisora's own `quisora ssh login --device` is a device sign-in too: the tenant's
[SSH application](../ssh/README.md#turning-it-on-for-a-tenant) has it turned on, and the same risk applies. It sends `acr_values` and `max_age` with the request, so the session that approves the code is stepped up to a second factor.)

## The device's side, step by step

```bash
export ISSUER=https://id.example.com/o/<org id>      # the organization's issuer
export CLIENT_ID=c_…   # the client ID from the console
```

**1. Ask for a code.** A public client sends its `client_id`; a confidential one authenticates as it does at the token
endpoint ([client authentication](client-authentication.md)). `scope` is optional (without it, every scope the client
is allowed), and so is `resource` ([resource indicators](sign-in.md#tokens-for-an-api-resource-indicators)).
`acr_values` and `max_age` are optional too and mean what they do in an authorization request: `acr_values=urn:quisora:acr:mfa`
makes the user who approves the code sign in with a second factor (a password-only session is sent to step up),
and `max_age` (seconds, not negative) makes a session older than that sign in again. Without them an existing session
goes straight on.

```bash
curl -s "$ISSUER/oauth/device_authorization" \
  -d client_id="$CLIENT_ID" -d scope="openid profile offline_access" | tee device.json
```

```json
{
  "device_code": "a1.clGjx-yXuyn5NlPiCcTvlDX2GCiWbZ1y",
  "user_code": "PRFL-NXBM",
  "verification_uri": "https://id.example.com/o/<org id>/device",
  "verification_uri_complete": "https://id.example.com/o/<org id>/device?user_code=PRFL-NXBM",
  "expires_in": 600,
  "interval": 5
}
```

**2. Show the user what to do.** Show `verification_uri` and `user_code`, for example *"Open
https://id.example.com/o/<org id>/device and enter PRFL-NXBM"*. A device with a screen can also show `verification_uri_complete`
as a QR code: scanning it opens the page with the code already filled in. Keep `device_code` to yourself: it is what
collects the tokens.

**3. Ask for the tokens every `interval` seconds** until the answer is no longer `authorization_pending`:

```bash
curl -s "$ISSUER/oauth/token" \
  -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
  -d client_id="$CLIENT_ID" \
  -d device_code="$(jq -r .device_code device.json)"
```

| Answer | What it means | What the device does |
| --- | --- | --- |
| `authorization_pending` (400) | The user has not finished yet. | Wait `interval` seconds and ask again. |
| `slow_down` (400) | It asked sooner than `interval`. | Add 5 seconds to the interval, wait, ask again. |
| `access_denied` (400) | The user chose Deny, cancelled, has no access to the application, or is a manager or administrator the application does not allow. | Stop, and say the sign-in was not approved. |
| `expired_token` (400) | The 10 minutes passed (or the tokens were already collected). | Start again from step 1. |
| 200 with tokens | Approved. | Keep the tokens. You get them once. |

A loop that does all of it:

```bash
interval=$(jq -r .interval device.json)
while :; do
  sleep "$interval"
  curl -s "$ISSUER/oauth/token" -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
    -d client_id="$CLIENT_ID" -d device_code="$(jq -r .device_code device.json)" > tokens.json
  case $(jq -r '.error // "ok"' tokens.json) in
    authorization_pending) ;;
    slow_down) interval=$((interval + 5)) ;;
    ok) echo "Signed in"; break ;;
    *) jq -r .error_description tokens.json; break ;;
  esac
done
```

**4. Use the tokens.** They are the same as from any other sign-in ([sign-in](sign-in.md)): an access token (10
minutes by default), an ID token when `openid` was asked for, and a refresh token when the client has the refresh
grant.

```bash
curl -s "$ISSUER/oauth/userinfo" -H "Authorization: Bearer $(jq -r .access_token tokens.json)"
curl -s "$ISSUER/oauth/token" -d grant_type=refresh_token -d client_id="$CLIENT_ID" \
  -d refresh_token="$(jq -r .refresh_token tokens.json)"
```

A public client's refresh tokens rotate: each answer has a new `refresh_token`, and the old one stops working (using
an old one again ends the whole sign-in, as it would if someone had copied it). Keep only the latest. To sign the
device out, revoke its refresh token ([revocation](sign-in.md#revoking-tokens)).

A device that holds a private key can bind its tokens to it with [DPoP](dpop.md): send a proof with each token
request, as at any token request.

## The user's side

1. They open `https://id.example.com/o/<org id>/device` (or scan the QR code) and type the code. Capital letters and the dash do
   not matter: `prfl nxbm` works.
2. They sign in, as for any application of the client's tenant: its sign-in methods, second factor and access lists
   apply, and so do the `acr_values` and `max_age` the device asked for. Someone already signed in in that browser goes
   straight on, unless those ask for more than their session has.
3. A consent screen names the application and what it asks for, shows the code, and warns: *"Allow only if you
   started this yourself on a device in front of you that shows the code … If someone sent you the code, choose
   Deny."*
4. **Allow** shows *"Your device is signed in"*; the device gets its tokens at its next request. **Deny** tells the
   device `access_denied`.

A code is the only thing linking the two, so it is short-lived and hard to guess: 8 letters from 20 consonants (no
vowels, so no words, and no 0/O or 1/I to confuse), 10 minutes, once. Each address may enter 20 wrong codes per 15
minutes, and start 30 device sign-ins per minute.

## How long it stays signed in

As with any sign-in, the tokens belong to a grant that lasts as long as the browser session that approved it, unless
the `offline_access` scope was granted: then the refresh tokens outlive that session (up to `tokens.refresh_ttl`, 30
days by default, renewed by each refresh). A CLI or TV that should stay signed in for days asks for `offline_access`,
and its client is allowed that scope. Ending that browser session from another session or by an administrator,
signing the user out everywhere, locking them out, an
[emergency sign-out](../emergency-sign-out.md) or removing their access ends the device's sign-in too.

## What is recorded

| Audit event | When |
| --- | --- |
| `oauth.device.approve` | The user allowed a device sign-in (who, which application, the scopes). |
| `oauth.consent` with `decision` `deny` | The user denied it. |
| `oauth.grant` with `grant_type` `device_code` | The device collected its tokens. |
| `oauth.device.start` | A device asked for a code (only with `audit.tokens = true`: anyone can ask for codes). |

If someone approved a code they were sent, see [the incident response](../SECURITY.md#incident-response).

## Reference

| | |
| --- | --- |
| Device endpoint | `POST /o/<org id>/oauth/device_authorization` (`device_authorization_endpoint` in discovery) |
| Grant type | `urn:ietf:params:oauth:grant-type:device_code` |
| Verification page | `/o/<org id>/device`, or `/o/<org id>/device?user_code=…` |
| Code lifetime | 600 seconds (`expires_in`) |
| Poll interval | 5 seconds, plus 5 for every `slow_down` |
| User code | 8 letters, shown as `XXXX-XXXX` |
| Client setting | `device_privileged_users` (managers and administrators may approve), off by default |
