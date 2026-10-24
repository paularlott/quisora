# FAPI 2.0 Security Profile

The FAPI 2.0 Security Profile is the OpenID Foundation's set of rules for APIs where a stolen token costs real money
or privacy: open banking, health records, payments. It puts several of Quisora's features together and forbids the
weaker options. Quisora passes the profile's certification tests for its `private_key_jwt` + DPoP variant
([conformance](../conformance.md)).

Turn it on per client: **FAPI 2.0 Security Profile** in the client dialog (shown for **Private key JWT**), or
`"fapi2_security_profile": true`. Other clients are unaffected.

## What it changes for the client

| | |
| --- | --- |
| Client authentication | [Private key JWT](client-authentication.md#private-key-jwt) only. Its assertions must have the issuer alone, as a string, as their `aud` (not the token endpoint, not an array), and must not be RS256. |
| Sign-in requests | [Pushed](par.md) only: **Require pushed authorization requests** is turned on. |
| Tokens | [DPoP](dpop.md)-bound only: **Require DPoP-bound tokens** is turned on. No RS256 proofs. |
| Refresh tokens | Do not rotate (the profile asks for it): the same refresh token keeps working, bound to the client's authentication. |
| ID tokens | Signed with the client's algorithm, never RS256: PS256, ES256 or EdDSA. |
| Authorization codes | Last at most 60 seconds, whatever `tokens.code_ttl` says. |
| PKCE | Required (S256). |
| Grants | The device grant is not allowed. Client credentials and token exchange work as for other clients. |

Saving a FAPI client that cannot meet these (a client secret, RS256 ID tokens, PKCE off, the device grant) is refused
with the field to fix.

**TLS.** The profile allows only forward-secret AEAD cipher suites over TLS 1.2. Quisora always offers only those
(the AES-GCM suites of RFC 9325), whatever the clients; TLS 1.3 is unaffected. Behind a proxy that ends TLS, the
proxy's configuration decides.

## A sign-in, step by step

The helpers in [jwt.sh](jwt.sh) (bash, OpenSSL 3 and jq) make the client assertions and DPoP proofs.

```bash
export QUISORA=https://id.example.com
source docs/oauth/jwt.sh
new_key client.key                                 # the client's signing key
echo "{\"keys\":[$(jwk client.key k1)]}"           # register this as the client's public keys (JWKS)
new_key dpop.key                                   # the DPoP key
assertion() { client_assertion client.key "$CLIENT_ID" "$QUISORA"; }   # aud: the issuer, as FAPI requires
JWT_BEARER=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
nonce() { grep -i '^dpop-nonce:' headers.txt | cut -d' ' -f2 | tr -d '\r'; }
```

**1. Push the request**, with a DPoP proof (which binds the code to the key). The first push gets the nonce:

```bash
VERIFIER=$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n')
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
push() {
  curl -s -D headers.txt "$QUISORA/oauth/par" -H "DPoP: $(dpop_proof dpop.key POST "$QUISORA/oauth/par" "$1")" \
    -d client_assertion_type=$JWT_BEARER --data-urlencode "client_assertion=$(assertion)" \
    -d response_type=code -d redirect_uri="$REDIRECT_URI" -d scope="openid accounts" \
    -d state=s1 -d nonce=n1 -d code_challenge="$CHALLENGE" -d code_challenge_method=S256
}
push                           # use_dpop_nonce
push "$(nonce)" | tee par.json # {"request_uri": "urn:ietf:params:oauth:request_uri:…", "expires_in": 60}
```

**2. Send the browser** to the authorization endpoint with the reference, within 60 seconds:

```bash
echo "$QUISORA/oauth/authorize?client_id=$CLIENT_ID&request_uri=$(jq -r .request_uri par.json | jq -Rr @uri)"
```

The user signs in and approves; the browser returns to the redirect URI with `code`, `state` and `iss`. Exchange the
code within 60 seconds.

**3. Exchange the code**, with a new assertion and a proof of the same key:

```bash
curl -s -D headers.txt "$QUISORA/oauth/token" -H "DPoP: $(dpop_proof dpop.key POST "$QUISORA/oauth/token" "$(nonce)")" \
  -d client_assertion_type=$JWT_BEARER --data-urlencode "client_assertion=$(assertion)" \
  -d grant_type=authorization_code -d code="$CODE" -d redirect_uri="$REDIRECT_URI" -d code_verifier="$VERIFIER" \
  | tee tokens.json
```

`token_type` is `DPoP`. Use the access token with a proof for each request
([using the token](dpop.md#using-the-token)), and refresh with an assertion and a proof:

```bash
curl -s -D headers.txt "$QUISORA/oauth/token" -H "DPoP: $(dpop_proof dpop.key POST "$QUISORA/oauth/token" "$(nonce)")" \
  -d client_assertion_type=$JWT_BEARER --data-urlencode "client_assertion=$(assertion)" \
  -d grant_type=refresh_token -d refresh_token="$(jq -r .refresh_token tokens.json)"
```

The answer has no new `refresh_token`: the one you have keeps working.

## Errors you may meet

| Error | Why |
| --- | --- |
| `invalid_client`: *a FAPI 2.0 client's assertion needs aud set to the issuer alone…* | The assertion's `aud` is the token endpoint, or an array, or it is RS256. |
| `invalid_request` (at the redirect URI): *this client must push its authorization requests* | An authorization request made without PAR. |
| `invalid_dpop_proof`: *this client must send a DPoP proof* | A token request without a proof. |
| `use_dpop_nonce` | Retry with the nonce in `DPoP-Nonce`. |

mTLS (certificate-bound tokens or client authentication) is not supported; use DPoP and private key JWT.
