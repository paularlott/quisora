# DPoP: tokens bound to a key

An ordinary access token is a bearer token: whoever holds it can use it, so a token leaked from a log, a proxy or a
compromised machine works for an attacker until it expires. With DPoP (RFC 9449) the application holds a private key
and proves it with every request: the tokens it gets are bound to that key, and are refused without a fresh proof
made with it. A copied token is useless.

A **DPoP proof** is a small JWT, signed with the application's key, with the public key in its header, made for one
request: the method (`htm`), the URL (`htu`), the time (`iat`), a unique `jti`, and, when it goes with an access token
to an API, the token's hash (`ath`). It is sent in a `DPoP` header.

The examples use the helpers in [jwt.sh](jwt.sh) (bash, OpenSSL 3 and jq) and an Ed25519 key; ES256, PS256 and RS256
keys work too (not RS256 with FAPI 2.0). In an application, your OAuth library does all of this.

```bash
export ISSUER=https://id.example.com/o/<org id>      # the organization's issuer
source docs/oauth/jwt.sh
new_key dpop.key            # the application's DPoP key: it never leaves the application
jwk_thumbprint dpop.key     # its thumbprint ("jkt"), which the tokens will name
```

## Getting a DPoP-bound token

Any token request can carry a proof: the code exchange, a refresh, client credentials, token exchange, device sign-in.
Proofs at the token endpoint need a **nonce** from Quisora, so they cannot be made in advance: the first request
without one fails with `use_dpop_nonce`, and every answer from the token endpoint carries the nonce to use next in
its `DPoP-Nonce` header.

```bash
# first try: no nonce yet, so the answer is use_dpop_nonce, with the nonce in DPoP-Nonce
curl -s -D headers.txt "$ISSUER/oauth/token" \
  -H "DPoP: $(dpop_proof dpop.key POST "$ISSUER/oauth/token")" \
  -d grant_type=client_credentials -d client_id="$CLIENT_ID" -d client_secret="$CLIENT_SECRET"
NONCE=$(grep -i '^dpop-nonce:' headers.txt | cut -d' ' -f2 | tr -d '\r')

# again, with the nonce
curl -s -D headers.txt "$ISSUER/oauth/token" \
  -H "DPoP: $(dpop_proof dpop.key POST "$ISSUER/oauth/token" "$NONCE")" \
  -d grant_type=client_credentials -d client_id="$CLIENT_ID" -d client_secret="$CLIENT_SECRET" | tee tokens.json
```

```json
{"access_token": "eyJhbGciOiJFUzI1NiIs…", "token_type": "DPoP", "expires_in": 600, "scope": "reports:read"}
```

`token_type` is `DPoP`, and the access token's `cnf.jkt` is the key's thumbprint:

```bash
jwt_claims "$(jq -r .access_token tokens.json)" | jq .cnf      # {"jkt": "Rh_sZ9Of…"}
```

A nonce lasts two to three minutes and works on every node; keep using the latest `DPoP-Nonce` you were sent. Each
proof works once, and its `iat` must be within 5 minutes of the server's clock.

For a user's sign-in, send the proof with the code exchange
([sign-in, step 2](sign-in.md#2-exchange-the-code-for-tokens)) in the same way.

## Using the token

At Quisora's userinfo and SCIM endpoints, and at any API that supports DPoP, send the token with the `DPoP`
authorization scheme (not `Bearer`) and a new proof for that request, including the token's hash:

```bash
AT=$(jq -r .access_token tokens.json)
curl -s "$ISSUER/oauth/userinfo" -H "Authorization: DPoP $AT" \
  -H "DPoP: $(dpop_proof dpop.key GET "$ISSUER/oauth/userinfo" "" "$AT")"
```

The same token without a proof, with a proof from another key, or as `Bearer`, is refused (`invalid_token`). At
resource endpoints a nonce is optional; one that is sent must be current.

## Refresh tokens

- A **public client**'s refresh tokens are bound to the key of its first proof: each refresh needs a proof made with
  that key. A refresh token copied off the device cannot be used elsewhere.
- A **confidential client**'s refresh tokens stay bound to its client authentication (its secret or private key), as
  without DPoP. It may still send a proof, to get DPoP-bound access tokens.

## Binding the code in advance

A sign-in can be bound to the key from the start, so that even the authorization code is useless to anyone else:
add `dpop_jkt=<the key's thumbprint>` to the authorization request, or send a proof with a [pushed
request](par.md#with-dpop). The code is then exchanged only with a proof made with that key.

```
…/oauth/authorize?…&dpop_jkt=Rh_sZ9Ofjvi3kMKqjCng-nD7UTCmH6fvpL94RnYf1RE
```

## Requiring it

**Require DPoP-bound tokens** on a client (`dpop_bound_access_tokens`) refuses its token requests without a proof,
so every token it ever gets is bound. Turn it on once the application sends proofs. The FAPI 2.0 profile turns it on.

## For APIs that check tokens themselves

An API that verifies Quisora's access tokens with the JWKS (rather than through introspection) must, for a token with
`cnf.jkt`:

1. accept it only with the `DPoP` scheme and a `DPoP` header holding one proof;
2. verify the proof's signature with the `jwk` in its header, and that the JWK's thumbprint equals `cnf.jkt`;
3. check `htm` and `htu` against the request, `iat` is recent, `jti` was not seen before, and `ath` is the base64url
   SHA-256 of the access token.

Through introspection, Quisora reports `cnf` and the API still checks the proof (steps 1 to 3). A DPoP library
for your language does all three.

## Errors

| Error | Why |
| --- | --- |
| `use_dpop_nonce` (400, with `DPoP-Nonce`) | The proof had no nonce, or an old one. Retry with the one in the header. |
| `invalid_dpop_proof` | The proof is malformed, signed with an unsupported algorithm, for another method or URL (`htu` is the URL without query or fragment), too old, or used before. |
| `invalid_dpop_proof`: *this client must send a DPoP proof* | The client has **Require DPoP-bound tokens** and sent no proof. |
| `invalid_grant`: *the refresh token is bound to a DPoP key* | A public client's refresh token presented without a proof, or with a proof made with another key. |
| `invalid_grant`: *not made with the key the authorization request named* | A code bound with `dpop_jkt` (or a pushed proof) exchanged with another key. |
