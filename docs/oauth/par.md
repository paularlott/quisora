# Pushed authorization requests

With a pushed authorization request (PAR, RFC 9126) the application sends the parameters of its sign-in request to
Quisora directly, server to server and authenticated, and the browser carries only a short reference to them. The
parameters cannot be read or changed on the way, never appear in browser history or logs, and are checked before
the user sees anything. FAPI 2.0 requires it; any confidential client can use it.

```bash
export ISSUER=https://id.example.com/o/<org id>      # the organization's issuer
```

## 1. Push the request

Everything that would go in the authorization URL, posted to the organization's `/oauth/par` with the client's authentication
([client authentication](client-authentication.md)). The PKCE values are made as in [the sign-in
guide](sign-in.md#1-send-the-browser-to-quisora).

```bash
curl -s "$ISSUER/oauth/par" -d client_id="$CLIENT_ID" -d client_secret="$CLIENT_SECRET" \
  -d response_type=code -d redirect_uri="$REDIRECT_URI" -d scope="openid profile" \
  -d state="$STATE" -d nonce="$NONCE" -d code_challenge="$CHALLENGE" -d code_challenge_method=S256
```

```json
{"request_uri": "urn:ietf:params:oauth:request_uri:djM6a…", "expires_in": 60}
```

The answer is `201 Created`. Anything wrong with the request is answered here, as an OAuth error
(`invalid_request`, `invalid_scope`…), instead of on a page in the user's browser.

## 2. Send the browser with the reference

```bash
echo "$ISSUER/oauth/authorize?client_id=$CLIENT_ID&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3AdjM6a…"
```

Only `client_id` and `request_uri`: any other parameter in the URL is ignored, the pushed ones count. The rest is the
usual sign-in: the browser comes back to the redirect URI with a `code`, which the application [exchanges for
tokens](sign-in.md#2-exchange-the-code-for-tokens) as always.

## The request_uri

The request_uri is the request itself, sealed with the server's key (encrypted and authenticated), so Quisora keeps
nothing for a push. It is about twice as long as the request, and goes in a URL the browser sends: a real request is
about 1 KB, and one over 8 KB is refused.

- **60 seconds** to start: the browser must reach the organization's `/oauth/authorize` within a minute of the push. The
  sign-in it starts then lasts as long as any sign-in flow, so a user who takes their time signing in is fine, but the
  authorization URL itself is no longer good after the minute.
- **Once.** It is used up when the request is decided (a code is issued, or the user denies or cancels), not on its
  first visit, so reloading the sign-in page works. Presented again after that, it goes back to the application as
  `invalid_request_uri`.
- **One client.** Only the client that pushed it can use it; with another `client_id`, or once expired, the browser
  gets an error page (nothing in such a request can be trusted to send the browser anywhere).

## Limits

A push is counted after the client has authenticated. A confidential client (secret or private key JWT) may push 1,800 a
minute, whatever its address and whatever other clients push; past that it gets `429 temporarily_unavailable` with
`Retry-After`. A public client is admitted by its `client_id` alone, so anyone can push as it: it may push 60 a minute
per address, and nothing it pushes is held by Quisora, so no one can use up another client's or organization's share.

## Requiring it

**Require pushed authorization requests** on the client (`require_pushed_authorization_requests`) refuses its
authorization requests made any other way (`invalid_request`, sent back to the application). The FAPI 2.0 profile
turns it on.

## With DPoP

A [DPoP](dpop.md) proof sent with the push (header `DPoP`, for `POST` and the PAR endpoint's URL) binds the code to
that key, as `dpop_jkt` would: the code is then exchanged only with a proof made with the same key. Proofs at the PAR
endpoint need a nonce from this server, like those at the token endpoint.

Request objects (JAR, signed `request` parameters) are not supported, pushed or not.
