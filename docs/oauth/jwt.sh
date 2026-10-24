# Helpers for the curl examples in docs/oauth: Ed25519 keys and EdDSA-signed JWTs, made with OpenSSL 3 and jq.
# Load them into your shell with:  source docs/oauth/jwt.sh
#
# They are for trying things out. A real application uses its OAuth library, and keeps its private key in a secret
# store rather than in a file next to the shell history.

# b64url: base64url without padding (RFC 7515), of standard input.
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# new_key FILE: a new Ed25519 private key in FILE.
new_key() { openssl genpkey -algorithm ed25519 -out "$1"; }

# jwk FILE [KID]: the public JWK of the key in FILE (with a key id, when given).
jwk() {
  local x
  x=$(openssl pkey -in "$1" -pubout -outform DER | tail -c 32 | b64url)
  if [ -n "$2" ]; then
    printf '{"kty":"OKP","crv":"Ed25519","x":"%s","kid":"%s"}' "$x" "$2"
  else
    printf '{"kty":"OKP","crv":"Ed25519","x":"%s"}' "$x"
  fi
}

# jwk_thumbprint FILE: the key's JWK thumbprint (RFC 7638), what DPoP calls its jkt.
jwk_thumbprint() { jwk "$1" | jq -cS '{crv, kty, x}' | tr -d '\n' | openssl dgst -sha256 -binary | b64url; }

# jwt FILE HEADER CLAIMS: a compact JWT of the JSON CLAIMS, with the JSON HEADER, signed with the key in FILE.
jwt() {
  local h p s in
  h=$(printf '%s' "$2" | b64url)
  p=$(printf '%s' "$3" | b64url)
  in=$(mktemp) # Ed25519 signs its whole input at once: OpenSSL reads it from a file, not a pipe
  printf '%s.%s' "$h" "$p" >"$in"
  s=$(openssl pkeyutl -sign -inkey "$1" -rawin -in "$in" | b64url)
  rm -f "$in"
  printf '%s.%s.%s' "$h" "$p" "$s"
}

# client_assertion FILE CLIENT_ID AUDIENCE: a private_key_jwt client assertion (RFC 7523), valid for one minute.
client_assertion() {
  local now
  now=$(date +%s)
  jwt "$1" '{"alg":"EdDSA","typ":"JWT"}' \
    "$(jq -nc --arg c "$2" --arg a "$3" --argjson now "$now" --arg j "$(openssl rand -hex 16)" \
      '{iss: $c, sub: $c, aud: $a, jti: $j, iat: $now, exp: ($now + 60)}')"
}

# dpop_proof FILE METHOD URL [NONCE] [ACCESS_TOKEN]: a DPoP proof (RFC 9449) for one request. Give the server's
# DPoP-Nonce when it asked for one, and the access token when the proof goes with it to an API (ath).
dpop_proof() {
  local claims
  claims=$(jq -nc --arg m "$2" --arg u "$3" --argjson now "$(date +%s)" --arg j "$(openssl rand -hex 16)" \
    '{jti: $j, htm: $m, htu: $u, iat: $now}')
  [ -n "$4" ] && claims=$(jq -c --arg n "$4" '. + {nonce: $n}' <<<"$claims")
  [ -n "$5" ] && claims=$(jq -c --arg a "$(printf '%s' "$5" | openssl dgst -sha256 -binary | b64url)" '. + {ath: $a}' <<<"$claims")
  jwt "$1" "$(jq -nc --argjson k "$(jwk "$1")" '{typ: "dpop+jwt", alg: "EdDSA", jwk: $k}')" "$claims"
}

# jwt_claims TOKEN: the claims of a JWT, to read (not verified).
jwt_claims() { cut -d. -f2 <<<"$1" | tr '_-' '/+' | awk '{ while (length($0) % 4) $0 = $0 "="; print }' | openssl base64 -d -A | jq .; }
