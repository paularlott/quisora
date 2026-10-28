package oidc

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// DPoP: sender-constrained tokens (RFC 9449). A client sends a DPoP proof, a JWT signed with a key of its own whose
// public half is in the proof's header, in the DPoP header of a token request; the access token it gets is bound to
// that key (cnf.jkt, the key's RFC 7638 thumbprint, token_type DPoP) and is only accepted with a fresh proof made
// with the same key for that request (the "DPoP" authorization scheme). A stolen token is useless without the key.
//
// Proofs at the token and PAR endpoints must carry a nonce this server issued (DPoP-Nonce header, use_dpop_nonce
// error), so a proof cannot be made ahead of time; at resource endpoints a nonce is checked when present. Nonces are
// stateless: a time step and its MAC under the master key, valid on every node for two to three steps. Every proof
// is used once (its jti is remembered for as long as its iat is accepted).
//
// Refresh tokens of public clients are bound to the key of the first proof (RFC 9449 §5); a confidential client's
// are bound to its client authentication as before. A client with DPoPBound (dpop_bound_access_tokens) must send a
// proof with every token request. An authorization request may name the key in advance (dpop_jkt, §10): the code is
// then only redeemed with a proof of that key.
const (
	dpopTyp        = "dpop+jwt"
	dpopMaxAge     = 5 * time.Minute // how old a proof's iat may be
	dpopNonceStep  = time.Minute
	dpopNonceSteps = 3
	maxDPoPProof   = 8 << 10
)

// dpopAlgs are the proof algorithms accepted (discovery's dpop_signing_alg_values_supported).
var dpopAlgs = allAlgs

// ErrDPoPProof is returned by VerifyRequestToken when the request's DPoP proof is missing, invalid or does not match
// the token: the caller answers with a DPoP challenge carrying error="invalid_dpop_proof".
var ErrDPoPProof = errors.New("oidc: invalid DPoP proof")

func dpopErr(desc string) *oauthError { return oerr("invalid_dpop_proof", desc) }

// privateJWKMembers are members only a private (or symmetric) JWK has.
var privateJWKMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// checkProof checks the request's DPoP proof for its method and URL, bound to accessToken when that is not empty
// (ath), and returns the thumbprint of its key; "" and nil when the request carries no proof. needNonce asks for a
// nonce of this server; fapi refuses RS256 proofs (FAPI 2.0 §5.4.1).
func (p *Provider) checkProof(r *http.Request, accessToken string, needNonce, fapi bool) (string, *oauthError) {
	vals := r.Header.Values("DPoP")
	if len(vals) == 0 {
		return "", nil
	}
	if len(vals) > 1 {
		return "", dpopErr("send exactly one DPoP proof")
	}
	proof := vals[0]
	if len(proof) > maxDPoPProof {
		return "", dpopErr("the DPoP proof is too large")
	}
	pj, err := ParseJWT(proof)
	if err != nil {
		return "", dpopErr("the DPoP proof is not a signed JWT with a supported algorithm")
	}
	if pj.Header.Typ != dpopTyp {
		return "", dpopErr("the DPoP proof's typ must be " + dpopTyp)
	}
	if fapi && pj.Header.Alg == AlgRS256 {
		return "", dpopErr("FAPI 2.0 does not allow RS256 DPoP proofs")
	}
	pub, err := proofKey(proof[:strings.IndexByte(proof, '.')])
	if err != nil {
		return "", dpopErr(err.Error())
	}
	jwk, _ := EncodeJWK(pub, "", "")
	if pj.Verify(pub) != nil { // (which also requires the key type of the header's alg)
		return "", dpopErr("the DPoP proof's signature does not verify with its jwk")
	}
	var cl struct {
		Jti   string      `json:"jti"`
		Htm   string      `json:"htm"`
		Htu   string      `json:"htu"`
		Iat   NumericDate `json:"iat"`
		Ath   string      `json:"ath"`
		Nonce string      `json:"nonce"`
	}
	if json.Unmarshal(pj.Payload, &cl) != nil {
		return "", dpopErr("the DPoP proof's claims could not be read")
	}
	now := time.Now()
	switch iat := time.Unix(int64(cl.Iat), 0); {
	case cl.Jti == "" || len(cl.Jti) > 256:
		return "", dpopErr("the DPoP proof needs a jti")
	case cl.Htm != r.Method:
		return "", dpopErr("the DPoP proof's htm is not this request's method")
	case !sameHTU(cl.Htu, p.requestURL(r)):
		return "", dpopErr("the DPoP proof's htu is not this endpoint")
	case cl.Iat == 0 || iat.After(now.Add(leeway)) || iat.Before(now.Add(-dpopMaxAge-leeway)):
		return "", dpopErr("the DPoP proof's iat is too old or in the future")
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if !hmac.Equal([]byte(cl.Ath), []byte(b64.EncodeToString(sum[:]))) {
			return "", dpopErr("the DPoP proof's ath is not the hash of the access token")
		}
	}
	if (cl.Nonce != "" || needNonce) && !p.validNonce(cl.Nonce, now) {
		return "", &oauthError{status: http.StatusBadRequest, code: "use_dpop_nonce",
			desc: "use the nonce in the DPoP-Nonce header", nonce: p.dpopNonce(now)}
	}
	jkt := thumbprint(jwk)
	first, err := p.svc.UseOnce(r.Context(), "dpop|"+jkt+"|"+cl.Jti, now.Add(dpopMaxAge+2*leeway))
	if err != nil {
		// The proof could not be recorded, so it cannot be told from a replay: not "invalid", but "not now".
		err = unavailable(err)
		e := serverError(err)
		e.cause = err
		return "", e
	}
	if !first {
		return "", dpopErr("the DPoP proof was already used")
	}
	return jkt, nil
}

// proofKey decodes the public key in a proof's JOSE header (its encoded form, hdr).
func proofKey(hdr string) (crypto.PublicKey, error) {
	hb, err := b64strict.DecodeString(hdr)
	if err != nil {
		return nil, errors.New("the DPoP proof's header could not be read")
	}
	var h struct {
		JWK map[string]json.RawMessage `json:"jwk"`
	}
	if json.Unmarshal(hb, &h) != nil || h.JWK == nil {
		return nil, errors.New("the DPoP proof needs a jwk header")
	}
	for _, k := range privateJWKMembers {
		if _, ok := h.JWK[k]; ok {
			return nil, errors.New("the DPoP proof's jwk must be a public key")
		}
	}
	raw, _ := json.Marshal(h.JWK)
	var j JWK
	if json.Unmarshal(raw, &j) != nil {
		return nil, errors.New("the DPoP proof's jwk could not be read")
	}
	pub, err := j.PublicKey()
	if err != nil {
		return nil, errors.New("the DPoP proof's jwk is not a supported public key")
	}
	return pub, nil
}

// thumbprint is the RFC 7638 SHA-256 thumbprint of a public JWK (as EncodeJWK makes it): the required members in
// lexicographic order, no whitespace.
func thumbprint(j JWK) string {
	o := newObj(160)
	switch j.Kty {
	case "EC", "OKP":
		o.str("crv", j.Crv)
		o.str("kty", j.Kty)
		o.str("x", j.X)
		if j.Kty == "EC" {
			o.str("y", j.Y)
		}
	case "RSA":
		o.str("e", j.E)
		o.str("kty", j.Kty)
		o.str("n", j.N)
	}
	sum := sha256.Sum256(o.bytes())
	return b64.EncodeToString(sum[:])
}

// sameHTU compares a proof's htu with the endpoint's URL, ignoring query and fragment (RFC 9449 §4.3), the case of
// scheme and host, and default ports.
func sameHTU(htu, want string) bool {
	a, err1 := url.Parse(htu)
	b, err2 := url.Parse(want)
	if err1 != nil || err2 != nil || a.Host == "" {
		return false
	}
	norm := func(u *url.URL) string {
		s, h := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname())
		if port := u.Port(); port != "" && !(s == "https" && port == "443" || s == "http" && port == "80") {
			h += ":" + port
		}
		path := u.EscapedPath()
		if path == "" {
			path = "/"
		}
		return s + "://" + h + path
	}
	return norm(a) == norm(b)
}

// dpopNonce is the nonce for the current time step.
func (p *Provider) dpopNonce(now time.Time) string {
	step := strconv.FormatInt(now.Unix()/int64(dpopNonceStep/time.Second), 10)
	return step + "." + b64.EncodeToString(p.svc.Sealer.MAC("dpop-nonce", step)[:16])
}

// validNonce reports whether n is a nonce of one of the last dpopNonceSteps steps (under any configured master key).
func (p *Provider) validNonce(n string, now time.Time) bool {
	s, mac, ok := strings.Cut(n, ".")
	step, err := strconv.ParseInt(s, 10, 64)
	cur := now.Unix() / int64(dpopNonceStep/time.Second)
	if !ok || err != nil || step > cur || cur-step >= dpopNonceSteps || strconv.FormatInt(step, 10) != s {
		return false
	}
	m, err := b64strict.DecodeString(mac)
	if err != nil {
		return false
	}
	for _, k := range p.svc.Sealer.MACs("dpop-nonce", s) {
		if hmac.Equal(k[:16], m) {
			return true
		}
	}
	return false
}

// setDPoPNonce gives the client the current nonce for its next proof.
func (p *Provider) setDPoPNonce(w http.ResponseWriter) {
	w.Header().Set("DPoP-Nonce", p.dpopNonce(time.Now()))
}

// VerifyRequestToken is verifyAccessToken for a token presented with the given authorization scheme ("Bearer" or
// "DPoP") in request r: a DPoP-bound token is accepted only with the DPoP scheme and a proof of its key for this
// request, and the DPoP scheme only with a bound token. A failed proof is ErrDPoPProof; one that could not be checked
// (the replay store failed) is an error for which service.IsUnavailable is true. A request to an organization's
// endpoint (web.Org) takes that organization's tokens only.
func (p *Provider) VerifyRequestToken(r *http.Request, scheme, tok string) (*Claims, error) {
	var cl *Claims
	var err error
	if org := web.Org(r); org != nil {
		cl, err = p.verifyIn(r.Context(), org.ID, tok)
	} else {
		cl, err = p.verifyAccessToken(r.Context(), tok)
	}
	if err != nil {
		return nil, err
	}
	dpop := strings.EqualFold(scheme, "DPoP")
	switch {
	case cl.Cnf == nil || cl.Cnf.JKT == "":
		if dpop {
			return nil, badToken("the DPoP scheme needs a DPoP-bound token")
		}
		return cl, nil
	case !dpop:
		return nil, badToken("a DPoP-bound token was presented as a bearer token")
	}
	fapi := false
	orgID, _ := p.issuerOrg(cl.Iss) // verified: the token's issuer is an organization's
	if ce, err := p.client(r.Context(), orgID, cl.ClientID); err == nil {
		fapi = ce.c.FAPI
	}
	jkt, e := p.checkProof(r, tok, false, fapi)
	if e != nil && service.IsUnavailable(e) {
		return nil, e // the proof could not be checked: not refused, and the caller answers "not now"
	}
	if e != nil || jkt == "" {
		return nil, ErrDPoPProof
	}
	if jkt != cl.Cnf.JKT {
		return nil, ErrDPoPProof
	}
	return cl, nil
}

// dpopChallenge answers a resource request whose token or proof failed with a DPoP challenge.
func (p *Provider) dpopChallenge(w http.ResponseWriter, status int, code string) {
	setNoStore(w)
	h := `DPoP algs="` + strings.Join(dpopAlgs, " ") + `"`
	if code != "" {
		h += `, error="` + code + `"`
	}
	w.Header().Set("WWW-Authenticate", h)
	p.setDPoPNonce(w)
	w.WriteHeader(status)
}

// tokenProof checks the DPoP proof of a token request from client c: required when the client is DPoP-bound, always
// with a nonce.
func (p *Provider) tokenProof(r *http.Request, c *model.Client) (string, *oauthError) {
	jkt, e := p.checkProof(r, "", true, c.FAPI)
	if e != nil {
		return "", e
	}
	if jkt == "" && c.DPoPBound {
		return "", dpopErr("this client must send a DPoP proof (dpop_bound_access_tokens)")
	}
	return jkt, nil
}

// validJKT reports whether s looks like a SHA-256 JWK thumbprint (dpop_jkt).
func validJKT(s string) bool { return len(s) == 43 && validChallenge(s) }
