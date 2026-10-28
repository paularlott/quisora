package oidc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/web"
)

// Pushed authorization requests (RFC 9126). The client posts the parameters of an authorization request to
// /o/<org>/oauth/par, authenticated the way it authenticates at the token endpoint, and gets back a single-use
// request_uri; it then sends the browser to /o/<org>/oauth/authorize with only client_id and that request_uri. The
// parameters never pass through the browser, and they are checked (the same way the authorization endpoint checks them) before the user is
// involved. A client with RequirePAR may start sign-ins no other way.
//
// The request_uri is the request itself, sealed with the server's key (encrypted and authenticated, bound to the
// organization and the client it was pushed for, with its expiry and a unique id inside), so a push stores nothing.
// That is what keeps a public client's pushes harmless: it is admitted by its client_id alone, anyone can push as it
// from as many addresses as they have, and anything a push held until it was used (in memory, for the node's
// shared budget) would let an anonymous party fill that budget or use up what the organization's public clients may
// push. Only a sign-in that decides its request records anything, and only the id.
//
// A request_uri must be visited within parTTL, by any number of flows (a browser that reloads the page carries on).
// It is used up when a request from it is decided (a code is issued, or the user denies or cancels): the id is then
// recorded as used (service.UseOnce, held for every node) until no flow of it can still decide, and presenting the
// request_uri again sends invalid_request_uri back to the client (RFC 9126 §7.3). A sign-in that was started goes on
// for as long as a sign-in flow does, whatever became of the request_uri meanwhile: the flow holds the request.
const (
	parURNPrefix = "urn:ietf:params:oauth:request_uri:"
	parTTL       = 60 * time.Second
	// parMaxParams is the largest authorization request (form-encoded) that may be pushed. The request_uri carries it
	// sealed and encoded twice for a URL (about 1.8 times its size, plus 200 bytes), and goes in a URL the browser
	// sends: a request of this size makes a request_uri of 7,501 bytes and an authorization URL of 7.6 KB, under the
	// 8 KiB request line nginx allows by default (a longer one is a 414 at the proxy, an error page with no way back
	// to the client). A real request is about 1 KiB.
	parMaxParams = 4 << 10
)

// Pushes are counted after the client has authenticated (which has failure limits of its own), before anything is
// checked or recorded (a DPoP proof is a replicated write). A confidential client is known and only pushes for its
// users, so it is counted alone, and a busy backend is not capped by anyone else's pushes or by its own address. A public
// client is counted by address: its own budget, which no one else's pushes can use up, bounds the proofs one
// address may have recorded. There is no limit per organization: nothing a push holds is shared.
const (
	parPerClientMin   = 1800
	parPublicPerIPMin = 60
)

// pushedRequest is what a request_uri holds, sealed (parBinding): the organization and client it is for are the
// binding, not part of it.
type pushedRequest struct {
	ID      string `json:"j"` // names the request_uri to the record of its use (usePushed)
	Expires int64  `json:"e"` // unix seconds: the last moment it may be visited
	Params  string `json:"q"` // the authorization request's parameters, form-encoded
}

var errPushed = errors.New("oidc: unknown, used or expired request_uri")

// clientAuthParams are the form fields of client authentication: not part of the authorization request.
var clientAuthParams = []string{"client_secret", "client_assertion", "client_assertion_type"}

// parBinding binds a sealed request to the organization and client it was pushed for: opened for any other, it fails,
// so no other client (or organization) can use it, with no check of ours that could be forgotten.
func parBinding(orgID, clientID string) string { return "oidc/par|" + orgID + "|" + clientID }

func (p *Provider) handlePAR(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	p.corsActual(w, r)
	p.setDPoPNonce(w)
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, oerr("invalid_request", "the request body could not be read"))
		return
	}
	form := r.PostForm
	if dup := repeated(form); dup != "" {
		writeOAuthError(w, oerr("invalid_request", dup+" is repeated"))
		return
	}
	ce, e := p.authenticateClient(r, true)
	if e != nil {
		writeOAuthError(w, e)
		return
	}
	p.corsRestrict(w, r, ce.c.ClientID())
	c := ce.c
	key, limit := "par|"+c.ID, int64(parPerClientMin)
	if c.Public() {
		key, limit = "par-ip|"+web.RateKeyIP(r), parPublicPerIPMin
	}
	n, err := p.s.Eph.Incr(r.Context(), nsRateOIDC, key, 1, time.Minute)
	if err != nil {
		writeOAuthError(w, serverError(unavailable(err)))
		return
	}
	if n > limit {
		writeOAuthError(w, &oauthError{status: http.StatusTooManyRequests, code: "temporarily_unavailable",
			desc: "too many pushed authorization requests; try again in a minute", retry: true})
		return
	}
	if form.Get("request_uri") != "" {
		writeOAuthError(w, oerr("invalid_request", "request_uri cannot be pushed"))
		return
	}
	// A DPoP proof here binds the code to its key, as dpop_jkt does (RFC 9449 §10.1).
	jkt, e := p.checkProof(r, "", true, c.FAPI)
	if e != nil {
		writeOAuthError(w, e)
		return
	}
	if jkt != "" {
		if v := form.Get("dpop_jkt"); v != "" && v != jkt {
			writeOAuthError(w, dpopErr("dpop_jkt is not the thumbprint of the DPoP proof's key"))
			return
		}
		form.Set("dpop_jkt", jkt)
	}
	if !redirectMatches(c.RedirectURIs, form.Get("redirect_uri")) {
		writeOAuthError(w, oerr("invalid_request", "redirect_uri is not registered for this client"))
		return
	}
	if len(form.Get("state")) > 2048 {
		writeOAuthError(w, oerr("invalid_request", "state is too long"))
		return
	}
	if _, e := p.checkAuthz(r.Context(), form, c, &flow{MaxAge: -1, Mode: "query"}); e != nil {
		writeOAuthError(w, e)
		return
	}
	params := url.Values{}
	for k, v := range form {
		if !slices.Contains(clientAuthParams, k) {
			params[k] = v
		}
	}
	params.Set("client_id", c.ClientID()) // a client using Basic authentication need not repeat it in the body
	enc := params.Encode()
	if len(enc) > parMaxParams {
		writeOAuthError(w, oerr("invalid_request", "the authorization request is too large"))
		return
	}
	// (Without HTML escaping, which would write every "&" of the parameters as six characters and take the request_uri past
	// the size parMaxParams is chosen for.)
	var b bytes.Buffer
	je := json.NewEncoder(&b)
	je.SetEscapeHTML(false)
	_ = je.Encode(pushedRequest{ID: model.NewID(), Expires: time.Now().Add(parTTL).Unix(), Params: enc})
	sealed := p.svc.Sealer.SealFor(parBinding(c.OrgID, c.ClientID()), b.Bytes())
	o := newObj(128)
	o.str("request_uri", parURNPrefix+base64.RawURLEncoding.EncodeToString([]byte(sealed)))
	o.num("expires_in", int64(parTTL/time.Second))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(o.bytes())
}

// loadPushed returns the parameters pushed as uri to organization orgID by clientID (only that client may use it, and
// only there), its id, and whether a request from it was already decided. errPushed is a request_uri that is not one
// of ours for that client, or has expired; any other error is a store that could not tell.
func (p *Provider) loadPushed(ctx context.Context, orgID, clientID, uri string) (q url.Values, id string, used bool, err error) {
	sealed, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(uri, parURNPrefix))
	if clientID == "" || err != nil {
		return nil, "", false, errPushed
	}
	raw, err := p.svc.Sealer.OpenFor(parBinding(orgID, clientID), string(sealed))
	var pr pushedRequest
	if err != nil || json.Unmarshal(raw, &pr) != nil || pr.ID == "" || time.Now().Unix() > pr.Expires {
		return nil, "", false, errPushed
	}
	if q, err = url.ParseQuery(pr.Params); err != nil {
		return nil, "", false, errPushed
	}
	if used, err = p.svc.Used(ctx, parUseKey(pr.ID)); err != nil {
		return nil, "", false, unavailable(err)
	}
	return q, pr.ID, used, nil
}

// parUseKey is the single-use value that records the request_uri with id as decided.
func parUseKey(id string) string { return "par|" + id }

// usePushed marks the pushed request id as decided. It reports false when it was already used, or when that cannot be
// told (a request that must not be answered with a code is refused, never let through): the request that called it
// must not issue a code. The record is kept as long as a flow of the request_uri may still be decided: one started at the
// request_uri's last moment (parTTL after the push) lasts flowTTL, and this is called after the push.
func (p *Provider) usePushed(ctx context.Context, id string) bool {
	first, err := p.svc.UseOnce(ctx, parUseKey(id), time.Now().Add(parTTL+flowTTL))
	return err == nil && first
}
