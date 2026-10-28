package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/web"
)

// Pushed authorization requests (RFC 9126). The client posts the parameters of an authorization request to
// /o/<org>/oauth/par, authenticated the way it authenticates at the token endpoint, and gets back a single-use
// request_uri; it then sends the browser to /o/<org>/oauth/authorize with only client_id and that request_uri. The
// parameters never pass through the browser, and they are checked (the same way the authorization endpoint checks them) before the user is
// involved. A client with RequirePAR may start sign-ins no other way.
//
// A request_uri must first be used within parTTL. It is used up when the request is decided (a code is issued, or
// the user denies or cancels), not on the first visit (FAPI 2.0 §5.3.2.2 note 3): a browser that reloads the page, or
// comes back from signing in, carries on. Once used, it is kept as used until the request would have expired, and
// presenting it again sends invalid_request_uri back to the client (RFC 9126 §7.3).
const (
	nsPAR        = "oauth.par"
	parURNPrefix = "urn:ietf:params:oauth:request_uri:"
	parTTL       = 60 * time.Second
	parMaxParams = 16 << 10 // the largest authorization request a push may keep (form-encoded)
)

// pushedRequest is a pushed authorization request waiting for the browser (ephemeral, ns "oauth.par", single use).
type pushedRequest struct {
	Org      string `json:"o"`           // the organization it was pushed to: only it takes the browser's visit
	ClientID string `json:"c"`           // as the client sent it (model.Client.ClientID)
	Params   string `json:"q"`           // the authorization request's parameters, form-encoded
	Started  bool   `json:"s,omitempty"` // visited: it lasts as long as a sign-in flow from then on
	Used     bool   `json:"u,omitempty"` // decided: presenting it again is an error
}

var errPushed = errors.New("oidc: unknown, used or expired request_uri")

// clientAuthParams are the form fields of client authentication: not part of the authorization request.
var clientAuthParams = []string{"client_secret", "client_assertion", "client_assertion_type"}

func (p *Provider) handlePAR(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	p.corsActual(w, r)
	p.setDPoPNonce(w)
	// Counted first, as authorization requests are (authorizePerIPMin, a budget of its own): a public client pushes
	// with its client_id alone, and each push holds up to parMaxParams of the request for parTTL and may record a
	// DPoP proof (a replicated write).
	n, err := p.s.Eph.Incr(r.Context(), nsRateOIDC, "par|"+web.RateKeyIP(r), 1, time.Minute)
	if err != nil {
		writeOAuthError(w, serverError(unavailable(err)))
		return
	}
	if n > authorizePerIPMin {
		writeOAuthError(w, &oauthError{status: http.StatusTooManyRequests, code: "temporarily_unavailable",
			desc: "too many pushed authorization requests from this address; try again in a minute", retry: true})
		return
	}
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
	if len(enc) > parMaxParams { // kept in memory until used: a real request is a fraction of this
		writeOAuthError(w, oerr("invalid_request", "the authorization request is too large"))
		return
	}
	b, _ := json.Marshal(pushedRequest{Org: c.OrgID, ClientID: c.ClientID(), Params: enc})
	id, err := p.s.Eph.New(r.Context(), nsPAR, b, parTTL)
	if errors.Is(err, ephemeral.ErrFull) {
		writeOAuthError(w, &oauthError{status: http.StatusServiceUnavailable, code: "temporarily_unavailable",
			desc: "the server is busy; try again shortly", retry: true})
		return
	}
	if err != nil {
		writeOAuthError(w, serverError(err))
		return
	}
	o := newObj(128)
	o.str("request_uri", parURNPrefix+id)
	o.num("expires_in", int64(parTTL/time.Second))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(o.bytes())
}

// loadPushed returns the parameters pushed as uri to organization orgID by clientID (only that client may use it, and
// only there), its id, and whether it was already used. Its first visit makes it last as long as the sign-in flow it
// starts.
func (p *Provider) loadPushed(ctx context.Context, orgID, clientID, uri string) (q url.Values, id string, used bool, err error) {
	id = strings.TrimPrefix(uri, parURNPrefix)
	if clientID == "" || id == "" || len(id) > 200 {
		return nil, "", false, errPushed
	}
	raw, err := p.s.Eph.Get(ctx, nsPAR, id)
	if err != nil {
		return nil, "", false, errPushed
	}
	var pr pushedRequest
	if json.Unmarshal(raw, &pr) != nil || pr.Org != orgID || pr.ClientID != clientID {
		return nil, "", false, errPushed
	}
	if q, err = url.ParseQuery(pr.Params); err != nil {
		return nil, "", false, errPushed
	}
	if !pr.Started && !pr.Used {
		pr.Used = p.startPushed(ctx, id)
	}
	return q, id, pr.Used, nil
}

// startPushed marks the pushed request id as started (lasting flowTTL) and reports whether it was used meanwhile.
// It takes the current value rather than writing over the copy read before: a flow of the same request_uri that
// completed in between (usePushed) must stay used. While it is taken a concurrent visit or completion is refused.
func (p *Provider) startPushed(ctx context.Context, id string) bool {
	raw, err := p.s.Eph.Take(ctx, nsPAR, id)
	if err != nil {
		return true // gone (taken by a concurrent flow): treat as used
	}
	var pr pushedRequest
	if json.Unmarshal(raw, &pr) != nil {
		return true
	}
	if !pr.Used {
		pr.Started = true
		raw, _ = json.Marshal(pr)
	}
	_ = p.s.Eph.Set(ctx, nsPAR, id, raw, flowTTL)
	return pr.Used
}

// usePushed marks the pushed request id as decided. It reports false when it was already used (or is gone): the
// request that called it must not issue a code. Take makes it atomic between concurrent flows of one request_uri.
func (p *Provider) usePushed(ctx context.Context, id string) bool {
	raw, err := p.s.Eph.Take(ctx, nsPAR, id)
	if err != nil {
		return false
	}
	var pr pushedRequest
	if json.Unmarshal(raw, &pr) != nil || pr.Used {
		return false
	}
	pr.Used = true
	b, _ := json.Marshal(pr)
	_ = p.s.Eph.Set(ctx, nsPAR, id, b, flowTTL)
	return true
}
