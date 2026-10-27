package oidc

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/service"
)

// The OAuth side of the audit trail: a user's consent, every grant a code exchange makes, a code presented twice,
// refresh token reuse, revocation, and (with audit.tokens) every refresh; each with the request's id.
func TestOAuthAuditEvents(t *testing.T) {
	t.Parallel()
	h := setup(t, func(c *config.Config) { c.Audit.Tokens = true })

	// consent, by the signed-in user
	third, _ := h.newClient(func(in *service.ClientInput) { in.FirstParty = ptr(false); in.Name = ptr("Third Party") })
	c, csrf := h.session(h.user)
	_, ch := pkce()
	u := h.authorize(c, authzQuery(third, ch, nil))
	b, _ := json.Marshal(map[string]any{"flow": u.Query().Get("flow"), "approve": true})
	req, _ := http.NewRequest("POST", h.env.URL+orgBase+"/api-internal/oauth/consent", strings.NewReader(string(b)))
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Content-Type", "application/json")
	if r, err := c.Do(req); err != nil || r.StatusCode != 200 {
		t.Fatalf("consent: %v", err)
	} else if r.Header.Get("X-Request-ID") == "" {
		t.Fatal("no X-Request-ID")
	}
	ev := h.auditEvents("oauth.consent")
	if len(ev) != 1 || ev[0].Detail["decision"] != "allow" || ev[0].Detail["client_id"] != third.ID ||
		ev[0].ActorID != h.user.ID || ev[0].RequestID == "" || ev[0].SessionID == "" || ev[0].UserAgent == "" {
		t.Fatalf("oauth.consent: %+v", ev)
	}

	// a grant, a refresh (audit.tokens) and a revocation
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid profile offline_access"}})
	if ev := h.auditEvents("oauth.grant"); len(ev) != 1 || ev[0].Target != "alice" || ev[0].Detail["client_id"] != cl.ID ||
		ev[0].Outcome != "success" {
		t.Fatalf("oauth.grant: %+v", ev)
	}
	rt := r.str("refresh_token")
	if r := h.refreshWith(cl, secret, rt); r.status != 200 {
		t.Fatalf("refresh: %d", r.status)
	}
	if ev := h.auditEvents("oauth.refresh"); len(ev) != 1 {
		t.Fatalf("oauth.refresh: %+v", ev)
	}
	if r := h.clientPost(orgBase+"/oauth/revoke", url.Values{"token": {rt}}, cl, secret); r.status != 200 {
		t.Fatalf("revoke: %d", r.status)
	}
	if ev := h.auditEvents("oauth.revoke"); len(ev) != 1 || ev[0].Detail["token"] != "refresh" {
		t.Fatalf("oauth.revoke: %+v", ev)
	}

	// a code presented twice: the grant goes, and it is recorded as a failure
	c2, _ := h.session(h.user)
	v, ch2 := pkce()
	code := h.getCode(c2, cl, ch2, nil)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}
	if r := h.token(form, cl, secret); r.status != 200 {
		t.Fatalf("exchange: %d", r.status)
	}
	if r := h.token(form, cl, secret); r.status != 400 {
		t.Fatalf("replay: %d", r.status)
	}
	if ev := h.auditEvents("oauth.code.replay"); len(ev) != 1 || ev[0].Outcome != "failure" || ev[0].Detail["grant_revoked"] != "true" {
		t.Fatalf("oauth.code.replay: %+v", ev)
	}

	// signing keys made by the server are on record
	if len(h.auditEvents("keys.create")) == 0 {
		t.Fatal("no keys.create event")
	}
}

// A rotated-out refresh token presented again revokes the grant and is recorded as a failure (here one two
// rotations old: the one just before the current is a retry within refreshRetryGrace).
func TestRefreshReuseIsAudited(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid profile offline_access"}})
	old := r.str("refresh_token")
	r1 := h.refreshWith(cl, secret, old)
	if r1.status != 200 {
		t.Fatalf("refresh: %d", r1.status)
	}
	if r := h.refreshWith(cl, secret, r1.str("refresh_token")); r.status != 200 {
		t.Fatalf("second refresh: %d", r.status)
	}
	if r := h.refreshWith(cl, secret, old); r.status != 400 {
		t.Fatalf("reuse: %d", r.status)
	}
	if ev := h.auditEvents("oauth.refresh.reuse"); len(ev) != 1 || ev[0].Outcome != "failure" || ev[0].Target != "alice" {
		t.Fatalf("oauth.refresh.reuse: %+v", ev)
	}
	if len(h.auditEvents("oauth.refresh")) != 0 {
		t.Fatal("refreshes audited without audit.tokens")
	}
}
