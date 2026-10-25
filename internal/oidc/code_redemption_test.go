package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/paularlott/quisora/internal/model"
)

// A code presented again while its first redemption is still making the grant (the replay found no grant yet to end)
// leaves a mark the first redemption finds: the grant it made is revoked and nothing is issued (RFC 6749 §4.1.2).
func TestCodeReplayDuringRedemptionRevokes(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	_ = h.p.s.Eph.Set(context.Background(), nsReplayed, code, []byte{1}, usedTTL) // the racing replay's mark
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}, cl, secret)
	if r.status != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("a redemption a replay raced: %d %v", r.status, r.m)
	}
	if ev := h.auditEvents("oauth.code.replay"); len(ev) != 1 || ev[0].Detail["grant_revoked"] != "true" {
		t.Fatalf("not revoked: %+v", ev)
	}
}

// A redemption that fails on our side (a store that cannot be read: 503) does not spend the code: the client's retry
// works.
func TestCodeKeptWhenRedemptionFails(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}
	users := h.env.Svc.Users.S
	h.env.Svc.Users.S = failReads{Store: users, kind: model.KindUser}
	h.p.users.clear()
	if r := h.token(form, cl, secret); r.status != 503 {
		t.Fatalf("with the user unreadable: %d %v", r.status, r.m)
	}
	h.env.Svc.Users.S = users
	h.p.users.clear()
	if r := h.token(form, cl, secret); r.status != 200 {
		t.Fatalf("the retry: %d %v", r.status, r.m)
	}
	if r := h.token(form, cl, secret); r.status != 400 {
		t.Fatalf("a third use: %d", r.status)
	}
}

// An approved device sign-in whose tokens cannot be made on our side (503) stays approved: the next poll gets them,
// and the user does not have to approve again.
func TestDeviceApprovalKeptWhenIssueFails(t *testing.T) {
	h := setup(t, nil)
	cl := h.deviceClient(nil)
	deviceCode, userCode := h.startDevice(cl, "openid")
	b, csrf := h.session(h.user)
	if status, _ := h.consentDevice(b, csrf, userCode, true); status != 200 {
		t.Fatalf("approve: %d", status)
	}
	users := h.env.Svc.Users.S
	h.env.Svc.Users.S = failReads{Store: users, kind: model.KindUser}
	h.p.users.clear()
	if r := h.pollDevice(cl, deviceCode); r.status != 503 {
		t.Fatalf("with the user unreadable: %d %v", r.status, r.m)
	}
	h.env.Svc.Users.S = users
	h.p.users.clear()
	if r := h.pollDevice(cl, deviceCode); r.status != 200 || r.str("access_token") == "" {
		t.Fatalf("the next poll: %d %v", r.status, r.m)
	}
}

func TestFormActionSource(t *testing.T) {
	for raw, want := range map[string]string{
		"https://app.example.com:8443/cb":     "https://app.example.com:8443",
		"com.example.app:/cb":                 "com.example.app:",
		"https://evil.example;script-src*/cb": "",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			continue // a host url.Parse refuses never gets this far
		}
		got, ok := formActionSource(u)
		if got != want || ok != (want != "") {
			t.Errorf("%s: %q %v, want %q", raw, got, ok, want)
		}
	}
	if _, ok := formActionSource(&url.URL{Scheme: "https", Host: "evil.example; script-src *"}); ok {
		t.Error("a host with a separator made a source")
	}
}
