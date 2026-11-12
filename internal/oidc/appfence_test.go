package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/paularlott/quisora/internal/model"
)

// Removing an application's access ends what the user approved for it and had not yet turned into a grant: an
// authorization code not yet redeemed makes none. An approval after the removal works, and another application's
// code in the same session is untouched.
func TestRemovedAccessEndsAPendingCode(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, sec := h.newClient(nil)
	other, osec := h.newClient(nil)
	c, _ := h.session(h.user)
	scope := url.Values{"scope": {"openid offline_access"}}
	v, ch := pkce()
	code := h.getCode(c, cl, ch, scope)
	ov, och := pkce()
	otherCode := h.getCode(c, other, och, scope)

	h.removeAccess(cl)
	tokenErr(t, h.exchangeCode(cl, sec, code, v), 400, "invalid_grant")
	if r := h.exchangeCode(other, osec, otherCode, ov); r.status != 200 {
		t.Fatalf("another application's code: %d %v", r.status, r.m)
	}

	v, ch = pkce()
	if r := h.exchangeCode(cl, sec, h.getCode(c, cl, ch, scope), v); r.status != 200 || r.str("refresh_token") == "" {
		t.Fatalf("a code approved after the removal: %d %v", r.status, r.m)
	}
}

// Removing an application's access ends a device sign-in the user approved and the device has not collected yet;
// one approved after the removal is collected.
func TestRemovedAccessEndsAnApprovedDeviceSignIn(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.deviceClient(nil)
	b, csrf := h.session(h.user)
	dc, uc := h.startDevice(cl, "openid offline_access")
	if st, pg := h.consentDevice(b, csrf, uc, true); st != 200 {
		t.Fatalf("approve: %d %s", st, pg)
	}
	h.removeAccess(cl)
	tokenErr(t, h.pollDevice(cl, dc), 400, "invalid_grant")

	dc, uc = h.startDevice(cl, "openid offline_access")
	if st, pg := h.consentDevice(b, csrf, uc, true); st != 200 {
		t.Fatalf("approve again: %d %s", st, pg)
	}
	if r := h.pollDevice(cl, dc); r.status != 200 || r.str("refresh_token") == "" {
		t.Fatalf("a device sign-in approved after the removal: %d %v", r.status, r.m)
	}
}

// removeAccess is the account page's "remove access" of cl: the sessions it fenced are evicted from this node's cache
// as the app does on every write of one (app.evict), which the harness has no hook for.
func (h *harness) removeAccess(cl *model.Client) {
	h.t.Helper()
	if _, err := h.env.Svc.RevokeAppAccess(context.Background(), h.user.ID, cl.ID); err != nil {
		h.t.Fatal(err)
	}
	h.env.Server.Sessions.Evict("", h.user.ID)
}
