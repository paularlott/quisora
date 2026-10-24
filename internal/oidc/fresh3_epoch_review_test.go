package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// An epoch change ends authorization approved by an earlier session even when
// physical deletion of that session fails: deletion is only housekeeping.
func TestFresh3EpochChangeEndsOutstandingAuthorizationCode(t *testing.T) {
	h := setup(t, nil)
	ctx := context.Background()
	client, secret := h.newClient(nil)
	browser, _ := h.session(h.user)
	verifier, challenge := pkce()
	code := h.getCode(browser, client, challenge, nil)
	base := h.env.Svc.Store
	h.env.Svc.Store = failDeletes{Store: base, kind: model.KindSession}
	if err := h.env.Svc.ResetCredentials(ctx, h.user.ID); err == nil {
		t.Fatal("setup: expected injected cleanup error")
	}
	h.env.Svc.Store = base
	current, err := h.env.Svc.Users.Get(ctx, h.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.CredEpoch == h.user.CredEpoch {
		t.Fatal("reset did not commit a new epoch")
	}
	h.p.InvalidateUser(h.user.ID) // as the production user-change notification does
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {client.RedirectURIs[0]}, "code_verifier": {verifier}}, client, secret)
	if r.status == 200 {
		_, verifyErr := h.p.VerifyAccessToken(ctx, r.str("access_token"))
		refreshed := h.refreshWith(client, secret, r.str("refresh_token"))
		t.Fatalf("authorization from a passed session epoch issued new tokens: access verification=%v refresh status=%d", verifyErr, refreshed.status)
	}
	if r.status != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("unexpected refusal: %d %v", r.status, r.m)
	}
}

// Emergency sign-out invalidates stamps before its background deletion runs.
func TestFresh3SignOutEndsOutstandingAuthorizationCode(t *testing.T) {
	h := setup(t, nil)
	ctx := context.Background()
	client, secret := h.newClient(nil)
	browser, _ := h.session(h.user)
	verifier, challenge := pkce()
	code := h.getCode(browser, client, challenge, nil)
	if _, err := h.env.Svc.SignOutOrg(ctx, service.System, h.user.OrgID, service.SignOutOptions{Reason: "review outstanding code"}); err != nil {
		t.Fatal(err)
	}
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {client.RedirectURIs[0]}, "code_verifier": {verifier}}, client, secret)
	if r.status == 200 {
		_, verifyErr := h.p.VerifyAccessToken(ctx, r.str("access_token"))
		t.Fatalf("authorization from a signed-out session issued tokens with current counters: access verification=%v", verifyErr)
	}
	if r.status != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("unexpected refusal: %d %v", r.status, r.m)
	}
}
