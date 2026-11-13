package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// A scope taken off an application after a code was issued for it is in neither the grant nor the tokens that code
// redeems (as a refresh narrows it away, and a new authorization refuses it), nor are the claims it unlocks; the
// scopes the application keeps are redeemed as before.
func TestCodeRedeemsOnlyScopesTheClientStillHas(t *testing.T) {
	h := setup(t, nil)
	ctx := context.Background()
	grp, err := h.env.Svc.CreateGroup(ctx, h.admin, h.env.Primary.ID, service.GroupInput{DisplayName: ptr("secretgroup")})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.env.Svc.SetMembership(ctx, h.admin, grp.ID, h.user.ID, true); err != nil {
		t.Fatal(err)
	}
	cl, secret := h.newClient(func(in *service.ClientInput) {
		in.Scopes = &[]string{"openid", "profile", "email", "groups", "orders:read"}
	})
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, url.Values{"scope": {"openid profile groups orders:read"}})
	if _, err := h.env.Svc.UpdateClient(ctx, h.admin, cl.ID, service.ClientInput{Scopes: &[]string{"openid", "profile", "email"}}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}}, cl, secret)
	if r.status != 200 || r.str("scope") != "openid profile" {
		t.Fatalf("exchange: %d %v", r.status, r.m)
	}
	claims := claimsOf(t, r.str("access_token"))
	if claims["scope"] != "openid profile" || claims["groups"] != nil {
		t.Errorf("the access token: scope %v, groups %v", claims["scope"], claims["groups"])
	}
	g, err := h.env.Svc.Grants.All(ctx, h.env.Primary.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range g {
		if x.ClientID == cl.ID && (len(x.Scopes) != 2 || x.Scopes[0] != "openid" || x.Scopes[1] != "profile") {
			t.Errorf("the grant keeps %v", x.Scopes)
		}
	}
}
