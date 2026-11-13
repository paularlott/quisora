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

// Nor do the claims parameter's claims outlive the scope that allowed them: a claim requested by name (here "groups",
// with only openid asked for) when the code was issued is not in the ID token, the access token's userinfo claims or
// at userinfo once its scope is taken off the application.
func TestCodeClaimsParameterNarrowsToScopesTheClientStillHas(t *testing.T) {
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
		in.Scopes = &[]string{"openid", "profile", "groups"}
	})
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, url.Values{"scope": {"openid"}, "claims": {`{"id_token":{"groups":null},"userinfo":{"groups":null}}`}})
	if _, err := h.env.Svc.UpdateClient(ctx, h.admin, cl.ID, service.ClientInput{Scopes: &[]string{"openid", "profile"}}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}}, cl, secret)
	if r.status != 200 {
		t.Fatalf("exchange: %d %v", r.status, r.m)
	}
	if id := claimsOf(t, r.str("id_token")); id["groups"] != nil {
		t.Errorf("the ID token carries groups: %v", id["groups"])
	}
	if at := claimsOf(t, r.str("access_token")); at["userinfo_claims"] != nil || at["groups"] != nil {
		t.Errorf("the access token: userinfo_claims %v, groups %v", at["userinfo_claims"], at["groups"])
	}
	if ui := h.userinfo(r.str("access_token")); ui["groups"] != nil {
		t.Errorf("userinfo serves groups: %v", ui["groups"])
	}
}
