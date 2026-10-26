package oidc

import (
	"context"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// Addresses Quisora itself calls (a client's back-channel logout and jwks_uri) are https only.
func TestOutboundClientURIsAreHTTPSOnly(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	for _, bad := range []string{"http://rp.example/logout", "http://127.0.0.1/logout", "com.example.app:/logout", "https://rp.example/x#frag", "https:///nohost"} {
		if _, _, err := h.env.Svc.CreateClient(ctx, h.admin, h.env.Primary.ID, service.ClientInput{Name: ptr("x"),
			RedirectURIs: &[]string{rpCallback}, BackchannelURI: ptr(bad)}); err == nil {
			t.Errorf("back-channel URI %q accepted", bad)
		}
		if _, _, err := h.env.Svc.CreateClient(ctx, h.admin, h.env.Primary.ID, service.ClientInput{Name: ptr("x"),
			RedirectURIs: &[]string{rpCallback}, JWKSURI: ptr(bad)}); err == nil {
			t.Errorf("jwks_uri %q accepted", bad)
		}
	}
	if _, _, err := h.env.Svc.CreateClient(ctx, h.admin, h.env.Primary.ID, service.ClientInput{Name: ptr("ok"),
		RedirectURIs: &[]string{rpCallback}, BackchannelURI: ptr("https://rp.example/logout")}); err != nil {
		t.Errorf("https back-channel URI: %v", err)
	}
}

// A new confidential client rotates its refresh tokens unless told otherwise; a public one cannot introspect.
func TestNewClientsRotateRefreshTokens(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	c, _, err := h.env.Svc.CreateClient(context.Background(), h.admin, h.env.Primary.ID, service.ClientInput{Name: ptr("x"),
		RedirectURIs: &[]string{rpCallback}})
	if err != nil {
		t.Fatal(err)
	}
	if !c.RotateRefresh || c.IntrospectOrg {
		t.Fatalf("defaults: rotate %v introspect_org %v", c.RotateRefresh, c.IntrospectOrg)
	}
	off, _, err := h.env.Svc.CreateClient(context.Background(), h.admin, h.env.Primary.ID, service.ClientInput{Name: ptr("y"),
		RedirectURIs: &[]string{rpCallback}, RotateRefresh: ptr(false)})
	if err != nil || off.RotateRefresh {
		t.Fatalf("rotation turned off: %v %v", off.RotateRefresh, err)
	}
	pub := h.publicClient(func(in *service.ClientInput) { in.IntrospectOrg = ptr(true) })
	if pub.IntrospectOrg {
		t.Fatal("a public client may introspect")
	}
}
