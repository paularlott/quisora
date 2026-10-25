package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// An application stands on its organization: once the organization is deleted the application is unknown, though
// its record is still there until the orphan sweep removes it.
func TestClientOfDeletedOrgUnknown(t *testing.T) {
	ctx := context.Background()
	h := setup(t, nil)
	org, err := h.env.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("doomed")})
	if err != nil {
		t.Fatal(err)
	}
	c, secret, err := h.env.Svc.CreateClient(ctx, service.System, org.ID, service.ClientInput{Name: ptr("app"),
		GrantTypes: &[]string{"client_credentials"}, Scopes: &[]string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	if r := h.token(form, c, secret); r.status != 200 {
		t.Fatalf("before: %d %v", r.status, r.m)
	}
	if err := h.env.Svc.DeleteOrg(ctx, service.System, org.ID, true); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateOrg(org.ID) // as the change feed does
	if _, err := h.env.Svc.Clients.Get(ctx, c.ID); err != nil {
		t.Fatalf("the record is the sweep's to remove: %v", err)
	}
	if r := h.token(form, c, secret); r.status != 401 || r.str("error") != "invalid_client" {
		t.Fatalf("after: %d %v", r.status, r.m)
	}
}
