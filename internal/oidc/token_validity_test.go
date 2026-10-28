package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// Tokens stop at once, wherever they are presented (userinfo, introspection by another client, the resource server's
// own check, refresh), when their application is disabled, their user's end date passes, or the organization is signed
// out. Each row starts from its own sign-in.
func TestTokensStopWhen(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		stop func(h *harness, cl *model.Client)
		// a disabled application can no longer authenticate itself: its own refresh is refused as a client, not a grant
		refreshStatus int
		signInAgain   bool
	}{
		{"the application is disabled", func(h *harness, cl *model.Client) {
			h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{Enabled: ptr(false)})
			h.p.InvalidateClient(cl.ID)
		}, 401, false},
		{"the user's end date passes", func(h *harness, cl *model.Client) {
			u, _ := h.env.Svc.Users.Get(context.Background(), h.user.ID)
			past := time.Now().Add(-time.Second)
			u.ValidUntil = &past
			if err := h.env.Svc.Users.Update(context.Background(), u); err != nil {
				h.t.Fatal(err)
			}
			h.p.InvalidateUser(u.ID)
		}, 400, false},
		{"the organization is signed out", func(h *harness, cl *model.Client) {
			if _, err := h.env.Svc.SignOutOrg(context.Background(), service.System, h.user.OrgID, service.SignOutOptions{Reason: "test"}); err != nil {
				h.t.Fatal(err)
			}
		}, 400, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := setup(t, nil)
			cl, secret := h.newClient(nil)
			other, osecret := h.newClient(func(in *service.ClientInput) { in.Name = ptr("other") })
			r, _ := h.login(cl, secret, nil)
			at, rt := r.str("access_token"), r.str("refresh_token")
			if resp := h.get(h.http, orgBase+"/oauth/userinfo", "Authorization", "Bearer "+at); resp.StatusCode != 200 {
				t.Fatalf("userinfo before: %d", resp.StatusCode)
			}
			tc.stop(h, cl)
			if resp := h.get(h.http, orgBase+"/oauth/userinfo", "Authorization", "Bearer "+at); resp.StatusCode != 401 {
				t.Errorf("userinfo: %d", resp.StatusCode)
			}
			if m := h.introspect(other, osecret, at); m["active"] != false {
				t.Errorf("introspection: %v", m)
			}
			if _, err := h.p.verifyAccessToken(context.Background(), at); err == nil {
				t.Error("verifyAccessToken accepted the token")
			}
			if x := h.refreshWith(cl, secret, rt); x.status != tc.refreshStatus {
				t.Errorf("refresh: %d %v, want %d", x.status, x.m, tc.refreshStatus)
			}
			if tc.refreshStatus == 400 { // the application can still ask about its own refresh token
				if m := h.introspect(cl, secret, rt); m["active"] != false {
					t.Errorf("refresh token introspection: %v", m)
				}
			}
			if tc.signInAgain {
				r, _ = h.login(cl, secret, nil)
				if resp := h.get(h.http, orgBase+"/oauth/userinfo", "Authorization", "Bearer "+r.str("access_token")); resp.StatusCode != 200 {
					t.Errorf("userinfo after signing in again: %d", resp.StatusCode)
				}
			}
		})
	}
}

func TestClientOfDeletedOrgUnknown(t *testing.T) {
	t.Parallel()
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
	h.env.Svc.InvalidateOrgs() // as the change feed does
	if _, err := h.env.Svc.Clients.Get(ctx, c.ID); err != nil {
		t.Fatalf("the record is the sweep's to remove: %v", err)
	}
	// the organization's address space is gone with it
	if r := h.token(form, c, secret); r.status != http.StatusNotFound {
		t.Fatalf("after: %d %v", r.status, r.m)
	}
	// and the application is unknown where it is looked up without a request
	if _, err := h.p.client(ctx, org.ID, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the client of a deleted organization is known: %v", err)
	}
}
