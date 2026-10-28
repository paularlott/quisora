package oidc

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestTenantAccessMembersOnly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	tn := h.tenant("staff", membersOnly())
	cl, secret := h.tenantClient(tn, nil)
	other, osecret := h.tenantClient(tn, nil)
	c, _ := h.session(h.user)
	v, ch := pkce()

	// no access: a clear page (403), and access_denied for prompt=none
	if code, st, text := h.tryCode(c, cl, ch, nil); code != "" || st != http.StatusForbidden || !strings.Contains(text, "do not have access") {
		t.Fatalf("no access: %d %q", st, text)
	}
	if code, _, e := h.tryCode(c, cl, ch, url.Values{"prompt": {"none"}}); code != "" || e != "access_denied" {
		t.Fatalf("prompt=none: %q", e)
	}

	// direct access to one client only, with roles and tags
	e := h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{AllClients: ptr(false), Clients: &[]string{cl.ID},
		Roles: &[]string{"editor"}, Tags: &[]string{"team:blue"}})
	code := h.getCode(c, cl, ch, orgScope)
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}, cl, secret)
	if r.status != 200 {
		t.Fatalf("exchange: %d %v", r.status, r.m)
	}
	for _, tok := range []string{r.str("access_token"), r.str("id_token")} {
		cm := claimsOf(t, tok)
		if !slices.Equal(strsOf(cm["roles"]), []string{"editor"}) || !slices.Contains(strsOf(cm["tags"]), "team:blue") {
			t.Fatalf("claims: %v", cm)
		}
	}
	// the other client of the tenant is not covered
	if code, st, _ := h.tryCode(c, other, ch, nil); code != "" || st != http.StatusForbidden {
		t.Fatalf("other client: %d", st)
	}

	// a group adds the other client and more roles (union)
	g, err := h.env.Svc.CreateGroup(ctx, h.admin, h.env.Primary.ID, service.GroupInput{DisplayName: ptr("Ops")})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.env.Svc.SetMembership(ctx, h.admin, g.ID, h.user.ID, true); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateMembership(h.env.Primary.ID) // the server does this on the change feed
	h.grant(tn, model.SubjectGroup, g.ID, service.AccessInput{Roles: &[]string{"viewer"}})
	r2, _ := h.login(other, osecret, orgScope)
	if roles := strsOf(claimsOf(t, r2.str("access_token"))["roles"]); !slices.Equal(roles, []string{"viewer"}) {
		t.Fatalf("other client roles: %v", roles)
	}
	r3, _ := h.login(cl, secret, orgScope)
	if roles := strsOf(claimsOf(t, r3.str("access_token"))["roles"]); !slices.Equal(roles, []string{"editor", "viewer"}) {
		t.Fatalf("merged roles: %v", roles)
	}

	// userinfo carries the roles too
	ui := h.get(&http.Client{Transport: h.http.Transport}, h.orgBase+"/oauth/userinfo", "Authorization", "Bearer "+r3.str("access_token"))
	if text := body(ui); ui.StatusCode != 200 || !strings.Contains(text, `"roles":["editor","viewer"]`) {
		t.Fatalf("userinfo: %d %s", ui.StatusCode, text)
	}

	// expiry: an expired direct entry no longer counts; the group still covers both clients
	past := time.Now().Add(-time.Minute).Format(time.RFC3339)
	if _, err := h.env.Svc.UpdateAccess(ctx, h.admin, tn.ID, e.ID, service.AccessInput{Expires: &past}); err != nil {
		t.Fatal(err)
	}
	r4 := h.refreshWith(cl, secret, r3.str("refresh_token"))
	if r4.status != 200 || !slices.Equal(strsOf(claimsOf(t, r4.str("access_token"))["roles"]), []string{"viewer"}) {
		t.Fatalf("refresh after expiry: %d %v", r4.status, r4.m)
	}

	// removing the group's access ends refresh, userinfo and introspection, and sign-in is refused again
	l, _, err := h.env.Svc.ListAccess(ctx, h.admin, tn.ID, store.ListQuery{})
	if err != nil || len(l) != 2 {
		t.Fatalf("list: %v %d", err, len(l))
	}
	for _, x := range l {
		if x.SubjectType == model.SubjectGroup {
			if err := h.env.Svc.RemoveAccess(ctx, h.admin, tn.ID, x.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if r := h.refreshWith(cl, secret, r3.str("refresh_token")); r.status != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("refresh after removal: %d %v", r.status, r.m)
	}
	for _, tok := range []string{r3.str("refresh_token"), r3.str("access_token")} {
		if m := h.introspect(cl, secret, tok); m["active"] != false {
			t.Fatalf("introspect after removal: %v", m)
		}
	}
	ui = h.get(&http.Client{Transport: h.http.Transport}, h.orgBase+"/oauth/userinfo", "Authorization", "Bearer "+r3.str("access_token"))
	if ui.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo after removal: %d", ui.StatusCode)
	}
	if code, st, _ := h.tryCode(c, cl, ch, nil); code != "" || st != http.StatusForbidden {
		t.Fatalf("after removal: %d", st)
	}
}

// A code issued while the user had access is refused at the token endpoint once the access is gone.
func TestTenantAccessCheckedAtExchange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	tn := h.tenant("staff", membersOnly())
	cl, secret := h.tenantClient(tn, nil)
	e := h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{})
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	if err := h.env.Svc.RemoveAccess(ctx, h.admin, tn.ID, e.ID); err != nil {
		t.Fatal(err)
	}
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}, cl, secret)
	if r.status != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("exchange: %d %v", r.status, r.m)
	}
}

// An open tenant lets everyone in and does not use its access entries (no roles from them).
func TestTenantAccessOpenTenantIgnoresEntries(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	open := model.DefaultTenantSettings()
	open.RequireMFA = false // the user signs in with a password alone
	tn := h.tenant("open", open)
	cl, secret := h.tenantClient(tn, nil)
	h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{Roles: &[]string{"admin"}})
	r, _ := h.login(cl, secret, nil)
	if _, ok := claimsOf(t, r.str("access_token"))["roles"]; ok {
		t.Fatal("an open tenant used its access entries")
	}
}
