package oidc

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

func tagsClaim(m map[string]any) []string {
	var out []string
	l, _ := m["tags"].([]any)
	for _, v := range l {
		out = append(out, v.(string))
	}
	return out
}

func TestTagsClaim(t *testing.T) {
	h := setup(t, nil)
	ctx := context.Background()
	svc := h.env.Svc
	cl, secret := h.newClient(nil)
	scope := url.Values{"scope": {"openid offline_access"}} // access tokens carry tags whatever the scopes

	r, _ := h.login(cl, secret, scope)
	rt := r.str("refresh_token")
	if _, has := claimsOf(t, r.str("access_token"))["tags"]; has {
		t.Fatal("tags claim present without any tags")
	}
	if _, has := claimsOf(t, r.str("id_token"))["tags"]; has {
		t.Fatal("tags in the ID token without any tags")
	}

	tags := []string{"vip", "dept:finance"}
	if _, err := svc.UpdateUser(ctx, h.admin, h.user.ID, service.UserInput{Tags: &tags}); err != nil {
		t.Fatal(err)
	}
	gt := []string{"team:blue", "vip"}
	grp, err := svc.CreateGroup(ctx, h.admin, h.env.Primary.ID, service.GroupInput{DisplayName: ptr("blue"), Tags: &gt})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetMembership(ctx, h.admin, grp.ID, h.user.ID, true); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(h.user.ID)
	h.p.InvalidateMembership(h.env.Primary.ID)

	want := []string{"dept:finance", "team:blue", "vip"}
	access := func() map[string]any {
		x := h.refreshWith(cl, secret, rt)
		if x.status != 200 {
			t.Fatal(x.m)
		}
		return claimsOf(t, x.str("access_token"))
	}
	if got := tagsClaim(access()); !slices.Equal(got, want) {
		t.Fatalf("access token tags %v, want %v", got, want)
	}
	// a new login: without the org scope the ID token and userinfo leave them out; with it they carry them
	r, _ = h.login(cl, secret, scope)
	if got := tagsClaim(claimsOf(t, r.str("id_token"))); len(got) != 0 {
		t.Fatalf("id token tags without the org scope: %v", got)
	}
	r, _ = h.login(cl, secret, url.Values{"scope": {scope.Get("scope") + " org"}})
	if got := tagsClaim(claimsOf(t, r.str("id_token"))); !slices.Equal(got, want) {
		t.Fatalf("id token tags %v", got)
	}
	resp := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+r.str("access_token"))
	var ui map[string]any
	_ = json.Unmarshal([]byte(body(resp)), &ui)
	if got := tagsClaim(ui); !slices.Equal(got, want) {
		t.Fatalf("userinfo tags %v", got)
	}
	// introspection of the access token, the refresh token and (via the same path) an API token
	if got := tagsClaim(h.introspect(cl, secret, r.str("access_token"))); !slices.Equal(got, want) {
		t.Fatalf("introspect access token tags %v", got)
	}
	if got := tagsClaim(h.introspect(cl, secret, r.str("refresh_token"))); !slices.Equal(got, want) {
		t.Fatalf("introspect refresh token tags %v", got)
	}

	// removing a tag from the group: still served from the cache until the membership generation moves
	gt2 := []string{"team:blue"}
	if _, err := svc.UpdateGroup(ctx, h.admin, grp.ID, service.GroupInput{Tags: &gt2}); err != nil {
		t.Fatal(err)
	}
	if got := tagsClaim(access()); !slices.Equal(got, want) {
		t.Fatalf("expected cached tags, got %v", got)
	}
	h.p.InvalidateMembership(h.env.Primary.ID)
	if got := tagsClaim(access()); !slices.Equal(got, []string{"dept:finance", "team:blue", "vip"}) {
		// "vip" stays: the user carries it too
		t.Fatalf("after invalidation %v", got)
	}
	// removing the user's own tag drops it now that no group has it either
	none := []string{}
	if _, err := svc.UpdateUser(ctx, h.admin, h.user.ID, service.UserInput{Tags: &none}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(h.user.ID)
	if got := tagsClaim(access()); !slices.Equal(got, []string{"team:blue"}) {
		t.Fatalf("after removing user tags %v", got)
	}
	// deleting the group removes its tags
	if err := svc.DeleteGroup(ctx, h.admin, grp.ID); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateMembership(h.env.Primary.ID)
	if _, has := access()["tags"]; has {
		t.Fatal("tags claim still present after the last tag went away")
	}
}

func TestTagsInDiscovery(t *testing.T) {
	h := setup(t, nil)
	var d struct {
		Claims []string `json:"claims_supported"`
	}
	_ = json.Unmarshal([]byte(body(h.get(h.http, "/.well-known/openid-configuration"))), &d)
	if !slices.Contains(d.Claims, "tags") {
		t.Fatalf("claims_supported lacks tags: %v", d.Claims)
	}
}
