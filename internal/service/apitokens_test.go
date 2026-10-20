package service_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestAPITokenScopesLimitedByRole(t *testing.T) {
	c := newCast(t)
	cases := []struct {
		name   string
		u      *model.User
		scopes []string
		ok     bool
	}{
		{"user api", c.aUser, []string{"api"}, true},
		{"user scim", c.aUser, []string{"scim"}, false},
		{"user admin", c.aUser, []string{"admin"}, false},
		{"user mixed", c.aUser, []string{"api", "scim"}, false},
		{"manager scim", c.aManager, []string{"scim"}, true},
		{"manager api+scim", c.aManager, []string{"api", "scim"}, false},
		{"admin api+admin", c.aAdmin, []string{"api", "admin"}, false},
		{"super api+backup", c.super, []string{"api", "backup"}, false},
		{"admin scim+admin", c.aAdmin, []string{"scim", "admin"}, true},
		{"super scim", c.super, []string{"scim"}, true},
		{"unknown", c.aAdmin, []string{"root"}, false},
		{"empty", c.aAdmin, nil, false},
	}
	for _, tc := range cases {
		tok, plain, err := c.svc.CreateAPIToken(c.ctx, actor(tc.u), service.APITokenInput{Name: "t", Scopes: tc.scopes})
		if tc.ok {
			if err != nil || !strings.HasPrefix(plain, "qsr_"+tok.ID+"_") {
				t.Errorf("%s: %v", tc.name, err)
			}
			continue
		}
		var fe *service.FieldError
		if !errors.As(err, &fe) || fe.Field != "scopes" {
			t.Errorf("%s: want scopes error, got %v", tc.name, err)
		}
	}
}

func TestAPITokensCannotMintTokens(t *testing.T) {
	c := newCast(t)
	tok, plain, err := c.svc.CreateAPIToken(c.ctx, actor(c.aAdmin), service.APITokenInput{Name: "t", Scopes: []string{"scim", "admin"}})
	if err != nil {
		t.Fatal(err)
	}
	_, u, err := c.svc.ValidateAPIToken(c.ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	ta := service.ActorForToken(tok, u, "1.1.1.1")
	if !ta.Scoped() || ta.UserID != u.ID || ta.Role != model.RoleAdmin || ta.OrgID != c.a.ID {
		t.Fatalf("token actor %+v", ta)
	}
	if _, _, err := c.svc.CreateAPIToken(c.ctx, ta, service.APITokenInput{Name: "child", Scopes: []string{"api"}}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("token minted token: %v", err)
	}
	// A token actor still acts with the owner's role: an admin token can create managers, a manager token cannot.
	n := c.next("tk")
	if _, err := c.svc.CreateUser(c.ctx, ta, c.a.ID, service.UserInput{GivenName: gn("T"), Username: &n, Email: ptr(n + "@example.com"), Role: ptr(model.RoleManager)}); err != nil {
		t.Errorf("admin token creating manager: %v", err)
	}
	mt, mplain, _ := c.svc.CreateAPIToken(c.ctx, actor(c.aManager), service.APITokenInput{Name: "m", Scopes: []string{"scim"}})
	_, mu, _ := c.svc.ValidateAPIToken(c.ctx, mplain)
	ma := service.ActorForToken(mt, mu, "")
	n2 := c.next("tk")
	if _, err := c.svc.CreateUser(c.ctx, ma, c.a.ID, service.UserInput{GivenName: gn("T"), Username: &n2, Email: ptr(n2 + "@example.com"), Role: ptr(model.RoleManager)}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("manager token creating manager: %v", err)
	}
	if _, err := c.svc.CreateUser(c.ctx, ma, c.a.ID, service.UserInput{GivenName: gn("T"), Username: &n2, Email: ptr(n2 + "@example.com")}); err != nil {
		t.Errorf("manager token creating user: %v", err)
	}
	if _, err := c.svc.CreateGroup(c.ctx, ma, c.a.ID, service.GroupInput{DisplayName: ptr("nope")}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("manager token creating group: %v", err)
	}
	if !ma.HasScope("scim") || ma.HasScope("admin") {
		t.Error("HasScope")
	}
	if !actor(c.aManager).HasScope("anything") {
		t.Error("interactive actors hold every scope")
	}
}

func TestAPITokenValidation(t *testing.T) {
	c := newCast(t)
	owner := c.user(c.a.ID, "owner", model.RoleManager)
	mk := func() (*model.APIToken, string) {
		tok, plain, err := c.svc.CreateAPIToken(c.ctx, actor(owner), service.APITokenInput{Name: "t", Scopes: []string{"scim"}})
		if err != nil {
			t.Fatal(err)
		}
		return tok, plain
	}
	expectBad := func(name, presented string) {
		t.Helper()
		if _, _, err := c.svc.ValidateAPIToken(c.ctx, presented); !errors.Is(err, service.ErrBadToken) {
			t.Errorf("%s: want ErrBadToken, got %v", name, err)
		}
	}

	tok, plain := mk()
	got, u, err := c.svc.ValidateAPIToken(c.ctx, plain)
	if err != nil || got.ID != tok.ID || u.ID != owner.ID {
		t.Fatalf("valid token: %v", err)
	}
	if !service.IsAPIToken(plain) || service.IsAPIToken("eyJ.abc.def") {
		t.Error("IsAPIToken")
	}

	// Garbage and tampering.
	expectBad("empty", "")
	expectBad("no prefix", strings.TrimPrefix(plain, "qsr_"))
	expectBad("prefix only", "qsr_")
	expectBad("no secret", "qsr_"+tok.ID)
	expectBad("empty secret", "qsr_"+tok.ID+"_")
	expectBad("unknown id", "qsr_nope_"+plain[strings.LastIndex(plain, "_")+1:])
	secret := plain[strings.LastIndex(plain, "_")+1:]
	flipped := []byte(secret)
	if flipped[0] == 'A' {
		flipped[0] = 'B'
	} else {
		flipped[0] = 'A'
	}
	expectBad("tampered secret", "qsr_"+tok.ID+"_"+string(flipped))
	expectBad("truncated secret", plain[:len(plain)-1])
	expectBad("extended secret", plain+"x")
	// Another token's secret does not open this one.
	_, plain2 := mk()
	expectBad("swapped secret", "qsr_"+tok.ID+"_"+plain2[strings.LastIndex(plain2, "_")+1:])

	// Expired.
	expTok, expPlain := mk()
	expTok, _ = c.svc.APITokens.Get(c.ctx, expTok.ID)
	expTok.Expires = time.Now().Add(-time.Minute)
	if err := c.svc.APITokens.Put(c.ctx, expTok); err != nil {
		t.Fatal(err)
	}
	expectBad("expired", expPlain)

	// Deleted by the owner.
	delTok, delPlain := mk()
	if err := c.svc.DeleteAPIToken(c.ctx, actor(owner), delTok.ID); err != nil {
		t.Fatal(err)
	}
	expectBad("deleted", delPlain)

	// Owner disabled, then re-enabled.
	_, offPlain := mk()
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.aAdmin), owner.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	expectBad("disabled owner", offPlain)
	expectBad("disabled owner (original token)", plain)
	// Disabling does not delete tokens... re-enabling restores them.
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.aAdmin), owner.ID, service.UserInput{Active: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.svc.ValidateAPIToken(c.ctx, offPlain); err != nil {
		t.Errorf("re-enabled owner: %v", err)
	}

	// Owner deleted.
	if err := c.svc.DeleteUser(c.ctx, actor(c.aAdmin), owner.ID); err != nil {
		t.Fatal(err)
	}
	expectBad("deleted owner", plain)
	expectBad("deleted owner 2", offPlain)
}

func TestAPITokenLifetimeAndManagement(t *testing.T) {
	c := newCast(t)
	a := actor(c.aManager)
	// With a server maximum, no expiry means the maximum.
	c.svc.Cfg.Tokens.APITokenMaxDays = 365
	tok, _, err := c.svc.CreateAPIToken(c.ctx, a, service.APITokenInput{Name: "default", Scopes: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	max := c.svc.Cfg.Tokens.APITokenMaxDays
	if d := time.Until(tok.Expires); d < time.Duration(max-1)*24*time.Hour || d > time.Duration(max)*24*time.Hour {
		t.Errorf("default expiry %v for max %d days", d, max)
	}
	tok, _, err = c.svc.CreateAPIToken(c.ctx, a, service.APITokenInput{Name: "short", Scopes: []string{"api"}, Expires: 1})
	if err != nil || time.Until(tok.Expires) > 25*time.Hour {
		t.Errorf("1 day token: %v %v", err, tok.Expires)
	}
	for _, d := range []int{-1, max + 1} {
		if _, _, err := c.svc.CreateAPIToken(c.ctx, a, service.APITokenInput{Name: "x", Scopes: []string{"api"}, Expires: d}); !errors.Is(err, service.ErrInvalid) {
			t.Errorf("expires %d: %v", d, err)
		}
	}
	for _, n := range []string{"", "   ", strings.Repeat("n", 101)} {
		if _, _, err := c.svc.CreateAPIToken(c.ctx, a, service.APITokenInput{Name: n, Scopes: []string{"api"}}); !errors.Is(err, service.ErrInvalid) {
			t.Errorf("name %q: %v", n, err)
		}
	}
	// With no server maximum (0) no expiry means never, and any positive lifetime is allowed.
	c.svc.Cfg.Tokens.APITokenMaxDays = 0
	tok, _, err = c.svc.CreateAPIToken(c.ctx, a, service.APITokenInput{Name: "forever", Scopes: []string{"api"}})
	if err != nil || !tok.Expires.IsZero() {
		t.Errorf("no max: %v %v", err, tok.Expires)
	}
	if _, _, err := c.svc.CreateAPIToken(c.ctx, a, service.APITokenInput{Name: "long", Scopes: []string{"api"}, Expires: 3650}); err != nil {
		t.Errorf("no max, 3650 days: %v", err)
	}
	for _, d := range []int{-1, 3651} {
		if _, _, err := c.svc.CreateAPIToken(c.ctx, a, service.APITokenInput{Name: "x", Scopes: []string{"api"}, Expires: d}); !errors.Is(err, service.ErrInvalid) {
			t.Errorf("no max, %d: %v", d, err)
		}
	}

	// Listing shows only the actor's own tokens; the secret hash never leaves.
	list, n, err := c.svc.ListAPITokens(c.ctx, a, store.ListQuery{})
	if err != nil || n != 4 || len(list) != 4 {
		t.Fatalf("list: %v %d", err, n)
	}
	if _, n, _ := c.svc.ListAPITokens(c.ctx, actor(c.aAdmin), store.ListQuery{}); n != 0 {
		t.Errorf("admin sees %d tokens of a manager", n)
	}
	if _, _, err := c.svc.ListAPITokens(c.ctx, service.ActorForClient(&model.Client{OrgID: c.a.ID}, ""), store.ListQuery{}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("client listing tokens: %v", err)
	}

	// Deleting: owner and managers of the owner may, others see "not found".
	if err := c.svc.DeleteAPIToken(c.ctx, actor(c.bAdmin), list[0].ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("other org delete: %v", err)
	}
	if err := c.svc.DeleteAPIToken(c.ctx, actor(c.aUser), list[0].ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("plain user delete: %v", err)
	}
	if err := c.svc.DeleteAPIToken(c.ctx, actor(c.aAdmin), list[0].ID); err != nil {
		t.Errorf("admin delete: %v", err)
	}
	if err := c.svc.DeleteAPIToken(c.ctx, a, list[1].ID); err != nil {
		t.Errorf("owner delete: %v", err)
	}
	if err := c.svc.DeleteAPIToken(c.ctx, a, list[1].ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("double delete: %v", err)
	}
	// An admin may not delete a super admin's token.
	st, _, _ := c.svc.CreateAPIToken(c.ctx, actor(c.super), service.APITokenInput{Name: "s", Scopes: []string{"api"}})
	if err := c.svc.DeleteAPIToken(c.ctx, actor(c.pAdmin), st.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("admin deleting super's token: %v", err)
	}
}

func TestAPITokenLastUsed(t *testing.T) {
	c := newCast(t)
	tok, plain, err := c.svc.CreateAPIToken(c.ctx, actor(c.aManager), service.APITokenInput{Name: "used", Scopes: []string{"api"}, Expires: 30})
	if err != nil || !tok.LastUsed.IsZero() {
		t.Fatalf("new token: %v %v", err, tok.LastUsed)
	}
	if _, _, err := c.svc.ValidateAPIToken(c.ctx, plain); err != nil {
		t.Fatal(err)
	}
	got, _ := c.svc.APITokens.Get(c.ctx, tok.ID)
	if got.LastUsed.IsZero() || time.Since(got.LastUsed) > time.Minute {
		t.Fatalf("last used not recorded: %v", got.LastUsed)
	}
	// a second use within the interval does not write again
	v := got.Version
	_, _, _ = c.svc.ValidateAPIToken(c.ctx, plain)
	if again, _ := c.svc.APITokens.Get(c.ctx, tok.ID); again.Version != v {
		t.Error("a use within the interval wrote again")
	}
}

// A new secret keeps the token (name, scopes, expiry) and stops the old secret; only the owner may ask for one, and
// only for scopes their role still allows.
func TestAPITokenRegenerate(t *testing.T) {
	c := newCast(t)
	tok, old, err := c.svc.CreateAPIToken(c.ctx, actor(c.aManager), service.APITokenInput{Name: "sync", Scopes: []string{"scim"}, Expires: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.svc.RegenerateAPIToken(c.ctx, actor(c.aAdmin), tok.ID); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("another user (an admin) regenerated it: %v", err)
	}
	_, u, _ := c.svc.ValidateAPIToken(c.ctx, old)
	if _, _, err := c.svc.RegenerateAPIToken(c.ctx, service.ActorForToken(tok, u, ""), tok.ID); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("a token regenerated itself: %v", err)
	}
	got, fresh, err := c.svc.RegenerateAPIToken(c.ctx, actor(c.aManager), tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fresh == old || got.ID != tok.ID || got.Name != "sync" || !got.Expires.Equal(tok.Expires) || got.Scopes[0] != "scim" {
		t.Fatalf("regenerated %+v", got)
	}
	if _, _, err := c.svc.ValidateAPIToken(c.ctx, old); err == nil {
		t.Fatal("old secret still works")
	}
	if _, _, err := c.svc.ValidateAPIToken(c.ctx, fresh); err != nil {
		t.Fatalf("new secret: %v", err)
	}
	// demoted since: no new secret for a scope the role no longer allows
	m := *c.aManager
	m.Role = model.RoleUser
	var fe *service.FieldError
	if _, _, err := c.svc.RegenerateAPIToken(c.ctx, actor(&m), tok.ID); !errors.As(err, &fe) || fe.Field != "scopes" {
		t.Fatalf("demoted owner: %v", err)
	}
}

// An api token can be narrowed to its applications' own scopes: only with applications chosen, only scopes they
// declare, only on an api token; editing checks again, and keeps the expiry.
func TestAPITokenAppScopes(t *testing.T) {
	c := newCast(t)
	sys := service.System
	orders, _, err := c.svc.CreateClient(c.ctx, sys, c.a.ID, service.ClientInput{Name: ptr("Orders"), GrantTypes: ptr([]string{"client_credentials"}),
		Scopes: ptr([]string{"openid", "orders:read", "orders:write"})})
	if err != nil {
		t.Fatal(err)
	}
	billing, _, err := c.svc.CreateClient(c.ctx, sys, c.a.ID, service.ClientInput{Name: ptr("Billing"), GrantTypes: ptr([]string{"client_credentials"}),
		Scopes: ptr([]string{"billing:read"})})
	if err != nil {
		t.Fatal(err)
	}
	a := actor(c.aUser)
	apps, err := c.svc.TokenApps(c.ctx, a)
	if err != nil || len(apps) < 2 {
		t.Fatalf("apps: %v %v", apps, err)
	}
	for _, app := range apps {
		if app.ID == orders.ID && strings.Join(app.Scopes, " ") != "orders:read orders:write" {
			t.Errorf("orders scopes %v (standard ones are not the application's own)", app.Scopes)
		}
	}
	tok, _, err := c.svc.CreateAPIToken(c.ctx, a, service.APITokenInput{Name: "r", Scopes: []string{"api"}, Audience: []string{orders.ID},
		AppScopes: []string{"orders:read"}, Expires: 5})
	if err != nil || strings.Join(tok.AppScopes, " ") != "orders:read" {
		t.Fatalf("narrowed token: %v %v", tok, err)
	}
	var fe *service.FieldError
	for name, in := range map[string]service.APITokenInput{
		"another app's scope": {Name: "x", Scopes: []string{"api"}, Audience: []string{orders.ID}, AppScopes: []string{"billing:read"}},
		"undeclared":          {Name: "x", Scopes: []string{"api"}, Audience: []string{orders.ID}, AppScopes: []string{"nope:read"}},
		"standard":            {Name: "x", Scopes: []string{"api"}, Audience: []string{orders.ID}, AppScopes: []string{"openid"}},
	} {
		if _, _, err := c.svc.CreateAPIToken(c.ctx, a, in); !errors.As(err, &fe) || fe.Field != "app_scopes" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.aManager), service.APITokenInput{Name: "x", Scopes: []string{"scim"}, AppScopes: []string{"orders:read"}}); !errors.As(err, &fe) || fe.Field != "app_scopes" {
		t.Errorf("app scopes on a scim token: %v", err)
	}
	// without chosen applications there is nothing to narrow
	if _, _, err := c.svc.CreateAPIToken(c.ctx, a, service.APITokenInput{Name: "y", Scopes: []string{"api"}, AppScopes: []string{"orders:read"}}); !errors.As(err, &fe) || fe.Field != "app_scopes" {
		t.Errorf("no audience: %v", err)
	}
	// with two applications, either one's scopes
	if _, _, err := c.svc.CreateAPIToken(c.ctx, a, service.APITokenInput{Name: "z", Scopes: []string{"api"}, Audience: []string{orders.ID, billing.ID},
		AppScopes: []string{"billing:read", "orders:read"}}); err != nil {
		t.Errorf("two applications: %v", err)
	}

	// edit: rename, move to the billing app (its scope must come with it), widen back to full access
	if _, err := c.svc.UpdateAPIToken(c.ctx, a, tok.ID, service.APITokenUpdate{Audience: &[]string{billing.ID}}); !errors.As(err, &fe) || fe.Field != "app_scopes" {
		t.Errorf("moved app, kept its scope: %v", err)
	}
	got, err := c.svc.UpdateAPIToken(c.ctx, a, tok.ID, service.APITokenUpdate{Name: ptr("billing reader"), Audience: &[]string{billing.ID}, AppScopes: &[]string{"billing:read"}})
	if err != nil || got.Name != "billing reader" || strings.Join(got.AppScopes, " ") != "billing:read" || !got.Expires.Equal(tok.Expires) {
		t.Fatalf("edit: %+v %v", got, err)
	}
	if got, err = c.svc.UpdateAPIToken(c.ctx, a, tok.ID, service.APITokenUpdate{AppScopes: &[]string{}}); err != nil || len(got.AppScopes) != 0 {
		t.Fatalf("back to full access: %v %v", got, err)
	}
	if _, err := c.svc.UpdateAPIToken(c.ctx, actor(c.aAdmin), tok.ID, service.APITokenUpdate{Name: ptr("mine")}); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("someone else edited it: %v", err)
	}
}
