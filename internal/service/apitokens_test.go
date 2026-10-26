package service_test

import (
	"errors"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
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
	made := map[*model.User]int{}
	for _, tc := range cases {
		tok, plain, err := c.svc.CreateAPIToken(c.ctx, actor(tc.u), service.APITokenInput{Name: "t", Scopes: tc.scopes})
		if tc.ok {
			made[tc.u]++
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
	// A refused request stores nothing.
	for u, want := range made {
		if n, _ := c.svc.APITokens.Count(c.ctx, u.ID); n != want {
			t.Errorf("%s holds %d tokens, want %d", u.Username, n, want)
		}
	}
	// The system actor has no tokens of its own.
	if _, _, err := c.svc.CreateAPIToken(c.ctx, service.System, service.APITokenInput{Name: "n", Scopes: []string{"api"}}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("system token: %v", err)
	}
	// The backup scope is for a super admin, and expires.
	if _, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.super), service.APITokenInput{Name: "b", Scopes: []string{"backup"}}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("backup token without an expiry: %v", err)
	}
	if tok, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.super), service.APITokenInput{Name: "b", Scopes: []string{"backup"}, Expires: 1}); err != nil || tok.Expires.IsZero() {
		t.Errorf("backup token: %v", err)
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
	if _, err := c.svc.CreateUser(c.ctx, ta, c.a.ID, service.UserInput{GivenName: ptr("T"), Username: &n, Email: ptr(n + "@example.com"), Role: ptr(model.RoleManager)}); err != nil {
		t.Errorf("admin token creating manager: %v", err)
	}
	mt, mplain, _ := c.svc.CreateAPIToken(c.ctx, actor(c.aManager), service.APITokenInput{Name: "m", Scopes: []string{"scim"}})
	_, mu, _ := c.svc.ValidateAPIToken(c.ctx, mplain)
	ma := service.ActorForToken(mt, mu, "")
	n2 := c.next("tk")
	if _, err := c.svc.CreateUser(c.ctx, ma, c.a.ID, service.UserInput{GivenName: ptr("T"), Username: &n2, Email: ptr(n2 + "@example.com"), Role: ptr(model.RoleManager)}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("manager token creating manager: %v", err)
	}
	if _, err := c.svc.CreateUser(c.ctx, ma, c.a.ID, service.UserInput{GivenName: ptr("T"), Username: &n2, Email: ptr(n2 + "@example.com")}); err != nil {
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

// A token's last use is recorded in the background, not rewritten within the interval, and written one at a time per
// token.
func TestAPITokenLastUsed(t *testing.T) {
	t.Run("recorded_and_not_rewritten_within_the_interval", func(t *testing.T) {
		c := newCast(t)
		tok, plain, err := c.svc.CreateAPIToken(c.ctx, actor(c.aManager), service.APITokenInput{Name: "used", Scopes: []string{"api"}, Expires: 30})
		if err != nil || !tok.LastUsed.IsZero() {
			t.Fatalf("new token: %v %v", err, tok.LastUsed)
		}
		if _, _, err := c.svc.ValidateAPIToken(c.ctx, plain); err != nil {
			t.Fatal(err)
		}
		c.svc.WaitBackground() // recorded in the background
		got, _ := c.svc.APITokens.Get(c.ctx, tok.ID)
		if got.LastUsed.IsZero() || time.Since(got.LastUsed) > time.Minute {
			t.Fatalf("last used not recorded: %v", got.LastUsed)
		}
		// a second use within the interval does not write again
		v := got.Version
		_, _, _ = c.svc.ValidateAPIToken(c.ctx, plain)
		c.svc.WaitBackground()
		if again, _ := c.svc.APITokens.Get(c.ctx, tok.ID); again.Version != v {
			t.Error("a use within the interval wrote again")
		}
	})

	t.Run("recorded_in_the_background_one_write_at_a_time", func(t *testing.T) {
		// The request is answered while the write is still running, and the requests that follow start no second one.
		c := newCast(t)
		tok, plain, err := c.svc.CreateAPIToken(c.ctx, actor(c.aManager), service.APITokenInput{Name: "bg", Scopes: []string{"api"}, Expires: 30})
		if err != nil {
			t.Fatal(err)
		}
		gt := newGate(t)
		var writes atomic.Int64
		c.svc.APITokens.S = &faultStore{Store: c.svc.Store, beforeCAS: func(r *store.Record, expect hlc.Timestamp) error {
			if r.Kind == model.KindAPIToken && expect != 0 {
				writes.Add(1)
				gt.stall()
			}
			return nil
		}}
		done := make(chan error, 1)
		go func() {
			for range 5 {
				if _, _, err := c.svc.ValidateAPIToken(c.ctx, plain); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a request waited for the last-use write")
		}
		gt.waitEntered(t, "the last-use write")
		gt.release()
		c.svc.WaitBackground()
		if n := writes.Load(); n != 1 {
			t.Fatalf("%d writes for five uses of one token, want 1", n)
		}
		if got, _ := c.svc.APITokens.Get(c.ctx, tok.ID); got.LastUsed.IsZero() {
			t.Fatal("the use was not recorded")
		}
	})
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
	c.svc.WaitBackground()
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
	if stored, _ := c.svc.APITokens.Get(c.ctx, tok.ID); string(stored.SecretHash) != string(got.SecretHash) {
		t.Error("the secret changed by a refused regeneration")
	}
	if _, _, err := c.svc.RegenerateAPIToken(c.ctx, service.System, tok.ID); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("system regenerate: %v", err)
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

// A refused token that exists is audited in its organization, and what a token does names the token.
func TestAPITokenRefusalAndUseAudited(t *testing.T) {
	c := newCast(t)
	sink := &auditSink{}
	c.svc.AuditWriter = sink
	tok, plain, err := c.svc.CreateAPIToken(c.ctx, actor(c.aAdmin), service.APITokenInput{Name: "deploy", Scopes: []string{"admin"}})
	if err != nil {
		t.Fatal(err)
	}
	wrong := plain[:len(plain)-1] + map[bool]string{true: "A", false: "B"}[!strings.HasSuffix(plain, "A")]
	for range 20 { // repeated at will by whoever knows the token's id: recorded once
		if _, _, err := c.svc.ValidateAPIToken(c.ctx, wrong); !errors.Is(err, service.ErrBadToken) {
			t.Fatalf("wrong secret: %v", err)
		}
	}
	refusals := sink.of("apitoken.refused")
	if len(refusals) != 1 {
		t.Fatalf("%d apitoken.refused events for 20 attempts in a minute, want 1", len(refusals))
	}
	e := refusals[0]
	if e.OrgID != c.a.ID || e.Target != "deploy" || e.Outcome != "failure" || e.Detail["reason"] != "wrong secret" ||
		e.Detail["token_id"] != tok.ID {
		t.Fatalf("refusal audit: %+v", e)
	}
	if _, _, err := c.svc.ValidateAPIToken(c.ctx, "qsr_nosuchtoken_secret"); !errors.Is(err, service.ErrBadToken) {
		t.Fatalf("unknown token: %v", err)
	}
	_, u, err := c.svc.ValidateAPIToken(c.ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	n := c.next("tk")
	if _, err := c.svc.CreateUser(c.ctx, service.ActorForToken(tok, u, ""), c.a.ID, service.UserInput{GivenName: ptr("T"),
		Username: &n, Email: ptr(n + "@example.com")}); err != nil {
		t.Fatal(err)
	}
	if created := sink.of("user.create"); len(created) != 1 || created[0].Detail["token_id"] != tok.ID {
		t.Fatalf("an action with a token does not name it: %+v", created)
	}
}

// A store failure while a token is checked is the server's, not the caller's: ErrUnavailable, never ErrBadToken.
func TestAPITokenUnavailableWhenAStoreReadFails(t *testing.T) {
	t.Run("token_read_fails", func(t *testing.T) {
		c := newCast(t)
		_, plain, err := c.svc.CreateAPIToken(c.ctx, actor(c.aAdmin), service.APITokenInput{Name: "t", Scopes: []string{"admin"}})
		if err != nil {
			t.Fatal(err)
		}
		c.svc.APITokens.S = failingReads(c.svc.APITokens.S, model.KindAPIToken)
		if _, _, err := c.svc.ValidateAPIToken(c.ctx, plain); !errors.Is(err, service.ErrUnavailable) || errors.Is(err, service.ErrBadToken) {
			t.Fatalf("store failure: %v, want ErrUnavailable", err)
		}
	})

	t.Run("sign_out_counters_unreadable", func(t *testing.T) {
		// The emergency sign-out counters a token's stamp is compared with cannot be read: the token is neither good
		// nor "ended by an emergency sign-out" (which would be audited as a refusal), but unchecked.
		e := newEnv(t)
		_, plain, err := e.svc.CreateAPIToken(e.ctx, actor(e.super), service.APITokenInput{Name: "t", Scopes: []string{"admin"}})
		if err != nil {
			t.Fatal(err)
		}
		good := e.svc.Orgs.S
		e.svc.Orgs.S = failingReads(good, model.KindOrg)
		e.svc.InvalidateSignOut() // the counters read when the token was made must not answer for the store
		_, _, err = e.svc.ValidateAPIToken(e.ctx, plain)
		if !errors.Is(err, service.ErrUnavailable) || errors.Is(err, service.ErrBadToken) {
			t.Fatalf("unreadable sign-out counters: %v, want ErrUnavailable", err)
		}
		if n := len(e.audits("apitoken.refused")); n != 0 {
			t.Fatalf("a refusal was audited for a token that was not refused (%d)", n)
		}
		e.svc.Orgs.S = good
		if _, _, err := e.svc.ValidateAPIToken(e.ctx, plain); err != nil {
			t.Fatalf("once the store answers again: %v", err)
		}
	})
}

// A new secret is made again when a use of the token wrote its last use first: the owner is not told that someone else
// changed it.
func TestAPITokenRegenerateSurvivesTheLastUseWrite(t *testing.T) {
	c := newCast(t)
	tok, old, err := c.svc.CreateAPIToken(c.ctx, actor(c.aManager), service.APITokenInput{Name: "race", Scopes: []string{"api"}, Expires: 10})
	if err != nil {
		t.Fatal(err)
	}
	base := c.svc.APITokens.S
	// A use of the token records its last use between the change's read and its write, as the background write of a use can.
	touched := false
	c.svc.APITokens.S = &faultStore{Store: base, beforeCAS: func(r *store.Record, _ hlc.Timestamp) error {
		if r.Kind != model.KindAPIToken || touched {
			return nil
		}
		touched = true
		cur, err := store.NewTable[model.APIToken](base).Get(c.ctx, tok.ID)
		if err != nil {
			t.Error(err)
			return nil
		}
		cur.LastUsed = time.Now().UTC()
		if err := store.NewTable[model.APIToken](base).Update(c.ctx, cur); err != nil {
			t.Error(err)
		}
		return nil
	}}
	_, fresh, err := c.svc.RegenerateAPIToken(c.ctx, actor(c.aManager), tok.ID)
	if err != nil {
		t.Fatalf("regenerate after a last-use write: %v", err)
	}
	c.svc.APITokens.S = base
	if _, _, err := c.svc.ValidateAPIToken(c.ctx, fresh); err != nil {
		t.Fatalf("the new secret: %v", err)
	}
	if _, _, err := c.svc.ValidateAPIToken(c.ctx, old); err == nil {
		t.Fatal("the old secret still works")
	}
}

// A token's owner, the managers above them and a super admin see and delete their tokens; anyone else is told nothing.
func TestAPITokenOwnerAndManagerAccess(t *testing.T) {
	c := newCast(t)
	tok, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.aUser), service.APITokenInput{Name: "mine", Scopes: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	if l, n, err := c.svc.ListAPITokens(c.ctx, actor(c.aUser), store.ListQuery{}); err != nil || n != 1 || l[0].ID != tok.ID {
		t.Fatalf("own list: %v %d", err, n)
	}
	if _, n, err := c.svc.ListAPITokens(c.ctx, actor(c.aManager), store.ListQuery{}); err != nil || n != 0 {
		t.Fatalf("a manager lists their own tokens only: %d %v", n, err)
	}
	if _, _, err := c.svc.ListAPITokens(c.ctx, service.System, store.ListQuery{}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("system has no tokens of its own: %v", err)
	}
	for _, tc := range []struct {
		name string
		u    *model.User
		want string
	}{
		{"owner", c.aUser, "ok"}, {"org admin", c.aAdmin, "ok"}, {"org manager", c.aManager, "ok"}, {"super", c.super, "ok"},
		{"foreign admin", c.bAdmin, "denied"}, {"primary user", c.pUser, "denied"}, {"peer", c.e2(c.a.ID), "denied"},
	} {
		_, _, err := c.svc.ListUserAPITokens(c.ctx, actor(tc.u), c.aUser.ID, store.ListQuery{})
		c.check(t, tc.name, err, tc.want)
	}
	if _, _, err := c.svc.ListUserAPITokens(c.ctx, actor(c.aAdmin), "nobody", store.ListQuery{}); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
	// Someone who may not manage the owner learns nothing, and the token survives.
	for name, u := range map[string]*model.User{"foreign admin": c.bAdmin, "peer": c.e2(c.a.ID)} {
		if err := c.svc.DeleteAPIToken(c.ctx, actor(u), tok.ID); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s delete: %v", name, err)
		}
	}
	if _, err := c.svc.APITokens.Get(c.ctx, tok.ID); err != nil {
		t.Fatal("token deleted by a stranger")
	}
	if err := c.svc.DeleteAPIToken(c.ctx, actor(c.aAdmin), tok.ID); err != nil {
		t.Fatal(err)
	}
	if ev := c.audited(c.a.ID, "apitoken.delete"); len(ev) != 1 || ev[0].Detail["owner"] != c.aUser.ID {
		t.Errorf("audit %+v", ev)
	}
}

// Only the owner changes a token, and only the name is theirs to set freely.
func TestAPITokenUpdateRules(t *testing.T) {
	c := newCast(t)
	tok, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.aManager), service.APITokenInput{Name: "scim", Scopes: []string{"scim"}, Expires: 5})
	if err != nil {
		t.Fatal(err)
	}
	for name, u := range map[string]*model.User{"admin of the org": c.aAdmin, "foreign": c.bAdmin} {
		if _, err := c.svc.UpdateAPIToken(c.ctx, actor(u), tok.ID, service.APITokenUpdate{Name: ptr("x")}); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s update: %v", name, err)
		}
	}
	if _, err := c.svc.UpdateAPIToken(c.ctx, service.System, tok.ID, service.APITokenUpdate{}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("system update: %v", err)
	}
	own, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.aUser), service.APITokenInput{Name: "t", Scopes: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "  ", strings.Repeat("n", 101)} {
		if _, err := c.svc.UpdateAPIToken(c.ctx, actor(c.aUser), own.ID, service.APITokenUpdate{Name: ptr(name)}); !isInvalid(err) {
			t.Errorf("name %q: %v", name, err)
		}
	}
	if got, err := c.svc.UpdateAPIToken(c.ctx, actor(c.aUser), own.ID, service.APITokenUpdate{Name: ptr(" renamed ")}); err != nil || got.Name != "renamed" {
		t.Errorf("rename: %v", err)
	}
}

// The applications a token can be limited to are the owner's organization's enabled, confidential ones.
func TestTokenAppsListsOnlyUsableApplications(t *testing.T) {
	c := newCast(t)
	sys := service.System
	app, _, err := c.svc.CreateClient(c.ctx, sys, c.a.ID, service.ClientInput{Name: ptr("Orders"), GrantTypes: ptr([]string{"client_credentials"}),
		Scopes: ptr([]string{"orders:read", "orders:write"})})
	if err != nil {
		t.Fatal(err)
	}
	foreign, _, err := c.svc.CreateClient(c.ctx, sys, c.b.ID, service.ClientInput{Name: ptr("Theirs"), GrantTypes: ptr([]string{"client_credentials"}),
		Scopes: ptr([]string{"theirs:read"})})
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := c.svc.CreateClient(c.ctx, sys, c.a.ID, service.ClientInput{Name: ptr("Public"), AuthMethod: ptr(model.AuthMethodNone),
		RedirectURIs: ptr([]string{"https://p.example.com/cb"})})
	off, _, _ := c.svc.CreateClient(c.ctx, sys, c.a.ID, service.ClientInput{Name: ptr("Off"), GrantTypes: ptr([]string{"client_credentials"}), Enabled: ptr(false)})
	apps, err := c.svc.TokenApps(c.ctx, actor(c.aUser))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, a := range apps {
		ids[a.ID] = true
	}
	if !ids[app.ID] || ids[foreign.ID] || ids[pub.ID] || ids[off.ID] {
		t.Errorf("token apps %+v", apps)
	}
	if _, err := c.svc.TokenApps(c.ctx, service.System); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("system: %v", err)
	}
	if _, err := c.svc.TokenApps(c.ctx, &service.Actor{UserID: "ghost"}); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("ghost: %v", err)
	}
}

// A token's audience is the owner's organization's applications, for an api token, at most twenty, normalised; editing
// the audience checks the application scopes again.
func TestAPITokenAudienceRules(t *testing.T) {
	c := newCast(t)
	sys := service.System
	app, _, err := c.svc.CreateClient(c.ctx, sys, c.a.ID, service.ClientInput{Name: ptr("Orders"), GrantTypes: ptr([]string{"client_credentials"}),
		Scopes: ptr([]string{"orders:read", "orders:write"})})
	if err != nil {
		t.Fatal(err)
	}
	foreign, _, err := c.svc.CreateClient(c.ctx, sys, c.b.ID, service.ClientInput{Name: ptr("Theirs"), GrantTypes: ptr([]string{"client_credentials"}),
		Scopes: ptr([]string{"theirs:read"})})
	if err != nil {
		t.Fatal(err)
	}
	mk := func(in service.APITokenInput) error {
		in.Name = "t"
		_, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.aUser), in)
		return err
	}
	for name, in := range map[string]service.APITokenInput{
		"foreign client":   {Scopes: []string{"api"}, Audience: []string{foreign.ID}},
		"audience on scim": {Scopes: []string{"scim"}, Audience: []string{app.ID}},
		"bad scope syntax": {Scopes: []string{"api"}, Audience: []string{app.ID}, AppScopes: []string{"a b"}},
	} {
		if err := mk(in); !isInvalid(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	over := make([]string, 21)
	for i := range over {
		over[i] = "x" + strconv.Itoa(i)
	}
	if err := mk(service.APITokenInput{Scopes: []string{"api"}, Audience: over}); !isInvalid(err) {
		t.Errorf("too many audience: %v", err)
	}
	if err := mk(service.APITokenInput{Scopes: []string{"api"}, Audience: []string{app.ID, " " + app.ID, ""}, AppScopes: []string{"orders:read"}}); err != nil {
		t.Fatalf("a blank and a padded audience entry are normalised: %v", err)
	}
	tok, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.aUser), service.APITokenInput{Name: "t2", Scopes: []string{"api"}, Audience: []string{app.ID}, AppScopes: []string{"orders:read"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.UpdateAPIToken(c.ctx, actor(c.aUser), tok.ID, service.APITokenUpdate{Audience: &[]string{foreign.ID}}); !isInvalid(err) {
		t.Errorf("foreign audience on update: %v", err)
	}
	if _, err := c.svc.UpdateAPIToken(c.ctx, actor(c.aUser), tok.ID, service.APITokenUpdate{AppScopes: &[]string{"orders:delete"}}); !isInvalid(err) {
		t.Errorf("undeclared scope on update: %v", err)
	}
	if got, err := c.svc.UpdateAPIToken(c.ctx, actor(c.aUser), tok.ID, service.APITokenUpdate{AppScopes: &[]string{"orders:write"}}); err != nil || got.AppScopes[0] != "orders:write" {
		t.Errorf("update scopes: %v", err)
	}
	if len(c.audited(c.a.ID, "apitoken.update")) != 1 {
		t.Error("update not audited")
	}
}

// A token that stopped working when its owner's sign-in was reset cannot be given a new secret or new settings
// (they would never work): its owner deletes it and makes a new one.
func TestStaleTokenCannotBeRegeneratedOrUpdated(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "tok", model.RoleUser)
	a := service.ActorForUser(u, "")
	tok, _, err := e.svc.CreateAPIToken(e.ctx, a, service.APITokenInput{Name: "t", Scopes: []string{service.ScopeAPI}})
	if err != nil {
		t.Fatal(err)
	}
	fresh, _ := e.svc.Users.Get(e.ctx, u.ID)
	fresh.SetCredEpoch(service.NewCredEpoch()) // the sign-in was reset
	if err := e.svc.Users.Update(e.ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.RegenerateAPIToken(e.ctx, a, tok.ID); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("regenerate: %v", err)
	}
	name := "renamed"
	if _, err := e.svc.UpdateAPIToken(e.ctx, a, tok.ID, service.APITokenUpdate{Name: &name}); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("update: %v", err)
	}
}
