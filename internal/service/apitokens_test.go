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
