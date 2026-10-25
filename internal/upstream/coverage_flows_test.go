package upstream_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/upstream"
)

func TestBeginConnectAndFinish(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)
	u := e.mkUser(t, "connector", "c@example.com", true)

	authURL, state, err := e.up.BeginConnect(e.ctx, e.org, p, u, "/account")
	if err != nil {
		t.Fatal(err)
	}
	code := e.oidc.Authorize(authURL, std("conn-sub", "c@corp.example"))
	res, err := e.up.Finish(e.ctx, p.ID, state, state, code)
	if err != nil {
		t.Fatal(err)
	}
	if res.Connect != u.ID || res.User != nil || res.Claims.Subject != "conn-sub" || res.Next != "/account" {
		t.Fatalf("connect result %+v", res)
	}
	// Connecting links nothing by itself, and provisions nobody.
	if _, err := e.svc.Identities.GetByUnique(e.ctx, model.IdentityKey(p.ID, "conn-sub")); err == nil {
		t.Fatal("connect must leave the linking to the caller")
	}
	if n, _ := e.svc.Users.Count(e.ctx, e.org.ID); n != 1 {
		t.Fatalf("connect provisioned a user: %d users", n)
	}

	// A user of another organization cannot connect here.
	other, err := e.svc.CreateOrg(e.ctx, service.System, service.OrgInput{Name: ptr("other")})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.up.BeginConnect(e.ctx, other, p, u, ""); !errors.Is(err, upstream.ErrDisabled) {
		t.Fatalf("foreign org: %v", err)
	}
}

func TestBeginRefusesDisabledAndForeignProviders(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)
	other, _ := e.svc.CreateOrg(e.ctx, service.System, service.OrgInput{Name: ptr("other")})
	if _, _, err := e.up.BeginTenant(e.ctx, other, p, "", ""); !errors.Is(err, upstream.ErrDisabled) {
		t.Fatalf("provider of another org: %v", err)
	}
	if _, err := e.svc.UpdateProvider(e.ctx, service.System, p.ID, service.ProviderInput{Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	p, _ = e.svc.Providers.Get(e.ctx, p.ID)
	if _, _, err := e.up.BeginTenant(e.ctx, e.org, p, "", ""); !errors.Is(err, upstream.ErrDisabled) {
		t.Fatalf("disabled provider: %v", err)
	}
}

func TestCancelAndCancelTenant(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)

	_, state, err := e.up.BeginTenant(e.ctx, e.org, p, "/next", "blue")
	if err != nil {
		t.Fatal(err)
	}
	// A cookie that does not match leaves nothing usable behind.
	if _, _, _, ok := e.up.CancelTenant(e.ctx, p.ID, state, "other"); ok {
		t.Fatal("cancel with a foreign cookie")
	}
	if _, _, _, ok := e.up.CancelTenant(e.ctx, p.ID, state, state); ok {
		t.Fatal("state survived a refused cancel")
	}

	_, state, _ = e.up.BeginTenant(e.ctx, e.org, p, "/next", "blue")
	org, next, tenant, ok := e.up.CancelTenant(e.ctx, p.ID, state, state)
	if !ok || org.ID != e.org.ID || next != "/next" || tenant != "blue" {
		t.Fatalf("cancel tenant: %v %v %q %q", ok, org, next, tenant)
	}
	if _, _, _, ok := e.up.CancelTenant(e.ctx, p.ID, state, state); ok {
		t.Fatal("cancel twice")
	}

	_, state, _ = e.up.BeginTenant(e.ctx, e.org, p, "/n2", "")
	if org, next, _, ok := e.up.CancelTenant(e.ctx, p.ID, state, state); !ok || org.ID != e.org.ID || next != "/n2" {
		t.Fatalf("cancel: %v %v %q", ok, org, next)
	}
	// Another provider's callback cannot cancel it.
	other := e.oidcProvider(t, func(in *service.ProviderInput) { in.Name = ptr("Other SSO") })
	_, state, _ = e.up.BeginTenant(e.ctx, e.org, p, "", "")
	if _, _, _, ok := e.up.CancelTenant(e.ctx, other.ID, state, state); ok {
		t.Fatal("cancel through another provider's callback")
	}
	if _, _, _, ok := e.up.CancelTenant(e.ctx, p.ID, "n1.unknown", "n1.unknown"); ok {
		t.Fatal("cancel of an unknown state")
	}
}

func TestCallbackURL(t *testing.T) {
	e := setup(t)
	if got := e.up.CallbackURL("p 1"); got != "https://quisora.example.test/login/callback/p%201" {
		t.Fatalf("callback url %q", got)
	}
	if upstream.CallbackPath("abc") != "/login/callback/abc" {
		t.Fatal("callback path")
	}
}

func TestFinishWithoutCode(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)
	_, state, _ := e.up.BeginTenant(e.ctx, e.org, p, "/n", "")
	res, err := e.up.Finish(e.ctx, p.ID, state, state, "")
	if !errors.Is(err, upstream.ErrUpstream) || res == nil || res.Next != "/n" || res.Provider == nil {
		t.Fatalf("no code: %+v %v", res, err)
	}
}

// ID tokens signed with an algorithm the key cannot verify, or that is not on the list, never sign anybody in.
func TestIDTokenAlgorithmMismatch(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)
	for _, alg := range []string{"RS512", "RS384", "PS256", "ES384", "PS512", "EdDSA", "RS1"} {
		if _, err := e.signIn(p, map[string]any{"sub": "x", "email": "x@example.com", "email_verified": true, "_alg": alg}); !errors.Is(err, upstream.ErrUpstream) {
			t.Errorf("%s: want ErrUpstream, got %v", alg, err)
		}
	}
	// The EC key with an RSA algorithm, and the RSA key id with an EC algorithm.
	if _, err := e.signIn(p, map[string]any{"sub": "x", "_kid": "k1-ec"}); !errors.Is(err, upstream.ErrUpstream) {
		t.Errorf("EC key used for RS256: %v", err)
	}
	if _, err := e.signIn(p, map[string]any{"sub": "x", "_alg": "ES256", "_kid": "k1"}); !errors.Is(err, upstream.ErrUpstream) {
		t.Errorf("RSA key used for ES256: %v", err)
	}
	if n, _ := e.svc.Users.Count(e.ctx, e.org.ID); n != 0 {
		t.Fatalf("%d users provisioned", n)
	}
}

func TestTokenEndpointRejectsSecret(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, func(in *service.ProviderInput) { in.ClientSecret = ptr("wrong") })
	res, err := e.signIn(p, std("s", "s@example.com"))
	if !errors.Is(err, upstream.ErrUpstream) || res == nil || res.Provider == nil {
		t.Fatalf("wrong client secret: %+v %v", res, err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Fatalf("secret leaked into the error: %v", err)
	}
}
