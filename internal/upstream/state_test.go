package upstream_test

import (
	"errors"
	"net/url"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/upstream"
)

func TestConnectFlowLinksNothingAndRefusesForeignOrg(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)
	u := e.mkUser(t, "connector", "c@example.com", true)

	authURL, state, err := e.up.BeginConnect(e.ctx, e.org, p, u, "/account")
	if err != nil {
		t.Fatal(err)
	}
	code := e.oidc.Authorize(authURL, std("conn-sub", "c@corp.example"))
	res, err := e.up.Finish(e.ctx, e.org.ID, p.ID, state, state, code)
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

func TestCancelOnlyThroughOwnProviderAndCookie(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)

	_, state, err := e.up.BeginTenant(e.ctx, e.org, p, "/next", "blue")
	if err != nil {
		t.Fatal(err)
	}
	// A cookie that does not match leaves nothing usable behind.
	if _, _, _, ok := e.up.CancelTenant(e.ctx, e.org.ID, p.ID, state, "other"); ok {
		t.Fatal("cancel with a foreign cookie")
	}
	if _, _, _, ok := e.up.CancelTenant(e.ctx, e.org.ID, p.ID, state, state); ok {
		t.Fatal("state survived a refused cancel")
	}

	_, state, _ = e.up.BeginTenant(e.ctx, e.org, p, "/next", "blue")
	org, next, tenant, ok := e.up.CancelTenant(e.ctx, e.org.ID, p.ID, state, state)
	if !ok || org.ID != e.org.ID || next != "/next" || tenant != "blue" {
		t.Fatalf("cancel tenant: %v %v %q %q", ok, org, next, tenant)
	}
	if _, _, _, ok := e.up.CancelTenant(e.ctx, e.org.ID, p.ID, state, state); ok {
		t.Fatal("cancel twice")
	}

	_, state, _ = e.up.BeginTenant(e.ctx, e.org, p, "/n2", "")
	if org, next, _, ok := e.up.CancelTenant(e.ctx, e.org.ID, p.ID, state, state); !ok || org.ID != e.org.ID || next != "/n2" {
		t.Fatalf("cancel: %v %v %q", ok, org, next)
	}
	// Another provider's callback cannot cancel it.
	other := e.oidcProvider(t, func(in *service.ProviderInput) { in.Name = ptr("Other SSO") })
	_, state, _ = e.up.BeginTenant(e.ctx, e.org, p, "", "")
	if _, _, _, ok := e.up.CancelTenant(e.ctx, e.org.ID, other.ID, state, state); ok {
		t.Fatal("cancel through another provider's callback")
	}
	if _, _, _, ok := e.up.CancelTenant(e.ctx, e.org.ID, p.ID, "n1.unknown", "n1.unknown"); ok {
		t.Fatal("cancel of an unknown state")
	}
}

func TestFinishWithoutCode(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)
	_, state, _ := e.up.BeginTenant(e.ctx, e.org, p, "/n", "")
	res, err := e.up.Finish(e.ctx, e.org.ID, p.ID, state, state, "")
	if !errors.Is(err, upstream.ErrUpstream) || res == nil || res.Next != "/n" || res.Provider == nil {
		t.Fatalf("no code: %+v %v", res, err)
	}
}

func TestStateHandling(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)

	authURL, state, err := e.up.BeginTenant(e.ctx, e.org, p, "/n", "")
	if err != nil {
		t.Fatal(err)
	}
	code := e.oidc.Authorize(authURL, std("s1", "s1@example.com"))
	// Cookie that does not match the state: login CSRF.
	if _, err := e.up.Finish(e.ctx, e.org.ID, p.ID, state, "other", code); !errors.Is(err, upstream.ErrState) {
		t.Fatalf("cookie mismatch: %v", err)
	}
	// ...and the state is burnt, so the right cookie cannot rescue it.
	if _, err := e.up.Finish(e.ctx, e.org.ID, p.ID, state, state, code); !errors.Is(err, upstream.ErrState) {
		t.Fatalf("burnt state: %v", err)
	}

	authURL, state, _ = e.up.BeginTenant(e.ctx, e.org, p, "/n", "")
	code = e.oidc.Authorize(authURL, std("s1", "s1@example.com"))
	if _, err := e.up.Finish(e.ctx, e.org.ID, p.ID, state, state, code); err != nil {
		t.Fatal(err)
	}
	if _, err := e.up.Finish(e.ctx, e.org.ID, p.ID, state, state, code); !errors.Is(err, upstream.ErrState) {
		t.Fatalf("replay: %v", err)
	}
	if _, err := e.up.Finish(e.ctx, e.org.ID, p.ID, "n1.unknown", "n1.unknown", "x"); !errors.Is(err, upstream.ErrState) {
		t.Fatalf("unknown state: %v", err)
	}
	if _, err := e.up.Finish(e.ctx, e.org.ID, p.ID, "", "", ""); !errors.Is(err, upstream.ErrState) {
		t.Fatalf("empty state: %v", err)
	}
	// A response arriving at another provider's callback address is refused (IdP mix-up), and the state is burnt.
	other := e.oidcProvider(t, func(in *service.ProviderInput) { in.Name = ptr("Other SSO") })
	authURL, state, _ = e.up.BeginTenant(e.ctx, e.org, p, "/n", "")
	code = e.oidc.Authorize(authURL, std("s1", "s1@example.com"))
	if _, err := e.up.Finish(e.ctx, e.org.ID, other.ID, state, state, code); !errors.Is(err, upstream.ErrState) {
		t.Fatalf("other provider's callback: %v", err)
	}
	if _, err := e.up.Finish(e.ctx, e.org.ID, p.ID, state, state, code); !errors.Is(err, upstream.ErrState) {
		t.Fatalf("state reused after a mix-up: %v", err)
	}
}

// A response that arrives in another organization's address space is refused as a mix-up is, and the state is burnt:
// a callback address belongs to the organization of its provider.
func TestResponseAtAnotherOrganizationsCallbackIsRefused(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)
	other, err := e.svc.CreateOrg(e.ctx, service.System, service.OrgInput{Name: ptr("other")})
	if err != nil {
		t.Fatal(err)
	}
	authURL, state, _ := e.up.BeginTenant(e.ctx, e.org, p, "/n", "")
	code := e.oidc.Authorize(authURL, std("s1", "s1@example.com"))
	if _, err := e.up.Finish(e.ctx, other.ID, p.ID, state, state, code); !errors.Is(err, upstream.ErrState) {
		t.Fatalf("callback of another organization: %v", err)
	}
	if _, err := e.up.Finish(e.ctx, e.org.ID, p.ID, state, state, code); !errors.Is(err, upstream.ErrState) {
		t.Fatalf("state reused after a mix-up: %v", err)
	}
	_, state, _ = e.up.BeginTenant(e.ctx, e.org, p, "/n", "")
	if _, _, _, ok := e.up.CancelTenant(e.ctx, other.ID, p.ID, state, state); ok {
		t.Fatal("cancel through another organization's callback")
	}
	if _, _, _, ok := e.up.CancelTenant(e.ctx, e.org.ID, p.ID, state, state); ok {
		t.Fatal("state reused after a refused cancel")
	}
}

func TestPKCEIsEnforcedByProvider(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)
	authURL, state, _ := e.up.BeginTenant(e.ctx, e.org, p, "", "")
	u, _ := url.Parse(authURL)
	if u.Query().Get("redirect_uri") != "https://quisora.example.test/o/"+e.org.ID+"/login/callback/"+p.ID || u.Query().Get("state") != state {
		t.Fatalf("authorization url %s", authURL)
	}
	// The fake provider checks the verifier against the challenge; a normal sign-in passing proves the verifier is sent.
	if _, err := e.signIn(p, std("p1", "p1@example.com")); err != nil {
		t.Fatal(err)
	}
}
