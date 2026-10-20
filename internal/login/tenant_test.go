package login_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func (e *env) tenant(t testing.TB, org *model.Org, name string, set model.TenantSettings) *model.Tenant {
	t.Helper()
	tn, err := e.Svc.CreateTenant(context.Background(), service.System, org.ID,
		service.TenantInput{Name: ptr(name), Settings: &set})
	if err != nil {
		t.Fatal(err)
	}
	return tn
}

const passwordForm = `autocomplete="current-password"`

func TestTenantPasswordRefused(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	e.user(t, org, "pat", model.RoleUser)
	e.tenant(t, org, "kiosk", model.TenantSettings{PasskeyLogin: true, AllProviders: true})
	b := e.browser(t)

	// the page for the tenant offers no password form; the org's own page and an unknown tenant do
	_, page := b.get("/login/acme?tenant=kiosk")
	if strings.Contains(page, passwordForm) || !strings.Contains(page, `data-tenant="kiosk"`) {
		t.Fatalf("kiosk page: %.1500s", page)
	}
	for _, p := range []string{"/login/acme", "/login/acme?tenant=nope", "/login/acme?tenant=" + strings.Repeat("x", 200),
		"/login/acme?tenant=Kiosk%00"} {
		if _, page := b.get(p); !strings.Contains(page, passwordForm) {
			t.Fatalf("%s: no password form", p)
		}
	}

	// calling the API directly is refused with the same failure as a wrong password
	res, out := b.post("/api/login/password", map[string]any{"org": "acme", "email": "pat@example.com", "password": userPassword, "tenant": "kiosk"})
	wantStatus(t, res, out, 401)
	if str(out, "error") != "The email address or password is incorrect." || b.hasSession() {
		t.Fatalf("refusal shape: %v session=%v", out, b.hasSession())
	}
	// an unknown tenant is ignored (org methods)
	res, out = b.post("/api/login/password", map[string]any{"org": "acme", "email": "pat@example.com", "password": userPassword, "tenant": "nope"})
	wantStatus(t, res, out, 200)
	// and the tenant's name resolves case-insensitively
	b2 := e.browser(t)
	res, out = b2.post("/api/login/password", map[string]any{"org": "acme", "email": "pat@example.com", "password": userPassword, "tenant": " KIOSK "})
	wantStatus(t, res, out, 401)
	// tenants of another org do not apply
	other := e.org(t, "other", nil)
	e.tenant(t, other, "kiosk2", model.TenantSettings{PasskeyLogin: true, AllProviders: true})
	b3 := e.browser(t)
	res, out = b3.post("/api/login/password", map[string]any{"org": "acme", "email": "pat@example.com", "password": userPassword, "tenant": "kiosk2"})
	wantStatus(t, res, out, 200)
}

func TestTenantPasskeyRestricted(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	e.tenant(t, org, "pwonly", model.TenantSettings{PasswordLogin: true, AllProviders: true})
	e.tenant(t, org, "pkonly", model.TenantSettings{PasskeyLogin: true, AllProviders: true})
	signed := e.signedIn(t, pat)
	signed.registerPasskey("Laptop")

	b := e.browser(t)
	b.auth = signed.auth
	if _, page := b.get("/login/acme?tenant=pwonly"); strings.Contains(page, `data-passkey="1"`) || strings.Contains(page, "Sign in with a passkey") {
		t.Fatal("password-only tenant page offers passkeys")
	}
	if _, page := b.get("/login/acme?tenant=pkonly"); !strings.Contains(page, `data-passkey="1"`) {
		t.Fatal("passkey tenant page lacks passkeys")
	}
	// begin with an org refuses
	status, out := b.passkeyLogin(map[string]any{"org": "acme", "tenant": "pwonly"})
	if status != 403 || b.hasSession() {
		t.Fatalf("org begin: %d %v", status, out)
	}
	// an org-less (landing page) ceremony is refused at finish, in the user's org
	status, out = b.passkeyLogin(map[string]any{"tenant": "pwonly"})
	if status != 403 || b.hasSession() {
		t.Fatalf("org-less finish: %d %v", status, out)
	}
	status, out = b.passkeyLogin(map[string]any{"org": "acme", "tenant": "pkonly"})
	if status != 200 || !b.hasSession() {
		t.Fatalf("allowed tenant: %d %v", status, out)
	}
	// without a tenant the org's methods apply
	b2 := e.browser(t)
	b2.auth = signed.auth
	if status, out = b2.passkeyLogin(map[string]any{"org": "acme"}); status != 200 {
		t.Fatalf("no tenant: %d %v", status, out)
	}
}

func TestTenantRequireMFAOnly(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	e.user(t, org, "pat", model.RoleUser)
	e.tenant(t, org, "secure", model.TenantSettings{PasswordLogin: true, PasskeyLogin: true, AllProviders: true, RequireMFA: true})

	b := e.browser(t)
	res, out := b.post("/api/login/password", map[string]any{"org": "acme", "email": "pat@example.com", "password": userPassword, "tenant": "secure"})
	wantStatus(t, res, out, 200)
	if str(out, "step") != "enrol" || str(out, "ticket") == "" || b.hasSession() {
		t.Fatalf("tenant MFA: %v", out)
	}
	// the org itself does not require it
	b2 := e.browser(t)
	res, out = b2.login("acme", "pat", userPassword)
	wantStatus(t, res, out, 200)
	if str(out, "step") != "" || !b2.hasSession() {
		t.Fatalf("org sign-in: %v", out)
	}
}

func TestTenantProviders(t *testing.T) {
	u := newUpEnv(t, nil)
	good := u.oidcProvider(t, nil)
	bad := u.oidcProvider(t, func(in *service.ProviderInput) { in.Name = ptr("Other SSO"); in.ClientID = ptr("cid2") })
	u.tenant(t, u.org, "sso", model.TenantSettings{AllProviders: false, Providers: []string{good.ID}})
	b := u.browser(t)

	_, page := b.get("/login/acme?tenant=sso")
	if !strings.Contains(page, "Continue with Corp SSO") || strings.Contains(page, "Continue with Other SSO") ||
		strings.Contains(page, passwordForm) || !strings.Contains(page, "tenant=sso") {
		t.Fatalf("sso page: %.2500s", page)
	}
	_, page = b.get("/login/acme")
	if !strings.Contains(page, "Continue with Other SSO") {
		t.Fatal("org page lacks the second provider")
	}

	// a provider the tenant does not allow is refused at start: back to the page with an error, no upstream hop
	res, _ := b.get("/login/acme/provider/" + bad.ID + "?tenant=sso&next=%2Fx")
	loc := res.Header.Get("Location")
	if res.StatusCode != 302 || !strings.HasPrefix(loc, "/login/acme?") || !strings.Contains(loc, "error=disabled") ||
		!strings.Contains(loc, "tenant=sso") {
		t.Fatalf("disallowed provider start: %d %q", res.StatusCode, loc)
	}
	// without the tenant it is allowed
	if res, _ = b.get("/login/acme/provider/" + bad.ID); !strings.HasPrefix(res.Header.Get("Location"), u.oidc.Srv.URL) {
		t.Fatalf("org-level start: %q", res.Header.Get("Location"))
	}

	// allowed provider: signs in and the session records the provider
	b2 := u.browser(t)
	res = b2.viaTenant(t, u, good, "acme", "sso", "/x", claims("sub-9", "kim@corp.example"))
	if res.StatusCode != 303 || res.Header.Get("Location") != "/x" || !b2.hasSession() {
		t.Fatalf("callback: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	user, err := u.Svc.FindUserByEmail(context.Background(), u.org.ID, "kim@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	sess := sessionsOf(t, u.env, user)
	if len(sess) != 1 || sess[0].Provider != good.ID || strings.Join(sess[0].AMR, ",") != "fed" {
		t.Fatalf("session %+v", sess)
	}

	// the tenant changing between start and callback is honoured
	b3 := u.browser(t)
	start, _ := b3.get("/login/acme/provider/" + good.ID + "?tenant=sso")
	loc = start.Header.Get("Location")
	lu, _ := url.Parse(loc)
	code := u.oidc.Authorize(loc, claims("sub-9", "kim@corp.example"))
	tn, _ := u.Svc.Tenants.GetByUnique(context.Background(), model.TenantNameKey(u.org.ID, "sso"))
	tn.Settings = model.TenantSettings{PasswordLogin: true, AllProviders: false}
	if err := u.Svc.Tenants.Update(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	res, _ = b3.get("/login/callback/" + good.ID + "?state=" + url.QueryEscape(lu.Query().Get("state")) + "&code=" + url.QueryEscape(code))
	loc = res.Header.Get("Location")
	if !strings.Contains(loc, "error=disabled") || !strings.Contains(loc, "tenant=sso") || b3.hasSession() {
		t.Fatalf("callback after tenant change: %d %q session=%v", res.StatusCode, loc, b3.hasSession())
	}
}
