package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

func (h *harness) tenant(name string, set model.TenantSettings) *model.Tenant {
	h.t.Helper()
	tn, err := h.env.Svc.CreateTenant(context.Background(), h.admin, h.env.Primary.ID,
		service.TenantInput{Name: ptr(name), Settings: &set})
	if err != nil {
		h.t.Fatal(err)
	}
	return tn
}

func (h *harness) tenantClient(tn *model.Tenant, edit func(*service.ClientInput)) (*model.Client, string) {
	h.t.Helper()
	return h.newClient(func(in *service.ClientInput) {
		in.TenantID = &tn.ID
		if edit != nil {
			edit(in)
		}
	})
}

// sessionFor signs the user in with the given amr and upstream provider.
func (h *harness) sessionFor(amr []string, provider string) *http.Client {
	h.t.Helper()
	c := h.sessionWith(h.user, amr, time.Now())
	pu, _ := url.Parse(h.env.URL)
	for _, ck := range c.Jar.Cookies(pu) {
		if ck.Name == web.SessionCookie {
			id := web.SessionID(ck.Value)
			s, err := h.env.Svc.Sessions.Get(context.Background(), id)
			if err != nil {
				h.t.Fatal(err)
			}
			s.Provider = provider
			if err := h.env.Svc.Sessions.Update(context.Background(), s); err != nil {
				h.t.Fatal(err)
			}
			h.env.Server.Sessions.Evict(id, "")
		}
	}
	return c
}

func passkeyOnly() model.TenantSettings {
	return model.TenantSettings{PasskeyLogin: true, AllProviders: false}
}

// wantReauth asserts authorize sent the browser to sign in again for the tenant.
func wantReauth(t *testing.T, u *url.URL, path, tenant string) {
	t.Helper()
	if u.Path != path || u.Query().Get("reauth") != "1" || u.Query().Get("tenant") != tenant ||
		!strings.HasPrefix(u.Query().Get("next"), "/oauth/authorize/resume") {
		t.Fatalf("expected reauth at %s for tenant %q: %s", path, tenant, u)
	}
}

func TestTenantPasskeyOnlyResume(t *testing.T) {
	h := setup(t, nil)
	tn := h.tenant("kiosk", passkeyOnly())
	cl, _ := h.tenantClient(tn, nil)
	def, _ := h.newClient(nil)
	_, ch := pkce()

	// not signed in: hand-off names the tenant
	u := h.authorize(h.anon(), authzQuery(cl, ch, nil))
	if u.Path != "/login/primary" || u.Query().Get("tenant") != "kiosk" || u.Query().Get("reauth") != "" {
		t.Fatalf("hand-off: %s", u)
	}
	// clients without a tenant use the default tenant
	if u := h.authorize(h.anon(), authzQuery(def, ch, nil)); u.Query().Get("tenant") != "default" {
		t.Fatalf("default tenant hand-off: %s", u)
	}

	pwd := h.sessionFor([]string{"pwd"}, "")
	wantReauth(t, h.authorize(pwd, authzQuery(cl, ch, nil)), "/login/primary", "kiosk")
	// the same password session is fine for the default tenant
	if u := h.authorize(pwd, authzQuery(def, ch, nil)); u.Query().Get("code") == "" {
		t.Fatalf("default tenant refused pwd session: %s", u)
	}
	// password + passkey second factor still counts as a password sign-in
	both := h.sessionFor([]string{"pwd", "swk", "user", "mfa"}, "")
	wantReauth(t, h.authorize(both, authzQuery(cl, ch, nil)), "/login/primary", "kiosk")
	// a federated session is not a passkey either
	wantReauth(t, h.authorize(h.sessionFor([]string{"fed"}, "x"), authzQuery(cl, ch, nil)), "/login/primary", "kiosk")

	pk := h.sessionFor([]string{"swk", "user"}, "")
	if u := h.authorize(pk, authzQuery(cl, ch, nil)); u.Query().Get("code") == "" {
		t.Fatalf("passkey session refused: %s", u)
	}
	// the org itself switching passwords off also refuses the default tenant
	h.setOrg(model.OrgSettings{PasswordLogin: false, PasskeyLogin: true})
	wantReauth(t, h.authorize(pwd, authzQuery(def, ch, nil)), "/login/primary", "default")
}

func (h *harness) setOrg(s model.OrgSettings) {
	h.t.Helper()
	if _, err := h.env.Svc.UpdateOrg(context.Background(), h.admin, h.env.Primary.ID, service.OrgInput{Settings: &s}); err != nil {
		h.t.Fatal(err)
	}
	h.p.InvalidateOrg(h.env.Primary.ID)
}

func TestTenantProviderRestrictions(t *testing.T) {
	h := setup(t, nil)
	mk := func(name string) *model.Provider {
		p, err := h.env.Svc.CreateProvider(context.Background(), service.System, h.env.Primary.ID, service.ProviderInput{
			Type: ptr(model.ProviderOIDC), Name: ptr(name), Issuer: ptr("https://quisora.example/" + name), ClientID: ptr("cid"),
			ClientSecret: ptr("secret")})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	good, bad := mk("good"), mk("bad")
	tn := h.tenant("sso", model.TenantSettings{AllProviders: false, Providers: []string{good.ID}})
	cl, _ := h.tenantClient(tn, nil)
	_, ch := pkce()

	if u := h.authorize(h.sessionFor([]string{"fed"}, good.ID), authzQuery(cl, ch, nil)); u.Query().Get("code") == "" {
		t.Fatalf("allowed provider refused: %s", u)
	}
	wantReauth(t, h.authorize(h.sessionFor([]string{"fed"}, bad.ID), authzQuery(cl, ch, nil)), "/login/primary", "sso")
	wantReauth(t, h.authorize(h.sessionFor([]string{"fed"}, ""), authzQuery(cl, ch, nil)), "/login/primary", "sso")
	// password is not allowed in this tenant (settings above have PasswordLogin false)
	wantReauth(t, h.authorize(h.sessionFor([]string{"pwd"}, ""), authzQuery(cl, ch, nil)), "/login/primary", "sso")

	// all providers: both work
	all := h.tenant("any", model.TenantSettings{AllProviders: true})
	cl2, _ := h.tenantClient(all, nil)
	for _, p := range []*model.Provider{good, bad} {
		if u := h.authorize(h.sessionFor([]string{"fed"}, p.ID), authzQuery(cl2, ch, nil)); u.Query().Get("code") == "" {
			t.Fatalf("provider %s refused: %s", p.Name, u)
		}
	}
}

func TestTenantRequireMFA(t *testing.T) {
	h := setup(t, nil)
	tn := h.tenant("secure", model.TenantSettings{PasswordLogin: true, PasskeyLogin: true, AllProviders: true, RequireMFA: true})
	cl, _ := h.tenantClient(tn, nil)
	def, _ := h.newClient(nil)
	_, ch := pkce()
	pwd := h.sessionFor([]string{"pwd"}, "")
	wantReauth(t, h.authorize(pwd, authzQuery(cl, ch, nil)), "/login/primary", "secure")
	if u := h.authorize(pwd, authzQuery(def, ch, nil)); u.Query().Get("code") == "" {
		t.Fatalf("org does not require MFA: %s", u)
	}
	if u := h.authorize(h.sessionFor([]string{"pwd", "otp", "mfa"}, ""), authzQuery(cl, ch, nil)); u.Query().Get("code") == "" {
		t.Fatalf("mfa session refused: %s", u)
	}
}

func TestTenantClaims(t *testing.T) {
	h := setup(t, nil)
	tn := h.tenant("kiosk", passkeyOnly())
	cl, secret := h.tenantClient(tn, nil)
	def, dsecret := h.newClient(nil)

	exchange := func(cl *model.Client, secret string, c *http.Client) tokResp {
		v, ch := pkce()
		code := h.getCode(c, cl, ch, url.Values{"scope": {"openid profile email org offline_access"}})
		r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
			"code_verifier": {v}}, cl, secret)
		if r.status != 200 {
			t.Fatalf("exchange: %d %v", r.status, r.m)
		}
		return r
	}
	r := exchange(cl, secret, h.sessionFor([]string{"swk", "user"}, ""))
	for name, tok := range map[string]string{"access": r.str("access_token"), "id": r.str("id_token")} {
		c := claimsOf(t, tok)
		if c["tenant"] != tn.ID || c["tenant_name"] != "kiosk" || c["org"] != h.env.Primary.ID {
			t.Errorf("%s token claims: %v", name, c)
		}
	}
	ui := h.get(h.anon(), "/oauth/userinfo", "Authorization", "Bearer "+r.str("access_token"))
	b := body(ui)
	if !strings.Contains(b, `"tenant_name":"kiosk"`) || !strings.Contains(b, `"tenant":"`+tn.ID+`"`) {
		t.Errorf("userinfo: %s", b)
	}
	in := h.introspect(cl, secret, r.str("access_token"))
	if in["tenant"] != tn.ID || in["tenant_name"] != "kiosk" {
		t.Errorf("introspect: %v", in)
	}
	// refresh keeps the claims
	rr := h.refreshWith(cl, secret, r.str("refresh_token"))
	if rr.status != 200 || claimsOf(t, rr.str("access_token"))["tenant_name"] != "kiosk" {
		t.Errorf("refresh: %v", rr.m)
	}
	// client_credentials too, and clients without a tenant carry the default tenant
	cc := h.token(url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, def, dsecret)
	if c := claimsOf(t, cc.str("access_token")); c["tenant_name"] != "default" || c["tenant"] == "" {
		t.Errorf("default tenant claims: %v", c)
	}
}
