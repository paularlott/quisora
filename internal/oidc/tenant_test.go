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
)

func passkeyOnly() model.TenantSettings {
	return model.TenantSettings{PasskeyLogin: true, AllProviders: false}
}

// wantReauth asserts authorize sent the browser to sign in again for the tenant.
func wantReauth(t *testing.T, u *url.URL, path, tenant string) {
	t.Helper()
	if u.Path != path || u.Query().Get("reauth") != "1" || u.Query().Get("tenant") != tenant ||
		!strings.HasPrefix(u.Query().Get("next"), orgBase+"/oauth/authorize/resume") {
		t.Fatalf("expected reauth at %s for tenant %q: %s", path, tenant, u)
	}
}

func TestTenantPasskeyOnlyResume(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	tn := h.tenant("kiosk", passkeyOnly())
	cl, _ := h.tenantClient(tn, nil)
	def, _ := h.newClient(nil)
	_, ch := pkce()

	// not signed in: hand-off names the tenant
	u := h.authorize(h.anon(), authzQuery(cl, ch, nil))
	if u.Path != orgBase+"/login" || u.Query().Get("tenant") != "kiosk" || u.Query().Get("reauth") != "" {
		t.Fatalf("hand-off: %s", u)
	}
	// clients without a tenant use the default tenant
	if u := h.authorize(h.anon(), authzQuery(def, ch, nil)); u.Query().Get("tenant") != "default" {
		t.Fatalf("default tenant hand-off: %s", u)
	}

	pwd := h.sessionFor([]string{"pwd"}, "")
	wantReauth(t, h.authorize(pwd, authzQuery(cl, ch, nil)), orgBase+"/login", "kiosk")
	// the same password session is fine for the default tenant
	if u := h.authorize(pwd, authzQuery(def, ch, nil)); u.Query().Get("code") == "" {
		t.Fatalf("default tenant refused pwd session: %s", u)
	}
	// password + passkey second factor still counts as a password sign-in
	both := h.sessionFor([]string{"pwd", "swk", "user", "mfa"}, "")
	wantReauth(t, h.authorize(both, authzQuery(cl, ch, nil)), orgBase+"/login", "kiosk")
	// a federated session is not a passkey either
	wantReauth(t, h.authorize(h.sessionFor([]string{"fed"}, "x"), authzQuery(cl, ch, nil)), orgBase+"/login", "kiosk")

	pk := h.sessionFor([]string{"swk", "user"}, "")
	if u := h.authorize(pk, authzQuery(cl, ch, nil)); u.Query().Get("code") == "" {
		t.Fatalf("passkey session refused: %s", u)
	}
	// the org itself switching passwords off also refuses the default tenant
	h.setOrg(model.OrgSettings{PasswordLogin: false, PasskeyLogin: true})
	wantReauth(t, h.authorize(pwd, authzQuery(def, ch, nil)), orgBase+"/login", "default")
}

func TestTenantProviderRestrictions(t *testing.T) {
	t.Parallel()
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
	wantReauth(t, h.authorize(h.sessionFor([]string{"fed"}, bad.ID), authzQuery(cl, ch, nil)), orgBase+"/login", "sso")
	wantReauth(t, h.authorize(h.sessionFor([]string{"fed"}, ""), authzQuery(cl, ch, nil)), orgBase+"/login", "sso")
	// password is not allowed in this tenant (settings above have PasswordLogin false)
	wantReauth(t, h.authorize(h.sessionFor([]string{"pwd"}, ""), authzQuery(cl, ch, nil)), orgBase+"/login", "sso")

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
	t.Parallel()
	h := setup(t, nil)
	tn := h.tenant("secure", model.TenantSettings{PasswordLogin: true, PasskeyLogin: true, AllProviders: true, RequireMFA: true})
	cl, _ := h.tenantClient(tn, nil)
	def, _ := h.newClient(nil)
	_, ch := pkce()
	pwd := h.sessionFor([]string{"pwd"}, "")
	wantReauth(t, h.authorize(pwd, authzQuery(cl, ch, nil)), orgBase+"/login", "secure")
	if u := h.authorize(pwd, authzQuery(def, ch, nil)); u.Query().Get("code") == "" {
		t.Fatalf("org does not require MFA: %s", u)
	}
	if u := h.authorize(h.sessionFor([]string{"pwd", "otp", "mfa"}, ""), authzQuery(cl, ch, nil)); u.Query().Get("code") == "" {
		t.Fatalf("mfa session refused: %s", u)
	}
}

func TestTenantClaims(t *testing.T) {
	t.Parallel()
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
	ui := h.get(h.anon(), orgBase+"/oauth/userinfo", "Authorization", "Bearer "+r.str("access_token"))
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

func TestRequireMFA(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	_, ch := pkce()
	_, err := h.env.Svc.UpdateOrg(context.Background(), h.admin, h.env.Primary.ID, service.OrgInput{
		Settings: &model.OrgSettings{PasswordLogin: true, PasskeyLogin: true, RequireMFA: true}})
	if err != nil {
		t.Fatal(err)
	}
	h.env.Svc.InvalidateOrgs()
	weak := h.sessionWith(h.user, []string{"pwd"}, time.Now())
	u := h.authorize(weak, authzQuery(cl, ch, nil))
	if u.Path != orgBase+"/login" || u.Query().Get("reauth") != "1" {
		t.Fatalf("pwd only: %s", u)
	}
	// a passkey is two factors only when it verified its user
	if u := h.authorize(h.sessionWith(h.user, []string{"hwk"}, time.Now()), authzQuery(cl, ch, nil)); u.Query().Get("reauth") != "1" {
		t.Errorf("passkey without user verification accepted as MFA: %s", u)
	}
	for _, amr := range [][]string{{"pwd", "otp"}, {"hwk", "user"}, {"swk", "user"}, {"pwd", "mfa"}} {
		c := h.sessionWith(h.user, amr, time.Now())
		if u := h.authorize(c, authzQuery(cl, ch, nil)); u.Query().Get("code") == "" {
			t.Errorf("amr %v refused: %s", amr, u)
		}
	}
	// the sign-in loop is bounded when the requirement can never be met
	fu := h.authorize(weak, authzQuery(cl, ch, nil))
	flowURL := fu.Query().Get("next")
	for range 10 {
		body(h.get(weak, flowURL))
	}
	if resp := h.get(weak, flowURL); resp.StatusCode != 400 && resp.StatusCode != 403 {
		t.Fatalf("loop not bounded: %d %s %s", resp.StatusCode, flowURL, body(resp))
	}
}
