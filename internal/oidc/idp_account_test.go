package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// withUpstreamAccount records on the session of browser c the account at the upstream provider it signed in with.
func (h *harness) withUpstreamAccount(c *http.Client, a *model.UpstreamAccount) {
	h.t.Helper()
	pu, _ := url.Parse(h.env.URL)
	for _, ck := range c.Jar.Cookies(pu) {
		if ck.Name == web.SessionCookieFor(h.env.Primary.ID) {
			s, err := h.env.Svc.Sessions.Get(context.Background(), web.SessionID(ck.Value))
			if err != nil {
				h.t.Fatal(err)
			}
			s.Upstream = a
			if err := h.env.Svc.Sessions.Update(context.Background(), s); err != nil {
				h.t.Fatal(err)
			}
			return
		}
	}
	h.t.Fatal("no session cookie")
}

// The idp scope says which account at the upstream provider a sign-in went through, as the provider names it: in the
// ID token, the access token (so userinfo and introspection can say it) and the tokens of a refresh. Without the scope
// none of it is released, a claim of it can be asked for by name, and a sign-in of Quisora's own has none.
func TestIdPScopeNamesTheUpstreamAccount(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	ms, err := h.env.Svc.CreateProvider(ctx, service.System, h.env.Primary.ID, service.ProviderInput{
		Type: ptr(model.ProviderMicrosoft), Tenant: ptr("72f988bf-86f1-41af-91ab-2d7cd011db47"), ClientID: ptr("cid"),
		ClientSecret: ptr("secret")})
	if err != nil {
		t.Fatal(err)
	}
	cl, secret := h.newClient(func(in *service.ClientInput) {
		in.Scopes = &[]string{"openid", "profile", "email", "idp", "offline_access"}
	})
	account := &model.UpstreamAccount{Subject: "0e4c2a1b-oid", Tenant: "72f988bf-86f1-41af-91ab-2d7cd011db47",
		Login: "ada@contoso.onmicrosoft.com"}
	want := map[string]any{"idp_sub": account.Subject, "idp_tenant": account.Tenant, "idp_login": account.Login}

	signIn := func(provider string, a *model.UpstreamAccount, scope string, extra url.Values) tokResp {
		t.Helper()
		c := h.sessionFor([]string{"fed"}, provider)
		if a != nil {
			h.withUpstreamAccount(c, a)
		}
		v, ch := pkce()
		q := url.Values{"scope": {scope}}
		for k, vs := range extra {
			q[k] = vs
		}
		code := h.getCode(c, cl, ch, q)
		r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
			"code_verifier": {v}}, cl, secret)
		if r.status != 200 {
			t.Fatalf("exchange: %d %v", r.status, r.m)
		}
		return r
	}
	has := func(name string, m map[string]any, wantAll bool) {
		t.Helper()
		for k, v := range want {
			got, ok := m[k]
			if wantAll && got != v {
				t.Errorf("%s: %s %v, want %v", name, k, got, v)
			}
			if !wantAll && ok {
				t.Errorf("%s: %s %v released", name, k, got)
			}
		}
	}

	r := signIn(ms.ID, account, "openid idp offline_access", nil)
	has("ID token", claimsOf(t, r.str("id_token")), true)
	has("access token", claimsOf(t, r.str("access_token")), true)
	has("userinfo", h.userinfo(r.str("access_token")), true)
	has("introspection", h.introspect(cl, secret, r.str("access_token")), true)
	refreshed := h.refreshWith(cl, secret, r.str("refresh_token"))
	if refreshed.status != 200 {
		t.Fatalf("refresh: %d %v", refreshed.status, refreshed.m)
	}
	has("refreshed ID token", claimsOf(t, refreshed.str("id_token")), true)
	has("refreshed access token", claimsOf(t, refreshed.str("access_token")), true)

	// without the scope: idp only
	r = signIn(ms.ID, account, "openid profile", nil)
	idt := claimsOf(t, r.str("id_token"))
	if idt["idp"] != model.ProviderMicrosoft {
		t.Errorf("idp %v", idt["idp"])
	}
	has("ID token without the scope", idt, false)
	has("access token without the scope", claimsOf(t, r.str("access_token")), false)
	has("userinfo without the scope", h.userinfo(r.str("access_token")), false)

	// one claim asked for by name, for userinfo: only it, and only there
	claims, _ := json.Marshal(map[string]any{"userinfo": map[string]any{"idp_login": nil}})
	r = signIn(ms.ID, account, "openid", url.Values{"claims": {string(claims)}})
	if _, ok := claimsOf(t, r.str("id_token"))["idp_login"]; ok {
		t.Error("idp_login asked for userinfo is in the ID token")
	}
	ui := h.userinfo(r.str("access_token"))
	if ui["idp_login"] != account.Login || ui["idp_sub"] != nil || ui["idp_tenant"] != nil {
		t.Errorf("userinfo with idp_login asked for: %v", ui)
	}

	// a password sign-in has none, whatever the scope
	pw := h.sessionFor([]string{"pwd"}, "")
	v, ch := pkce()
	code := h.getCode(pw, cl, ch, url.Values{"scope": {"openid idp"}})
	r = h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}, cl, secret)
	has("password sign-in", claimsOf(t, r.str("id_token")), false)
}

// The consent screen names the idp scope, and discovery lists it and its claims.
func TestIdPScopeIsDescribed(t *testing.T) {
	t.Parallel()
	if scopeDescriptions["idp"] == "" {
		t.Error("the idp scope has no consent description")
	}
	h := setup(t, nil)
	resp := h.get(h.http, h.orgBase+"/.well-known/openid-configuration")
	var d struct {
		Scopes []string `json:"scopes_supported"`
		Claims []string `json:"claims_supported"`
	}
	if err := json.Unmarshal([]byte(body(resp)), &d); err != nil {
		t.Fatal(err)
	}
	for _, s := range []struct {
		list []string
		v    string
	}{{d.Scopes, "idp"}, {d.Claims, "idp_sub"}, {d.Claims, "idp_tenant"}, {d.Claims, "idp_login"}} {
		found := false
		for _, x := range s.list {
			found = found || x == s.v
		}
		if !found {
			t.Errorf("discovery does not list %s", s.v)
		}
	}
}
