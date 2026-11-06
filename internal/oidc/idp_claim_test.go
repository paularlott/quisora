package oidc

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// The idp claim names the type of the upstream provider a sign-in went through, so an application can tell a
// Microsoft sign-in from a Google one (amr says only "fed"). It is a claim of the idp scope, like the account there
// (idp_account_test.go): without the scope no token says it, and it can be asked for by name. It is carried from the
// session into the grant, so the tokens of a refresh say the same; a sign-in of Quisora's own has none.
func TestIdPClaimNamesTheUpstreamProvider(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ms, err := h.env.Svc.CreateProvider(context.Background(), service.System, h.env.Primary.ID, service.ProviderInput{
		Type: ptr(model.ProviderMicrosoft), Tenant: ptr("72f988bf-86f1-41af-91ab-2d7cd011db47"), ClientID: ptr("cid"),
		ClientSecret: ptr("secret")})
	if err != nil {
		t.Fatal(err)
	}
	cl, secret := h.newClient(func(in *service.ClientInput) {
		in.Scopes = &[]string{"openid", "profile", "idp", "offline_access"}
	})

	signIn := func(amr []string, provider, scope string, extra url.Values) tokResp {
		t.Helper()
		v, ch := pkce()
		q := url.Values{"scope": {scope}}
		for k, vs := range extra {
			q[k] = vs
		}
		code := h.getCode(h.sessionFor(amr, provider), cl, ch, q)
		r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
			"code_verifier": {v}}, cl, secret)
		if r.status != 200 {
			t.Fatalf("exchange: %d %v", r.status, r.m)
		}
		return r
	}
	idp := func(name string, m map[string]any, want bool) {
		t.Helper()
		got, ok := m["idp"]
		if want && got != model.ProviderMicrosoft {
			t.Errorf("%s: idp %v, want %q", name, got, model.ProviderMicrosoft)
		}
		if !want && ok {
			t.Errorf("%s: idp %v released", name, got)
		}
	}

	// with the idp scope: every token, userinfo and introspection, and again after a refresh
	r := signIn([]string{"fed"}, ms.ID, "openid idp offline_access", nil)
	idp("ID token", claimsOf(t, r.str("id_token")), true)
	idp("access token", claimsOf(t, r.str("access_token")), true)
	idp("userinfo", h.userinfo(r.str("access_token")), true)
	idp("introspection", h.introspect(cl, secret, r.str("access_token")), true)
	refreshed := h.refreshWith(cl, secret, r.str("refresh_token"))
	if refreshed.status != 200 {
		t.Fatalf("refresh: %d %v", refreshed.status, refreshed.m)
	}
	idp("refreshed ID token", claimsOf(t, refreshed.str("id_token")), true)
	idp("refreshed access token", claimsOf(t, refreshed.str("access_token")), true)

	// without it: nowhere, though amr still says it was a provider
	r = signIn([]string{"fed"}, ms.ID, "openid profile", nil)
	idt := claimsOf(t, r.str("id_token"))
	idp("ID token without the scope", idt, false)
	idp("access token without the scope", claimsOf(t, r.str("access_token")), false)
	idp("userinfo without the scope", h.userinfo(r.str("access_token")), false)
	idp("introspection without the scope", h.introspect(cl, secret, r.str("access_token")), false)
	if amr, _ := idt["amr"].([]any); len(amr) == 0 || amr[0] != "fed" {
		t.Errorf("amr without the scope: %v", idt["amr"])
	}

	// asked for by name, for the ID token: there and only there
	claims, _ := json.Marshal(map[string]any{"id_token": map[string]any{"idp": nil}})
	r = signIn([]string{"fed"}, ms.ID, "openid", url.Values{"claims": {string(claims)}})
	idt = claimsOf(t, r.str("id_token"))
	idp("ID token with idp asked for", idt, true)
	if idt["idp_sub"] != nil {
		t.Errorf("idp_sub released with only idp asked for: %v", idt["idp_sub"])
	}
	idp("userinfo with idp asked for the ID token", h.userinfo(r.str("access_token")), false)

	// a password sign-in: none, whatever the scope
	idp("password sign-in", claimsOf(t, signIn([]string{"pwd"}, "", "openid idp", nil).str("id_token")), false)
}
