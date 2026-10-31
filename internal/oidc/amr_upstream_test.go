package oidc

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// microsoft adds a Microsoft provider to the primary organization.
func (h *harness) microsoft() *model.Provider {
	h.t.Helper()
	ms, err := h.env.Svc.CreateProvider(context.Background(), service.System, h.env.Primary.ID, service.ProviderInput{
		Type: ptr(model.ProviderMicrosoft), Tenant: ptr("72f988bf-86f1-41af-91ab-2d7cd011db47"), ClientID: ptr("cid"),
		ClientSecret: ptr("secret")})
	if err != nil {
		h.t.Fatal(err)
	}
	return ms
}

func amrOf(t *testing.T, tok string) []string {
	t.Helper()
	var out []string
	list, _ := claimsOf(t, tok)["amr"].([]any)
	for _, v := range list {
		out = append(out, v.(string))
	}
	return out
}

// After a sign-in through an upstream provider the tokens' amr is Quisora's own references, then those the provider
// reported (its ID token's amr): an application sees how the person signed in to Microsoft. acr is decided from
// Quisora's own alone, so a provider's "mfa" never makes a token claim the second factor Quisora did not ask for or
// trust. The provider's references stay with the grant: refreshed and exchanged tokens say the same.
func TestUpstreamAMRIsPassedOn(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ms := h.microsoft()
	cl, secret := h.newClient(nil)
	api, apiSecret := h.newClient(func(in *service.ClientInput) {
		withExchange(in)
		in.IntrospectOrg = ptr(true)
		in.Scopes = &[]string{"openid", "api"}
		in.Resources = &[]string{"https://api.example/b"}
	})

	signIn := func(amr, upstream []string) tokResp {
		t.Helper()
		c := h.sessionWith(h.user, amr, time.Now())
		h.signedInThrough(c, ms.ID, upstream)
		v, ch := pkce()
		code := h.getCode(c, cl, ch, url.Values{"scope": {"openid api offline_access"}})
		r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
			"code_verifier": {v}}, cl, secret)
		if r.status != 200 {
			t.Fatalf("exchange: %d %v", r.status, r.m)
		}
		return r
	}
	check := func(what, tok string, amr []string, acr string) {
		t.Helper()
		if got := amrOf(t, tok); !slices.Equal(got, amr) {
			t.Errorf("%s: amr %v, want %v", what, got, amr)
		}
		if got := claimsOf(t, tok)["acr"]; got != acr {
			t.Errorf("%s: acr %v, want %q", what, got, acr)
		}
	}

	// Microsoft said password and MFA; Quisora, not trusting it for the second factor, verified neither
	r := signIn([]string{"fed"}, []string{"pwd", "mfa"})
	want := []string{"fed", "pwd", "mfa"}
	check("ID token", r.str("id_token"), want, acrBasic)
	check("access token", r.str("access_token"), want, acrBasic)
	if m := h.introspect(api, apiSecret, r.str("access_token")); !slices.Equal(anyStrings(m["amr"]), want) {
		t.Errorf("introspection amr %v", m["amr"])
	}
	refreshed := h.refreshWith(cl, secret, r.str("refresh_token"))
	if refreshed.status != 200 {
		t.Fatalf("refresh: %d %v", refreshed.status, refreshed.m)
	}
	check("refreshed ID token", refreshed.str("id_token"), want, acrBasic)
	x := h.exchange(api, apiSecret, r.str("access_token"), url.Values{"resource": {"https://api.example/b"}})
	if x.status != 200 {
		t.Fatalf("token exchange: %d %v", x.status, x.m)
	}
	check("exchanged token", x.str("access_token"), want, acrBasic)

	// Quisora asked for its own second factor after the provider: that is the MFA, the provider's references follow
	r = signIn([]string{"fed", "otp", "mfa"}, []string{"pwd", "mfa"})
	check("after Quisora's code", r.str("id_token"), []string{"fed", "otp", "mfa", "pwd"}, acrMFA)

	// a provider that says nothing (GitHub, Google) leaves Quisora's own
	r = signIn([]string{"fed"}, nil)
	check("no upstream amr", r.str("id_token"), []string{"fed"}, acrBasic)
}

// The SSH sign endpoint asks for a second factor of the token's sign-in as Quisora saw it (the grant's amr), never
// from the token's amr claim, which carries what the upstream provider said: a provider's "mfa" alone gets no
// certificate, Quisora's own code after it does.
func TestSSHSignIgnoresUpstreamMFA(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ms := h.microsoft()
	e := h.sshTenant("prod", service.SSHSettingsInput{})
	key, _ := sshKey(t)

	tokenFrom := func(amr []string) string {
		t.Helper()
		c := e.sessionWith(h.user, amr, time.Now())
		h.signedInThrough(c, ms.ID, []string{"pwd", "mfa"})
		tok := e.tokenIn(e.cl, c, nil).str("access_token")
		if got := amrOf(t, tok); !slices.Contains(got, "mfa") {
			t.Fatalf("test set-up: the token's amr %v carries no mfa", got)
		}
		return tok
	}
	st, m, _ := e.sign(tokenFrom([]string{"fed"}), map[string]any{"public_key": key})
	if desc, _ := m["error_description"].(string); st != 403 || !strings.Contains(desc, "second factor") {
		t.Errorf("the provider's mfa alone: %d %v", st, m)
	}
	if st, m, _ := e.sign(tokenFrom([]string{"fed", "otp", "mfa"}), map[string]any{"public_key": key}); st != 200 {
		t.Errorf("Quisora's own code after the provider: %d %v", st, m)
	}
}

func anyStrings(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, x := range list {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}
