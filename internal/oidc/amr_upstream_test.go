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
// reported (its ID token's amr): an application sees how the person signed in to Microsoft. A token says "mfa" only
// when Quisora's own references do (it asked for a second factor, or trusts the provider's), never on the provider's
// word, and acr is decided from Quisora's own alone. The provider's references stay with the grant: refreshed and
// exchanged tokens say the same.
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

	// Microsoft said password and MFA; Quisora, not trusting it for the second factor, asked for none: no mfa
	r := signIn([]string{"fed"}, []string{"pwd", "mfa"})
	want := []string{"fed", "pwd"}
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

	// a provider trusted for the second factor, which said it used one: mfa, Quisora's own
	r = signIn([]string{"fed", "mfa"}, []string{"pwd", "mfa"})
	check("trusted provider", r.str("id_token"), []string{"fed", "mfa", "pwd"}, acrMFA)

	// a provider that says nothing (GitHub, Google) leaves Quisora's own
	r = signIn([]string{"fed"}, nil)
	check("no upstream amr", r.str("id_token"), []string{"fed"}, acrBasic)

	// a provider that spells its second factor out (password and code, a passkey that verified its user): no second
	// factor in the tokens either, so the provider's references are left out
	for _, up := range [][]string{{"pwd", "otp"}, {"swk", "user"}} {
		r = signIn([]string{"fed"}, up)
		check("provider's "+strings.Join(up, "+")+", ID token", r.str("id_token"), []string{"fed"}, acrBasic)
		check("provider's "+strings.Join(up, "+")+", access token", r.str("access_token"), []string{"fed"}, acrBasic)
	}
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
		if got := amrOf(t, tok); slices.Contains(got, "mfa") != slices.Contains(amr, "mfa") {
			t.Fatalf("the token's amr %v: mfa only where Quisora's own %v has it", got, amr)
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

// A device sign-in approved in a browser that signed in through a provider carries what the provider said into the
// device's tokens and its refresh grant, as a browser sign-in does.
func TestDeviceGrantPassesUpstreamAMROn(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ms := h.microsoft()
	cl := h.deviceClient(func(in *service.ClientInput) { in.Scopes = &[]string{"openid", "idp", "offline_access"} })
	dc, uc := h.startDevice(cl, "openid idp offline_access")
	b, csrf := h.session(h.user)
	h.signedInThrough(b, ms.ID, []string{"pwd", "mfa"}, "fed")
	if status, page := h.consentDevice(b, csrf, uc, true); status != 200 || !strings.Contains(page, "Your device is signed in") {
		t.Fatalf("approving: %d %s", status, page)
	}
	r := h.pollDevice(cl, dc)
	if r.status != 200 {
		t.Fatalf("tokens: %d %v", r.status, r.m)
	}
	want := []string{"fed", "pwd"}
	for name, tok := range map[string]string{"ID token": r.str("id_token"), "access token": r.str("access_token")} {
		c := claimsOf(t, tok)
		if got := amrOf(t, tok); !slices.Equal(got, want) || c["acr"] != acrBasic || c["idp"] != model.ProviderMicrosoft {
			t.Errorf("%s: amr %v acr %v idp %v", name, got, c["acr"], c["idp"])
		}
	}
	refreshed := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r.str("refresh_token")}}, cl, "")
	if refreshed.status != 200 {
		t.Fatalf("refresh: %d %v", refreshed.status, refreshed.m)
	}
	if got := amrOf(t, refreshed.str("access_token")); !slices.Equal(got, want) {
		t.Errorf("refreshed: amr %v", got)
	}
}

// The idp claim is kept with the grant for good, so a provider that cannot be read is not taken for "no provider":
// the sign-in is answered server_error, to be tried again, rather than given tokens without idp. A provider removed
// since the sign-in gives none.
func TestIdPClaimFailsClosedOnAProviderReadFailure(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ms := h.microsoft()
	cl, _ := h.newClient(nil)
	c := h.sessionFor([]string{"fed"}, ms.ID)
	_, ch := pkce()

	good := h.env.Svc.Providers.S
	h.env.Svc.Providers.S = failReads(good, model.KindProvider)
	u := h.authorize(c, authzQuery(cl, ch, nil))
	h.env.Svc.Providers.S = good
	if u.Query().Get("code") != "" || u.Query().Get("error") != "server_error" {
		t.Fatalf("a provider that cannot be read: %s", u)
	}
	if code := h.getCode(c, cl, ch, nil); code == "" {
		t.Fatal("no code once the provider can be read")
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
