package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// The idp claim names the type of the upstream provider a sign-in went through, so an application can tell a
// Microsoft sign-in from a Google one (amr says only "fed"). It is carried from the session into the grant, so the
// tokens of a refresh, and those exchanged from them, say the same; a sign-in of Quisora's own has none.
func TestIdPClaimNamesTheUpstreamProvider(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ms, err := h.env.Svc.CreateProvider(context.Background(), service.System, h.env.Primary.ID, service.ProviderInput{
		Type: ptr(model.ProviderMicrosoft), Tenant: ptr("72f988bf-86f1-41af-91ab-2d7cd011db47"), ClientID: ptr("cid"),
		ClientSecret: ptr("secret")})
	if err != nil {
		t.Fatal(err)
	}
	cl, secret := h.newClient(nil)

	signIn := func(amr []string, provider string) tokResp {
		t.Helper()
		v, ch := pkce()
		code := h.getCode(h.sessionFor(amr, provider), cl, ch, nil)
		r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
			"code_verifier": {v}}, cl, secret)
		if r.status != 200 {
			t.Fatalf("exchange: %d %v", r.status, r.m)
		}
		return r
	}

	r := signIn([]string{"fed"}, ms.ID)
	for name, tok := range map[string]string{"ID token": r.str("id_token"), "access token": r.str("access_token")} {
		if got := claimsOf(t, tok)["idp"]; got != model.ProviderMicrosoft {
			t.Errorf("%s: idp %v, want %q", name, got, model.ProviderMicrosoft)
		}
	}
	refreshed := h.refreshWith(cl, secret, r.str("refresh_token"))
	if refreshed.status != 200 {
		t.Fatalf("refresh: %d %v", refreshed.status, refreshed.m)
	}
	if got := claimsOf(t, refreshed.str("id_token"))["idp"]; got != model.ProviderMicrosoft {
		t.Errorf("refreshed ID token: idp %v", got)
	}

	// A password sign-in: no claim.
	if _, ok := claimsOf(t, signIn([]string{"pwd"}, "").str("id_token"))["idp"]; ok {
		t.Error("a password sign-in has an idp claim")
	}
}
