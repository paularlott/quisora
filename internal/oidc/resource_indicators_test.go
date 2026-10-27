package oidc

import (
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// Resource indicators (RFC 8707) at the authorization, token and refresh endpoints.
func TestResourceIndicators(t *testing.T) {
	t.Parallel()
	t.Run("code exchange", func(t *testing.T) {
		h := setup(t, nil)
		cl, secret := h.newClient(nil)
		c, _ := h.session(h.user)
		v, ch := pkce()
		code := h.getCode(c, cl, ch, url.Values{"resource": {"https://api.example/a", "https://api.example/b"}})
		// asking for a resource that was not authorized is refused
		r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}, "resource": {"https://evil.example"}}, cl, secret)
		if r.m["error"] != "invalid_target" {
			t.Fatalf("%v", r.m)
		}
		code = h.getCode(c, cl, ch, url.Values{"resource": {"https://api.example/a", "https://api.example/b"}})
		r = h.exchangeCode(cl, secret, code, v)
		aud, _ := claimsOf(t, r.str("access_token"))["aud"].([]any)
		if len(aud) != 3 || aud[0] != cl.ID {
			t.Fatalf("aud %v", aud)
		}
	})

	// A code issued without resource indicators cannot gain one at the exchange.
	t.Run("code exchange cannot add", func(t *testing.T) {
		h := setup(t, nil)
		cl, secret := h.newClient(nil)
		c, _ := h.session(h.user)
		v, ch := pkce()
		code := h.getCode(c, cl, ch, nil)
		r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
			"code_verifier": {v}, "resource": {"https://api.other.example/"}}, cl, secret)
		if r.status != 400 || r.str("error") != "invalid_target" {
			t.Fatalf("resource added at exchange: %d %v", r.status, r.m)
		}
	})

	// Resource indicators (RFC 8707): URNs are accepted; a refresh may narrow the authorized resources but never widen
	// them; without a resource it keeps the authorized ones.
	t.Run("refresh", func(t *testing.T) {
		h := setup(t, nil)
		cl, secret := h.newClient(nil)
		r, _ := h.login(cl, secret, url.Values{"resource": {"https://api.example/a", "urn:example:billing"}})
		if r.status != 200 {
			t.Fatalf("login with resources: %v", r.m)
		}
		rt := r.str("refresh_token")
		aud := func(tok string) []string {
			switch v := claimsOf(t, tok)["aud"].(type) {
			case string:
				return []string{v}
			case []any:
				out := []string{}
				for _, x := range v {
					out = append(out, x.(string))
				}
				return out
			}
			return nil
		}
		if a := aud(h.refreshWith(cl, secret, rt).str("access_token")); !slices.Contains(a, "urn:example:billing") || !slices.Contains(a, "https://api.example/a") {
			t.Errorf("refresh without resource: %v", a)
		}
		x := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "resource": {"https://api.example/a"}}, cl, secret)
		if a := aud(x.str("access_token")); x.status != 200 || slices.Contains(a, "urn:example:billing") {
			t.Errorf("narrowed refresh: %d %v", x.status, a)
		}
		for _, wider := range []string{"https://other.example/", "https://api.example/b"} { // unregistered; registered but not granted
			x = h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "resource": {wider}}, cl, secret)
			if x.status != 400 || x.str("error") != "invalid_target" {
				t.Errorf("widened refresh to %s: %d %v", wider, x.status, x.m)
			}
		}
		// a grant made without resources cannot gain one
		r2, _ := h.login(cl, secret, nil)
		x = h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r2.str("refresh_token")}, "resource": {"https://api.example/a"}}, cl, secret)
		if x.status != 400 || x.str("error") != "invalid_target" {
			t.Errorf("resource added at refresh: %d %v", x.status, x.m)
		}
	})

	// Resource indicators (RFC 8707): a client may name only the resources registered for it, at the authorization
	// endpoint and with client_credentials; the consent page shows them and consent is remembered per resource set.
	t.Run("allow list", func(t *testing.T) {
		h := setup(t, nil)
		cl, secret := h.newClient(func(in *service.ClientInput) {
			in.FirstParty = ptr(false)
			in.Name = ptr("Billing App")
			in.Resources = &[]string{"https://api.example/a", "https://api.example/b"}
		})
		c, csrf := h.session(h.user)
		v, ch := pkce()

		// unlisted: invalid_target back to the client
		if u := h.authorize(c, authzQuery(cl, ch, url.Values{"resource": {"https://evil.example/"}})); u.Query().Get("error") != "invalid_target" {
			t.Fatalf("unlisted resource at authorize: %s", u)
		}
		cc := h.token(url.Values{"grant_type": {"client_credentials"}, "resource": {"https://evil.example/"}}, cl, secret)
		if cc.m["error"] != "invalid_target" {
			t.Fatalf("unlisted resource with client_credentials: %v", cc.m)
		}
		cc = h.token(url.Values{"grant_type": {"client_credentials"}, "resource": {"https://api.example/b"}}, cl, secret)
		if aud, _ := claimsOf(t, cc.str("access_token"))["aud"].([]any); len(aud) != 2 || aud[1] != "https://api.example/b" {
			t.Fatalf("client_credentials aud: %v (%v)", aud, cc.m)
		}

		// listed: the consent page names it, and the access token is for it
		u := h.authorize(c, authzQuery(cl, ch, url.Values{"resource": {"https://api.example/a"}}))
		if u.Path != orgBase+"/oauth/consent" {
			t.Fatalf("expected consent: %s", u)
		}
		flowID := u.Query().Get("flow")
		if page := body(h.get(c, u.RequestURI())); !strings.Contains(page, "https://api.example/a") {
			t.Fatalf("consent page does not show the resource: %s", page)
		}
		_, redirect := h.decideConsent(c, csrf, flowID, true)
		code := loc(t, h.get(c, redirect)).Query().Get("code")
		r := h.exchangeCode(cl, secret, code, v)
		if aud, _ := claimsOf(t, r.str("access_token"))["aud"].([]any); len(aud) != 2 || aud[0] != cl.ID || aud[1] != "https://api.example/a" {
			t.Fatalf("aud: %v (%v)", aud, r.m)
		}

		// consent is remembered for that resource ...
		_, ch2 := pkce()
		if u := h.authorize(c, authzQuery(cl, ch2, url.Values{"resource": {"https://api.example/a"}, "prompt": {"none"}})); u.Query().Get("code") == "" {
			t.Fatalf("consent for the same resource not remembered: %s", u)
		}
		// ... but not for another one
		if u := h.authorize(c, authzQuery(cl, ch2, url.Values{"resource": {"https://api.example/b"}, "prompt": {"none"}})); u.Query().Get("error") != "consent_required" {
			t.Fatalf("consent for another resource: %s", u)
		}
		if u := h.authorize(c, authzQuery(cl, ch2, url.Values{"resource": {"https://api.example/b"}})); u.Path != orgBase+"/oauth/consent" {
			t.Fatalf("another resource without consent: %s", u)
		}
	})
}
