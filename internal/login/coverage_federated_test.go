package login_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// An ID token that does not match the request it answers (another nonce), has expired, comes from another issuer or
// says nothing about its nonce signs nobody in and links nothing.
func TestCoverageUpstreamBadIDTokens(t *testing.T) {
	u := newUpEnv(t, func(c *config.Config) { c.Audit.Logins = true })
	p := u.oidcProvider(t, nil)
	cases := map[string]map[string]any{
		"nonce mismatch": {"nonce": "somebody-elses-nonce"},
		"no nonce":       {"nonce": nil},
		"expired":        {"exp": time.Now().Add(-time.Hour).Unix()},
		"wrong issuer":   {"iss": "https://evil.example"},
		"no subject":     {"sub": nil},
		"not yet issued": {"nbf": time.Now().Add(time.Hour).Unix()},
	}
	for name, extra := range cases {
		c := claims("sub-"+name, "x@corp.example")
		for k, v := range extra {
			c[k] = v
		}
		b := u.browser(t)
		res := b.via(t, u, p, "acme", "", c)
		loc := res.Header.Get("Location")
		if res.StatusCode != http.StatusFound || loc != "/login/acme?error=failed" || b.hasSession() {
			t.Errorf("%s: %d %q session=%v", name, res.StatusCode, loc, b.hasSession())
		}
	}
	if ids, _ := u.Svc.Identities.All(context.Background(), ""); len(ids) != 0 {
		t.Fatalf("identities created from rejected tokens: %d", len(ids))
	}
	if n := len(u.audits(t, "login.failure")); n != len(cases) {
		t.Fatalf("failures audited: %d", n)
	}
}

// Starting a sign-in at a provider that is unknown, belongs to another organization or is switched off goes back to
// the sign-in page, and a provider callback for an unknown provider id does nothing.
func TestCoverageUpstreamStartRefusals(t *testing.T) {
	u := newUpEnv(t, nil)
	p := u.oidcProvider(t, nil)
	off := u.oidcProvider(t, func(in *service.ProviderInput) { in.Name = ptr("Off"); in.Enabled = ptr(false) })
	b := u.browser(t)

	res, _ := b.get("/login/acme/provider/nope")
	if res.StatusCode != 302 || res.Header.Get("Location") != "/login/acme?error=disabled" {
		t.Fatalf("unknown provider: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	res, _ = b.get("/login/acme/provider/" + off.ID)
	if res.Header.Get("Location") != "/login/acme?error=disabled" {
		t.Fatalf("disabled provider: %q", res.Header.Get("Location"))
	}
	other := u.org2(t)
	res, _ = b.get("/login/" + other.Name + "/provider/" + p.ID)
	if loc := res.Header.Get("Location"); loc != "/login/"+other.Name+"?error=disabled" {
		t.Fatalf("another organization's provider: %q", loc)
	}
	res, _ = b.get("/login/nosuchorg/provider/" + p.ID)
	if res.StatusCode != 404 && res.StatusCode != 302 {
		t.Fatalf("unknown org: %d", res.StatusCode)
	}
	res, _ = b.get("/login/callback/nope?state=x&code=y")
	if res.StatusCode != 302 || b.hasSession() {
		t.Fatalf("callback for unknown provider: %d", res.StatusCode)
	}
	res, _ = b.get("/login/callback/" + p.ID + "?error=access_denied&state=unknown")
	if res.Header.Get("Location") != "/?error=failed" {
		t.Fatalf("denied with an unknown state: %q", res.Header.Get("Location"))
	}
}

func (u *upEnv) connectURL(t *testing.T, b *browser, p *model.Provider) string {
	t.Helper()
	b.markReauth()
	res, out := b.post("/api-internal/account/providers/"+p.ID+"/connect", nil)
	wantStatus(t, res, out, 200)
	return str(out, "url")
}

func (u *upEnv) connectCallback(t *testing.T, b *browser, p *model.Provider, authURL string, c map[string]any) string {
	t.Helper()
	code := u.oidc.Authorize(authURL, c)
	lu, _ := url.Parse(authURL)
	res, _ := b.get("/login/callback/" + p.ID + "?state=" + url.QueryEscape(lu.Query().Get("state")) + "&code=" + url.QueryEscape(code))
	return res.Header.Get("Location")
}

// Connecting a provider to an account: the browser that finishes must be the one signed in as the account that
// began, the e-mail domain rule applies, connecting again is idempotent and an unknown or switched-off provider is
// not found.
func TestCoverageConnectRefusals(t *testing.T) {
	u := newUpEnv(t, func(c *config.Config) { c.Audit.Logins = true })
	p := u.oidcProvider(t, func(in *service.ProviderInput) {
		in.AutoProvision = ptr(false)
		in.AllowedDomains = &[]string{"corp.example"}
	})
	off := u.oidcProvider(t, func(in *service.ProviderInput) { in.Name = ptr("Off"); in.Enabled = ptr(false) })
	pat := u.user(t, u.org, "pat", model.RoleUser)
	b := u.signedIn(t, pat)

	b.markReauth()
	for _, id := range []string{"nope", off.ID} {
		res, out := b.post("/api-internal/account/providers/"+id+"/connect", nil)
		wantStatus(t, res, out, 404)
	}

	// finished by a browser that did not start it (no state cookie: anonymous, or signed in as someone else): nothing is linked
	authURL := u.connectURL(t, b, p)
	if loc := u.connectCallback(t, u.browser(t), p, authURL, claims("pat-sub", "pat@corp.example")); loc != "/?error=failed" {
		t.Fatalf("anonymous finish: %q", loc)
	}
	sam := u.user(t, u.org, "sam", model.RoleUser)
	sb := u.signedIn(t, sam)
	authURL = u.connectURL(t, b, p)
	if loc := u.connectCallback(t, sb, p, authURL, claims("pat-sub", "pat@corp.example")); loc != "/?error=failed" {
		t.Fatalf("another user's finish: %q", loc)
	}
	if ids, _ := u.Svc.Identities.All(context.Background(), ""); len(ids) != 0 {
		t.Fatalf("identities linked by refused finishes: %d", len(ids))
	}

	// an address outside the provider's allowed domains
	authURL = u.connectURL(t, b, p)
	if loc := u.connectCallback(t, b, p, authURL, claims("pat-sub", "pat@evil.example")); loc != "/account?provider=domain#providers" {
		t.Fatalf("domain: %q", loc)
	}
	if len(u.audits(t, "account.provider.connect_refused")) != 1 {
		t.Fatal("refusal not audited")
	}

	// success, and again with the same identity
	authURL = u.connectURL(t, b, p)
	if loc := u.connectCallback(t, b, p, authURL, claims("pat-sub", "pat@corp.example")); loc != "/account?provider=connected#providers" {
		t.Fatalf("connect: %q", loc)
	}
	authURL = u.connectURL(t, b, p)
	if loc := u.connectCallback(t, b, p, authURL, claims("pat-sub", "pat@corp.example")); loc != "/account?provider=connected#providers" {
		t.Fatalf("connect again: %q", loc)
	}
	if ids, _ := u.Svc.Identities.All(context.Background(), pat.ID); len(ids) != 1 {
		t.Fatalf("identities: %d", len(ids))
	}
	// sam cannot take pat's identity
	authURL = u.connectURL(t, sb, p)
	if loc := u.connectCallback(t, sb, p, authURL, claims("pat-sub", "sam@corp.example")); loc != "/account?provider=taken#providers" {
		t.Fatalf("taken: %q", loc)
	}

	// disconnecting something not connected
	b.markReauth()
	res, out := b.api("DELETE", "/api-internal/account/providers/nope", nil)
	wantStatus(t, res, out, 404)
}
