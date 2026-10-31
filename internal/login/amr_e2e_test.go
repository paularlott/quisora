package login_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// From one end to the other, with a real provider: a person of the primary organization who signed in there with a
// password and an authenticator code continues to acme through the organization provider. The primary organization's
// ID token says how ("pwd","otp","mfa"); acme keeps that apart from its own ("fed": not trusted for the second factor),
// so a tenant of acme that requires a second factor still asks for acme's own, and the tokens acme issues to one of
// its applications carry both, but not the provider's "mfa" (acme neither asked for a second factor nor trusts the
// provider's), with acr from acme's own alone and idp naming the provider's type.
func TestUpstreamAMRFromProviderToApplication(t *testing.T) {
	g := newGuestEnv(t, func(in *service.ProviderInput) { in.LinkByEmail = ptr(true) })
	ctx := context.Background()
	pat := g.person(t, g.Primary, "pat", "pat@example.com")
	guest := g.person(t, g.acme, "pat-guest", "pat@example.com")

	b, done := g.continueAsVia(t, g.signedInWith(t, pat, []string{"pwd", "otp", "mfa"}), g.acme, g.p)
	if want := web.OrgPath(g.acme.ID, "/account"); done != want {
		t.Fatalf("after the callback: %q, want %q", done, want)
	}
	sess := sessionsOf(t, g.env, guest)
	if len(sess) != 1 || !slices.Equal(sess[0].AMR, []string{"fed"}) || !slices.Equal(sess[0].UpstreamAMR, []string{"pwd", "otp", "mfa"}) {
		t.Fatalf("acme's session: %+v", sess)
	}

	// applications of acme sign the person in (first party: no consent screen)
	redirect := "https://app.example/cb"
	newApp := func(tenant *model.Tenant) *model.Client {
		t.Helper()
		in := service.ClientInput{Name: ptr("App"), AuthMethod: ptr(model.AuthMethodNone), GrantTypes: &[]string{"authorization_code"},
			RedirectURIs: &[]string{redirect}, Scopes: &[]string{"openid"}, FirstParty: ptr(true)}
		if tenant != nil {
			in.TenantID = &tenant.ID
		}
		c, _, err := g.Svc.CreateClient(ctx, service.System, g.acme.ID, in)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	verifier := secure.RandomToken(32)
	sum := sha256.Sum256([]byte(verifier))
	iu, err := url.Parse(g.Cfg.OrgIssuer(g.acme.ID))
	if err != nil {
		t.Fatal(err)
	}
	issuer := iu.Path // the server's own address, as the browser reaches it
	authorize := func(app *model.Client) (int, string) {
		t.Helper()
		q := url.Values{"response_type": {"code"}, "client_id": {app.ID}, "redirect_uri": {redirect}, "scope": {"openid"},
			"state": {"s"}, "nonce": {"n"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
			"code_challenge_method": {"S256"}}
		res, _ := b.getAbs(issuer + "/oauth/authorize?" + q.Encode())
		return res.StatusCode, res.Header.Get("Location")
	}

	// acme's default tenant requires a second factor: the provider's "mfa" is not one, so acme asks for its own
	if st, loc := authorize(newApp(nil)); st != 302 || !strings.Contains(loc, "/login?") || !strings.Contains(loc, "reauth=1") {
		t.Fatalf("a tenant requiring a second factor, after the provider's mfa: %d %q", st, loc)
	}
	// a tenant that requires none signs the person in, and its tokens say how
	open := model.DefaultTenantSettings()
	open.RequireMFA = false
	tn, err := g.Svc.CreateTenant(ctx, service.System, g.acme.ID, service.TenantInput{Name: ptr("apps"), DisplayName: ptr("Apps"),
		Settings: &open})
	if err != nil {
		t.Fatal(err)
	}
	g.setSettings(t, g.acme, func(s *model.OrgSettings) { s.RequireMFA = false })
	app := newApp(tn)
	st, loc := authorize(app)
	to, err := url.Parse(loc)
	if err != nil || st != 302 || !strings.HasPrefix(loc, redirect+"?") || to.Query().Get("code") == "" {
		t.Fatalf("authorize: %d %q", st, loc)
	}
	tr, err := b.c.PostForm(g.URL+issuer+"/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {to.Query().Get("code")},
		"client_id": {app.ID}, "redirect_uri": {redirect}, "code_verifier": {verifier}})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Body.Close()
	var tok struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tr.Body).Decode(&tok); err != nil || tr.StatusCode != 200 {
		t.Fatalf("token: %d %v", tr.StatusCode, err)
	}
	for name, jwt := range map[string]string{"ID token": tok.IDToken, "access token": tok.AccessToken} {
		c := payload(t, jwt)
		amr, _ := json.Marshal(c["amr"])
		if string(amr) != `["fed","pwd","otp"]` || c["acr"] != "urn:quisora:acr:basic" || c["idp"] != model.ProviderOrganization {
			t.Errorf("%s: amr %s acr %v idp %v", name, amr, c["acr"], c["idp"])
		}
	}
}

// payload is the claims of a JWT (its signature is the token endpoint's business, tested where it is made).
func payload(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	var c map[string]any
	if err != nil || json.Unmarshal(b, &c) != nil {
		t.Fatalf("JWT payload: %v", err)
	}
	return c
}
