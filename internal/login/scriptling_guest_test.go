package login_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
)

// The application's side, with the Scriptling library: an application of acme given a guest's access token asks
// acme's introspection endpoint about it, as itself, and labels the guest with the organization and tenant they came
// from (quisora.introspect, quisora.guest_of: examples/guest_token.py). A token it cannot use is not described. Skipped
// where Scriptling is not installed.
func TestScriptlingNamesAGuestsHome(t *testing.T) {
	bin, err := exec.LookPath("scriptling")
	if err != nil {
		t.Skip("scriptling is not installed")
	}
	dir, err := filepath.Abs("../../scriptling")
	if err != nil {
		t.Fatal(err)
	}
	g := newGuestEnv(t, func(in *service.ProviderInput) { in.LinkByEmail = ptr(true) })
	ctx := context.Background()
	pat := g.person(t, g.Primary, "pat", "pat@example.com")
	g.person(t, g.acme, "pat-guest", "pat@example.com")
	b, _ := g.continueAs(t, pat)
	if !signedInToAcme(b) {
		t.Fatal("the guest is not signed in to acme")
	}

	// a confidential application of acme, in a tenant asking no second factor, with the idp scope
	open := model.DefaultTenantSettings()
	open.RequireMFA = false
	tn, err := g.Svc.CreateTenant(ctx, service.System, g.acme.ID, service.TenantInput{Name: ptr("kb"), Settings: &open})
	if err != nil {
		t.Fatal(err)
	}
	g.setSettings(t, g.acme, func(s *model.OrgSettings) { s.RequireMFA = false })
	redirect := "https://kb.example/cb"
	app, secret, err := g.Svc.CreateClient(ctx, service.System, g.acme.ID, service.ClientInput{Name: ptr("KB"),
		AuthMethod: ptr(model.AuthMethodSecretPost), GrantTypes: &[]string{"authorization_code"}, RedirectURIs: &[]string{redirect},
		Scopes: &[]string{"openid", "idp"}, FirstParty: ptr(true), TenantID: &tn.ID})
	if err != nil {
		t.Fatal(err)
	}
	iu, err := url.Parse(g.Cfg.OrgIssuer(g.acme.ID))
	if err != nil {
		t.Fatal(err)
	}
	verifier := secure.RandomToken(32)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {app.ID}, "redirect_uri": {redirect}, "scope": {"openid idp"},
		"state": {"s"}, "nonce": {"n"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	res, _ := b.getAbs(iu.Path + "/oauth/authorize?" + q.Encode())
	to, err := url.Parse(res.Header.Get("Location"))
	if err != nil || res.StatusCode != 302 || to.Query().Get("code") == "" {
		t.Fatalf("authorize: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	tr, err := b.c.PostForm(g.URL+iu.Path+"/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {to.Query().Get("code")},
		"client_id": {app.ID}, "client_secret": {secret}, "redirect_uri": {redirect}, "code_verifier": {verifier}})
	if err != nil {
		t.Fatal(err)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(tr.Body).Decode(&tok)
	tr.Body.Close()
	if err != nil || tr.StatusCode != 200 || tok.AccessToken == "" {
		t.Fatalf("token: %d %v", tr.StatusCode, err)
	}

	run := func(token string) (string, bool) {
		t.Helper()
		cmd := exec.Command(bin, "-L", "lib", "examples/guest_token.py", "acme", token)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "QUISORA_URL="+g.URL, "QUISORA_INSECURE=1", "QUISORA_APP_CLIENT_ID="+app.ID,
			"QUISORA_APP_CLIENT_SECRET="+secret)
		out, err := cmd.CombinedOutput()
		return string(out), err == nil
	}
	src, err := g.Svc.Tenants.Get(ctx, g.p.SourceTenant)
	if err != nil {
		t.Fatal(err)
	}
	want := "a guest from " + g.Primary.Name + ", " + src.Name + " (their id there " + pat.ID + ", organization " + g.Primary.ID + ")"
	if out, ok := run(tok.AccessToken); !ok || !strings.Contains(out, want) {
		t.Fatalf("a guest's token: %v, want %q in\n%s", ok, want, out)
	}
	if out, ok := run("not-a-token"); ok || !strings.Contains(out, "Not an active token") {
		t.Fatalf("a token it cannot use: %v\n%s", ok, out)
	}
}
