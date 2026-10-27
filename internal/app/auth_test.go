package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/webtest"
)

// The management API takes personal API tokens only: anything else, and unknown tokens, are rejected.
func TestBearerRejections(t *testing.T) {
	a, _, _ := startApp(t, "sqlite")
	f := bearer(a.Svc)
	r := httptest.NewRequest("GET", "/api/me", nil)
	for _, tok := range []string{"", "plain-oauth-access-token", "eyJhbGciOiJFUzI1NiJ9.e30.sig"} {
		if _, err := f(context.Background(), r, tok); !errors.Is(err, service.ErrBadToken) {
			t.Fatalf("token %q: %v", tok, err)
		}
	}
	// well formed but unknown: refused (never an actor)
	tok := "qsr_pat_" + strings.Repeat("a", 40)
	if !service.IsAPIToken(tok) {
		t.Skip("API token prefix changed; adjust the test")
	}
	if act, err := f(context.Background(), r, tok); err == nil || act != nil {
		t.Fatalf("unknown API token accepted: %v %v", act, err)
	}
}

// SCIM takes OAuth client_credentials tokens only; garbage is refused.
func TestSCIMVerifierRejectsGarbage(t *testing.T) {
	a, _, _ := startApp(t, "sqlite")
	v := scimVerifier(a)
	r := httptest.NewRequest("GET", "/scim/v2/acme/Users", nil)
	for _, tok := range []string{"", "garbage", "a.b.c"} {
		if act, err := v(r, "Bearer", tok); err == nil || act != nil {
			t.Fatalf("token %q accepted: %v %v", tok, act, err)
		}
	}
	if act, err := v(r, "DPoP", "garbage"); err == nil || act != nil {
		t.Fatalf("DPoP garbage accepted: %v %v", act, err)
	}
}

// prompt=login re-authenticates the user on their existing session: the refresh grant another application holds on
// it keeps working. Signing in as a different user on the same browser ends the previous user's session and grants.
func TestPromptLoginKeepsOtherApplicationsGrants(t *testing.T) {
	a, hc, base := startApp(t, "sqlite")
	ctx := context.Background()
	jar, _ := cookiejar.New(nil)
	hc.Jar = jar
	org, _ := a.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("acme")})
	webtest.NoTenantMFA(t, a.Svc, org.ID)
	for _, n := range []string{"jane", "bob"} {
		if _, err := a.Svc.CreateUser(ctx, service.System, org.ID, service.UserInput{GivenName: gn("T"), Username: ptr(n),
			Email: ptr(n + "@acme.test"), Password: ptr("correct horse battery")}); err != nil {
			t.Fatal(err)
		}
	}
	newRP := func(name string) (*model.Client, string) {
		cl, secret, err := a.Svc.CreateClient(ctx, service.System, org.ID, service.ClientInput{Name: ptr(name),
			RedirectURIs: ptr([]string{"https://" + name + ".example/cb"}), FirstParty: ptr(true)})
		if err != nil {
			t.Fatal(err)
		}
		return cl, secret
	}
	rp1, s1 := newRP("one")
	rp2, s2 := newRP("two")
	verifier := "a-very-long-pkce-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"
	sum := sha256.Sum256([]byte(verifier))
	formHdr := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	get := func(u string) *http.Response {
		t.Helper()
		resp, err := hc.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	// signIn runs an authorization request for cl (prompt given), signing in as who when the server asks, and
	// returns the token response.
	signIn := func(cl *model.Client, secret, prompt, who string) map[string]any {
		t.Helper()
		redirect := cl.RedirectURIs[0]
		q := url.Values{"response_type": {"code"}, "client_id": {cl.ID}, "redirect_uri": {redirect},
			"scope": {"openid profile email"}, "state": {"s"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
			"code_challenge_method": {"S256"}}
		if prompt != "" {
			q.Set("prompt", prompt)
		}
		resp := get(base + "/o/" + org.ID + "/oauth/authorize?" + q.Encode())
		loc := resp.Header.Get("Location")
		if strings.HasPrefix(loc, "/o/"+org.ID+"/login?") {
			resp, err := hc.Get(base + loc)
			if err != nil {
				t.Fatal(err)
			}
			page, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			m := regexp.MustCompile(`name="csrf-token" content="([^"]+)"`).FindSubmatch(page)
			if m == nil {
				t.Fatalf("login page %d", resp.StatusCode)
			}
			lu, _ := url.Parse(loc)
			body, _ := json.Marshal(map[string]string{"email": who + "@acme.test", "password": "correct horse battery",
				"next": lu.Query().Get("next"), "tenant": lu.Query().Get("tenant")})
			code, out := doJSON(t, hc, "POST", base+"/o/"+org.ID+"/api-internal/login/password", map[string]string{"Content-Type": "application/json",
				"X-CSRF-Token": string(m[1]), "Origin": base}, strings.NewReader(string(body)))
			if code != 200 || out["next"] == nil {
				t.Fatalf("sign-in as %s: %d %v", who, code, out)
			}
			loc = get(base + out["next"].(string)).Header.Get("Location")
		} else if prompt == "login" {
			t.Fatalf("prompt=login did not ask to sign in: %s", loc)
		}
		cb, _ := url.Parse(loc)
		if cb.Query().Get("code") == "" {
			t.Fatalf("no code: %s", loc)
		}
		form := url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")}, "redirect_uri": {redirect},
			"code_verifier": {verifier}, "client_id": {cl.ID}, "client_secret": {secret}}
		code, tok := doJSON(t, hc, "POST", base+"/o/"+org.ID+"/oauth/token", formHdr, strings.NewReader(form.Encode()))
		if code != 200 || tok["refresh_token"] == nil {
			t.Fatalf("token: %d %v", code, tok)
		}
		return tok
	}
	refreshOK := func(cl *model.Client, secret, rt string) bool {
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {cl.ID}, "client_secret": {secret}}
		code, _ := doJSON(t, hc, "POST", base+"/o/"+org.ID+"/oauth/token", formHdr, strings.NewReader(form.Encode()))
		return code == 200
	}

	t1 := signIn(rp1, s1, "", "jane")
	sid := func(tok map[string]any) string {
		parts := strings.Split(tok["id_token"].(string), ".")
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var c map[string]any
		_ = json.Unmarshal(raw, &c)
		s, _ := c["sid"].(string)
		return s
	}
	t2 := signIn(rp2, s2, "login", "jane") // re-authentication for the second application
	if !refreshOK(rp1, s1, t1["refresh_token"].(string)) {
		t.Fatal("prompt=login for another application ended the first application's refresh grant")
	}
	if sid(t1) == "" || sid(t1) != sid(t2) {
		t.Fatalf("the session (sid) changed on re-authentication: %q -> %q", sid(t1), sid(t2))
	}
	// A different user on the same browser: jane's session and grants end.
	signIn(rp2, s2, "login", "bob")
	if refreshOK(rp1, s1, t1["refresh_token"].(string)) || refreshOK(rp2, s2, t2["refresh_token"].(string)) {
		t.Fatal("the previous user's refresh grants survived another user's sign-in")
	}
}
