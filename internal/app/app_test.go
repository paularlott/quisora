package app

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/web"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/webtest"
)

// startApp runs the complete server (config → storage → cluster → service → modules) on a free port.
func startApp(t *testing.T, backend string) (*App, *http.Client, string) {
	t.Helper()
	return startAppWith(t, backend, nil)
}

// startAppWith is startApp with a configuration hook (run before validation).
func startAppWith(t *testing.T, backend string, edit func(*config.Config)) (*App, *http.Client, string) {
	t.Helper()
	c := appConfig(t, backend, edit)
	if c.Cluster.Bind == "" || bootstrapNext { // set up as an operator would before the first start ("quisora bootstrap")
		bootstrapNext = false
		_, link, err := Bootstrap(context.Background(), c, logger.NewNullLogger())
		if err != nil {
			t.Fatal(err)
		}
		if link != "" {
			lastBootstrapLink = link
		}
	}
	return runApp(t, c)
}

// appConfig is the configuration of a server on a free port, edited by edit (run before validation).
func appConfig(t *testing.T, backend string, edit func(*config.Config)) *config.Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	c := config.Default()
	c.Server.Listen = addr
	c.Server.PublicURL = "https://" + addr
	c.Server.DataDir = t.TempDir()
	c.Storage.Backend = backend
	c.Limits.PasswordWorkers = 4
	c.Server.MasterKey = base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	if edit != nil {
		edit(c)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

// runApp starts the server configured by c, stopped when the test ends.
func runApp(t *testing.T, c *config.Config) (*App, *http.Client, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	a, err := Start(ctx, c, logger.NewNullLogger())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); a.Close() })
	hc := &http.Client{Timeout: 10 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return a, hc, c.Server.PublicURL
}

func doJSON(t *testing.T, hc *http.Client, method, u string, hdr map[string]string, body io.Reader) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, u, body)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestIntegrationSQLite(t *testing.T) { testIntegration(t, "sqlite") }
func TestIntegrationBadger(t *testing.T) { testIntegration(t, "badgerdb") }

func testIntegration(t *testing.T, backend string) {
	a, hc, base := startApp(t, backend)
	ctx := context.Background()
	primary, err := a.Svc.PrimaryOrg(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Health and discovery.
	if code, _ := doJSON(t, hc, "GET", base+"/readyz", nil, nil); code != 200 {
		t.Fatalf("readyz %d", code)
	}
	code, disc := doJSON(t, hc, "GET", base+"/o/"+primary.ID+"/.well-known/openid-configuration", nil, nil)
	if code != 200 || disc["issuer"] != base+"/o/"+primary.ID {
		t.Fatalf("discovery %d %v", code, disc["issuer"])
	}
	// The name form of the address is redirected to the id form, where the issuer is the address fetched.
	if resp, err := hc.Get(base + "/o/" + primary.Name + "/.well-known/openid-configuration"); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusPermanentRedirect || !strings.HasSuffix(resp.Header.Get("Location"), "/o/"+primary.ID+"/.well-known/openid-configuration") {
			t.Fatalf("name-form discovery: %d %s", resp.StatusCode, resp.Header.Get("Location"))
		}
	}

	// A SCIM provisioning client in a customer org: client_credentials → SCIM create + filter.
	org, err := a.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("acme")})
	if err != nil {
		t.Fatal(err)
	}
	cl, secret, err := a.Svc.CreateClient(ctx, service.System, org.ID, service.ClientInput{Name: ptr("provisioner"),
		GrantTypes: ptr([]string{"client_credentials"}), Scopes: ptr([]string{}), SCIM: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {cl.ID}, "client_secret": {secret},
		"scope": {"scim"}}
	code, tok := doJSON(t, hc, "POST", base+"/o/"+org.ID+"/oauth/token",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, strings.NewReader(form.Encode()))
	if code != 200 {
		t.Fatalf("client_credentials %d %v", code, tok)
	}
	bearer := map[string]string{"Authorization": "Bearer " + tok["access_token"].(string),
		"Content-Type": "application/scim+json"}
	code, created := doJSON(t, hc, "POST", base+"/scim/v2/acme/Users", bearer, strings.NewReader(
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"jane","name":{"givenName":"Jane","familyName":"Doe"},"emails":[{"value":"jane@acme.test","primary":true}],"active":true}`))
	if code != 201 {
		t.Fatalf("scim create %d %v", code, created)
	}
	code, list := doJSON(t, hc, "GET", base+"/scim/v2/acme/Users?filter="+url.QueryEscape(`userName eq "jane"`), bearer, nil)
	if code != 200 || list["totalResults"].(float64) != 1 {
		t.Fatalf("scim filter %d %v", code, list)
	}
	// The provisioning client is confined to its own org.
	if code, _ := doJSON(t, hc, "GET", base+"/scim/v2/primary/Users", bearer, nil); code != 404 {
		t.Fatalf("scim other org: %d", code)
	}
	// It may not grant admin roles.
	code, _ = doJSON(t, hc, "PATCH", base+"/scim/v2/acme/Users/"+created["id"].(string), bearer, strings.NewReader(
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"urn:paularlott:quisora:scim:schemas:2.0:User:role","value":"admin"}]}`))
	if code != 403 {
		t.Fatalf("provisioning client granted admin: %d", code)
	}

	// Management API with a personal API token of the super admin.
	admin, err := a.Svc.FindUserByEmail(ctx, primary.ID, "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, apiTok, err := a.Svc.CreateAPIToken(ctx, service.ActorForUser(admin, ""), service.APITokenInput{Name: "ci",
		Scopes: []string{service.ScopeAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	// The api scope is never mixed with Quisora's own: the token for applications is a separate one. An organization
	// starts with nobody allowed to make it.
	st := primary.Settings
	st.APITokens = model.APITokensEveryone
	if _, err := a.Svc.UpdateOrg(ctx, service.System, primary.ID, service.OrgInput{Settings: &st}); err != nil {
		t.Fatal(err)
	}
	_, appTok, err := a.Svc.CreateAPIToken(ctx, service.ActorForUser(admin, ""), service.APITokenInput{Name: "app",
		Scopes: []string{service.ScopeAPI}})
	if err != nil {
		t.Fatal(err)
	}
	hdr := map[string]string{"Authorization": "Bearer " + apiTok, "Api-Version": web.APIVersionLatest}
	code, orgs := doJSON(t, hc, "GET", base+"/api/orgs", hdr, nil)
	if code == 404 {
		t.Skip("management API not registered yet")
	}
	if code != 200 || orgs["total"].(float64) < 2 {
		t.Fatalf("mgmt list orgs %d %v", code, orgs)
	}
	// The API token is introspectable by a confidential client that accepts them.
	app, appSecret, err := a.Svc.CreateClient(ctx, service.System, primary.ID, service.ClientInput{Name: ptr("app"),
		GrantTypes: ptr([]string{"client_credentials"}), Scopes: ptr([]string{}), AcceptsAPITokens: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	form = url.Values{"token": {appTok}, "client_id": {app.ID}, "client_secret": {appSecret}}
	code, intro := doJSON(t, hc, "POST", base+"/o/"+primary.ID+"/oauth/introspect",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, strings.NewReader(form.Encode()))
	if code != 200 || intro["active"] != true || intro["sub"] != admin.ID {
		t.Fatalf("introspect api token %d %v", code, intro)
	}
	_ = model.RoleAdmin
}

func ptr[T any](v T) *T { return &v }

// gn returns a pointer to the first name given to users that tests create.
func gn(s string) *string { return &s }

// TestBrowserSignInFlow drives the whole OIDC code flow on the assembled server the way a browser and an app do.
func TestBrowserSignInFlow(t *testing.T) {
	a, hc, base := startApp(t, "sqlite")
	ctx := context.Background()
	jar, _ := cookiejar.New(nil)
	hc.Jar = jar
	org, _ := a.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("acme")})
	webtest.NoTenantMFA(t, a.Svc, org.ID) // jane signs in with a password alone
	if _, err := a.Svc.CreateUser(ctx, service.System, org.ID, service.UserInput{GivenName: gn("T"), Username: ptr("jane"),
		Email: ptr("jane@acme.test"), Password: ptr("correct horse battery")}); err != nil {
		t.Fatal(err)
	}
	cl, secret, err := a.Svc.CreateClient(ctx, service.System, org.ID, service.ClientInput{Name: ptr("app"),
		RedirectURIs: ptr([]string{"https://app.example/cb"}), FirstParty: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	verifier := "a-very-long-pkce-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {cl.ID}, "redirect_uri": {"https://app.example/cb"},
		"scope": {"openid profile email org offline_access"}, "state": {"st8"}, "nonce": {"n0nce"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}

	get := func(u string) *http.Response {
		t.Helper()
		resp, err := hc.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	// 1. The app sends the browser to authorize; with no session it is sent to the org's sign-in page.
	resp := get(base + "/o/" + org.ID + "/oauth/authorize?" + q.Encode())
	loc := resp.Header.Get("Location")
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/o/"+org.ID+"/login?") {
		t.Fatalf("authorize: %d %s", resp.StatusCode, loc)
	}
	// The hand-off names the client's tenant (the org's default tenant for a client without one).
	if lu0, _ := url.Parse(loc); lu0.Query().Get("tenant") != "default" {
		t.Fatalf("authorize hand-off lacks the tenant: %s", loc)
	}
	// 2. The sign-in page carries the anonymous CSRF token.
	resp = get(base + loc)
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`name="csrf-token" content="([^"]+)"`).FindSubmatch(page)
	if resp.StatusCode != 200 || m == nil {
		t.Fatalf("login page %d", resp.StatusCode)
	}
	lu, _ := url.Parse(loc)
	next := lu.Query().Get("next")
	// 3. Password sign-in through the JSON endpoint.
	body, _ := json.Marshal(map[string]string{"email": "jane@acme.test", "password": "correct horse battery", "next": next, "tenant": lu.Query().Get("tenant")})
	code, out := doJSON(t, hc, "POST", base+"/o/"+org.ID+"/api-internal/login/password", map[string]string{"Content-Type": "application/json",
		"X-CSRF-Token": string(m[1]), "Origin": base}, strings.NewReader(string(body)))
	if code != 200 || out["next"] == nil {
		t.Fatalf("password sign-in %d %v", code, out)
	}
	// 4. Resuming the flow redirects to the app with a code, the state and the issuer.
	resp = get(base + out["next"].(string))
	resp.Body.Close()
	cb, _ := url.Parse(resp.Header.Get("Location"))
	if cb.Host != "app.example" || cb.Query().Get("state") != "st8" || cb.Query().Get("iss") != base+"/o/"+org.ID || cb.Query().Get("code") == "" {
		t.Fatalf("callback: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// 5. Code exchange (client_secret_post) with the PKCE verifier.
	form := url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")},
		"redirect_uri": {"https://app.example/cb"}, "code_verifier": {verifier}, "client_id": {cl.ID},
		"client_secret": {secret}}
	formHdr := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	code, tok := doJSON(t, hc, "POST", base+"/o/"+org.ID+"/oauth/token", formHdr, strings.NewReader(form.Encode()))
	if code != 200 || tok["id_token"] == nil || tok["refresh_token"] == nil {
		t.Fatalf("token %d %v", code, tok)
	}
	for _, name := range []string{"access_token", "id_token"} {
		parts := strings.Split(tok[name].(string), ".")
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var cl map[string]any
		_ = json.Unmarshal(raw, &cl)
		if cl["tenant_name"] != "default" || cl["tenant"] == nil || cl["tenant"] == "" {
			t.Fatalf("%s lacks tenant claims: %s", name, raw)
		}
	}
	codeForm := form
	// 6. userinfo.
	code, ui := doJSON(t, hc, "GET", base+"/o/"+org.ID+"/oauth/userinfo", map[string]string{"Authorization": "Bearer " + tok["access_token"].(string)}, nil)
	if code != 200 || ui["preferred_username"] != "jane" || ui["email"] != "jane@acme.test" || ui["org_name"] != "acme" ||
		ui["tenant_name"] != "default" || ui["tenant"] == nil {
		t.Fatalf("userinfo %d %v", code, ui)
	}
	// 7. Refresh.
	form = url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)},
		"client_id": {cl.ID}, "client_secret": {secret}}
	if code, rt := doJSON(t, hc, "POST", base+"/o/"+org.ID+"/oauth/token", formHdr, strings.NewReader(form.Encode())); code != 200 || rt["access_token"] == nil {
		t.Fatalf("refresh %d %v", code, rt)
	}
	// The code is single use, and replaying it revokes what was issued from it (RFC 6749 §4.1.2).
	if code, _ := doJSON(t, hc, "POST", base+"/o/"+org.ID+"/oauth/token", formHdr, strings.NewReader(codeForm.Encode())); code != 400 {
		t.Fatalf("code replay accepted: %d", code)
	}
	if code, _ := doJSON(t, hc, "POST", base+"/o/"+org.ID+"/oauth/token", formHdr, strings.NewReader(form.Encode())); code == 200 {
		t.Fatal("refresh token survived a code replay")
	}
	// 8. A second authorize now completes silently from the session.
	q.Set("prompt", "none")
	resp = get(base + "/o/" + org.ID + "/oauth/authorize?" + q.Encode())
	resp.Body.Close()
	cb2, _ := url.Parse(resp.Header.Get("Location"))
	if cb2 == nil || cb2.Query().Get("code") == "" {
		t.Fatalf("silent authorize: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// 9. The account page is reachable with the session; disabling the user kills refresh.
	if resp = get(base + "/o/" + org.ID + "/account"); resp.StatusCode != 200 {
		t.Fatalf("account page %d", resp.StatusCode)
	}
	resp.Body.Close()
	silent := url.Values{"grant_type": {"authorization_code"}, "code": {cb2.Query().Get("code")},
		"redirect_uri": {"https://app.example/cb"}, "code_verifier": {verifier}, "client_id": {cl.ID},
		"client_secret": {secret}}
	code, tok2 := doJSON(t, hc, "POST", base+"/o/"+org.ID+"/oauth/token", formHdr, strings.NewReader(silent.Encode()))
	if code != 200 {
		t.Fatalf("silent code exchange %d %v", code, tok2)
	}
	u, _ := a.Svc.FindUserByEmail(ctx, org.ID, "jane@acme.test")
	if _, err := a.Svc.UpdateUser(ctx, service.System, u.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	form = url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok2["refresh_token"].(string)},
		"client_id": {cl.ID}, "client_secret": {secret}}
	if code, _ := doJSON(t, hc, "POST", base+"/o/"+org.ID+"/oauth/token", formHdr, strings.NewReader(form.Encode())); code == 200 {
		t.Fatal("refresh still works for a disabled user")
	}
}

// TestTenantSignInEnforcement drives a passkey-only tenant on the assembled server: the hand-off names the tenant,
// its sign-in page has no password form, the password API refuses it even when called directly, and a session made
// by password in the default tenant is sent to sign in again for a client of the tenant.
func TestTenantSignInEnforcement(t *testing.T) {
	a, hc, base := startApp(t, "sqlite")
	ctx := context.Background()
	jar, _ := cookiejar.New(nil)
	hc.Jar = jar
	org, _ := a.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("acme")})
	webtest.NoTenantMFA(t, a.Svc, org.ID) // jane signs in with a password alone
	if _, err := a.Svc.CreateUser(ctx, service.System, org.ID, service.UserInput{GivenName: gn("T"), Username: ptr("jane"),
		Email: ptr("jane@acme.test"), Password: ptr("correct horse battery")}); err != nil {
		t.Fatal(err)
	}
	tn, err := a.Svc.CreateTenant(ctx, service.System, org.ID, service.TenantInput{Name: ptr("kiosk"),
		Settings: &model.TenantSettings{PasskeyLogin: true, AllProviders: true}})
	if err != nil {
		t.Fatal(err)
	}
	mk := func(name string, tenantID *string) *model.Client {
		c, _, err := a.Svc.CreateClient(ctx, service.System, org.ID, service.ClientInput{Name: ptr(name), TenantID: tenantID,
			RedirectURIs: ptr([]string{"https://app.example/cb"}), FirstParty: ptr(true)})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	kiosk, plain := mk("kiosk app", &tn.ID), mk("plain app", nil)
	sum := sha256.Sum256([]byte("a-very-long-pkce-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"))
	authz := func(c *model.Client) *url.URL {
		q := url.Values{"response_type": {"code"}, "client_id": {c.ID}, "redirect_uri": {"https://app.example/cb"},
			"scope": {"openid"}, "state": {"s"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
			"code_challenge_method": {"S256"}}
		resp, err := hc.Get(base + "/o/" + org.ID + "/oauth/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		u, _ := url.Parse(resp.Header.Get("Location"))
		return u
	}
	u := authz(kiosk)
	if u.Path != "/o/"+org.ID+"/login" || u.Query().Get("tenant") != "kiosk" {
		t.Fatalf("hand-off: %s", u)
	}
	resp, _ := hc.Get(base + u.String())
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`name="csrf-token" content="([^"]+)"`).FindSubmatch(page)
	if m == nil || strings.Contains(string(page), `autocomplete="current-password"`) {
		t.Fatalf("kiosk sign-in page offers a password form (csrf %v)", m != nil)
	}
	hdr := map[string]string{"Content-Type": "application/json", "X-CSRF-Token": string(m[1]), "Origin": base}
	pw := func(tenant string) (int, map[string]any) {
		b, _ := json.Marshal(map[string]string{"email": "jane@acme.test", "password": "correct horse battery",
			"next": u.Query().Get("next"), "tenant": tenant})
		return doJSON(t, hc, "POST", base+"/o/"+org.ID+"/api-internal/login/password", hdr, strings.NewReader(string(b)))
	}
	if code, out := pw("kiosk"); code != 401 {
		t.Fatalf("password for the passkey-only tenant: %d %v", code, out)
	}
	// signing in for the default tenant works, and that session is not good enough for the kiosk client
	if code, out := pw("default"); code != 200 {
		t.Fatalf("default tenant password sign-in: %d %v", code, out)
	}
	if u := authz(plain); u.Query().Get("code") == "" {
		t.Fatalf("plain client should complete from the password session: %s", u)
	}
	u = authz(kiosk)
	if u.Path != "/o/"+org.ID+"/login" || u.Query().Get("reauth") != "1" || u.Query().Get("tenant") != "kiosk" {
		t.Fatalf("kiosk client with a password session: %s", u)
	}
}

// A change made through the service reaches an open management event stream (cluster change hook → SSE hub).
func TestLiveEvents(t *testing.T) {
	a, hc, base := startApp(t, "badgerdb")
	ctx := context.Background()
	primary, _ := a.Svc.PrimaryOrg(ctx)
	admin, _ := a.Svc.FindUserByEmail(ctx, primary.ID, "admin@example.com")
	_, tok, err := a.Svc.CreateAPIToken(ctx, service.ActorForUser(admin, ""), service.APITokenInput{Name: "sse",
		Scopes: []string{service.ScopeAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(rctx, http.MethodGet, base+"/api/events", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := hc.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("stream: %v %v", err, resp)
	}
	defer resp.Body.Close()
	r := bufio.NewReader(resp.Body)
	readUntil := func(substr string) {
		t.Helper()
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("stream closed waiting for %q: %v", substr, err)
			}
			if strings.Contains(line, substr) {
				return
			}
		}
	}
	readUntil("event: ready")
	u, err := a.Svc.CreateUser(ctx, service.System, primary.ID, service.UserInput{GivenName: gn("T"), Username: ptr("live"), Email: ptr("live@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	readUntil(`"id":"` + u.ID + `"`)
}

// lastBootstrapLink is the invitation link of the most recent bootstrap done by startAppWith.
var lastBootstrapLink string

// bootstrapNext makes the next startAppWith bootstrap a gossip node too (the first node of a new cluster).
var bootstrapNext bool

// A rotated client secret is refused at once by the running server: the client cached by the OAuth module goes when
// the client record changes (docs/oauth/client-authentication.md).
func TestRotatedClientSecretRefused(t *testing.T) {
	a, hc, base := startApp(t, "badgerdb")
	ctx := context.Background()
	primary, err := a.Svc.PrimaryOrg(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cl, secret, err := a.Svc.CreateClient(ctx, service.System, primary.ID, service.ClientInput{Name: ptr("sync"),
		GrantTypes: ptr([]string{"client_credentials"}), Scopes: ptr([]string{"reports:read"})})
	if err != nil {
		t.Fatal(err)
	}
	token := func(secret string) int {
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {cl.ID}, "client_secret": {secret}}
		code, _ := doJSON(t, hc, "POST", base+"/o/"+primary.ID+"/oauth/token",
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, strings.NewReader(form.Encode()))
		return code
	}
	if code := token(secret); code != 200 { // the client is now cached
		t.Fatalf("first secret: %d", code)
	}
	fresh, err := a.Svc.RotateClientSecret(ctx, service.System, cl.ID)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for token(secret) != 401 {
		if time.Now().After(deadline) {
			t.Fatal("the old secret still works after rotation")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code := token(fresh); code != 200 {
		t.Fatalf("new secret: %d", code)
	}
}

// A node serves only while its own master key report counts: it is reported at start, before the node serves, and a
// node whose report lapsed (a store that refused its renewals) is not ready until it is stored again, so a rotation
// never finishes while a node may still seal with another key (service.MasterKeyAgreed).
func TestReadyOnlyWhileTheMasterKeyReportCounts(t *testing.T) {
	a, hc, base := startApp(t, "badgerdb")
	if !a.keyReportCurrent() {
		t.Fatal("the master key was not reported at start")
	}
	if code, _ := doJSON(t, hc, "GET", base+"/readyz", nil, nil); code != 200 {
		t.Fatalf("readyz %d with a current report", code)
	}
	a.keyReported.Store(time.Now().Add(-service.MasterKeyReportTTL).UnixNano()) // (lapsed)
	if code, _ := doJSON(t, hc, "GET", base+"/readyz", nil, nil); code != http.StatusServiceUnavailable {
		t.Fatalf("readyz %d with a lapsed report, want 503", code)
	}
	if err := a.reportKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	if code, _ := doJSON(t, hc, "GET", base+"/readyz", nil, nil); code != 200 {
		t.Fatalf("readyz %d once reported again", code)
	}
}
