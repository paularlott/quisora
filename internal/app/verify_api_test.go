package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/webtest"
)

// A CRM that signs agents in through Quisora verifies callers as them: it asks for the organization's caller
// verification API as the resource (RFC 8707), and the access token the agent's sign-in gives it starts a verification
// in their own name. The token works for that organization's API only, and a sign-in token without the resource does
// not work at all.
func TestCallVerificationAPIWithTheAgentsSignIn(t *testing.T) {
	a, hc, base := startApp(t, "sqlite")
	ctx := context.Background()
	jar, _ := cookiejar.New(nil)
	hc.Jar = jar
	org, _ := a.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("acme")})
	other, _ := a.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("other")})
	webtest.NoTenantMFA(t, a.Svc, org.ID)
	users := map[string]*model.User{}
	for _, n := range []string{"grace", "alan"} {
		u, err := a.Svc.CreateUser(ctx, service.System, org.ID, service.UserInput{GivenName: gn(strings.ToUpper(n[:1]) + n[1:]),
			Username: ptr(n), Email: ptr(n + "@acme.test"), Password: ptr("correct horse battery")})
		if err != nil {
			t.Fatal(err)
		}
		users[n] = u
	}
	agents, err := a.Svc.CreateGroupWithMembers(ctx, service.System, org.ID, service.GroupInput{DisplayName: ptr("Support")}, []string{users["grace"].ID})
	if err != nil {
		t.Fatal(err)
	}
	o, _ := a.Svc.Orgs.Get(ctx, org.ID)
	set := o.Settings
	set.VerifyCallers, set.VerifyAgentGroups = true, []string{agents.ID}
	if _, err := a.Svc.UpdateOrg(ctx, service.System, org.ID, service.OrgInput{Settings: &set}); err != nil {
		t.Fatal(err)
	}

	// the CRM: an application of a tenant that owns the organization's caller verification API, and lists it
	resource := a.Svc.Cfg.OrgVerifyAPI(org.ID)
	tset := model.DefaultTenantSettings()
	tset.MembersOnly, tset.RequireMFA = false, false // everyone of the organization, with a password (the test signs in so)
	tn, err := a.Svc.CreateTenant(ctx, service.System, org.ID, service.TenantInput{Name: ptr("crm"), Settings: &tset, Resources: &[]string{resource}})
	if err != nil {
		t.Fatal(err)
	}
	crm, secret, err := a.Svc.CreateClient(ctx, service.System, org.ID, service.ClientInput{Name: ptr("CRM"), TenantID: &tn.ID,
		RedirectURIs: ptr([]string{"https://crm.example/cb"}), FirstParty: ptr(true), Resources: &[]string{resource}})
	if err != nil {
		t.Fatal(err)
	}

	// Grace signs in to the CRM through Quisora, the CRM asking for the API as the resource
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
	signIn := func(withResource bool) string {
		t.Helper()
		q := url.Values{"response_type": {"code"}, "client_id": {crm.ID}, "redirect_uri": {"https://crm.example/cb"},
			"scope": {"openid profile email"}, "state": {"s"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
			"code_challenge_method": {"S256"}}
		if withResource {
			q.Set("resource", resource)
		}
		loc := get(base + "/o/" + org.ID + "/oauth/authorize?" + q.Encode()).Header.Get("Location")
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
			body, _ := json.Marshal(map[string]string{"email": "grace@acme.test", "password": "correct horse battery",
				"next": lu.Query().Get("next"), "tenant": lu.Query().Get("tenant")})
			code, out := doJSON(t, hc, "POST", base+"/o/"+org.ID+"/api-internal/login/password", map[string]string{"Content-Type": "application/json",
				"X-CSRF-Token": string(m[1]), "Origin": base}, strings.NewReader(string(body)))
			if code != 200 || out["next"] == nil {
				t.Fatalf("sign-in: %d %v", code, out)
			}
			loc = get(base + out["next"].(string)).Header.Get("Location")
		}
		cb, _ := url.Parse(loc)
		if cb.Query().Get("code") == "" {
			t.Fatalf("no code: %s", loc)
		}
		form := url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")}, "redirect_uri": {"https://crm.example/cb"},
			"code_verifier": {verifier}, "client_id": {crm.ID}, "client_secret": {secret}}
		code, tok := doJSON(t, hc, "POST", base+"/o/"+org.ID+"/oauth/token", formHdr, strings.NewReader(form.Encode()))
		if code != 200 || tok["access_token"] == nil {
			t.Fatalf("token: %d %v", code, tok)
		}
		return tok["access_token"].(string)
	}
	call := func(tok, orgRef string) (int, map[string]any) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"user_id": users["alan"].ID, "direction": model.VerifyInbound, "reason": "CRM-1"})
		return doJSON(t, &http.Client{Transport: hc.Transport}, "POST", base+"/api/orgs/"+orgRef+"/verifications",
			map[string]string{"Authorization": "Bearer " + tok, "Content-Type": "application/json"}, strings.NewReader(string(body)))
	}

	tok := signIn(true)
	code, out := call(tok, "acme")
	if code != 201 {
		t.Fatalf("start with Grace's token for the API: %d %v", code, out)
	}
	v, _ := out["verification"].(map[string]any)
	if c, _ := out["code"].(string); len(c) != 6 || v["agent_id"] != users["grace"].ID || v["direction"] != model.VerifyInbound {
		t.Fatalf("started: %v", out)
	}
	// for another organization's API it is not: the address is the organization's
	if code, out := call(tok, other.Name); code == 201 {
		t.Errorf("Grace's token started one through another organization's API: %v", out)
	}
	// a sign-in token of the CRM without the resource is not one either
	if code, out := call(signIn(false), "acme"); code != 401 {
		t.Errorf("a token without the API as its resource: %d %v", code, out)
	}
}
