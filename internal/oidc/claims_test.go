package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/service"
)

// The claims parameter asks for single claims beyond the scopes: answered for the target it names, only for claims
// whose scope the client may use, and kept across a refresh. Unknown claims and members are ignored.
func TestClaimsParameter(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil) // may use profile and email, not phone or enterprise
	claims := `{"userinfo":{"name":{"essential":true},"email":null,"nickname":null},` +
		`"id_token":{"given_name":null,"enterprise":null}}`
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid offline_access"}, "claims": {claims}})
	id := claimsOf(t, r.str("id_token"))
	if id["given_name"] != "Alice" || id["name"] != nil || id["email"] != nil || id["enterprise"] != nil {
		t.Fatalf("id token: %v", id)
	}
	ui := h.userinfo(r.str("access_token"))
	if ui["name"] != "Alice A" || ui["email"] != "alice@example.com" || ui["given_name"] != nil || ui["nickname"] != nil {
		t.Fatalf("userinfo: %v", ui)
	}
	// A refresh keeps them.
	rr := h.refreshWith(cl, secret, r.str("refresh_token"))
	if rr.status != 200 || claimsOf(t, rr.str("id_token"))["given_name"] != "Alice" ||
		h.userinfo(rr.str("access_token"))["name"] != "Alice A" {
		t.Fatalf("after refresh: %d %v", rr.status, rr.m)
	}

	// A client without the profile scope cannot read the name this way.
	narrow, nsecret := h.newClient(func(in *service.ClientInput) {
		in.Name = ptr("narrow")
		in.Scopes = &[]string{"openid", "email"}
	})
	r, _ = h.login(narrow, nsecret, url.Values{"scope": {"openid"}, "claims": {`{"userinfo":{"name":null,"email":null}}`}})
	if ui := h.userinfo(r.str("access_token")); ui["name"] != nil || ui["email"] != "alice@example.com" {
		t.Fatalf("narrow client userinfo: %v", ui)
	}

	// Not JSON: an error for the client.
	c, _ := h.session(h.user)
	_, ch := pkce()
	u := h.authorize(c, authzQuery(cl, ch, url.Values{"claims": {"{not json"}}))
	if u.Query().Get("error") != "invalid_request" {
		t.Fatalf("bad claims: %s", u)
	}
}

// A third-party client asking for a claim through the claims parameter needs consent for its scope, which the
// consent page lists.
func TestClaimsParameterNeedsConsent(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) { in.FirstParty = ptr(false) })
	c, _ := h.session(h.user)
	_, ch := pkce()
	u := h.authorize(c, authzQuery(cl, ch, url.Values{"scope": {"openid"}, "claims": {`{"userinfo":{"email":null}}`}}))
	if u.Path != "/oauth/consent" {
		t.Fatalf("expected consent: %s", u)
	}
	page := body(h.get(c, u.String()))
	if !strings.Contains(page, "Your email address") {
		t.Fatalf("consent page does not list the email scope")
	}
}

// acr values are in order of preference: when the first known one (an acr claim request first, then acr_values) is
// urn:quisora:acr:mfa a second factor is a condition of this sign-in; when it is basic, or none is known, it is not.
// An essential acr claim with no known value fails the request. The ID token's acr is always one of the requested
// known values when any were named.
func TestACRValues(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	_, ch := pkce()
	weak := h.sessionWith(h.user, []string{"pwd"}, time.Now())
	for _, extra := range []url.Values{
		{"acr_values": {acrMFA}},
		{"acr_values": {"urn:other " + acrMFA + " " + acrBasic}}, // mfa preferred over basic
		{"claims": {`{"id_token":{"acr":{"essential":true,"values":["` + acrMFA + `"]}}}`}},
	} {
		u := h.authorize(weak, authzQuery(cl, ch, extra))
		if u.Path != "/login/primary" || u.Query().Get("reauth") != "1" {
			t.Fatalf("%v with a password session: %s", extra, u)
		}
		// the sign-in page is told to ask for the second factor
		if !h.p.FlowWantsMFA(context.Background(), u.Query().Get("next")) {
			t.Fatalf("%v: sign-in not asked for a second factor", extra)
		}
	}
	strong := h.sessionWith(h.user, []string{"pwd", "otp"}, time.Now())
	if u := h.authorize(strong, authzQuery(cl, ch, url.Values{"acr_values": {acrMFA}})); u.Query().Get("code") == "" {
		t.Fatalf("mfa session refused: %s", u)
	}
	for _, v := range []string{acrBasic + " " + acrMFA, "1 2", acrBasic} { // basic preferred, unknown only, basic
		u := h.authorize(weak, authzQuery(cl, ch, url.Values{"acr_values": {v}}))
		if u.Query().Get("code") == "" {
			t.Fatalf("acr_values %q refused a password session: %s", v, u)
		}
		if h.p.FlowWantsMFA(context.Background(), "/oauth/authorize/resume?flow=x") {
			t.Fatal("unknown flow wants MFA")
		}
	}
	// an essential acr Quisora cannot give fails instead of signing the user in at another level
	u := h.authorize(strong, authzQuery(cl, ch, url.Values{"claims": {`{"id_token":{"acr":{"essential":true,"values":["urn:other:loa:3"]}}}`}}))
	if u.Query().Get("error") != "unmet_authentication_requirements" || u.Query().Get("code") != "" {
		t.Fatalf("essential unknown acr: %s", u)
	}
	// essential without values only asks that an acr be returned (OIDC Core 5.5.1.1): it always is
	if u := h.authorize(weak, authzQuery(cl, ch, url.Values{"claims": {`{"id_token":{"acr":{"essential":true}}}`}})); u.Query().Get("code") == "" {
		t.Fatalf("essential acr without values refused: %s", u)
	}
	// not essential: ignored
	if u := h.authorize(weak, authzQuery(cl, ch, url.Values{"claims": {`{"id_token":{"acr":{"values":["urn:other:loa:3"]}}}`}})); u.Query().Get("code") == "" {
		t.Fatalf("voluntary unknown acr refused: %s", u)
	}
	r, _ := h.login(cl, secret, url.Values{"acr_values": {acrBasic + " " + acrMFA}})
	if acr := claimsOf(t, r.str("id_token"))["acr"]; !slices.Contains([]any{acrBasic, acrMFA}, acr) {
		t.Fatalf("acr %v", acr)
	}
}

// The phone scope carries the contact number and whether it was verified; without a number, neither claim.
func TestPhoneScope(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) {
		in.Scopes = &[]string{"openid", "profile", "email", "phone", "offline_access"}
	})
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid phone"}})
	if ui := h.userinfo(r.str("access_token")); ui["phone_number"] != nil || ui["phone_number_verified"] != nil {
		t.Fatalf("no number: %v", ui)
	}
	if _, err := h.env.Svc.UpdateUser(context.Background(), service.System, h.user.ID,
		service.UserInput{Phone: ptr("+44 20 7946 0958"), PhoneVerified: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(h.user.ID) // as the change hook does
	r, _ = h.login(cl, secret, url.Values{"scope": {"openid phone"}})
	if ui := h.userinfo(r.str("access_token")); ui["phone_number"] != "+442079460958" || ui["phone_number_verified"] != true {
		t.Fatalf("userinfo: %v", ui)
	}
	if id := claimsOf(t, r.str("id_token")); id["phone_number"] != "+442079460958" {
		t.Fatalf("id token: %v", id)
	}
}

// The ID token names the organization, tenant and Quisora role only for the "org" scope (as userinfo does); the access
// token always does, for resource servers.
func TestIDTokenOrgClaimsNeedOrgScope(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	id := claimsOf(t, r.str("id_token"))
	for _, k := range []string{"org", "org_name", "tenant", "tenant_name", "role"} {
		if _, ok := id[k]; ok {
			t.Errorf("id token without the org scope has %q", k)
		}
	}
	if at := claimsOf(t, r.str("access_token")); at["org"] == nil || at["role"] == nil {
		t.Errorf("access token lost the org claims: %v", at)
	}
	r, _ = h.login(cl, secret, url.Values{"scope": {"openid profile email org"}})
	if id := claimsOf(t, r.str("id_token")); id["org"] == nil || id["tenant_name"] == nil || id["role"] == nil {
		t.Errorf("id token with the org scope: %v", id)
	}
}

func TestTagsClaim(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	svc := h.env.Svc
	cl, secret := h.newClient(nil)
	scope := url.Values{"scope": {"openid offline_access"}} // access tokens carry tags whatever the scopes

	r, _ := h.login(cl, secret, scope)
	rt := r.str("refresh_token")
	if _, has := claimsOf(t, r.str("access_token"))["tags"]; has {
		t.Fatal("tags claim present without any tags")
	}
	if _, has := claimsOf(t, r.str("id_token"))["tags"]; has {
		t.Fatal("tags in the ID token without any tags")
	}

	tags := []string{"vip", "dept:finance"}
	if _, err := svc.UpdateUser(ctx, h.admin, h.user.ID, service.UserInput{Tags: &tags}); err != nil {
		t.Fatal(err)
	}
	gt := []string{"team:blue", "vip"}
	grp, err := svc.CreateGroup(ctx, h.admin, h.env.Primary.ID, service.GroupInput{DisplayName: ptr("blue"), Tags: &gt})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetMembership(ctx, h.admin, grp.ID, h.user.ID, true); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(h.user.ID)
	h.p.InvalidateMembership(h.env.Primary.ID)

	want := []string{"dept:finance", "team:blue", "vip"}
	access := func() map[string]any {
		x := h.refreshWith(cl, secret, rt)
		if x.status != 200 {
			t.Fatal(x.m)
		}
		return claimsOf(t, x.str("access_token"))
	}
	if got := tagsClaim(access()); !slices.Equal(got, want) {
		t.Fatalf("access token tags %v, want %v", got, want)
	}
	// a new login: without the org scope the ID token and userinfo leave them out; with it they carry them
	r, _ = h.login(cl, secret, scope)
	if got := tagsClaim(claimsOf(t, r.str("id_token"))); len(got) != 0 {
		t.Fatalf("id token tags without the org scope: %v", got)
	}
	r, _ = h.login(cl, secret, url.Values{"scope": {scope.Get("scope") + " org"}})
	if got := tagsClaim(claimsOf(t, r.str("id_token"))); !slices.Equal(got, want) {
		t.Fatalf("id token tags %v", got)
	}
	resp := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+r.str("access_token"))
	var ui map[string]any
	_ = json.Unmarshal([]byte(body(resp)), &ui)
	if got := tagsClaim(ui); !slices.Equal(got, want) {
		t.Fatalf("userinfo tags %v", got)
	}
	// introspection of the access token, the refresh token and (via the same path) an API token
	if got := tagsClaim(h.introspect(cl, secret, r.str("access_token"))); !slices.Equal(got, want) {
		t.Fatalf("introspect access token tags %v", got)
	}
	if got := tagsClaim(h.introspect(cl, secret, r.str("refresh_token"))); !slices.Equal(got, want) {
		t.Fatalf("introspect refresh token tags %v", got)
	}

	// removing a tag from the group: still served from the cache until the membership generation moves
	gt2 := []string{"team:blue"}
	if _, err := svc.UpdateGroup(ctx, h.admin, grp.ID, service.GroupInput{Tags: &gt2}); err != nil {
		t.Fatal(err)
	}
	if got := tagsClaim(access()); !slices.Equal(got, want) {
		t.Fatalf("expected cached tags, got %v", got)
	}
	h.p.InvalidateMembership(h.env.Primary.ID)
	if got := tagsClaim(access()); !slices.Equal(got, []string{"dept:finance", "team:blue", "vip"}) {
		// "vip" stays: the user carries it too
		t.Fatalf("after invalidation %v", got)
	}
	// removing the user's own tag drops it now that no group has it either
	none := []string{}
	if _, err := svc.UpdateUser(ctx, h.admin, h.user.ID, service.UserInput{Tags: &none}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(h.user.ID)
	if got := tagsClaim(access()); !slices.Equal(got, []string{"team:blue"}) {
		t.Fatalf("after removing user tags %v", got)
	}
	// deleting the group removes its tags
	if err := svc.DeleteGroup(ctx, h.admin, grp.ID); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateMembership(h.env.Primary.ID)
	if _, has := access()["tags"]; has {
		t.Fatal("tags claim still present after the last tag went away")
	}
}

func tagsClaim(m map[string]any) []string {
	var out []string
	l, _ := m["tags"].([]any)
	for _, v := range l {
		out = append(out, v.(string))
	}
	return out
}

// RFC 6750 §2: a client must not use more than one method to send the token; query tokens are not supported.
func TestUserinfoRequestShapes(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid"}})
	at := r.str("access_token")
	send := func(query string, form url.Values, auth string) int {
		req, _ := http.NewRequest(http.MethodPost, h.env.URL+"/oauth/userinfo"+query, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := h.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body(resp)
		return resp.StatusCode
	}
	for name, tc := range map[string]struct {
		query string
		form  url.Values
		auth  string
		want  int
	}{
		"header":              {"", nil, "Bearer " + at, 200},
		"form body":           {"", url.Values{"access_token": {at}}, "", 200},
		"header and form":     {"", url.Values{"access_token": {at}}, "Bearer " + at, 400},
		"two form tokens":     {"", url.Values{"access_token": {at, at}}, "", 400},
		"query string":        {"?access_token=" + at, nil, "", 400},
		"scheme not accepted": {"", nil, "Basic abc", 401},
	} {
		if got := send(tc.query, tc.form, tc.auth); got != tc.want {
			t.Errorf("%s: %d, want %d", name, got, tc.want)
		}
	}
	if resp := h.get(h.http, "/oauth/userinfo?access_token="+at); resp.StatusCode != 400 {
		t.Errorf("query token on GET: %d", resp.StatusCode)
	}
	// a token without openid has no business at userinfo
	api, _ := h.login(cl, secret, url.Values{"scope": {"api"}})
	resp := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+api.str("access_token"))
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "insufficient_scope") {
		t.Errorf("no openid: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	body(resp)
}

// The enterprise scope carries the work details as one "enterprise" object (ID token, userinfo, access token);
// without the scope they are absent. The profile scope carries locale and zoneinfo.
func TestEnterpriseScope(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) {
		in.Scopes = &[]string{"openid", "profile", "email", "enterprise", "offline_access"}
	})
	until := "2099-06-30"
	if _, err := h.env.Svc.UpdateUser(context.Background(), service.System, h.user.ID, service.UserInput{
		Locale: ptr("en-GB"), ZoneInfo: ptr("Europe/London"), UserType: ptr("contractor"), ValidUntil: &until,
		Work: &service.WorkInput{Title: ptr("Engineer"), Department: ptr("QA"), CostCenter: ptr("CC-9")}}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(h.user.ID)
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid profile enterprise offline_access"}})
	for name, tok := range map[string]string{"id token": r.str("id_token"), "access token": r.str("access_token")} {
		c := claimsOf(t, tok)
		ent, _ := c["enterprise"].(map[string]any)
		if ent["department"] != "QA" || ent["title"] != "Engineer" || ent["cost_center"] != "CC-9" || ent["user_type"] != "contractor" || ent["valid_until"] == nil {
			t.Errorf("%s enterprise claim: %v", name, c["enterprise"])
		}
	}
	if c := claimsOf(t, r.str("id_token")); c["zoneinfo"] != "Europe/London" || c["locale"] != "en-GB" {
		t.Errorf("profile claims: %v %v", c["zoneinfo"], c["locale"])
	}
	resp := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+r.str("access_token"))
	var ui map[string]any
	_ = json.Unmarshal([]byte(body(resp)), &ui)
	if ui["enterprise"] == nil {
		t.Errorf("userinfo without enterprise: %v", ui)
	}
	// not asked for: not sent
	r2, _ := h.login(cl, secret, url.Values{"scope": {"openid profile offline_access"}})
	if c := claimsOf(t, r2.str("id_token")); c["enterprise"] != nil {
		t.Error("enterprise claim without the scope")
	}
}

// The scope list is capped, and the claims parameter is bounded and takes only string authentication class references.
func TestParseClaimsParamAndScopeCap(t *testing.T) {
	t.Parallel()
	if n := len(splitScope(strings.Repeat("s ", maxScopes+10))); n != maxScopes {
		t.Fatalf("scopes not capped: %d", n)
	}
	if _, err := parseClaimsParam(strings.Repeat("x", maxClaimsParam+1), nil); err == nil {
		t.Fatal("long claims")
	}
	cp, err := parseClaimsParam(`{"id_token":{"acr":{"essential":true,"value":"urn:a","values":["urn:b",7,""]}}}`, nil)
	if err != nil || !cp.ACREssential || len(cp.ACR) != 2 || cp.ACR[0] != "urn:a" || cp.ACR[1] != "urn:b" {
		t.Fatalf("%+v %v", cp, err)
	}
}
