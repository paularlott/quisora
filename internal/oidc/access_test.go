package oidc

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// orgScope asks for the organization claims (org, tenant, role, tags, roles) in ID tokens and at userinfo.
var orgScope = url.Values{"scope": {"openid profile email offline_access org"}}

func membersOnly() model.TenantSettings {
	return model.TenantSettings{MembersOnly: true, PasswordLogin: true, PasskeyLogin: true, AllProviders: true}
}

func (h *harness) grant(tn *model.Tenant, typ, id string, in service.AccessInput) *service.AccessEntry {
	h.t.Helper()
	in.SubjectType, in.SubjectID = typ, id
	e, err := h.env.Svc.AddAccess(context.Background(), h.admin, tn.ID, in)
	if err != nil {
		h.t.Fatal(err)
	}
	return e
}

// tryCode runs authorize for a signed-in browser and reports the code, or the status and body of the refusal.
func (h *harness) tryCode(c *http.Client, cl *model.Client, challenge string, extra url.Values) (code string, status int, text string) {
	h.t.Helper()
	resp := h.get(c, "/oauth/authorize?"+authzQuery(cl, challenge, extra).Encode())
	if resp.StatusCode == http.StatusFound {
		u := loc(h.t, resp)
		return u.Query().Get("code"), resp.StatusCode, u.Query().Get("error")
	}
	return "", resp.StatusCode, body(resp)
}

func strsOf(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func TestTenantAccessMembersOnly(t *testing.T) {
	ctx := context.Background()
	h := setup(t, nil)
	tn := h.tenant("staff", membersOnly())
	cl, secret := h.tenantClient(tn, nil)
	other, osecret := h.tenantClient(tn, nil)
	c, _ := h.session(h.user)
	v, ch := pkce()

	// no access: a clear page (403), and access_denied for prompt=none
	if code, st, text := h.tryCode(c, cl, ch, nil); code != "" || st != http.StatusForbidden || !strings.Contains(text, "do not have access") {
		t.Fatalf("no access: %d %q", st, text)
	}
	if code, _, e := h.tryCode(c, cl, ch, url.Values{"prompt": {"none"}}); code != "" || e != "access_denied" {
		t.Fatalf("prompt=none: %q", e)
	}

	// direct access to one client only, with roles and tags
	e := h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{AllClients: ptr(false), Clients: &[]string{cl.ID},
		Roles: &[]string{"editor"}, Tags: &[]string{"team:blue"}})
	code := h.getCode(c, cl, ch, orgScope)
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}, cl, secret)
	if r.status != 200 {
		t.Fatalf("exchange: %d %v", r.status, r.m)
	}
	for _, tok := range []string{r.str("access_token"), r.str("id_token")} {
		cm := claimsOf(t, tok)
		if !slices.Equal(strsOf(cm["roles"]), []string{"editor"}) || !slices.Contains(strsOf(cm["tags"]), "team:blue") {
			t.Fatalf("claims: %v", cm)
		}
	}
	// the other client of the tenant is not covered
	if code, st, _ := h.tryCode(c, other, ch, nil); code != "" || st != http.StatusForbidden {
		t.Fatalf("other client: %d", st)
	}

	// a group adds the other client and more roles (union)
	g, err := h.env.Svc.CreateGroup(ctx, h.admin, h.env.Primary.ID, service.GroupInput{DisplayName: ptr("Ops")})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.env.Svc.SetMembership(ctx, h.admin, g.ID, h.user.ID, true); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateMembership(h.env.Primary.ID) // the server does this on the change feed
	h.grant(tn, model.SubjectGroup, g.ID, service.AccessInput{Roles: &[]string{"viewer"}})
	r2, _ := h.login(other, osecret, orgScope)
	if roles := strsOf(claimsOf(t, r2.str("access_token"))["roles"]); !slices.Equal(roles, []string{"viewer"}) {
		t.Fatalf("other client roles: %v", roles)
	}
	r3, _ := h.login(cl, secret, orgScope)
	if roles := strsOf(claimsOf(t, r3.str("access_token"))["roles"]); !slices.Equal(roles, []string{"editor", "viewer"}) {
		t.Fatalf("merged roles: %v", roles)
	}

	// userinfo carries the roles too
	ui := h.get(&http.Client{Transport: h.http.Transport}, "/oauth/userinfo", "Authorization", "Bearer "+r3.str("access_token"))
	if text := body(ui); ui.StatusCode != 200 || !strings.Contains(text, `"roles":["editor","viewer"]`) {
		t.Fatalf("userinfo: %d %s", ui.StatusCode, text)
	}

	// expiry: an expired direct entry no longer counts; the group still covers both clients
	past := time.Now().Add(-time.Minute).Format(time.RFC3339)
	if _, err := h.env.Svc.UpdateAccess(ctx, h.admin, tn.ID, e.ID, service.AccessInput{Expires: &past}); err != nil {
		t.Fatal(err)
	}
	r4 := h.refreshWith(cl, secret, r3.str("refresh_token"))
	if r4.status != 200 || !slices.Equal(strsOf(claimsOf(t, r4.str("access_token"))["roles"]), []string{"viewer"}) {
		t.Fatalf("refresh after expiry: %d %v", r4.status, r4.m)
	}

	// removing the group's access ends refresh, userinfo and introspection, and sign-in is refused again
	l, _, err := h.env.Svc.ListAccess(ctx, h.admin, tn.ID, emptyQuery())
	if err != nil || len(l) != 2 {
		t.Fatalf("list: %v %d", err, len(l))
	}
	for _, x := range l {
		if x.SubjectType == model.SubjectGroup {
			if err := h.env.Svc.RemoveAccess(ctx, h.admin, tn.ID, x.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if r := h.refreshWith(cl, secret, r3.str("refresh_token")); r.status != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("refresh after removal: %d %v", r.status, r.m)
	}
	if m := h.introspect(cl, secret, r3.str("refresh_token")); m["active"] != false {
		t.Fatalf("introspect after removal: %v", m)
	}
	ui = h.get(&http.Client{Transport: h.http.Transport}, "/oauth/userinfo", "Authorization", "Bearer "+r3.str("access_token"))
	if ui.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo after removal: %d", ui.StatusCode)
	}
	if code, st, _ := h.tryCode(c, cl, ch, nil); code != "" || st != http.StatusForbidden {
		t.Fatalf("after removal: %d", st)
	}
}

// A code issued while the user had access is refused at the token endpoint once the access is gone.
func TestTenantAccessCheckedAtExchange(t *testing.T) {
	ctx := context.Background()
	h := setup(t, nil)
	tn := h.tenant("staff", membersOnly())
	cl, secret := h.tenantClient(tn, nil)
	e := h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{})
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	if err := h.env.Svc.RemoveAccess(ctx, h.admin, tn.ID, e.ID); err != nil {
		t.Fatal(err)
	}
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}, cl, secret)
	if r.status != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("exchange: %d %v", r.status, r.m)
	}
}

// An open tenant lets everyone in and does not use its access entries (no roles from them).
func TestTenantAccessOpenTenantIgnoresEntries(t *testing.T) {
	h := setup(t, nil)
	open := model.DefaultTenantSettings()
	open.RequireMFA = false // the user signs in with a password alone
	tn := h.tenant("open", open)
	cl, secret := h.tenantClient(tn, nil)
	h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{Roles: &[]string{"admin"}})
	r, _ := h.login(cl, secret, nil)
	if _, ok := claimsOf(t, r.str("access_token"))["roles"]; ok {
		t.Fatal("an open tenant used its access entries")
	}
}

func emptyQuery() store.ListQuery { return store.ListQuery{} }

// The ID token names the organization, tenant and Quisora role only for the "org" scope (as userinfo does); the access
// token always does, for resource servers.
func TestIDTokenOrgClaimsNeedOrgScope(t *testing.T) {
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

// An ID token hint signed by a key that has since been retired and deleted (relying parties keep ID tokens for as long
// as their own sessions last) is treated as absent: the user is asked to confirm, and the redirect is still checked
// against the client the hint names. A tampered hint, or one in an algorithm we never use, is still refused.
func TestLogoutHintWithRetiredKey(t *testing.T) {
	ctx := context.Background()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.PostLogoutURIs = &[]string{"https://rp.example/bye"} })
	r, _ := h.login(cl, secret, nil)
	old := r.str("id_token")
	kid, _ := headerOf(t, old)["kid"].(string)
	if err := h.env.Svc.Keys.Delete(ctx, kid); err != nil {
		t.Fatal(err)
	}
	h.p.Invalidate()
	if err := h.p.EnsureKeys(ctx); err != nil {
		t.Fatal(err)
	}
	c, _ := h.session(h.user)
	q := url.Values{"id_token_hint": {old}, "post_logout_redirect_uri": {"https://rp.example/bye"}}
	resp := h.get(c, "/oauth/logout?"+q.Encode())
	if page := body(resp); resp.StatusCode != 200 || !strings.Contains(page, `action="/oauth/logout/confirm"`) {
		t.Fatalf("retired-key hint: %d", resp.StatusCode)
	}
	// an address the client did not register is still refused
	q.Set("post_logout_redirect_uri", "https://evil.example/")
	if resp := h.get(c, "/oauth/logout?"+q.Encode()); resp.StatusCode != 400 {
		t.Fatalf("unregistered address with a retired-key hint: %d", resp.StatusCode)
	}
	// a current key with a broken signature, and an algorithm Quisora never signs with, are refused
	r2, _ := h.login(cl, secret, nil)
	fresh := r2.str("id_token")
	tampered := fresh[:len(fresh)-4] + "AAAA"
	hs := strings.Replace(fresh, strings.Split(fresh, ".")[0], b64url(`{"alg":"HS256","kid":"gone","typ":"JWT"}`), 1)
	for name, tok := range map[string]string{"tampered": tampered, "HS256": hs} {
		if resp := h.get(c, "/oauth/logout?"+url.Values{"id_token_hint": {tok}}.Encode()); resp.StatusCode != 400 {
			t.Errorf("%s hint: %d", name, resp.StatusCode)
		}
	}
}

func b64url(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// A relying party's cross-site POST to the logout endpoint carries no SameSite=Lax cookie: it is turned into a GET
// (a top-level navigation, which does carry it), so the session really ends.
func TestCrossSitePostLogout(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.PostLogoutURIs = &[]string{"https://rp.example/bye"} })
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}, cl, secret)
	form := url.Values{"id_token_hint": {r.str("id_token")}, "post_logout_redirect_uri": {"https://rp.example/bye"}, "state": {"s1"}}
	// without the cookie (as the browser sends it cross-site)
	resp := h.post("/oauth/logout", form, "", "")
	if resp.status != http.StatusSeeOther {
		t.Fatalf("cookieless POST: %d", resp.status)
	}
	loc, _ := url.Parse(resp.hdr.Get("Location"))
	if loc.Path != "/oauth/logout" || loc.Query().Get("id_token_hint") != r.str("id_token") || loc.Query().Get("state") != "s1" {
		t.Fatalf("redirect: %s", loc)
	}
	// the GET, with the session cookie, ends the session and returns to the client
	get := h.get(c, loc.String())
	if get.StatusCode != http.StatusFound || get.Header.Get("Location") != "https://rp.example/bye?state=s1" {
		t.Fatalf("GET logout: %d %q", get.StatusCode, get.Header.Get("Location"))
	}
	if _, sess := h.env.Server.Sessions.Current(reqWithCookies(h, c)); sess != nil {
		t.Fatal("the session survived the logout")
	}
}

// A personal api token introspected by an application carries what a sign-in to that application would: the user's
// roles for it and their access's tags, merged from their own entry and their groups'. Without access to a
// members-only tenant's application the token is inactive there; an open tenant's application gets no roles.
func TestAPITokenIntrospectionCarriesAccess(t *testing.T) {
	ctx := context.Background()
	h := setup(t, nil)
	tn := h.tenant("apps", membersOnly())
	app, appSecret := h.tenantClient(tn, nil)
	open, openSecret := h.newClient(nil)
	tags := []string{"vpn"}
	if _, err := h.env.Svc.UpdateUser(ctx, h.admin, h.user.ID, service.UserInput{Tags: &tags}); err != nil {
		t.Fatal(err)
	}
	_, tok, err := h.env.Svc.CreateAPIToken(ctx, service.ActorForUser(h.user, ""), service.APITokenInput{Name: "script", Scopes: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := h.introspect(app, appSecret, tok); got["active"] != false {
		t.Fatalf("no access, still active: %v", got)
	}

	h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{Roles: &[]string{"editor"}, Tags: &[]string{"team:blue"}})
	g, err := h.env.Svc.CreateGroup(ctx, h.admin, h.env.Primary.ID, service.GroupInput{DisplayName: ptr("Ops"), Tags: &[]string{"dept:ops"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.env.Svc.SetMembership(ctx, h.admin, g.ID, h.user.ID, true); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateMembership(h.env.Primary.ID)
	h.grant(tn, model.SubjectGroup, g.ID, service.AccessInput{Roles: &[]string{"viewer"}})

	got := h.introspect(app, appSecret, tok)
	if got["active"] != true || got["scope"] != "api" || !slices.Equal(strsOf(got["roles"]), []string{"editor", "viewer"}) ||
		!slices.Equal(strsOf(got["tags"]), []string{"dept:ops", "team:blue", "vpn"}) {
		t.Fatalf("members-only app: %v", got)
	}
	got = h.introspect(open, openSecret, tok)
	if got["active"] != true || got["roles"] != nil || !slices.Equal(strsOf(got["tags"]), []string{"dept:ops", "vpn"}) {
		t.Fatalf("open app: %v", got)
	}
}

// A token narrowed to application scopes: the application declaring them sees "api" and those scopes; another
// application, declaring none of them, sees the token inactive (else "api" alone would read as full access). An
// unnarrowed token is "api" everywhere.
func TestAPITokenIntrospectionAppScopes(t *testing.T) {
	ctx := context.Background()
	h := setup(t, nil)
	orders, ordersSecret := h.newClient(func(in *service.ClientInput) { in.Scopes = ptr([]string{"openid", "orders:read", "orders:write"}) })
	billing, billingSecret := h.newClient(func(in *service.ClientInput) { in.Scopes = ptr([]string{"billing:read"}) })
	a := service.ActorForUser(h.user, "")
	_, narrow, err := h.env.Svc.CreateAPIToken(ctx, a, service.APITokenInput{Name: "n", Scopes: []string{"api"},
		Audience: []string{orders.ID, billing.ID}, AppScopes: []string{"orders:read"}}) // billing may see it, but declares none of its scopes
	if err != nil {
		t.Fatal(err)
	}
	_, full, _ := h.env.Svc.CreateAPIToken(ctx, a, service.APITokenInput{Name: "f", Scopes: []string{"api"}})
	if got := h.introspect(orders, ordersSecret, narrow); got["active"] != true || got["scope"] != "api orders:read" {
		t.Fatalf("orders, narrowed: %v", got)
	}
	if got := h.introspect(billing, billingSecret, narrow); got["active"] != false {
		t.Fatalf("billing, narrowed to orders: %v", got)
	}
	for _, c := range []struct {
		cl  *model.Client
		sec string
	}{{orders, ordersSecret}, {billing, billingSecret}} {
		if got := h.introspect(c.cl, c.sec, full); got["active"] != true || got["scope"] != "api" {
			t.Fatalf("%s, full: %v", c.cl.Name, got)
		}
	}
}
