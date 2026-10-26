package oidc

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func TestIntrospection(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	at, rt := r.str("access_token"), r.str("refresh_token")

	m := h.introspect(cl, secret, at)
	if m["active"] != true || m["sub"] != h.user.ID || m["client_id"] != cl.ID || m["username"] != "alice" ||
		m["token_type"] != "Bearer" || m["scope"] != "openid profile email offline_access" || m["exp"] == nil || m["iss"] != h.env.URL {
		t.Fatalf("jwt: %v", m)
	}
	m = h.introspect(cl, secret, rt)
	if m["active"] != true || m["token_type"] != nil || m["token_kind"] != "refresh_token" || m["sub"] != h.user.ID || m["username"] != "alice" {
		t.Fatalf("refresh: %v", m)
	}
	// another client of the organization does not see our access token as active, unless it may introspect every
	// token of the organization; it never sees our refresh token
	other, osecret := h.newClient(nil)
	if h.introspect(other, osecret, at)["active"] != false {
		t.Fatal("jwt introspection by another client")
	}
	rs, rsecret := h.newClient(func(in *service.ClientInput) { in.IntrospectOrg = ptr(true) })
	if m := h.introspect(rs, rsecret, at); m["active"] != true || m["sub"] != h.user.ID {
		t.Fatalf("jwt introspection by an introspect_org client: %v", m)
	}
	if h.introspect(other, osecret, rt)["active"] != false {
		t.Fatal("refresh token visible to another client")
	}
	// API token
	_, plain, err := h.env.Svc.CreateAPIToken(context.Background(), service.ActorForUser(h.user, ""), service.APITokenInput{Name: "t", Scopes: []string{"api"}, Expires: 30})
	if err != nil {
		t.Fatal(err)
	}
	m = h.introspect(other, osecret, plain)
	if m["active"] != true || m["token_type"] != "Bearer" || m["token_kind"] != "api_token" || m["sub"] != h.user.ID || m["scope"] != "api" || m["username"] != "alice" ||
		m["org"] != h.env.Primary.ID || m["exp"] == nil {
		t.Fatalf("api token: %v", m)
	}
	if h.introspect(other, osecret, plain+"x")["active"] != false {
		t.Fatal("bad api token active")
	}
	// garbage, forged, wrong typ, expired
	for _, bad := range []string{"garbage", "eyJhbGciOiJub25lIn0.e30.", at + "x", at[:len(at)-4], "qsr_x_y"} {
		if h.introspect(cl, secret, bad)["active"] != false {
			t.Errorf("%q active", bad)
		}
	}
	if h.introspect(cl, secret, r.str("id_token"))["active"] != false {
		t.Error("ID token introspected as access token")
	}
	// client credentials JWT
	cc := h.token(url.Values{"grant_type": {"client_credentials"}}, cl, secret)
	if m := h.introspect(cl, secret, cc.str("access_token")); m["active"] != true || m["sub"] != cl.ID {
		t.Fatalf("cc: %v", m)
	}
	// unauthenticated and wrong credentials
	if r := h.post("/oauth/introspect", url.Values{"token": {at}}, "", ""); r.status != 401 {
		t.Fatal(r.status)
	}
	if r := h.clientPost("/oauth/introspect", url.Values{"token": {at}}, cl, "wrong"); r.status != 401 {
		t.Fatal(r.status)
	}
	if r := h.clientPost("/oauth/introspect", url.Values{}, cl, secret); r.status != 400 {
		t.Fatal(r.status)
	}
	// an expired token: the real token's claims, back-dated and signed again with the server's key
	claims := claimsOf(t, at)
	claims["iat"], claims["exp"] = time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-time.Hour).Unix()
	if h.introspect(cl, secret, h.forge(typAccess, mustJSON(claims)))["active"] != false {
		t.Fatal("expired token active")
	}
	if h.introspect(cl, secret, at)["active"] != true {
		t.Fatal("the unexpired original is no longer active")
	}
}

// Introspection of a token carries what the resource needs to decide: the user's groups, and the tags and roles they
// have for the application, for the access token and the refresh token alike.
func TestIntrospectionCarriesGroupsTagsAndRoles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	tn := h.tenant("detail", membersOnly())
	cl, secret := h.tenantClient(tn, nil)
	h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{Roles: &[]string{"editor"}, Tags: &[]string{"gold"}})
	g, err := h.env.Svc.CreateGroup(ctx, h.admin, h.env.Primary.ID, service.GroupInput{DisplayName: ptr("Ops")})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.env.Svc.SetMembership(ctx, h.admin, g.ID, h.user.ID, true); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateMembership(h.env.Primary.ID)
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid profile email groups org offline_access"}})
	for name, tok := range map[string]string{"access token": r.str("access_token"), "refresh token": r.str("refresh_token")} {
		m := h.introspect(cl, secret, tok)
		if m["active"] != true || !slices.Equal(strsOf(m["roles"]), []string{"editor"}) || !slices.Contains(strsOf(m["tags"]), "gold") {
			t.Errorf("%s: %v", name, m)
		}
	}
	if m := h.introspect(cl, secret, r.str("access_token")); !slices.Equal(strsOf(m["groups"]), []string{"Ops"}) {
		t.Errorf("groups: %v", m["groups"])
	}
}

func TestIntrospectionRejectsForeignKeyAndAlgConfusion(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	at := r.str("access_token")
	hd := headerOf(t, at)
	// valid kid, signature from an attacker key
	k := genKeys(t)[0]
	forged := signWith(t, k, hd["kid"].(string), "at+jwt", string(mustJSON(claimsOf(t, at))))
	if h.introspect(cl, secret, forged)["active"] != false {
		t.Fatal("forged token active")
	}
	// HS256 using the public JWK as the secret
	jw := body(h.get(h.http, "/oauth/jwks"))
	hh := b64.EncodeToString([]byte(`{"alg":"HS256","kid":"` + hd["kid"].(string) + `","typ":"at+jwt"}`))
	pl := b64.EncodeToString(mustJSON(claimsOf(t, at)))
	tok := hh + "." + pl + "." + b64.EncodeToString([]byte(jw))
	if h.introspect(cl, secret, tok)["active"] != false {
		t.Fatal("HS256 token active")
	}
}

// Introspection must not be a cross-tenant oracle.
func TestIntrospectionTenantIsolation(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	at := r.str("access_token")
	_, plain, err := h.env.Svc.CreateAPIToken(ctx, service.ActorForUser(h.user, ""), service.APITokenInput{Name: "t", Scopes: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	isInactive := func(c *model.Client, s, tok string) {
		t.Helper()
		resp := h.clientPost("/oauth/introspect", url.Values{"token": {tok}}, c, s)
		if resp.status != 200 || len(resp.m) != 1 || resp.m["active"] != false {
			t.Fatalf("want exactly {active:false}, got %v", resp.m)
		}
	}

	// a same-org client that is not the audience sees the API token (it has no audience) but not the access token;
	// a resource server allowed to introspect every token of the organization sees both
	other, otherSecret := h.newClient(nil)
	if h.introspect(other, otherSecret, at)["active"] != false || h.introspect(other, otherSecret, plain)["active"] != true {
		t.Fatal("same-org client without introspect_org")
	}
	rs, rsSecret := h.newClient(func(in *service.ClientInput) { in.IntrospectOrg = ptr(true) })
	if h.introspect(rs, rsSecret, at)["active"] != true || h.introspect(rs, rsSecret, plain)["active"] != true {
		t.Fatal("same-org introspect_org client cannot introspect")
	}

	// a client of another org gets nothing
	org2, err := h.env.Svc.CreateOrg(ctx, h.admin, service.OrgInput{Name: ptr("acme"), DisplayName: ptr("Acme")})
	if err != nil {
		t.Fatal(err)
	}
	foreign, fsecret, err := h.env.Svc.CreateClient(ctx, h.admin, org2.ID, service.ClientInput{Name: ptr("foreign"),
		RedirectURIs: &[]string{rpCallback}, GrantTypes: &[]string{"authorization_code"}, FirstParty: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	isInactive(foreign, fsecret, at)
	isInactive(foreign, fsecret, plain)

	// a foreign-org user's token is invisible to our org's client, visible to its own org's client
	pw := "correct horse battery"
	u2, err := h.env.Svc.CreateUser(ctx, service.System, org2.ID, service.UserInput{GivenName: ptr("T"), Username: ptr("bob"), Email: ptr("bob@acme.test"),
		Password: &pw, Verified: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	_, plain2, err := h.env.Svc.CreateAPIToken(ctx, service.ActorForUser(u2, ""), service.APITokenInput{Name: "t", Scopes: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	isInactive(rs, rsSecret, plain2)
	if h.introspect(foreign, fsecret, plain2)["active"] != true {
		t.Fatal("own-org API token not visible")
	}
}

// Personal API tokens: only a token made for applications (the api scope) is active to them, only to the clients
// in its audience when it has one, and introspection names its scope and audience.
func TestIntrospectAPITokenScopeAndAudience(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	rs, rsSecret := h.newClient(nil)
	other, otherSecret := h.newClient(nil)

	// A token for Quisora's own APIs is no application's business.
	_, adminTok, err := h.env.Svc.CreateAPIToken(ctx, h.admin, service.APITokenInput{Name: "ops", Scopes: []string{service.ScopeAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	if m := h.introspect(rs, rsSecret, adminTok); m["active"] != false || len(m) != 1 {
		t.Fatalf("admin-scope token introspected: %v", m)
	}
	// Mixing api with Quisora's own scopes is refused at mint.
	if _, _, err := h.env.Svc.CreateAPIToken(ctx, h.admin, service.APITokenInput{Name: "mix", Scopes: []string{service.ScopeAPI, service.ScopeAdmin}}); err == nil {
		t.Fatal("minted an api+admin token")
	}

	// An api token without an audience: any confidential client of the org.
	_, open, err := h.env.Svc.CreateAPIToken(ctx, service.ActorForUser(h.user, ""), service.APITokenInput{Name: "open", Scopes: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	if m := h.introspect(other, otherSecret, open); m["active"] != true || m["scope"] != "api" || m["aud"] != nil {
		t.Fatalf("open api token: %v", m)
	}

	// With an audience: only the listed client.
	_, scoped, err := h.env.Svc.CreateAPIToken(ctx, service.ActorForUser(h.user, ""), service.APITokenInput{Name: "rs only",
		Scopes: []string{"api"}, Audience: []string{rs.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if m := h.introspect(rs, rsSecret, scoped); m["active"] != true || m["aud"] != rs.ID || m["scope"] != "api" {
		t.Fatalf("audience client: %v", m)
	}
	if m := h.clientPost("/oauth/introspect", url.Values{"token": {scoped}}, other, otherSecret); len(m.m) != 1 || m.m["active"] != false {
		t.Fatalf("client outside the audience: %v", m.m)
	}
	// An audience is for api tokens, and names clients of the owner's organization only.
	if _, _, err := h.env.Svc.CreateAPIToken(ctx, h.admin, service.APITokenInput{Name: "x", Scopes: []string{service.ScopeAdmin},
		Audience: []string{rs.ID}}); err == nil {
		t.Fatal("audience on an admin token")
	}
	if _, _, err := h.env.Svc.CreateAPIToken(ctx, service.ActorForUser(h.user, ""), service.APITokenInput{Name: "x", Scopes: []string{"api"},
		Audience: []string{"no-such-client"}}); err == nil {
		t.Fatal("unknown audience accepted")
	}
}

// A personal api token introspected by an application carries what a sign-in to that application would: the user's
// roles for it and their access's tags, merged from their own entry and their groups'. Without access to a
// members-only tenant's application the token is inactive there; an open tenant's application gets no roles.
func TestAPITokenIntrospectionCarriesAccess(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

func TestRevocation(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	other, osecret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	rt, at := r.str("refresh_token"), r.str("access_token")

	// another client's revoke is a no-op but still 200
	if x := h.clientPost("/oauth/revoke", url.Values{"token": {rt}}, other, osecret); x.status != 200 {
		t.Fatal(x.status)
	}
	if h.refreshWith(cl, secret, rt).status != 200 {
		t.Fatal("foreign revoke worked")
	}
	for _, junk := range []string{"garbage", "a.b"} {
		if x := h.clientPost("/oauth/revoke", url.Values{"token": {junk}}, cl, secret); x.status != 200 {
			t.Fatalf("%q: %d", junk, x.status)
		}
	}
	if x := h.post("/oauth/revoke", url.Values{"token": {rt}}, "", ""); x.status != 401 {
		t.Fatal("unauthenticated revoke", x.status)
	}
	if x := h.clientPost("/oauth/revoke", url.Values{"token": {rt}}, cl, secret); x.status != 200 {
		t.Fatal(x.status)
	}
	if h.refreshWith(cl, secret, rt).status != 400 {
		t.Fatal("revoked refresh token works")
	}
	h.p.InvalidateGrant(claimsOf(t, at)["gid"].(string))
	if h.introspect(cl, secret, at)["active"] != false {
		t.Fatal("access token active after its grant was revoked")
	}
	// API tokens are not revocable here, and the answer says so rather than claiming success (RFC 7009 §2.2.1)
	_, plain, _ := h.env.Svc.CreateAPIToken(context.Background(), service.ActorForUser(h.user, ""), service.APITokenInput{Name: "t", Scopes: []string{"api"}, Expires: 30})
	for _, tok := range []string{plain, "qsr_a_b"} {
		if x := h.clientPost("/oauth/revoke", url.Values{"token": {tok}}, cl, secret); x.status != 400 || x.str("error") != "unsupported_token_type" {
			t.Fatalf("API token %q: %d %v", tok[:6], x.status, x.m)
		}
	}
	if h.introspect(cl, secret, plain)["active"] != true {
		t.Fatal("API token revoked through /oauth/revoke")
	}
	// revoking an access token ends its grant
	r, _ = h.login(cl, secret, nil)
	h.clientPost("/oauth/revoke", url.Values{"token": {r.str("access_token")}}, cl, secret)
	if h.refreshWith(cl, secret, r.str("refresh_token")).status != 400 {
		t.Fatal("refresh survived access token revocation")
	}
}

func TestRevokeAndIntrospectIgnoreForgedOrStaleRefreshTokens(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	f := func(tok string) url.Values {
		return url.Values{"token": {tok}, "client_id": {cl.ID}, "client_secret": {secret}}
	}
	for _, path := range []string{"/oauth/revoke", "/oauth/introspect"} {
		tokenErr(t, h.post(path, f(""), "", ""), 400, "invalid_request")
	}
	r, _ := h.login(cl, secret, nil)
	rt := r.str("refresh_token")
	parts := strings.Split(rt, ".")
	// refresh tokens that are not the grant's current one are no business of revocation or introspection
	forged := parts[0] + ".0." + b64.EncodeToString([]byte("forged-forged-forged-forged-forge"))
	stale := parts[0] + ".9." + parts[2]
	for _, tok := range []string{forged, stale} {
		if x := h.post("/oauth/revoke", f(tok), "", ""); x.status != 200 {
			t.Fatalf("revoke %d", x.status)
		}
		if h.introspect(cl, secret, tok)["active"] != false {
			t.Fatal("introspected as active")
		}
	}
	if h.refreshWith(cl, secret, rt).status != 200 {
		t.Fatal("the real token was revoked by a forgery")
	}
	// a static token from before rotation began is stale: counted tokens only
	static := parts[0] + "." + b64.EncodeToString(randBytes(32))
	if h.introspect(cl, secret, static)["active"] != false {
		t.Fatal("static token active")
	}
}

// RFC 7009: revoking an access token ends what it was issued from. A client_credentials token has no grant and a JWT
// cannot be recalled, so the revocation is refused as unsupported_token_type (§2.2.1), not answered 200 (which the
// client would take to mean the token is dead).
func TestRevokeClientCredentialsTokenUnsupported(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r := h.token(url.Values{"grant_type": {"client_credentials"}}, cl, secret)
	at := r.str("access_token")
	if h.introspect(cl, secret, at)["active"] != true {
		t.Fatal("fresh token not active")
	}
	if x := h.clientPost("/oauth/revoke", url.Values{"token": {at}}, cl, secret); x.status != 400 || x.str("error") != "unsupported_token_type" {
		t.Fatalf("revoke: %d %v", x.status, x.str("error"))
	}
}
