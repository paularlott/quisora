package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// forge signs claims with the provider's own key (what only the provider can do), with the given typ header.
func (h *harness) forge(typ string, payload []byte) string {
	h.t.Helper()
	key, err := h.p.signingKey(context.Background(), h.env.Cfg.Tokens.SigningAlg)
	if err != nil {
		h.t.Fatal(err)
	}
	tok, err := key.sign(typ, payload)
	if err != nil {
		h.t.Fatal(err)
	}
	return tok
}

func (h *harness) forgeAccess(cl *model.Client, edit func(map[string]any)) string {
	now := time.Now()
	m := map[string]any{"iss": h.p.issuer, "sub": h.user.ID, "client_id": cl.ID, "aud": []string{cl.ID}, "scope": "openid",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": secureID()}
	if edit != nil {
		edit(m)
	}
	for k, v := range m {
		if v == nil {
			delete(m, k)
		}
	}
	return h.forge(typAccess, mustJSON(m))
}

func TestCoverageVerifyAccessTokenRefusals(t *testing.T) {
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	ctx := context.Background()
	if _, err := h.p.VerifyAccessToken(ctx, h.forgeAccess(cl, nil)); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, tok := range map[string]string{
		"id token typ":  h.forge(typJWT, mustJSON(map[string]any{"iss": h.p.issuer})),
		"claims shape":  h.forge(typAccess, []byte(`[1]`)),
		"issuer":        h.forgeAccess(cl, func(m map[string]any) { m["iss"] = "https://evil.example" }),
		"no expiry":     h.forgeAccess(cl, func(m map[string]any) { m["exp"] = nil }),
		"expired":       h.forgeAccess(cl, func(m map[string]any) { m["exp"] = time.Now().Add(-time.Hour).Unix() }),
		"not yet":       h.forgeAccess(cl, func(m map[string]any) { m["nbf"] = time.Now().Add(time.Hour).Unix() }),
		"future iat":    h.forgeAccess(cl, func(m map[string]any) { m["iat"] = time.Now().Add(time.Hour).Unix() }),
		"no subject":    h.forgeAccess(cl, func(m map[string]any) { m["sub"] = nil }),
		"no client":     h.forgeAccess(cl, func(m map[string]any) { m["client_id"] = nil }),
		"unknown user":  h.forgeAccess(cl, func(m map[string]any) { m["sub"] = "nosuchuser" }),
		"unknown app":   h.forgeAccess(cl, func(m map[string]any) { m["client_id"] = "nosuchclient" }),
		"revoked grant": h.forgeAccess(cl, func(m map[string]any) { m["gid"] = "nosuchgrant" }),
	} {
		if _, err := h.p.VerifyAccessToken(ctx, tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a key that is not published, and a published key id with another algorithm
	ks, err := h.p.keys(ctx)
	if err != nil || len(ks.list) == 0 {
		t.Fatalf("keys: %v", err)
	}
	real := ks.list[0]
	var other assertionKey
	for _, k := range newAssertionKeys(t) {
		if k.alg != real.alg {
			other = k
		}
	}
	fake := func(kid string) string {
		b := mustJSON(map[string]any{"iss": h.p.issuer, "sub": h.user.ID, "client_id": cl.ID, "exp": time.Now().Add(time.Minute).Unix()})
		tok, err := signJWT(other.alg, other.priv, mkHeader(other.alg, kid, typAccess), b)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	for _, kid := range []string{"nokey", real.rec.ID} {
		if _, err := h.p.VerifyAccessToken(ctx, fake(kid)); err == nil {
			t.Errorf("kid %s: accepted", kid)
		}
	}
}

func TestCoverageVerifyAccessTokenUnavailable(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	at := r.str("access_token")
	gid := claimsOf(t, at)["gid"].(string)
	ctx := context.Background()

	clients := h.env.Svc.Clients.S
	h.env.Svc.Clients.S = failReads{Store: clients, kind: model.KindClient}
	h.p.InvalidateClient(cl.ID)
	if _, err := h.p.VerifyAccessToken(ctx, h.forgeAccess(cl, nil)); !isUnavailable(err) {
		t.Fatalf("client read: %v", err)
	}
	h.env.Svc.Clients.S = clients

	users := h.env.Svc.Users.S
	h.env.Svc.Users.S = failReads{Store: users, kind: model.KindUser}
	h.p.users.clear()
	if _, err := h.p.VerifyAccessToken(ctx, at); !isUnavailable(err) {
		t.Fatalf("user read: %v", err)
	}
	ui := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+at)
	if ui.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("userinfo with unreadable user: %d", ui.StatusCode)
	}
	body(ui)
	h.env.Svc.Users.S = users
	h.p.users.clear()

	grants := h.env.Svc.Grants.S
	h.env.Svc.Grants.S = failReads{Store: grants, kind: model.KindGrant}
	h.p.InvalidateGrant(gid)
	if _, err := h.p.VerifyAccessToken(ctx, at); !isUnavailable(err) {
		t.Fatalf("grant read: %v", err)
	}
	// revocation and introspection cannot decide either
	f := url.Values{"token": {at}, "client_id": {cl.ID}, "client_secret": {secret}}
	expectUnavailable(t, "revoke", h.post("/oauth/revoke", f, "", ""))
	expectUnavailable(t, "introspect", h.post("/oauth/introspect", f, "", ""))
	f.Set("token", r.str("refresh_token"))
	expectUnavailable(t, "revoke refresh", h.post("/oauth/revoke", f, "", ""))
	h.env.Svc.Grants.S = grants
	h.p.InvalidateGrant(gid)

	orgs := h.env.Svc.Orgs.S
	h.env.Svc.Orgs.S = failReads{Store: orgs, kind: model.KindOrg}
	h.p.orgs.clear()
	h.p.users.clear()
	_, err := h.p.VerifyAccessToken(ctx, at)
	h.env.Svc.Orgs.S = orgs
	h.p.orgs.clear()
	if err != nil && !isUnavailable(err) {
		t.Fatalf("org read: %v", err)
	}
	// exchange of a subject token that cannot be checked: the caller retries
	app, asecret := h.newClient(withExchange)
	r2, _ := h.login(app, asecret, url.Values{"scope": {"openid profile email api"}})
	h.env.Svc.Users.S = failReads{Store: users, kind: model.KindUser}
	h.p.users.clear()
	expectUnavailable(t, "exchange", h.exchange(app, asecret, r2.str("access_token"), nil))
	h.env.Svc.Users.S = users
	h.p.users.clear()
}

func isUnavailable(err error) bool {
	return err != nil && strings.Contains(err.Error(), service.ErrUnavailable.Error())
}

func TestCoverageUserinfoRequestShapes(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid"}})
	at := r.str("access_token")
	// two tokens in the form body, a scheme that is neither Bearer nor DPoP, a token in the query string
	post := func(form url.Values, auth string) int {
		req, _ := http.NewRequest(http.MethodPost, h.env.URL+"/oauth/userinfo", strings.NewReader(form.Encode()))
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
	if st := post(url.Values{"access_token": {at, at}}, ""); st != 400 {
		t.Fatalf("two form tokens: %d", st)
	}
	if st := post(url.Values{"access_token": {at}}, "Bearer "+at); st != 400 {
		t.Fatalf("header and form: %d", st)
	}
	if st := post(url.Values{"access_token": {at}}, ""); st != 200 {
		t.Fatalf("form token: %d", st)
	}
	if st := post(nil, "Basic abc"); st != 401 {
		t.Fatalf("basic scheme: %d", st)
	}
	if resp := h.get(h.http, "/oauth/userinfo?access_token="+at); resp.StatusCode != 400 {
		t.Fatalf("query token: %d", resp.StatusCode)
	}
	// a token without openid has no business at userinfo
	api, _ := h.login(cl, secret, url.Values{"scope": {"api"}})
	resp := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+api.str("access_token"))
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "insufficient_scope") {
		t.Fatalf("no openid: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	body(resp)
}

func TestCoverageRevokeAndIntrospectRefusals(t *testing.T) {
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

func TestCoverageIntrospectionDetails(t *testing.T) {
	h := setup(t, nil)
	tn := h.tenant("detail", membersOnly())
	cl, secret := h.tenantClient(tn, nil)
	h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{Roles: ptr([]string{"editor"}), Tags: ptr([]string{"gold"})})
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid profile email groups org"}})
	m := h.introspect(cl, secret, r.str("access_token"))
	if m["active"] != true || strsOf(m["roles"]) == nil && strsOf(m["tags"]) == nil {
		t.Logf("introspection: %v", m)
	}
	if m["active"] != true {
		t.Fatalf("%v", m)
	}
	rm := h.introspect(cl, secret, r.str("refresh_token"))
	if rm["active"] != true || rm["token_kind"] != "refresh_token" {
		t.Fatalf("%v", rm)
	}
}
