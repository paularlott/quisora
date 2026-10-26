package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func TestCodeFlowEndToEnd(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	grp, _ := h.env.Svc.CreateGroup(context.Background(), h.admin, h.env.Primary.ID, service.GroupInput{DisplayName: ptr("devs")})
	_ = h.env.Svc.SetMembership(context.Background(), h.admin, grp.ID, h.user.ID, true)

	r, _ := h.login(cl, secret, url.Values{"scope": {"openid profile email groups org offline_access"}, "resource": {"https://api.example/v1"}})
	if r.str("token_type") != "Bearer" || r.str("refresh_token") == "" || r.hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("%v %v", r.m, r.hdr)
	}
	at, idt := r.str("access_token"), r.str("id_token")

	// access token (RFC 9068)
	if hd := headerOf(t, at); hd["typ"] != "at+jwt" || hd["alg"] != "ES256" || hd["kid"] == "" {
		t.Fatalf("header %v", hd)
	}
	ac := claimsOf(t, at)
	aud, _ := ac["aud"].([]any)
	if ac["iss"] != h.env.URL || ac["sub"] != h.user.ID || ac["client_id"] != cl.ID || len(aud) != 2 || aud[0] != cl.ID ||
		aud[1] != "https://api.example/v1" || ac["org"] != h.env.Primary.ID || ac["org_name"] != "primary" ||
		ac["role"] != "user" || ac["jti"] == "" || ac["sid"] == "" || ac["acr"] != acrBasic {
		t.Fatalf("access claims %v", ac)
	}
	if g, _ := ac["groups"].([]any); len(g) != 1 || g[0] != "devs" {
		t.Fatalf("groups %v", ac["groups"])
	}
	// the configured lifetime is the one the response and the token carry
	ttl := h.env.Cfg.Tokens.Access().Seconds()
	if r.m["expires_in"] != ttl || ac["exp"].(float64)-ac["iat"].(float64) != ttl {
		t.Fatalf("lifetime: expires_in %v, exp-iat %v, configured %v", r.m["expires_in"], ac["exp"].(float64)-ac["iat"].(float64), ttl)
	}
	// ID token
	if hd := headerOf(t, idt); hd["typ"] != "JWT" {
		t.Fatalf("id header %v", hd)
	}
	ic := claimsOf(t, idt)
	sum := sha256.Sum256([]byte(at))
	if ic["aud"] != cl.ID || ic["nonce"] != "n1" || ic["email"] != "alice@example.com" || ic["email_verified"] != true ||
		ic["preferred_username"] != "alice" || ic["name"] != "Alice A" || ic["sid"] != ac["sid"] ||
		ic["at_hash"] != b64.EncodeToString(sum[:16]) || ic["auth_time"] == nil || ic["amr"] == nil {
		t.Fatalf("id claims %v", ic)
	}
	// verify both against the published JWKS with an independent path
	jw, _ := ParseJWKS([]byte(body(h.get(h.http, "/oauth/jwks"))))
	pub, _ := jw[0].PublicKey()
	decodeIndependently(t, at, pub)
	decodeIndependently(t, idt, pub)

	// userinfo
	resp := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+at)
	var ui map[string]any
	_ = json.Unmarshal([]byte(body(resp)), &ui)
	if ui["sub"] != h.user.ID || ui["email"] != "alice@example.com" || ui["org_name"] != "primary" || ui["role"] != "user" {
		t.Fatalf("userinfo %v", ui)
	}
	// narrower scope -> fewer claims
	r2 := h.refreshWith(cl, secret, r.str("refresh_token"))
	if r2.status != 200 {
		t.Fatal(r2)
	}
	r3 := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r.str("refresh_token")}, "scope": {"openid"}}, cl, secret)
	resp = h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+r3.str("access_token"))
	ui = map[string]any{}
	_ = json.Unmarshal([]byte(body(resp)), &ui)
	if ui["email"] != nil || ui["sub"] != h.user.ID {
		t.Fatalf("userinfo openid-only %v", ui)
	}
	// bad / missing bearer
	if resp := h.get(h.http, "/oauth/userinfo"); resp.StatusCode != 401 {
		t.Fatal(resp.StatusCode)
	}
	resp = h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+at+"x")
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "invalid_token") {
		t.Fatal(resp.StatusCode, resp.Header)
	}
}

func TestTokenEndpointPKCEAndBindings(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	other, otherSecret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	form := func(code string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}}
	}
	expectErr := func(r tokResp, status int, code string) {
		t.Helper()
		if r.status != status || r.m["error"] != code {
			t.Fatalf("want %d %s, got %d %v", status, code, r.status, r.m)
		}
		if r.hdr.Get("Cache-Control") != "no-store" {
			t.Fatal("no-store missing")
		}
	}
	// wrong verifier burns the code
	code := h.getCode(c, cl, ch, nil)
	bad := form(code)
	bad.Set("code_verifier", strings.Repeat("a", 43))
	expectErr(h.token(bad, cl, secret), 400, "invalid_grant")
	expectErr(h.token(form(code), cl, secret), 400, "invalid_grant")
	// missing verifier
	code = h.getCode(c, cl, ch, nil)
	f := form(code)
	f.Del("code_verifier")
	expectErr(h.token(f, cl, secret), 400, "invalid_grant")
	// short verifier
	code = h.getCode(c, cl, ch, nil)
	f = form(code)
	f.Set("code_verifier", v[:20])
	expectErr(h.token(f, cl, secret), 400, "invalid_grant")
	// wrong redirect_uri
	code = h.getCode(c, cl, ch, nil)
	f = form(code)
	f.Set("redirect_uri", "https://evil.example/cb")
	expectErr(h.token(f, cl, secret), 400, "invalid_grant")
	// another client cannot redeem it
	code = h.getCode(c, cl, ch, nil)
	expectErr(h.token(form(code), other, otherSecret), 400, "invalid_grant")
	// wrong secret
	code = h.getCode(c, cl, ch, nil)
	r := h.token(form(code), cl, "qsrs_wrong")
	expectErr(r, 401, "invalid_client")
	if !strings.HasPrefix(r.hdr.Get("WWW-Authenticate"), "Basic") {
		t.Fatal("WWW-Authenticate missing")
	}
	// the code survived a failed client authentication
	if r := h.token(form(code), cl, secret); r.status != 200 {
		t.Fatalf("%v", r.m)
	}
	// a verifier with characters that are not allowed
	code = h.getCode(c, cl, ch, nil)
	f = form(code)
	f.Set("code_verifier", "bad verifier with spaces and a very long tail 0123456789")
	expectErr(h.token(f, cl, secret), 400, "invalid_grant")
	// an empty, over-long or unknown code
	expectErr(h.token(form(""), cl, secret), 400, "invalid_request")
	expectErr(h.token(form(strings.Repeat("x", 201)), cl, secret), 400, "invalid_request")
	expectErr(h.token(form("nosuchcode"), cl, secret), 400, "invalid_grant")
	// resources: malformed, or registered but not asked for at authorization
	code = h.getCode(c, cl, ch, nil)
	f = form(code)
	f.Set("resource", "nope")
	expectErr(h.token(f, cl, secret), 400, "invalid_target")
	code = h.getCode(c, cl, ch, nil)
	f = form(code)
	f.Set("resource", "https://api.example/a")
	expectErr(h.token(f, cl, secret), 400, "invalid_target")
	// unsupported / missing grant type, no auth at all, both auth methods
	expectErr(h.token(url.Values{"grant_type": {"password"}}, cl, secret), 400, "unsupported_grant_type")
	expectErr(h.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}}, "", ""), 401, "invalid_client")
	expectErr(h.post("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_secret": {secret}}, cl.ID, secret), 400, "invalid_request")
	// grant type not allowed for the client
	h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{GrantTypes: &[]string{"authorization_code"}})
	h.p.InvalidateClient(cl.ID)
	expectErr(h.token(url.Values{"grant_type": {"client_credentials"}}, cl, secret), 400, "unauthorized_client")
	// GET is not allowed
	if resp := h.get(h.http, "/oauth/token"); resp.StatusCode != 405 {
		t.Fatalf("GET token: %d", resp.StatusCode)
	}
	// the user is disabled between code and exchange
	code = h.getCode(c, cl, ch, nil)
	if _, err := h.env.Svc.UpdateUser(context.Background(), h.admin, h.user.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(h.user.ID) // as the change feed does
	rr := h.token(form(code), cl, secret)
	expectErr(rr, 400, "invalid_grant")
	if rr.str("error_description") != "the user is no longer active" {
		t.Fatalf("disabled user: %v", rr.m)
	}
}

// PKCE is required unless a confidential client opts out (require_pkce off); a public client cannot. An opted-out
// client may still use PKCE, and then the verifier is checked; a code issued without a challenge refuses a verifier.
func TestRequirePKCESetting(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	strict, _ := h.newClient(nil)
	loose, lsecret := h.newClient(func(in *service.ClientInput) { in.RequirePKCE = ptr(false) })
	c, _ := h.session(h.user)
	noPKCE := url.Values{"code_challenge": {""}, "code_challenge_method": {""}}

	// default: refused without PKCE
	if u := h.authorize(c, authzQuery(strict, "", noPKCE)); u.Query().Get("error") != "invalid_request" {
		t.Fatalf("strict client without PKCE: %s", u)
	}
	// opted out: a code without PKCE, exchanged without a verifier
	exchange := func(cl *model.Client, secret, code, verifier string) tokResp {
		f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]}}
		if verifier != "" {
			f.Set("code_verifier", verifier)
		}
		return h.token(f, cl, secret)
	}
	code := h.getCode(c, loose, "", noPKCE)
	if r := exchange(loose, lsecret, code, ""); r.status != 200 || r.str("id_token") == "" {
		t.Fatalf("opted-out exchange: %d %v", r.status, r.m)
	}
	// ...a verifier for a code issued without a challenge is refused
	code = h.getCode(c, loose, "", noPKCE)
	v, _ := pkce()
	if r := exchange(loose, lsecret, code, v); r.status != 400 {
		t.Fatalf("verifier without a challenge: %d", r.status)
	}
	// ...and PKCE used anyway is still checked
	v, ch := pkce()
	code = h.getCode(c, loose, ch, nil)
	if r := exchange(loose, lsecret, code, ""); r.status != 400 {
		t.Fatalf("challenge without the verifier: %d", r.status)
	}
	code = h.getCode(c, loose, ch, nil)
	if r := exchange(loose, lsecret, code, v); r.status != 200 {
		t.Fatalf("challenge with the verifier: %d", r.status)
	}

	// the client JSON says so
	if !strict.RequirePKCE() || loose.RequirePKCE() {
		t.Fatal("RequirePKCE")
	}
}

func TestCodeReplayRevokesGrant(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}}
	first := h.token(form, cl, secret)
	if first.status != 200 {
		t.Fatal(first)
	}
	rt := first.str("refresh_token")
	if r := h.refreshWith(cl, secret, rt); r.status != 200 {
		t.Fatal("refresh before replay", r.m)
	}
	if r := h.token(form, cl, secret); r.status != 400 || r.m["error"] != "invalid_grant" {
		t.Fatalf("replay: %v", r)
	}
	if r := h.refreshWith(cl, secret, rt); r.status != 400 {
		t.Fatalf("refresh token survived code replay: %v", r.m)
	}
	h.p.InvalidateGrant(claimsOf(t, first.str("access_token"))["gid"].(string))
	if m := h.introspect(cl, secret, first.str("access_token")); m["active"] != false {
		t.Fatalf("access token still active after replay: %v", m)
	}
}

// A code presented again while its first redemption is still making the grant (the replay found no grant yet to end)
// leaves a mark the first redemption finds: the grant it made is revoked and nothing is issued (RFC 6749 §4.1.2).
func TestCodeReplayDuringRedemptionRevokes(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	_ = h.p.s.Eph.Set(context.Background(), nsReplayed, code, []byte{1}, usedTTL) // the racing replay's mark
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}, cl, secret)
	if r.status != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("a redemption a replay raced: %d %v", r.status, r.m)
	}
	if ev := h.auditEvents("oauth.code.replay"); len(ev) != 1 || ev[0].Detail["grant_revoked"] != "true" {
		t.Fatalf("not revoked: %+v", ev)
	}
}

// A redemption that fails on our side (a store that cannot be read: 503) does not spend the code: the client's retry
// works.
func TestCodeKeptWhenRedemptionFails(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}
	users := h.env.Svc.Users.S
	h.env.Svc.Users.S = failReads(users, model.KindUser)
	h.p.users.clear()
	if r := h.token(form, cl, secret); r.status != 503 {
		t.Fatalf("with the user unreadable: %d %v", r.status, r.m)
	}
	h.env.Svc.Users.S = users
	h.p.users.clear()
	if r := h.token(form, cl, secret); r.status != 200 {
		t.Fatalf("the retry: %d %v", r.status, r.m)
	}
	if r := h.token(form, cl, secret); r.status != 400 {
		t.Fatalf("a third use: %d", r.status)
	}
}

// The code exchange needs the user's session to still be valid (expiry and idle timeout), not merely to exist.
func TestCodeExchangeNeedsLiveSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	for _, s := range sessionsFor(t, h) {
		s.LastSeen, s.IdleTTL = time.Now().Add(-time.Hour), 60
		if err := h.env.Svc.Sessions.Update(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}, cl, secret)
	if r.status != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("exchange after the session went idle: %d %v", r.status, r.m)
	}
}

func TestClientCredentials(t *testing.T) {
	t.Parallel()
	h := setup(t, func(c *config.Config) { c.Audit.Tokens = true })
	cl, secret := h.newClient(nil)
	r := h.token(url.Values{"grant_type": {"client_credentials"}, "resource": {"https://api.example"}}, cl, secret)
	if r.status != 200 || r.str("refresh_token") != "" || r.str("id_token") != "" || r.str("scope") != "api" {
		t.Fatalf("%v", r)
	}
	if len(h.auditEvents("oauth.client_credentials")) != 1 {
		t.Fatal("client_credentials not audited")
	}
	ac := claimsOf(t, r.str("access_token"))
	if ac["sub"] != cl.ID || ac["client_id"] != cl.ID || ac["sid"] != nil || ac["role"] != nil || ac["org"] != h.env.Primary.ID {
		t.Fatalf("%v", ac)
	}
	if r := h.token(url.Values{"grant_type": {"client_credentials"}, "resource": {"not a uri"}}, cl, secret); r.status != 400 || r.str("error") != "invalid_target" {
		t.Errorf("malformed resource: %d %v", r.status, r.m)
	}
	for _, bad := range []string{"openid", "api scim", "admin", "offline_access"} {
		if r := h.token(url.Values{"grant_type": {"client_credentials"}, "scope": {bad}}, cl, secret); r.m["error"] != "invalid_scope" {
			t.Errorf("%q: %v", bad, r.m)
		}
	}
	// SCIM client gets the scim scope
	sc, ssecret := h.newClient(func(in *service.ClientInput) { in.SCIM = ptr(true) })
	r = h.token(url.Values{"grant_type": {"client_credentials"}}, sc, ssecret)
	if !slices.Contains(strings.Fields(r.str("scope")), "scim") {
		t.Fatalf("scim scope missing: %v", r.m)
	}
	// verified by the provider's resource-server helper
	cl2, err := h.p.VerifyAccessToken(context.Background(), r.str("access_token"))
	if err != nil || !cl2.HasScope("scim") {
		t.Fatal(err)
	}
	// disabled client
	h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{Enabled: ptr(false)})
	h.p.InvalidateClient(cl.ID)
	if r2 := h.token(url.Values{"grant_type": {"client_credentials"}}, cl, secret); r2.status != 401 {
		t.Fatalf("disabled client: %d", r2.status)
	}
	if _, err := h.p.VerifyAccessToken(context.Background(), h.token(url.Values{"grant_type": {"client_credentials"}}, sc, ssecret).str("access_token")); err != nil {
		t.Fatal(err)
	}
	h.env.Svc.UpdateClient(context.Background(), h.admin, sc.ID, service.ClientInput{Enabled: ptr(false)})
	h.p.InvalidateClient(sc.ID)
	if _, err := h.p.VerifyAccessToken(context.Background(), r.str("access_token")); err == nil {
		t.Fatal("token of a disabled client verified")
	}
}

func TestConcurrentTokenRequests(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	rt := r.str("refresh_token")
	var wg sync.WaitGroup
	var bad atomic.Int32
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				if h.refreshWith(cl, secret, rt).status != 200 || h.token(url.Values{"grant_type": {"client_credentials"}}, cl, secret).status != 200 {
					bad.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d failures", bad.Load())
	}
}

func TestMalformedRequestBodiesRefused(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	for _, path := range []string{"/oauth/token", "/oauth/par", "/oauth/device_authorization", "/oauth/revoke", "/oauth/introspect"} {
		r := h.rawPost(path, "a=%zz")
		if r.status != 400 {
			t.Errorf("%s: %d %v", path, r.status, r.m)
		}
	}
}

// A failure nothing in the request can cure is a 500 that names a cancelled request but never the error itself.
func TestServerErrorAnswers(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"cancelled": {context.Canceled, "temporary failure (canceled)"},
		"disk full": {errors.New("disk full at /var/lib/quisora"), "temporary failure (internal)"},
		"wrapped":   {fmt.Errorf("reading: %w", context.Canceled), "temporary failure (canceled)"},
	} {
		if e := serverError(tc.err); e.status != http.StatusInternalServerError || e.code != "server_error" || e.desc != tc.want {
			t.Errorf("%s: %d %s %q, want %q", name, e.status, e.code, e.desc, tc.want)
		}
	}
}
