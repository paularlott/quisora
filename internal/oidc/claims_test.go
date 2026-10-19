package oidc

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/service"
)

func (h *harness) userinfo(at string) map[string]any {
	h.t.Helper()
	resp := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+at)
	if resp.StatusCode != 200 {
		h.t.Fatalf("userinfo: %d", resp.StatusCode)
	}
	m := map[string]any{}
	_ = json.Unmarshal([]byte(body(resp)), &m)
	return m
}

// The claims parameter asks for single claims beyond the scopes: answered for the target it names, only for claims
// whose scope the client may use, and kept across a refresh. Unknown claims and members are ignored.
func TestClaimsParameter(t *testing.T) {
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

// acr_values (or an acr claim request) naming only urn:quisora:acr:mfa makes a second factor a condition of this
// sign-in; naming both values, or unknown ones, does not. The ID token's acr is always one of the requested known
// values when any were named.
func TestACRValues(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	_, ch := pkce()
	weak := h.sessionWith(h.user, []string{"pwd"}, time.Now())
	for _, extra := range []url.Values{
		{"acr_values": {acrMFA}},
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
	for _, v := range []string{acrBasic + " " + acrMFA, "1 2", acrBasic} {
		u := h.authorize(weak, authzQuery(cl, ch, url.Values{"acr_values": {v}}))
		if u.Query().Get("code") == "" {
			t.Fatalf("acr_values %q refused a password session: %s", v, u)
		}
		if h.p.FlowWantsMFA(context.Background(), "/oauth/authorize/resume?flow=x") {
			t.Fatal("unknown flow wants MFA")
		}
	}
	r, _ := h.login(cl, secret, url.Values{"acr_values": {acrBasic + " " + acrMFA}})
	if acr := claimsOf(t, r.str("id_token"))["acr"]; !slices.Contains([]any{acrBasic, acrMFA}, acr) {
		t.Fatalf("acr %v", acr)
	}
}

// The phone scope carries the contact number and whether it was verified; without a number, neither claim.
func TestPhoneScope(t *testing.T) {
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

// A verified access token is cached (no second signature check), but everything that can change is checked on every
// use: a disabled user, a revoked grant. A token differing in one byte is never served from the cache.
func TestVerifiedTokenCache(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	at := r.str("access_token")
	ctx := context.Background()
	if _, err := h.p.VerifyAccessToken(ctx, at); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := h.p.verified.get(tokenKey(at), time.Now()); !ok {
		t.Fatal("a verified token was not cached")
	}
	if _, err := h.p.VerifyAccessToken(ctx, at); err != nil {
		t.Fatalf("from the cache: %v", err)
	}
	// one byte off (in the signature): a different token, verified in full and refused
	b := []byte(at)
	if b[len(b)-2] == 'A' {
		b[len(b)-2] = 'B'
	} else {
		b[len(b)-2] = 'A'
	}
	if _, err := h.p.VerifyAccessToken(ctx, string(b)); err == nil {
		t.Fatal("a tampered token was accepted")
	}
	// the user disabled: refused although the token is cached
	off := false
	if _, err := h.env.Svc.UpdateUser(ctx, service.System, h.user.ID, service.UserInput{Active: &off}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(h.user.ID) // as the change hook does
	if _, err := h.p.VerifyAccessToken(ctx, at); err == nil {
		t.Fatal("a cached token of a disabled user was accepted")
	}
	// enabled again, then its grant revoked: refused
	on := true
	if _, err := h.env.Svc.UpdateUser(ctx, service.System, h.user.ID, service.UserInput{Active: &on}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(h.user.ID)
	r2, _ := h.login(cl, secret, nil)
	at2 := r2.str("access_token")
	if _, err := h.p.VerifyAccessToken(ctx, at2); err != nil {
		t.Fatal(err)
	}
	gid, _ := claimsOf(t, at2)["gid"].(string)
	if rv := h.clientPost("/oauth/revoke", url.Values{"token": {r2.str("refresh_token")}}, cl, secret); rv.status != 200 {
		t.Fatalf("revoke: %d", rv.status)
	}
	h.p.InvalidateGrant(gid)
	if _, err := h.p.VerifyAccessToken(ctx, at2); err == nil {
		t.Fatal("a cached token of a revoked grant was accepted")
	}
	// keys reloaded: the cache starts again
	h.p.Invalidate()
	if _, _, _, ok := h.p.verified.get(tokenKey(at), time.Now()); ok {
		t.Fatal("the cache survived a key reload")
	}
}
