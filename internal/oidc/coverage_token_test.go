package oidc

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

func tokenErr(t *testing.T, r tokResp, status int, code string) {
	t.Helper()
	if r.status != status || r.m["error"] != code {
		t.Fatalf("want %d %s, got %d %v", status, code, r.status, r.m)
	}
}

func TestCoverageTokenEndpointRefusals(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	pub := h.publicClient(nil)
	noCC, noCCSecret := h.newClient(func(in *service.ClientInput) {
		in.GrantTypes = &[]string{"authorization_code", "refresh_token"}
	})

	tokenErr(t, h.token(url.Values{"grant_type": {"password"}}, cl, secret), 400, "unsupported_grant_type")
	tokenErr(t, h.token(url.Values{"grant_type": {"client_credentials"}}, noCC, noCCSecret), 400, "unauthorized_client")
	tokenErr(t, h.token(url.Values{"grant_type": {"client_credentials"}}, pub, ""), 400, "unauthorized_client")
	tokenErr(t, h.token(url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, cl, "wrong"), 401, "invalid_client")
	// a parameter given twice
	f := url.Values{"grant_type": {"client_credentials", "client_credentials"}, "client_id": {cl.ID}, "client_secret": {secret}}
	tokenErr(t, h.post("/oauth/token", f, "", ""), 400, "invalid_request")

	// client_credentials: an unregistered resource, a malformed one
	tokenErr(t, h.token(url.Values{"grant_type": {"client_credentials"}, "resource": {"https://other.example"}}, cl, secret), 400, "invalid_target")
	tokenErr(t, h.token(url.Values{"grant_type": {"client_credentials"}, "resource": {"not a uri"}}, cl, secret), 400, "invalid_target")
}

func TestCoverageCodeExchangeRefusals(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	other, osecret := h.newClient(nil)
	c, _ := h.session(h.user)
	code := func(extra url.Values) (string, string) {
		v, ch := pkce()
		return h.getCode(c, cl, ch, extra), v
	}
	exch := func(cd, ru, v string, extra url.Values) tokResp {
		f := url.Values{"grant_type": {"authorization_code"}, "code": {cd}, "redirect_uri": {ru}, "code_verifier": {v}}
		for k, x := range extra {
			f[k] = x
		}
		return h.token(f, cl, secret)
	}

	tokenErr(t, exch("", cl.RedirectURIs[0], "v", nil), 400, "invalid_request")
	tokenErr(t, exch(strings.Repeat("x", 201), cl.RedirectURIs[0], "v", nil), 400, "invalid_request")
	tokenErr(t, exch("nosuchcode", cl.RedirectURIs[0], "v", nil), 400, "invalid_grant")

	cd, v := code(nil)
	// the code of another client
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {cd}, "redirect_uri": {cl.RedirectURIs[0]}, "code_verifier": {v}}, other, osecret)
	tokenErr(t, r, 400, "invalid_grant")

	cd, v = code(nil)
	tokenErr(t, exch(cd, "https://rp.example/other", v, nil), 400, "invalid_grant")

	cd, v = code(nil)
	tokenErr(t, exch(cd, cl.RedirectURIs[0], "wrong-verifier", nil), 400, "invalid_grant")

	// resources: more than the request named, and malformed
	cd, v = code(nil)
	tokenErr(t, exch(cd, cl.RedirectURIs[0], v, url.Values{"resource": {"https://api.example/a"}}), 400, "invalid_target")
	cd, v = code(nil)
	tokenErr(t, exch(cd, cl.RedirectURIs[0], v, url.Values{"resource": {"nope"}}), 400, "invalid_target")

	// a DPoP-bound request needs the proof
	k := newDPoPKey(t, AlgES256)
	cd, v = code(url.Values{"dpop_jkt": {k.jkt}})
	tokenErr(t, exch(cd, cl.RedirectURIs[0], v, nil), 400, "invalid_grant")

	// the user is disabled between code and exchange
	cd, v = code(nil)
	if _, err := h.env.Svc.UpdateUser(context.Background(), h.admin, h.user.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	tokenErr(t, exch(cd, cl.RedirectURIs[0], v, nil), 400, "invalid_grant")
}

func TestCoverageRefreshRefusals(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	other, osecret := h.newClient(nil)
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid profile offline_access"}, "resource": {"https://api.example/a"}})
	rt := r.str("refresh_token")
	parts := strings.Split(rt, ".")

	for _, bad := range []string{"", "nodot", ".x", "a.b.c", "a.x.!!", "g.1.x" + strings.Repeat("y", 400), parts[0] + ".!!!"} {
		tokenErr(t, h.refreshWith(cl, secret, bad), 400, "invalid_grant")
	}
	// unknown grant
	tokenErr(t, h.refreshWith(cl, secret, "nosuchgrant."+parts[1]+"."+parts[2]), 400, "invalid_grant")
	// another client's token
	tokenErr(t, h.refreshWith(other, osecret, rt), 400, "invalid_grant")
	// forged MAC
	tokenErr(t, h.refreshWith(cl, secret, parts[0]+".0."+b64.EncodeToString([]byte("forged-mac-forged-mac-forged-mac!"))), 400, "invalid_grant")
	// a counter ahead of the grant's is refused without ending it
	tokenErr(t, h.refreshWith(cl, secret, parts[0]+".7."+parts[2]), 400, "invalid_grant")

	// scope beyond the grant, resources beyond the grant
	tokenErr(t, h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "scope": {"openid email"}}, cl, secret), 400, "invalid_scope")
	tokenErr(t, h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "resource": {"https://api.example/b"}}, cl, secret), 400, "invalid_target")
	tokenErr(t, h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "resource": {"%%"}}, cl, secret), 400, "invalid_target")

	// a narrowed refresh works and rotates
	ok := h.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "scope": {"openid"}, "resource": {"https://api.example/a"}}, cl, secret)
	if ok.status != 200 || ok.str("scope") != "openid" || ok.str("refresh_token") == rt {
		t.Fatalf("%d %v", ok.status, ok.m)
	}

	// a disabled user ends refreshing
	if _, err := h.env.Svc.UpdateUser(context.Background(), h.admin, h.user.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	tokenErr(t, h.refreshWith(cl, secret, ok.str("refresh_token")), 400, "invalid_grant")
}

// A refresh whose rotation committed (the counter moved) but whose response never reached the client: the client
// retries with the token it still has. A confidential client (it authenticates, so a copied token alone is not
// enough) retrying within refreshRetryGrace gets the token it missed, and nothing rotates again; a public client
// without DPoP has only the token, so its retry is reuse and the grant ends.
func TestRefreshLostResponseRetry(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	r, _ := h.login(cl, secret, nil)
	old := r.str("refresh_token")
	gid := strings.SplitN(old, ".", 2)[0]
	lost := h.refreshWith(cl, secret, old)
	if lost.status != 200 {
		t.Fatalf("%v", lost.m)
	}
	retry := h.refreshWith(cl, secret, old)
	if retry.status != 200 || retry.str("refresh_token") != lost.str("refresh_token") {
		t.Fatalf("the retry: %d, same token %v", retry.status, retry.str("refresh_token") == lost.str("refresh_token"))
	}
	if g, err := h.env.Svc.Grants.Get(context.Background(), gid); err != nil || g.Revoked || g.Counter != 1 {
		t.Fatalf("after the retry: %+v %v", g, err)
	}
	if next := h.refreshWith(cl, secret, retry.str("refresh_token")); next.status != 200 {
		t.Fatalf("the token the retry got: %d", next.status)
	}
	if len(h.auditActions("oauth.refresh.reuse")) != 0 {
		t.Fatal("a retry was recorded as reuse")
	}
}

// RFC 7009: revoking an access token ends what it was issued from. A client_credentials token has no grant and a JWT
// cannot be recalled, so the revocation is refused as unsupported_token_type (§2.2.1), not answered 200 (which the
// client would take to mean the token is dead).
func TestCoverageRevokeClientCredentialsToken(t *testing.T) {
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

func TestCoverageRefreshStaticClientRotationBoundary(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil) // static tokens
	r, _ := h.login(cl, secret, nil)
	rt := r.str("refresh_token")
	// a counted token for a static client whose counter is not the grant's is refused
	g := strings.SplitN(rt, ".", 2)[0]
	tokenErr(t, h.refreshWith(cl, secret, g+".3."+b64.EncodeToString([]byte("x"))), 400, "invalid_grant")
	if h.refreshWith(cl, secret, rt).status != 200 {
		t.Fatal("static refresh")
	}
}
