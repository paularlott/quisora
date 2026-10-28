package oidc

import (
	"net/http"
	"net/url"
	"strconv"
	"testing"
)

// Token requests that fail on what they present (unknown codes here) are counted by address: past the limit the
// address is refused before anything is looked up or recorded, as "try again in a minute", not as invalid_grant
// (which would make a client drop tokens that are good). Requests that succeed do not count.
func TestFailedTokenRequestsAreThrottledByAddress(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid offline_access"}})
	rt := r.str("refresh_token")
	for range tokenFailuresPerIPMin + 5 { // successes are not failures
		if x := h.refreshWith(cl, secret, rt); x.status != 200 {
			t.Fatalf("refresh: %d %v", x.status, x.m)
		}
	}
	bad := func(i int) tokResp {
		return h.token(url.Values{"grant_type": {"authorization_code"}, "code": {"unknown-" + strconv.Itoa(i)},
			"redirect_uri": {rpCallback}, "code_verifier": {"v"}}, cl, secret)
	}
	for i := range tokenFailuresPerIPMin {
		expectErr(t, bad(i), 400, "invalid_grant")
	}
	x := bad(-1)
	expectErr(t, x, http.StatusTooManyRequests, "temporarily_unavailable")
	if x.hdr.Get("Retry-After") == "" {
		t.Errorf("no Retry-After: %v", x.hdr)
	}
	// the address is refused whatever it presents now, a good refresh token included, and keeps the token
	expectErr(t, h.refreshWith(cl, secret, rt), http.StatusTooManyRequests, "temporarily_unavailable")
}

// Pushed authorization requests are counted by address, whatever they push (a public client pushes with its
// client_id alone, and each push is held in memory and may record a DPoP proof).
func TestPushedAuthorizationRequestsAreLimitedByAddress(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	push := func() tokResp {
		return h.post(h.at(cl, "/oauth/par"), url.Values{"client_id": {cl.ID}, "client_secret": {secret},
			"request_uri": {"urn:x"}}, "", "")
	}
	for range authorizePerIPMin {
		expectErr(t, push(), 400, "invalid_request")
	}
	x := push()
	expectErr(t, x, http.StatusTooManyRequests, "temporarily_unavailable")
	if x.hdr.Get("Retry-After") == "" {
		t.Errorf("no Retry-After: %v", x.hdr)
	}
}

func expectErr(t testing.TB, r tokResp, status int, code string) {
	t.Helper()
	if r.status != status || r.m["error"] != code {
		t.Fatalf("want %d %s, got %d %v", status, code, r.status, r.m)
	}
}
