package oidc

import (
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
)

// unknownCode is a token request that fails on what it presents: a code that was never issued.
func (h *harness) unknownCode(c *model.Client, secret string, i int) tokResp {
	return h.token(url.Values{"grant_type": {"authorization_code"}, "code": {"unknown-" + strconv.Itoa(i)},
		"redirect_uri": {c.RedirectURIs[0]}, "code_verifier": {"v"}}, c, secret)
}

// Token requests of a confidential client that fail on what they present (unknown codes here) are counted against that
// client and grant type alone: past its limit it is refused that grant type before anything is looked up or recorded,
// as "try again in a minute", not as invalid_grant (which would make it drop tokens that are good); a backend failing
// for thousands of users is not capped by what an address may fail, and no other client behind its address is
// throttled. Requests that succeed do not count.
func TestFailedTokenRequestsAreThrottledPerClient(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	other, otherSecret := h.newClient(nil)
	pub := h.publicClient(nil)
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid offline_access"}})
	rt := r.str("refresh_token")
	for range failuresPerIPMin + 5 { // successes are not failures
		if x := h.refreshWith(cl, secret, rt); x.status != 200 {
			t.Fatalf("refresh: %d %v", x.status, x.m)
		}
	}
	for i := range tokenFailuresPerClientMin {
		if x := h.unknownCode(cl, secret, i); x.status != 400 || x.m["error"] != "invalid_grant" {
			t.Fatalf("failure %d: %d %v, want invalid_grant (the client's limit is more than the address's)", i, x.status, x.m)
		}
	}
	x := h.unknownCode(cl, secret, -1)
	expectErr(t, x, http.StatusTooManyRequests, "temporarily_unavailable")
	if x.hdr.Get("Retry-After") == "" {
		t.Errorf("no Retry-After: %v", x.hdr)
	}
	// the client is refused that grant type whatever it presents now, and keeps the others
	if x := h.refreshWith(cl, secret, rt); x.status != 200 {
		t.Errorf("a good refresh token while its code exchanges are refused: %d %v", x.status, x.m)
	}
	// other clients behind the same address are not: a confidential one, and a public one
	if x := h.refreshWith(other, otherSecret, "unknown"); x.status != 400 || x.m["error"] != "invalid_grant" {
		t.Errorf("another confidential client from the same address: %d %v", x.status, x.m)
	}
	if o, _ := h.login(other, otherSecret, nil); o.status != 200 {
		t.Errorf("another client's code exchange from the same address: %d %v", o.status, o.m)
	}
	if x := h.unknownCode(pub, "", 0); x.status != 400 || x.m["error"] != "invalid_grant" {
		t.Errorf("a public client from the same address: %d %v", x.status, x.m)
	}
}

// After an organization's sessions are revoked, a backend's stale refresh tokens fail by the thousand; that must not
// stop the same client's code exchanges, which the users signing back in need at that very moment.
func TestRefreshFailuresDoNotBlockCodeExchanges(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	for i := range tokenFailuresPerClientMin {
		if x := h.refreshWith(cl, secret, "stale-"+strconv.Itoa(i)); x.status != 400 || x.m["error"] != "invalid_grant" {
			t.Fatalf("refresh %d: %d %v", i, x.status, x.m)
		}
	}
	expectErr(t, h.refreshWith(cl, secret, "stale"), http.StatusTooManyRequests, "temporarily_unavailable")
	if x, _ := h.login(cl, secret, nil); x.status != 200 {
		t.Fatalf("a code exchange after %d refresh failures: %d %v", tokenFailuresPerClientMin, x.status, x.m)
	}
}

// A public client is admitted by its client_id alone, so anyone can fail as it: its failures count against the address,
// and past the limit the address is refused (as "try again", not as invalid_grant or invalid_client, which would make
// a public client drop tokens that are good). The failures of client authentication count in the same counter, and a
// request costs one counter read of it, not two.
func TestFailedTokenRequestsOfAPublicClientAreThrottledByAddress(t *testing.T) {
	h := setup(t, nil)
	pub := h.publicClient(nil)
	var reads atomic.Int32
	h.useEph(func(op, ns string) error {
		if op == "incr" && ns == nsRateOIDC {
			reads.Add(1)
		}
		return nil
	})
	expectErr(t, h.unknownCode(pub, "", 0), 400, "invalid_grant")
	// the client-authentication budget (read), the address's (read) and the failure counted in it
	if n := reads.Load(); n != 3 {
		t.Errorf("a failing public client's token request used %d counter operations, want 3", n)
	}
	for i := 1; i < failuresPerIPMin; i++ {
		expectErr(t, h.unknownCode(pub, "", i), 400, "invalid_grant")
	}
	x := h.unknownCode(pub, "", -1)
	expectErr(t, x, http.StatusTooManyRequests, "temporarily_unavailable")
	if x.hdr.Get("Retry-After") == "" {
		t.Errorf("no Retry-After: %v", x.hdr)
	}
	// a client that is named without its credentials is refused too, an unknown one and one with the wrong secret
	cl, secret := h.newClient(nil)
	expectErr(t, h.token(url.Values{"grant_type": {"client_credentials"}}, &model.Client{ID: "nobody"}, "x"), http.StatusTooManyRequests, "temporarily_unavailable")
	expectErr(t, h.token(url.Values{"grant_type": {"client_credentials"}}, cl, "wrong"), http.StatusTooManyRequests, "temporarily_unavailable")
	// but a confidential client that proves its secret is not: its failures are its own, and the address's other
	// clients (every public client's invalid_grants after a revocation, behind one NAT) must not keep it from its users
	expectErr(t, h.unknownCode(cl, secret, 0), 400, "invalid_grant")
	if o, _ := h.login(cl, secret, nil); o.status != 200 {
		t.Errorf("a confidential client's code exchange from an address whose public clients fail: %d %v", o.status, o.m)
	}
}

// An address that has failed far more than failuresPerIPMin (made-up client ids, wrong secrets) is refused without
// anything being looked up, a client's right credentials included: each unknown id would cost a store read.
func TestFailuresPerAddressAreBounded(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	good := h.env.Svc.Clients.S
	counted := &faultStore{Store: good}
	h.env.Svc.Clients.S = counted
	t.Cleanup(func() { h.env.Svc.Clients.S = good })
	ctx := t.Context()
	if _, err := h.env.Server.Eph.Incr(ctx, nsRateOIDC, "fail-ip|127.0.0.1", failuresPerIPMax-2, time.Minute); err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		expectErr(t, h.token(url.Values{"grant_type": {"client_credentials"}}, &model.Client{ID: "nobody-" + strconv.Itoa(i)}, "x"),
			http.StatusTooManyRequests, "temporarily_unavailable")
	}
	if n := counted.gets.Load(); n > 2 {
		t.Errorf("%d store reads for unknown client ids past the address's ceiling, want at most the 2 under it", n)
	}
	expectErr(t, h.unknownCode(cl, secret, 0), http.StatusTooManyRequests, "temporarily_unavailable")
}

// A confidential client's pushed authorization requests are counted against it alone, not against its address before
// it has authenticated: a backend may push more than an address could, and no other client from its address is
// affected by its limit. Pushes count whatever they turn out to be.
func TestPushedAuthorizationRequestsAreLimitedPerClient(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	other, otherSecret := h.newClient(nil)
	push := func(c *model.Client, secret string) tokResp {
		return h.clientPost(orgBase+"/oauth/par", url.Values{"request_uri": {"urn:x"}}, c, secret)
	}
	for range parPerClientMin {
		expectErr(t, push(cl, secret), 400, "invalid_request")
	}
	x := push(cl, secret)
	expectErr(t, x, http.StatusTooManyRequests, "temporarily_unavailable")
	if x.hdr.Get("Retry-After") == "" {
		t.Errorf("no Retry-After: %v", x.hdr)
	}
	_, ch := pkce()
	if r := h.push(other, otherSecret, authzQuery(other, ch, nil)); r.status != 201 {
		t.Errorf("another client from the same address: %d %v", r.status, r.m)
	}
}

// A public client's pushes are counted per address (the proofs one address may have recorded) and by nothing shared:
// the organization's other public clients, and other addresses, are not held back by them.
func TestPublicPushedAuthorizationRequestsAreLimitedByAddress(t *testing.T) {
	h := setup(t, nil)
	pub := h.publicClient(nil)
	_, ch := pkce()
	if r := h.push(pub, "", authzQuery(pub, ch, nil)); r.status != 201 {
		t.Fatalf("a public client's push: %d %v", r.status, r.m)
	}
	// one more than the address's budget (one was made above)
	for range parPublicPerIPMin - 1 {
		expectErr(t, h.push(pub, "", url.Values{"request_uri": {"urn:x"}}), 400, "invalid_request")
	}
	x := h.push(pub, "", url.Values{"request_uri": {"urn:x"}})
	expectErr(t, x, http.StatusTooManyRequests, "temporarily_unavailable")
	if x.hdr.Get("Retry-After") == "" {
		t.Errorf("no Retry-After: %v", x.hdr)
	}
	// a confidential client is not held back by what public clients pushed
	cl, secret := h.newClient(nil)
	if r := h.push(cl, secret, authzQuery(cl, ch, nil)); r.status != 201 {
		t.Errorf("a confidential client after an address's public budget is spent: %d %v", r.status, r.m)
	}
}

func expectErr(t testing.TB, r tokResp, status int, code string) {
	t.Helper()
	if r.status != status || r.m["error"] != code {
		t.Fatalf("want %d %s, got %d %v", status, code, r.status, r.m)
	}
}
