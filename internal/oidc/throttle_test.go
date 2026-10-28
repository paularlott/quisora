package oidc

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
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
// client alone: past its limit it is refused before anything is looked up or recorded, as "try again in a minute",
// not as invalid_grant (which would make it drop tokens that are good); a backend failing for thousands of users is
// not capped by what an address may fail, and no other client behind its address is throttled. Requests that succeed
// do not count.
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
	// the client is refused whatever it presents now, a good refresh token included, and keeps the token
	expectErr(t, h.refreshWith(cl, secret, rt), http.StatusTooManyRequests, "temporarily_unavailable")
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

// A public client is admitted by its client_id alone, so anyone can fail as it: its failures count against the address,
// and past the limit the address is refused before anything is looked at (as "try again", not as invalid_grant or
// invalid_client, which would make a public client drop tokens that are good). The failures of client authentication
// count in the same counter, and a request costs one counter read of it, not two.
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
	// anyone can name a public client, so nothing from the address is looked at now, a client's good credentials included
	cl, secret := h.newClient(nil)
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

// A public client's pushes are small, and counted per address and per organization (the bound that holds however
// many addresses push): they are the pushes anyone can make, each held in memory until it is used.
func TestPublicPushedAuthorizationRequestsAreBounded(t *testing.T) {
	h := setup(t, nil)
	pub := h.publicClient(nil)
	_, ch := pkce()
	if r := h.push(pub, "", authzQuery(pub, ch, nil)); r.status != 201 {
		t.Fatalf("a public client's push: %d %v", r.status, r.m)
	}
	big := authzQuery(pub, ch, url.Values{"x_padding": {strings.Repeat("x", parPublicMaxParams)}})
	if r := h.push(pub, "", big); r.status != 400 || r.m["error"] != "invalid_request" {
		t.Fatalf("a public client's push over the size limit: %d %v", r.status, r.m)
	}
	// the address: one more than its budget (two were made above)
	for range parPublicPerIPMin - 2 {
		expectErr(t, h.push(pub, "", url.Values{"request_uri": {"urn:x"}}), 400, "invalid_request")
	}
	x := h.push(pub, "", url.Values{"request_uri": {"urn:x"}})
	expectErr(t, x, http.StatusTooManyRequests, "temporarily_unavailable")
	if x.hdr.Get("Retry-After") == "" {
		t.Errorf("no Retry-After: %v", x.hdr)
	}
	// the organization: whatever the address, once its public clients have pushed their share
	h2 := setup(t, nil)
	pub2 := h2.publicClient(nil)
	if _, err := h2.env.Server.Eph.Incr(t.Context(), nsRateOIDC, "par-org|"+pub2.OrgID, parPublicPerOrgMin, time.Minute); err != nil {
		t.Fatal(err)
	}
	expectErr(t, h2.push(pub2, "", url.Values{"request_uri": {"urn:x"}}), http.StatusTooManyRequests, "temporarily_unavailable")
	// a confidential client of the organization is not held back by what public clients pushed
	cl, secret := h2.newClient(nil)
	if r := h2.push(cl, secret, authzQuery(cl, ch, nil)); r.status != 201 {
		t.Errorf("a confidential client after the organization's public budget is spent: %d %v", r.status, r.m)
	}
}

func expectErr(t testing.TB, r tokResp, status int, code string) {
	t.Helper()
	if r.status != status || r.m["error"] != code {
		t.Fatalf("want %d %s, got %d %v", status, code, r.status, r.m)
	}
}
