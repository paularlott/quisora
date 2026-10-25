package oidc

import "testing"

// OIDC Core §12.2: an ID token issued at a refresh has no nonce (it answers no authentication request), while the
// one of the code exchange carries the request's. Pinned so that no one carries the nonce over to refreshes.
func TestRefreshIDTokenHasNoNonce(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	if n := claimsOf(t, r.str("id_token"))["nonce"]; n != "n1" {
		t.Fatalf("the code exchange's ID token nonce: %v", n)
	}
	x := h.refreshWith(cl, secret, r.str("refresh_token"))
	if x.status != 200 || x.str("id_token") == "" {
		t.Fatalf("refresh: %d %v", x.status, x.m)
	}
	if n, ok := claimsOf(t, x.str("id_token"))["nonce"]; ok {
		t.Fatalf("a refreshed ID token carries a nonce: %v", n)
	}
}
