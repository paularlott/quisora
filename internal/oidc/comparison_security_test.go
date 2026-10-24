//go:build comparisonreview

package oidc

import (
	"net/url"
	"testing"
	"time"
)

// The same operational acceptance criterion as the Fortix Identity probe.
// Allow the documented three-second grant cache to expire.
func TestComparisonRevocationDeactivatesAccessToken(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	first, _ := h.login(cl, secret, nil)
	at, rt := first.str("access_token"), first.str("refresh_token")
	if before := h.introspect(cl, secret, at); before["active"] != true {
		t.Fatalf("before: %v", before)
	}
	r := h.post("/oauth/revoke", url.Values{"token": {rt}, "client_id": {cl.ID}, "client_secret": {secret}}, "", "")
	if r.status != 200 {
		t.Fatalf("revoke: %d", r.status)
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		after := h.introspect(cl, secret, at)
		if after["active"] == false {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("access token remains active after revocation: %v", after)
		}
		time.Sleep(25 * time.Millisecond)
	}
}
