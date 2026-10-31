package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/paularlott/quisora/internal/ephemeral"
)

// The limits of the SSH endpoints count per minute, and the sign limits are shared by what asks through them (the
// sign endpoint and the account page both call SSHSignAllowed).
func TestSSHRateLimits(t *testing.T) {
	ctx := context.Background()
	s := &Server{Eph: ephemeral.NewLocal("test")}
	req := func(addr string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = addr + ":1234"
		return r
	}

	for i := range SSHSignsPerUser {
		if ok, err := s.SSHSignAllowed(ctx, req("192.0.2.1"), "u1"); err != nil || !ok {
			t.Fatalf("sign %d: %v %v", i, ok, err)
		}
	}
	if ok, _ := s.SSHSignAllowed(ctx, req("192.0.2.1"), "u1"); ok {
		t.Error("the 21st request of a user in a minute was allowed")
	}
	if ok, _ := s.SSHSignAllowed(ctx, req("192.0.2.2"), "u2"); !ok {
		t.Error("another user and address are held up")
	}
	for i := range SSHSignsPerIP { // the address, over many users
		s.SSHSignAllowed(ctx, req("192.0.2.9"), "many"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	if ok, _ := s.SSHSignAllowed(ctx, req("192.0.2.9"), "fresh-user"); ok {
		t.Error("an address over its limit was allowed")
	}

	for i := range SSHHostSignsPerActor {
		if ok, err := s.SSHHostSignAllowed(ctx, "client1"); err != nil || !ok {
			t.Fatalf("host sign %d: %v %v", i, ok, err)
		}
	}
	if ok, _ := s.SSHHostSignAllowed(ctx, "client1"); ok {
		t.Error("the 121st host certificate of an actor in a minute was allowed")
	}
	if ok, _ := s.SSHHostSignAllowed(ctx, "client2"); !ok {
		t.Error("another actor is held up")
	}

	for i := range SSHRevokesPerUser {
		if ok, err := s.SSHRevokeAllowed(ctx, "u1"); err != nil || !ok {
			t.Fatalf("revoke %d: %v %v", i, ok, err)
		}
	}
	if ok, _ := s.SSHRevokeAllowed(ctx, "u1"); ok {
		t.Error("a revocation over the limit of a user was allowed")
	}
	if ok, _ := s.SSHRevokeAllowed(ctx, "u2"); !ok {
		t.Error("another user is held up")
	}

	// The public documents: per address and tenant, a 304 costing less than a document. The servers behind one
	// address fetching every minute are many more than the old 600 requests an address allowed.
	const nat = "198.51.100.7"
	served := SSHFetchUnitsPerIP / SSHFetchCost // documents sent before the budget is spent
	if served < 2000 {
		t.Fatalf("the budget of an address allows only %d documents a minute", served)
	}
	for i := range served {
		if ok, err := s.SSHFetchAllowed(ctx, req(nat), "t-prod"); err != nil || !ok {
			t.Fatalf("fetch %d: %v %v", i, ok, err)
		}
		s.SSHFetchServed(ctx, req(nat), "t-prod")
	}
	if ok, _ := s.SSHFetchAllowed(ctx, req(nat), "t-prod"); ok {
		t.Error("a fetch over the budget of an address and tenant was allowed")
	}
	if ok, _ := s.SSHFetchAllowed(ctx, req(nat), "t-staging"); !ok {
		t.Error("another tenant's budget of the same address is spent too")
	}
	// 304 answers cost less: as many again revalidate within the budget, four times over
	for i := range SSHFetchUnitsPerIP / SSHFetchCost304 {
		if ok, _ := s.SSHFetchAllowed(ctx, req("203.0.113.5"), "t-prod"); !ok {
			t.Fatalf("revalidation %d was refused", i)
		}
	}
	if ok, _ := s.SSHFetchAllowed(ctx, req("203.0.113.5"), "t-prod"); ok {
		t.Error("a revalidation over the budget was allowed")
	}
	// the paths that name no tenant share one budget of the address, whatever they name
	for range SSHFetchUnitsPerIP {
		s.SSHFetchAllowed(ctx, req("203.0.113.9"), "")
	}
	if ok, _ := s.SSHFetchAllowed(ctx, req("203.0.113.9"), ""); ok {
		t.Error("requests for unknown tenants over the address's budget were allowed")
	}
	if ok, _ := s.SSHFetchAllowed(ctx, req("203.0.113.9"), "t-prod"); !ok {
		t.Error("a known tenant's budget is spent by the unknown ones")
	}
	// an IPv6 client is one address by its /64
	for range SSHFetchUnitsPerIP {
		s.SSHFetchAllowed(ctx, req("[2001:db8::1]"), "t-prod")
	}
	if ok, _ := s.SSHFetchAllowed(ctx, req("[2001:db8::2]"), "t-prod"); ok {
		t.Error("another address of the same /64 has a budget of its own")
	}
}
