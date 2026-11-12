package login_test

import (
	"testing"

	"github.com/paularlott/quisora/internal/ephemeral"
)

// A node whose short-lived state is full answers the sign-in steps that need to keep some (the ticket of a second
// factor, a passkey challenge) with 503 and Retry-After: the person tries again in a moment, it is no server error.
func TestFullEphemeralStoreAnswers503(t *testing.T) {
	e := newEnv(t, nil)
	e.giveTOTP(t, e.member(t))
	local, ok := e.Server.Eph.(*ephemeral.Local)
	if !ok {
		t.Fatalf("the test server's ephemeral store is %T", e.Server.Eph)
	}
	local.Budget = 1 // nothing more fits; the rate-limit counters are still kept
	b := e.browser(t)
	res, out := b.login("primary", "member", userPassword)
	wantStatus(t, res, out, 503)
	if res.Header.Get("Retry-After") == "" {
		t.Fatal("no Retry-After on the password step")
	}
	res, out = b.post("/o/primary/api-internal/login/passkey/begin", map[string]any{})
	wantStatus(t, res, out, 503)
	if res.Header.Get("Retry-After") == "" {
		t.Fatal("no Retry-After on a passkey challenge")
	}
	local.Budget = 0 // the default again
	res, out = b.login("primary", "member", userPassword)
	wantStatus(t, res, out, 200)
}
