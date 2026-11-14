package service

import (
	"strconv"
	"testing"

	"github.com/paularlott/quisora/internal/metrics"
)

// Lockout refusals held back from the audit log (in their window, past their address's allowance) are still counted
// as login.failure in the metrics, as wrong credentials held back are: an alert keyed on that rate sees an address
// hammering a locked account, not one event a minute.
func TestLockoutRefusalsHeldBackAreCounted(t *testing.T) {
	s := &Service{}
	recorded := 0
	events := metrics.AuditEvents.Value("login.failure", "failure")
	for range 5 {
		s.AuditLoginRefusal(true, "org", "addr1", "user1", "locked|password", func(map[string]string) { recorded++ })
	}
	for i := range LoginRowsPerAddressUnknown + 10 { // past the address's allowance for logins that name no account
		s.AuditLoginRefusal(false, "org", "addr2", "x:"+strconv.Itoa(i), "locked|password", func(map[string]string) { recorded++ })
	}
	attempts := 5 + LoginRowsPerAddressUnknown + 10
	// recorded events are counted when the audit event is recorded (not here: the record func stands in for it)
	if held := int(metrics.AuditEvents.Value("login.failure", "failure") - events); recorded+held != attempts || held == 0 {
		t.Fatalf("%d refusals: recorded %d, counted held back %d", attempts, recorded, held)
	}
}
