package service

import (
	"fmt"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// An address cannot spend its allowance on decoy accounts (its own, say) and then guess at its target unrecorded:
// past the allowance an existing account's event goes through the limiter keyed without the address, so the target
// is still named once a window, by that address, and the repeats are counted there.
func TestDecoysCannotHideTheTarget(t *testing.T) {
	for _, refusal := range []bool{false, true} {
		s := &Service{}
		named := map[string]int{}
		kind := "password"
		if refusal {
			kind = "locked|password"
		}
		try := func(sub string) {
			f := func(map[string]string) { named[sub]++ }
			if refusal {
				s.AuditLoginRefusal(true, "org", "203.0.113.9", sub, kind, f)
			} else {
				s.AuditLoginFailure(true, "org", "203.0.113.9", sub, kind, f)
			}
		}
		for i := range LoginRowsPerAddress + 1 { // the allowance and its summary, all on decoys
			try("decoy" + strconv.Itoa(i))
		}
		for range 1000 {
			try("victim")
		}
		if named["victim"] != 1 {
			t.Fatalf("refusal %v: the target was named %d times after 1000 attempts", refusal, named["victim"])
		}
		l := &s.accountFailures
		if refusal {
			l = &s.accountRefusals
		}
		if seen := l.flooded.seen["org|victim|"+kind]; seen == nil || seen.suppressed != 999 {
			t.Fatalf("refusal %v: the repeats are not counted against the target: %+v", refusal, seen)
		}
	}
}

// The limiters' caps are an organization's as well as the node's: one organization's flood of addresses fills only
// its share, and another organization's addresses are named as before (device sign-ins started too).
func TestOneOrganizationsFloodLeavesTheOthersNamed(t *testing.T) {
	s := &Service{}
	for i := range refusalKeys {
		a := "a" + strconv.Itoa(i)
		s.AuditLoginFailure(true, "attacker-org", a, "own-account", "passkey other organization", func(map[string]string) {})
		s.AuditLoginFailure(false, "attacker-org", a, "x:"+a, "password", func(map[string]string) {})
		s.AuditDeviceStart("attacker-org", "client|"+a, func(map[string]string) {})
	}
	named := map[string]bool{}
	for i := range 50 {
		a := "real" + strconv.Itoa(i)
		s.AuditLoginFailure(true, "victim-org", a, "victim", "password", func(map[string]string) { named["account "+a] = true })
		s.AuditLoginFailure(false, "victim-org", a, "x:"+a, "password", func(map[string]string) { named["login "+a] = true })
		s.AuditDeviceStart("victim-org", "client|"+a, func(map[string]string) { named["device "+a] = true })
	}
	if len(named) != 150 {
		t.Fatalf("another organization's addresses named: %d of 150", len(named))
	}
	if n := s.accountFailures.addrs.count.orgs["attacker-org"]; n > refusalKeysPerOrg {
		t.Fatalf("one organization holds %d addresses", n)
	}
	if n := s.deviceStarts.count.orgs["attacker-org"]; n != refusalKeysPerOrg {
		t.Fatalf("one organization holds %d device sign-in keys", n)
	}
}

// What an organization has recorded naming addresses is bounded however many addresses send the events, and an IPv6
// /48 has one allowance however many /64s it holds: a flood from 20,000 addresses costs the organization a few
// hundred events a minute, not 10,000, and the kind's event that cannot name its address says how many were left
// unnamed.
func TestAddressFloodBoundedPerOrganization(t *testing.T) {
	s := &Service{}
	n := 0
	for i := range 20000 {
		s.AuditLoginFailure(false, "org1", fmt.Sprintf("2001:db8:1:%x::/64", i), "", "callback", func(map[string]string) { n++ })
	}
	if n != LoginRowsPerAddressUnknown+1+1 { // the /48's allowance, its summary, and the kind's own event
		t.Fatalf("20,000 /64s of one /48: %d events", n)
	}

	s = &Service{}
	var details []map[string]string
	for i := range 20000 {
		addr := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String()
		s.AuditLoginFailure(false, "org1", addr, "", "callback", func(d map[string]string) { details = append(details, d) })
	}
	if len(details) != LoginAddressRowsPerOrg+1 {
		t.Fatalf("20,000 addresses: %d events", len(details))
	}
	if first := details[LoginAddressRowsPerOrg]; first["addresses_unnamed"] != "" { // the first one past the cap
		t.Fatalf("the first event past the organization's allowance: %v", first)
	}
	s.loginFailures.flooded.seen["org1|callback"].until = time.Now() // the kind's window is over
	details = nil
	s.AuditLoginFailure(false, "org1", "10.200.0.1", "", "callback", func(d map[string]string) { details = append(details, d) })
	if len(details) != 1 || details[0]["suppressed"] == "" {
		t.Fatalf("the kind's next event: %v", details)
	}
	// The allowance tracks refusalKeysPerOrg addresses of the organization, the cap's first 200 named among them.
	if got, _ := strconv.Atoi(details[0]["addresses_unnamed"]); got != refusalKeysPerOrg-LoginAddressRowsPerOrg-1 {
		t.Fatalf("addresses left unnamed: %v", details[0])
	}

	for in, want := range map[string]string{
		"2001:db8:1:2::/64": "2001:db8:1::/48", "2001:db8:1:2::5": "2001:db8:1::/48", "2001:db8::/32": "2001:db8::/32",
		"192.0.2.1": "192.0.2.1", "::ffff:192.0.2.1": "::ffff:192.0.2.1", "x": "x",
	} {
		if got := wideAddr(in); got != want {
			t.Fatalf("wideAddr(%s) = %s, want %s", in, got, want)
		}
	}
}

// The events that name no account (a provider's callback failing, a passkey nobody holds) have an event keyed
// without the address as well, per organization and kind: a flood of made-up logins from more addresses than the
// limiter holds cannot crowd out a real provider's failures, a kind of their own.
func TestUnknownLoginEventsHaveAFallback(t *testing.T) {
	s := &Service{}
	for i := range refusalKeys + 10 {
		s.AuditLoginFailure(false, "org1", "a"+strconv.Itoa(i), "", "callback", func(map[string]string) {})
	}
	recorded := 0
	for i := range 3 {
		s.AuditLoginFailure(false, "org1", "late"+strconv.Itoa(i), "", "upstream not_linked", func(map[string]string) { recorded++ })
	}
	if recorded != 1 {
		t.Fatalf("a real provider's failures under a flood: recorded %d", recorded)
	}
	if seen := s.loginFailures.flooded.seen["org1|upstream not_linked"]; seen == nil || seen.suppressed != 2 {
		t.Fatalf("the repeats are not counted: %+v", seen)
	}
}

// A sweep of a full limiter is paid once a second at most, and never before a key can have expired: a flood that
// keeps a share full does not pay a pass over 10,000 keys a request.
func TestFullLimiterSweepsSparingly(t *testing.T) {
	var l refusalLimiter
	now := time.Now()
	for i := range refusalKeysPerOrg {
		l.allow("o", strconv.Itoa(i), now)
	}
	if ok, _, full, _ := l.allow("o", "more", now); ok || !full {
		t.Fatal("past the organization's share")
	}
	if !l.count.next.Equal(now.Add(refusalWindow)) || !l.count.swept.Equal(now) {
		t.Fatalf("after a sweep: next %v swept %v", l.count.next, l.count.swept)
	}
	l.seen["0"].until = now // as if it expired: still not swept before next
	if ok, _, _, _ := l.allow("o", "more", now.Add(2*time.Second)); ok {
		t.Fatal("swept before any key could have expired")
	}
	if ok, _, _, _ := l.allow("other", "k", now.Add(2*time.Second)); !ok {
		t.Fatal("another organization was held back by one's share")
	}
	if ok, _, _, _ := l.allow("o", "more", now.Add(refusalWindow)); !ok {
		t.Fatal("not swept once the keys expired")
	}
}
