package service

import (
	"strconv"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/metrics"
)

// One refusal event per key and window; the next one says how many were held back; the key space is capped.
func TestRefusalLimiter(t *testing.T) {
	var l refusalLimiter
	now := time.Now()
	if ok, n, _, _ := l.allow("o", "k", now); !ok || n != 0 {
		t.Fatalf("first: %v %d", ok, n)
	}
	for range 5 {
		if ok, _, _, _ := l.allow("o", "k", now.Add(time.Second)); ok {
			t.Fatal("a repeat within the window was let through")
		}
	}
	if ok, _, _, _ := l.allow("o", "other", now); !ok {
		t.Fatal("another key was held back")
	}
	if ok, n, _, _ := l.allow("o", "k", now.Add(refusalWindow)); !ok || n != 5 {
		t.Fatalf("after the window: %v, suppressed %d (want 5)", ok, n)
	}
	var full refusalLimiter
	for i := range refusalKeys {
		full.allow("o"+strconv.Itoa(i%4), strconv.Itoa(i), now)
	}
	if ok, _, _, _ := full.allow("o5", "one more", now); ok {
		t.Fatal("a key past the cap was let through while every key is live")
	}
	if ok, _, _, _ := full.allow("o5", "one more", now.Add(refusalWindow)); !ok {
		t.Fatal("expired keys were not pruned to make room")
	}
}

// A flood of sign-in lockout refusals, whose keys the refused choose, fills only their own limiter: the other
// refusal events (a token presented with a wrong secret) are still recorded. The flood itself has its organization's
// events naming addresses recorded, then one for the kind that cannot name its address.
func TestLoginRefusalsHaveTheirOwnLimiter(t *testing.T) {
	s := &Service{}
	recorded := 0
	for i := range refusalKeys + 100 {
		s.AuditLoginRefusal(false, "org", "addr"+strconv.Itoa(i), "x:"+strconv.Itoa(i), "locked|password", func(map[string]string) { recorded++ })
	}
	if recorded != LoginAddressRowsPerOrg+1 {
		t.Fatalf("login refusals recorded: %d", recorded)
	}
	api := false
	s.auditRefusal("org", "token|t1|wrong secret", func(map[string]string) { api = true })
	if !api {
		t.Fatal("a token refusal was silenced by the login refusals")
	}
}

// A full limiter holds back refusals of new keys, but counts them (quisora_audit_refusals_dropped_total) for the
// operator, and asks for a warning once a minute, rather than telling some organization's next event.
func TestFullRefusalLimiterCountsWhatItHoldsBack(t *testing.T) {
	var l refusalLimiter
	now := time.Now()
	for i := range refusalKeys {
		l.allow("o"+strconv.Itoa(i%4), strconv.Itoa(i), now)
	}
	warned := 0
	for i := range 7 {
		ok, _, full, warn := l.allow("o5", "new"+strconv.Itoa(i), now.Add(time.Second))
		if ok || !full {
			t.Fatalf("while full: ok %v full %v", ok, full)
		}
		if warn {
			warned++
		}
	}
	if warned != 1 {
		t.Fatalf("warnings asked for: %d", warned)
	}
	if _, _, _, warn := l.allow("o5", "again", now.Add(time.Second+time.Minute-time.Millisecond)); warn {
		t.Fatal("warned again within the minute")
	}
	s := &Service{}
	before := metrics.AuditRefusalsDropped.Value("refusals")
	var details []map[string]string
	for i := range refusalKeys + 3 {
		s.auditRefusal("o"+strconv.Itoa(i%4), "k"+strconv.Itoa(i), func(d map[string]string) { details = append(details, d) })
	}
	if got := metrics.AuditRefusalsDropped.Value("refusals") - before; got != 3 || len(details) != refusalKeys {
		t.Fatalf("dropped %d, recorded %d", got, len(details))
	}
}

// A flood of lockout refusals for keys the refused make up cannot crowd out a real account's: those have a limiter
// of their own.
func TestAccountLockoutRefusalsNotCrowdedOut(t *testing.T) {
	s := &Service{}
	for i := range refusalKeys + 100 {
		s.AuditLoginRefusal(false, "org", "addr"+strconv.Itoa(i), "x:"+strconv.Itoa(i), "locked|password", func(map[string]string) {})
	}
	recorded := false
	s.AuditLoginRefusal(true, "org", "addr1", "user1", "locked|password", func(map[string]string) { recorded = true })
	if !recorded {
		t.Fatal("a real account's lockout refusal was silenced by a flood of made-up keys")
	}
}

// Wrong credentials at sign-in go through limiters of their own: one event per key and window, the next saying how
// many were held back, each held back still counted as a login.failure in the metrics. A flood of them for logins
// that name no account cannot crowd out a real account's (nor the lockout refusals'), and a flood of lockout
// refusals cannot crowd out a failure.
func TestLoginFailuresThrottledApart(t *testing.T) {
	s := &Service{}
	recorded := 0
	events := metrics.AuditEvents.Value("login.failure", "failure")
	for range 5 {
		s.AuditLoginFailure(true, "org", "addr1", "user1", "password", func(map[string]string) { recorded++ })
	}
	if held := metrics.AuditEvents.Value("login.failure", "failure") - events; recorded != 1 || held != 4 {
		t.Fatalf("recorded %d, counted held back %d", recorded, held)
	}
	seen := s.accountFailures.keys.seen["org|user1|password|addr1"]
	if seen == nil {
		t.Fatal("a real account's failure is not held in the accounts' failure limiter")
	}
	seen.until = time.Now() // the window is over
	var detail map[string]string
	s.AuditLoginFailure(true, "org", "addr1", "user1", "password", func(d map[string]string) { detail = d })
	if detail == nil || detail["suppressed"] != "4" {
		t.Fatalf("after the window: %v", detail)
	}

	dropped := metrics.AuditRefusalsDropped.Value("login_failures")
	for i := range refusalKeys + 10 {
		s.AuditLoginFailure(false, "org", "addr"+strconv.Itoa(i), "x:"+strconv.Itoa(i), "password", func(map[string]string) {})
		s.AuditLoginRefusal(true, "org", "addr"+strconv.Itoa(i), "u"+strconv.Itoa(i), "locked|password", func(map[string]string) {})
	}
	if got := metrics.AuditRefusalsDropped.Value("login_failures") - dropped; got != refusalKeys+10-LoginAddressRowsPerOrg {
		t.Fatalf("made-up logins' failures dropped: %d", got)
	}
	account, refusal := false, false
	s.AuditLoginFailure(true, "org", "addr2", "user2", "totp", func(map[string]string) { account = true })
	s.AuditLoginRefusal(false, "org", "addr1", "addr:1", "address locked|password", func(map[string]string) { refusal = true })
	if !account || !refusal {
		t.Fatalf("a real account's failure recorded %v, an address's refusal %v", account, refusal)
	}
}

// Every address that sends a wrong credential, or is refused as locked, is named by an event of the window: the key
// holds the address, so an address that sends one attempt first does not take the account's only event and leave
// the one that sends every attempt after it unnamed (only counted).
func TestLoginEventsNameEveryAddress(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record func(s *Service, account bool, addr, subject string, f func(map[string]string))
	}{
		{"failure", func(s *Service, account bool, addr, subject string, f func(map[string]string)) {
			s.AuditLoginFailure(account, "org", addr, subject, "password", f)
		}},
		{"refusal", func(s *Service, account bool, addr, subject string, f func(map[string]string)) {
			s.AuditLoginRefusal(account, "org", addr, subject, "locked|password", f)
		}},
	} {
		for _, account := range []bool{true, false} {
			s := &Service{}
			named := map[string]int{}
			from := func(addr string) { tc.record(s, account, addr, "pat", func(map[string]string) { named[addr]++ }) }
			from("decoy")
			for range 500 {
				from("guesser")
			}
			for i := range 50 {
				from("other" + strconv.Itoa(i))
			}
			if len(named) != 52 || named["decoy"] != 1 || named["guesser"] != 1 {
				t.Fatalf("%s (account %v): events by address %v", tc.name, account, named)
			}
		}
	}
}

// What one address can have recorded is bounded however many accounts it tries, or logins it makes up: its allowance
// of events in the organization for the window, then one that says the allowance is spent, then none; the next
// window's first event says how many were held back past it. Another address, and the same address in another
// organization, have their own. Past the allowance, an existing account is still named once a window by an event
// that cannot name its address (one per account), and the logins that name no account once per organization and
// kind. Every attempt held back is still counted.
func TestLoginEventsPerAddressAllowance(t *testing.T) {
	for _, tc := range []struct {
		account  bool
		limit    int
		fallback int // events past the allowance recorded without naming the address
	}{{true, LoginRowsPerAddress, 100 - LoginRowsPerAddress - 1}, {false, LoginRowsPerAddressUnknown, 1}} {
		s := &Service{}
		var details []map[string]string
		try := func(org, addr string, i int) {
			s.AuditLoginFailure(tc.account, org, addr, "u"+strconv.Itoa(i), "password", func(d map[string]string) { details = append(details, d) })
		}
		events := metrics.AuditEvents.Value("login.failure", "failure")
		for i := range 100 {
			try("org", "addr1", i)
		}
		if len(details) != tc.limit+1+tc.fallback {
			t.Fatalf("account %v: %d events of one address, want its %d, the one that says so and %d past it", tc.account, len(details), tc.limit, tc.fallback)
		}
		if last := details[tc.limit]; last["address_limit"] != strconv.Itoa(tc.limit) || last["address_suppressed"] != "0" {
			t.Fatalf("account %v: the event past the allowance: %v", tc.account, last)
		}
		for _, d := range details[tc.limit+1:] {
			if d["address_limit"] != "" || d["address_suppressed"] != "" {
				t.Fatalf("account %v: an event past the allowance: %v", tc.account, d)
			}
		}
		heldBack := 100 - tc.limit - 1 - tc.fallback
		if held := metrics.AuditEvents.Value("login.failure", "failure") - events; held != uint64(heldBack) {
			t.Fatalf("account %v: counted held back %d", tc.account, held)
		}
		details = nil
		try("org", "addr2", 0)
		try("org2", "addr1", 0)
		if len(details) != 2 {
			t.Fatalf("account %v: another address and another organization recorded %d events", tc.account, len(details))
		}
		l := &s.loginFailures
		if tc.account {
			l = &s.accountFailures
		}
		l.addrs.seen["org|addr1"].until = time.Now() // the window is over
		details = nil
		try("org", "addr1", 1000)
		want := ""
		if heldBack > 0 {
			want = strconv.Itoa(heldBack)
		}
		if len(details) != 1 || details[0]["address_suppressed"] != want || details[0]["address_limit"] != "" {
			t.Fatalf("account %v: after the window: %v", tc.account, details)
		}
	}
}

// The keys hold addresses, which a flood can make up: while the accounts' limiter is full of them, a real account's
// events are still recorded once per window (naming one address), not silenced, and what is dropped is counted.
func TestAccountLoginEventsSurviveAFloodOfAddresses(t *testing.T) {
	s := &Service{}
	for i := range refusalKeys {
		s.AuditLoginFailure(true, "org", "addr"+strconv.Itoa(i), "user1", "password", func(map[string]string) {})
	}
	dropped := metrics.AuditRefusalsDropped.Value("login_account_failures")
	recorded := 0
	for i := range 10 {
		s.AuditLoginFailure(true, "org", "late"+strconv.Itoa(i), "user2", "password", func(map[string]string) { recorded++ })
	}
	if got := metrics.AuditRefusalsDropped.Value("login_account_failures") - dropped; recorded != 1 || got != 10 {
		t.Fatalf("under a flood of addresses: recorded %d, dropped %d", recorded, got)
	}
	recorded = 0
	for i := range 10 {
		s.AuditLoginFailure(false, "org", "late"+strconv.Itoa(i), "nobody", "password", func(map[string]string) { recorded++ })
	}
	if recorded != 10 {
		t.Fatalf("the logins that name no account were silenced by the accounts' flood: %d", recorded)
	}
}
