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
	if ok, n, _, _ := l.allow("k", now); !ok || n != 0 {
		t.Fatalf("first: %v %d", ok, n)
	}
	for range 5 {
		if ok, _, _, _ := l.allow("k", now.Add(time.Second)); ok {
			t.Fatal("a repeat within the window was let through")
		}
	}
	if ok, _, _, _ := l.allow("other", now); !ok {
		t.Fatal("another key was held back")
	}
	if ok, n, _, _ := l.allow("k", now.Add(refusalWindow)); !ok || n != 5 {
		t.Fatalf("after the window: %v, suppressed %d (want 5)", ok, n)
	}
	var full refusalLimiter
	for i := range refusalKeys {
		full.allow(strconv.Itoa(i), now)
	}
	if ok, _, _, _ := full.allow("one more", now); ok {
		t.Fatal("a key past the cap was let through while every key is live")
	}
	if ok, _, _, _ := full.allow("one more", now.Add(refusalWindow)); !ok {
		t.Fatal("expired keys were not pruned to make room")
	}
}

// A flood of sign-in lockout refusals, whose keys the refused choose, fills only their own limiter: the other
// refusal events (a token presented with a wrong secret) are still recorded.
func TestLoginRefusalsHaveTheirOwnLimiter(t *testing.T) {
	s := &Service{}
	recorded := 0
	for i := range refusalKeys + 100 {
		s.AuditLoginRefusal(false, "login|org|x:"+strconv.Itoa(i)+"|locked", func(map[string]string) { recorded++ })
	}
	if recorded != refusalKeys {
		t.Fatalf("login refusals recorded: %d", recorded)
	}
	api := false
	s.auditRefusal("token|t1|wrong secret", func(map[string]string) { api = true })
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
		l.allow(strconv.Itoa(i), now)
	}
	warned := 0
	for i := range 7 {
		ok, _, full, warn := l.allow("new"+strconv.Itoa(i), now.Add(time.Second))
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
	if _, _, _, warn := l.allow("again", now.Add(time.Second+time.Minute-time.Millisecond)); warn {
		t.Fatal("warned again within the minute")
	}
	s := &Service{}
	before := metrics.AuditRefusalsDropped.Value("refusals")
	var details []map[string]string
	for i := range refusalKeys + 3 {
		s.auditRefusal("k"+strconv.Itoa(i), func(d map[string]string) { details = append(details, d) })
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
		s.AuditLoginRefusal(false, "login|org|x:"+strconv.Itoa(i)+"|locked", func(map[string]string) {})
	}
	recorded := false
	s.AuditLoginRefusal(true, "login|org|user1|locked", func(map[string]string) { recorded = true })
	if !recorded {
		t.Fatal("a real account's lockout refusal was silenced by a flood of made-up keys")
	}
}
