package service

import (
	"strconv"
	"testing"
	"time"
)

// One refusal event per key and window; the next one says how many were held back; the key space is capped.
func TestRefusalLimiter(t *testing.T) {
	var l refusalLimiter
	now := time.Now()
	if ok, n := l.allow("k", now); !ok || n != 0 {
		t.Fatalf("first: %v %d", ok, n)
	}
	for range 5 {
		if ok, _ := l.allow("k", now.Add(time.Second)); ok {
			t.Fatal("a repeat within the window was let through")
		}
	}
	if ok, _ := l.allow("other", now); !ok {
		t.Fatal("another key was held back")
	}
	if ok, n := l.allow("k", now.Add(refusalWindow)); !ok || n != 5 {
		t.Fatalf("after the window: %v, suppressed %d (want 5)", ok, n)
	}
	var full refusalLimiter
	for i := range refusalKeys {
		full.allow(strconv.Itoa(i), now)
	}
	if ok, _ := full.allow("one more", now); ok {
		t.Fatal("a key past the cap was let through while every key is live")
	}
	if ok, _ := full.allow("one more", now.Add(refusalWindow)); !ok {
		t.Fatal("expired keys were not pruned to make room")
	}
}

// A flood of sign-in lockout refusals, whose keys the refused choose, fills only their own limiter: the other
// refusal events (a token presented with a wrong secret) are still recorded.
func TestLoginRefusalsHaveTheirOwnLimiter(t *testing.T) {
	s := &Service{}
	recorded := 0
	for i := range refusalKeys + 100 {
		s.AuditLoginRefusal("login|org|x:"+strconv.Itoa(i)+"|locked", func(map[string]string) { recorded++ })
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
