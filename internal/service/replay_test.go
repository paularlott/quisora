package service_test

import (
	"testing"
	"time"
)

// A value is used once: a replay of it, until it expires, is refused, and another value is its own.
func TestUseOnce(t *testing.T) {
	e := newEnv(t)
	exp := time.Now().Add(time.Minute)
	if ok, err := e.svc.UseOnce(e.ctx, "ns:value", exp); err != nil || !ok {
		t.Fatalf("first use: %v %v", ok, err)
	}
	if ok, err := e.svc.UseOnce(e.ctx, "ns:value", exp); err != nil || ok {
		t.Fatalf("replay: %v %v", ok, err)
	}
	if ok, err := e.svc.UseOnce(e.ctx, "ns:other", exp); err != nil || !ok {
		t.Fatalf("other key: %v %v", ok, err)
	}
}
