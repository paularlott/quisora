package service_test

import (
	"strconv"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// CreateUser without a password skips argon2id, so this measures validation, the store write and the audit record.
func BenchmarkCreateUser(b *testing.B) {
	e := newEnv(b)
	org := e.org("bench")
	a := service.System
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		name := "user" + strconv.Itoa(i)
		email := name + "@example.com"
		if _, err := e.svc.CreateUser(e.ctx, a, org.ID, service.UserInput{GivenName: gn("T"), Username: &name, Email: &email}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkListUsers1000(b *testing.B) {
	e := newEnv(b)
	org := e.org("bench")
	for i := range 1000 {
		name := "user" + strconv.Itoa(i)
		email := name + "@example.com"
		if _, err := e.svc.CreateUser(e.ctx, service.System, org.ID, service.UserInput{GivenName: gn("T"), Username: &name, Email: &email}); err != nil {
			b.Fatal(err)
		}
	}
	admin := e.user(org.ID, "boss", model.RoleAdmin)
	a := actor(admin)
	b.Run("page50", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, n, err := e.svc.ListUsers(e.ctx, a, org.ID, store.ListQuery{Sort: "username", Limit: 50}); err != nil || n != 1001 {
				b.Fatal(err, n)
			}
		}
	})
	b.Run("search", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, n, err := e.svc.ListUsers(e.ctx, a, org.ID, store.ListQuery{Search: "user99", Limit: 50}); err != nil || n != 11 {
				b.Fatal(err, n)
			}
		}
	})
	b.Run("all", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, n, err := e.svc.ListUsers(e.ctx, a, org.ID, store.ListQuery{}); err != nil || n != 1001 {
				b.Fatal(err, n)
			}
		}
	})
}

func BenchmarkValidateAPIToken(b *testing.B) {
	e := newEnv(b)
	u := e.user(e.primary.ID, "tokenuser", model.RoleManager)
	_, plain, err := e.svc.CreateAPIToken(e.ctx, actor(u), service.APITokenInput{Name: "bench", Scopes: []string{"scim"}})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := e.svc.ValidateAPIToken(e.ctx, plain); err != nil {
			b.Fatal(err)
		}
	}
}
