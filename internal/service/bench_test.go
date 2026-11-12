package service_test

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/kvstore"
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
		if _, err := e.svc.CreateUser(e.ctx, a, org.ID, service.UserInput{GivenName: ptr("T"), Username: &name, Email: &email}); err != nil {
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
		if _, err := e.svc.CreateUser(e.ctx, service.System, org.ID, service.UserInput{GivenName: ptr("T"), Username: &name, Email: &email}); err != nil {
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

// A page of an organization's users sorted by username, for an administrator and for a manager (to whom the
// administrators are directory entries, sorted on ""): both are a page of the store's sort index, however large the
// organization.
func BenchmarkUsersPageByRole(b *testing.B) {
	for _, n := range []int{10000, 50000} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			st, err := kvstore.OpenBadger(b.Context(), b.TempDir(), kvstore.BadgerOptions{InMemory: true})
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = st.Close() })
			e := newEnvOn(b, st)
			org := e.org("big")
			admin := e.user(org.ID, "boss", model.RoleAdmin)
			mgr := e.user(org.ID, "mgr", model.RoleManager)
			recs := make([]*store.Record, 0, 1000)
			for i := range n {
				name := fmt.Sprintf("user-%06d", i)
				u := &model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: org.ID, Username: name, Email: name + "@example.test",
					GivenName: name, Role: model.RoleUser, Active: true}
				if i%1000 == 7 {
					u.Role = model.RoleAdmin
				}
				rec, err := store.Encode(u)
				if err != nil {
					b.Fatal(err)
				}
				if recs = append(recs, rec); len(recs) == cap(recs) || i == n-1 {
					if _, err := st.PutReplicatedBatch(e.ctx, recs); err != nil {
						b.Fatal(err)
					}
					recs = recs[:0]
				}
			}
			for _, who := range []struct {
				name string
				u    *model.User
			}{{"admin", admin}, {"manager", mgr}} {
				b.Run(who.name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						l, total, err := e.svc.ListUsers(e.ctx, actor(who.u), org.ID, store.ListQuery{Sort: "username", Offset: 100, Limit: 25})
						if err != nil || len(l) != 25 || total != n+2 {
							b.Fatal(err, len(l), total)
						}
					}
				})
			}
		})
	}
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
