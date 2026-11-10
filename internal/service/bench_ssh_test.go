package service_test

import (
	"strconv"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/kvstore"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// BenchmarkSSHKRL is a full build of one tenant's revocation list (cache dropped every iteration): N users each
// holding C live certificates, all read and evaluated for revocation. On the memory store, whose every listing scans
// every record, and on BadgerDB, whose listings by an indexed field read the matches only: a build lists each user's
// group memberships, so the memory store's cost grows with the square of the users.
func BenchmarkSSHKRL(b *testing.B) {
	const certs = 2
	stores := []struct {
		name string
		open func(b *testing.B) store.Store
	}{
		{"memory", func(b *testing.B) store.Store { return memstore.New() }},
		{"badger", func(b *testing.B) store.Store {
			st, err := kvstore.OpenBadger(b.Context(), b.TempDir(), kvstore.BadgerOptions{NoSync: true})
			if err != nil {
				b.Fatal(err)
			}
			return st
		}},
	}
	for _, sto := range stores {
		for _, users := range []int{100, 1000} {
			b.Run("store="+sto.name+"/users="+strconv.Itoa(users), func(b *testing.B) {
				st := sto.open(b)
				b.Cleanup(func() { _ = st.Close() })
				benchSSHKRL(b, newEnvOn(b, st), users, certs)
			})
		}
	}
}

// benchSSHKRL measures the build of the revocation list of a tenant of e open to everyone, with users users each
// holding certs certificates.
func benchSSHKRL(b *testing.B, e *env, users, certs int) {
	org := e.org("acme")
	ten := e.tenant(org.ID, "prod")
	open := ten.Settings
	open.MembersOnly = false
	ten, err := e.svc.UpdateTenant(e.ctx, service.System, ten.ID, service.TenantInput{Settings: &open})
	if err != nil {
		b.Fatal(err)
	}
	w := &sshWorld{env: e, org: org, tenant: ten, admin: e.user(org.ID, "boss", model.RoleAdmin)}
	w.enable()
	for i := range users {
		u := e.user(org.ID, "user"+strconv.Itoa(i), model.RoleUser)
		for range certs {
			w.mustSign(u)
		}
	}
	if _, err := e.svc.SSHKRL(e.ctx, ten.ID); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		e.svc.InvalidateSSHKRL()
		if data, err := e.svc.SSHKRL(e.ctx, ten.ID); err != nil || len(data) == 0 {
			b.Fatal(err, len(data))
		}
	}
}
