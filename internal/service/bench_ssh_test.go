package service_test

import (
	"strconv"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// BenchmarkSSHKRL is a full build of one tenant's revocation list (cache dropped every iteration): N users each
// holding C live certificates, all read and evaluated for revocation.
func BenchmarkSSHKRL(b *testing.B) {
	const certs = 2
	for _, users := range []int{100, 1000} {
		b.Run("users="+strconv.Itoa(users), func(b *testing.B) {
			e := newEnv(b)
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
		})
	}
}
