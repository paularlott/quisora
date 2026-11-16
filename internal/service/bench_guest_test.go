package service_test

import (
	"context"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store/kvstore"
)

// The check every request of a guest's session makes of the accounts it came from (SourcesHold): the source user
// alone (no sign-in application recorded), and with the sign-in application it came through in an open tenant and in
// a members-only one whose access is through a group of the user's (the vendor case). On the memory store and on the
// key-value store a cluster node runs on.
func BenchmarkGuestSourcesHold(b *testing.B) {
	for _, st := range []string{"memstore", "badger"} {
		b.Run(st, func(b *testing.B) {
			e := newEnv(b)
			if st == "badger" {
				s, err := kvstore.OpenBadger(context.Background(), b.TempDir(), kvstore.BadgerOptions{})
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { s.Close() })
				e = newEnvOn(b, s)
			}
			org := e.org("vendor")
			u := e.user(org.ID, "pat", model.RoleUser)
			open, err := e.svc.DefaultTenant(e.ctx, org.ID)
			if err != nil {
				b.Fatal(err)
			}
			closed, err := e.svc.CreateTenant(e.ctx, service.System, org.ID, service.TenantInput{Name: ptr("support")})
			if err != nil {
				b.Fatal(err)
			}
			for i := range 5 { // a few groups, one of which has access
				g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: ptr("g" + string(rune('a'+i)))}, []string{u.ID})
				if err != nil {
					b.Fatal(err)
				}
				if i == 4 {
					if _, err := e.svc.AddAccess(e.ctx, service.System, closed.ID, service.AccessInput{SubjectType: model.SubjectGroup, SubjectID: g.ID}); err != nil {
						b.Fatal(err)
					}
				}
			}
			client := func(t *model.Tenant) string {
				c, _, err := e.svc.CreateClient(e.ctx, service.System, org.ID, service.ClientInput{Name: ptr("Sign-in"), TenantID: &t.ID,
					RedirectURIs: &[]string{"https://idp.example/cb"}})
				if err != nil {
					b.Fatal(err)
				}
				return c.ID
			}
			openClient, closedClient := client(open), client(closed)
			users := func(ctx context.Context, id string) (*model.User, error) { return u, nil } // as the session cache gives it
			for _, tc := range []struct {
				name string
				src  model.GuestSource
			}{
				{"user only", model.GuestSource{UserID: u.ID}},
				{"open tenant", model.GuestSource{UserID: u.ID, Client: openClient}},
				{"members-only tenant", model.GuestSource{UserID: u.ID, Client: closedClient}},
			} {
				b.Run(tc.name, func(b *testing.B) {
					srcs := []model.GuestSource{tc.src}
					b.ReportAllocs()
					for b.Loop() {
						if ok, err := e.svc.SourcesHold(e.ctx, srcs, users); err != nil || !ok {
							b.Fatal(ok, err)
						}
					}
				})
			}
		})
	}
}
