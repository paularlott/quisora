package service_test

import (
	"fmt"
	"os"
	"runtime"
	"runtime/metrics"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/kvstore"
)

// TestScale times the console and token paths on Badger with 100,000 organizations and one organization of 100,000
// users. Opt-in (QUISORA_SCALE=1): seeding takes minutes.
func TestScale(t *testing.T) {
	if os.Getenv("QUISORA_SCALE") == "" {
		t.Skip("set QUISORA_SCALE=1")
	}
	orgs, users, groups := 100_000, 100_000, 50
	if os.Getenv("QUISORA_SCALE") == "small" {
		orgs, users = 1000, 20_000
	}
	st, err := kvstore.OpenBadger(t.Context(), t.TempDir(), kvstore.BadgerOptions{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := newEnvOn(t, st)
	svc, ctx := e.svc, e.ctx

	start := time.Now()
	for i := range orgs {
		if err := svc.Orgs.Create(ctx, &model.Org{Name: fmt.Sprintf("org-%06d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	big := e.org("big")
	admin := e.user(big.ID, "boss", model.RoleAdmin)
	var gs []*model.Group
	for i := range groups {
		g := &model.Group{OrgID: big.ID, DisplayName: fmt.Sprintf("group-%02d", i)}
		if err := svc.Groups.Create(ctx, g); err != nil {
			t.Fatal(err)
		}
		gs = append(gs, g)
	}
	var some *model.User
	for i := range users {
		u := &model.User{OrgID: big.ID, Username: fmt.Sprintf("user-%06d", i), Email: fmt.Sprintf("user-%06d@example.com", i),
			GivenName: fmt.Sprintf("User %06d", i), Role: model.RoleUser, Active: true}
		if i%10 == 0 {
			u.Tags = []string{"staff"}
		}
		if err := svc.Users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		if err := svc.SignIns.Create(ctx, &model.SignIn{Meta: model.Meta{ID: u.ID}, OrgID: big.ID,
			LastLogin: time.Now().Add(-time.Duration(i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
		for _, g := range gs[:3] {
			_ = svc.Members.Create(ctx, &model.Member{Meta: model.Meta{ID: model.MemberID(g.ID, u.ID)}, GroupID: g.ID, UserID: u.ID, OrgID: big.ID})
		}
		some = u
	}
	t.Logf("seeded %d orgs, %d users in one org in %s", orgs, users, time.Since(start).Round(time.Second))

	super := service.System
	adm := actor(admin)
	// measure reports time per call, bytes allocated per call (garbage the GC must collect), and the most live heap
	// the GC found above the baseline while the calls ran: what a call actually holds at once.
	live := func() uint64 {
		s := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
		metrics.Read(s)
		return s[0].Value.Uint64()
	}
	runtime.GC()
	t.Logf("baseline live heap %.0f MB (the store's caches and the test's data)", float64(live())/(1<<20))
	measure := func(name string, fn func() error) {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		base := live()
		var peak atomic.Uint64
		stop := make(chan struct{})
		sampled := make(chan struct{})
		go func() {
			defer close(sampled)
			for {
				if l := live(); l > peak.Load() {
					peak.Store(l)
				}
				select {
				case <-stop:
					return
				case <-time.After(time.Millisecond):
				}
			}
		}()
		const n = 5
		start := time.Now()
		for range n {
			if err := fn(); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		took := time.Since(start)
		close(stop)
		<-sampled
		runtime.ReadMemStats(&after)
		held := float64(0)
		if p := peak.Load(); p > base {
			held = float64(p-base) / (1 << 20)
		}
		t.Logf("%-46s %10s/op %8.1f MB alloc/op %8.1f MB held", name, (took / n).Round(time.Microsecond),
			float64(after.TotalAlloc-before.TotalAlloc)/n/(1<<20), held)
	}
	list := func(q store.ListQuery) func() error {
		return func() error { _, _, err := svc.ListUsers(ctx, adm, big.ID, q); return err }
	}
	measure("orgs: page 25 by name", func() error {
		_, _, err := svc.ListOrgs(ctx, super, store.ListQuery{Sort: "name", Limit: 25})
		return err
	})
	measure("orgs: page 25 by name, offset 50,000", func() error {
		_, _, err := svc.ListOrgs(ctx, super, store.ListQuery{Sort: "name", Offset: 50_000, Limit: 25})
		return err
	})
	measure("orgs: search (100 matches)", func() error {
		_, _, err := svc.ListOrgs(ctx, super, store.ListQuery{Search: "org-0999", Limit: 25})
		return err
	})
	measure("users: page 25", list(store.ListQuery{Limit: 25}))
	measure("users: page 25 by username", list(store.ListQuery{Sort: "username", Limit: 25}))
	measure("users: page 25 by username, offset 50,000", list(store.ListQuery{Sort: "username", Offset: 50_000, Limit: 25}))
	measure("users: page 25 by email desc", list(store.ListQuery{Sort: "email", Desc: true, Limit: 25}))
	measure("users: search (10 matches)", list(store.ListQuery{Search: "user-09999", Limit: 25}))
	measure("users: search (1,000 matches)", list(store.ListQuery{Search: "user-099", Limit: 25}))
	measure("users: search matching everyone (worst case)", list(store.ListQuery{Search: "user-", Limit: 25}))
	measure("users: tagged staff, page 25", func() error {
		_, _, err := svc.ListUsersTagged(ctx, adm, big.ID, store.ListQuery{Limit: 25}, "staff")
		return err
	})
	measure("users: by username (unique)", func() error {
		_, err := svc.Users.GetByUnique(ctx, model.UserUsernameKey(big.ID, "user-050000"))
		return err
	})
	measure("users: admins (admin_rank index)", func() error {
		_, _, err := svc.Users.List(ctx, store.ListQuery{Scope: big.ID, Filters: []store.Filter{{Field: "admin_rank", Value: true}}})
		return err
	})
	measure("token: UserGroups (50 groups)", func() error { _, err := svc.UserGroups(ctx, some); return err })
	measure("groups: members of a group (100,000)", func() error {
		_, err := svc.GroupMembers(ctx, adm, gs[0].ID)
		return err
	})
}
