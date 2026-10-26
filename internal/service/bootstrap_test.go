package service_test

import (
	"context"
	"sync"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// Many nodes bootstrapping one database at once make one primary organization, one first super admin and one
// invitation; a renamed primary organization is not made again; an organization left without its admin (a crash
// between the steps) gets one on the next start.
func TestBootstrapOnce(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 2
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	st := memstore.New()
	var wg sync.WaitGroup
	var mu sync.Mutex
	links := 0
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u, link, err := service.New(cfg, st, sealer).Bootstrap(ctx, "root@example.com")
			if err != nil {
				t.Error(err)
				return
			}
			if u != nil && link != "" {
				mu.Lock()
				links++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	svc := service.New(cfg, st, sealer)
	orgs, _, _ := svc.Orgs.List(ctx, store.ListQuery{})
	supers, _, _ := svc.Users.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "role", Value: string(model.RoleSuperAdmin)}}})
	if len(orgs) != 1 || len(supers) != 1 || links != 1 {
		t.Fatalf("orgs %d, super admins %d, invitation links %d; want 1 each", len(orgs), len(supers), links)
	}
	// the first super admin has no password (an invitation is how they set one), and the primary organization requires MFA
	if supers[0].PasswordHash != "" {
		t.Fatal("the first admin has a password")
	}
	if !orgs[0].Settings.RequireMFA {
		t.Fatal("the primary org must require MFA")
	}
	// renamed: still the primary organization, nothing new
	o := orgs[0]
	o.Name = "headquarters"
	if err := svc.Orgs.Update(ctx, o); err != nil {
		t.Fatal(err)
	}
	if u, _, err := service.New(cfg, st, sealer).Bootstrap(ctx, "other@example.com"); err != nil || u != nil {
		t.Fatalf("bootstrap after a rename made %v (%v)", u, err)
	}
	// a bootstrap that stopped after the organization (no admin yet) is completed by the next run
	st2 := memstore.New()
	half := service.New(cfg, st2, sealer)
	o2 := &model.Org{Meta: model.Meta{ID: model.PrimaryOrgID}, Name: "primary", Primary: true, Settings: model.DefaultOrgSettings()}
	if err := half.Orgs.Create(ctx, o2); err != nil {
		t.Fatal(err)
	}
	if u, link, err := half.Bootstrap(ctx, "root@example.com"); err != nil || u == nil || link == "" {
		t.Fatalf("missing first admin not made: %v %v", u, err)
	}
	// records written by bootstrap carry the oldest version: anything that exists is newer
	if r, err := st.Get(ctx, model.KindTenant, model.PrimaryTenantID); err != nil || r.Version != model.BootstrapVersion {
		t.Fatalf("default tenant: %v %v", r, err)
	}
}
