package cluster

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

type deepPromotionDeleteGate struct {
	store.Store
	id           string
	fired        atomic.Bool
	beforeDelete func()
}

func (g *deepPromotionDeleteGate) CompareAndPut(ctx context.Context, r *store.Record, expected hlc.Timestamp) error {
	if r.Deleted && r.Kind == model.KindUser && r.ID == g.id && g.fired.CompareAndSwap(false, true) {
		g.beforeDelete()
	}
	return g.Store.CompareAndPut(ctx, r, expected)
}
func TestDeepReviewDeleteUserRechecksConcurrentPromotion(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svc := service.New(config.Default(), c.nodes[0].st(), sealer)
	if _, _, err := svc.Bootstrap(bg, "root@example.test"); err != nil {
		t.Fatal(err)
	}
	org, err := svc.PrimaryOrg(bg)
	if err != nil {
		t.Fatal(err)
	}
	makeUser := func(name string, role model.Role) *model.User {
		email := name + "@example.test"
		u, err := svc.CreateUser(bg, service.System, org.ID, service.UserInput{Username: &name, GivenName: &name, Email: &email, Role: &role})
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	admin := makeUser("admin", model.RoleAdmin)
	target := makeUser("target", model.RoleUser)
	svc.MinSuperAdmins = 2
	gate := &deepPromotionDeleteGate{Store: svc.Users.S, id: target.ID}
	gate.beforeDelete = func() {
		role := model.RoleSuperAdmin
		if _, err := svc.UpdateUser(bg, service.System, target.ID, service.UserInput{Role: &role}); err != nil {
			t.Error(err)
		}
	}
	svc.Users.S = gate
	if err := svc.DeleteUser(bg, service.ActorForUser(admin, ""), target.ID); err == nil {
		t.Fatal("ordinary admin deleted concurrently promoted super admin without rechecking permissions or last-admin guard")
	}
}
