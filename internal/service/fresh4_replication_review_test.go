package service_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

type fresh4ReadCounter struct {
	store.Store
	calls atomic.Int64
}

func (c *fresh4ReadCounter) Fresh(ctx context.Context, kind model.Kind, ids []string) (map[string]*store.Record, error) {
	c.calls.Add(1)
	out := map[string]*store.Record{}
	for _, id := range ids {
		r, err := c.Store.Lookup(ctx, kind, id)
		if err != nil {
			return nil, err
		}
		out[id] = r
	}
	return out, nil
}

// Measurement: changes to other members leave this user's membership at an older
// sequence. Every such group currently requires its own serialized quorum read.
func TestFresh4UserGroupsQuorumReadFanout(t *testing.T) {
	e := newEnv(t)
	org := e.org("fresh-quorum-fanout")
	u := e.user(org.ID, "member", model.RoleUser)
	other := e.user(org.ID, "other", model.RoleUser)
	const groups = 12
	for i := range groups {
		name := fmt.Sprintf("Group %02d", i)
		g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{u.ID})
		if err != nil {
			t.Fatal(err)
		}
		if err := e.svc.SetMembership(e.ctx, service.System, g.ID, other.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	counter := &fresh4ReadCounter{Store: e.svc.Store}
	e.svc.Store = counter
	gs, err := e.svc.UserGroups(e.ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != groups {
		t.Fatalf("got %d groups, want %d", len(gs), groups)
	}
	t.Logf("%d unchanged memberships caused %d serial quorum read calls", groups, counter.calls.Load())
}
