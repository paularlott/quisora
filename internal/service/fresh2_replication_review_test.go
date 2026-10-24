package service_test

import (
	"context"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

type fresh2MemberSnapshot struct {
	store.Store
	blocked         atomic.Bool
	entered, resume chan struct{}
}

func (g *fresh2MemberSnapshot) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	r, err := g.Store.List(ctx, kind, q)
	if kind == model.KindMember && g.blocked.CompareAndSwap(false, true) {
		close(g.entered)
		<-g.resume
	}
	return r, err
}

// A group update atomically removes a user while granting the group a new tag.
// A concurrent token lookup must not combine membership from before the commit
// with tags from after the commit: the user never possessed that tag.
func TestFreshUserGroupsCannotGrantTagsAfterAtomicRemoval(t *testing.T) {
	e := newEnv(t)
	org := e.org("fresh-read-snapshot")
	u := e.user(org.ID, "member", model.RoleUser)
	name := "Group"
	g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{u.ID})
	if err != nil {
		t.Fatal(err)
	}
	gate := &fresh2MemberSnapshot{Store: e.svc.Store, entered: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Members.S = gate
	type result struct {
		gs  []*model.Group
		err error
	}
	done := make(chan result, 1)
	go func() { gs, err := e.svc.UserGroups(e.ctx, u); done <- result{gs, err} }()
	<-gate.entered
	tags := []string{"admin"}
	_, err = e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{Tags: &tags}, nil, []string{u.ID})
	close(gate.resume)
	r := <-done
	if err != nil {
		t.Fatal(err)
	}
	if r.err != nil {
		t.Fatal(r.err)
	}
	for _, group := range r.gs {
		if group.ID == g.ID && slices.Contains(group.Tags, "admin") {
			t.Fatalf("removed user received newly privileged group: %+v", group)
		}
	}
}
