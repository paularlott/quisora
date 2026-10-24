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

type fresh3GroupSnapshot struct {
	store.Store
	members, groups                                  atomic.Bool
	memberRead, memberResume, groupRead, groupResume chan struct{}
}

func (g *fresh3GroupSnapshot) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	r, err := g.Store.List(ctx, kind, q)
	if kind == model.KindMember && g.members.CompareAndSwap(false, true) {
		close(g.memberRead)
		<-g.memberResume
	}
	return r, err
}

func (g *fresh3GroupSnapshot) GetMany(ctx context.Context, kind model.Kind, ids []string) ([]*store.Record, error) {
	var r []*store.Record
	var err error
	for _, id := range ids {
		var rec *store.Record
		rec, err = g.Store.Get(ctx, kind, id)
		if err != nil {
			break
		}
		r = append(r, rec)
	}
	if kind == model.KindGroup && g.groups.CompareAndSwap(false, true) {
		close(g.groupRead)
		<-g.groupResume
	}
	return r, err
}

// The recheck must match the group version whose tags it authorizes: a newer
// active membership cannot authorize a group snapshot under which it was removed.
func TestFreshGroupRecheckCannotAuthorizeAnOlderPrivilegeSnapshot(t *testing.T) {
	e := newEnv(t)
	org := e.org("fresh-recheck-snapshot")
	u := e.user(org.ID, "member", model.RoleUser)
	name := "Group"
	g, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name}, []string{u.ID})
	if err != nil {
		t.Fatal(err)
	}
	gate := &fresh3GroupSnapshot{Store: e.svc.Store, memberRead: make(chan struct{}), memberResume: make(chan struct{}), groupRead: make(chan struct{}), groupResume: make(chan struct{})}
	e.svc.Members.S, e.svc.Groups.S = gate, gate
	type result struct {
		gs  []*model.Group
		err error
	}
	done := make(chan result, 1)
	go func() { gs, err := e.svc.UserGroups(e.ctx, u); done <- result{gs, err} }()
	<-gate.memberRead // reader holds initial membership, seq 1
	tags := []string{"admin"}
	g, err = e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{Tags: &tags}, nil, []string{u.ID})
	if err != nil {
		close(gate.memberResume)
		close(gate.groupResume)
		t.Fatal(err)
	}
	close(gate.memberResume)
	<-gate.groupRead // reader holds group seq 2: admin tag, user removed
	tags = nil
	_, err = e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{Tags: &tags}, []string{u.ID}, nil)
	close(gate.groupResume) // recheck sees membership seq 3: user re-added, admin tag gone
	r := <-done
	if err != nil {
		t.Fatal(err)
	}
	if r.err != nil {
		t.Fatal(r.err)
	}
	for _, group := range r.gs {
		if group.ID == g.ID && slices.Contains(group.Tags, "admin") {
			t.Fatalf("user received a privilege they never held: %+v", group)
		}
	}
}
