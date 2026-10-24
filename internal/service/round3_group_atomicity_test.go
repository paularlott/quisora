package service_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

type round3GroupRollbackGate struct {
	store.Store
	groupID, failedMemberID string
	groupWrites             atomic.Int32
	entered, resume         chan struct{}
	paused                  atomic.Bool
	resumeOnce              sync.Once
}

func (g *round3GroupRollbackGate) letResume() { g.resumeOnce.Do(func() { close(g.resume) }) }

// Get lets the failed request resume as soon as the concurrent one is seen waiting for the group's lock: the failed
// request holds it through its undo, so the concurrent one cannot finish (as it would have, unisolated) until it does.
func (g *round3GroupRollbackGate) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == model.KindLock && id == "group/"+g.groupID && g.paused.Load() {
		g.letResume()
	}
	return g.Store.Get(ctx, kind, id)
}

func (g *round3GroupRollbackGate) Put(ctx context.Context, r *store.Record) error {
	if r.Kind == model.KindMember && r.ID == g.failedMemberID {
		return errors.New("review: membership storage failure")
	}
	return g.Store.Put(ctx, r)
}

func (g *round3GroupRollbackGate) CompareAndPut(ctx context.Context, r *store.Record, expected hlc.Timestamp) error {
	if r.Kind == model.KindMember && r.ID == g.failedMemberID {
		return errors.New("review: membership storage failure")
	}
	err := g.Store.CompareAndPut(ctx, r, expected)
	if r.Kind == model.KindGroup && r.ID == g.groupID && err == nil && g.groupWrites.Add(1) == 2 {
		g.paused.Store(true)
		close(g.entered)
		<-g.resume
	}
	return err
}

func TestRound3GroupRollbackCannotEraseLaterSuccessfulMembership(t *testing.T) {
	for _, adding := range []bool{true, false} {
		name := "retain-added-membership"
		if !adding {
			name = "retain-revocation"
		}
		t.Run(name, func(t *testing.T) { round3GroupRollback(t, adding) })
	}
}

func round3GroupRollback(t *testing.T, adding bool) {
	e := newEnv(t)
	org := e.org("rollback-window")
	first := e.user(org.ID, "first", model.RoleUser)
	second := e.user(org.ID, "second", model.RoleUser)
	name := "Original"
	group, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	if !adding {
		for _, user := range []*model.User{first, second} {
			if err := e.svc.SetMembership(e.ctx, service.System, group.ID, user.ID, true); err != nil {
				t.Fatal(err)
			}
		}
		group, err = e.svc.Groups.Get(e.ctx, group.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	gate := &round3GroupRollbackGate{Store: e.svc.Store, groupID: group.ID, failedMemberID: model.MemberID(group.ID, second.ID), entered: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Groups.S = gate
	e.svc.Members.S = gate
	e.svc.Locks.S = gate
	done := make(chan error, 1)
	go func() {
		add, remove := []string{first.ID, second.ID}, []string(nil)
		if !adding {
			add, remove = nil, add
		}
		_, err := e.svc.ChangeGroup(e.ctx, service.System, group, service.GroupInput{}, add, remove)
		done <- err
	}()
	<-gate.entered // failed request restored the group; its membership undo is still pending
	fresh, err := e.svc.Groups.Get(e.ctx, group.ID)
	if err != nil {
		gate.letResume()
		<-done
		t.Fatal(err)
	}
	renamed := "Concurrent success"
	add, remove := []string{first.ID}, []string(nil)
	if !adding {
		add, remove = nil, add
	}
	_, concurrentErr := e.svc.ChangeGroup(e.ctx, service.System, fresh, service.GroupInput{DisplayName: &renamed}, add, remove)
	gate.letResume()
	failedErr := <-done
	if concurrentErr != nil {
		t.Fatal(concurrentErr)
	}
	if failedErr == nil {
		t.Fatal("fault injection did not fail the first request")
	}
	_, err = e.svc.Members.Get(e.ctx, model.MemberID(group.ID, first.ID))
	if adding && err != nil {
		t.Fatalf("rollback erased membership explicitly retained by later successful update: %v", err)
	}
	if !adding && err == nil {
		t.Fatal("rollback restored membership explicitly revoked by later successful update")
	}
}
