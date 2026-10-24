package service_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

type deepManagerClearGate struct {
	store.Store
	reportID        string
	armed           atomic.Bool
	entered, resume chan struct{}
}

func (g *deepManagerClearGate) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindUser && r.ID == g.reportID && g.armed.CompareAndSwap(true, false) {
		close(g.entered)
		<-g.resume
	}
	return g.Store.CompareAndPut(ctx, r, expect)
}

func TestDeepReviewDeleteManagerPreservesConcurrentReassignment(t *testing.T) {
	e := newEnv(t)
	org := e.org("manager-race")
	oldManager := e.user(org.ID, "oldmanager", model.RoleUser)
	newManager := e.user(org.ID, "newmanager", model.RoleUser)
	report := e.user(org.ID, "report", model.RoleUser)
	if _, err := e.svc.UpdateUser(e.ctx, service.System, report.ID, service.UserInput{Work: &service.WorkInput{ManagerID: &oldManager.ID}}); err != nil {
		t.Fatal(err)
	}
	rawUsers := store.NewTable[model.User](e.svc.Store)
	gate := &deepManagerClearGate{Store: e.svc.Users.S, reportID: report.ID, entered: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Users.S = gate
	gate.armed.Store(true)
	done := make(chan error, 1)
	go func() { done <- e.svc.DeleteUser(e.ctx, service.System, oldManager.ID) }()
	<-gate.entered
	fresh, err := rawUsers.Get(e.ctx, report.ID)
	if err != nil {
		close(gate.resume)
		<-done
		t.Fatal(err)
	}
	fresh.Work.ManagerID = newManager.ID
	err = rawUsers.Update(e.ctx, fresh)
	close(gate.resume)
	deletionErr := <-done
	if err != nil {
		t.Fatal(err)
	}
	if deletionErr != nil {
		t.Fatal(deletionErr)
	}
	final, err := rawUsers.Get(e.ctx, report.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Work.ManagerID != newManager.ID {
		t.Fatalf("deleting former manager erased concurrent reassignment: got manager %q", final.Work.ManagerID)
	}
}
