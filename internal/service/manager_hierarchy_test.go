package service_test

import (
	"testing"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// Deleting a manager clears the manager of their reports, but not a manager a concurrent change has given one of them
// since.
func TestDeletingAManagerKeepsAConcurrentReassignment(t *testing.T) {
	e := newEnv(t)
	org := e.org("manager-race")
	oldManager := e.user(org.ID, "oldmanager", model.RoleUser)
	newManager := e.user(org.ID, "newmanager", model.RoleUser)
	report := e.user(org.ID, "report", model.RoleUser)
	if _, err := e.svc.UpdateUser(e.ctx, service.System, report.ID, service.UserInput{Work: &service.WorkInput{ManagerID: &oldManager.ID}}); err != nil {
		t.Fatal(err)
	}
	rawUsers := store.NewTable[model.User](e.svc.Store)
	gt := newGate(t)
	e.svc.Users.S = &faultStore{Store: e.svc.Users.S, beforeCAS: func(r *store.Record, _ hlc.Timestamp) error {
		if r.Kind == model.KindUser && r.ID == report.ID {
			gt.stall()
		}
		return nil
	}}
	done := make(chan error, 1)
	go func() { done <- e.svc.DeleteUser(e.ctx, service.System, oldManager.ID) }()
	gt.waitEntered(t, "the deletion's write of the report")
	fresh, err := rawUsers.Get(e.ctx, report.ID)
	if err != nil {
		t.Fatal(err)
	}
	fresh.Work.ManagerID = newManager.ID
	err = rawUsers.Update(e.ctx, fresh)
	gt.release()
	if deletionErr := <-done; deletionErr != nil {
		t.Fatal(deletionErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	final, err := rawUsers.Get(e.ctx, report.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Work.ManagerID != newManager.ID {
		t.Fatalf("deleting the former manager erased a concurrent reassignment: manager is %q", final.Work.ManagerID)
	}
}
