package service_test

import (
	"strconv"
	"sync"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Two changes at once that together would make a loop (A reports to B, B reports to A) never both succeed: they
// hold the organization's managers lock in turn, and the second sees the first.
func TestConcurrentManagerChangesMakeNoLoop(t *testing.T) {
	e := newEnv(t)
	for round := range 20 {
		a := e.user(e.primary.ID, "a"+strconv.Itoa(round), model.RoleUser)
		b := e.user(e.primary.ID, "b"+strconv.Itoa(round), model.RoleUser)
		var wg sync.WaitGroup
		errs := make([]error, 2)
		set := func(i int, who, mgr *model.User) {
			defer wg.Done()
			_, errs[i] = e.svc.UpdateUser(e.ctx, service.System, who.ID, service.UserInput{Work: &service.WorkInput{ManagerID: &mgr.ID}})
		}
		wg.Add(2)
		go set(0, a, b)
		go set(1, b, a)
		wg.Wait()
		if errs[0] == nil && errs[1] == nil {
			t.Fatalf("round %d: both changes passed: a loop", round)
		}
		ga, _ := e.svc.Users.Get(e.ctx, a.ID)
		gb, _ := e.svc.Users.Get(e.ctx, b.ID)
		if ga.Work.ManagerID == b.ID && gb.Work.ManagerID == a.ID {
			t.Fatalf("round %d: a loop was stored", round)
		}
	}
}
