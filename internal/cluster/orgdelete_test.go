package cluster

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// A user's creation on one node and its organization's deletion (not cascading) on another, racing, never both succeed:
// the organization record is in the global partition and its users in its own, and the deletion guard in the
// organization's partition (service.DeleteOrg) keeps them apart in a cluster as in a single store.
func TestDeleteOrgAndCreateUserOnTwoNodes(t *testing.T) {
	c := started(t, badgerBackend())
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svcs := make([]*service.Service, 2)
	for i := range svcs {
		cfg := config.Default()
		cfg.Limits.PasswordWorkers = 1
		svcs[i] = service.New(cfg, c.nodes[i].st(), sealer)
	}
	if _, _, err := svcs[0].Bootstrap(bg, "root@example.com"); err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		name := "race-" + string(rune('a'+i))
		org, err := svcs[0].CreateOrg(bg, service.System, service.OrgInput{Name: &name})
		if err != nil {
			t.Fatal(err)
		}
		waitFor(t, 10*time.Second, "the organization on the creating node", func() bool {
			_, err := svcs[1].Orgs.Get(bg, org.ID)
			return err == nil
		})
		var wg sync.WaitGroup
		var created *model.User
		var createErr, delErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			user, email := "u", "u@example.com"
			created, createErr = svcs[1].CreateUser(bg, service.System, org.ID, service.UserInput{Username: &user,
				GivenName: &user, Email: &email})
		}()
		go func() {
			defer wg.Done()
			delErr = svcs[0].DeleteOrg(bg, service.System, org.ID, false)
		}()
		wg.Wait()
		if createErr == nil && delErr == nil {
			t.Fatalf("round %d: both the creation of user %s and the deletion of its organization succeeded", i, created.ID)
		}
		if createErr == nil {
			waitFor(t, 10*time.Second, "the user on the deleting node", func() bool {
				_, err := svcs[0].Users.Get(bg, created.ID)
				return err == nil
			})
			if _, err := svcs[0].Orgs.Get(bg, org.ID); err != nil {
				t.Fatalf("round %d: the user was created and its organization is gone: %v", i, err)
			}
		}
		if delErr == nil {
			if _, err := svcs[0].Orgs.Get(bg, org.ID); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("round %d: the deletion succeeded and the organization is still there: %v", i, err)
			}
		}
		t.Logf("round %d: create %v, delete %v", i, createErr, delErr)
	}
}
