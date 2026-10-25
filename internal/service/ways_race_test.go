package service_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Two removals at once, each of a different one of the account's two passkeys, cannot both succeed: each would
// leave the other as the last way in. One goes, the other is refused as the last way in.
func TestConcurrentRemovalsKeepALastWayIn(t *testing.T) {
	e := newEnv(t)
	for round := range 10 {
		u := e.user(e.primary.ID, fmt.Sprintf("two-keys-%d", round), model.RoleUser)
		var keys []*model.Passkey
		for _, name := range []string{"a", "b"} {
			p := &model.Passkey{UserID: u.ID, OrgID: u.OrgID, Name: name, Epoch: u.CredEpoch, UserVerified: true,
				CredentialID: []byte(fmt.Sprintf("%s-%d", name, round))}
			if err := e.svc.Passkeys.Create(e.ctx, p); err != nil {
				t.Fatal(err)
			}
			keys = append(keys, p)
		}
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i, p := range keys {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = e.svc.RemovePasskey(service.SelfService(e.ctx), actor(u), u.ID, p.ID, "")
			}()
		}
		wg.Wait()
		ok, refused := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, service.ErrConflict):
				refused++
			default:
				t.Fatalf("round %d: %v", round, err)
			}
		}
		left, err := e.svc.Passkeys.All(e.ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		if ok != 1 || refused != 1 || len(left) != 1 {
			t.Fatalf("round %d: %d removed, %d refused, %d passkeys left", round, ok, refused, len(left))
		}
	}
}
