package service_test

import (
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Old-epoch records may remain after best-effort cleanup. They are not another
// way to sign in and must not permit removal of the last current credential.
func TestFresh4LastPasskeyGuardIgnoresPassedEpoch(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "epoch-last-passkey", model.RoleUser)
	u.CredEpoch = service.NewCredEpoch()
	if err := e.svc.Users.Update(e.ctx, u); err != nil {
		t.Fatal(err)
	}
	makeKey := func(name string, epoch uint64) *model.Passkey {
		p := &model.Passkey{UserID: u.ID, OrgID: u.OrgID, Name: name, Epoch: epoch, UserVerified: true, CredentialID: []byte(name)}
		if err := e.svc.Passkeys.Create(e.ctx, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	current := makeKey("current", u.CredEpoch)
	makeKey("superseded", 0)
	_, err := e.svc.RemovePasskey(service.SelfService(e.ctx), actor(u), u.ID, current.ID, "")
	if err == nil {
		remaining, readErr := e.svc.Passkeys.All(e.ctx, u.ID)
		if readErr != nil {
			t.Fatal(readErr)
		}
		usable := 0
		for _, p := range remaining {
			if u.Holds(p.Epoch) && p.Usable() {
				usable++
			}
		}
		t.Fatalf("self-service removed the last usable passkey because a passed-epoch record counted as an alternative: usable credentials remaining=%d", usable)
	}
	if !errors.Is(err, service.ErrConflict) {
		t.Fatalf("expected last-credential conflict, got %v", err)
	}
}
