package service_test

import (
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// A token that stopped working when its owner's sign-in was reset cannot be given a new secret or new settings
// (they would never work): its owner deletes it and makes a new one.
func TestStaleTokenCannotBeRegeneratedOrUpdated(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "tok", model.RoleUser)
	a := service.ActorForUser(u, "")
	tok, _, err := e.svc.CreateAPIToken(e.ctx, a, service.APITokenInput{Name: "t", Scopes: []string{service.ScopeAPI}})
	if err != nil {
		t.Fatal(err)
	}
	fresh, _ := e.svc.Users.Get(e.ctx, u.ID)
	fresh.SetCredEpoch(service.NewCredEpoch()) // the sign-in was reset
	if err := e.svc.Users.Update(e.ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.RegenerateAPIToken(e.ctx, a, tok.ID); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("regenerate: %v", err)
	}
	name := "renamed"
	if _, err := e.svc.UpdateAPIToken(e.ctx, a, tok.ID, service.APITokenUpdate{Name: &name}); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("update: %v", err)
	}
}
