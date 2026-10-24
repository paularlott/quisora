package service_test

import (
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Cleanup belongs to the epoch it replaced; a later acceptance can commit while
// its session enumeration is slow, and must retain its own new credentials.
func TestFresh3OlderInviteCleanupPreservesLaterEpochCredentials(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "epoch-cleanup", model.RoleUser)
	first, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	gate := &reviewInviteCleanupGate{Store: e.svc.Store, id: u.ID, entered: make(chan struct{}), resume: make(chan struct{})}
	e.svc.Store = gate
	t.Cleanup(func() {
		select {
		case <-gate.resume:
		default:
			close(gate.resume)
		}
	})
	done := make(chan error, 1)
	go func() {
		_, _, err := e.svc.UseSignInLink(e.ctx, tokenFrom(first), service.LinkInvite, "", service.NewCredEpoch())
		done <- err
	}()
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first acceptance did not reach cleanup")
	}
	second, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	epoch := service.NewCredEpoch()
	pk := &model.Passkey{Meta: model.Meta{ID: model.NewID()}, UserID: u.ID, OrgID: u.OrgID, Epoch: epoch, Name: "second acceptance", CredentialID: []byte("fresh3-credential")}
	if err := e.svc.Passkeys.Create(e.ctx, pk); err != nil {
		t.Fatal(err)
	}
	_, current, err := e.svc.UseSignInLink(e.ctx, tokenFrom(second), service.LinkInvite, "", epoch)
	if err != nil {
		t.Fatal(err)
	}
	if !current.Holds(epoch) {
		t.Fatal("second acceptance did not commit its epoch")
	}
	if _, err := e.svc.Passkeys.Get(e.ctx, pk.ID); err != nil {
		t.Fatalf("credential absent before old cleanup: %v", err)
	}
	close(gate.resume)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Passkeys.Get(e.ctx, pk.ID); err != nil {
		t.Fatalf("cleanup from earlier accepted invitation removed the current epoch's credential: %v", err)
	}
}
