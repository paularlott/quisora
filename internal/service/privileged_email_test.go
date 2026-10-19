package service_test

import (
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// Password resets go to the primary address, so an administrator who could set a peer's would take the peer's account
// over through "forgot password": for an established manager or administrator it is a super admin's change, as an
// invitation is; a plain user's stays an ordinary change, and so does a privileged account's own linked address.
func TestPrivilegedEmailChangeIsASignInReset(t *testing.T) {
	c := newCast(t)
	pw := "correct horse battery staple 9"
	for _, u := range []string{c.aManager.ID, c.aUser.ID} {
		if _, err := c.svc.UpdateUser(c.ctx, service.System, u, service.UserInput{Password: &pw}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.aAdmin), c.aManager.ID, service.UserInput{Email: ptr("mine@evil.example")}); err == nil {
		t.Fatal("an admin set an established manager's primary address")
	}
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.super), c.aManager.ID, service.UserInput{Email: ptr("new@acme.example")}); err != nil {
		t.Fatalf("a super admin: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.aAdmin), c.aUser.ID, service.UserInput{Email: ptr("other@acme.example")}); err != nil {
		t.Fatalf("a plain user's address: %v", err)
	}
}
