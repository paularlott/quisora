package service_test

import (
	"strings"
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

// The same guard covers making a verified linked address the primary one (MakePrimary): resets go to the primary
// address, so an administrator who could set an established manager's would take the account over; the manager's own
// linked address stays their own change.
func TestMakePrimaryOfPrivilegedIsASignInReset(t *testing.T) {
	c := newCast(t)
	pw := "correct horse battery staple 9"
	if _, err := c.svc.UpdateUser(c.ctx, service.System, c.aManager.ID, service.UserInput{Password: &pw}); err != nil {
		t.Fatal(err)
	}
	addr, other := "linked@acme.example", "other@acme.example"
	for _, a := range []string{addr, other} {
		if _, err := c.svc.AddLinkedEmail(c.ctx, service.System, c.aManager.ID, a, true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.svc.MakePrimary(c.ctx, actor(c.aAdmin), c.aManager.ID, addr); err == nil {
		t.Fatal("an admin made an established manager's linked address primary")
	}
	self := service.SelfService(c.ctx)
	u, err := c.svc.MakePrimary(self, actor(c.aManager), c.aManager.ID, addr)
	if err != nil || !strings.EqualFold(u.Email, addr) {
		t.Fatalf("the manager's own: %v %s", err, u.Email)
	}
	u, err = c.svc.MakePrimary(c.ctx, actor(c.super), c.aManager.ID, other)
	if err != nil {
		t.Fatalf("a super admin: %v", err)
	}
	if !strings.EqualFold(u.Email, other) {
		t.Fatalf("a super admin: email is %s", u.Email)
	}
}
