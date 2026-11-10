package service_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Only a super admin resets the sign-in of a manager or administrator that has one: an administrator cannot issue a
// peer an invitation (which replaces every way they sign in), remove their password, or lower their role (and so
// cannot demote, invite and promote again either). The first invitation of an account that never had a way to sign
// in is anyone's who may manage it; a plain user's sign-in is reset by their administrators as before.
func TestPrivilegedSignInResetIsSuperAdminOnly(t *testing.T) {
	e := newEnv(t)
	org := e.org("acme")
	admin := e.user(org.ID, "ada", model.RoleAdmin)
	withPassword := func(name string, role model.Role) *model.User {
		u := e.user(org.ID, name, role)
		u, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Password: ptr("correct horse battery staple")})
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	peer := withPassword("bob", model.RoleAdmin)
	mgr := withPassword("mia", model.RoleManager)
	plain := withPassword("pat", model.RoleUser)
	refused := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, service.ErrInvalid) || !strings.Contains(err.Error(), "super admin") {
			t.Errorf("%s: %v", what, err)
		}
	}
	a := actor(admin)

	for _, u := range []*model.User{peer, mgr} {
		_, _, err := e.svc.CreateInvite(e.ctx, a, u.ID)
		refused("invite "+u.Username, err)
		refused("remove password of "+u.Username, e.svc.RemovePassword(e.ctx, a, u.ID))
	}
	_, err := e.svc.UpdateUser(e.ctx, a, peer.ID, service.UserInput{Role: ptr(model.RoleUser)})
	refused("demote a peer admin", err)
	_, err = e.svc.UpdateUser(e.ctx, a, mgr.ID, service.UserInput{Role: ptr(model.RoleUser)})
	refused("demote a manager", err)
	if _, err := e.svc.UpdateUser(e.ctx, a, plain.ID, service.UserInput{Role: ptr(model.RoleManager)}); err != nil {
		t.Errorf("promote a user: %v", err) // raising a role stays the administrators'
	}
	if e.svc.CanResetSignIn(e.ctx, a, peer) {
		t.Error("CanResetSignIn for a peer admin")
	}

	// plain users: as before
	other := withPassword("sam", model.RoleUser)
	if _, _, err := e.svc.CreateInvite(e.ctx, a, other.ID); err != nil {
		t.Errorf("invite a plain user: %v", err)
	}
	// a new manager who never had a way to sign in: the first invitation is the administrator's
	fresh := e.user(org.ID, "neo", model.RoleManager)
	if _, _, err := e.svc.CreateInvite(e.ctx, a, fresh.ID); err != nil || !e.svc.CanResetSignIn(e.ctx, a, fresh) {
		t.Errorf("first invitation of a new manager: %v", err)
	}
	// ...but not once they have signed in, whatever is left of their sign-in methods
	e.svc.TouchLogin(e.ctx, fresh)
	_, _, err = e.svc.CreateInvite(e.ctx, a, fresh.ID)
	refused("invite a manager who has signed in", err)
	// a manager signing in only through a provider has a way in too
	viaSSO := e.user(org.ID, "sso", model.RoleManager)
	p, err := e.svc.CreateProvider(e.ctx, service.System, org.ID, service.ProviderInput{Type: ptr(model.ProviderOIDC),
		Name: ptr("SSO"), Issuer: ptr("https://sso.example.com"), ClientID: ptr("c"), ClientSecret: ptr("s")})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Identities.Create(e.ctx, model.NewIdentity(viaSSO, p, "sub-1", "", "admin")); err != nil {
		t.Fatal(err)
	}
	_, _, err = e.svc.CreateInvite(e.ctx, a, viaSSO.ID)
	refused("invite a manager who signs in through a provider", err)

	// a provisioning service account cannot lower a manager's role either
	cl, _, err := e.svc.CreateServiceAccount(e.ctx, service.System, org.ID, service.ServiceAccountInput{Name: ptr("dir"), Scopes: ptr([]string{"scim"})})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.UpdateUser(e.ctx, service.ActorForServiceAccount(cl, cl.Scopes, ""), mgr.ID, service.UserInput{Role: ptr(model.RoleUser)})
	refused("a provisioning client demoting a manager", err)

	// a super admin can do all of it
	s := actor(e.super)
	if _, _, err := e.svc.CreateInvite(e.ctx, s, peer.ID); err != nil {
		t.Errorf("super admin invites an admin: %v", err)
	}
	if err := e.svc.RemovePassword(e.ctx, s, mgr.ID); err != nil {
		t.Errorf("super admin removes a manager's password: %v", err)
	}
	if _, err := e.svc.UpdateUser(e.ctx, s, mgr.ID, service.UserInput{Role: ptr(model.RoleUser)}); err != nil {
		t.Errorf("super admin demotes a manager: %v", err)
	}
}

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

// An established manager or administrator's addresses and invitations are a super admin's to change: an administrator
// may not link a verified address, which links provider sign-ins to the account and so resets the sign-in, nor an
// unverified one, whose verification link goes to the address added (so to whoever added it, if it is theirs).
func TestEstablishedManagerAddressesAreSuperAdminOnly(t *testing.T) {
	c := newCast(t)
	c.establish(c.aManager)
	c.establish(c.aAdmin)
	admin := actor(c.aAdmin)
	if _, err := c.svc.AddLinkedEmail(c.ctx, admin, c.aManager.ID, "m1@example.com", false); !isInvalid(err) {
		t.Fatalf("admin adding an unverified address to a manager: %v", err)
	}
	if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.super), c.aManager.ID, "m1@example.com", false); err != nil {
		t.Fatalf("super admin adding an unverified address: %v", err)
	}
	// Each of the ways to link a verified address is refused, and no upstream sign-in matches it afterwards.
	attacker := "attacker@controlled.example"
	if _, err := c.svc.AddLinkedEmail(c.ctx, admin, c.aManager.ID, attacker, true); !isInvalid(err) {
		t.Errorf("admin adding a verified address to a manager: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, admin, c.aManager.ID, service.UserInput{LinkedEmails: &[]string{attacker}}); !isInvalid(err) {
		t.Errorf("admin replacing a manager's linked addresses: %v", err)
	}
	if _, err := c.svc.MarkEmailVerified(c.ctx, admin, c.aManager.ID, "m1@example.com"); !isInvalid(err) {
		t.Errorf("admin verifying a manager's address: %v", err)
	}
	if matched, err := c.svc.UsersByVerifiedEmail(c.ctx, c.a.ID, []string{attacker, "m1@example.com"}); err != nil || len(matched) != 0 {
		t.Fatalf("a refused change left a verified address: %v %v", matched, err)
	}
	if got := c.fresh(c.aManager); got.PasswordHash == "" || len(got.LinkedEmails) != 1 {
		t.Error("manager changed")
	}
	// the super admin may, once
	if _, err := c.svc.MarkEmailVerified(c.ctx, actor(c.super), c.aManager.ID, "m1@example.com"); err != nil {
		t.Errorf("super verifying: %v", err)
	}
	if _, err := c.svc.MarkEmailVerified(c.ctx, actor(c.super), c.aManager.ID, "m1@example.com"); !errors.Is(err, service.ErrConflict) {
		t.Errorf("already verified: %v", err)
	}
	if _, err := c.svc.MarkEmailVerified(c.ctx, actor(c.aManager), c.aManager.ID, "m1@example.com"); !isInvalid(err) {
		t.Errorf("manager verifying own address: %v", err)
	}
	// an invitation a super admin issued is not replaced by an admin, and nobody invites themselves
	if _, _, err := c.svc.CreateInvite(c.ctx, actor(c.super), c.aManager.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.svc.CreateInvite(c.ctx, admin, c.aManager.ID); !isInvalid(err) {
		t.Errorf("admin replacing a super admin's invite: %v", err)
	}
	if _, _, err := c.svc.CreateInvite(c.ctx, actor(c.super), c.super.ID); !isInvalid(err) {
		t.Errorf("inviting yourself: %v", err)
	}
	// a fresh privileged account that has never signed in gets its first invitation from whoever manages it, and
	// then another administrator may not replace it
	n := c.next("fresh")
	fresh, err := c.svc.CreateUser(c.ctx, admin, c.a.ID, service.UserInput{Username: &n, GivenName: ptr("F"), Email: ptr(n + "@example.com"), Role: ptr(model.RoleManager)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.svc.CreateInvite(c.ctx, admin, fresh.ID); err != nil {
		t.Errorf("first invite of a new manager: %v", err)
	}
	peer := c.user(c.a.ID, c.next("padm"), model.RoleAdmin)
	if _, _, err := c.svc.CreateInvite(c.ctx, actor(peer), fresh.ID); !isInvalid(err) {
		t.Errorf("another admin replacing a live invitation: %v", err)
	}
}
