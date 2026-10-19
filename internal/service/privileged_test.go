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

	// a provisioning client cannot lower a manager's role either
	cl, _, err := e.svc.CreateClient(e.ctx, service.System, org.ID, service.ClientInput{Name: ptr("dir"), GrantTypes: ptr([]string{"client_credentials"})})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.UpdateUser(e.ctx, service.ActorForClient(cl, ""), mgr.ID, service.UserInput{Role: ptr(model.RoleUser)})
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
