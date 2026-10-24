package service_test

import (
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func (e *env) gen(id string) uint64 {
	e.t.Helper()
	u, err := e.svc.Users.Get(e.ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return u.SecurityGen
}

// The security generation moves on with every credential change made through the service, and with nothing else.
func TestSecurityGenerationMoves(t *testing.T) {
	e := newEnv(t)
	org := e.org("acme")
	u := e.user(org.ID, "pat", model.RoleUser)
	gen := e.gen(u.ID)
	step := func(what string, moved bool, f func()) {
		t.Helper()
		f()
		got := e.gen(u.ID)
		switch {
		case moved && got != gen+1:
			t.Errorf("%s: generation %d, want %d", what, got, gen+1)
		case !moved && got != gen:
			t.Errorf("%s: generation moved %d -> %d", what, gen, got)
		}
		gen = got
	}
	update := func(in service.UserInput) func() {
		return func() {
			if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, in); err != nil {
				t.Fatal(err)
			}
		}
	}
	step("profile edit", false, update(service.UserInput{GivenName: ptr("Patricia")}))
	step("role", false, update(service.UserInput{Role: ptr(model.RoleManager)}))
	step("end date", false, update(service.UserInput{ValidUntil: ptr("2099-01-01")}))
	step("password set", true, update(service.UserInput{Password: ptr("a first password 123")}))
	step("password changed", true, update(service.UserInput{Password: ptr("a second password 456")}))
	step("disabled", true, update(service.UserInput{Active: ptr(false)}))
	step("enabled again", true, update(service.UserInput{Active: ptr(true)}))
	step("passkey or provider (AdvanceSecurity)", true, func() {
		if _, err := e.svc.AdvanceSecurity(e.ctx, u.ID); err != nil {
			t.Fatal(err)
		}
	})
	step("recovery codes made", true, func() {
		cur, _ := e.svc.Users.Get(e.ctx, u.ID)
		cur.TOTPSecret = e.svc.Sealer.SealFor(service.TOTPBinding(u.ID), []byte("secret"))
		if err := e.svc.Users.Update(e.ctx, cur); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.CreateRecoveryCodes(e.ctx, service.System, cur); err != nil {
			t.Fatal(err)
		}
	})
	step("password removed", true, func() {
		if err := e.svc.RemovePassword(e.ctx, actor(e.super), u.ID); err != nil {
			t.Fatal(err)
		}
	})
	step("credentials reset", true, func() {
		if err := e.svc.ResetCredentials(e.ctx, u.ID, ""); err != nil {
			t.Fatal(err)
		}
	})
}

// Invitation and reset links are bound to the generation they were issued under; a verification link is not (it
// proves an address, and checks that the address is still on the account).
func TestLinksBoundToSecurityGeneration(t *testing.T) {
	e := newEnv(t)
	org := e.org("acme")
	u := e.user(org.ID, "pat", model.RoleUser)
	if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Password: ptr("a first password 123")}); err != nil {
		t.Fatal(err)
	}
	u, _ = e.svc.Users.Get(e.ctx, u.ID)
	reset, _, err := e.svc.IssueLink(e.ctx, u, service.LinkReset, u.Email, service.ResetTTL)
	if err != nil {
		t.Fatal(err)
	}
	verify, err := e.svc.IssueEmailLink(e.ctx, u, u.Email)
	if err != nil {
		t.Fatal(err)
	}
	invite, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{reset, verify, tokenFrom(invite)} {
		if _, _, err := e.svc.PeekLink(e.ctx, tok, service.LinkReset, service.LinkVerify, service.LinkInvite); err != nil {
			t.Fatalf("fresh link: %v", err)
		}
	}
	if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Password: ptr("a second password 456")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, reset, service.LinkReset); !errors.Is(err, service.ErrLink) {
		t.Errorf("reset link after a password change: %v", err)
	}
	if _, _, err := e.svc.UseSignInLink(e.ctx, tokenFrom(invite), service.LinkInvite, ""); !errors.Is(err, service.ErrLink) {
		t.Errorf("invitation after a password change: %v", err)
	}
	if _, _, err := e.svc.RedeemLink(e.ctx, verify); err != nil {
		t.Errorf("verification link after a password change: %v", err)
	}
	// a link issued now (for the user as it is now) is good until the next change
	u, _ = e.svc.Users.Get(e.ctx, u.ID)
	reset, _, err = e.svc.IssueLink(e.ctx, u, service.LinkReset, u.Email, service.ResetTTL)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, reset, service.LinkReset); err != nil {
		t.Fatalf("new reset link: %v", err)
	}
	if _, err := e.svc.AdvanceSecurity(e.ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, reset, service.LinkReset); !errors.Is(err, service.ErrLink) {
		t.Errorf("reset link after a passkey change: %v", err)
	}
}
