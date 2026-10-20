package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func TestLinkedEmailAdminAdds(t *testing.T) {
	c := newCast(t)
	u, err := c.svc.AddLinkedEmail(c.ctx, actor(c.aAdmin), c.aUser.ID, "Alt@Example.org", true)
	if err != nil || len(u.LinkedEmails) != 1 || !u.LinkedEmails[0].Verified || u.LinkedEmails[0].Address != "Alt@Example.org" {
		t.Fatalf("admin add, verified: %v %+v", err, u.LinkedEmails)
	}
	// with email set up the caller asks for an unverified address (and mails the user a link)
	if u, err = c.svc.AddLinkedEmail(c.ctx, actor(c.aAdmin), c.aUser.ID, "pending@example.org", false); err != nil || u.LinkedEmails[1].Verified {
		t.Fatalf("admin add, unverified: %v %+v", err, u.LinkedEmails)
	}
	// the address is in the org's email namespace and finds the user, but never signs in with a password
	got, err := c.svc.Users.GetByUnique(c.ctx, model.UserEmailKey(c.a.ID, "alt@example.org"))
	if err != nil || got.ID != c.aUser.ID {
		t.Fatalf("lookup by linked address: %v", err)
	}
	if _, err := c.svc.FindUserByEmail(c.ctx, c.a.ID, "alt@example.org"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("password sign-in must stay primary-email only: %v", err)
	}
	if _, err := c.svc.FindUserByEmail(c.ctx, c.a.ID, c.aUser.Email); err != nil {
		t.Fatal(err)
	}
	// the same address in another org is a different namespace
	if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.bAdmin), c.bAdmin.ID+"", "alt@example.org", true); err == nil {
		t.Fatal("an admin must not act through their own id without self-service")
	}
	if _, err := c.svc.AddLinkedEmail(c.ctx, service.System, c.bAdmin.ID, "alt@example.org", true); err != nil {
		t.Fatalf("another org may use the same address: %v", err)
	}
}

func TestLinkedEmailUniquenessAndLimit(t *testing.T) {
	c := newCast(t)
	adm := actor(c.aAdmin)
	if _, err := c.svc.AddLinkedEmail(c.ctx, adm, c.aUser.ID, "x@example.org", true); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ user, addr string }{
		"same user again":       {c.aUser.ID, "X@example.org"},
		"other user's linked":   {c.aManager.ID, "x@example.org"},
		"other user's primary":  {c.aManager.ID, c.aUser.Email},
		"own primary":           {c.aUser.ID, c.aUser.Email},
		"primary of other case": {c.aManager.ID, strings.ToUpper(c.aUser.Email)},
	} {
		_, err := c.svc.AddLinkedEmail(c.ctx, adm, tc.user, tc.addr, true)
		if !errors.Is(err, service.ErrConflict) {
			t.Errorf("%s: want conflict, got %v", name, err)
		}
	}
	// a primary address cannot be changed to someone's linked address either
	if _, err := c.svc.UpdateUser(c.ctx, adm, c.aManager.ID, service.UserInput{Email: ptr("x@example.org")}); !errors.Is(err, service.ErrConflict) {
		t.Errorf("primary onto a linked address: %v", err)
	}
	for _, bad := range []string{"", "nope", "Name <a@b.com>"} {
		if _, err := c.svc.AddLinkedEmail(c.ctx, adm, c.aUser.ID, bad, true); !errors.Is(err, service.ErrInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	for i := 1; i < model.MaxLinkedEmails; i++ {
		if _, err := c.svc.AddLinkedEmail(c.ctx, adm, c.aUser.ID, "n"+itoa(i)+"@example.org", true); err != nil {
			t.Fatalf("address %d: %v", i, err)
		}
	}
	if _, err := c.svc.AddLinkedEmail(c.ctx, adm, c.aUser.ID, "one-too-many@example.org", true); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("limit: %v", err)
	}
}

func TestLinkedEmailRBAC(t *testing.T) {
	c := newCast(t)
	self := service.SelfService(c.ctx)
	user := actor(c.aUser)
	// users below manager never add, remove or change their own addresses, account page or not
	for _, ctx := range []context.Context{c.ctx, self} {
		if _, err := c.svc.AddLinkedEmail(ctx, user, c.aUser.ID, "me@example.org", false); !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("user adds own address: %v", err)
		}
	}
	if _, err := c.svc.UpdateUser(self, user, c.aUser.ID, service.UserInput{Email: ptr("me@example.org")}); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("user changes own primary address: %v", err)
	}
	if _, err := c.svc.UpdateUser(self, user, c.aUser.ID, service.UserInput{Email: ptr(c.aUser.Email)}); err != nil {
		t.Fatalf("saving the profile with the same address: %v", err)
	}
	if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.aManager), c.aUser.ID, "me@example.org", true); err != nil {
		t.Fatalf("manager adds a user's address: %v", err)
	}
	if _, err := c.svc.RemoveLinkedEmail(self, user, c.aUser.ID, "me@example.org"); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("user removes own address: %v", err)
	}
	// other users cannot touch it; admins of other orgs do not even learn it exists
	if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.pUser), c.aUser.ID, "z@example.org", true); err == nil {
		t.Error("a plain user changed someone else's addresses")
	}
	if _, err := c.svc.RemoveLinkedEmail(c.ctx, actor(c.bAdmin), c.aUser.ID, "me@example.org"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("other org's admin: %v", err)
	}
	if _, err := c.svc.RemoveLinkedEmail(c.ctx, actor(c.aManager), c.aAdmin.ID, "x@example.org"); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("manager on admin: %v", err)
	}
	// a manager may manage a plain user's addresses
	if _, err := c.svc.RemoveLinkedEmail(c.ctx, actor(c.aManager), c.aUser.ID, "me@example.org"); err != nil {
		t.Errorf("manager on user: %v", err)
	}
	// managers and up add their own, self-service only (the caller re-authenticated), and always unverified
	if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.aAdmin), c.aAdmin.ID, "adm@example.org", true); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("admin adds own address without self-service: %v", err)
	}
	if u, err := c.svc.AddLinkedEmail(self, actor(c.aAdmin), c.aAdmin.ID, "adm@example.org", true); err != nil || u.LinkedEmails[0].Verified {
		t.Errorf("admin adds own address: %v", err)
	}
	// nobody edits their own primary address directly (add one, verify it, make it primary)
	for _, ctx := range []context.Context{c.ctx, self} {
		if _, err := c.svc.UpdateUser(ctx, actor(c.aManager), c.aManager.ID, service.UserInput{Email: ptr("mgr-new@example.org")}); !errors.Is(err, service.ErrInvalid) {
			t.Errorf("manager changes own primary address: %v", err)
		}
	}
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.aAdmin), c.aManager.ID, service.UserInput{Email: ptr("mgr-new@example.org")}); err != nil {
		t.Errorf("admin changes a manager's primary address: %v", err)
	}
	// SCIM-style replacement is for others only
	if _, err := c.svc.UpdateUser(self, user, c.aUser.ID, service.UserInput{LinkedEmails: &[]string{"q@example.org"}}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("own linked set replace: %v", err)
	}
}

func TestLinkedEmailVerifyAndPrimary(t *testing.T) {
	c := newCast(t)
	self := service.SelfService(c.ctx)
	user := actor(c.aUser)
	if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.aManager), c.aUser.ID, "gh@example.org", false); err != nil {
		t.Fatal(err)
	}
	// an unverified address cannot become primary
	if _, err := c.svc.MakePrimary(self, user, c.aUser.ID, "gh@example.org"); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("make primary unverified: %v", err)
	}
	// the verification link is bound to the address
	u, _ := c.svc.Users.Get(c.ctx, c.aUser.ID)
	tok, err := c.svc.IssueEmailLink(c.ctx, u, "gh@example.org")
	if err != nil {
		t.Fatal(err)
	}
	l, lu, err := c.svc.RedeemLink(c.ctx, tok, service.LinkVerify)
	if err != nil || l.Email != "gh@example.org" {
		t.Fatalf("redeem: %v %+v", err, l)
	}
	if err := c.svc.VerifyEmailAddress(c.ctx, lu.ID, l.Email); err != nil {
		t.Fatal(err)
	}
	u, _ = c.svc.Users.Get(c.ctx, c.aUser.ID)
	if !u.LinkedEmails[0].Verified {
		t.Fatal("not verified")
	}
	if _, err := c.svc.IssueEmailLink(c.ctx, u, "gh@example.org"); !errors.Is(err, service.ErrConflict) {
		t.Fatalf("verifying a verified address: %v", err)
	}
	if _, err := c.svc.IssueEmailLink(c.ctx, u, "other@example.org"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("link for a foreign address: %v", err)
	}
	// a link for an address that is removed afterwards verifies nothing
	if err := c.svc.VerifyEmailAddress(c.ctx, u.ID, "gone@example.org"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("verify unknown address: %v", err)
	}

	oldPrimary := u.Email
	if _, err := c.svc.MakePrimary(c.ctx, user, c.aUser.ID, "gh@example.org"); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("make primary without self-service: %v", err)
	}
	u, err = c.svc.MakePrimary(self, user, c.aUser.ID, "gh@example.org")
	if err != nil || u.Email != "gh@example.org" || !u.EmailVerified || len(u.LinkedEmails) != 1 || u.LinkedEmails[0].Address != oldPrimary {
		t.Fatalf("make primary: %v %+v", err, u)
	}
	// password sign-in follows the new primary
	if _, err := c.svc.FindUserByEmail(c.ctx, c.a.ID, oldPrimary); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("old primary still signs in: %v", err)
	}
	if _, err := c.svc.FindUserByEmail(c.ctx, c.a.ID, "gh@example.org"); err != nil {
		t.Fatal(err)
	}
	// the primary cannot be removed; unlinking the old one works (a manager's job)
	mgr := actor(c.aManager)
	if _, err := c.svc.RemoveLinkedEmail(c.ctx, mgr, c.aUser.ID, "gh@example.org"); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("remove primary: %v", err)
	}
	if _, err := c.svc.RemoveLinkedEmail(c.ctx, mgr, c.aUser.ID, "nothere@example.org"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("remove unknown: %v", err)
	}
	if u, err = c.svc.RemoveLinkedEmail(c.ctx, mgr, c.aUser.ID, oldPrimary); err != nil || len(u.LinkedEmails) != 0 {
		t.Fatalf("remove: %v %+v", err, u)
	}
	// the freed address can be used by someone else
	if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.aAdmin), c.aManager.ID, oldPrimary, true); err != nil {
		t.Fatalf("freed address: %v", err)
	}
}

func TestLinkedEmailsReplaceAndPromote(t *testing.T) {
	c := newCast(t)
	adm := actor(c.aAdmin)
	set := []string{"a1@example.org", "a2@example.org", "A1@example.org", c.aUser.Email}
	u, err := c.svc.UpdateUser(c.ctx, adm, c.aUser.ID, service.UserInput{LinkedEmails: &set})
	if err != nil || len(u.LinkedEmails) != 2 || !u.LinkedEmails[0].Verified {
		t.Fatalf("replace: %v %+v", err, u.LinkedEmails)
	}
	// promoting a linked address by editing the primary drops it from the linked list
	u, err = c.svc.UpdateUser(c.ctx, adm, c.aUser.ID, service.UserInput{Email: ptr("a2@example.org")})
	if err != nil || u.Email != "a2@example.org" || len(u.LinkedEmails) != 1 || u.LinkedEmails[0].Address != "a1@example.org" {
		t.Fatalf("promote: %v %+v", err, u)
	}
	empty := []string{}
	if u, err = c.svc.UpdateUser(c.ctx, adm, c.aUser.ID, service.UserInput{LinkedEmails: &empty}); err != nil || len(u.LinkedEmails) != 0 {
		t.Fatalf("clear: %v %+v", err, u)
	}
	// a clash with another user is a conflict on email
	taken := []string{c.aManager.Email}
	if _, err := c.svc.UpdateUser(c.ctx, adm, c.aUser.ID, service.UserInput{LinkedEmails: &taken}); !errors.Is(err, service.ErrConflict) {
		t.Fatalf("clash: %v", err)
	}
}

func TestUsersByVerifiedEmail(t *testing.T) {
	c := newCast(t)
	adm := actor(c.aAdmin)
	c.svc.AddLinkedEmail(c.ctx, adm, c.aUser.ID, "lnk@example.org", true)
	c.svc.AddLinkedEmail(c.ctx, service.System, c.aManager.ID, "unv@example.org", false)
	users, err := c.svc.UsersByVerifiedEmail(c.ctx, c.a.ID, []string{"LNK@example.org", "unv@example.org", "nobody@example.org"})
	if err != nil || len(users) != 1 || users[0].ID != c.aUser.ID {
		t.Fatalf("verified only: %v %v", err, users)
	}
	// the primary only counts once verified
	if users, _ = c.svc.UsersByVerifiedEmail(c.ctx, c.a.ID, []string{c.aUser.Email}); len(users) != 0 {
		t.Fatalf("unverified primary matched: %v", users)
	}
	tr := true
	c.svc.UpdateUser(c.ctx, adm, c.aUser.ID, service.UserInput{Verified: &tr})
	if users, _ = c.svc.UsersByVerifiedEmail(c.ctx, c.a.ID, []string{c.aUser.Email}); len(users) != 1 {
		t.Fatalf("verified primary: %v", users)
	}
	if users, _ = c.svc.UsersByVerifiedEmail(c.ctx, c.b.ID, []string{c.aUser.Email}); len(users) != 0 {
		t.Fatalf("other org matched: %v", users)
	}
}

func TestFullNameAndGivenNameRequired(t *testing.T) {
	c := newCast(t)
	adm := actor(c.aAdmin)
	if _, err := c.svc.CreateUser(c.ctx, adm, c.a.ID, service.UserInput{Email: ptr("noname@example.org")}); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("create without a first name: %v", err)
	}
	empty := " "
	if _, err := c.svc.UpdateUser(c.ctx, adm, c.aUser.ID, service.UserInput{GivenName: &empty}); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("clearing the first name: %v", err)
	}
	u, err := c.svc.CreateUser(c.ctx, adm, c.a.ID, service.UserInput{Email: ptr("one@example.org"), GivenName: ptr("Cher")})
	if err != nil || u.FullName() != "Cher" {
		t.Fatalf("single name: %v %q", err, u.FullName())
	}
	u, _ = c.svc.UpdateUser(c.ctx, adm, u.ID, service.UserInput{FamilyName: ptr("Sarkisian")})
	if u.FullName() != "Cher Sarkisian" {
		t.Fatal(u.FullName())
	}
	if (&model.User{Username: "u", Email: "e@x.test"}).FullName() != "u" || (&model.User{Email: "e@x.test"}).FullName() != "e@x.test" {
		t.Fatal("full name fallbacks")
	}
}

func TestMarkEmailVerified(t *testing.T) {
	c := newCast(t)
	self := service.SelfService(c.ctx)
	if _, err := c.svc.AddLinkedEmail(c.ctx, service.System, c.aUser.ID, "alt@example.org", false); err != nil {
		t.Fatal(err)
	}
	// a manager marks a user's linked and primary addresses verified; once is enough
	u, err := c.svc.MarkEmailVerified(c.ctx, actor(c.aManager), c.aUser.ID, "ALT@example.org")
	if err != nil || !u.LinkedEmails[0].Verified {
		t.Fatalf("linked: %v %+v", err, u.LinkedEmails)
	}
	if u, err = c.svc.MarkEmailVerified(c.ctx, actor(c.aManager), c.aUser.ID, c.aUser.Email); err != nil || !u.EmailVerified {
		t.Fatalf("primary: %v", err)
	}
	if _, err := c.svc.MarkEmailVerified(c.ctx, actor(c.aManager), c.aUser.ID, c.aUser.Email); !errors.Is(err, service.ErrConflict) {
		t.Fatalf("already verified: %v", err)
	}
	if _, err := c.svc.MarkEmailVerified(c.ctx, actor(c.aManager), c.aUser.ID, "nobody@example.org"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("not on the account: %v", err)
	}
	// who: not plain users, not other orgs, never yourself (self-service or not, super admin or not)
	if _, err := c.svc.MarkEmailVerified(c.ctx, actor(c.pUser), c.aManager.ID, c.aManager.Email); err == nil {
		t.Error("a plain user marked an address")
	}
	if _, err := c.svc.MarkEmailVerified(c.ctx, actor(c.bAdmin), c.aManager.ID, c.aManager.Email); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("other org's admin: %v", err)
	}
	for _, who := range []*model.User{c.aAdmin, c.super} {
		for _, ctx := range []context.Context{c.ctx, self} {
			if _, err := c.svc.MarkEmailVerified(ctx, actor(who), who.ID, who.Email); !errors.Is(err, service.ErrInvalid) {
				t.Errorf("%s marks own address: %v", who.Username, err)
			}
			if _, err := c.svc.UpdateUser(ctx, actor(who), who.ID, service.UserInput{Verified: ptr(true)}); err == nil {
				t.Errorf("%s sets own email_verified", who.Username)
			}
		}
	}
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.aAdmin), c.aAdmin.ID, service.UserInput{PhoneVerified: ptr(true)}); err == nil {
		t.Error("admin sets own phone_number_verified")
	}
	// an established manager's address: only a super admin, by either route
	if _, err := c.svc.UpdateUser(c.ctx, service.System, c.aManager.ID, service.UserInput{Password: ptr("a long enough password")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.MarkEmailVerified(c.ctx, actor(c.aAdmin), c.aManager.ID, c.aManager.Email); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("admin marks an established manager's address: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.aAdmin), c.aManager.ID, service.UserInput{Verified: ptr(true)}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("admin sets an established manager's email_verified: %v", err)
	}
	if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.aAdmin), c.aManager.ID, "mgr-alt@example.org", true); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("admin adds a verified address for an established manager: %v", err)
	}
	mgr, _ := c.svc.Users.Get(c.ctx, c.aManager.ID) // now with a password
	if !c.svc.CanMarkEmailVerified(c.ctx, actor(c.aAdmin), c.aUser) || c.svc.CanMarkEmailVerified(c.ctx, actor(c.aAdmin), mgr) ||
		c.svc.CanMarkEmailVerified(c.ctx, actor(c.aAdmin), c.aAdmin) {
		t.Error("CanMarkEmailVerified")
	}
	if u, err := c.svc.MarkEmailVerified(c.ctx, actor(c.super), c.aManager.ID, c.aManager.Email); err != nil || !u.EmailVerified {
		t.Errorf("super admin: %v", err)
	}
}
