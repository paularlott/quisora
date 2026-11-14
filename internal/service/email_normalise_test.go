package service_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// An address is matched with the stored one by the rule that keeps addresses unique (model.Lower: case and
// compatibility forms folded), on both sides: an account a directory stored full-width is found by the address
// people type for password sign-in, as its unique key promised; the account's own address operations find it in any
// form; and what proves an address (a link mailed to it, a provider's word for it) proves only the form it names
// (model.SameAddress): another form may be another mailbox.
func TestAddressesMatchByTheirUniqueKey(t *testing.T) {
	c := newCast(t)
	adm := actor(c.aAdmin)
	wide := "ｗｉｄｅ@example.com" // as a directory sent it
	u, err := c.svc.CreateUser(c.ctx, service.System, c.a.ID, service.UserInput{
		Username: ptr("wide"), GivenName: ptr("Wide"), Email: ptr(wide), Verified: ptr(true), Role: ptr(model.RoleUser),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.Email != wide {
		t.Fatalf("the address is stored as given: %q", u.Email)
	}

	// Password sign-in's lookup: the primary address, in the form typed.
	for _, typed := range []string{"wide@example.com", "WIDE@example.com", wide} {
		if got, err := c.svc.FindUserByEmail(c.ctx, c.a.ID, typed); err != nil || got.ID != u.ID {
			t.Errorf("FindUserByEmail(%q): %v", typed, err)
		}
	}
	// A provider's verified address links to the account only as it is written there (in any ASCII case): the ASCII
	// form a provider vouches for may be another mailbox than the full-width one the account verified.
	if got, err := c.svc.UsersByVerifiedEmail(c.ctx, c.a.ID, []string{"wide@example.com"}); err != nil || len(got) != 0 {
		t.Errorf("UsersByVerifiedEmail by another form: %v %d", err, len(got))
	}
	if got, err := c.svc.UsersByVerifiedEmail(c.ctx, c.a.ID, []string{wide}); err != nil || len(got) != 1 || got[0].ID != u.ID {
		t.Errorf("UsersByVerifiedEmail: %v %d", err, len(got))
	}

	// No other account can claim another form of it.
	if _, err := c.svc.CreateUser(c.ctx, service.System, c.a.ID, service.UserInput{
		Username: ptr("narrow"), GivenName: ptr("Narrow"), Email: ptr("wide@example.com"), Role: ptr(model.RoleUser),
	}); !errors.Is(err, service.ErrConflict) {
		t.Fatalf("a second account with the ASCII form: %v", err)
	}
	// Nor can the account link another form of its own primary address: it already is the primary.
	if _, err := c.svc.AddLinkedEmail(c.ctx, adm, u.ID, "Wide@example.com", true); !errors.Is(err, service.ErrConflict) {
		t.Fatalf("the ASCII form of the primary linked: %v", err)
	}

	// A linked address stored full-width is found, made primary and removed by its ASCII form, and a linked list
	// naming it in another form keeps one address, not two. Marking it verified vouches for the form named, so that
	// takes the form stored (TestMarkEmailVerifiedNeedsTheStoredForm).
	alt := "ａｌｔ@example.com"
	if _, err := c.svc.AddLinkedEmail(c.ctx, adm, u.ID, alt, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.MarkEmailVerified(c.ctx, adm, u.ID, alt); err != nil {
		t.Fatalf("mark verified: %v", err)
	}
	if got, err := c.svc.UsersByVerifiedEmail(c.ctx, c.a.ID, []string{"ALT@example.com"}); err != nil || len(got) != 0 {
		t.Errorf("linked address by the ASCII form: %v %d", err, len(got))
	}
	if got, err := c.svc.UsersByVerifiedEmail(c.ctx, c.a.ID, []string{alt}); err != nil || len(got) != 1 {
		t.Errorf("linked address as stored: %v %d", err, len(got))
	}
	if got, err := c.svc.UpdateUser(c.ctx, adm, u.ID, service.UserInput{LinkedEmails: &[]string{alt, "alt@example.com"}}); err != nil || len(got.LinkedEmails) != 1 {
		t.Fatalf("a list naming one address in two forms: %v %+v", err, got)
	}
	if got, err := c.svc.MakePrimary(c.ctx, adm, u.ID, "alt@example.com"); err != nil || !model.SameKey(got.Email, alt) || len(got.LinkedEmails) != 1 {
		t.Fatalf("make primary by the ASCII form: %v %+v", err, got)
	}
	if got, err := c.svc.RemoveLinkedEmail(c.ctx, adm, u.ID, "wide@example.com"); err != nil || len(got.LinkedEmails) != 0 {
		t.Fatalf("remove by the ASCII form: %v %+v", err, got)
	}

	// A verification link proves the form it was mailed to only: mail to the ASCII form verifies no full-width
	// address, and none is issued for it.
	third := "ｔｈｉｒｄ@example.com"
	cur, err := c.svc.AddLinkedEmail(c.ctx, adm, u.ID, third, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.IssueEmailLink(c.ctx, cur, "third@example.com"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("a link for another form of the address: %v", err)
	}
	if err := c.svc.VerifyEmailAddress(c.ctx, u.ID, "third@example.com"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("a link to another form verified the address: %v", err)
	}
	if _, err := c.svc.IssueEmailLink(c.ctx, cur, third); err != nil {
		t.Errorf("a link for the address as stored: %v", err)
	}
}

// Marking an address verified without the mailed link vouches for the address as the caller names it, so, like the
// link, it takes the form the account stores (in any ASCII case: model.SameAddress): a manager naming victim@corp.com does not verify a stored
// full-width ｖictim@corp.com, which may be another mailbox, and which would then link a provider's victim@corp.com
// sign-in to the account. The audit event names the address as stored.
func TestMarkEmailVerifiedNeedsTheStoredForm(t *testing.T) {
	c := newCast(t)
	mgr := actor(c.aManager)
	for _, stored := range []string{"ｖictim@corp.com", "ｐrimary@corp.com"} {
		u := c.user(c.a.ID, c.next("u"), model.RoleUser)
		var err error
		if stored == "ｐrimary@corp.com" {
			u, err = c.svc.UpdateUser(c.ctx, service.System, u.ID, service.UserInput{Email: ptr(stored), Verified: ptr(false)})
		} else {
			u, err = c.svc.AddLinkedEmail(c.ctx, service.System, u.ID, stored, false)
		}
		if err != nil {
			t.Fatal(err)
		}
		named := model.Lower(stored) // the ASCII form: the same key, another address
		if _, err := c.svc.MarkEmailVerified(c.ctx, mgr, u.ID, named); !errors.Is(err, service.ErrNotFound) {
			t.Fatalf("%s marked verified by naming %s: %v", stored, named, err)
		}
		if got, err := c.svc.UsersByVerifiedEmail(c.ctx, c.a.ID, []string{named}); err != nil || len(got) != 0 {
			t.Fatalf("a provider's %s links to the account: %v %d", named, err, len(got))
		}
		if _, err := c.svc.MarkEmailVerified(c.ctx, mgr, u.ID, asciiUpper(stored)); err != nil {
			t.Fatalf("%s by its stored form in capitals: %v", stored, err)
		}
		if got := c.lastAudit("user.email.verify").Detail["email"]; got != stored {
			t.Errorf("audited %q, want the stored %q", got, stored)
		}
	}
}

// asciiUpper is s with its ASCII letters in capitals, and nothing else changed.
func asciiUpper(s string) string {
	return strings.Map(func(r rune) rune {
		if 'a' <= r && r <= 'z' {
			return r - 'a' + 'A'
		}
		return r
	}, s)
}
