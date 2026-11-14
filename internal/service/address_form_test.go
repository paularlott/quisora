package service_test

import (
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// kelvin is the Kelvin sign (U+212A): strings.EqualFold folds it with k, model.Lower (NFKC) to k as well, so
// "Kate@corp.com" claims the key of kate@corp.com while it is not the same address as written.
const kelvin = "K"

// A linked list naming another form of a verified linked address (full-width, or with the Kelvin sign for a k) adds
// an address: setLinked stores the form named, verified, and that form may be another mailbox. So for an established
// manager it is a sign-in reset, a super admin's to make, as adding any verified address is; the same address in
// other ASCII capitals adds nothing.
func TestAnotherFormOfAVerifiedLinkedAddressIsAnAddition(t *testing.T) {
	c := newCast(t)
	c.establish(c.aManager)
	c.establish(c.aAdmin)
	admin := actor(c.aAdmin)
	for _, tc := range []struct{ stored, named string }{
		{"boss@corp.com", "ｂoss@corp.com"},
		{"kate@corp.com", kelvin + "ate@corp.com"},
	} {
		if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.super), c.aManager.ID, tc.stored, true); err != nil {
			t.Fatal(err)
		}
		if _, err := c.svc.UpdateUser(c.ctx, admin, c.aManager.ID, service.UserInput{LinkedEmails: &[]string{tc.named}}); !isInvalid(err) {
			t.Fatalf("an administrator replaced a manager's verified %s with %s: %v", tc.stored, tc.named, err)
		}
		got := c.fresh(c.aManager)
		if l, ok := got.LinkedEmail(tc.stored); !ok || l.Address != tc.stored || !l.Verified {
			t.Fatalf("the manager's address changed: %+v", got.LinkedEmails)
		}
		if _, err := c.svc.UpdateUser(c.ctx, admin, c.aManager.ID, service.UserInput{LinkedEmails: &[]string{asciiUpper(tc.stored)}}); err != nil {
			t.Fatalf("the same address in capitals: %v", err)
		}
		if _, err := c.svc.RemoveLinkedEmail(c.ctx, actor(c.super), c.aManager.ID, tc.stored); err != nil {
			t.Fatal(err)
		}
	}
}

// A provider vouching for an address links a sign-in to the account that verified that very address (in any ASCII
// case), never to the one that verified another form claiming the same key: a provider's full-width ｖictim@corp.com,
// or Kate@corp.com, may be another mailbox than the account's victim@corp.com or kate@corp.com.
func TestProviderLinksOnlyTheVerifiedForm(t *testing.T) {
	c := newCast(t)
	for _, tc := range []struct{ stored, other string }{
		{"victim@corp.com", "ｖictim@corp.com"},
		{"kate@corp.com", kelvin + "ate@corp.com"},
	} {
		primary := c.user(c.a.ID, c.next("p"), model.RoleUser)
		primary, err := c.svc.UpdateUser(c.ctx, service.System, primary.ID, service.UserInput{Email: ptr(tc.stored), Verified: ptr(true)})
		if err != nil {
			t.Fatal(err)
		}
		linked := c.user(c.a.ID, c.next("l"), model.RoleUser)
		if _, err := c.svc.AddLinkedEmail(c.ctx, service.System, linked.ID, "linked."+tc.stored, true); err != nil {
			t.Fatal(err)
		}
		for _, addr := range []struct {
			name, want string
			id         string
		}{{tc.other, "", primary.ID}, {"linked." + tc.other, "", linked.ID}, {asciiUpper(tc.stored), primary.ID, primary.ID},
			{"linked." + tc.stored, linked.ID, linked.ID}} {
			got, err := c.svc.UsersByVerifiedEmail(c.ctx, c.a.ID, []string{addr.name})
			if err != nil {
				t.Fatal(err)
			}
			if (addr.want == "" && len(got) != 0) || (addr.want != "" && (len(got) != 1 || got[0].ID != addr.want)) {
				t.Fatalf("a provider's %s matched %d accounts", addr.name, len(got))
			}
			if u := c.fresh(&model.User{Meta: model.Meta{ID: addr.id}}); u.HasVerifiedEmail(addr.name) != (addr.want != "") {
				t.Fatalf("HasVerifiedEmail(%s): %v", addr.name, !(addr.want != ""))
			}
		}
	}
}

// What proves or changes an address compares it as written, in any ASCII case and no other folding: the Kelvin sign
// for a k is another address, so naming it verifies nothing (MarkEmailVerified, a mailed link) and making it the
// primary address leaves that unverified.
func TestKelvinSignIsAnotherAddress(t *testing.T) {
	c := newCast(t)
	mgr := actor(c.aManager)
	stored, named := "kate@corp.com", kelvin+"ate@corp.com"
	u := c.user(c.a.ID, c.next("k"), model.RoleUser)
	u, err := c.svc.UpdateUser(c.ctx, service.System, u.ID, service.UserInput{Email: ptr(stored), Verified: ptr(false)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.MarkEmailVerified(c.ctx, mgr, u.ID, named); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("marked verified by naming %s: %v", named, err)
	}
	if _, err := c.svc.IssueEmailLink(c.ctx, u, named); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("a link issued for %s: %v", named, err)
	}
	if err := c.svc.VerifyEmailAddress(c.ctx, u.ID, named); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("a link to %s verified %s: %v", named, stored, err)
	}
	if u, err = c.svc.UpdateUser(c.ctx, service.System, u.ID, service.UserInput{Verified: ptr(true)}); err != nil || !u.EmailVerified {
		t.Fatal(err)
	}
	if u, err = c.svc.UpdateUser(c.ctx, actor(c.aAdmin), u.ID, service.UserInput{Email: ptr(named)}); err != nil {
		t.Fatal(err)
	}
	if u.Email != named || u.EmailVerified {
		t.Fatalf("the primary address changed to %s and is still verified: %+v", named, u.EmailVerified)
	}
}
