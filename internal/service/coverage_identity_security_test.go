package service_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// establish gives u a password so that their sign-in counts as established (privileged-account rules apply).
func (e *env) establish(u *model.User) *model.User {
	e.t.Helper()
	got, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Password: ptr("correct horse battery")})
	if err != nil {
		e.t.Fatal(err)
	}
	return got
}

func TestEmailChangesAuthorizationMatrix(t *testing.T) {
	c := newCast(t)
	target := c.aUser
	for _, tc := range []struct {
		name string
		u    *model.User
		want string
	}{
		{"org admin", c.aAdmin, "ok"}, {"org manager", c.aManager, "ok"}, {"super", c.super, "ok"},
		{"foreign admin", c.bAdmin, "notfound"}, {"peer", c.e2(c.a.ID), "denied"},
	} {
		addr := c.next("x") + "@example.com"
		_, err := c.svc.AddLinkedEmail(c.ctx, actor(tc.u), target.ID, addr, false)
		c.check(t, tc.name+" add", err, tc.want)
		if tc.want == "ok" {
			_, err = c.svc.RemoveLinkedEmail(c.ctx, actor(tc.u), target.ID, addr)
			c.check(t, tc.name+" remove", err, "ok")
			continue
		}
		// a denied caller cannot touch an address that exists
		if _, err := c.svc.RemoveLinkedEmail(c.ctx, actor(tc.u), target.ID, "nothing@example.com"); !match(outcome(err), "denied") {
			t.Errorf("%s remove: %v", tc.name, err)
		}
		if _, err := c.svc.MakePrimary(c.ctx, actor(tc.u), target.ID, "nothing@example.com"); !match(outcome(err), "denied") {
			t.Errorf("%s make primary: %v", tc.name, err)
		}
		if _, err := c.svc.MarkEmailVerified(c.ctx, actor(tc.u), target.ID, target.Email); !match(outcome(err), "denied") {
			t.Errorf("%s mark verified: %v", tc.name, err)
		}
	}
	if got := c.fresh(target); len(got.LinkedEmails) != 0 || got.Email != target.Email {
		t.Errorf("addresses changed by denied callers: %+v", got.LinkedEmails)
	}
	for _, f := range []func() error{
		func() error {
			_, err := c.svc.AddLinkedEmail(c.ctx, actor(c.aAdmin), "nobody", "a@example.com", false)
			return err
		},
		func() error {
			_, err := c.svc.RemoveLinkedEmail(c.ctx, actor(c.aAdmin), "nobody", "a@example.com")
			return err
		},
		func() error {
			_, err := c.svc.MakePrimary(c.ctx, actor(c.aAdmin), "nobody", "a@example.com")
			return err
		},
		func() error {
			_, err := c.svc.MarkEmailVerified(c.ctx, actor(c.aAdmin), "nobody", "a@example.com")
			return err
		},
	} {
		if err := f(); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("unknown user: %v", err)
		}
	}
}

func TestEmailSelfServiceRules(t *testing.T) {
	c := newCast(t)
	self := service.SelfService(c.ctx)
	// without re-authentication nobody changes their own addresses
	if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.aManager), c.aManager.ID, "m2@example.com", false); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("manager add without re-auth: %v", err)
	}
	// users below manager never add or remove their own
	if _, err := c.svc.AddLinkedEmail(self, actor(c.aUser), c.aUser.ID, "u2@example.com", false); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("plain user add: %v", err)
	}
	if _, err := c.svc.RemoveLinkedEmail(self, actor(c.aUser), c.aUser.ID, "u2@example.com"); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("plain user remove: %v", err)
	}
	// a manager adds their own: always unverified, even if verified was asked for
	u, err := c.svc.AddLinkedEmail(self, actor(c.aManager), c.aManager.ID, "M2@Example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(u.LinkedEmails) != 1 || u.LinkedEmails[0].Verified || !strings.EqualFold(u.LinkedEmails[0].Address, "m2@example.com") {
		t.Fatalf("linked %+v", u.LinkedEmails)
	}
	// it cannot be made primary until verified; nobody verifies their own by hand
	if _, err := c.svc.MakePrimary(self, actor(c.aManager), c.aManager.ID, "m2@example.com"); !isInvalid(err) {
		t.Errorf("unverified made primary: %v", err)
	}
	if _, err := c.svc.MarkEmailVerified(self, actor(c.aManager), c.aManager.ID, "m2@example.com"); !isInvalid(err) {
		t.Errorf("own address marked verified: %v", err)
	}
	if err := c.svc.VerifyEmailAddress(c.ctx, c.aManager.ID, "m2@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.VerifyEmailAddress(c.ctx, c.aManager.ID, "m2@example.com"); err != nil { // already: no second event
		t.Fatal(err)
	}
	if n := len(c.audited(c.a.ID, "user.email.verify")); n != 1 {
		t.Errorf("verify events %d", n)
	}
	if err := c.svc.VerifyEmailAddress(c.ctx, c.aManager.ID, "gone@example.com"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("verifying an address not on the account: %v", err)
	}
	if err := c.svc.VerifyEmailAddress(c.ctx, c.aManager.ID, c.aManager.Email); err != nil {
		t.Errorf("verifying the primary: %v", err)
	}
	got, err := c.svc.MakePrimary(self, actor(c.aManager), c.aManager.ID, "m2@example.com")
	if err != nil || !strings.EqualFold(got.Email, "m2@example.com") || !got.EmailVerified {
		t.Fatalf("make primary: %v", err)
	}
	if l, ok := got.LinkedEmail(c.aManager.Email); !ok || !l.Verified {
		t.Errorf("old primary not kept as a verified linked address")
	}
	if _, err := c.svc.RemoveLinkedEmail(self, actor(c.aManager), c.aManager.ID, got.Email); !isInvalid(err) {
		t.Errorf("removing the primary: %v", err)
	}
	if _, err := c.svc.RemoveLinkedEmail(self, actor(c.aManager), c.aManager.ID, "unknown@example.com"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("removing an unknown address: %v", err)
	}
	if _, err := c.svc.MakePrimary(self, actor(c.aManager), c.aManager.ID, "unknown@example.com"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("primary of an unknown address: %v", err)
	}
	if len(c.audited(c.a.ID, "user.email.primary")) != 1 {
		t.Error("primary change not audited")
	}
}

func TestEmailValidationAndLimit(t *testing.T) {
	c := newCast(t)
	for name, addr := range map[string]string{"empty": "", "no at": "nobody", "spaces": "a b@example.com", "two ats": "a@@example.com"} {
		if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.aAdmin), c.aUser.ID, addr, false); !isInvalid(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.aAdmin), c.aUser.ID, c.aUser.Email, false); !errors.Is(err, service.ErrConflict) {
		t.Errorf("the primary as linked: %v", err)
	}
	if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.aAdmin), c.aUser.ID, "a1@example.com", false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.aAdmin), c.aUser.ID, "A1@example.com", false); !errors.Is(err, service.ErrConflict) {
		t.Errorf("duplicate: %v", err)
	}
	for i := 1; i < model.MaxLinkedEmails; i++ {
		if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.aAdmin), c.aUser.ID, "n"+itoa(i)+"@example.com", false); err != nil {
			t.Fatalf("address %d: %v", i, err)
		}
	}
	if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.aAdmin), c.aUser.ID, "over@example.com", false); !isInvalid(err) {
		t.Errorf("over the limit: %v", err)
	}
	// an address of another account in the org is reserved
	if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.aAdmin), c.aUser.ID, c.aManager.Email, false); err == nil {
		t.Error("another user's primary address linked")
	}
	// the same list through UpdateUser: more than the limit, and a bad address, change nothing
	many := make([]string, model.MaxLinkedEmails+1)
	for i := range many {
		many[i] = "bulk" + itoa(i) + "@example.com"
	}
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.aAdmin), c.aManager.ID, service.UserInput{LinkedEmails: &many}); !isInvalid(err) {
		t.Errorf("bulk over the limit: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.aAdmin), c.aManager.ID, service.UserInput{LinkedEmails: &[]string{"nope"}}); !isInvalid(err) {
		t.Errorf("bulk bad address: %v", err)
	}
	if got := c.fresh(c.aManager); len(got.LinkedEmails) != 0 {
		t.Errorf("linked after refused updates: %d", len(got.LinkedEmails))
	}
	// SCIM-style replacement keeps the user's own pending address, skips the primary and duplicates
	pending, err := c.svc.AddLinkedEmail(service.SelfService(c.ctx), actor(c.aManager), c.aManager.ID, "mine@example.com", false)
	if err != nil || len(pending.LinkedEmails) != 1 {
		t.Fatal(err)
	}
	set := []string{c.aManager.Email, "dir@example.com", "DIR@example.com"}
	got, err := c.svc.UpdateUser(c.ctx, actor(c.aAdmin), c.aManager.ID, service.UserInput{LinkedEmails: &set})
	if err != nil {
		t.Fatal(err)
	}
	var verified, unverified []string
	for _, l := range got.LinkedEmails {
		if l.Verified {
			verified = append(verified, l.Address)
		} else {
			unverified = append(unverified, l.Address)
		}
	}
	if len(verified) != 1 || verified[0] != "dir@example.com" || len(unverified) != 1 || unverified[0] != "mine@example.com" {
		t.Errorf("verified %v unverified %v", verified, unverified)
	}
}

func TestIssueEmailLinkBranches(t *testing.T) {
	c := newCast(t)
	u := c.fresh(c.aUser)
	if _, err := c.svc.IssueEmailLink(c.ctx, u, "stranger@example.com"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("address not on the account: %v", err)
	}
	// the primary of a user created by an admin starts unverified
	if u.EmailVerified {
		t.Skip("primary starts verified")
	}
	tok, err := c.svc.IssueEmailLink(c.ctx, u, strings.ToUpper(u.Email))
	if err != nil || tok == "" {
		t.Fatalf("primary link: %v", err)
	}
	l, got, err := c.svc.RedeemLink(c.ctx, tok)
	if err != nil || got.ID != u.ID || l.Email == "" {
		t.Fatalf("redeem: %v", err)
	}
	if _, _, err := c.svc.RedeemLink(c.ctx, tok); !errors.Is(err, service.ErrLink) {
		t.Errorf("redeemed twice: %v", err)
	}
	if _, _, err := c.svc.RedeemLink(c.ctx, "garbage"); !errors.Is(err, service.ErrLink) {
		t.Errorf("garbage token: %v", err)
	}
	if err := c.svc.VerifyEmailAddress(c.ctx, u.ID, l.Email); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.IssueEmailLink(c.ctx, c.fresh(c.aUser), u.Email); !errors.Is(err, service.ErrConflict) {
		t.Errorf("already verified primary: %v", err)
	}
	// a linked address: verified ones are refused too
	if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.aAdmin), u.ID, "l1@example.com", false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.AddLinkedEmail(c.ctx, actor(c.aAdmin), u.ID, "l2@example.com", true); err != nil {
		t.Fatal(err)
	}
	cur := c.fresh(c.aUser)
	if _, err := c.svc.IssueEmailLink(c.ctx, cur, "l1@example.com"); err != nil {
		t.Errorf("unverified linked address: %v", err)
	}
	if _, err := c.svc.IssueEmailLink(c.ctx, cur, "l2@example.com"); !errors.Is(err, service.ErrConflict) {
		t.Errorf("verified linked address: %v", err)
	}
}

// An established manager or administrator's addresses and sign-in are changed by a super admin only.
func TestPrivilegedAccountEmailAndInviteRules(t *testing.T) {
	c := newCast(t)
	c.establish(c.aManager)
	c.establish(c.aAdmin)
	admin := actor(c.aAdmin)
	// unverified linked addresses are the user's own business: anyone who manages them may add one...
	if _, err := c.svc.AddLinkedEmail(c.ctx, admin, c.aManager.ID, "m1@example.com", false); err != nil {
		t.Fatalf("unverified add: %v", err)
	}
	// ...but a verified one links provider sign-ins to the account: a sign-in reset
	if _, err := c.svc.AddLinkedEmail(c.ctx, admin, c.aManager.ID, "m2@example.com", true); !isInvalid(err) {
		t.Errorf("admin adding a verified address to a manager: %v", err)
	}
	if _, err := c.svc.MarkEmailVerified(c.ctx, admin, c.aManager.ID, "m1@example.com"); !isInvalid(err) {
		t.Errorf("admin verifying a manager's address: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, admin, c.aManager.ID, service.UserInput{LinkedEmails: &[]string{"m3@example.com"}}); !isInvalid(err) {
		t.Errorf("admin replacing a manager's verified addresses: %v", err)
	}
	if _, _, err := c.svc.CreateInvite(c.ctx, admin, c.aManager.ID); !isInvalid(err) {
		t.Errorf("admin inviting an established manager: %v", err)
	}
	if _, err := c.svc.LockOutUser(c.ctx, admin, c.aManager.ID, "x"); !isInvalid(err) {
		t.Errorf("admin locking out an established manager: %v", err)
	}
	if c.svc.CanResetSignIn(c.ctx, admin, c.fresh(c.aManager)) || c.svc.CanMarkEmailVerified(c.ctx, admin, c.fresh(c.aManager)) {
		t.Error("Can* says yes where the action is refused")
	}
	if !c.svc.CanResetSignIn(c.ctx, admin, c.fresh(c.aUser)) || !c.svc.CanMarkEmailVerified(c.ctx, admin, c.fresh(c.aUser)) {
		t.Error("Can* says no for a plain user")
	}
	if c.svc.CanMarkEmailVerified(c.ctx, admin, c.fresh(c.aAdmin)) {
		t.Error("own address can be marked verified")
	}
	if got := c.fresh(c.aManager); got.PasswordHash == "" || len(got.LinkedEmails) != 1 {
		t.Error("manager changed")
	}
	// the super admin may
	if _, err := c.svc.MarkEmailVerified(c.ctx, actor(c.super), c.aManager.ID, "m1@example.com"); err != nil {
		t.Errorf("super verifying: %v", err)
	}
	if _, err := c.svc.MarkEmailVerified(c.ctx, actor(c.super), c.aManager.ID, "m1@example.com"); !errors.Is(err, service.ErrConflict) {
		t.Errorf("already verified: %v", err)
	}
	if _, err := c.svc.MarkEmailVerified(c.ctx, actor(c.super), c.aManager.ID, c.aManager.Email); err != nil {
		t.Errorf("super verifying primary: %v", err)
	}
	if _, err := c.svc.MarkEmailVerified(c.ctx, actor(c.super), c.aManager.ID, c.aManager.Email); !errors.Is(err, service.ErrConflict) {
		t.Errorf("primary already verified: %v", err)
	}
	if _, err := c.svc.MarkEmailVerified(c.ctx, actor(c.super), c.aManager.ID, "unknown@example.com"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown address: %v", err)
	}
	if _, err := c.svc.MarkEmailVerified(c.ctx, actor(c.aManager), c.aManager.ID, "m1@example.com"); !isInvalid(err) {
		t.Errorf("manager verifying own address: %v", err)
	}
	link, _, err := c.svc.CreateInvite(c.ctx, actor(c.super), c.aManager.ID)
	if err != nil {
		t.Fatal(err)
	}
	_ = link
	// an invitation of a super admin's issuing is not replaced by an admin
	if _, _, err := c.svc.CreateInvite(c.ctx, admin, c.aManager.ID); !isInvalid(err) {
		t.Errorf("admin replacing a super admin's invite: %v", err)
	}
	if _, _, err := c.svc.CreateInvite(c.ctx, actor(c.super), c.super.ID); !isInvalid(err) {
		t.Errorf("inviting yourself: %v", err)
	}
	// a fresh privileged account that has never signed in gets its first invitation from whoever manages it
	n := c.next("fresh")
	fresh, err := c.svc.CreateUser(c.ctx, admin, c.a.ID, service.UserInput{Username: &n, GivenName: ptr("F"), Email: ptr(n + "@example.com"), Role: ptr(model.RoleManager)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.svc.CreateInvite(c.ctx, admin, fresh.ID); err != nil {
		t.Errorf("first invite of a new manager: %v", err)
	}
	// an invitation an admin issued for a new manager: a different admin cannot replace it
	if _, _, err := c.svc.CreateInvite(c.ctx, actor(c.bAdminPeerOf(c.a.ID)), fresh.ID); !isInvalid(err) && !errors.Is(err, service.ErrForbidden) {
		t.Errorf("another admin replacing a live invitation: %v", err)
	}
}

func (c *cast) bAdminPeerOf(orgID string) *model.User {
	return c.user(orgID, c.next("padm"), model.RoleAdmin)
}

func TestRecoveryCodesLifecycleAndFactorRemoval(t *testing.T) {
	c := newCast(t)
	u := c.fresh(c.aUser)
	if _, err := c.svc.CreateRecoveryCodes(c.ctx, actor(u), u); !isInvalid(err) {
		t.Fatalf("codes without a second factor: %v", err)
	}
	if n, at := c.svc.RecoveryCodesLeft(c.ctx, u); n != 0 || at != nil {
		t.Errorf("left %d %v", n, at)
	}
	if ok, left := c.svc.ConsumeRecoveryCode(c.ctx, u, "AAAA-AAAA-AAAA-AAAA"); ok || left != 0 {
		t.Error("code accepted with none made")
	}
	if err := c.svc.SetTOTP(c.ctx, u, secure.RandomBytes(20), 1); err != nil {
		t.Fatal(err)
	}
	codes, err := c.svc.CreateRecoveryCodes(c.ctx, actor(u), u)
	if err != nil || len(codes) != service.RecoveryCodeCount {
		t.Fatalf("create: %v", err)
	}
	u = c.fresh(c.aUser)
	if n, at := c.svc.RecoveryCodesLeft(c.ctx, u); n != service.RecoveryCodeCount || at == nil {
		t.Errorf("left %d %v", n, at)
	}
	// typed sloppily: lower case, spaces, look-alike letters
	sloppy := strings.ToLower(strings.ReplaceAll(codes[0], "-", " "))
	if ok, left := c.svc.ConsumeRecoveryCode(c.ctx, u, sloppy); !ok || left != service.RecoveryCodeCount-1 {
		t.Fatalf("sloppy code: %v %d", ok, left)
	}
	if ok, _ := c.svc.ConsumeRecoveryCode(c.ctx, u, codes[0]); ok {
		t.Error("a recovery code worked twice")
	}
	for _, bad := range []string{"", "short", strings.Repeat("U", 16), "ZZZZ-ZZZZ-ZZZZ-ZZZZ"} {
		if ok, _ := c.svc.ConsumeRecoveryCode(c.ctx, u, bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	// another user's code is not valid here
	v := c.fresh(c.aManager)
	if err := c.svc.SetTOTP(c.ctx, v, secure.RandomBytes(20), 1); err != nil {
		t.Fatal(err)
	}
	vc, _ := c.svc.CreateRecoveryCodes(c.ctx, actor(v), c.fresh(c.aManager))
	if ok, _ := c.svc.ConsumeRecoveryCode(c.ctx, u, vc[0]); ok {
		t.Error("a code of another account worked")
	}
	if n, _ := c.svc.RecoveryCodesLeft(c.ctx, u); n != service.RecoveryCodeCount-1 {
		t.Errorf("left %d", n)
	}
	// a new set replaces the old: the old codes stop working
	if _, err := c.svc.CreateRecoveryCodes(c.ctx, actor(u), c.fresh(c.aUser)); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.svc.ConsumeRecoveryCode(c.ctx, c.fresh(c.aUser), codes[1]); ok {
		t.Error("a code of a replaced set worked")
	}
	if len(c.audited(c.a.ID, "account.recovery_codes.create")) != 3 {
		t.Error("creation not audited")
	}
	// the codes go with the last second factor, and do not come back
	if err := c.svc.DropRecoveryCodes(c.ctx, u.ID); err != nil || len(c.fresh(c.aUser).RecoveryCodes) == 0 {
		t.Fatalf("dropped while a factor remains: %v", err)
	}
	if err := c.svc.RemoveTOTP(c.ctx, actor(c.aAdmin), u.ID); err != nil {
		t.Fatal(err)
	}
	if got := c.fresh(c.aUser); len(got.RecoveryCodes) != 0 || got.RecoveryCreated != nil {
		t.Error("recovery codes outlived the last second factor")
	}
	if err := c.svc.DropRecoveryCodes(c.ctx, u.ID); err != nil {
		t.Errorf("dropping none: %v", err)
	}
	if err := c.svc.DropRecoveryCodes(c.ctx, "nobody"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
	// with a passkey as the second factor the codes stay; without it they go
	// (a manager's sign-in methods are a super admin's to remove, not another administrator's: mayResetSignIn)
	pk := c.passkey(c.aManager, "k")
	if err := c.svc.RemoveTOTP(c.ctx, actor(c.aAdmin), c.aManager.ID); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("an administrator removed a manager's authenticator app: %v", err)
	}
	if _, err := c.svc.RemovePasskey(c.ctx, actor(c.aAdmin), c.aManager.ID, pk.ID, ""); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("an administrator removed a manager's passkey: %v", err)
	}
	if err := c.svc.RemoveTOTP(c.ctx, actor(c.super), c.aManager.ID); err != nil {
		t.Fatal(err)
	}
	if len(c.fresh(c.aManager).RecoveryCodes) == 0 {
		t.Error("codes dropped although a passkey remains")
	}
	if _, err := c.svc.RemovePasskey(c.ctx, actor(c.super), c.aManager.ID, pk.ID, ""); err != nil {
		t.Fatal(err)
	}
	if len(c.fresh(c.aManager).RecoveryCodes) != 0 {
		t.Error("codes kept after the last factor went")
	}
}

func TestLockOutAuthorization(t *testing.T) {
	c := newCast(t)
	for _, tc := range []struct {
		name string
		u    *model.User
		want string
	}{
		{"foreign admin", c.bAdmin, "notfound"}, {"peer user", c.e2(c.a.ID), "denied"}, {"manager of a user", c.aManager, "ok"},
	} {
		victim := c.user(c.a.ID, c.next("v"), model.RoleUser)
		_, err := c.svc.LockOutUser(c.ctx, actor(tc.u), victim.ID, "r")
		c.check(t, tc.name, err, tc.want)
		if tc.want != "ok" && !c.fresh(victim).Active {
			t.Errorf("%s: user disabled by a refused lock-out", tc.name)
		}
	}
	if _, err := c.svc.LockOutUser(c.ctx, actor(c.aAdmin), c.aAdmin.ID, "x"); !isInvalid(err) {
		t.Errorf("self lock-out: %v", err)
	}
	if _, err := c.svc.LockOutUser(c.ctx, actor(c.aAdmin), "nobody", "x"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
	if _, err := c.svc.LockOutUser(c.ctx, actor(c.aManager), c.aAdmin.ID, "x"); err == nil {
		t.Error("manager locked out an admin")
	}
	if !c.fresh(c.aAdmin).Active {
		t.Error("admin disabled by a manager")
	}
	if len(c.audited(c.a.ID, "user.locked_out")) != 1 {
		t.Error("lock-out not audited exactly once")
	}
}

// What a manager can find by searching must not reveal an administrator's address, username or tags: they are
// directory entries to a manager, found only by name.
func TestSearchDoesNotLeakHiddenFields(t *testing.T) {
	c := newCast(t)
	if _, err := c.svc.UpdateUser(c.ctx, service.System, c.aAdmin.ID, service.UserInput{Tags: tags("finance")}); err != nil {
		t.Fatal(err)
	}
	m := actor(c.aManager)
	names := func(q store.ListQuery) map[string]bool {
		l, _, err := c.svc.ListUsers(c.ctx, m, c.a.ID, q)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, u := range l {
			out[u.Username] = true
		}
		return out
	}
	if got := names(store.ListQuery{Search: "aadmin@example"}); got["aadmin"] || len(got) != 0 {
		t.Errorf("search by an admin's address found %v", got)
	}
	if got := names(store.ListQuery{Search: "aadmin"}); got["aadmin"] {
		t.Errorf("search by an admin's username found %v", got)
	}
	if got := names(store.ListQuery{Filters: []store.Filter{{Field: "tags", Value: "finance"}}}); len(got) != 0 {
		t.Errorf("filter by an admin's tag found %v", got)
	}
	// the same searches by an admin find them, and a name is still found as a directory entry
	l, _, err := c.svc.ListUsers(c.ctx, actor(c.aAdmin), c.a.ID, store.ListQuery{Search: "aadmin@example"})
	if err != nil || len(l) != 1 {
		t.Errorf("admin search: %v %d", err, len(l))
	}
	// sorting on a field a directory entry blanks does not show the entry's place by its hidden value
	l, _, err = c.svc.ListUsers(c.ctx, m, c.a.ID, store.ListQuery{Sort: "username"})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range l {
		if u.ID == c.aAdmin.ID && (u.Username != "" || u.Email != "") {
			t.Errorf("directory entry shows %q %q", u.Username, u.Email)
		}
	}
	// FullViewQuery: a provisioning client is shown administrators only if it has the rank
	cl := service.ActorForClient(&model.Client{Meta: model.Meta{ID: "scim"}, OrgID: c.a.ID}, "")
	q := service.FullViewQuery(m, store.ListQuery{})
	var fields []string
	for _, f := range q.Filters {
		fields = append(fields, f.Field)
	}
	if !strings.Contains(strings.Join(fields, ","), "super_admin") || !strings.Contains(strings.Join(fields, ","), "admin_rank") {
		t.Errorf("manager full view filters %v", fields)
	}
	if q := service.FullViewQuery(cl, store.ListQuery{}); len(q.Filters) != 1 {
		t.Errorf("client full view filters %+v", q.Filters)
	}
	if q := service.FullViewQuery(actor(c.super), store.ListQuery{}); len(q.Filters) != 0 {
		t.Errorf("super full view filters %+v", q.Filters)
	}
	if _, err := c.svc.GetUser(c.ctx, m, c.aAdmin.ID); err != nil {
		t.Errorf("manager reading an admin (directory entry): %v", err)
	} else if u, _ := c.svc.GetUser(c.ctx, m, c.aAdmin.ID); u.Email != "" {
		t.Errorf("directory entry has an email: %q", u.Email)
	}
	if _, err := c.svc.GetUser(c.ctx, m, c.super.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("super admin visible to a manager: %v", err)
	}
	if _, err := c.svc.GetUser(c.ctx, actor(c.aUser), c.aManager.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("plain user reading a manager: %v", err)
	}
	if _, err := c.svc.GetUser(c.ctx, actor(c.aUser), c.aUser.ID); err != nil {
		t.Errorf("own record: %v", err)
	}
	if _, err := c.svc.GetUser(c.ctx, actor(c.bAdmin), c.aUser.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("foreign admin reading a user: %v", err)
	}
	_ = time.Now
}
