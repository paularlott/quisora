package service_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
)

func TestRecoveryCodes(t *testing.T) {
	e := newEnv(t)
	acme := e.org("acme")
	u := e.user(acme.ID, "ann", model.RoleUser)
	if _, err := e.svc.CreateRecoveryCodes(e.ctx, service.System, u); err == nil {
		t.Fatal("codes made for an account with no second factor")
	}
	u.TOTPSecret = "sealed-secret" // an authenticator app (only its presence matters here)
	if err := e.svc.Users.Update(e.ctx, u); err != nil {
		t.Fatal(err)
	}
	codes, err := e.svc.CreateRecoveryCodes(e.ctx, service.System, u)
	if err != nil || len(codes) != service.RecoveryCodeCount {
		t.Fatalf("create: %v %v", codes, err)
	}
	for _, c := range codes {
		if len(c) != 19 || strings.Count(c, "-") != 3 || strings.ContainsAny(c, "ILOU") {
			t.Fatalf("code %q", c)
		}
	}
	u, _ = e.svc.Users.Get(e.ctx, u.ID)
	if left, created := e.svc.RecoveryCodesLeft(e.ctx, u); left != 10 || created == nil {
		t.Fatalf("left %d %v", left, created)
	}

	// typed loosely: lower case, no dashes, O for 0 and I or L for 1
	loose := strings.ToLower(strings.ReplaceAll(codes[0], "-", " "))
	loose = strings.NewReplacer("0", "o", "1", "l").Replace(loose)
	if ok, left, _ := e.svc.ConsumeRecoveryCode(e.ctx, u, loose); !ok || left != 9 {
		t.Fatalf("first use: %v %d", ok, left)
	}
	if ok, _, _ := e.svc.ConsumeRecoveryCode(e.ctx, u, codes[0]); ok {
		t.Fatal("a code worked twice")
	}
	for _, bad := range []string{"", "nonsense", codes[1][:18], codes[1] + "X", "AAAA-AAAA-AAAA-AAAA"} {
		if ok, _, _ := e.svc.ConsumeRecoveryCode(e.ctx, u, bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	other := e.user(acme.ID, "bob", model.RoleUser)
	other.RecoveryCodes = u.RecoveryCodes // another user's codes (hashes salted with the user id) do not match
	if ok, _, _ := e.svc.ConsumeRecoveryCode(e.ctx, other, codes[1]); ok {
		t.Fatal("a code worked for another user")
	}

	// a new set: the old codes stop working, the count starts again
	fresh, err := e.svc.CreateRecoveryCodes(e.ctx, service.System, u)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = e.svc.Users.Get(e.ctx, u.ID)
	if ok, _, _ := e.svc.ConsumeRecoveryCode(e.ctx, u, codes[1]); ok {
		t.Fatal("an old code worked after a new set")
	}
	if ok, left, _ := e.svc.ConsumeRecoveryCode(e.ctx, u, fresh[3]); !ok || left != 9 {
		t.Fatalf("new set: %v %d", ok, left)
	}

	// the last second factor removed: the codes go with it (a factor added later must not bring them back)
	u.TOTPSecret = ""
	_ = e.svc.Users.Update(e.ctx, u)
	if err := e.svc.DropRecoveryCodes(e.ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	u, _ = e.svc.Users.Get(e.ctx, u.ID)
	if left, _ := e.svc.RecoveryCodesLeft(e.ctx, u); left != 0 || len(u.RecoveryCodes) != 0 {
		t.Fatal("codes kept without a second factor")
	}
	u.TOTPSecret = "sealed-secret"
	_ = e.svc.Users.Update(e.ctx, u)
	if fresh, err = e.svc.CreateRecoveryCodes(e.ctx, service.System, u); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DropRecoveryCodes(e.ctx, u.ID); err != nil { // with a factor: nothing happens
		t.Fatal(err)
	}
	u, _ = e.svc.Users.Get(e.ctx, u.ID)
	if left, _ := e.svc.RecoveryCodesLeft(e.ctx, u); left != 10 {
		t.Fatalf("codes dropped although a factor is left: %d", left)
	}

	// an invitation or a lock-out starts the account afresh: no codes
	if err := e.svc.ResetCredentials(e.ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	u, _ = e.svc.Users.Get(e.ctx, u.ID)
	if left, created := e.svc.RecoveryCodesLeft(e.ctx, u); left != 0 || created != nil {
		t.Fatalf("after reset: %d %v", left, created)
	}
	if ok, _, _ := e.svc.ConsumeRecoveryCode(e.ctx, u, fresh[4]); ok {
		t.Fatal("a code worked after the credentials were reset")
	}
}

// The recovery codes go with the last second factor and do not come back; while another factor remains they stay. A
// manager's factors are a super admin's to remove, not another administrator's.
func TestRemovingTheLastSecondFactorDropsRecoveryCodes(t *testing.T) {
	c := newCast(t)
	u := c.fresh(c.aUser)
	if err := c.svc.SetTOTP(c.ctx, u, secure.RandomBytes(20), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.CreateRecoveryCodes(c.ctx, actor(u), c.fresh(c.aUser)); err != nil {
		t.Fatal(err)
	}
	if len(c.audited(c.a.ID, "account.recovery_codes.create")) != 1 {
		t.Error("creation not audited")
	}
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

	// With a passkey as the second factor the codes stay while the passkey does.
	m := c.fresh(c.aManager)
	if err := c.svc.SetTOTP(c.ctx, m, secure.RandomBytes(20), 1); err != nil {
		t.Fatal(err)
	}
	pk := c.passkey(c.aManager, "k")
	if _, err := c.svc.CreateRecoveryCodes(c.ctx, actor(m), c.fresh(c.aManager)); err != nil {
		t.Fatal(err)
	}
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
