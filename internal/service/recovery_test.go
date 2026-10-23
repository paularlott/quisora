package service_test

import (
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
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
	if ok, left := e.svc.ConsumeRecoveryCode(e.ctx, u, loose); !ok || left != 9 {
		t.Fatalf("first use: %v %d", ok, left)
	}
	if ok, _ := e.svc.ConsumeRecoveryCode(e.ctx, u, codes[0]); ok {
		t.Fatal("a code worked twice")
	}
	for _, bad := range []string{"", "nonsense", codes[1][:18], codes[1] + "X", "AAAA-AAAA-AAAA-AAAA"} {
		if ok, _ := e.svc.ConsumeRecoveryCode(e.ctx, u, bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	other := e.user(acme.ID, "bob", model.RoleUser)
	other.RecoveryCodes = u.RecoveryCodes // another user's codes (hashes salted with the user id) do not match
	if ok, _ := e.svc.ConsumeRecoveryCode(e.ctx, other, codes[1]); ok {
		t.Fatal("a code worked for another user")
	}

	// a new set: the old codes stop working, the count starts again
	fresh, err := e.svc.CreateRecoveryCodes(e.ctx, service.System, u)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = e.svc.Users.Get(e.ctx, u.ID)
	if ok, _ := e.svc.ConsumeRecoveryCode(e.ctx, u, codes[1]); ok {
		t.Fatal("an old code worked after a new set")
	}
	if ok, left := e.svc.ConsumeRecoveryCode(e.ctx, u, fresh[3]); !ok || left != 9 {
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
	if err := e.svc.ResetCredentials(e.ctx, u.ID, ""); err != nil {
		t.Fatal(err)
	}
	u, _ = e.svc.Users.Get(e.ctx, u.ID)
	if left, created := e.svc.RecoveryCodesLeft(e.ctx, u); left != 0 || created != nil {
		t.Fatalf("after reset: %d %v", left, created)
	}
	if ok, _ := e.svc.ConsumeRecoveryCode(e.ctx, u, fresh[4]); ok {
		t.Fatal("a code worked after the credentials were reset")
	}
}
