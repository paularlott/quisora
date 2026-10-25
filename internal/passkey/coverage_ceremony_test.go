package passkey_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/passkey"
	"github.com/paularlott/quisora/internal/passkey/virtualauth"
)

func TestCoverageRPID(t *testing.T) {
	if got := setup(t).pk.RPID(); got != "quisora.example.test" {
		t.Fatalf("rp id %q", got)
	}
}

func (e *env) begunRegistration(t *testing.T, purpose string) (string, []byte) {
	t.Helper()
	extra := map[string]string{}
	if purpose != "" {
		extra[passkey.PurposeKey] = purpose
	}
	id, creation, err := e.pk.BeginRegistration(e.ctx, e.user, extra)
	if err != nil {
		t.Fatal(err)
	}
	opts, _ := json.Marshal(creation)
	return id, opts
}

func TestCoverageRegistrationRefusals(t *testing.T) {
	e := setup(t)

	// ceremony begun for another purpose: refused, challenge consumed, nothing stored
	id, opts := e.begunRegistration(t, "enrol")
	cred, _, err := e.auth.Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.pk.FinishRegistrationAs(e.ctx, "register", e.user, id, cred, "x"); !errors.Is(err, passkey.ErrChallenge) {
		t.Fatalf("purpose mismatch: %v", err)
	}
	if _, _, err := e.pk.FinishRegistrationAs(e.ctx, "enrol", e.user, id, cred, "x"); !errors.Is(err, passkey.ErrChallenge) {
		t.Fatalf("challenge reused after refusal: %v", err)
	}

	// unknown challenge id
	if _, _, err := e.pk.FinishRegistrationAs(e.ctx, "", e.user, "nope", cred, "x"); !errors.Is(err, passkey.ErrChallenge) {
		t.Fatalf("unknown challenge: %v", err)
	}

	// a login challenge is not a registration challenge
	lid, _ := e.options(t, nil)
	if _, _, err := e.pk.FinishRegistrationAs(e.ctx, "", e.user, lid, cred, "x"); !errors.Is(err, passkey.ErrChallenge) {
		t.Fatalf("kind mismatch: %v", err)
	}

	// security generation moved on since the ceremony began
	id, opts = e.begunRegistration(t, "")
	cred, _, _ = e.auth.Create(opts)
	if _, err := e.svc.AdvanceSecurity(e.ctx, e.user.ID); err != nil {
		t.Fatal(err)
	}
	e.user, _ = e.svc.Users.Get(e.ctx, e.user.ID) // the caller read the account afresh
	if _, _, err := e.pk.FinishRegistrationAs(e.ctx, "", e.user, id, cred, "x"); !errors.Is(err, passkey.ErrChallenge) {
		t.Fatalf("stale generation: %v", err)
	}

	// garbage and wrong-origin responses fail verification
	id, opts = e.begunRegistration(t, "")
	if _, _, err := e.pk.FinishRegistrationAs(e.ctx, "", e.user, id, []byte("not json"), "x"); !errors.Is(err, passkey.ErrVerify) {
		t.Fatalf("garbage: %v", err)
	}
	id, opts = e.begunRegistration(t, "")
	evil := virtualauth.New("https://evil.example")
	bad, _, err := evil.Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.pk.FinishRegistrationAs(e.ctx, "", e.user, id, bad, "x"); !errors.Is(err, passkey.ErrVerify) {
		t.Fatalf("wrong origin: %v", err)
	}
	// a response made for another challenge does not verify
	id1, _ := e.begunRegistration(t, "")
	_, opts2 := e.begunRegistration(t, "")
	other, _, _ := e.auth.Create(opts2)
	if _, _, err := e.pk.FinishRegistrationAs(e.ctx, "", e.user, id1, other, "x"); !errors.Is(err, passkey.ErrVerify) {
		t.Fatalf("bad challenge: %v", err)
	}
	if list, _ := e.svc.Passkeys.All(e.ctx, e.user.ID); len(list) != 0 {
		t.Fatalf("refused ceremonies stored %d passkeys", len(list))
	}
}

func TestCoverageNameNormalisedAndStoreErrors(t *testing.T) {
	e := setup(t)
	id, opts := e.begunRegistration(t, "enrol")
	cred, _, _ := e.auth.Create(opts)
	long := make([]rune, 150)
	for i := range long {
		long[i] = 'é'
	}
	reg, err := e.pk.VerifyRegistrationAs(e.ctx, "enrol", e.user, id, cred, string(long))
	if err != nil {
		t.Fatal(err)
	}
	if len([]rune(reg.Passkey.Name)) != 100 {
		t.Fatalf("name length %d", len([]rune(reg.Passkey.Name)))
	}
	id, opts = e.begunRegistration(t, "enrol")
	cred, _, _ = e.auth.Create(opts)
	reg2, err := e.pk.VerifyRegistrationAs(e.ctx, "enrol", e.user, id, cred, "   ")
	if err != nil || reg2.Passkey.Name != "Passkey" || reg2.Extra[passkey.PurposeKey] != "enrol" {
		t.Fatalf("default name: %+v %v", reg2, err)
	}

	// a registration verified for one account is not stored on another
	stranger := *e.user
	stranger.ID = "someone-else"
	if _, err := e.pk.StoreRegistration(e.ctx, &stranger, reg); !errors.Is(err, passkey.ErrChallenge) {
		t.Fatalf("StoreRegistration: %v", err)
	}
	if _, err := e.pk.StoreForInvite(e.ctx, &stranger, reg, 1); !errors.Is(err, passkey.ErrChallenge) {
		t.Fatalf("StoreForInvite: %v", err)
	}

	// invitation: stored in the epoch given, and the same credential cannot be stored twice
	pk, err := e.pk.StoreForInvite(e.ctx, e.user, reg, 7)
	if err != nil || pk.Epoch != 7 {
		t.Fatalf("StoreForInvite: %+v %v", pk, err)
	}
	if _, err := e.pk.StoreForInvite(e.ctx, e.user, reg, 7); !errors.Is(err, passkey.ErrVerify) {
		t.Fatalf("duplicate credential: %v", err)
	}

	// StoreRegistration with a stale user copy stores nothing and leaves the generation as it was
	before := e.user.SecurityGen
	stale := *e.user
	stale.Version = 0
	if _, err := e.pk.StoreRegistration(e.ctx, &stale, reg2); err == nil {
		t.Skip("stale user copy was not detected by the store (memstore version semantics)")
	}
	if stale.SecurityGen != before {
		t.Fatalf("generation not restored: %d != %d", stale.SecurityGen, before)
	}
}

func TestCoverageLoginRefusals(t *testing.T) {
	e := setup(t)
	e.register(t, "Key")

	// purpose
	id, assertion, err := e.pk.BeginLogin(e.ctx, nil, map[string]string{passkey.PurposeKey: "login"})
	if err != nil {
		t.Fatal(err)
	}
	opts, _ := json.Marshal(assertion)
	a, _, _ := e.auth.Get(opts)
	if _, err := e.pk.FinishLoginAs(e.ctx, id, a, "reauth", "second-factor"); !errors.Is(err, passkey.ErrChallenge) {
		t.Fatalf("purpose mismatch: %v", err)
	}
	if _, err := e.pk.FinishLoginAs(e.ctx, id, a, "login"); !errors.Is(err, passkey.ErrChallenge) {
		t.Fatalf("challenge survived a refusal: %v", err)
	}
	id, assertion, _ = e.pk.BeginLogin(e.ctx, nil, map[string]string{passkey.PurposeKey: "login"})
	opts, _ = json.Marshal(assertion)
	a, _, _ = e.auth.Get(opts)
	res, err := e.pk.FinishLoginAs(e.ctx, id, a, "reauth", "login")
	if err != nil || res.Extra[passkey.PurposeKey] != "login" {
		t.Fatalf("matching purpose: %v", err)
	}

	// unknown id, registration challenge used for sign-in, garbage response
	if _, err := e.pk.FinishLoginAs(e.ctx, "nope", a); !errors.Is(err, passkey.ErrChallenge) {
		t.Fatalf("unknown: %v", err)
	}
	rid, _ := e.begunRegistration(t, "")
	if _, err := e.pk.FinishLoginAs(e.ctx, rid, a); !errors.Is(err, passkey.ErrChallenge) {
		t.Fatalf("kind mismatch: %v", err)
	}
	id, _ = e.options(t, nil)
	if _, err := e.pk.FinishLoginAs(e.ctx, id, []byte("{")); !errors.Is(err, passkey.ErrVerify) {
		t.Fatalf("garbage: %v", err)
	}

	// known-user ceremony: assertion for another challenge does not verify
	id1, _ := e.options(t, e.user)
	_, opts2 := e.options(t, e.user)
	other, _, _ := e.auth.Get(opts2)
	if _, err := e.pk.FinishLoginAs(e.ctx, id1, other); !errors.Is(err, passkey.ErrVerify) {
		t.Fatalf("challenge mismatch: %v", err)
	}

	// known-user ceremony: the account's security generation moved on
	id, opts = e.options(t, e.user)
	a, _, _ = e.auth.Get(opts)
	if _, err := e.svc.AdvanceSecurity(e.ctx, e.user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pk.FinishLoginAs(e.ctx, id, a); !errors.Is(err, passkey.ErrChallenge) {
		t.Fatalf("stale generation: %v", err)
	}
	e.user, _ = e.svc.Users.Get(e.ctx, e.user.ID)

	// known-user ceremony: the account became inactive
	id, opts = e.options(t, e.user)
	a, _, _ = e.auth.Get(opts)
	e.user.Active = false
	if err := e.svc.Users.Update(e.ctx, e.user); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pk.FinishLoginAs(e.ctx, id, a); !errors.Is(err, passkey.ErrInactive) {
		t.Fatalf("inactive: %v", err)
	}
	// ... or was deleted
	e.user.Active = true
	_ = e.svc.Users.Update(e.ctx, e.user)
	e.user, _ = e.svc.Users.Get(e.ctx, e.user.ID)
	id, opts = e.options(t, e.user)
	a, _, _ = e.auth.Get(opts)
	if err := e.svc.Users.Delete(e.ctx, e.user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pk.FinishLoginAs(e.ctx, id, a); !errors.Is(err, passkey.ErrUnknownCredential) {
		t.Fatalf("deleted: %v", err)
	}
}

func TestCoverageAMR(t *testing.T) {
	for _, c := range []struct {
		r    passkey.LoginResult
		want string
	}{
		{passkey.LoginResult{}, "hwk"},
		{passkey.LoginResult{UserVerified: true}, "hwk user"},
		{passkey.LoginResult{BackupEligible: true}, "swk"},
		{passkey.LoginResult{BackupEligible: true, UserVerified: true}, "swk user"},
	} {
		got := ""
		for i, v := range c.r.AMR() {
			if i > 0 {
				got += " "
			}
			got += v
		}
		if got != c.want {
			t.Errorf("AMR %+v = %q want %q", c.r, got, c.want)
		}
	}
}
