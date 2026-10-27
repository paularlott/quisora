package passkey_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/passkey"
	"github.com/paularlott/quisora/internal/passkey/virtualauth"
	"github.com/paularlott/quisora/internal/service"
)

func TestRegistrationChallengeBinding(t *testing.T) {
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

	// garbage fails verification (a wrong-origin response: TestWrongOrigin)
	id, _ = e.begunRegistration(t, "")
	if _, _, err := e.pk.FinishRegistrationAs(e.ctx, "", e.user, id, []byte("not json"), "x"); !errors.Is(err, passkey.ErrVerify) {
		t.Fatalf("garbage: %v", err)
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

func TestStoredPasskeyNameAndAccountBinding(t *testing.T) {
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
		t.Fatalf("a stale user copy was not detected by the store")
	}
	if stale.SecurityGen != before {
		t.Fatalf("generation not restored: %d != %d", stale.SecurityGen, before)
	}
}

func TestLoginChallengeBinding(t *testing.T) {
	e := setup(t)
	e.register(t, "Key")

	// purpose
	id, assertion, err := e.pk.BeginLogin(e.ctx, nil, map[string]string{passkey.PurposeKey: "login", "org": e.user.OrgID})
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
	id, assertion, _ = e.pk.BeginLogin(e.ctx, nil, map[string]string{passkey.PurposeKey: "login", "org": e.user.OrgID})
	opts, _ = json.Marshal(assertion)
	a, _, _ = e.auth.Get(opts)
	res, err := e.pk.FinishLoginAs(e.ctx, id, a, "reauth", "login")
	if err != nil || res.Extra[passkey.PurposeKey] != "login" {
		t.Fatalf("matching purpose: %v", err)
	}

	// unknown id (a registration challenge for sign-in, and garbage: TestReplayedChallenge)
	if _, err := e.pk.FinishLoginAs(e.ctx, "nope", a); !errors.Is(err, passkey.ErrChallenge) {
		t.Fatalf("unknown: %v", err)
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

// secondOrgUser makes another organization with a user in it.
func (e *env) secondOrgUser(t *testing.T) (*model.Org, *model.User) {
	t.Helper()
	name, display, username, email, given, family := "second", "Second", "bob", "bob@example.com", "Bob", "Builder"
	org, err := e.svc.CreateOrg(e.ctx, service.System, service.OrgInput{Name: &name, DisplayName: &display})
	if err != nil {
		t.Fatal(err)
	}
	u, err := e.svc.CreateUser(e.ctx, service.System, org.ID, service.UserInput{Username: &username, Email: &email, GivenName: &given, FamilyName: &family})
	if err != nil {
		t.Fatal(err)
	}
	return org, u
}

// A credential id is unique per user: two users of different organizations may hold the same one (the same bytes,
// as an authenticator that gives every account one would), the same user may not hold it twice, and a discoverable
// sign-in of one organization refuses a credential whose user belongs to another.
func TestCredentialIDIsPerUserAndSignInStaysInItsOrganization(t *testing.T) {
	e := setup(t)
	org2, bob := e.secondOrgUser(t)
	orgs, err := e.svc.Orgs.Get(e.ctx, e.user.OrgID)
	if err != nil {
		t.Fatal(err)
	}

	// Alice registers; the registration names her account and her organization for the browser's picker.
	id, opts := e.begunRegistration(t, "")
	var co struct {
		PublicKey struct {
			User struct{ Name, DisplayName string } `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(opts, &co); err != nil {
		t.Fatal(err)
	}
	if want := e.user.Username + " · " + orgs.DisplayName; co.PublicKey.User.Name != want {
		t.Fatalf("user name %q, want %q", co.PublicKey.User.Name, want)
	}
	cred, _, err := e.auth.Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := e.pk.VerifyRegistrationAs(e.ctx, "", e.user, id, cred, "Alice's")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.pk.StoreForInvite(e.ctx, e.user, reg, e.user.CredEpoch); err != nil {
		t.Fatal(err)
	}

	// Bob registers the very same credential id and key, in his organization: allowed. The same user twice is not.
	same := *reg.Passkey
	same.ID, same.UserID, same.OrgID = "", bob.ID, org2.ID
	if _, err := e.pk.StoreForInvite(e.ctx, bob, &passkey.Registration{Passkey: &same}, bob.CredEpoch); err != nil {
		t.Fatalf("the same credential id in another organization: %v", err)
	}
	if _, err := e.pk.StoreForInvite(e.ctx, bob, &passkey.Registration{Passkey: &same}, bob.CredEpoch); !errors.Is(err, passkey.ErrVerify) {
		t.Fatalf("the same credential id of the same user: %v", err)
	}
	if _, err := e.pk.StoreForInvite(e.ctx, e.user, reg, e.user.CredEpoch); !errors.Is(err, passkey.ErrVerify) {
		t.Fatalf("the same credential id of the first user again: %v", err)
	}

	// Bob's own authenticator, registered for his account only.
	bobAuth := virtualauth.New(origin)
	bid, bcreation, err := e.pk.BeginRegistration(e.ctx, bob, nil)
	if err != nil {
		t.Fatal(err)
	}
	bopts, _ := json.Marshal(bcreation)
	bcred, _, err := bobAuth.Create(bopts)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.pk.FinishRegistrationAs(e.ctx, "", bob, bid, bcred, "Bob's"); err != nil {
		t.Fatal(err)
	}

	signIn := func(a *virtualauth.Authenticator, org string) error {
		id, assertion, err := e.pk.BeginLogin(e.ctx, nil, map[string]string{passkey.PurposeKey: "login", "org": org})
		if err != nil {
			t.Fatal(err)
		}
		o, _ := json.Marshal(assertion)
		resp, _, err := a.Get(o)
		if err != nil {
			t.Fatal(err)
		}
		_, err = e.pk.FinishLoginAs(e.ctx, id, resp, "login")
		return err
	}
	if err := signIn(bobAuth, org2.ID); err != nil {
		t.Fatalf("Bob at his organization: %v", err)
	}
	if err := signIn(bobAuth, e.user.OrgID); !errors.Is(err, passkey.ErrUnknownCredential) {
		t.Fatalf("Bob's credential at another organization's sign-in: %v", err)
	}
	if err := signIn(e.auth, e.user.OrgID); err != nil {
		t.Fatalf("Alice at her organization: %v", err)
	}
	if err := signIn(e.auth, org2.ID); !errors.Is(err, passkey.ErrUnknownCredential) {
		t.Fatalf("Alice's credential at another organization's sign-in: %v", err)
	}
}

// A user handle naming a user who does not hold the credential (a credential id registered by someone else, or a
// handle that is no user) is an unknown credential, not a verification failure of the real holder's.
func TestDiscoverableSignInChecksTheCredentialIsTheUsers(t *testing.T) {
	e := setup(t)
	_, bob := e.secondOrgUser(t)
	e.register(t, "Key")
	// An authenticator whose credential claims Bob's handle but whose id is not among Bob's passkeys.
	forged := virtualauth.New(origin)
	bid, bcreation, err := e.pk.BeginRegistration(e.ctx, bob, nil)
	if err != nil {
		t.Fatal(err)
	}
	bopts, _ := json.Marshal(bcreation)
	if _, _, err := forged.Create(bopts); err != nil {
		t.Fatal(err)
	}
	_ = bid // never finished: Bob holds no passkey
	id, opts := e.options(t, nil)
	a, _, err := forged.Get(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.pk.FinishLoginAs(e.ctx, id, a); !errors.Is(err, passkey.ErrUnknownCredential) {
		t.Fatalf("a credential its named user does not have: %v", err)
	}
	forged.Creds[0].UserHandle = []byte("no-such-user")
	id, opts = e.options(t, nil)
	a, _, _ = forged.Get(opts)
	if _, err := e.pk.FinishLoginAs(e.ctx, id, a); !errors.Is(err, passkey.ErrUnknownCredential) {
		t.Fatalf("a handle that names no user: %v", err)
	}
}
