package passkey_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/passkey"
	"github.com/paularlott/quisora/internal/passkey/virtualauth"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store/memstore"
)

const origin = "https://quisora.example.test"

type env struct {
	ctx  context.Context
	svc  *service.Service
	pk   *passkey.Service
	user *model.User
	auth *virtualauth.Authenticator
}

func setup(t testing.TB) *env {
	t.Helper()
	ctx := context.Background()
	cfg := config.Default()
	cfg.Server.PublicURL = origin
	cfg.Limits.PasswordWorkers = 2
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svc := service.New(cfg, memstore.New(), sealer)
	admin, _, err := svc.Bootstrap(ctx, "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	eph := ephemeral.NewLocal("n1")
	t.Cleanup(eph.Close)
	pk, err := passkey.New(cfg, svc, eph)
	if err != nil {
		t.Fatal(err)
	}
	return &env{ctx: ctx, svc: svc, pk: pk, user: admin, auth: virtualauth.New(origin)}
}

func (e *env) register(t testing.TB, name string) *virtualauth.Credential {
	t.Helper()
	id, creation, err := e.pk.BeginRegistration(e.ctx, e.user, map[string]string{"next": "/x"})
	if err != nil {
		t.Fatal(err)
	}
	opts, _ := json.Marshal(creation)
	cred, c, err := e.auth.Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	pk, extra, err := e.pk.FinishRegistrationAs(e.ctx, "", e.user, id, cred, name)
	if err != nil {
		t.Fatalf("finish registration: %v", err)
	}
	if extra["next"] != "/x" || pk.Name != name || len(pk.PublicKey) == 0 {
		t.Fatalf("bad passkey %+v extra %v", pk, extra)
	}
	return c
}

func (e *env) options(t testing.TB, u *model.User) (string, []byte) {
	t.Helper()
	id, assertion, err := e.pk.BeginLogin(e.ctx, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	opts, _ := json.Marshal(assertion)
	return id, opts
}

func TestRegisterAndDiscoverableLogin(t *testing.T) {
	e := setup(t)
	e.register(t, "Laptop")
	list, _ := e.svc.Passkeys.All(e.ctx, e.user.ID)
	if len(list) != 1 || !list[0].UserVerified || list[0].BackupEligible {
		t.Fatalf("stored passkey %+v", list)
	}

	id, opts := e.options(t, nil)
	if json.Unmarshal(opts, &struct{}{}); string(opts) == "" {
		t.Fatal("no options")
	}
	var o struct {
		PublicKey struct {
			AllowCredentials []any  `json:"allowCredentials"`
			UV               string `json:"userVerification"`
			RPID             string `json:"rpId"`
		} `json:"publicKey"`
	}
	_ = json.Unmarshal(opts, &o)
	if len(o.PublicKey.AllowCredentials) != 0 || o.PublicKey.UV != "required" || o.PublicKey.RPID != "quisora.example.test" {
		t.Fatalf("discoverable options: %s", opts)
	}
	assertion, _, err := e.auth.Get(opts)
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.pk.FinishLoginAs(e.ctx, id, assertion)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if res.User.ID != e.user.ID || !res.UserVerified {
		t.Fatalf("bad result %+v", res)
	}
	if got := res.AMR(); len(got) != 2 || got[0] != "hwk" || got[1] != "user" {
		t.Fatalf("amr %v", got)
	}
	list, _ = e.svc.Passkeys.All(e.ctx, e.user.ID)
	if list[0].SignCount != 1 || list[0].LastUsed.IsZero() {
		t.Fatalf("counter not stored: %+v", list[0])
	}
}

func TestKnownUserLogin(t *testing.T) {
	e := setup(t)
	e.register(t, "Key")
	other := virtualauth.New(origin)
	other.Creds = nil

	id, opts := e.options(t, e.user)
	var o struct {
		PublicKey struct {
			AllowCredentials []struct{ ID string } `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	_ = json.Unmarshal(opts, &o)
	if len(o.PublicKey.AllowCredentials) != 1 {
		t.Fatalf("expected allowCredentials: %s", opts)
	}
	assertion, _, err := e.auth.Get(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.pk.FinishLoginAs(e.ctx, id, assertion); err != nil {
		t.Fatalf("login: %v", err)
	}
	// A user with no passkeys cannot begin a known-user ceremony.
	noPK := &model.User{Meta: model.Meta{ID: "nobody"}}
	if _, _, err := e.pk.BeginLogin(e.ctx, noPK, nil); !errors.Is(err, passkey.ErrUnknownCredential) {
		t.Fatalf("want ErrUnknownCredential, got %v", err)
	}
}

func TestWrongOrigin(t *testing.T) {
	e := setup(t)
	c := e.register(t, "Key")
	id, opts := e.options(t, nil)
	bad, err := e.auth.GetWith(opts, c, 5, "https://evil.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.pk.FinishLoginAs(e.ctx, id, bad); !errors.Is(err, passkey.ErrVerify) {
		t.Fatalf("want ErrVerify, got %v", err)
	}
	// Registration from the wrong origin fails too.
	evil := virtualauth.New("https://evil.example")
	rid, creation, _ := e.pk.BeginRegistration(e.ctx, e.user, nil)
	ro, _ := json.Marshal(creation)
	cred, _, err := evil.Create(ro)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.pk.FinishRegistrationAs(e.ctx, "", e.user, rid, cred, "x"); !errors.Is(err, passkey.ErrVerify) {
		t.Fatalf("want ErrVerify, got %v", err)
	}
}

func TestReplayedChallenge(t *testing.T) {
	e := setup(t)
	e.register(t, "Key")
	id, opts := e.options(t, nil)
	assertion, _, _ := e.auth.Get(opts)
	if _, err := e.pk.FinishLoginAs(e.ctx, id, assertion); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pk.FinishLoginAs(e.ctx, id, assertion); !errors.Is(err, passkey.ErrChallenge) {
		t.Fatalf("replay: want ErrChallenge, got %v", err)
	}
	// A failed attempt also burns the challenge.
	id2, opts2 := e.options(t, nil)
	if _, err := e.pk.FinishLoginAs(e.ctx, id2, []byte(`{}`)); err == nil {
		t.Fatal("garbage accepted")
	}
	a2, _, _ := e.auth.Get(opts2)
	if _, err := e.pk.FinishLoginAs(e.ctx, id2, a2); !errors.Is(err, passkey.ErrChallenge) {
		t.Fatalf("burnt challenge reusable: %v", err)
	}
	// A login challenge cannot finish a registration and vice versa.
	rid, _, _ := e.pk.BeginRegistration(e.ctx, e.user, nil)
	if _, err := e.pk.FinishLoginAs(e.ctx, rid, assertion); !errors.Is(err, passkey.ErrChallenge) {
		t.Fatalf("cross-purpose: %v", err)
	}
	// Registration challenge is bound to the user who began it.
	rid2, _, _ := e.pk.BeginRegistration(e.ctx, e.user, nil)
	other := &model.User{Meta: model.Meta{ID: "someone-else"}}
	if _, _, err := e.pk.FinishRegistrationAs(e.ctx, "", other, rid2, []byte(`{}`), "x"); !errors.Is(err, passkey.ErrChallenge) {
		t.Fatalf("user binding: %v", err)
	}
}

func TestSignCountRegression(t *testing.T) {
	e := setup(t)
	c := e.register(t, "Key")
	for want := uint32(1); want <= 3; want++ {
		id, opts := e.options(t, nil)
		a, _, _ := e.auth.Get(opts)
		if _, err := e.pk.FinishLoginAs(e.ctx, id, a); err != nil {
			t.Fatalf("login %d: %v", want, err)
		}
	}
	// sessions signed in with this passkey (one of them may be the copy's holder's) and one signed in otherwise
	list0, _ := e.svc.Passkeys.All(e.ctx, e.user.ID)
	for i, pk := range []string{list0[0].ID, list0[0].ID, ""} {
		if err := e.svc.Sessions.Create(e.ctx, &model.Session{Meta: model.Meta{ID: fmt.Sprintf("s%d", i)}, UserID: e.user.ID,
			OrgID: e.user.OrgID, Passkey: pk, Expires: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	id, opts := e.options(t, nil)
	stale, err := e.auth.GetWith(opts, c, 2, origin)
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.pk.FinishLoginAs(e.ctx, id, stale)
	if !errors.Is(err, passkey.ErrCloneDetected) || res == nil || res.User.ID != e.user.ID {
		t.Fatalf("want ErrCloneDetected with user, got %v %v", res, err)
	}
	list, _ := e.svc.Passkeys.All(e.ctx, e.user.ID)
	if list[0].SignCount != 3 {
		t.Fatalf("counter moved to %d", list[0].SignCount)
	}
	// Every session the passkey signed in has ended; the other one stays.
	if left, _ := e.svc.Sessions.All(e.ctx, e.user.ID); len(left) != 1 || left[0].ID != "s2" {
		t.Fatalf("sessions after a clone warning: %d", len(left))
	}
	// The suspected clone is disabled: even the genuine authenticator no longer signs in with it.
	if !list[0].Disabled || list[0].Usable() {
		t.Fatalf("passkey not disabled after a clone warning: %+v", list[0])
	}
	id, opts = e.options(t, nil)
	a, _, _ := e.auth.Get(opts)
	if _, err := e.pk.FinishLoginAs(e.ctx, id, a); !errors.Is(err, passkey.ErrUnusable) {
		t.Fatalf("disabled passkey signed in: %v", err)
	}
	if _, _, err := e.pk.BeginLogin(e.ctx, e.user, nil); !errors.Is(err, passkey.ErrUnknownCredential) {
		t.Fatalf("a disabled passkey is still offered: %v", err)
	}
}

// A passkey registered without user verification (before registration required it) cannot sign in, and is not
// offered.
func TestLegacyUnverifiedPasskeyUnusable(t *testing.T) {
	e := setup(t)
	e.register(t, "Old key")
	list, _ := e.svc.Passkeys.All(e.ctx, e.user.ID)
	list[0].UserVerified = false
	if err := e.svc.Passkeys.Update(e.ctx, list[0]); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.svc.UsablePasskeys(e.ctx, e.user, ""); n != 0 {
		t.Fatalf("usable count %d", n)
	}
	id, opts := e.options(t, nil) // discoverable: the authenticator still offers it
	a, _, _ := e.auth.Get(opts)
	if _, err := e.pk.FinishLoginAs(e.ctx, id, a); !errors.Is(err, passkey.ErrUnusable) {
		t.Fatalf("unverified passkey signed in: %v", err)
	}
}

func TestZeroCounterSyncedPasskey(t *testing.T) {
	e := setup(t)
	e.auth.CounterStep = 0
	e.auth.BackupEligible, e.auth.BackupState = true, true
	e.register(t, "iCloud")
	for range 3 {
		id, opts := e.options(t, nil)
		a, _, _ := e.auth.Get(opts)
		res, err := e.pk.FinishLoginAs(e.ctx, id, a)
		if err != nil {
			t.Fatalf("zero counters must be accepted: %v", err)
		}
		if got := res.AMR(); got[0] != "swk" {
			t.Fatalf("synced key amr %v", got)
		}
	}
	list, _ := e.svc.Passkeys.All(e.ctx, e.user.ID)
	if !list[0].BackupEligible || !list[0].BackupState {
		t.Fatalf("backup flags not stored: %+v", list[0])
	}
}

func TestUserVerificationRequired(t *testing.T) {
	e := setup(t)
	e.register(t, "Key")
	e.auth.UserVerified = false
	id, opts := e.options(t, nil)
	a, _, _ := e.auth.Get(opts)
	if _, err := e.pk.FinishLoginAs(e.ctx, id, a); !errors.Is(err, passkey.ErrVerify) {
		t.Fatalf("login without UV accepted: %v", err)
	}
}

func TestExcludeAndDuplicate(t *testing.T) {
	e := setup(t)
	e.register(t, "Key")
	_, creation, _ := e.pk.BeginRegistration(e.ctx, e.user, nil)
	opts, _ := json.Marshal(creation)
	if _, _, err := e.auth.Create(opts); err == nil {
		t.Fatal("authenticator should refuse an excluded credential")
	}
}

func TestInactiveUser(t *testing.T) {
	e := setup(t)
	e.register(t, "Key")
	id, opts := e.options(t, nil)
	a, _, _ := e.auth.Get(opts)
	e.user.Active = false
	if err := e.svc.Users.Update(e.ctx, e.user); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pk.FinishLoginAs(e.ctx, id, a); !errors.Is(err, passkey.ErrInactive) {
		t.Fatalf("want ErrInactive, got %v", err)
	}
}

func TestUnknownCredentialAndIPHost(t *testing.T) {
	e := setup(t)
	e.register(t, "Key")
	// A different authenticator holding a credential the server has never seen.
	stranger := virtualauth.New(origin)
	_, creation, _ := e.pk.BeginRegistration(e.ctx, e.user, nil)
	ro, _ := json.Marshal(creation)
	if _, _, err := stranger.Create(ro); err != nil {
		t.Fatal(err)
	}
	id, opts := e.options(t, nil)
	a, _, err := stranger.Get(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.pk.FinishLoginAs(e.ctx, id, a); !errors.Is(err, passkey.ErrUnknownCredential) {
		t.Fatalf("want ErrUnknownCredential, got %v", err)
	}

	cfg := config.Default()
	cfg.Server.PublicURL = "https://127.0.0.1:8443"
	if _, err := passkey.New(cfg, e.svc, ephemeral.NewLocal("x")); err == nil {
		t.Fatal("an IP address is not a valid RP ID")
	}
}

func BenchmarkAssertionVerify(b *testing.B) {
	e := setup(b)
	e.auth.CounterStep = 1
	e.register(b, "Key")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		id, opts := e.options(b, nil)
		a, _, _ := e.auth.Get(opts)
		b.StartTimer()
		if _, err := e.pk.FinishLoginAs(e.ctx, id, a); err != nil {
			b.Fatal(err)
		}
	}
}

// Registration requires user verification, as sign-in does: a key that cannot verify its user (no PIN) is refused
// at registration rather than registering and never signing in.
func TestRegistrationRequiresUserVerification(t *testing.T) {
	e := setup(t)
	id, creation, err := e.pk.BeginRegistration(e.ctx, e.user, nil)
	if err != nil {
		t.Fatal(err)
	}
	opts, _ := json.Marshal(creation)
	var o struct {
		PublicKey struct {
			Sel struct {
				UV string `json:"userVerification"`
			} `json:"authenticatorSelection"`
		} `json:"publicKey"`
	}
	_ = json.Unmarshal(opts, &o)
	if o.PublicKey.Sel.UV != "required" {
		t.Fatalf("registration options ask for %q user verification", o.PublicKey.Sel.UV)
	}
	e.auth.UserVerified = false
	cred, _, err := e.auth.Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.pk.FinishRegistrationAs(e.ctx, "", e.user, id, cred, "No PIN"); !errors.Is(err, passkey.ErrVerify) {
		t.Fatalf("a credential without user verification was registered: %v", err)
	}
	if list, _ := e.svc.Passkeys.All(e.ctx, e.user.ID); len(list) != 0 {
		t.Fatalf("stored %d passkeys", len(list))
	}
}
