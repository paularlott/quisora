package service_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// argonHash is an argon2id hash of pw with the given settings, not yet sealed.
func argonHash(pw string, m, t uint32) string {
	salt := secure.RandomBytes(16)
	key := argon2.IDKey([]byte(pw), salt, t, m, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=1$%s$%s", m, t, base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

func (e *env) setHash(u *model.User, h string) *model.User {
	e.t.Helper()
	got, err := e.svc.Users.Get(e.ctx, u.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	got.PasswordHash = h
	if err := e.svc.Users.Update(e.ctx, got); err != nil {
		e.t.Fatal(err)
	}
	return got
}

func (e *env) stored(u *model.User) string {
	e.t.Helper()
	got, err := e.svc.Users.Get(e.ctx, u.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	return got.PasswordHash
}

func (e *env) verify(u *model.User, pw string) bool {
	e.t.Helper()
	got, err := e.svc.Users.Get(e.ctx, u.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	ok, err := e.svc.VerifyPassword(e.ctx, "", got, pw)
	if err != nil {
		e.t.Fatal(err)
	}
	return ok
}

// Passwords are stored as argon2id hashes sealed with the master key, bound to their user.
func TestPasswordsSealed(t *testing.T) {
	e := newEnv(t)
	acme := e.org("acme")
	alan, bob := e.user(acme.ID, "alan", model.RoleUser), e.user(acme.ID, "bob", model.RoleUser)
	if _, err := e.svc.UpdateUser(e.ctx, service.System, alan.ID, service.UserInput{Password: ptr("correct horse battery")}); err != nil {
		t.Fatal(err)
	}
	h := e.stored(alan)
	if !strings.HasPrefix(h, "v3:") || strings.Contains(h, "argon2") {
		t.Fatalf("stored in the clear: %q", h)
	}
	if !e.verify(alan, "correct horse battery") || e.verify(alan, "wrong") {
		t.Error("verify")
	}
	if ok, err := e.svc.VerifyPassword(e.ctx, "", nil, "anything"); ok || err != nil {
		t.Errorf("no user: %v %v", ok, err)
	}
	// copied onto another account, it opens nothing
	e.setHash(bob, h)
	if e.verify(bob, "correct horse battery") {
		t.Error("a hash copied onto another user verified")
	}
	// a user created with a password (the system, or an accepted invitation) gets a sealed hash bound to its id
	u, err := e.svc.CreateUser(e.ctx, service.System, acme.ID, service.UserInput{GivenName: ptr("C"), Username: ptr("carol"),
		Email: ptr("carol@example.com"), Password: ptr("correct horse battery")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u.PasswordHash, "v3:") || !e.verify(u, "correct horse battery") {
		t.Errorf("new user's hash: %q", u.PasswordHash)
	}
}

// A hash made with weaker settings is re-hashed with today's at the next sign-in; one naming settings out of range is
// refused, and so is one that is not sealed.
func TestPasswordUpgrades(t *testing.T) {
	e := newEnv(t)
	acme := e.org("acme")
	alan := e.user(acme.ID, "alan", model.RoleUser)
	seal := func(h string) string { return e.svc.SealPasswordHash(alan.ID, h) }

	current := seal(argonHash("pw one two three", 19*1024, 2))
	e.setHash(alan, current)
	if !e.verify(alan, "pw one two three") || e.stored(alan) != current {
		t.Error("a current hash was replaced")
	}

	e.setHash(alan, seal(argonHash("pw one two three", 12*1024, 1)))
	if !e.verify(alan, "pw one two three") {
		t.Fatal("a weaker hash does not verify")
	}
	inner, err := e.svc.Sealer.OpenFor(service.PasswordBinding(alan.ID), e.stored(alan))
	if err != nil || !strings.Contains(string(inner), "m=19456,t=2,p=1") {
		t.Errorf("not re-hashed with today's settings: %q %v", inner, err)
	}

	e.setHash(alan, seal("$argon2id$v=19$m=4194304,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaA"))
	if e.verify(alan, "pw one two three") {
		t.Error("a hash out of range verified")
	}
	e.setHash(alan, argonHash("pw one two three", 19*1024, 2))
	if e.verify(alan, "pw one two three") {
		t.Error("an unsealed hash verified")
	}
}

// A master key rotation re-seals every secret the service holds: once the previous key is gone everyone can still
// sign in and the upstream refresh tokens still open.
func TestResealSecrets(t *testing.T) {
	ring := func(keys ...[]byte) *secure.Sealer {
		r, err := secure.NewKeyring(keys[0], keys[1:]...)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	t.Run("password", func(t *testing.T) {
		e := newEnv(t)
		keyA, keyB := secure.RandomBytes(32), secure.RandomBytes(32)
		e.svc.Sealer.Replace(ring(keyA))
		acme := e.org("acme")
		alan, bob := e.user(acme.ID, "alan", model.RoleUser), e.user(acme.ID, "bob", model.RoleUser)
		for _, c := range []struct {
			u  *model.User
			pw string
		}{{alan, "first sealed passphrase"}, {bob, "second sealed passphrase!"}} {
			if _, err := e.svc.UpdateUser(e.ctx, service.System, c.u.ID, service.UserInput{Password: ptr(c.pw)}); err != nil {
				t.Fatal(err)
			}
		}

		// rotate: key B active, key A previous; re-seal; then key A is removed
		e.svc.Sealer.Replace(ring(keyB, keyA))
		res, err := e.svc.ResealSecrets(e.ctx, 1000)
		if err != nil || !res.Done() || res.Resealed != 2 {
			t.Fatalf("re-seal after the rotation: %+v %v", res, err)
		}
		e.svc.Sealer.Replace(ring(keyB))
		if !e.verify(alan, "first sealed passphrase") || !e.verify(bob, "second sealed passphrase!") {
			t.Error("a password no longer verifies after the rotation")
		}
		// had the previous key been removed before the re-seal, the password could not be checked (and is refused)
		e.setHash(bob, ring(keyA).SealFor(service.PasswordBinding(bob.ID), []byte(argonHash("second sealed passphrase!", 19*1024, 2))))
		if e.verify(bob, "second sealed passphrase!") {
			t.Error("a hash sealed with a key that is not configured verified")
		}
	})

	t.Run("identity_refresh_token", func(t *testing.T) {
		e := newEnv(t)
		oldKey, newKey := secure.RandomBytes(32), secure.RandomBytes(32)
		old, _ := secure.NewSealer(oldKey)
		e.svc.Sealer.Replace(old)
		u := e.user(e.primary.ID, "alan", model.RoleUser)
		p, _ := e.svc.CreateProvider(e.ctx, service.System, e.primary.ID, goodProvider("sso"))
		id := model.NewIdentity(u, p, "sub", "", "admin")
		if err := e.svc.Identities.Create(e.ctx, id); err != nil {
			t.Fatal(err)
		}
		id.Refresh = old.SealFor(service.IdentityRefreshBinding(id.ID), []byte("upstream-refresh"))
		if err := e.svc.Identities.Update(e.ctx, id); err != nil {
			t.Fatal(err)
		}
		e.svc.Sealer.Replace(ring(newKey, oldKey))
		// a dry run (status) only counts
		st, _ := e.svc.RotationStatus(e.ctx)
		if st.Stale < 1 {
			t.Fatalf("stale not counted: %+v", st)
		}
		if got, _ := e.svc.Identities.Get(e.ctx, id.ID); got.Refresh != id.Refresh {
			t.Error("status rewrote a secret")
		}
		if r, err := e.svc.ResealSecrets(e.ctx, 100); err != nil || r.Resealed < 1 || !r.Done() {
			t.Fatalf("reseal %+v %v", r, err)
		}
		only, _ := secure.NewSealer(newKey)
		got, _ := e.svc.Identities.Get(e.ctx, id.ID)
		if v, err := only.OpenFor(service.IdentityRefreshBinding(id.ID), got.Refresh); err != nil || string(v) != "upstream-refresh" {
			t.Errorf("identity refresh token: %q %v", v, err)
		}
	})
}

// Users created with a bcrypt (or argon2id) hash from another system: only by the system or a super admin (a token
// only with the import scope), only at creation, only valid hashes; the first sign-in re-hashes it with argon2id.
func TestImportPasswordHash(t *testing.T) {
	e := newEnv(t)
	acme := e.org("acme")
	admin := e.user(acme.ID, "admin", model.RoleAdmin)
	bc, err := bcrypt.GenerateFromPassword([]byte("old system password"), 10)
	if err != nil {
		t.Fatal(err)
	}
	in := func(name, hash string) service.UserInput {
		return service.UserInput{GivenName: ptr("I"), Username: ptr(name), Email: ptr(name + "@example.com"), PasswordHash: ptr(hash)}
	}
	superTok := func(scopes ...string) *service.Actor {
		a := *actor(e.super)
		a.Unscoped, a.Scopes = false, scopes
		return &a
	}
	for _, c := range []struct {
		name string
		a    *service.Actor
		in   service.UserInput
	}{
		{"an organization's admin", actor(admin), in("i1", string(bc))},
		{"a super admin's token without import", superTok(service.ScopeAdmin), in("i2", string(bc))},
		{"not a supported hash", actor(e.super), in("i3", "$1$md5$abc")},
		{"bcrypt cost too high", actor(e.super), in("i4", "$2b$31$"+string(bc)[7:])},
		{"a password and a hash", actor(e.super), func() service.UserInput { x := in("i5", string(bc)); x.Password = ptr("x y z w v u"); return x }()},
	} {
		if _, err := e.svc.CreateUser(e.ctx, c.a, acme.ID, c.in); outcome(err) != "invalid" {
			t.Errorf("%s: %v", c.name, err)
		}
	}

	u, err := e.svc.CreateUser(e.ctx, superTok(service.ScopeAdmin, service.ScopeImport), acme.ID, in("imported", string(bc)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u.PasswordHash, "v3:") {
		t.Fatalf("stored unsealed: %q", u.PasswordHash)
	}
	if inner, _ := e.svc.Sealer.OpenFor(service.PasswordBinding(u.ID), u.PasswordHash); string(inner) != string(bc) {
		t.Fatal("the imported hash is not what was stored")
	}
	if e.verify(u, "wrong") {
		t.Error("a wrong password verified")
	}
	if !e.verify(u, "old system password") {
		t.Fatal("the imported password does not verify")
	}
	inner, _ := e.svc.Sealer.OpenFor(service.PasswordBinding(u.ID), e.stored(u))
	if !strings.HasPrefix(string(inner), "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("not re-hashed with argon2id at the first sign-in: %q", inner)
	}
	if !e.verify(u, "old system password") {
		t.Error("the re-hashed password does not verify")
	}

	// never on an update: an existing account could be taken over
	if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{PasswordHash: ptr(string(bc))}); outcome(err) != "invalid" {
		t.Errorf("hash on an update: %v", err)
	}
	// an argon2id hash from another system is accepted too
	if _, err := e.svc.CreateUser(e.ctx, service.System, acme.ID, in("a2", argonHash("pw pw pw pw", 19*1024, 2))); err != nil {
		t.Errorf("argon2id import: %v", err)
	}
}

// A user created with a SHA-512 crypt hash (what PHP's crypt() made in the system they come from) signs in with the
// password they had, and the hash is then argon2id; hashes asking for too many rounds are refused at creation.
func TestImportSHA512CryptHash(t *testing.T) {
	e := newEnv(t)
	acme := e.org("acme")
	const hash = "$6$aZ09./aZ09./aZ09$JNpuOzbJHWS6aFNixpRZk4jTQsizfyAu/UAR2aRai8mCqPKjtRvYsUsCOajeqcNfK.UM.Qc9hpmXeM8kHaatU0"
	in := func(name, hash string) service.UserInput {
		return service.UserInput{GivenName: ptr("I"), Username: ptr(name), Email: ptr(name + "@example.com"), PasswordHash: ptr(hash)}
	}
	if _, err := e.svc.CreateUser(e.ctx, service.System, acme.ID, in("too-many", "$6$rounds=1000001$"+hash[3:])); outcome(err) != "invalid" {
		t.Errorf("rounds over the cap: %v", err)
	}
	u, err := e.svc.CreateUser(e.ctx, service.System, acme.ID, in("php", hash))
	if err != nil {
		t.Fatal(err)
	}
	if e.verify(u, "wrong horse battery") {
		t.Error("a wrong password verified")
	}
	if inner, _ := e.svc.Sealer.OpenFor(service.PasswordBinding(u.ID), e.stored(u)); string(inner) != hash {
		t.Error("a wrong password changed the stored hash")
	}
	if !e.verify(u, "correct horse battery") {
		t.Fatal("the imported password does not verify")
	}
	inner, _ := e.svc.Sealer.OpenFor(service.PasswordBinding(u.ID), e.stored(u))
	if !strings.HasPrefix(string(inner), "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("not re-hashed with argon2id at the first sign-in: %q", inner)
	}
	if !e.verify(u, "correct horse battery") {
		t.Error("the re-hashed password does not verify")
	}
}

// A password is checked for length (limits.password_min_length: 15 by default, NIST SP 800-63B rev 4, where a password
// may be the only factor; lower where the operator sets it, as the development server does with 10), for being easy to
// guess, and for being built on what identifies its owner.
func TestCheckPassword(t *testing.T) {
	t.Run("length", func(t *testing.T) {
		e := newEnv(t)
		u := e.user(e.primary.ID, "len", model.RoleUser)
		if got := e.svc.Cfg.Limits.PasswordMinLength; got != 15 {
			t.Fatalf("default %d", got)
		}
		if err := e.svc.CheckPassword(e.ctx, u, "fourteen chars"); !errors.Is(err, service.ErrInvalid) {
			t.Fatalf("14 characters accepted by default: %v", err)
		}
		if err := e.svc.CheckPassword(e.ctx, u, "violet maple ox"); err != nil {
			t.Fatalf("15 characters refused: %v", err)
		}
		e.svc.Cfg.Limits.PasswordMinLength = 10
		if err := e.svc.CheckPassword(e.ctx, u, "violet oak"); err != nil {
			t.Fatalf("10 characters refused with the minimum at 10: %v", err)
		}
	})

	t.Run("easy_to_guess", func(t *testing.T) {
		personal := []string{"Alice", "Example", "alice.smith", "Acme Corp", "Quisora"}
		weak := []string{
			"aaaaaaaaaaaa", "abababababab", "1212121212", // too few characters, repeats
			"1234567890", "abcdefghijk", "qwertyuiop", "asdfghjkl;'", "0987654321", "1qaz2wsx3edc", "zyxwvutsrq", // runs
			"Password2026!", "P@ssw0rd123", "welcome1!!!", "Summ3r2025", "!!Letmein99", "Qwerty12345", "iloveyou12", // common
			"Alice2026!!", "smith-rocks-99", "quisora12345", "Acme2026Corp", // personal
		}
		strong := []string{
			"correct horse battery staple", "a long enough password", "Tr0ub4dor&3xyz", "8475920193",
			"purple-elephant-dances", "Ma ternelle! 1999", "zh7#Lq2!pVw9", "alicorn meadows",
		}
		for _, pw := range weak {
			if service.WeakPassword(pw, personal) == "" {
				t.Errorf("%q accepted", pw)
			}
		}
		for _, pw := range strong {
			if why := service.WeakPassword(pw, personal); why != "" {
				t.Errorf("%q refused: %s", pw, why)
			}
		}
	})

	t.Run("built_on_what_identifies_the_user", func(t *testing.T) {
		// Each password is long and unrelated to anything common, and is refused only for the user it names: the
		// given and family name, the username, the parts of the address and the organization's names are all words
		// it must not be built on.
		e := newEnv(t)
		org, err := e.svc.CreateOrg(e.ctx, service.System, service.OrgInput{Name: ptr("marmot-works"), DisplayName: ptr("Marmot Works Ltd")})
		if err != nil {
			t.Fatal(err)
		}
		u, err := e.svc.CreateUser(e.ctx, service.System, org.ID, service.UserInput{GivenName: ptr("Zephyr"), FamilyName: ptr("Quokkason"),
			Username: ptr("zq-user"), Email: ptr("wombat.local@kiwicorp.example")})
		if err != nil {
			t.Fatal(err)
		}
		stranger := e.user(e.primary.ID, "someone", model.RoleUser)
		for name, pw := range map[string]string{
			"given name":      "zephyr rides over rivers",
			"family name":     "the quokkason family sings",
			"address name":    "my wombat naps at noon",
			"address host":    "visit the kiwicorp offices",
			"organization":    "marmot works is far away",
			"leet-speak name": "z3phyr rides over rivers",
		} {
			if err := e.svc.CheckPassword(e.ctx, u, pw); !errors.Is(err, service.ErrInvalid) {
				t.Errorf("%s: %q accepted for the user it names: %v", name, pw, err)
			}
			if err := e.svc.CheckPassword(e.ctx, stranger, pw); err != nil {
				t.Errorf("%s: %q refused for someone else: %v", name, pw, err)
			}
		}
	})
}

func TestUserPasswordHashAndSessions(t *testing.T) {
	c := newCast(t)
	// Admins cannot set passwords, at creation or later: only the system can (an accepted invitation does).
	if _, err := c.svc.CreateUser(c.ctx, actor(c.aAdmin), c.a.ID, service.UserInput{GivenName: ptr("T"), Username: ptr("pw0"), Email: ptr("pw0@example.com"), Password: ptr("correct horse battery")}); !errors.As(err, new(*service.FieldError)) {
		t.Fatalf("admin created a user with a password: %v", err)
	}
	u, err := c.svc.CreateUser(c.ctx, service.System, c.a.ID, service.UserInput{GivenName: ptr("T"), Username: ptr("pw"), Email: ptr("pw@example.com"), Password: ptr("correct horse battery")})
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.svc.VerifyPassword(c.ctx, "", u, "correct horse battery")
	if err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	// Sessions, grants and tokens of a user die with a disable.
	sess := &model.Session{Meta: model.Meta{ID: "sess-" + u.ID}, UserID: u.ID, OrgID: u.OrgID}
	if err := c.svc.Sessions.Create(c.ctx, sess); err != nil {
		t.Fatal(err)
	}
	grant := &model.Grant{UserID: u.ID, OrgID: u.OrgID}
	if err := c.svc.Grants.Create(c.ctx, grant); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.aAdmin), u.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.Sessions.Get(c.ctx, sess.ID); !errors.Is(err, store.ErrNotFound) {
		t.Error("session survived disable")
	}
	if _, err := c.svc.Grants.Get(c.ctx, grant.ID); !errors.Is(err, store.ErrNotFound) {
		t.Error("grant survived disable")
	}
	// Password reset by someone else ends sessions; by the user themselves it keeps them.
	sess2 := &model.Session{Meta: model.Meta{ID: "sess2-" + u.ID}, UserID: u.ID, OrgID: u.OrgID}
	_ = c.svc.Sessions.Create(c.ctx, sess2)
	if _, err := c.svc.UpdateUser(service.SelfService(c.ctx), actor(u), u.ID, service.UserInput{Password: ptr("another-long-password")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.Sessions.Get(c.ctx, sess2.ID); err != nil {
		t.Error("own password change ended own session")
	}
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.aAdmin), u.ID, service.UserInput{Password: ptr("admin-reset-password")}); err == nil {
		t.Fatal("an admin set someone's password")
	}
	if _, err := c.svc.Sessions.Get(c.ctx, sess2.ID); err != nil {
		t.Error("a refused password change ended a session")
	}
	// The system (an accepted invitation or reset link) sets a password and ends every session.
	if _, err := c.svc.UpdateUser(c.ctx, service.System, u.ID, service.UserInput{Password: ptr("link-chosen-password")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.Sessions.Get(c.ctx, sess2.ID); !errors.Is(err, store.ErrNotFound) {
		t.Error("system password set kept session")
	}
}

func TestRemovePasswordEndsAccess(t *testing.T) {
	c := newCast(t)
	u, err := c.svc.CreateUser(c.ctx, service.System, c.a.ID, service.UserInput{GivenName: ptr("T"), Username: ptr("pw"), Email: ptr("pw@example.com"), Password: ptr("correct horse battery")})
	if err != nil {
		t.Fatal(err)
	}
	sess := &model.Session{Meta: model.Meta{ID: "sess-" + u.ID}, UserID: u.ID, OrgID: u.OrgID}
	if err := c.svc.Sessions.Create(c.ctx, sess); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.RemovePassword(c.ctx, actor(c.aAdmin), u.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := c.svc.Users.Get(c.ctx, u.ID)
	if got.PasswordHash != "" {
		t.Fatal("password still set")
	}
	if _, err := c.svc.Sessions.Get(c.ctx, sess.ID); err == nil {
		t.Fatal("session survived")
	}
	// Idempotent, and nobody removes their own password here.
	if err := c.svc.RemovePassword(c.ctx, actor(c.aAdmin), u.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.RemovePassword(c.ctx, actor(c.aAdmin), c.aAdmin.ID); err == nil {
		t.Fatal("removed own password")
	}
	if _, _, err := c.svc.CreateInvite(c.ctx, actor(c.aAdmin), c.aAdmin.ID); err == nil {
		t.Fatal("invited self")
	}
}
