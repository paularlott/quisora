package service_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"golang.org/x/crypto/argon2"
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
	ok, err := e.svc.VerifyPassword(e.ctx, got, pw)
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
	if ok, err := e.svc.VerifyPassword(e.ctx, nil, "anything"); ok || err != nil {
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

// A master key rotation re-seals every password hash: once the previous key is gone everyone can still sign in.
func TestPasswordsReseal(t *testing.T) {
	e := newEnv(t)
	keyA, keyB := secure.RandomBytes(32), secure.RandomBytes(32)
	ring := func(keys ...[]byte) *secure.Sealer {
		r, err := secure.NewKeyring(keys[0], keys[1:]...)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	e.svc.Sealer.Replace(ring(keyA))
	acme := e.org("acme")
	alan, bob := e.user(acme.ID, "alan", model.RoleUser), e.user(acme.ID, "bob", model.RoleUser)
	for _, c := range []struct {
		u  *model.User
		pw string
	}{{alan, "alan's password"}, {bob, "bob's password!"}} {
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
	if !e.verify(alan, "alan's password") || !e.verify(bob, "bob's password!") {
		t.Error("a password no longer verifies after the rotation")
	}
	// had the previous key been removed before the re-seal, the password could not be checked (and is refused)
	e.setHash(bob, ring(keyA).SealFor(service.PasswordBinding(bob.ID), []byte(argonHash("bob's password!", 19*1024, 2))))
	if e.verify(bob, "bob's password!") {
		t.Error("a hash sealed with a key that is not configured verified")
	}
}
