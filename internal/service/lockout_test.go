package service_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Locking a user out disables them and removes every way in; enabling them again brings none of it back.
func TestLockOutUser(t *testing.T) {
	e := newEnv(t)
	acme := e.org("acme")
	admin := e.user(acme.ID, "admin", model.RoleAdmin)
	alan := e.user(acme.ID, "alan", model.RoleUser)
	if _, err := e.svc.UpdateUser(e.ctx, service.System, alan.ID, service.UserInput{Password: ptr("correct horse battery")}); err != nil {
		t.Fatal(err)
	}
	sess := e.session(alan)
	e.grant(alan, sess.ID)
	tok := e.apiToken(alan)
	if err := e.svc.Passkeys.Create(e.ctx, &model.Passkey{UserID: alan.ID, OrgID: acme.ID, Name: "key"}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Identities.Create(e.ctx, &model.Identity{UserID: alan.ID, OrgID: acme.ID, ProviderID: "p1", Subject: "s1"}); err != nil {
		t.Fatal(err)
	}
	link, _, err := e.svc.CreateInvite(e.ctx, actor(admin), alan.ID)
	if err != nil {
		t.Fatal(err)
	}
	token := link[strings.Index(link, "token=")+6:]

	u, err := e.svc.LockOutUser(e.ctx, actor(admin), alan.ID, "laptop stolen")
	if err != nil {
		t.Fatal(err)
	}
	if u.Active || u.PasswordHash != "" || u.StatusChanged == nil || u.StatusChanged.Reason != "laptop stolen" {
		t.Errorf("user after lock-out: active %v, password %q, status %+v", u.Active, u.PasswordHash, u.StatusChanged)
	}
	count := func(n int, err error) int {
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	for name, n := range map[string]int{
		"sessions":   count(e.svc.Sessions.Count(e.ctx, alan.ID)),
		"grants":     count(e.svc.Grants.Count(e.ctx, alan.ID)),
		"passkeys":   count(e.svc.Passkeys.Count(e.ctx, alan.ID)),
		"identities": count(e.svc.Identities.Count(e.ctx, alan.ID)),
		"api tokens": count(e.svc.APITokens.Count(e.ctx, alan.ID)),
		"links":      count(e.svc.Links.Count(e.ctx, alan.ID)),
	} {
		if n != 0 {
			t.Errorf("%s left: %d", name, n)
		}
	}

	// enabled again: still no way in, until a new invitation
	if _, err := e.svc.UpdateUser(e.ctx, actor(admin), alan.ID, service.UserInput{Active: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if e.tokenLive(tok) {
		t.Error("the API token works again")
	}
	if _, _, err := e.svc.PeekLink(e.ctx, token, service.LinkInvite); err == nil {
		t.Error("the old invitation works again")
	}
	if got, _ := e.svc.Users.Get(e.ctx, alan.ID); got.PasswordHash != "" || got.TOTPSecret != "" {
		t.Error("a password or authenticator app came back")
	}
}

// Who may lock whom out: the rules of disabling someone and of removing their password.
func TestLockOutUserRules(t *testing.T) {
	e := newEnv(t)
	acme, globex := e.org("acme"), e.org("globex")
	admin, admin2 := e.user(acme.ID, "admin", model.RoleAdmin), e.user(acme.ID, "admin2", model.RoleAdmin)
	mgr, alan := e.user(acme.ID, "mgr", model.RoleManager), e.user(acme.ID, "alan", model.RoleUser)
	gadmin := e.user(globex.ID, "gadmin", model.RoleAdmin)
	peer := e.user(acme.ID, "peer", model.RoleUser)
	// admin2 is established: a password set, so it can sign in (an administrator's sign-in is reset only by a super admin)
	if _, err := e.svc.UpdateUser(e.ctx, service.System, admin2.ID, service.UserInput{Password: ptr("correct horse battery")}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		a      *service.Actor
		target string
		want   string
	}{
		{"a user", actor(alan), mgr.ID, "notfound"},
		{"a peer user", actor(peer), alan.ID, "notfound"},
		{"a manager on an administrator", actor(mgr), admin.ID, "forbidden"},
		{"another organization's admin", actor(gadmin), alan.ID, "notfound"},
		{"yourself", actor(admin), admin.ID, "invalid"},
		{"an admin on an established admin", actor(admin), admin2.ID, "invalid"},
	} {
		if _, err := e.svc.LockOutUser(e.ctx, c.a, c.target, "x"); outcome(err) != c.want {
			t.Errorf("%s: %v, want %s", c.name, err, c.want)
		}
		if got, _ := e.svc.Users.Get(e.ctx, c.target); !got.Active {
			t.Errorf("%s: a refused lock-out disabled the user", c.name)
		}
	}
	if _, err := e.svc.LockOutUser(e.ctx, actor(admin), "nobody", "x"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("an unknown user: %v", err)
	}
	if _, err := e.svc.LockOutUser(e.ctx, actor(mgr), alan.ID, ""); err != nil {
		t.Errorf("a manager on a user: %v", err)
	}
	if n := len(e.audited(acme.ID, "user.locked_out")); n != 1 {
		t.Errorf("%d lock-outs audited, want 1", n)
	}
	if _, err := e.svc.LockOutUser(e.ctx, actor(e.super), admin2.ID, "x"); err != nil {
		t.Errorf("a super admin on an established admin: %v", err)
	}
}
