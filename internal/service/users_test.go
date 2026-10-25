package service_test

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestSelfGuards(t *testing.T) {
	c := newCast(t)
	for _, ac := range c.actors() {
		a := actor(ac.u)
		// Nobody changes their own role.
		other := model.RoleUser
		if ac.u.Role == model.RoleUser {
			other = model.RoleManager
		}
		_, err := c.svc.UpdateUser(c.ctx, a, ac.u.ID, service.UserInput{Role: &other})
		if err == nil {
			t.Errorf("%s changed own role", ac.name)
		}
		// Nobody disables themselves.
		_, err = c.svc.UpdateUser(c.ctx, a, ac.u.ID, service.UserInput{Active: ptr(false)})
		if err == nil {
			t.Errorf("%s disabled self", ac.name)
		}
		// Nobody deletes themselves.
		err = c.svc.DeleteUser(c.ctx, a, ac.u.ID)
		if !errors.Is(err, service.ErrInvalid) {
			t.Errorf("%s delete self: %v", ac.name, err)
		}
		u, _ := c.svc.Users.Get(c.ctx, ac.u.ID)
		if u == nil || u.Role != ac.u.Role || !u.Active {
			t.Errorf("%s was modified", ac.name)
		}
		// Re-submitting the unchanged role is harmless for those allowed to edit.
		same := ac.u.Role
		if _, err := c.svc.UpdateUser(c.ctx, a, ac.u.ID, service.UserInput{Role: &same}); err != nil && ac.u.Role != model.RoleUser && ac.u.Role != model.RoleManager {
			t.Errorf("%s resubmit own role: %v", ac.name, err)
		}
	}
}

func TestSelfServiceProfile(t *testing.T) {
	c := newCast(t)
	// A plain user may edit their profile and password, but nothing privileged.
	u := actor(c.aUser)
	got, err := c.svc.UpdateUser(service.SelfService(c.ctx), u, c.aUser.ID, service.UserInput{FamilyName: ptr("Me"),
		GivenName: ptr("A"), Password: ptr("my-new-password-1")})
	if err != nil || got.FamilyName != "Me" || got.PasswordHash == "" {
		t.Fatalf("self update: %v %+v", err, got)
	}
	for name, in := range map[string]service.UserInput{
		"username": {Username: ptr("renamed")},
		"active":   {Active: ptr(false)}, // a value equal to the stored one is no change (a whole-form save)
		"external": {ExternalID: ptr("x")},
		"verified": {Verified: ptr(true)},
		"tags":     {Tags: tags("a")},
		"role":     {Role: ptr(model.RoleAdmin)},
	} {
		if _, err := c.svc.UpdateUser(c.ctx, u, c.aUser.ID, in); err == nil {
			t.Errorf("plain user could set %s", name)
		}
	}
	// A manager editing their own profile.
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.aManager), c.aManager.ID, service.UserInput{FamilyName: ptr("Boss")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.aManager), c.aManager.ID, service.UserInput{Role: ptr(model.RoleAdmin)}); err == nil {
		t.Fatal("manager promoted self")
	}
}

// Organizations need no administrator (super admins administer every one): an organization's last administrator can
// be demoted, disabled or deleted.
func TestLastOrgAdminNotProtected(t *testing.T) {
	c := newCast(t)
	org := c.org("solo")
	for _, change := range []service.UserInput{{Role: ptr(model.RoleUser)}, {Active: ptr(false)}} {
		only := c.user(org.ID, c.next("only"), model.RoleAdmin)
		if _, err := c.svc.UpdateUser(c.ctx, actor(c.super), only.ID, change); err != nil {
			t.Errorf("change of the last admin %+v: %v", change, err)
		}
	}
	only := c.user(org.ID, "last", model.RoleAdmin)
	if err := c.svc.DeleteUser(c.ctx, actor(c.super), only.ID); err != nil {
		t.Errorf("delete the last admin: %v", err)
	}
}

// Deactivating a super admin (disabling, locking out, or an end date in the past) is refused when fewer usable super
// admins than the server keeps would remain: one, or two in a gossip cluster.
func TestSuperAdminDeactivationThreshold(t *testing.T) {
	c := newCast(t)
	ghost := &service.Actor{UserID: "someone-else", OrgID: c.primary.ID, Role: model.RoleSuperAdmin, Name: "ghost"}
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	deactivations := map[string]func(id string) error{
		"disable": func(id string) error {
			_, err := c.svc.UpdateUser(c.ctx, ghost, id, service.UserInput{Active: ptr(false)})
			return err
		},
		"lock out": func(id string) error { _, err := c.svc.LockOutUser(c.ctx, ghost, id, "x"); return err },
		"end date": func(id string) error {
			_, err := c.svc.UpdateUser(c.ctx, ghost, id, service.UserInput{ValidUntil: ptr(past)})
			return err
		},
	}
	// one super admin: none of them
	for name, f := range deactivations {
		if err := f(c.super.ID); !errors.Is(err, service.ErrLastAdmin) {
			t.Errorf("%s the only super admin: %v", name, err)
		}
	}
	// a gossip cluster keeps two: with two, still none
	c.svc.MinSuperAdmins = 2
	s2 := c.user(c.primary.ID, "s2", model.RoleSuperAdmin)
	for name, f := range deactivations {
		if err := f(s2.ID); !errors.Is(err, service.ErrLastAdmin) {
			t.Errorf("%s one of two super admins in a gossip cluster: %v", name, err)
		}
	}
	if got, _ := c.svc.Users.Get(c.ctx, s2.ID); !got.Active || got.ValidUntil != nil {
		t.Error("a refused deactivation changed the super admin")
	}
	// with three, one may go
	c.user(c.primary.ID, "s3", model.RoleSuperAdmin)
	if err := deactivations["disable"](s2.ID); err != nil {
		t.Errorf("disable one of three super admins in a gossip cluster: %v", err)
	}
}

// The server keeps as many super admins as it needs (Service.MinSuperAdmins): two in a gossip cluster, and the error
// says so.
func TestMinSuperAdmins(t *testing.T) {
	c := newCast(t)
	c.svc.MinSuperAdmins = 2
	s2 := c.user(c.primary.ID, "s2", model.RoleSuperAdmin)
	s3 := c.user(c.primary.ID, "s3", model.RoleSuperAdmin)
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.super), s3.ID, service.UserInput{Role: ptr(model.RoleAdmin)}); err != nil {
		t.Fatalf("three super admins, one demoted: %v", err)
	}
	_, err := c.svc.UpdateUser(c.ctx, actor(c.super), s2.ID, service.UserInput{Role: ptr(model.RoleAdmin)})
	if !errors.Is(err, service.ErrLastAdmin) || !strings.Contains(err.Error(), "at least 2 super admins") {
		t.Fatalf("two super admins in a gossip cluster: %v", err)
	}
	c.svc.MinSuperAdmins = 0
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.super), s2.ID, service.UserInput{Role: ptr(model.RoleAdmin)}); err != nil {
		t.Fatalf("one super admin is enough without gossip: %v", err)
	}
	ghost := &service.Actor{UserID: "someone-else", OrgID: c.primary.ID, Role: model.RoleSuperAdmin, Name: "ghost"}
	_, err = c.svc.UpdateUser(c.ctx, ghost, c.super.ID, service.UserInput{Role: ptr(model.RoleAdmin)})
	if !errors.Is(err, service.ErrLastAdmin) || !strings.Contains(err.Error(), "last super admin") {
		t.Fatalf("the last super admin: %v", err)
	}
}

func TestLastSuperAdminProtection(t *testing.T) {
	c := newCast(t)
	super2 := c.user(c.primary.ID, "super2", model.RoleSuperAdmin)
	// Two supers: one may demote the other.
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.super), super2.ID, service.UserInput{Role: ptr(model.RoleAdmin)}); err != nil {
		t.Fatalf("demote second super: %v", err)
	}
	// Now only one super admin remains: a (hypothetical) second actor with the super role cannot remove it.
	ghost := &service.Actor{UserID: "someone-else", OrgID: c.primary.ID, Role: model.RoleSuperAdmin, Name: "ghost"}
	if _, err := c.svc.UpdateUser(c.ctx, ghost, c.super.ID, service.UserInput{Role: ptr(model.RoleAdmin)}); !errors.Is(err, service.ErrLastAdmin) {
		t.Errorf("demote last super: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, ghost, c.super.ID, service.UserInput{Active: ptr(false)}); !errors.Is(err, service.ErrLastAdmin) {
		t.Errorf("disable last super: %v", err)
	}
	if err := c.svc.DeleteUser(c.ctx, ghost, c.super.ID); !errors.Is(err, service.ErrLastAdmin) {
		t.Errorf("delete last super: %v", err)
	}
}

func TestClientActorCannotGrantAdmin(t *testing.T) {
	c := newCast(t)
	cl, _, err := c.svc.CreateClient(c.ctx, actor(c.super), c.a.ID, service.ClientInput{Name: ptr("scim"), SCIM: ptr(true),
		RedirectURIs: ptr([]string{"https://x.example.com/cb"})})
	if err != nil {
		t.Fatal(err)
	}
	a := service.ActorForClient(cl, "1.2.3.4")
	if a.Role != model.RoleAdmin || !a.HasScope(service.ScopeSCIM) || a.HasScope(service.ScopeAdmin) || a.ClientID != cl.ID {
		t.Fatalf("unexpected client actor %+v", a)
	}
	n := c.next("c")
	if _, err := c.svc.CreateUser(c.ctx, a, c.a.ID, service.UserInput{GivenName: gn("T"), Username: &n, Email: ptr(n + "@example.com"), Role: ptr(model.RoleAdmin)}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("client created admin: %v", err)
	}
	if _, err := c.svc.CreateUser(c.ctx, a, c.a.ID, service.UserInput{GivenName: gn("T"), Username: &n, Email: ptr(n + "@example.com"), Role: ptr(model.RoleSuperAdmin)}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("client created super: %v", err)
	}
	m, err := c.svc.CreateUser(c.ctx, a, c.a.ID, service.UserInput{GivenName: gn("T"), Username: &n, Email: ptr(n + "@example.com"), Role: ptr(model.RoleManager)})
	if err != nil {
		t.Fatalf("client creating manager: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, a, m.ID, service.UserInput{Role: ptr(model.RoleAdmin)}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("client promoted to admin: %v", err)
	}
	// Other org is out of reach.
	n2 := c.next("c")
	if _, err := c.svc.CreateUser(c.ctx, a, c.b.ID, service.UserInput{GivenName: gn("T"), Username: &n2, Email: ptr(n2 + "@example.com")}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("client in other org: %v", err)
	}
	// Groups are fine (admin of its org).
	if _, err := c.svc.CreateGroup(c.ctx, a, c.a.ID, service.GroupInput{DisplayName: ptr("g")}); err != nil {
		t.Errorf("client group: %v", err)
	}
	// A client actor has no user id so it can neither mint nor list API tokens.
	if _, _, err := c.svc.CreateAPIToken(c.ctx, a, service.APITokenInput{Name: "x", Scopes: []string{"api"}}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("client minted token: %v", err)
	}
}

func TestUserUniqueConflictsAreFieldErrors(t *testing.T) {
	c := newCast(t)
	base := c.user(c.a.ID, "alice", model.RoleUser)
	_, err := c.svc.UpdateUser(c.ctx, actor(c.aAdmin), base.ID, service.UserInput{ExternalID: ptr("ext-1")})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		in    service.UserInput
		field string
	}{
		{"username", service.UserInput{Username: ptr("alice"), Email: ptr("alice@example.com")}, "username"},
		{"username case", service.UserInput{Username: ptr("ALICE"), Email: ptr("ALICE@example.com")}, "username"},
		{"email", service.UserInput{Username: ptr("other"), Email: ptr("Alice@Example.com")}, "email"},
		{"external", service.UserInput{Username: ptr("other2"), Email: ptr("other2@example.com"), ExternalID: ptr("ext-1")}, "external_id"},
	}
	for _, tc := range cases {
		tc.in.GivenName = gn("T")
		_, err := c.svc.CreateUser(c.ctx, actor(c.aAdmin), c.a.ID, tc.in)
		var fe *service.FieldError
		if !errors.As(err, &fe) || fe.Field != tc.field || !errors.Is(err, service.ErrConflict) || !errors.Is(err, service.ErrInvalid) {
			t.Errorf("%s: want conflict field error on %s, got %v", tc.name, tc.field, err)
		}
	}
	// The same values are fine in another org.
	if _, err := c.svc.CreateUser(c.ctx, actor(c.bAdmin), c.b.ID, service.UserInput{GivenName: gn("T"), Username: ptr("alice"), Email: ptr("alice@example.com"), ExternalID: ptr("ext-1")}); err != nil {
		t.Errorf("same values in other org: %v", err)
	}
	// Updating to a clashing value.
	bob := c.user(c.a.ID, "bob", model.RoleUser)
	_, err = c.svc.UpdateUser(c.ctx, actor(c.aAdmin), bob.ID, service.UserInput{Email: ptr("alice@example.com")})
	var fe *service.FieldError
	if !errors.As(err, &fe) || fe.Field != "email" {
		t.Errorf("update email clash: %v", err)
	}
	_, err = c.svc.UpdateUser(c.ctx, actor(c.aAdmin), bob.ID, service.UserInput{Username: ptr("alice"), Email: ptr("alice@example.com")})
	if !errors.As(err, &fe) || fe.Field != "username" {
		t.Errorf("update username clash: %v", err)
	}
	// Updating a user to its own values is not a clash.
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.aAdmin), base.ID, service.UserInput{Username: ptr("alice"), Email: ptr("alice@example.com"), ExternalID: ptr("ext-1")}); err != nil {
		t.Errorf("self values: %v", err)
	}
	// A deleted user frees its keys.
	if err := c.svc.DeleteUser(c.ctx, actor(c.aAdmin), base.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.CreateUser(c.ctx, actor(c.aAdmin), c.a.ID, service.UserInput{GivenName: gn("T"), Username: ptr("alice"), Email: ptr("alice@example.com"), ExternalID: ptr("ext-1")}); err != nil {
		t.Errorf("reuse after delete: %v", err)
	}
}

func TestUserValidation(t *testing.T) {
	c := newCast(t)
	long := strings.Repeat("x", 201)
	cases := []struct {
		name  string
		in    service.UserInput
		field string
	}{
		{"nothing", service.UserInput{}, "email"},
		{"username only", service.UserInput{Username: ptr("nomail")}, "email"},
		{"blank email", service.UserInput{Username: ptr("nomail"), Email: ptr("   ")}, "email"},
		{"bad username", service.UserInput{Username: ptr("a b"), Email: ptr("ab@example.com")}, "username"},
		{"long username", service.UserInput{Username: ptr(strings.Repeat("a", 129)), Email: ptr("la@example.com")}, "username"},
		{"bad email", service.UserInput{Username: ptr("u1"), Email: ptr("nope")}, "email"},
		{"display email", service.UserInput{Username: ptr("u2"), Email: ptr("Name <a@b.com>")}, "email"},
		{"bad role", service.UserInput{Username: ptr("u3"), Email: ptr("u3@example.com"), Role: ptr(model.Role("root"))}, "role"},
		{"long name", service.UserInput{Username: ptr("u4"), Email: ptr("u4@example.com"), GivenName: &long}, "given_name"},
		{"short password", service.UserInput{Username: ptr("u5"), Email: ptr("u5@example.com"), Password: ptr("short")}, "password"},
		{"long password", service.UserInput{Username: ptr("u6"), Email: ptr("u6@example.com"), Password: ptr(strings.Repeat("p", 1025))}, "password"},
		{"long locale", service.UserInput{Username: ptr("u7"), Email: ptr("u7@example.com"), Locale: ptr(strings.Repeat("l", 36))}, "locale"},
	}
	for _, tc := range cases {
		if tc.in.GivenName == nil {
			tc.in.GivenName = gn("T")
		}
		_, err := c.svc.CreateUser(c.ctx, actor(c.aAdmin), c.a.ID, tc.in)
		var fe *service.FieldError
		if !errors.As(err, &fe) || !errors.Is(err, service.ErrInvalid) || fe.Field != tc.field || fe.Msg == "" {
			t.Errorf("%s: want invalid on %s, got %v", tc.name, tc.field, err)
		}
	}
	// Username falls back to the email; display name to the full name then the username.
	u, err := c.svc.CreateUser(c.ctx, actor(c.aAdmin), c.a.ID, service.UserInput{Email: ptr("carol@example.com"),
		GivenName: ptr("Carol"), FamilyName: ptr("Jones")})
	if err != nil || u.Username != "carol@example.com" || u.FullName() != "Carol Jones" || !u.Active || u.Role != model.RoleUser {
		t.Errorf("defaults: %v %+v", err, u)
	}
	u, err = c.svc.CreateUser(c.ctx, actor(c.aAdmin), c.a.ID, service.UserInput{GivenName: gn("T"), Username: ptr("dave"), Email: ptr("dave@example.com")})
	if err != nil || u.FullName() != "T" {
		t.Errorf("name default: %v %+v", err, u)
	}
	// A blank username also falls back to the email; the username never needs to be given.
	u, err = c.svc.CreateUser(c.ctx, actor(c.aAdmin), c.a.ID, service.UserInput{GivenName: gn("T"), Username: ptr("  "), Email: ptr("erica@example.com")})
	if err != nil || u.Username != "erica@example.com" {
		t.Errorf("blank username default: %v %+v", err, u)
	}
	// The email cannot be cleared by an update (and a failed update changes nothing).
	for _, blank := range []string{"", "  "} {
		_, err = c.svc.UpdateUser(c.ctx, actor(c.aAdmin), u.ID, service.UserInput{Email: ptr(blank)})
		var fe *service.FieldError
		if !errors.As(err, &fe) || fe.Field != "email" {
			t.Errorf("clearing email %q: %v", blank, err)
		}
	}
	// Unknown org.
	if _, err := c.svc.CreateUser(c.ctx, actor(c.super), "no-such-org", service.UserInput{GivenName: gn("T"), Username: ptr("x"), Email: ptr("x@example.com")}); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown org: %v", err)
	}
	// Changing the email clears the verified flag.
	v, err := c.svc.CreateUser(c.ctx, actor(c.aAdmin), c.a.ID, service.UserInput{GivenName: gn("T"), Username: ptr("erin"), Email: ptr("erin@example.com"), Verified: ptr(true)})
	if err != nil || !v.EmailVerified {
		t.Fatalf("verified: %v", err)
	}
	v, err = c.svc.UpdateUser(c.ctx, actor(c.aAdmin), v.ID, service.UserInput{Email: ptr("erin2@example.com")})
	if err != nil || v.EmailVerified {
		t.Errorf("email change should clear verified: %v %+v", err, v)
	}
}

func TestUserPasswordHashAndSessions(t *testing.T) {
	c := newCast(t)
	// Admins cannot set passwords, at creation or later: only the system can (an accepted invitation does).
	if _, err := c.svc.CreateUser(c.ctx, actor(c.aAdmin), c.a.ID, service.UserInput{GivenName: gn("T"), Username: ptr("pw0"), Email: ptr("pw0@example.com"), Password: ptr("correct horse battery")}); !errors.As(err, new(*service.FieldError)) {
		t.Fatalf("admin created a user with a password: %v", err)
	}
	u, err := c.svc.CreateUser(c.ctx, service.System, c.a.ID, service.UserInput{GivenName: gn("T"), Username: ptr("pw"), Email: ptr("pw@example.com"), Password: ptr("correct horse battery")})
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.svc.VerifyPassword(c.ctx, u, "correct horse battery")
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

// Deleting a user deletes the user record: what was theirs stops counting at once, and the orphan sweep removes it.
func TestDeleteUserRemovesEverything(t *testing.T) {
	c := newCast(t)
	u := c.aUser
	g, _ := c.svc.CreateGroup(c.ctx, actor(c.aAdmin), c.a.ID, service.GroupInput{DisplayName: ptr("staff")})
	if err := c.svc.SetMembership(c.ctx, actor(c.aAdmin), g.ID, u.ID, true); err != nil {
		t.Fatal(err)
	}
	tok, plain, err := c.svc.CreateAPIToken(c.ctx, actor(u), service.APITokenInput{Name: "t", Scopes: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	sess := &model.Session{Meta: model.Meta{ID: "s-" + u.ID}, UserID: u.ID, OrgID: u.OrgID}
	_ = c.svc.Sessions.Create(c.ctx, sess)
	if err := c.svc.DeleteUser(c.ctx, actor(c.aAdmin), u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.Users.Get(c.ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Error("user remains")
	}
	if _, _, err := c.svc.ValidateAPIToken(c.ctx, plain); err == nil {
		t.Error("token of a deleted user accepted")
	}
	if _, err := c.svc.SweepAll(c.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.APITokens.Get(c.ctx, tok.ID); !errors.Is(err, store.ErrNotFound) {
		t.Error("token remains")
	}
	if _, err := c.svc.Sessions.Get(c.ctx, sess.ID); !errors.Is(err, store.ErrNotFound) {
		t.Error("session remains")
	}
	ids, err := c.svc.GroupMembers(c.ctx, actor(c.aAdmin), g.ID)
	if err != nil || len(ids) != 0 {
		t.Errorf("membership remains: %v %v", ids, err)
	}
	if err := c.svc.DeleteUser(c.ctx, actor(c.aAdmin), u.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

func TestOptimisticConcurrency(t *testing.T) {
	c := newCast(t)
	u := c.user(c.a.ID, "race", model.RoleUser)
	a := actor(c.aAdmin)
	var wg sync.WaitGroup
	var mu sync.Mutex
	counts := map[string]int{}
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.svc.UpdateUser(c.ctx, a, u.ID, service.UserInput{FamilyName: ptr("t" + itoa(i))})
			mu.Lock()
			counts[outcome(err)]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	for k := range counts {
		if k != "ok" && k != "stale" {
			t.Errorf("unexpected outcome %s", k)
		}
	}
	if counts["ok"] == 0 {
		t.Error("no update succeeded")
	}
	t.Logf("concurrent updates: %v", counts)

	// A write by someone else between read and write is reported, never silently lost: simulate with a stale entity.
	stale, _ := c.svc.Users.Get(c.ctx, u.ID)
	fresh, _ := c.svc.Users.Get(c.ctx, u.ID)
	fresh.FamilyName = "fresh"
	if err := c.svc.Users.Update(c.ctx, fresh); err != nil {
		t.Fatal(err)
	}
	stale.FamilyName = "stale"
	err := c.svc.Users.Update(c.ctx, stale)
	if !errors.Is(err, store.ErrStale) {
		t.Fatalf("stale update: %v", err)
	}
	got, _ := c.svc.Users.Get(c.ctx, u.ID)
	if got.FamilyName != "fresh" {
		t.Errorf("lost update: %q", got.FamilyName)
	}
}

func TestStaleSurfacesFromService(t *testing.T) {
	// Hammer one org, group and client with concurrent writers; every failure must be ErrStale (retryable).
	c := newCast(t)
	g, _ := c.svc.CreateGroup(c.ctx, actor(c.aAdmin), c.a.ID, service.GroupInput{DisplayName: ptr("race-group")})
	cl, _, _ := c.svc.CreateClient(c.ctx, actor(c.aAdmin), c.a.ID, service.ClientInput{Name: ptr("race-client"),
		RedirectURIs: ptr([]string{"https://r.example.com/cb"})})
	var wg sync.WaitGroup
	var mu sync.Mutex
	bad := []string{}
	record := func(err error) {
		if err != nil && !errors.Is(err, service.ErrStale) {
			mu.Lock()
			bad = append(bad, err.Error())
			mu.Unlock()
		}
	}
	for i := range 30 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			_, err := c.svc.UpdateGroup(c.ctx, actor(c.aAdmin), g.ID, service.GroupInput{ExternalID: ptr("e" + itoa(i))})
			record(err)
		}()
		go func() {
			defer wg.Done()
			_, err := c.svc.UpdateClient(c.ctx, actor(c.aAdmin), cl.ID, service.ClientInput{Description: ptr("d" + itoa(i))})
			record(err)
		}()
		go func() {
			defer wg.Done()
			_, err := c.svc.UpdateOrg(c.ctx, actor(c.super), c.a.ID, service.OrgInput{DisplayName: ptr("n" + itoa(i))})
			record(err)
		}()
	}
	wg.Wait()
	if len(bad) > 0 {
		t.Errorf("non-stale failures: %v", bad)
	}
}

func TestAuditTrail(t *testing.T) {
	c := newCast(t)
	u := c.user(c.a.ID, "audited", model.RoleUser)
	_, _ = c.svc.UpdateUser(c.ctx, actor(c.aAdmin), u.ID, service.UserInput{FamilyName: ptr("x")})
	_ = c.svc.DeleteUser(c.ctx, actor(c.aAdmin), u.ID)
	pg, err := c.svc.ListAudit(c.ctx, actor(c.aAdmin), c.a.ID, service.AuditQuery{Limit: 100})
	list, n := pg.Items, pg.Total
	if err != nil || n == 0 {
		t.Fatalf("audit: %v %d", err, n)
	}
	seen := map[string]bool{}
	for _, e := range list {
		seen[e.Action] = true
		if e.Action == "user.delete" && (e.Actor != "aadmin" || e.ActorID != c.aAdmin.ID || e.Target != "audited") {
			t.Errorf("audit entry %+v", e)
		}
	}
	for _, a := range []string{"user.create", "user.update", "user.delete"} {
		if !seen[a] {
			t.Errorf("missing audit action %s", a)
		}
	}
}

func TestListUsersQuery(t *testing.T) {
	c := newCast(t)
	for i := range 25 {
		c.user(c.a.ID, "list"+itoa(100+i), model.RoleUser)
	}
	a := actor(c.aAdmin)
	page, total, err := c.svc.ListUsers(c.ctx, a, c.a.ID, store.ListQuery{Search: "list1", Sort: "username", Limit: 10, Offset: 5})
	if err != nil || total != 25 || len(page) != 10 || page[0].Username != "list105" {
		t.Fatalf("page: %v total=%d len=%d", err, total, len(page))
	}
	_, total, _ = c.svc.ListUsers(c.ctx, a, c.a.ID, store.ListQuery{Filters: []store.Filter{{Field: "role", Value: "admin"}}})
	if total != 1 {
		t.Errorf("admin filter total %d", total)
	}
	if _, _, err := c.svc.ListUsers(c.ctx, a, c.a.ID, store.ListQuery{Sort: "password_hash"}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("bad sort: %v", err)
	}
	if _, _, err := c.svc.ListUsers(c.ctx, a, c.a.ID, store.ListQuery{Filters: []store.Filter{{Field: "nope", Value: "x"}}}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("bad filter: %v", err)
	}
	// Scope cannot be overridden to read another org.
	_, total, err = c.svc.ListUsers(c.ctx, a, c.a.ID, store.ListQuery{Scope: c.b.ID})
	if err != nil || total != 28 {
		t.Errorf("scope override: %v total=%d", err, total)
	}
}

// Own password and email change only through the account page (SelfService): the management API, sessions or
// tokens, cannot bypass the current-password / re-authentication check.
func TestSelfCredentialsNeedAccountPage(t *testing.T) {
	c := newCast(t)
	for _, u := range []*model.User{c.aUser, c.aAdmin} {
		if _, err := c.svc.UpdateUser(c.ctx, actor(u), u.ID, service.UserInput{Password: ptr("my-new-password-1")}); !errors.Is(err, service.ErrInvalid) {
			t.Errorf("%s: self password via UpdateUser: %v", u.Username, err)
		}
		if _, err := c.svc.UpdateUser(c.ctx, actor(u), u.ID, service.UserInput{Email: ptr("new-" + u.Email)}); !errors.Is(err, service.ErrInvalid) {
			t.Errorf("%s: self email via UpdateUser: %v", u.Username, err)
		}
		if _, err := c.svc.UpdateUser(c.ctx, actor(u), u.ID, service.UserInput{Email: ptr(u.Email), FamilyName: ptr("ok")}); err != nil {
			t.Errorf("%s: unchanged email must be accepted: %v", u.Username, err)
		}
	}
}

// Provisioning clients (SCIM client_credentials) never touch admins: no password reset, disable, delete or demote.
func TestProvisioningClientCannotTouchAdmins(t *testing.T) {
	c := newCast(t)
	cl := &model.Client{Meta: model.Meta{ID: "scim-client"}, OrgID: c.aAdmin.OrgID, Name: "prov", SCIM: true}
	a := service.ActorForClient(cl, "")
	f := false
	role := model.RoleUser
	for name, in := range map[string]service.UserInput{
		"password": {Password: ptr("attacker-password-1")}, "disable": {Active: &f}, "demote": {Role: &role},
	} {
		if _, err := c.svc.UpdateUser(c.ctx, a, c.aAdmin.ID, in); !errors.Is(err, service.ErrForbidden) {
			t.Errorf("%s admin: %v", name, err)
		}
	}
	if err := c.svc.DeleteUser(c.ctx, a, c.aAdmin.ID); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("delete admin: %v", err)
	}
	// Plain users and managers remain manageable, but never get a password from the client: no setting it, and
	// no inviting or clearing the password of an admin.
	if _, err := c.svc.UpdateUser(c.ctx, a, c.aUser.ID, service.UserInput{Password: ptr("provisioned-pass-1")}); !errors.As(err, new(*service.FieldError)) {
		t.Errorf("plain user password: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, a, c.aUser.ID, service.UserInput{FamilyName: ptr("Renamed")}); err != nil {
		t.Errorf("plain user: %v", err)
	}
	if _, _, err := c.svc.CreateInvite(c.ctx, a, c.aAdmin.ID); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("invite admin: %v", err)
	}
	if err := c.svc.RemovePassword(c.ctx, a, c.aAdmin.ID); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("remove admin password: %v", err)
	}
	if _, _, err := c.svc.CreateInvite(c.ctx, a, c.aUser.ID); err != nil {
		t.Errorf("invite plain user: %v", err)
	}
}

// Concurrent demotions of the only two admins must leave exactly one admin.
func TestLastAdminRace(t *testing.T) {
	for i := range 20 {
		c := newCast(t)
		second, err := c.svc.CreateUser(c.ctx, service.System, c.primary.ID, service.UserInput{GivenName: gn("T"),
			Username: ptr(fmt.Sprintf("super2-%d", i)), Email: ptr(fmt.Sprintf("super2-%d@example.com", i)), Role: ptr(model.RoleSuperAdmin)})
		if err != nil {
			t.Fatal(err)
		}
		role := model.RoleUser
		var wg sync.WaitGroup
		for _, id := range []string{c.super.ID, second.ID} {
			wg.Go(func() { _, _ = c.svc.UpdateUser(c.ctx, service.System, id, service.UserInput{Role: &role}) })
		}
		wg.Wait()
		_, n, err := c.svc.Users.List(c.ctx, store.ListQuery{Scope: c.primary.ID, Filters: []store.Filter{
			{Field: "role", Value: "super_admin"}, {Field: "active", Value: true}}})
		if err != nil || n != 1 {
			t.Fatalf("run %d: %d active super admins left", i, n)
		}
	}
}

// Sign-in lookup is by email address only, case-insensitively; the username never matches.
func TestFindUserByEmail(t *testing.T) {
	c := newCast(t)
	u, err := c.svc.CreateUser(c.ctx, actor(c.aAdmin), c.a.ID, service.UserInput{GivenName: gn("T"), Username: ptr("zed"), Email: ptr("Zed@Example.com")})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []string{"Zed@Example.com", "zed@example.com", "  ZED@EXAMPLE.COM "} {
		if got, err := c.svc.FindUserByEmail(c.ctx, c.a.ID, e); err != nil || got.ID != u.ID {
			t.Errorf("%q: %v", e, err)
		}
	}
	if _, err := c.svc.FindUserByEmail(c.ctx, c.a.ID, "zed"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("username must not find the user: %v", err)
	}
	if _, err := c.svc.FindUserByEmail(c.ctx, c.b.ID, "zed@example.com"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("other org: %v", err)
	}
}
