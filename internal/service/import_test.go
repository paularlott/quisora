package service_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
)

// importer is a super admin's API token holding the admin and import scopes.
func (e *env) importer(scopes ...string) *service.Actor {
	a := *actor(e.super)
	a.Unscoped, a.Scopes = false, scopes
	return &a
}

// An authenticator secret from another system is allowed where a password hash is (and only for a new user), read
// the way apps and exports write it, sealed to the new user's id, and enrols the account as a set-up one does. It is
// never in an error, the audit log, or what the user shows.
func TestImportTOTPSecret(t *testing.T) {
	e := newEnv(t)
	acme := e.org("acme")
	admin := e.user(acme.ID, "admin", model.RoleAdmin)
	tok := e.importer(service.ScopeAdmin, service.ScopeImport)
	const secret = "JBSWY3DPEHPK3PXP" // 16 characters: 80 bits, as Freedom3 makes them
	in := func(name, totp string) service.UserInput {
		return service.UserInput{GivenName: ptr("I"), Username: ptr(name), Email: ptr(name + "@example.com"), TOTPSecret: ptr(totp)}
	}

	created := len(e.audits("user.create"))
	for _, c := range []struct {
		name string
		a    *service.Actor
		in   service.UserInput
	}{
		{"an organization's admin", actor(admin), in("t1", secret)},
		{"a super admin's token without import", e.importer(service.ScopeAdmin), in("t2", secret)},
		{"not base32", tok, in("t3", "JBSWY3DP!HPK3PXP")},
		{"base32 digits outside 2 to 7", tok, in("t4", "JBSWY3DPEHPK3PX1")},
		{"79 bits", tok, in("t5", "JBSWY3DPEHPK3PX")},
		{"empty", tok, in("t6", " ")},
		{"too long", tok, in("t7", strings.Repeat("A", 129))},
	} {
		_, err := e.svc.CreateUser(e.ctx, c.a, acme.ID, c.in)
		if outcome(err) != "invalid" || !strings.HasPrefix(err.Error(), "totp_secret:") {
			t.Errorf("%s: %v", c.name, err)
		} else if v := strings.TrimSpace(*c.in.TOTPSecret); v != "" && strings.Contains(err.Error(), v) {
			t.Errorf("%s: the error repeats the value: %v", c.name, err)
		}
	}
	if n := len(e.audits("user.create")); n != created {
		t.Errorf("a refused import was audited: %d new user.create events", n-created)
	}

	u, err := e.svc.CreateUser(e.ctx, tok, acme.ID, in("pat", "jbsw y3dp ehpk 3pxp =="))
	if err != nil {
		t.Fatal(err)
	}
	if !u.HasTOTP() || u.MFAEnrolledAt == nil || strings.Contains(u.TOTPSecret, secret) {
		t.Fatalf("not enrolled with a sealed secret: %+v", u)
	}
	got, err := e.svc.Sealer.OpenFor(service.TOTPBinding(u.ID), u.TOTPSecret)
	if err != nil || string(got) != secret {
		t.Fatalf("sealed secret: %q %v", got, err)
	}
	if _, err := e.svc.Sealer.OpenFor(service.TOTPBinding("another"), u.TOTPSecret); err == nil {
		t.Error("the secret opens for another user")
	}
	if !e.ways(u).TOTP {
		t.Error("the user's ways do not include the authenticator app")
	}
	// the app's current code verifies against what is stored, one step either way
	for _, d := range []time.Duration{0, -30 * time.Second, 30 * time.Second} {
		at := time.Now().Add(d)
		if _, ok := secure.VerifyTOTP(string(got), secure.TOTPCode(secret, at), time.Now(), 0); !ok {
			t.Errorf("code at %v refused", d)
		}
	}

	// a 160-bit secret, as Quisora makes them, is accepted as well
	if _, err := e.svc.CreateUser(e.ctx, service.System, acme.ID, in("long", secure.NewTOTPSecret())); err != nil {
		t.Errorf("160 bits: %v", err)
	}

	// never on an update
	if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{TOTPSecret: ptr(secret)}); outcome(err) != "invalid" {
		t.Errorf("secret on an update: %v", err)
	}

	// audited as mfa.import on the user, without the secret anywhere in an event
	ev := e.audits("mfa.import")[0]
	if ev.TargetID != u.ID || ev.OrgID != acme.ID || ev.Detail["method"] != "totp" {
		t.Errorf("mfa.import: %+v", ev)
	}
	if len(e.audits("mfa.import")) != 2 { // pat and the 160-bit one
		t.Errorf("mfa.import events: %d", len(e.audits("mfa.import")))
	}
	all, _ := json.Marshal(append(e.audits("mfa.import"), e.audits("user.create")...))
	if strings.Contains(strings.ToUpper(string(all)), "JBSWY3DP") {
		t.Errorf("the secret is in the audit log: %s", all)
	}
	if v, _ := json.Marshal(u); strings.Contains(strings.ToUpper(string(v)), "JBSWY3DP") {
		t.Errorf("the secret is in the user's JSON: %s", v)
	}
}

// A user is created with links to providers of their organization, in the write that creates them: their own
// subjects, marked as an administrator's, and no other user can hold the same subject at a provider.
func TestImportProviderLinks(t *testing.T) {
	c := newCast(t)
	tok := c.importer(service.ScopeAdmin, service.ScopeImport)
	corp, err := c.svc.CreateProvider(c.ctx, service.System, c.a.ID, goodProvider("Corp"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := c.svc.CreateProvider(c.ctx, service.System, c.a.ID, goodProvider("Partner"))
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := c.svc.CreateProvider(c.ctx, service.System, c.b.ID, goodProvider("Corp"))
	if err != nil {
		t.Fatal(err)
	}
	in := func(name string, links ...service.IdentityInput) service.UserInput {
		return service.UserInput{GivenName: ptr("I"), Username: ptr(name), Email: ptr(name + "@example.com"), Identities: links}
	}
	link := func(p, subject string) service.IdentityInput {
		return service.IdentityInput{Provider: p, Subject: subject}
	}

	for _, tc := range []struct {
		name string
		a    *service.Actor
		in   service.UserInput
		want string
	}{
		{"an organization's admin", actor(c.aAdmin), in("l1", link(corp.ID, "s1")), "invalid"},
		{"a token without import", c.importer(service.ScopeAdmin), in("l2", link(corp.ID, "s1")), "invalid"},
		{"a provider of another organization, by id", tok, in("l3", link(foreign.ID, "s1")), "invalid"},
		{"no such provider", tok, in("l4", link("nonesuch", "s1")), "invalid"},
		{"an empty subject", tok, in("l5", link(corp.ID, "")), "invalid"},
		{"a subject too long", tok, in("l6", link(corp.ID, strings.Repeat("s", 256))), "invalid"},
		{"two subjects at one provider", tok, in("l7", link(corp.ID, "s1"), link("corp", "s2")), "invalid"},
		{"too many", tok, in("l8", repeatLinks(corp.ID, 11)...), "invalid"},
	} {
		if _, err := c.svc.CreateUser(c.ctx, tc.a, c.a.ID, tc.in); outcome(err) != tc.want {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	if _, err := c.svc.Users.GetByUnique(c.ctx, model.UserUsernameKey(c.a.ID, "l3")); err == nil {
		t.Error("a refused creation left a user behind")
	}

	// by id and by name (any case), each at a provider of the organization
	u, err := c.svc.CreateUser(c.ctx, tok, c.a.ID, in("pat", link(corp.ID, "sub-1"), link("PARTNER", "sub 2")))
	if err != nil {
		t.Fatal(err)
	}
	ids, err := c.svc.Identities.All(c.ctx, u.ID)
	if err != nil || len(ids) != 2 {
		t.Fatalf("links: %d %v", len(ids), err)
	}
	for _, id := range ids {
		if id.Via != "admin" || id.OrgID != c.a.ID || !u.Counts(id) {
			t.Errorf("link %+v", id)
		}
	}
	got, err := c.svc.Identities.GetByUnique(c.ctx, model.IdentityKey(other.ID, "sub 2"))
	if err != nil || got.UserID != u.ID || got.Authority != model.ProviderAuthority(other) {
		t.Fatalf("link by name: %+v %v", got, err)
	}
	if ev := c.lastAudit("user.create"); ev.TargetID != u.ID || ev.Detail["providers"] != "Corp Partner" {
		t.Errorf("audit: %+v", ev)
	}

	// the same subject at the same provider is taken: 409 on the field, and nothing of the second user is kept
	_, err = c.svc.CreateUser(c.ctx, tok, c.a.ID, in("sam", link(corp.ID, "sub-1")))
	if !errors.Is(err, service.ErrConflict) || !strings.HasPrefix(err.Error(), "identities:") {
		t.Fatalf("duplicate subject: %v", err)
	}
	if _, err := c.svc.Users.GetByUnique(c.ctx, model.UserUsernameKey(c.a.ID, "sam")); err == nil {
		t.Error("a conflicting creation left a user behind")
	}
	// another provider's subjects are another namespace
	if _, err := c.svc.CreateUser(c.ctx, tok, c.a.ID, in("kim", link(other.ID, "sub-1"))); err != nil {
		t.Errorf("same subject at another provider: %v", err)
	}
	// never on an update
	if _, err := c.svc.UpdateUser(c.ctx, service.System, u.ID, service.UserInput{Identities: []service.IdentityInput{link(corp.ID, "x")}}); outcome(err) != "invalid" {
		t.Errorf("links on an update: %v", err)
	}

	// an administrator's link is dropped with the others when the user becomes a manager
	if _, err := c.svc.UpdateUser(c.ctx, service.System, u.ID, service.UserInput{Role: ptr(model.RoleManager)}); err != nil {
		t.Fatal(err)
	}
	if ids, _ := c.svc.Identities.All(c.ctx, u.ID); len(ids) != 0 {
		t.Errorf("links after promotion: %d", len(ids))
	}
}

func repeatLinks(provider string, n int) []service.IdentityInput {
	l := make([]service.IdentityInput, n)
	for i := range l {
		l[i] = service.IdentityInput{Provider: provider, Subject: strings.Repeat("s", i+1)}
	}
	return l
}
