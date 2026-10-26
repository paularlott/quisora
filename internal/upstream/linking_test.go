package upstream_test

import (
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/upstream"
)

// mkUser creates an active user with a verified primary address.
func (e *env) mkUser(t *testing.T, name, email string, verified bool) *model.User {
	t.Helper()
	u, err := e.svc.CreateUser(e.ctx, service.System, e.org.ID, service.UserInput{Username: ptr(name), Email: ptr(email),
		GivenName: ptr(name), Verified: ptr(verified)})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (e *env) link(t *testing.T, userID, address string) {
	t.Helper()
	if _, err := e.svc.AddLinkedEmail(e.ctx, service.System, userID, address, true); err != nil {
		t.Fatal(err)
	}
}

func (e *env) audited(t *testing.T, action string) bool {
	t.Helper()
	pg, err := e.svc.ListAudit(e.ctx, service.System, e.org.ID, service.AuditQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	l := pg.Items
	for _, a := range l {
		if a.Action == action {
			return true
		}
	}
	return false
}

// An address that is not VERIFIED on our side never links (see email_link_test.go for the verified cases).
func TestNeverLinksByEmail(t *testing.T) {
	e := setup(t)
	victim, err := e.svc.CreateUser(e.ctx, service.System, e.org.ID, service.UserInput{GivenName: ptr("T"),
		Username: ptr("victim"), Email: ptr("victim@example.com"), Password: ptr("a-long-password-1")})
	if err != nil {
		t.Fatal(err)
	}

	// Auto-provision on: an upstream account claiming the same (verified) email is refused, not linked.
	p := e.oidcProvider(t, nil)
	if _, err := e.signIn(p, std("attacker", "victim@example.com")); !errors.Is(err, upstream.ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}
	if _, err := e.svc.Identities.GetByUnique(e.ctx, model.IdentityKey(p.ID, "attacker")); err == nil {
		t.Fatal("identity created for an email clash")
	}

	// Auto-provision off: no link, no sign-in.
	p2 := e.oidcProvider(t, func(in *service.ProviderInput) { in.Name = ptr("Closed"); in.AutoProvision = ptr(false) })
	if _, err := e.signIn(p2, std("attacker", "victim@example.com")); !errors.Is(err, upstream.ErrNotLinked) {
		t.Fatalf("want ErrNotLinked, got %v", err)
	}
	// ...unless an identity was linked deliberately.
	if err := e.svc.Identities.Create(e.ctx, model.NewIdentity(victim, p2, "legit", "", "admin")); err != nil {
		t.Fatal(err)
	}
	res, err := e.signIn(p2, std("legit", "anything@else.example"))
	if err != nil || res.User.ID != victim.ID {
		t.Fatalf("linked identity sign-in: %v %+v", err, res)
	}
}

// The owner's case: the local account is paul.arlott@gmail.com, GitHub reports paul@the7thdream.com.
func TestGitHubLinksByVerifiedLinkedEmail(t *testing.T) {
	e := setup(t)
	p := e.githubProvider(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(false) })
	paul := e.mkUser(t, "paul", "paul.arlott@gmail.com", true)
	e.link(t, paul.ID, "paul@the7thdream.com")
	e.gh.Emails = []map[string]any{{"email": "paul@the7thdream.com", "primary": true, "verified": true}}
	res, err := e.signIn(p, nil)
	if err != nil || res.Provisioned || res.User.ID != paul.ID {
		t.Fatalf("link by linked email: %v %+v", err, res)
	}
	if id, err := e.svc.Identities.GetByUnique(e.ctx, model.IdentityKey(p.ID, "583231")); err != nil || id.UserID != paul.ID {
		t.Fatalf("identity not created: %v", err)
	}
	if !e.audited(t, "identity.link.email") {
		t.Fatal("link not audited")
	}
	// next time the identity does the work, whatever the provider reports
	e.gh.Emails = []map[string]any{{"email": "somebody@else.example", "primary": true, "verified": true}}
	if res, err = e.signIn(p, nil); err != nil || res.User.ID != paul.ID {
		t.Fatalf("second sign-in: %v", err)
	}
}

func TestLinksByVerifiedSecondaryGitHubAddressAndPrimary(t *testing.T) {
	e := setup(t)
	p := e.githubProvider(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(false) })
	u := e.mkUser(t, "pat", "pat@example.com", true) // verified primary on our side
	e.gh.Emails = []map[string]any{
		{"email": "x@nowhere.example", "primary": true, "verified": true},
		{"email": "pat@example.com", "primary": false, "verified": true},
	}
	res, err := e.signIn(p, nil)
	if err != nil || res.User.ID != u.ID {
		t.Fatalf("verified secondary on GitHub matching our verified primary: %v", err)
	}
}

func TestOIDCLinksByVerifiedEmail(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(false) })
	u := e.mkUser(t, "olga", "olga@home.example", true)
	e.link(t, u.ID, "olga@corp.example")
	res, err := e.signIn(p, std("o-1", "Olga@Corp.Example"))
	if err != nil || res.User.ID != u.ID || res.Provisioned {
		t.Fatalf("oidc link: %v", err)
	}
}

func TestNoLinkOnUnverifiedAddresses(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(false) })
	victim := e.mkUser(t, "victim", "victim@example.com", false) // unverified primary
	if _, err := e.svc.AddLinkedEmail(e.ctx, service.System, victim.ID, "v2@example.com", false); err != nil {
		t.Fatal(err) // an unverified linked address (added by an administrator, its link not yet followed)
	}
	// the provider vouches for both addresses, but ours are unverified
	for _, addr := range []string{"victim@example.com", "v2@example.com"} {
		if _, err := e.signIn(p, std("att-"+addr, addr)); !errors.Is(err, upstream.ErrNotLinked) {
			t.Errorf("%s: unverified account address linked: %v", addr, err)
		}
	}
	// verified on our side but the provider does not vouch
	e.mkUser(t, "good", "good@example.com", true)
	c := std("att-2", "good@example.com")
	c["email_verified"] = false
	if _, err := e.signIn(p, c); !errors.Is(err, upstream.ErrNotLinked) {
		t.Errorf("unverified provider address linked: %v", err)
	}
	if _, err := e.svc.Identities.GetByUnique(e.ctx, model.IdentityKey(p.ID, "att-2")); err == nil {
		t.Error("identity created")
	}
	// GitHub: only unverified addresses reported
	gp := e.githubProvider(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(false) })
	e.gh.Emails = []map[string]any{{"email": "good@example.com", "primary": true, "verified": false}}
	if _, err := e.signIn(gp, nil); !errors.Is(err, upstream.ErrNotLinked) {
		t.Errorf("github unverified: %v", err)
	}
}

func TestNoLinkWhenTwoUsersMatch(t *testing.T) {
	e := setup(t)
	p := e.githubProvider(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(true) })
	e.mkUser(t, "ann", "ann@example.com", true)
	e.mkUser(t, "bob", "bob@example.com", true)
	e.gh.Emails = []map[string]any{
		{"email": "ann@example.com", "primary": true, "verified": true},
		{"email": "bob@example.com", "primary": false, "verified": true},
	}
	if _, err := e.signIn(p, nil); !errors.Is(err, upstream.ErrExists) {
		t.Fatalf("ambiguous match: %v", err)
	}
	if _, err := e.svc.Identities.GetByUnique(e.ctx, model.IdentityKey(p.ID, "583231")); err == nil {
		t.Fatal("identity created for an ambiguous match")
	}
	if n, _ := e.svc.Users.Count(e.ctx, e.org.ID); n != 2 {
		t.Fatalf("a duplicate user was provisioned: %d", n)
	}
}

func TestLinkByEmailOff(t *testing.T) {
	e := setup(t)
	u := e.mkUser(t, "pat", "pat@example.com", true)
	off := e.oidcProvider(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(false); in.LinkByEmail = ptr(false) })
	if off.LinkByEmail {
		t.Fatal("link_by_email=false not stored")
	}
	if _, err := e.signIn(off, std("p-1", "pat@example.com")); !errors.Is(err, upstream.ErrNotLinked) {
		t.Fatalf("linking is off: %v", err)
	}
	// new providers link by email unless told not to
	on := e.oidcProvider(t, func(in *service.ProviderInput) { in.Name = ptr("On"); in.AutoProvision = ptr(false) })
	if !on.LinkByEmail {
		t.Fatal("linking must default to on")
	}
	if res, err := e.signIn(on, std("p-2", "pat@example.com")); err != nil || res.User.ID != u.ID {
		t.Fatalf("default: %v", err)
	}
	// and it can be switched
	if on, err := e.svc.UpdateProvider(e.ctx, service.System, on.ID, service.ProviderInput{LinkByEmail: ptr(false)}); err != nil || on.LinkByEmail {
		t.Fatalf("update: %v", err)
	}
}

func TestAutoProvisionDoesNotDuplicateAndStillProvisions(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil) // auto-provision on
	u := e.mkUser(t, "pat", "pat@example.com", true)
	res, err := e.signIn(p, std("p-1", "pat@example.com"))
	if err != nil || res.Provisioned || res.User.ID != u.ID {
		t.Fatalf("existing verified user must be linked, not duplicated: %v %+v", err, res)
	}
	if n, _ := e.svc.Users.Count(e.ctx, e.org.ID); n != 1 {
		t.Fatalf("users %d", n)
	}
	// an unverified owner of the address: refused, still no duplicate
	e.mkUser(t, "una", "una@example.com", false)
	if _, err := e.signIn(p, std("p-2", "una@example.com")); !errors.Is(err, upstream.ErrExists) {
		t.Fatalf("unverified match: %v", err)
	}
	// a new address provisions as before
	res, err = e.signIn(p, std("p-3", "fresh@example.com"))
	if err != nil || !res.Provisioned {
		t.Fatalf("provision: %v", err)
	}
}

func TestLinkRespectsDisabledUsersAndDomains(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, func(in *service.ProviderInput) {
		in.AutoProvision = ptr(false)
		in.AllowedDomains = &[]string{"corp.example"}
	})
	u := e.mkUser(t, "dan", "dan@home.example", true)
	e.link(t, u.ID, "dan@other.example")
	e.link(t, u.ID, "dan@corp.example")
	// the provider's address is outside the allowed domains
	if _, err := e.signIn(p, std("d-0", "dan@other.example")); !errors.Is(err, upstream.ErrNotLinked) {
		t.Fatalf("domain: %v", err)
	}
	off := false
	if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Active: &off}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.signIn(p, std("d-1", "dan@corp.example")); !errors.Is(err, upstream.ErrDisabled) {
		t.Fatalf("disabled user: %v", err)
	}
	if _, err := e.svc.Identities.GetByUnique(e.ctx, model.IdentityKey(p.ID, "d-1")); err == nil {
		t.Fatal("identity created for a disabled user")
	}
}

func TestProvisionedNames(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)
	c := std("n-1", "solo@example.com")
	c["given_name"], c["family_name"], c["name"] = nil, nil, "Mary Ann Smith"
	res, err := e.signIn(p, c)
	if err != nil || res.User.GivenName != "Mary" || res.User.FamilyName != "Ann Smith" {
		t.Fatalf("split full name: %v %+v", err, res.User)
	}
	c = std("n-2", "nameless@example.com")
	c["given_name"], c["family_name"], c["name"] = nil, nil, nil
	res, err = e.signIn(p, c)
	if err != nil || res.User.GivenName != "nameless" {
		t.Fatalf("fallback to the address: %v %+v", err, res.User)
	}
}

// Managers and administrators are never linked by email (a provider an org administrator set up could otherwise
// claim their address and become them); the refusal is audited and nothing is linked or provisioned.
func TestNoEmailLinkForPrivilegedAccounts(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)                                             // auto-provisioning on, linking by email on
	for _, role := range []model.Role{model.RoleManager, model.RoleAdmin} { // super admins rank higher still
		email := string(role) + "@example.com"
		u, err := e.svc.CreateUser(e.ctx, service.System, e.org.ID, service.UserInput{Username: ptr(string(role)), Email: ptr(email),
			GivenName: ptr("P"), Verified: ptr(true), Role: ptr(role)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.signIn(p, std("claim-"+string(role), email)); !errors.Is(err, upstream.ErrPrivileged) {
			t.Errorf("%s: %v", role, err)
		}
		if ids, _ := e.svc.Identities.All(e.ctx, u.ID); len(ids) != 0 {
			t.Errorf("%s linked", role)
		}
	}
	if !e.audited(t, "identity.link.refused") {
		t.Error("refusal not audited")
	}
	// a plain user still links
	e.mkUser(t, "plain", "plain@example.com", true)
	if res, err := e.signIn(p, std("claim-plain", "plain@example.com")); err != nil || res.User == nil {
		t.Fatalf("plain user: %v", err)
	}
}

// A link means something only at the provider it was made with: changing the provider's issuer or type, or deleting
// it and creating it again under the same id, ends its links (an org admin cannot point a provider somewhere else and
// sign in as whoever was linked). The provider's allowed domains also apply to linked identities.
func TestLinksFollowTheProvider(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(false) })
	u := e.mkUser(t, "sam", "sam@example.com", true)
	if err := e.svc.Identities.Create(e.ctx, model.NewIdentity(u, p, "sam-sub", "", "connect")); err != nil {
		t.Fatal(err)
	}
	if res, err := e.signIn(p, std("sam-sub", "any@x.example")); err != nil || res.User.ID != u.ID {
		t.Fatalf("linked sign-in: %v", err)
	}
	// allowed domains now restrict the provider: the linked identity must bring an address there
	p, _ = e.svc.UpdateProvider(e.ctx, service.System, p.ID, service.ProviderInput{AllowedDomains: &[]string{"corp.example"}})
	if _, err := e.signIn(p, std("sam-sub", "any@x.example")); !errors.Is(err, upstream.ErrDomain) {
		t.Fatalf("linked identity outside the allowed domains: %v", err)
	}
	p, _ = e.svc.UpdateProvider(e.ctx, service.System, p.ID, service.ProviderInput{AllowedDomains: &[]string{}})
	// a new issuer: the links go
	e.oidc.IssuerOver = e.oidc.Srv.URL + "/"
	// ... which needs the new issuer's own client secret: the old one is not sent there
	if _, err := e.svc.UpdateProvider(e.ctx, service.System, p.ID, service.ProviderInput{Issuer: ptr(e.oidc.Srv.URL + "/v2")}); err == nil {
		t.Fatal("issuer changed without a new client secret")
	}
	p, err := e.svc.UpdateProvider(e.ctx, service.System, p.ID, service.ProviderInput{Issuer: ptr(e.oidc.Srv.URL + "/v2"),
		ClientSecret: ptr("s3cret")})
	if err != nil {
		t.Fatal(err)
	}
	if ids, _ := e.svc.Identities.All(e.ctx, u.ID); len(ids) != 0 {
		t.Fatalf("links kept after the issuer changed: %d", len(ids))
	}
	if !e.audited(t, "provider.update") {
		t.Fatal("not audited")
	}
	// a link that survived (a purge missed on another node) is not used either: written by hand here
	stale := model.NewIdentity(u, p, "sam-sub", "", "connect")
	stale.Authority = "oidc|https://elsewhere.example||0"
	if err := e.svc.Identities.Create(e.ctx, stale); err != nil {
		t.Fatal(err)
	}
	e.oidc.IssuerOver = ""
	p, _ = e.svc.UpdateProvider(e.ctx, service.System, p.ID, service.ProviderInput{Issuer: ptr(e.oidc.Srv.URL), ClientSecret: ptr("s3cret")})
	_ = e.svc.Identities.Create(e.ctx, stale) // purged by that update; put it back
	if _, err := e.signIn(p, std("sam-sub", "any@x.example")); !errors.Is(err, upstream.ErrNotLinked) {
		t.Fatalf("stale link used: %v", err)
	}
	// deleted and created again under the same id: old links never match
	link := model.NewIdentity(u, p, "sam-2", "", "connect")
	_ = e.svc.Identities.Create(e.ctx, link)
	if err := e.svc.DeleteProvider(e.ctx, service.System, p.ID); err != nil {
		t.Fatal(err)
	}
	_ = e.svc.Identities.Create(e.ctx, link) // as if the purge had been missed
	again, err := e.svc.CreateProvider(e.ctx, service.System, e.org.ID, service.ProviderInput{ID: ptr(p.ID), Type: ptr(model.ProviderOIDC),
		Name: ptr("Again"), Issuer: ptr(e.oidc.Srv.URL), ClientID: ptr("cid"), ClientSecret: ptr("s3cret"), AutoProvision: ptr(false)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.signIn(again, std("sam-2", "any@x.example")); !errors.Is(err, upstream.ErrNotLinked) {
		t.Fatalf("a link made with the deleted provider was used: %v", err)
	}
}
