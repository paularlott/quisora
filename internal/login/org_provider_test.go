package login_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/oidc"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// guestEnv is a server with the OAuth endpoints and an organization "acme" whose sign-in page offers the primary
// organization's users a way in: an organization provider of the primary organization.
type guestEnv struct {
	*env
	acme *model.Org
	p    *model.Provider
}

func newGuestEnv(t *testing.T, mut func(*service.ProviderInput), cfg ...func(*config.Config)) *guestEnv {
	e := newEnvModules(t, false, func(s *web.Server) []web.Module { return []web.Module{oidc.New(s)} }, append(cfg, noIPLimit)...)
	g := &guestEnv{env: e, acme: e.org(t, "acme", nil)}
	in := service.ProviderInput{Type: ptr(model.ProviderOrganization), SourceOrg: &e.Primary.ID}
	if mut != nil {
		mut(&in)
	}
	p, err := e.Svc.CreateProvider(context.Background(), service.System, g.acme.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	g.p = p
	return g
}

// person adds a user with a verified email address to org.
func (g *guestEnv) person(t *testing.T, org *model.Org, name, email string) *model.User {
	t.Helper()
	u, err := g.Svc.CreateUser(context.Background(), service.System, org.ID, service.UserInput{Username: &name, Email: &email,
		Verified: ptr(true), GivenName: &name, Role: ptr(model.RoleUser)})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// continueAs is a browser signed in at the primary organization as u, which then chooses "Continue with ..." on acme's
// sign-in page. It returns the response of acme's callback, after the primary organization's authorization endpoint
// (reached through the browser, as the provider's redirect leads it) has issued the code.
func (g *guestEnv) continueAs(t *testing.T, u *model.User) (*browser, string) {
	t.Helper()
	return g.continueAsVia(t, g.signedIn(t, u), g.acme, g.p)
}

// continueAsVia is continueAs for the browser b, signed in at the primary organization, and the organization provider
// p of org.
func (g *guestEnv) continueAsVia(t *testing.T, b *browser, org *model.Org, p *model.Provider) (*browser, string) {
	t.Helper()
	b.base = web.OrgPath(org.ID, "")
	res, _ := b.get("/login/provider/" + p.ID)
	if res.StatusCode != 302 {
		t.Fatalf("provider start: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	hop := func(loc string) string {
		t.Helper()
		lu, err := url.Parse(loc)
		if err != nil {
			t.Fatal(err)
		}
		next, _ := b.getAbs(lu.RequestURI())
		return next.Header.Get("Location")
	}
	// the primary organization's authorization endpoint: signed in, and the client trusted: the code comes back at once
	loc := res.Header.Get("Location")
	if !strings.HasPrefix(loc, g.Cfg.OrgIssuer(g.Primary.ID)+"/oauth/authorize?") {
		t.Fatalf("the provider sent the browser to %q", loc)
	}
	back := hop(loc)
	if !strings.HasPrefix(back, g.Cfg.OrgIssuer(org.ID)+"/login/callback/"+p.ID+"?") {
		t.Fatalf("the authorization endpoint sent the browser to %q", back)
	}
	return b, hop(back)
}

// hasSessionIn reports whether the browser holds a session cookie of org.
func (b *browser) hasSessionIn(org *model.Org) bool {
	u, _ := url.Parse(b.e.URL)
	for _, c := range b.c.Jar.Cookies(u) {
		if c.Name == web.SessionCookieFor(org.ID) {
			return true
		}
	}
	return false
}

// A user of the primary organization whom an administrator of "acme" added (with their verified address) signs in to
// acme through "Continue with <primary organization>": the provider's requests to the primary organization are served
// by the server itself, the user is linked by their verified email, and the session is acme's, from the provider.
func TestOrganizationProviderSignsGuestsIn(t *testing.T) {
	// linking by email is the super admin's choice for an organization provider: it is off until turned on
	g := newGuestEnv(t, func(in *service.ProviderInput) { in.LinkByEmail = ptr(true) })
	pat := g.person(t, g.Primary, "pat", "pat@example.com")
	guest := g.person(t, g.acme, "pat-guest", "pat@example.com")

	// the sign-in page offers it, by the source organization's name
	_, page := g.browserAt(t, g.acme).get("/login")
	if want := "Continue with " + g.Primary.DisplayName; !strings.Contains(page, want) {
		t.Fatalf("no %q on the sign-in page: %.600s", want, page)
	}

	b, done := g.continueAs(t, pat)
	if want := web.OrgPath(g.acme.ID, "/account"); done != want {
		t.Fatalf("after the callback: %q, want %q", done, want)
	}
	if !b.hasSessionIn(g.acme) {
		t.Fatal("no session of acme")
	}
	sess := sessionsOf(t, g.env, guest)
	if len(sess) != 1 || strings.Join(sess[0].AMR, ",") != "fed" || sess[0].Provider != g.p.ID || sess[0].OrgID != g.acme.ID {
		t.Fatalf("sessions of the guest: %+v", sess)
	}
	if res, body := b.get("/account"); res.StatusCode != 200 || !strings.Contains(body, "Your account") {
		t.Fatalf("account: %d", res.StatusCode)
	}
	// the account was linked, to the primary user's id (the subject), by email; none was made
	id, err := g.Svc.Identities.GetByUnique(context.Background(), model.IdentityKey(g.p.ID, pat.ID))
	if err != nil || id.UserID != guest.ID || id.Via != "email" {
		t.Fatalf("identity: %+v %v", id, err)
	}
	if n, _ := g.Svc.Users.Count(context.Background(), g.acme.ID); n != 1 {
		t.Fatalf("users of acme: %d", n)
	}
	// and later sign-ins go by the link, whatever the address has become
	if _, err := g.Svc.UpdateUser(context.Background(), service.System, pat.ID, service.UserInput{Email: ptr("pat@other.example")}); err != nil {
		t.Fatal(err)
	}
	if b2, done := g.continueAs(t, pat); done != web.OrgPath(g.acme.ID, "/account") || !b2.hasSessionIn(g.acme) {
		t.Fatalf("second sign-in: %q", done)
	}
}

// Another organization's provider is for that organization's people, not this one's: it is offered last, after the
// email form, in its own group named "via another organization", and lighter than the organization's own sign-ins.
func TestOrganizationProviderIsOfferedLastInItsOwnGroup(t *testing.T) {
	g := newGuestEnv(t, nil)
	_, page := g.browserAt(t, g.acme).get("/login")
	group := strings.Index(page, `<div class="other-orgs" role="group" aria-labelledby="other-orgs-label"`)
	label := strings.Index(page, `id="other-orgs-label">via another organization</div>`)
	button := strings.Index(page, "Continue with "+g.Primary.DisplayName)
	email := strings.Index(page, `id="f-email"`)
	if email < 0 || group < email || label < group || button < label {
		t.Fatalf("order: email %d, group %d, label %d, button %d: %.2000s", email, group, label, button, page)
	}
	if !strings.Contains(page[group:button], `class="btn btn-subtle btn-sm w-full"`) {
		t.Fatalf("the button is not the lighter style: %.600s", page[group:])
	}
	if one := strings.Index(page, `class="provider-list"`); one >= 0 && strings.Contains(page[one:email], "Continue with "+g.Primary.DisplayName) {
		t.Fatal("offered with the organization's own sign-ins too")
	}
}

// By default an organization provider does not link by email: the source organization's managers can mark any address
// verified, so a user of the primary organization with the address of one of acme's users is not signed in as them,
// whether or not accounts are made automatically (that would clash with the address, as it must).
func TestOrganizationProviderDoesNotLinkByEmail(t *testing.T) {
	for name, auto := range map[string]bool{"existing users only": false, "accounts made automatically": true} {
		t.Run(name, func(t *testing.T) {
			g := newGuestEnv(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(auto) })
			victim := g.person(t, g.acme, "victim", "victim@example.com")
			mallory := g.person(t, g.Primary, "mallory", "victim@example.com") // a manager of the primary organization set it, verified

			b, done := g.continueAs(t, mallory)
			if !strings.HasPrefix(done, web.OrgPath(g.acme.ID, "/login?")) {
				t.Fatalf("callback: %q", done)
			}
			if b.hasSessionIn(g.acme) || len(sessionsOf(t, g.env, victim)) != 0 {
				t.Fatal("signed in to acme as its user with that address")
			}
			if _, err := g.Svc.Identities.GetByUnique(context.Background(), model.IdentityKey(g.p.ID, mallory.ID)); err == nil {
				t.Fatal("the primary user was linked to acme's")
			}
		})
	}
}

// A user of the primary organization nobody added to "acme" is refused, with accounts not made automatically: the
// organization's administrators decide who comes in.
func TestOrganizationProviderRefusesUsersNotAdded(t *testing.T) {
	g := newGuestEnv(t, nil)
	eve := g.person(t, g.Primary, "eve", "eve@example.com")
	g.person(t, g.acme, "other", "other@example.com")

	b, done := g.continueAs(t, eve)
	if !strings.HasPrefix(done, web.OrgPath(g.acme.ID, "/login?")) || !strings.Contains(done, "error=not_linked") {
		t.Fatalf("callback: %q", done)
	}
	if b.hasSessionIn(g.acme) {
		t.Fatal("a session of acme for a user who was not added")
	}
	if n, _ := g.Svc.Users.Count(context.Background(), g.acme.ID); n != 1 {
		t.Fatalf("users of acme: %d", n)
	}
}

// With automatic accounts on, the first sign-in makes the guest account.
func TestOrganizationProviderCanMakeGuestAccounts(t *testing.T) {
	g := newGuestEnv(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(true) })
	eve := g.person(t, g.Primary, "eve", "eve@example.com")

	b, done := g.continueAs(t, eve)
	if done != web.OrgPath(g.acme.ID, "/account") || !b.hasSessionIn(g.acme) {
		t.Fatalf("callback: %q", done)
	}
	guest, err := g.Svc.FindUserByEmail(context.Background(), g.acme.ID, "eve@example.com")
	if err != nil || guest.Role != model.RoleUser || !guest.EmailVerified || guest.OrgID != g.acme.ID {
		t.Fatalf("guest: %+v %v", guest, err)
	}
}

// fromAddress makes the browser's requests arrive through a trusted proxy (see trustLoopbackProxy) as those of the
// client at ip.
func (b *browser) fromAddress(ip string) {
	base := b.c.Transport
	b.c.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.Header.Set("X-Forwarded-For", ip)
		return base.RoundTrip(r)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func trustLoopbackProxy(c *config.Config) { c.Server.TrustProxy = []string{"127.0.0.1"} }

// The requests an organization provider makes to its source organization are counted as those of the client whose
// sign-in caused them. Someone who fails the code exchange of one provider over and over (a made-up code at the
// callback) is refused by the token endpoint's failure limit for their own address, and the sign-ins through another
// organization's provider, from other addresses, go on: the limit is not one the providers' requests share.
func TestOrganizationProviderFailuresAreCountedPerClientAddress(t *testing.T) {
	g := newGuestEnv(t, func(in *service.ProviderInput) { in.LinkByEmail = ptr(true) }, trustLoopbackProxy)
	beta := g.org(t, "beta", nil)
	in := service.ProviderInput{Type: ptr(model.ProviderOrganization), SourceOrg: &g.Primary.ID, LinkByEmail: ptr(true)}
	pb, err := g.Svc.CreateProvider(context.Background(), service.System, beta.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	pat := g.person(t, g.Primary, "pat", "pat@example.com")
	guest := g.person(t, beta, "pat-guest", "pat@example.com")

	// Past the limit (300 failures a minute) with room to spare.
	attacker := g.browserAt(t, g.acme)
	attacker.fromAddress("198.51.100.7")
	for range 320 {
		res, _ := attacker.get("/login/provider/" + g.p.ID)
		loc, err := url.Parse(res.Header.Get("Location"))
		if err != nil || res.StatusCode != 302 {
			t.Fatalf("provider start: %d %v", res.StatusCode, err)
		}
		attacker.get("/login/callback/" + g.p.ID + "?code=made-up&state=" + url.QueryEscape(loc.Query().Get("state")))
	}

	b := g.signedIn(t, pat)
	b.fromAddress("203.0.113.5")
	if _, done := g.continueAsVia(t, b, beta, pb); done != web.OrgPath(beta.ID, "/account") || len(sessionsOf(t, g.env, guest)) != 1 {
		t.Fatalf("a sign-in through beta's provider from another address after the failures: %q", done)
	}
}

// With groups, only their members sign in through the provider: a member's first sign-in makes their guest account,
// someone in none of the groups is refused before any account is made (with accounts made automatically, and with
// linking by email too), and a guest taken out of the groups is refused at their next sign-in.
func TestOrganizationProviderAdmitsOnlyItsGroups(t *testing.T) {
	g := newGuestEnv(t, func(in *service.ProviderInput) { in.AutoProvision, in.LinkByEmail = ptr(true), ptr(true) })
	ctx := context.Background()
	eve := g.person(t, g.Primary, "eve", "eve@example.com")
	mal := g.person(t, g.Primary, "mal", "mal@example.com")
	g.person(t, g.acme, "mal-here", "mal@example.com") // added by hand: linking by email would match them
	staff, err := g.Svc.CreateGroupWithMembers(ctx, service.System, g.Primary.ID, service.GroupInput{DisplayName: ptr("staff")}, []string{eve.ID})
	if err != nil {
		t.Fatal(err)
	}
	if g.p, err = g.Svc.UpdateProvider(ctx, service.System, g.p.ID, service.ProviderInput{SourceGroups: &[]string{staff.ID}}); err != nil {
		t.Fatal(err)
	}

	b, done := g.continueAs(t, eve)
	if done != web.OrgPath(g.acme.ID, "/account") || !b.hasSessionIn(g.acme) {
		t.Fatalf("a member: %q", done)
	}
	before, _ := g.Svc.Users.Count(ctx, g.acme.ID)
	b, done = g.continueAs(t, mal)
	if !strings.Contains(done, "error=group") || b.hasSessionIn(g.acme) {
		t.Fatalf("not a member: %q", done)
	}
	if after, _ := g.Svc.Users.Count(ctx, g.acme.ID); after != before {
		t.Fatalf("users of acme: %d, then %d", before, after)
	}
	if _, err := g.Svc.Identities.GetByUnique(ctx, model.IdentityKey(g.p.ID, mal.ID)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("mal linked by email: %v", err)
	}
	if _, err := g.Svc.Identities.GetByUnique(ctx, model.IdentityKey(g.p.ID, eve.ID)); err != nil {
		t.Fatalf("eve's link: %v", err)
	}

	// eve leaves the group: her guest account stays, and her next sign-in is refused
	if _, err := g.Svc.ChangeGroup(ctx, service.System, staff, service.GroupInput{}, nil, []string{eve.ID}); err != nil {
		t.Fatal(err)
	}
	if b, done = g.continueAs(t, eve); !strings.Contains(done, "error=group") || b.hasSessionIn(g.acme) {
		t.Fatalf("a member no longer: %q", done)
	}
	// with no groups, everyone of the source organization signs in again
	if _, err := g.Svc.UpdateProvider(ctx, service.System, g.p.ID, service.ProviderInput{SourceGroups: &[]string{}}); err != nil {
		t.Fatal(err)
	}
	if b, done = g.continueAs(t, eve); done != web.OrgPath(g.acme.ID, "/account") || !b.hasSessionIn(g.acme) {
		t.Fatalf("no groups: %q", done)
	}
}
