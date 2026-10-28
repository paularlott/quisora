package login_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/oidc"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// guestEnv is a server with the OAuth endpoints and an organization "acme" whose sign-in page offers the primary
// organization's users a way in: an organization provider of the primary organization.
type guestEnv struct {
	*env
	acme *model.Org
	p    *model.Provider
}

func newGuestEnv(t *testing.T, mut func(*service.ProviderInput)) *guestEnv {
	e := newEnvModules(t, false, func(s *web.Server) []web.Module { return []web.Module{oidc.New(s)} }, noIPLimit)
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
	b := g.signedIn(t, u)
	b.base = web.OrgPath(g.acme.ID, "")
	res, _ := b.get("/login/provider/" + g.p.ID)
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
	if !strings.HasPrefix(back, g.Cfg.OrgIssuer(g.acme.ID)+"/login/callback/"+g.p.ID+"?") {
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
