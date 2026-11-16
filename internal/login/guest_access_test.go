package login_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// vendorTenant puts the guest environment's provider's sign-in application in a new members-only tenant of the primary
// organization ("vendor"), and returns that tenant.
func (g *guestEnv) vendorTenant(t *testing.T) *model.Tenant {
	t.Helper()
	ctx := context.Background()
	set := model.DefaultTenantSettings()
	set.MembersOnly, set.RequireMFA = true, false
	tn, err := g.Svc.CreateTenant(ctx, service.System, g.Primary.ID, service.TenantInput{Name: ptr("vendor"), DisplayName: ptr("Vendor"), Settings: &set})
	if err != nil {
		t.Fatal(err)
	}
	was := g.p.ClientID
	p, err := g.Svc.UpdateProvider(ctx, service.System, g.p.ID, service.ProviderInput{SourceTenant: ptr("vendor")})
	if err != nil {
		t.Fatal(err)
	}
	if p.SourceTenant != tn.ID || p.ClientID == was {
		t.Fatalf("the provider's source tenant %q (want %q), client %q (was %q)", p.SourceTenant, tn.ID, p.ClientID, was)
	}
	if c, err := g.Svc.Clients.Get(ctx, p.ClientID); err != nil || c.TenantID != tn.ID {
		t.Fatalf("the sign-in application is not in the vendor tenant: %v %+v", err, c)
	}
	g.p = p
	return tn
}

// refusedAtSource has u, signed in at the source organization, choose "Continue with" on acme's sign-in page, and
// reports whether the source organization's authorization endpoint refused them (403: no access to the sign-in
// application) rather than sending a code back.
func (g *guestEnv) refusedAtSource(t *testing.T, u *model.User) bool {
	t.Helper()
	b := g.signedIn(t, u)
	b.base = web.OrgPath(g.acme.ID, "")
	res, _ := b.get("/login/provider/" + g.p.ID)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("provider start: %d", res.StatusCode)
	}
	lu, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	next, _ := b.getAbs(lu.RequestURI())
	return next.StatusCode == http.StatusForbidden
}

// The vendor case: the provider's sign-in application is in a members-only tenant of the source organization, so only
// the people on its access list sign in as guests, and only until their access ends. When it ends (by its end, before
// any sweep), the guest's session, refresh token and access token stop at once; the sweep then ends the guest's
// sessions too.
func TestGuestSignInStandsOnTheSourceTenantAccess(t *testing.T) {
	g := newGuestEnv(t, func(in *service.ProviderInput) { in.LinkByEmail = ptr(true) })
	ctx := context.Background()
	tn := g.vendorTenant(t)
	pat := g.person(t, g.Primary, "pat", "pat@example.com")
	patGuest := g.person(t, g.acme, "pat-guest", "pat@example.com")

	if !g.refusedAtSource(t, pat) {
		t.Fatal("no refusal for a user with no access to the vendor tenant")
	}

	end := time.Now().Add(time.Hour).Format(time.RFC3339)
	e, err := g.Svc.AddAccess(ctx, service.System, tn.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: pat.ID,
		Expires: &end, Reason: ptr("SUP-1")})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := g.continueAs(t, pat)
	if !signedInToAcme(b) {
		t.Fatal("not signed in as a guest with access to the vendor tenant")
	}
	app := g.signInToApp(t, b)
	if ok, e := app.refreshes(); !ok || app.userinfo() != 200 {
		t.Fatalf("the guest's application: refresh %v %q, userinfo %d", ok, e, app.userinfo())
	}
	ss := sessionsOf(t, g.env, patGuest)
	if len(ss) != 1 || len(ss[0].Sources) != 1 || ss[0].Sources[0].Client != g.p.ClientID {
		t.Fatalf("the guest's session does not record the sign-in application it came through: %+v", ss)
	}

	// The access ends: nothing has run yet, and the guest is out at once.
	acc, err := g.Svc.Access.Get(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	acc.Expires = time.Now().Add(-time.Second).UTC()
	if err := g.Svc.Access.Update(ctx, acc); err != nil {
		t.Fatal(err)
	}
	if signedInToAcme(b) {
		t.Fatal("the guest's session still signs in after the access ended")
	}
	if ok, e := app.refreshes(); ok || e != "invalid_grant" {
		t.Fatalf("the guest's refresh token after the access ended: %v %q", ok, e)
	}
	if st := app.userinfo(); st != 401 {
		t.Fatalf("the guest's access token after the access ended: %d", st)
	}

	// The sweep removes the entry and the guest's sessions.
	if n, err := g.Svc.ExpireAccess(ctx); err != nil || n != 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	if n := len(sessionsOf(t, g.env, patGuest)); n != 0 {
		t.Fatalf("%d guest sessions left after the sweep", n)
	}
	if !g.refusedAtSource(t, pat) {
		t.Fatal("no refusal at the source after the access ended")
	}
}

// Access removed in the source organization ends the guest's sign-in at once too, and the removal signs the guest
// out (its sessions removed) without waiting for any sweep. Access through a group counts as through an entry.
func TestGuestSignInEndsWhenSourceAccessIsRemoved(t *testing.T) {
	g := newGuestEnv(t, func(in *service.ProviderInput) { in.LinkByEmail = ptr(true) })
	ctx := context.Background()
	tn := g.vendorTenant(t)
	pat := g.person(t, g.Primary, "pat", "pat@example.com")
	patGuest := g.person(t, g.acme, "pat-guest", "pat@example.com")
	grp, err := g.Svc.CreateGroupWithMembers(ctx, service.System, g.Primary.ID, service.GroupInput{DisplayName: ptr("Support")}, []string{pat.ID})
	if err != nil {
		t.Fatal(err)
	}
	e, err := g.Svc.AddAccess(ctx, service.System, tn.ID, service.AccessInput{SubjectType: model.SubjectGroup, SubjectID: grp.ID})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := g.continueAs(t, pat)
	if !signedInToAcme(b) {
		t.Fatal("not signed in as a guest through the group's access")
	}
	if err := g.Svc.RemoveAccess(ctx, service.System, tn.ID, e.ID); err != nil {
		t.Fatal(err)
	}
	if signedInToAcme(b) {
		t.Fatal("the guest's session still signs in after the group's access was removed")
	}
	g.Svc.WaitBackground()
	if n := len(sessionsOf(t, g.env, patGuest)); n != 0 {
		t.Fatalf("%d guest sessions left after the access was removed", n)
	}
}

// With the provider's sign-in application in an open tenant (the default tenant, as before), guests sign in as they
// always did: everyone of the source organization.
func TestGuestSignInThroughAnOpenSourceTenant(t *testing.T) {
	g := newGuestEnv(t, func(in *service.ProviderInput) { in.LinkByEmail = ptr(true) })
	def, err := g.Svc.DefaultTenant(context.Background(), g.Primary.ID)
	if err != nil {
		t.Fatal(err)
	}
	if g.p.SourceTenant != def.ID {
		t.Fatalf("source tenant %q, want the default %q", g.p.SourceTenant, def.ID)
	}
	pat := g.person(t, g.Primary, "pat", "pat@example.com")
	g.person(t, g.acme, "pat-guest", "pat@example.com")
	b, _ := g.continueAs(t, pat)
	if !signedInToAcme(b) {
		t.Fatal("not signed in as a guest through the default tenant")
	}
}
