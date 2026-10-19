package service_test

import (
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// cast is a fixed set of actors used by the RBAC matrix: one of each role in the primary org and in org A, and an
// admin of org B.
type cast struct {
	*env
	a, b                           *model.Org
	super, pAdmin, pManager, pUser *model.User
	aAdmin, aManager, aUser        *model.User
	bAdmin                         *model.User
}

func newCast(t testing.TB) *cast {
	e := newEnv(t)
	c := &cast{env: e, a: e.org("org-a"), b: e.org("org-b")}
	c.super = e.super
	c.pAdmin = e.user(e.primary.ID, "padmin", model.RoleAdmin)
	c.pManager = e.user(e.primary.ID, "pmanager", model.RoleManager)
	c.pUser = e.user(e.primary.ID, "puser", model.RoleUser)
	c.aAdmin = e.user(c.a.ID, "aadmin", model.RoleAdmin)
	c.aManager = e.user(c.a.ID, "amanager", model.RoleManager)
	c.aUser = e.user(c.a.ID, "auser", model.RoleUser)
	c.bAdmin = e.user(c.b.ID, "badmin", model.RoleAdmin)
	return c
}

type actorCase struct {
	name string
	u    *model.User
}

func (c *cast) actors() []actorCase {
	return []actorCase{
		{"super", c.super}, {"primary-admin", c.pAdmin}, {"primary-manager", c.pManager}, {"primary-user", c.pUser},
		{"a-admin", c.aAdmin}, {"a-manager", c.aManager}, {"a-user", c.aUser}, {"b-admin", c.bAdmin},
	}
}

// match compares an outcome with an expectation; "denied" accepts forbidden or notfound.
func match(got, want string) bool {
	if want == "denied" {
		return got == "forbidden" || got == "notfound"
	}
	return got == want
}

func (c *cast) check(t *testing.T, name string, err error, want string) {
	t.Helper()
	if got := outcome(err); !match(got, want) {
		t.Errorf("%s: got %s (%v), want %s", name, got, err, want)
	}
}

func TestMatrixCreateUser(t *testing.T) {
	c := newCast(t)
	roles := []model.Role{model.RoleUser, model.RoleManager, model.RoleAdmin, model.RoleSuperAdmin}
	// want[actor][role] for creating a user in org A.
	want := map[string]map[model.Role]string{
		"super":           {model.RoleUser: "ok", model.RoleManager: "ok", model.RoleAdmin: "ok", model.RoleSuperAdmin: "forbidden"},
		"primary-admin":   {model.RoleUser: "forbidden", model.RoleManager: "forbidden", model.RoleAdmin: "forbidden", model.RoleSuperAdmin: "forbidden"},
		"primary-manager": {model.RoleUser: "forbidden", model.RoleManager: "forbidden", model.RoleAdmin: "forbidden", model.RoleSuperAdmin: "forbidden"},
		"primary-user":    {model.RoleUser: "forbidden", model.RoleManager: "forbidden", model.RoleAdmin: "forbidden", model.RoleSuperAdmin: "forbidden"},
		"a-admin":         {model.RoleUser: "ok", model.RoleManager: "ok", model.RoleAdmin: "ok", model.RoleSuperAdmin: "forbidden"},
		"a-manager":       {model.RoleUser: "ok", model.RoleManager: "forbidden", model.RoleAdmin: "forbidden", model.RoleSuperAdmin: "forbidden"},
		"a-user":          {model.RoleUser: "forbidden", model.RoleManager: "forbidden", model.RoleAdmin: "forbidden", model.RoleSuperAdmin: "forbidden"},
		"b-admin":         {model.RoleUser: "forbidden", model.RoleManager: "forbidden", model.RoleAdmin: "forbidden", model.RoleSuperAdmin: "forbidden"},
	}
	for _, ac := range c.actors() {
		for _, r := range roles {
			name := c.next("n")
			_, err := c.svc.CreateUser(c.ctx, actor(ac.u), c.a.ID, service.UserInput{GivenName: gn("T"), Username: &name, Email: ptr(name + "@example.com"), Role: ptr(r)})
			c.check(t, "create "+string(r)+" in org-a as "+ac.name, err, want[ac.name][r])
		}
	}
}

func TestMatrixCreateSuperAdminInPrimary(t *testing.T) {
	c := newCast(t)
	for _, ac := range c.actors() {
		name := c.next("s")
		_, err := c.svc.CreateUser(c.ctx, actor(ac.u), c.primary.ID, service.UserInput{GivenName: gn("T"), Username: &name, Email: ptr(name + "@example.com"), Role: ptr(model.RoleSuperAdmin)})
		want := "forbidden"
		if ac.name == "super" {
			want = "ok"
		}
		c.check(t, "create super_admin in primary as "+ac.name, err, want)
	}
}

func TestMatrixCreatePlainUserInPrimary(t *testing.T) {
	c := newCast(t)
	// Admins/managers of other orgs and of the primary org: primary org members manage the primary org only.
	for _, ac := range c.actors() {
		name := c.next("p")
		_, err := c.svc.CreateUser(c.ctx, actor(ac.u), c.primary.ID, service.UserInput{GivenName: gn("T"), Username: &name, Email: ptr(name + "@example.com")})
		want := "forbidden"
		switch ac.name {
		case "super", "primary-admin", "primary-manager":
			want = "ok"
		}
		c.check(t, "create user in primary as "+ac.name, err, want)
	}
}

func TestMatrixUpdateDisableDeleteUser(t *testing.T) {
	c := newCast(t)
	targets := []model.Role{model.RoleUser, model.RoleManager, model.RoleAdmin}
	// who may modify which target role in org A.
	may := func(actor string, target model.Role) bool {
		switch actor {
		case "super", "a-admin":
			return true
		case "a-manager":
			return target == model.RoleUser
		}
		return false
	}
	for _, ac := range c.actors() {
		for _, tr := range targets {
			mk := func() *model.User { return c.user(c.a.ID, c.next("t"), tr) }
			want := "ok"
			if !may(ac.name, tr) {
				want = "denied"
			}
			// profile edit
			_, err := c.svc.UpdateUser(c.ctx, actor(ac.u), mk().ID, service.UserInput{FamilyName: ptr("New Name")})
			c.check(t, "edit "+string(tr)+" as "+ac.name, err, want)
			// disable
			_, err = c.svc.UpdateUser(c.ctx, actor(ac.u), mk().ID, service.UserInput{Active: ptr(false)})
			c.check(t, "disable "+string(tr)+" as "+ac.name, err, want)
			// nobody sets someone else's password (only the system, for accepted invitations); the permission check
			// still comes first, so actors without access are told "denied"
			_, err = c.svc.UpdateUser(c.ctx, actor(ac.u), mk().ID, service.UserInput{Password: ptr("a-long-enough-password")})
			wantSet := "invalid"
			if want == "denied" {
				wantSet = "denied"
			}
			c.check(t, "set password "+string(tr)+" as "+ac.name, err, wantSet)
			// remove password
			err = c.svc.RemovePassword(c.ctx, actor(ac.u), mk().ID)
			c.check(t, "remove password "+string(tr)+" as "+ac.name, err, want)
			// new invitation
			_, _, err = c.svc.CreateInvite(c.ctx, actor(ac.u), mk().ID)
			c.check(t, "invite "+string(tr)+" as "+ac.name, err, want)
			// delete
			err = c.svc.DeleteUser(c.ctx, actor(ac.u), mk().ID)
			c.check(t, "delete "+string(tr)+" as "+ac.name, err, want)
			// revoke sessions
			err = c.svc.RevokeSessions(c.ctx, actor(ac.u), mk().ID)
			c.check(t, "revoke sessions "+string(tr)+" as "+ac.name, err, want)
		}
	}
}

func TestMatrixRoleChange(t *testing.T) {
	c := newCast(t)
	type change struct{ from, to model.Role }
	changes := []change{
		{model.RoleUser, model.RoleManager}, {model.RoleUser, model.RoleAdmin}, {model.RoleManager, model.RoleUser},
		{model.RoleManager, model.RoleAdmin}, {model.RoleAdmin, model.RoleUser}, {model.RoleAdmin, model.RoleManager},
		{model.RoleUser, model.RoleSuperAdmin},
	}
	for _, ac := range c.actors() {
		for _, ch := range changes {
			target := c.user(c.a.ID, c.next("r"), ch.from)
			// A second admin so the last-admin guard is not what is being tested.
			_, err := c.svc.UpdateUser(c.ctx, actor(ac.u), target.ID, service.UserInput{Role: ptr(ch.to)})
			want := "denied"
			switch {
			case ch.to == model.RoleSuperAdmin:
				want = "denied"
			case ac.name == "super" || ac.name == "a-admin":
				want = "ok"
			}
			c.check(t, "role "+string(ch.from)+"->"+string(ch.to)+" as "+ac.name, err, want)
		}
	}
}

func TestMatrixPrimaryOrgSuperAdminProtection(t *testing.T) {
	c := newCast(t)
	super2 := c.user(c.primary.ID, "super2", model.RoleSuperAdmin)
	for _, ac := range c.actors() {
		if ac.name == "super" {
			continue
		}
		// Nobody but a super admin may touch a super admin, whatever their role in the same org.
		_, err := c.svc.UpdateUser(c.ctx, actor(ac.u), super2.ID, service.UserInput{FamilyName: ptr("x")})
		c.check(t, "edit super as "+ac.name, err, "denied")
		_, err = c.svc.UpdateUser(c.ctx, actor(ac.u), super2.ID, service.UserInput{Role: ptr(model.RoleUser)})
		c.check(t, "demote super as "+ac.name, err, "denied")
		err = c.svc.DeleteUser(c.ctx, actor(ac.u), super2.ID)
		c.check(t, "delete super as "+ac.name, err, "denied")
		_, err = c.svc.UpdateUser(c.ctx, actor(ac.u), super2.ID, service.UserInput{Active: ptr(false)})
		c.check(t, "disable super as "+ac.name, err, "denied")
	}
	// A super admin may (a second one exists).
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.super), super2.ID, service.UserInput{FamilyName: ptr("ok")}); err != nil {
		t.Fatal(err)
	}
	// Super admin cannot be created in a non-primary org nor promoted there.
	u := c.user(c.a.ID, "promote-me", model.RoleAdmin)
	_, err := c.svc.UpdateUser(c.ctx, actor(c.super), u.ID, service.UserInput{Role: ptr(model.RoleSuperAdmin)})
	c.check(t, "promote in non-primary org", err, "forbidden")
	// ... even for the system actor.
	_, err = c.svc.CreateUser(c.ctx, service.System, c.a.ID, service.UserInput{GivenName: gn("T"), Username: ptr("sa-in-a"), Email: ptr("sa-in-a@example.com"), Role: ptr(model.RoleSuperAdmin)})
	c.check(t, "create super in non-primary org as system", err, "forbidden")
	// Promotion of a primary-org admin to super admin by a super admin is allowed.
	pa := c.user(c.primary.ID, "promo", model.RoleAdmin)
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.super), pa.ID, service.UserInput{Role: ptr(model.RoleSuperAdmin)}); err != nil {
		t.Fatalf("promote in primary: %v", err)
	}
}

func TestMatrixOrgs(t *testing.T) {
	c := newCast(t)
	for _, ac := range c.actors() {
		name := strings.ToLower(c.next("o") + "-x")
		o, err := c.svc.CreateOrg(c.ctx, actor(ac.u), service.OrgInput{Name: &name})
		want := "forbidden"
		if ac.name == "super" {
			want = "ok"
		}
		c.check(t, "create org as "+ac.name, err, want)
		_ = o
		victim := c.org(strings.ToLower(c.next("v") + "-v"))
		err = c.svc.DeleteOrg(c.ctx, actor(ac.u), victim.ID, false)
		c.check(t, "delete org as "+ac.name, err, want)

		// Edit own org / org A / org B.
		for _, tgt := range []struct {
			org  *model.Org
			own  bool
			name string
		}{{c.primary, ac.u.OrgID == c.primary.ID, "primary"}, {c.a, ac.u.OrgID == c.a.ID, "a"}, {c.b, ac.u.OrgID == c.b.ID, "b"}} {
			_, err := c.svc.UpdateOrg(c.ctx, actor(ac.u), tgt.org.ID, service.OrgInput{DisplayName: ptr("Renamed " + tgt.name)})
			w := "forbidden"
			if ac.name == "super" || (tgt.own && ac.u.Role == model.RoleAdmin) {
				w = "ok"
			}
			c.check(t, "update org "+tgt.name+" as "+ac.name, err, w)
		}

		// Visibility.
		_, err = c.svc.GetOrg(c.ctx, actor(ac.u), c.a.ID)
		w := "notfound"
		if ac.name == "super" || ac.u.OrgID == c.a.ID {
			w = "ok"
		}
		c.check(t, "get org a as "+ac.name, err, w)
		orgs, n, err := c.svc.ListOrgs(c.ctx, actor(ac.u), store.ListQuery{})
		if err != nil {
			t.Fatal(err)
		}
		if ac.name == "super" {
			if n < 3 {
				t.Errorf("super sees %d orgs", n)
			}
		} else if n != 1 || len(orgs) != 1 || orgs[0].ID != ac.u.OrgID {
			t.Errorf("%s should see only own org, got %d", ac.name, n)
		}
	}
}

func TestMatrixGroupsClientsProviders(t *testing.T) {
	c := newCast(t)
	for _, ac := range c.actors() {
		adminOfA := ac.name == "super" || ac.name == "a-admin"
		wantAdmin := "forbidden"
		if adminOfA {
			wantAdmin = "ok"
		}
		// groups
		g, err := c.svc.CreateGroup(c.ctx, actor(ac.u), c.a.ID, service.GroupInput{DisplayName: ptr(c.next("grp"))})
		c.check(t, "create group as "+ac.name, err, wantAdmin)
		if g == nil {
			g, _ = c.svc.CreateGroup(c.ctx, service.System, c.a.ID, service.GroupInput{DisplayName: ptr(c.next("grp"))})
		}
		_, err = c.svc.UpdateGroup(c.ctx, actor(ac.u), g.ID, service.GroupInput{DisplayName: ptr(c.next("grp"))})
		c.check(t, "update group as "+ac.name, err, wantAdmin)
		err = c.svc.SetMembership(c.ctx, actor(ac.u), g.ID, c.aUser.ID, true)
		c.check(t, "add member as "+ac.name, err, wantAdmin)
		err = c.svc.SetMembership(c.ctx, actor(ac.u), g.ID, c.aUser.ID, false)
		c.check(t, "remove member as "+ac.name, err, wantAdmin)
		// Read access to groups follows user management.
		readGroups := ac.name == "super" || ac.name == "a-admin" || ac.name == "a-manager"
		wantRead := "forbidden"
		if readGroups {
			wantRead = "ok"
		}
		_, _, err = c.svc.ListGroups(c.ctx, actor(ac.u), c.a.ID, store.ListQuery{})
		c.check(t, "list groups as "+ac.name, err, wantRead)
		_, err = c.svc.GetGroup(c.ctx, actor(ac.u), g.ID)
		if readGroups {
			c.check(t, "get group as "+ac.name, err, "ok")
		} else {
			c.check(t, "get group as "+ac.name, err, "notfound")
		}
		err = c.svc.DeleteGroup(c.ctx, actor(ac.u), g.ID)
		c.check(t, "delete group as "+ac.name, err, wantAdmin)

		// clients
		cl, secret, err := c.svc.CreateClient(c.ctx, actor(ac.u), c.a.ID, service.ClientInput{Name: ptr(c.next("cli")),
			RedirectURIs: ptr([]string{"https://app.example.com/cb"})})
		c.check(t, "create client as "+ac.name, err, wantAdmin)
		if err == nil && (cl == nil || !strings.HasPrefix(secret, "qsrs_")) {
			t.Errorf("client secret missing")
		}
		if cl == nil {
			cl, _, _ = c.svc.CreateClient(c.ctx, service.System, c.a.ID, service.ClientInput{Name: ptr(c.next("cli")),
				RedirectURIs: ptr([]string{"https://app.example.com/cb"})})
		}
		_, _, err = c.svc.ListClients(c.ctx, actor(ac.u), c.a.ID, store.ListQuery{})
		c.check(t, "list clients as "+ac.name, err, wantAdmin)
		_, err = c.svc.UpdateClient(c.ctx, actor(ac.u), cl.ID, service.ClientInput{Description: ptr("d")})
		if adminOfA {
			c.check(t, "update client as "+ac.name, err, "ok")
		} else {
			c.check(t, "update client as "+ac.name, err, "notfound")
		}
		_, err = c.svc.RotateClientSecret(c.ctx, actor(ac.u), cl.ID)
		if adminOfA {
			c.check(t, "rotate secret as "+ac.name, err, "ok")
		} else {
			c.check(t, "rotate secret as "+ac.name, err, "notfound")
		}
		err = c.svc.DeleteClient(c.ctx, actor(ac.u), cl.ID)
		if adminOfA {
			c.check(t, "delete client as "+ac.name, err, "ok")
		} else {
			c.check(t, "delete client as "+ac.name, err, "notfound")
		}

		// providers
		p, err := c.svc.CreateProvider(c.ctx, actor(ac.u), c.a.ID, goodProvider(c.next("prov")))
		c.check(t, "create provider as "+ac.name, err, wantAdmin)
		if p == nil {
			p, _ = c.svc.CreateProvider(c.ctx, service.System, c.a.ID, goodProvider(c.next("prov")))
		}
		_, _, err = c.svc.ListProviders(c.ctx, actor(ac.u), c.a.ID, store.ListQuery{})
		c.check(t, "list providers as "+ac.name, err, wantAdmin)
		err = c.svc.DeleteProvider(c.ctx, actor(ac.u), p.ID)
		if adminOfA {
			c.check(t, "delete provider as "+ac.name, err, "ok")
		} else {
			c.check(t, "delete provider as "+ac.name, err, "notfound")
		}
	}
}

func goodProvider(name string) service.ProviderInput {
	return service.ProviderInput{Name: &name, Issuer: ptr("https://login.example.com"), ClientID: ptr("cid"),
		ClientSecret: ptr("csecret")}
}

func TestMatrixAuditAndRevoke(t *testing.T) {
	c := newCast(t)
	for _, ac := range c.actors() {
		_, err := c.svc.ListAudit(c.ctx, actor(ac.u), c.a.ID, service.AuditQuery{})
		want := "forbidden"
		if ac.name == "super" || ac.name == "a-admin" {
			want = "ok"
		}
		c.check(t, "audit as "+ac.name, err, want)
	}
}

func TestGetListUserVisibility(t *testing.T) {
	c := newCast(t)
	for _, ac := range c.actors() {
		// Reading a user of org A.
		_, err := c.svc.GetUser(c.ctx, actor(ac.u), c.aUser.ID)
		want := "notfound"
		switch ac.name {
		case "super", "a-admin", "a-manager", "a-user": // a-user is the target itself
			want = "ok"
		}
		c.check(t, "get user as "+ac.name, err, want)
		_, _, err = c.svc.ListUsers(c.ctx, actor(ac.u), c.a.ID, store.ListQuery{})
		want = "forbidden"
		switch ac.name {
		case "super", "a-admin", "a-manager":
			want = "ok"
		}
		c.check(t, "list users as "+ac.name, err, want)
	}
	// Users always see themselves.
	for _, ac := range c.actors() {
		if _, err := c.svc.GetUser(c.ctx, actor(ac.u), ac.u.ID); err != nil {
			t.Errorf("%s cannot read self: %v", ac.name, err)
		}
	}
}
