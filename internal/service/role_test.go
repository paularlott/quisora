package service_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Every path that raises a user to a manager, administrator or super admin ends with the same consequences, because
// they all change the role through applyRole: the sign-in links nobody chose (made by email address, or of unknown
// origin) are gone, an audit event says so, and the links the user made themselves stay.
func TestEveryPromotionDropsEmailLinks(t *testing.T) {
	// each path makes a user of an organization (the primary one, or a new one set-primary makes primary) with two
	// links, promotes them and returns them with the role they should have
	paths := []struct {
		name string
		run  func(e *env, promote func(u *model.User)) (*model.User, model.Role)
	}{
		{"UpdateUser as the system", func(e *env, promote func(*model.User)) (*model.User, model.Role) {
			u := e.user(e.primary.ID, "viasys", model.RoleUser)
			promote(u)
			if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Role: ptr(model.RoleAdmin)}); err != nil {
				e.t.Fatal(err)
			}
			return u, model.RoleAdmin
		}},
		{"UpdateUser as a super admin", func(e *env, promote func(*model.User)) (*model.User, model.Role) {
			u := e.user(e.primary.ID, "viasuper", model.RoleUser)
			promote(u)
			if _, err := e.svc.UpdateUser(e.ctx, actor(e.super), u.ID, service.UserInput{Role: ptr(model.RoleManager)}); err != nil {
				e.t.Fatal(err)
			}
			return u, model.RoleManager
		}},
		{"break-glass --super-admin", func(e *env, promote func(*model.User)) (*model.User, model.Role) {
			u := e.user(e.primary.ID, "viabg", model.RoleUser)
			promote(u)
			if _, _, err := e.svc.CreateBreakGlassInvite(e.ctx, u.ID, true); err != nil {
				e.t.Fatal(err)
			}
			return u, model.RoleSuperAdmin
		}},
		{"set-primary", func(e *env, promote func(*model.User)) (*model.User, model.Role) {
			o := e.org("next-primary")
			u := e.user(o.ID, "viaprimary", model.RoleUser)
			promote(u)
			if _, _, err := e.svc.SetPrimaryOrg(e.ctx, o.ID, u.ID); err != nil {
				e.t.Fatal(err)
			}
			return u, model.RoleSuperAdmin
		}},
	}
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			e := newEnv(t)
			var byEmail, byAdmin *model.Identity
			u, want := p.run(e, func(u *model.User) {
				org := e.fresh(u).OrgID
				a, err := e.svc.CreateProvider(e.ctx, service.System, org, goodProvider("sso-a"))
				if err != nil {
					t.Fatal(err)
				}
				b, err := e.svc.CreateProvider(e.ctx, service.System, org, goodProvider("sso-b"))
				if err != nil {
					t.Fatal(err)
				}
				byEmail = model.NewIdentity(e.fresh(u), a, "s1", u.Email, "email")
				byAdmin = model.NewIdentity(e.fresh(u), b, "s2", u.Email, "admin")
				for _, i := range []*model.Identity{byEmail, byAdmin} {
					if err := e.svc.Identities.Create(e.ctx, i); err != nil {
						t.Fatal(err)
					}
				}
			})
			if got := e.fresh(u).Role; got != want {
				t.Fatalf("role %s, want %s", got, want)
			}
			left, err := e.svc.Identities.All(e.ctx, u.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(left) != 1 || left[0].ID != byAdmin.ID {
				t.Errorf("after the promotion the links are %d (want only the one the user made)", len(left))
			}
			ev := e.audits("identity.unlink")
			if len(ev) != 1 || ev[0].Detail["reason"] != "promoted to "+string(want) {
				t.Errorf("unlink events: %+v", ev)
			}
		})
	}
}

// A promotion whose outcome is unknown (it may have landed, and a rerun finds nothing left to change) finishes the same
// way: the links nobody chose go.
func TestPromotionOfUnknownOutcomeDropsEmailLinks(t *testing.T) {
	e, lands := newUnknownEnv(t)
	u := e.user(e.primary.ID, "unk", model.RoleUser)
	p, err := e.svc.CreateProvider(e.ctx, service.System, e.primary.ID, goodProvider("sso"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Identities.Create(e.ctx, model.NewIdentity(e.fresh(u), p, "s1", u.Email, "email")); err != nil {
		t.Fatal(err)
	}
	lands.arm(model.KindUser)
	if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Role: ptr(model.RoleManager)}); err == nil {
		t.Fatal("the write was not reported as unknown")
	}
	if got := e.fresh(u).Role; got != model.RoleManager {
		t.Fatalf("the write did not land: %s", got)
	}
	if left, _ := e.svc.Identities.All(e.ctx, u.ID); len(left) != 0 {
		t.Errorf("the link nobody chose survived a promotion of unknown outcome")
	}
}

// A user's role is assigned in one place only (applyRole, role.go): no other code of the service, SCIM, the console or
// the sign-in side assigns a Role field, so a new way to change a role cannot skip what a change in privilege does.
// (New accounts are made with their role in the record: they have no links to drop.)
func TestRoleIsSetOnlyByApplyRole(t *testing.T) {
	for _, dir := range []string{".", "../scim", "../admin", "../login", "../oidc", "../upstream"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			tree, err := parser.ParseFile(token.NewFileSet(), f, src, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(tree, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, l := range as.Lhs {
					sel, ok := l.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "Role" {
						continue
					}
					x, _ := sel.X.(*ast.Ident)
					switch {
					case filepath.Base(f) == "role.go":
						continue // applyRole itself
					case x != nil && x.Name == "a" && filepath.Base(f) == "login.go":
						continue // a request's actor takes its role from its user: not a change of the user's role
					case x != nil && (x.Name == "in" || x.Name == "d"):
						continue // the role asked for in a UserInput (the service decides it), not the user's
					}
					t.Errorf("%s assigns a Role field: change a user's role through applyRole", f)
				}
				return true
			})
		}
	}
}
