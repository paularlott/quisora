package service_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// Every path that raises a user to a manager, administrator or super admin ends with the same consequences, because
// they all change the role through applyRole: the sign-in links the user did not make themselves from their own
// account page (made by email address, by an account a provider created at first sign-in, by an administrator, or of
// unknown origin) are gone, an audit event says so for each, and the link the user connected stays.
func TestEveryPromotionDropsEmailLinks(t *testing.T) {
	// each path makes a user of the primary organization with four links, promotes them and returns them with the
	// role they should have
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
	}
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			e := newEnv(t)
			var byConnect *model.Identity
			u, want := p.run(e, func(u *model.User) {
				org := e.fresh(u).OrgID
				prov, err := e.svc.CreateProvider(e.ctx, service.System, org, goodProvider("sso"))
				if err != nil {
					t.Fatal(err)
				}
				for _, via := range []string{"email", "provision", "admin", "connect"} {
					i := model.NewIdentity(e.fresh(u), prov, "sub-"+via, u.Email, via)
					if err := e.svc.Identities.Create(e.ctx, i); err != nil {
						t.Fatal(err)
					}
					if via == "connect" {
						byConnect = i
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
			if len(left) != 1 || left[0].ID != byConnect.ID {
				t.Errorf("after the promotion %d links are left (want only the one the user connected)", len(left))
			}
			ev := e.audits("identity.unlink")
			if len(ev) != 3 || ev[0].Detail["reason"] != "promoted to "+string(want) {
				t.Errorf("unlink events: %+v", ev)
			}
		})
	}
}

// Credentials set up through a provider's sign-in (model.User.SetUpBy) go with a promotion that leaves the account
// without that provider, by every path of promotion, in the write that promotes: the password, the authenticator app,
// the recovery codes and the credential epoch (passkeys, connected providers, API tokens), audited as
// user.signin.reset. A link the account connected itself does not spare it: the provider's holder could connect one
// under the provider's own sign-in.
func TestPromotionResetsCredentialsAProviderSetUp(t *testing.T) {
	for _, tc := range []struct {
		name    string
		via     string // how the provider that set the credentials up is linked
		promote func(e *env, u *model.User)
		reset   bool
	}{
		{"UpdateUser, provider created the account", "provision", func(e *env, u *model.User) {
			if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Role: ptr(model.RoleManager)}); err != nil {
				e.t.Fatal(err)
			}
		}, true},
		{"break-glass --super-admin, linked by email", "email", func(e *env, u *model.User) {
			if _, _, err := e.svc.CreateBreakGlassInvite(e.ctx, u.ID, true); err != nil {
				e.t.Fatal(err)
			}
		}, true},
		{"UpdateUser, provider the account connected", "connect", func(e *env, u *model.User) {
			if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Role: ptr(model.RoleManager)}); err != nil {
				e.t.Fatal(err)
			}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			u := e.user(e.primary.ID, "pat", model.RoleUser)
			prov, err := e.svc.CreateProvider(e.ctx, service.System, e.primary.ID, goodProvider("sso"))
			if err != nil {
				t.Fatal(err)
			}
			if err := e.svc.Identities.Create(e.ctx, model.NewIdentity(e.fresh(u), prov, "sub-1", u.Email, tc.via)); err != nil {
				t.Fatal(err)
			}
			set := e.fresh(u)
			set.SetUpBy, set.PasswordHash, set.TOTPSecret, set.RecoveryCodes = prov.ID, "hash", "sealed secret", []string{"code"}
			if err := e.svc.Users.Update(e.ctx, set); err != nil {
				t.Fatal(err)
			}
			tc.promote(e, u)
			got := e.fresh(u)
			cleared := got.PasswordHash == "" && got.TOTPSecret == "" && got.RecoveryCodes == nil && got.SetUpBy == "" &&
				got.CredEpoch != set.CredEpoch
			kept := got.PasswordHash != "" && got.TOTPSecret != "" && got.SetUpBy == prov.ID && got.CredEpoch == set.CredEpoch
			if tc.reset && !cleared || !tc.reset && !kept {
				t.Fatalf("after the promotion: password %v, app %v, set up by %q, same epoch %v", got.PasswordHash != "",
					got.TOTPSecret != "", got.SetUpBy, got.CredEpoch == set.CredEpoch)
			}
			if ev := e.audits("user.signin.reset"); tc.reset != (len(ev) == 1) || tc.reset && ev[0].Detail["provider"] != prov.ID {
				t.Fatalf("user.signin.reset events: %+v", ev)
			}
		})
	}
}

// An API token made for a provider's sign-in while the account had no second factor of its own
// (APITokenInput.SetUpBy) records the provider on the account in the write that makes it, and a promotion that leaves
// the account without that provider ends the token. One made without it records nothing and stays.
func TestPromotionEndsTokenAProviderSetUp(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setUp bool
	}{{"made through the provider", true}, {"the account's own", false}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.setAPITokens(e.primary.ID, model.APITokensEveryone)
			u := e.user(e.primary.ID, "pat", model.RoleUser)
			prov, err := e.svc.CreateProvider(e.ctx, service.System, e.primary.ID, goodProvider("sso"))
			if err != nil {
				t.Fatal(err)
			}
			if err := e.svc.Identities.Create(e.ctx, model.NewIdentity(e.fresh(u), prov, "sub-1", u.Email, "email")); err != nil {
				t.Fatal(err)
			}
			in := service.APITokenInput{Name: "ci", Scopes: []string{service.ScopeAPI}}
			if tc.setUp {
				in.SetUpBy = prov.ID
			}
			_, plain, err := e.svc.CreateAPIToken(e.ctx, actor(e.fresh(u)), in)
			if err != nil {
				t.Fatal(err)
			}
			if got := e.fresh(u); got.SetUpBy != in.SetUpBy {
				t.Errorf("set up by %q, want %q", got.SetUpBy, in.SetUpBy)
			}
			if _, _, err := e.svc.ValidateAPIToken(e.ctx, plain); err != nil {
				t.Fatalf("the new token: %v", err)
			}
			if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Role: ptr(model.RoleManager)}); err != nil {
				t.Fatal(err)
			}
			if _, _, err := e.svc.ValidateAPIToken(e.ctx, plain); tc.setUp == (err == nil) {
				t.Fatalf("the token after the promotion: %v", err)
			}
		})
	}
}

// A token is made only for the account its maker decided on: a promotion committed while it is being made (after the
// account is read, before the token is written) refuses it, whether it is the provider's (SetUpBy, which is not then
// recorded on the promoted account) or not, and so does one committed before, seen by the caller on an older copy
// (APITokenInput.Seen). Otherwise a token made by a plain user's session, with the credential epoch the promotion
// did not reset, would work for the manager forever.
func TestTokenMadeAcrossAPromotionIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setUp  bool
		during bool // the promotion commits while the token is being made; otherwise before, on a copy seen earlier
	}{
		{"the provider's, promoted meanwhile", true, true},
		{"the account's own, promoted meanwhile", false, true},
		{"the provider's, promoted before", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.setAPITokens(e.primary.ID, model.APITokensEveryone)
			u := e.user(e.primary.ID, "pat", model.RoleUser)
			prov, err := e.svc.CreateProvider(e.ctx, service.System, e.primary.ID, goodProvider("sso"))
			if err != nil {
				t.Fatal(err)
			}
			if err := e.svc.Identities.Create(e.ctx, model.NewIdentity(e.fresh(u), prov, "sub-1", "", "connect")); err != nil {
				t.Fatal(err)
			}
			seen := e.fresh(u)
			in := service.APITokenInput{Name: "ci", Scopes: []string{service.ScopeAPI}, Seen: seen}
			if tc.setUp {
				in.SetUpBy = prov.ID
			}
			promote := func() {
				if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Role: ptr(model.RoleManager)}); err != nil {
					t.Error(err)
				}
			}
			if tc.during {
				var once sync.Once
				fs := &faultStore{Store: e.svc.Store, beforeCAS: func(r *store.Record, _ hlc.Timestamp) error {
					if r.Kind == model.KindAPIToken {
						once.Do(promote)
					}
					return nil
				}}
				e.svc.Users.S, e.svc.APITokens.S = fs, fs
			} else {
				promote()
			}
			_, plain, err := e.svc.CreateAPIToken(e.ctx, actor(seen), in)
			if !errors.Is(err, service.ErrStale) {
				t.Fatalf("a token made across a promotion: %v (validates: %v)", err, validates(e, plain))
			}
			got := e.fresh(u)
			if got.Role != model.RoleManager || got.SetUpBy != "" {
				t.Fatalf("after: role %s, set up by %q", got.Role, got.SetUpBy)
			}
			if l, _, err := e.svc.ListAPITokens(e.ctx, actor(got), store.ListQuery{}); err != nil || len(l) != 0 {
				t.Fatalf("tokens stored: %d %v", len(l), err)
			}
		})
	}
}

// A promotion that resets nothing still ends the account's sessions (a new session epoch): their records are tidied
// away and their applications told once, as for any end of sessions, by every path of promotion.
func TestPromotionWithoutResetTidiesTheSessionsItEnds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		promote func(e *env, u *model.User) error
	}{
		{"UpdateUser", func(e *env, u *model.User) error {
			_, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Role: ptr(model.RoleManager)})
			return err
		}},
		{"break-glass --super-admin", func(e *env, u *model.User) error {
			_, _, err := e.svc.CreateBreakGlassInvite(e.ctx, u.ID, true)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			u := e.user(e.primary.ID, "pat", model.RoleUser)
			s := &model.Session{UserID: u.ID, OrgID: u.OrgID, Epoch: e.fresh(u).SessionEpoch, Expires: time.Now().Add(time.Hour),
				LastSeen: time.Now()}
			if err := e.svc.Sessions.Create(e.ctx, s); err != nil {
				t.Fatal(err)
			}
			var told []string
			e.svc.OnSessionsEnding = func(_ context.Context, _ string, ids []string) { told = append(told, ids...) }
			if err := tc.promote(e, u); err != nil {
				t.Fatal(err)
			}
			if len(e.audits("user.signin.reset")) != 0 {
				t.Fatal("the promotion reset the account (not this test's case)")
			}
			if _, err := e.svc.Sessions.Get(e.ctx, s.ID); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("the ended session's record is left: %v", err)
			}
			if len(told) != 1 || told[0] != s.ID {
				t.Fatalf("applications told of %v, want %s once", told, s.ID)
			}
		})
	}
}

func validates(e *env, plain string) bool {
	if plain == "" {
		return false
	}
	_, _, err := e.svc.ValidateAPIToken(e.ctx, plain)
	return err == nil
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
