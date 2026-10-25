package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestAPITokenListingAndDeletionAuthorization(t *testing.T) {
	c := newCast(t)
	tok, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.aUser), service.APITokenInput{Name: "mine", Scopes: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	if l, n, err := c.svc.ListAPITokens(c.ctx, actor(c.aUser), store.ListQuery{}); err != nil || n != 1 || l[0].ID != tok.ID {
		t.Fatalf("own list: %v %d", err, n)
	}
	if _, _, err := c.svc.ListAPITokens(c.ctx, actor(c.aManager), store.ListQuery{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.svc.ListAPITokens(c.ctx, service.System, store.ListQuery{}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("system has no tokens of its own: %v", err)
	}
	for _, tc := range []struct {
		name string
		u    *model.User
		want string
	}{
		{"owner", c.aUser, "ok"}, {"org admin", c.aAdmin, "ok"}, {"org manager", c.aManager, "ok"}, {"super", c.super, "ok"},
		{"foreign admin", c.bAdmin, "denied"}, {"primary user", c.pUser, "denied"}, {"peer", c.e2(c.a.ID), "denied"},
	} {
		_, _, err := c.svc.ListUserAPITokens(c.ctx, actor(tc.u), c.aUser.ID, store.ListQuery{})
		c.check(t, tc.name, err, tc.want)
	}
	if _, _, err := c.svc.ListUserAPITokens(c.ctx, actor(c.aAdmin), "nobody", store.ListQuery{}); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
	// Deleting: someone who may not manage the owner learns nothing, and the token survives.
	for name, u := range map[string]*model.User{"foreign admin": c.bAdmin, "peer": c.e2(c.a.ID)} {
		if err := c.svc.DeleteAPIToken(c.ctx, actor(u), tok.ID); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s delete: %v", name, err)
		}
	}
	if _, err := c.svc.APITokens.Get(c.ctx, tok.ID); err != nil {
		t.Fatal("token deleted by a stranger")
	}
	if err := c.svc.DeleteAPIToken(c.ctx, actor(c.aAdmin), tok.ID); err != nil {
		t.Fatal(err)
	}
	ev := c.audited(c.a.ID, "apitoken.delete")
	if len(ev) != 1 || ev[0].Detail["owner"] != c.aUser.ID {
		t.Errorf("audit %+v", ev)
	}
	if err := c.svc.DeleteAPIToken(c.ctx, actor(c.aAdmin), tok.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("twice: %v", err)
	}
}

func TestAPITokenRegenerateAndUpdateRules(t *testing.T) {
	c := newCast(t)
	tok, plain, err := c.svc.CreateAPIToken(c.ctx, actor(c.aManager), service.APITokenInput{Name: "scim", Scopes: []string{"scim"}, Expires: 5})
	if err != nil {
		t.Fatal(err)
	}
	n, fresh, err := c.svc.RegenerateAPIToken(c.ctx, actor(c.aManager), tok.ID)
	if err != nil || fresh == plain || !n.Expires.Equal(tok.Expires) {
		t.Fatalf("regenerate: %v", err)
	}
	if c.tokenLive(plain) || !c.tokenLive(fresh) {
		t.Error("old secret works, or the new one does not")
	}
	for name, u := range map[string]*model.User{"admin of the org": c.aAdmin, "foreign": c.bAdmin} {
		if _, _, err := c.svc.RegenerateAPIToken(c.ctx, actor(u), tok.ID); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s regenerate: %v", name, err)
		}
		if _, err := c.svc.UpdateAPIToken(c.ctx, actor(u), tok.ID, service.APITokenUpdate{Name: ptr("x")}); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s update: %v", name, err)
		}
	}
	if _, _, err := c.svc.RegenerateAPIToken(c.ctx, service.System, tok.ID); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("system regenerate: %v", err)
	}
	if _, err := c.svc.UpdateAPIToken(c.ctx, service.System, tok.ID, service.APITokenUpdate{}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("system update: %v", err)
	}
	// demoted owner: the scim scope is no longer theirs, so no new secret
	if _, err := c.svc.UpdateUser(c.ctx, service.System, c.aManager.ID, service.UserInput{Role: ptr(model.RoleUser)}); err != nil {
		t.Fatal(err)
	}
	demoted := c.fresh(c.aManager)
	if _, _, err := c.svc.RegenerateAPIToken(c.ctx, actor(demoted), tok.ID); !isInvalid(err) {
		t.Errorf("regenerate after demotion: %v", err)
	}
	if got, _ := c.svc.APITokens.Get(c.ctx, tok.ID); string(got.SecretHash) != string(n.SecretHash) {
		t.Error("secret changed by a refused regeneration")
	}
	// update name rules
	own, _, _ := c.svc.CreateAPIToken(c.ctx, actor(c.aUser), service.APITokenInput{Name: "t", Scopes: []string{"api"}})
	for _, name := range []string{"", "  ", strings.Repeat("n", 101)} {
		if _, err := c.svc.UpdateAPIToken(c.ctx, actor(c.aUser), own.ID, service.APITokenUpdate{Name: ptr(name)}); !isInvalid(err) {
			t.Errorf("name %q: %v", name, err)
		}
	}
	if got, err := c.svc.UpdateAPIToken(c.ctx, actor(c.aUser), own.ID, service.APITokenUpdate{Name: ptr(" renamed ")}); err != nil || got.Name != "renamed" {
		t.Errorf("rename: %v", err)
	}
}

func TestAPITokenCreateValidation(t *testing.T) {
	c := newCast(t)
	for name, in := range map[string]service.APITokenInput{
		"no name":          {Scopes: []string{"api"}},
		"long name":        {Name: strings.Repeat("n", 101), Scopes: []string{"api"}},
		"backup no expiry": {Name: "b", Scopes: []string{"backup"}},
		"negative days":    {Name: "n", Scopes: []string{"api"}, Expires: -1},
		"huge days":        {Name: "n", Scopes: []string{"api"}, Expires: 1 << 20},
		"foreign audience": {Name: "n", Scopes: []string{"api"}, Audience: []string{"nope"}},
	} {
		a := c.aUser
		if strings.HasPrefix(name, "backup") {
			a = c.super
		}
		if _, _, err := c.svc.CreateAPIToken(c.ctx, actor(a), in); !isInvalid(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := c.svc.CreateAPIToken(c.ctx, service.System, service.APITokenInput{Name: "n", Scopes: []string{"api"}}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("system token: %v", err)
	}
	if n, _ := c.svc.APITokens.Count(c.ctx, c.aUser.ID); n != 0 {
		t.Errorf("%d tokens stored by refused requests", n)
	}
	// backup scope: super admin, expiring
	if tok, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.super), service.APITokenInput{Name: "b", Scopes: []string{"backup"}, Expires: 1}); err != nil || tok.Expires.IsZero() {
		t.Errorf("backup token: %v", err)
	}
}

func TestAPITokenAudienceAndAppScopes(t *testing.T) {
	c := newCast(t)
	sys := service.System
	app, _, err := c.svc.CreateClient(c.ctx, sys, c.a.ID, service.ClientInput{Name: ptr("Orders"), GrantTypes: ptr([]string{"client_credentials"}),
		Scopes: ptr([]string{"orders:read", "orders:write"})})
	if err != nil {
		t.Fatal(err)
	}
	foreign, _, err := c.svc.CreateClient(c.ctx, sys, c.b.ID, service.ClientInput{Name: ptr("Theirs"), GrantTypes: ptr([]string{"client_credentials"}),
		Scopes: ptr([]string{"theirs:read"})})
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := c.svc.CreateClient(c.ctx, sys, c.a.ID, service.ClientInput{Name: ptr("Public"), AuthMethod: ptr(model.AuthMethodNone),
		RedirectURIs: ptr([]string{"https://p.example.com/cb"})})
	off, _, _ := c.svc.CreateClient(c.ctx, sys, c.a.ID, service.ClientInput{Name: ptr("Off"), GrantTypes: ptr([]string{"client_credentials"}), Enabled: ptr(false)})

	apps, err := c.svc.TokenApps(c.ctx, actor(c.aUser))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, a := range apps {
		ids[a.ID] = true
	}
	if !ids[app.ID] || ids[foreign.ID] || ids[pub.ID] || ids[off.ID] {
		t.Errorf("token apps %+v", apps)
	}
	if _, err := c.svc.TokenApps(c.ctx, service.System); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("system: %v", err)
	}
	if _, err := c.svc.TokenApps(c.ctx, &service.Actor{UserID: "ghost"}); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("ghost: %v", err)
	}

	mk := func(in service.APITokenInput) error {
		in.Name = "t"
		_, _, err := c.svc.CreateAPIToken(c.ctx, actor(c.aUser), in)
		return err
	}
	for name, in := range map[string]service.APITokenInput{
		"foreign client":         {Scopes: []string{"api"}, Audience: []string{foreign.ID}},
		"audience on scim":       {Scopes: []string{"scim"}, Audience: []string{app.ID}},
		"app scopes no api":      {Scopes: []string{"scim"}, AppScopes: []string{"orders:read"}},
		"app scopes no audience": {Scopes: []string{"api"}, AppScopes: []string{"orders:read"}},
		"undeclared scope":       {Scopes: []string{"api"}, Audience: []string{app.ID}, AppScopes: []string{"orders:delete"}},
		"bad scope syntax":       {Scopes: []string{"api"}, Audience: []string{app.ID}, AppScopes: []string{"a b"}},
	} {
		if err := mk(in); !isInvalid(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	over := make([]string, 21)
	for i := range over {
		over[i] = "x" + itoa(i)
	}
	if err := mk(service.APITokenInput{Scopes: []string{"api"}, Audience: over}); !isInvalid(err) {
		t.Errorf("too many audience: %v", err)
	}
	if err := mk(service.APITokenInput{Scopes: []string{"api"}, Audience: []string{app.ID, " " + app.ID, ""}, AppScopes: []string{"orders:read"}}); err != nil {
		t.Fatalf("good token: %v", err)
	}
	// Updating the audience re-checks the scopes: a scope must stay one of the applications'.
	tok, _, _ := c.svc.CreateAPIToken(c.ctx, actor(c.aUser), service.APITokenInput{Name: "t2", Scopes: []string{"api"}, Audience: []string{app.ID}, AppScopes: []string{"orders:read"}})
	if _, err := c.svc.UpdateAPIToken(c.ctx, actor(c.aUser), tok.ID, service.APITokenUpdate{Audience: &[]string{foreign.ID}}); !isInvalid(err) {
		t.Errorf("foreign audience on update: %v", err)
	}
	if _, err := c.svc.UpdateAPIToken(c.ctx, actor(c.aUser), tok.ID, service.APITokenUpdate{AppScopes: &[]string{"orders:delete"}}); !isInvalid(err) {
		t.Errorf("undeclared scope on update: %v", err)
	}
	if got, err := c.svc.UpdateAPIToken(c.ctx, actor(c.aUser), tok.ID, service.APITokenUpdate{AppScopes: &[]string{"orders:write"}}); err != nil || got.AppScopes[0] != "orders:write" {
		t.Errorf("update scopes: %v", err)
	}
	if len(c.audited(c.a.ID, "apitoken.update")) != 1 {
		t.Error("update not audited")
	}
}

func TestListAccessSortSearchAndAuthorization(t *testing.T) {
	c := newCast(t)
	sys := service.System
	ten, _ := c.svc.CreateTenant(c.ctx, sys, c.a.ID, service.TenantInput{Name: ptr("staff")})
	grp, err := c.svc.CreateGroup(c.ctx, sys, c.a.ID, service.GroupInput{DisplayName: ptr("Operations")})
	if err != nil {
		t.Fatal(err)
	}
	add := func(typ, id string, in service.AccessInput) *service.AccessEntry {
		in.SubjectType, in.SubjectID = typ, id
		e, err := c.svc.AddAccess(c.ctx, actor(c.aAdmin), ten.ID, in)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	exp := time.Now().Add(48 * time.Hour).Format(time.DateOnly)
	add(model.SubjectUser, c.aUser.ID, service.AccessInput{Expires: &exp})
	add(model.SubjectUser, c.aManager.ID, service.AccessInput{})
	past := time.Now().Add(-48 * time.Hour).Format(time.RFC3339)
	g := add(model.SubjectGroup, grp.ID, service.AccessInput{Expires: &past, Roles: &[]string{"Viewer"}})
	if !g.Expired || g.Roles[0] != "Viewer" {
		t.Errorf("group entry %+v", g.TenantAccess)
	}
	// a super admin's access cannot be added or seen below them
	if _, err := c.svc.AddAccess(c.ctx, actor(c.aAdmin), ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: c.super.ID}); !isInvalid(err) {
		t.Errorf("super admin subject: %v", err)
	}
	names := func(q store.ListQuery) []string {
		l, _, err := c.svc.ListAccess(c.ctx, actor(c.aAdmin), ten.ID, q)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range l {
			out = append(out, e.Name)
		}
		return out
	}
	if got := names(store.ListQuery{}); len(got) != 3 || got[0] != "amanager" {
		t.Errorf("by name: %v", got)
	}
	if got := names(store.ListQuery{Sort: "name", Desc: true}); got[0] != "Operations" {
		t.Errorf("by name desc: %v", got)
	}
	if got := names(store.ListQuery{Sort: "type"}); got[2] != "Operations" {
		t.Errorf("by type (users first): %v", got)
	}
	if got := names(store.ListQuery{Sort: "expires"}); got[2] != "amanager" {
		t.Errorf("by expires (none last): %v", got)
	}
	if got := names(store.ListQuery{Sort: "created"}); len(got) != 3 {
		t.Errorf("by created: %v", got)
	}
	if got := names(store.ListQuery{Search: "AUSER@example"}); len(got) != 1 || got[0] != "auser" {
		t.Errorf("search by email: %v", got)
	}
	if got := names(store.ListQuery{Offset: 1, Limit: 1}); len(got) != 1 {
		t.Errorf("paging: %v", got)
	}
	if got := names(store.ListQuery{Offset: 9}); len(got) != 0 {
		t.Errorf("offset past end: %v", got)
	}
	if _, _, err := c.svc.ListAccess(c.ctx, actor(c.aAdmin), ten.ID, store.ListQuery{Sort: "bogus"}); !isInvalid(err) {
		t.Errorf("bad sort: %v", err)
	}
	for name, u := range map[string]*model.User{"manager": c.aManager, "foreign admin": c.bAdmin} {
		if _, _, err := c.svc.ListAccess(c.ctx, actor(u), ten.ID, store.ListQuery{}); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s list: %v", name, err)
		}
		if _, err := c.svc.AddAccess(c.ctx, actor(u), ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: c.pUser.ID}); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s add: %v", name, err)
		}
		if _, err := c.svc.UpdateAccess(c.ctx, actor(u), ten.ID, g.ID, service.AccessInput{Roles: &[]string{"x"}}); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s update: %v", name, err)
		}
		if err := c.svc.RemoveAccess(c.ctx, actor(u), ten.ID, g.ID); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%s remove: %v", name, err)
		}
	}
	if n, _, _ := c.svc.ListAccess(c.ctx, actor(c.aAdmin), ten.ID, store.ListQuery{}); len(n) != 3 {
		t.Error("access changed by denied callers")
	}
	// a user of another org is no subject
	if _, err := c.svc.AddAccess(c.ctx, actor(c.aAdmin), ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: c.bAdmin.ID}); !isInvalid(err) {
		t.Errorf("foreign user: %v", err)
	}
	if _, err := c.svc.AddAccess(c.ctx, actor(c.aAdmin), ten.ID, service.AccessInput{SubjectType: "robot", SubjectID: "x"}); !isInvalid(err) {
		t.Errorf("bad subject type: %v", err)
	}
	if _, err := c.svc.AddAccess(c.ctx, actor(c.aAdmin), ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: c.aUser.ID}); !errors.Is(err, service.ErrConflict) {
		t.Errorf("duplicate: %v", err)
	}
	// input validation
	for name, in := range map[string]service.AccessInput{
		"bad role":    {Roles: &[]string{"no spaces"}},
		"bad tag":     {Tags: &[]string{"no spaces"}},
		"bad date":    {Expires: ptr("tomorrow")},
		"unknown app": {AllClients: ptr(false), Clients: &[]string{"nope"}},
		"no apps":     {AllClients: ptr(false)},
	} {
		in.SubjectType, in.SubjectID = model.SubjectUser, c.pManager.ID
		if name == "no apps" || name == "unknown app" || name == "bad role" || name == "bad tag" || name == "bad date" {
			in.SubjectID = c.aAdmin.ID
		}
		if _, err := c.svc.AddAccess(c.ctx, actor(c.aAdmin), ten.ID, in); !isInvalid(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// update and remove are audited
	if _, err := c.svc.UpdateAccess(c.ctx, actor(c.aAdmin), ten.ID, g.ID, service.AccessInput{Expires: ptr("")}); err != nil {
		t.Fatal(err)
	}
	if err := c.svc.RemoveAccess(c.ctx, actor(c.aAdmin), ten.ID, g.ID); err != nil {
		t.Fatal(err)
	}
	if len(c.audited(c.a.ID, "tenant.access.update")) != 1 || len(c.audited(c.a.ID, "tenant.access.remove")) != 1 {
		t.Error("access update/remove not audited")
	}
	// removed and re-added: a new generation, not a conflict
	if _, err := c.svc.AddAccess(c.ctx, actor(c.aAdmin), ten.ID, service.AccessInput{SubjectType: model.SubjectGroup, SubjectID: grp.ID}); err != nil {
		t.Errorf("re-adding: %v", err)
	}
}

func TestCurbsAdmin(t *testing.T) {
	day := func(d int) *string { s := time.Now().UTC().AddDate(0, 0, d).Format(time.DateOnly); return &s }
	admin := &model.User{Role: model.RoleAdmin, Active: true}
	super := &model.User{Role: model.RoleSuperAdmin, Active: true}
	manager := &model.User{Role: model.RoleManager, Active: true}
	soon := &model.User{Role: model.RoleAdmin, Active: true, ValidUntil: ptr(time.Now().UTC().AddDate(0, 0, 10))}
	for _, tc := range []struct {
		name string
		u    *model.User
		in   service.UserInput
		want bool
	}{
		{"demote admin", admin, service.UserInput{Role: ptr(model.RoleManager)}, true},
		{"keep role", admin, service.UserInput{Role: ptr(model.RoleAdmin)}, false},
		{"promote manager", manager, service.UserInput{Role: ptr(model.RoleAdmin)}, false},
		{"disable admin", admin, service.UserInput{Active: ptr(false)}, true},
		{"disable super", super, service.UserInput{Active: ptr(false)}, true},
		{"disable manager", manager, service.UserInput{Active: ptr(false)}, false},
		{"enable disabled admin", &model.User{Role: model.RoleAdmin}, service.UserInput{Active: ptr(true)}, false},
		{"disable already disabled", &model.User{Role: model.RoleAdmin}, service.UserInput{Active: ptr(false)}, false},
		{"end date on admin with none", admin, service.UserInput{ValidUntil: day(5)}, true},
		{"earlier end date", soon, service.UserInput{ValidUntil: day(2)}, true},
		{"later end date", soon, service.UserInput{ValidUntil: day(30)}, false},
		{"clear end date", soon, service.UserInput{ValidUntil: ptr("")}, false},
		{"unparsable end date", admin, service.UserInput{ValidUntil: ptr("soon")}, false},
		{"end date on manager", manager, service.UserInput{ValidUntil: day(1)}, false},
		{"nothing", admin, service.UserInput{}, false},
	} {
		if got := service.CurbsAdmin(tc.u, tc.in); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestConsumeTOTPOnce(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "alan", model.RoleUser)
	secret := secure.NewTOTPSecret()
	now := time.Now()
	code := secure.TOTPCode(secret, now)
	if !e.svc.ConsumeTOTPAt(e.ctx, u, secret, code, now) {
		t.Fatal("a good code refused")
	}
	if e.svc.ConsumeTOTPAt(e.ctx, u, secret, code, now) {
		t.Error("the same code accepted twice")
	}
	if e.svc.ConsumeTOTPAt(e.ctx, u, secret, "000000", now.Add(time.Hour)) {
		t.Error("a wrong code accepted")
	}
	// another user's record is independent
	v := e.user(e.primary.ID, "bea", model.RoleUser)
	if !e.svc.ConsumeTOTPAt(e.ctx, v, secret, code, now) {
		t.Error("one user's use spent another's step")
	}
	// fails closed when the step cannot be recorded
	w := e.user(e.primary.ID, "cy", model.RoleUser)
	if err := e.svc.SignIns.Create(e.ctx, &model.SignIn{Meta: model.Meta{ID: w.ID}, OrgID: w.OrgID, TOTPLastStep: 1 << 40}); err != nil {
		t.Fatal(err)
	}
	if e.svc.ConsumeTOTPAt(e.ctx, w, secret, code, now) {
		t.Error("a code at or before the last step accepted")
	}
}

func TestSessionUsableVerdicts(t *testing.T) {
	e := newEnv(t)
	org := e.org("acme")
	u := e.user(org.ID, "alan", model.RoleUser)
	sess := e.session(u)
	if ok, err := e.svc.SessionUsable(e.ctx, sess, u); err != nil || !ok {
		t.Fatalf("fresh: %v %v", ok, err)
	}
	other := e.user(org.ID, "bea", model.RoleUser)
	if ok, _ := e.svc.SessionUsable(e.ctx, sess, other); ok {
		t.Error("session usable for another user")
	}
	exp := *sess
	exp.Expires = time.Now().Add(-time.Minute)
	if ok, _ := e.svc.SessionUsable(e.ctx, &exp, u); ok {
		t.Error("expired session usable")
	}
	stale := *sess
	stale.Epoch = 12345
	if ok, _ := e.svc.SessionUsable(e.ctx, &stale, u); ok {
		t.Error("session of another epoch usable")
	}
	off := *u
	off.Active = false
	if ok, err := e.svc.SessionUsable(e.ctx, sess, &off); ok || err != nil {
		t.Errorf("disabled user: %v %v", ok, err)
	}
	ghost := *u
	ghost.OrgID = "gone"
	if ok, err := e.svc.UserUsable(e.ctx, &ghost); ok || err != nil {
		t.Errorf("user of a missing org: %v %v", ok, err)
	}
	// after an emergency sign-out of the org, the old session is ended
	if _, err := e.svc.SignOutOrg(e.ctx, service.System, org.ID, service.SignOutOptions{Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := e.svc.SessionUsable(e.ctx, sess, u); ok || err != nil {
		t.Errorf("after sign-out: %v %v", ok, err)
	}
	want, err := e.svc.SessionStamp(e.ctx, org.ID)
	if err != nil || service.SessionUsableAt(sess, u, want) {
		t.Errorf("SessionUsableAt after sign-out: %v", err)
	}
}

func TestSessionsEndingHookAndAuditRefusal(t *testing.T) {
	e := newEnv(t)
	e.svc.SessionsEnding(e.ctx, "u1", "s1") // no hook: nothing happens
	var got []string
	e.svc.OnSessionsEnding = func(_ context.Context, user string, ids []string) { got = append(got, user+":"+strings.Join(ids, ",")) }
	e.svc.SessionsEnding(e.ctx, "u1", "s1", "s2")
	if len(got) != 1 || got[0] != "u1:s1,s2" {
		t.Errorf("hook calls %v", got)
	}
	a := actor(e.super)
	e.svc.AuditRefused(e.ctx, a, "POST", "/api/users", "scope")
	e.svc.AuditRefused(e.ctx, a, "POST", "/api/users", "scope") // rate limited: one a minute per caller and reason
	e.svc.AuditRefused(e.ctx, a, "GET", "/api/orgs", "role")
	ev := e.audited(e.super.OrgID, "api.request.refused")
	if len(ev) != 2 {
		t.Fatalf("events %d, want 2 (one per reason)", len(ev))
	}
	for _, x := range ev {
		if x.Detail["reason"] == "" || x.Target == "" {
			t.Errorf("event %+v", x)
		}
	}
}

func TestBackgroundWorkWaits(t *testing.T) {
	e := newEnv(t)
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(e.ctx)
	e.svc.Background(ctx, func(ctx context.Context) {
		cancel() // the request ends; the work's context does not
		if ctx.Err() != nil {
			t.Error("background context was cancelled with the request")
		}
		close(done)
	})
	e.svc.WaitBackground()
	select {
	case <-done:
	default:
		t.Error("WaitBackground returned before the work finished")
	}
}
