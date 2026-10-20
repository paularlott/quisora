package service_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestOrgValidation(t *testing.T) {
	c := newCast(t)
	bad := []string{"", "Admin", "admin", "scim", "api", "-a", "a-", "has space", "UPPER", "a_b", strings.Repeat("a", 64), "well-known", "oauth"}
	for _, n := range bad {
		_, err := c.svc.CreateOrg(c.ctx, actor(c.super), service.OrgInput{Name: ptr(n)})
		var fe *service.FieldError
		if !errors.As(err, &fe) || fe.Field != "name" {
			t.Errorf("name %q: want field error, got %v", n, err)
		}
	}
	if _, err := c.svc.CreateOrg(c.ctx, actor(c.super), service.OrgInput{}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("missing name: %v", err)
	}
	for _, n := range []string{"a", "x1", "my-org", strings.Repeat("a", 63)} {
		if _, err := c.svc.CreateOrg(c.ctx, actor(c.super), service.OrgInput{Name: ptr(n)}); err != nil {
			t.Errorf("name %q rejected: %v", n, err)
		}
	}
	if _, err := c.svc.CreateOrg(c.ctx, actor(c.super), service.OrgInput{Name: ptr("neg-ttl"), Settings: &model.OrgSettings{SessionIdle: -1}}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("negative lifetime on create: %v", err)
	}
	o, err := c.svc.CreateOrg(c.ctx, actor(c.super), service.OrgInput{Name: ptr("defaults"), DisplayName: ptr("  Pretty  ")})
	if err != nil || o.DisplayName != "Pretty" || !o.Settings.PasswordLogin || o.Primary {
		t.Errorf("defaults: %v %+v", err, o)
	}
	o2, _ := c.svc.CreateOrg(c.ctx, actor(c.super), service.OrgInput{Name: ptr("nodisp")})
	if o2.DisplayName != "nodisp" {
		t.Errorf("display default %q", o2.DisplayName)
	}
	// Duplicate name, any case.
	_, err = c.svc.CreateOrg(c.ctx, actor(c.super), service.OrgInput{Name: ptr("defaults")})
	if !errors.Is(err, service.ErrConflict) {
		t.Errorf("duplicate org: %v", err)
	}
	var fe *service.FieldError
	if !errors.As(err, &fe) || fe.Field != "name" {
		t.Errorf("duplicate org should be a name field error: %v", err)
	}
	// Rename into an existing name / invalid / update validation.
	_, err = c.svc.UpdateOrg(c.ctx, actor(c.super), c.a.ID, service.OrgInput{Name: ptr("org-b")})
	if !errors.Is(err, service.ErrConflict) || !errors.As(err, &fe) || fe.Field != "name" {
		t.Errorf("rename clash: %v", err)
	}
	if _, err := c.svc.UpdateOrg(c.ctx, actor(c.super), c.a.ID, service.OrgInput{Name: ptr("scim")}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("reserved rename: %v", err)
	}
	if _, err := c.svc.UpdateOrg(c.ctx, actor(c.super), c.a.ID, service.OrgInput{DisplayName: ptr("  ")}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("blank display: %v", err)
	}
	if _, err := c.svc.UpdateOrg(c.ctx, actor(c.super), c.a.ID, service.OrgInput{Settings: &model.OrgSettings{SessionTTL: -1}}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("negative ttl: %v", err)
	}
	got, err := c.svc.UpdateOrg(c.ctx, actor(c.super), c.a.ID, service.OrgInput{Name: ptr("renamed-a"), Settings: &model.OrgSettings{RequireMFA: true, SessionTTL: 60}})
	if err != nil || got.Name != "renamed-a" || !got.Settings.RequireMFA {
		t.Errorf("update: %v %+v", err, got)
	}
	by, err := c.svc.OrgByName(c.ctx, "RENAMED-A")
	if err != nil || by.ID != c.a.ID {
		t.Errorf("OrgByName after rename: %v", err)
	}
	if _, err := c.svc.OrgByName(c.ctx, "org-a"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("old name still resolves: %v", err)
	}
}

func TestPrimaryOrgRules(t *testing.T) {
	c := newCast(t)
	p, err := c.svc.PrimaryOrg(c.ctx)
	if err != nil || p.ID != c.primary.ID || !p.Primary {
		t.Fatalf("primary: %v", err)
	}
	// Never deletable, with or without cascade.
	for _, cascade := range []bool{false, true} {
		if err := c.svc.DeleteOrg(c.ctx, actor(c.super), c.primary.ID, cascade); !errors.Is(err, service.ErrPrimaryOrg) {
			t.Errorf("delete primary cascade=%v: %v", cascade, err)
		}
	}
	// Renamable, and stays primary.
	got, err := c.svc.UpdateOrg(c.ctx, actor(c.super), c.primary.ID, service.OrgInput{Name: ptr("home")})
	if err != nil || !got.Primary || got.Name != "home" {
		t.Fatalf("rename primary: %v %+v", err, got)
	}
	p, _ = c.svc.PrimaryOrg(c.ctx)
	if p.ID != c.primary.ID {
		t.Error("primary moved")
	}
	// Only one org is ever primary.
	_, n, _ := c.svc.Orgs.List(c.ctx, store.ListQuery{Filters: []store.Filter{{Field: "primary", Value: true}}})
	if n != 1 {
		t.Errorf("%d primary orgs", n)
	}
	// Bootstrap is idempotent.
	u, pw, err := c.svc.Bootstrap(c.ctx, "x@example.com")
	if err != nil || u != nil || pw != "" {
		t.Errorf("second bootstrap: %v %v %q", err, u, pw)
	}
}

func TestDeleteOrgEmptyAndNotEmpty(t *testing.T) {
	c := newCast(t)
	empty := c.org("empty")
	if err := c.svc.DeleteOrg(c.ctx, actor(c.super), empty.ID, false); err != nil {
		t.Fatalf("delete empty: %v", err)
	}
	if _, err := c.svc.GetOrg(c.ctx, nil, empty.ID); !errors.Is(err, service.ErrNotFound) {
		t.Error("org remains")
	}
	if _, err := c.svc.OrgByName(c.ctx, "empty"); !errors.Is(err, service.ErrNotFound) {
		t.Error("name remains")
	}
	// The name can be reused.
	c.org("empty")
	// Non-empty org needs a cascade.
	if err := c.svc.DeleteOrg(c.ctx, actor(c.super), c.a.ID, false); !errors.Is(err, service.ErrNotEmpty) {
		t.Errorf("delete non-empty: %v", err)
	}
	if _, err := c.svc.GetOrg(c.ctx, nil, c.a.ID); err != nil {
		t.Error("non-empty org vanished")
	}
	if err := c.svc.DeleteOrg(c.ctx, actor(c.super), "missing", false); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("delete missing: %v", err)
	}
	// An org admin cannot delete even their own org.
	if err := c.svc.DeleteOrg(c.ctx, actor(c.aAdmin), c.a.ID, true); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("admin delete own org: %v", err)
	}
}

func TestDeleteOrgCascade(t *testing.T) {
	c := newCast(t)
	org := c.org("doomed")
	admin := c.user(org.ID, "dadmin", model.RoleAdmin)
	u1 := c.user(org.ID, "du1", model.RoleUser)
	u2 := c.user(org.ID, "du2", model.RoleUser)
	g, err := c.svc.CreateGroup(c.ctx, service.System, org.ID, service.GroupInput{DisplayName: ptr("everyone")})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []*model.User{u1, u2} {
		if err := c.svc.SetMembership(c.ctx, service.System, g.ID, u.ID, true); err != nil {
			t.Fatal(err)
		}
	}
	cl, _, err := c.svc.CreateClient(c.ctx, service.System, org.ID, service.ClientInput{Name: ptr("app"),
		RedirectURIs: ptr([]string{"https://app.example.com/cb"})})
	if err != nil {
		t.Fatal(err)
	}
	prov, err := c.svc.CreateProvider(c.ctx, service.System, org.ID, goodProvider("sso"))
	if err != nil {
		t.Fatal(err)
	}
	tok, plain, err := c.svc.CreateAPIToken(c.ctx, actor(admin), service.APITokenInput{Name: "t", Scopes: []string{"scim"}})
	if err != nil {
		t.Fatal(err)
	}
	sess := &model.Session{Meta: model.Meta{ID: "sess-doomed-1234567890"}, UserID: u1.ID, OrgID: org.ID}
	if err := c.svc.Sessions.Create(c.ctx, sess); err != nil {
		t.Fatal(err)
	}
	grant := &model.Grant{UserID: u2.ID, OrgID: org.ID, ClientID: cl.ID}
	if err := c.svc.Grants.Create(c.ctx, grant); err != nil {
		t.Fatal(err)
	}
	pk := &model.Passkey{UserID: u1.ID, OrgID: org.ID, CredentialID: []byte("cred-1"), Name: "k"}
	if err := c.svc.Passkeys.Create(c.ctx, pk); err != nil {
		t.Fatal(err)
	}
	ident := model.NewIdentity(u2, prov, "sub", "", "admin")
	if err := c.svc.Identities.Create(c.ctx, ident); err != nil {
		t.Fatal(err)
	}
	// Another org's data must survive.
	keep := c.aUser

	if err := c.svc.DeleteOrg(c.ctx, actor(c.super), org.ID, true); err != nil {
		t.Fatalf("cascade: %v", err)
	}
	gone := []struct {
		name string
		err  error
	}{
		{"org", func() error { _, e := c.svc.Orgs.Get(c.ctx, org.ID); return e }()},
		{"admin", func() error { _, e := c.svc.Users.Get(c.ctx, admin.ID); return e }()},
		{"user1", func() error { _, e := c.svc.Users.Get(c.ctx, u1.ID); return e }()},
		{"user2", func() error { _, e := c.svc.Users.Get(c.ctx, u2.ID); return e }()},
		{"group", func() error { _, e := c.svc.Groups.Get(c.ctx, g.ID); return e }()},
		{"member", func() error { _, e := c.svc.Members.Get(c.ctx, model.MemberID(g.ID, u1.ID)); return e }()},
		{"client", func() error { _, e := c.svc.Clients.Get(c.ctx, cl.ID); return e }()},
		{"provider", func() error { _, e := c.svc.Providers.Get(c.ctx, prov.ID); return e }()},
		{"apitoken", func() error { _, e := c.svc.APITokens.Get(c.ctx, tok.ID); return e }()},
		{"session", func() error { _, e := c.svc.Sessions.Get(c.ctx, sess.ID); return e }()},
		{"grant", func() error { _, e := c.svc.Grants.Get(c.ctx, grant.ID); return e }()},
		{"passkey", func() error { _, e := c.svc.Passkeys.Get(c.ctx, pk.ID); return e }()},
		{"identity", func() error { _, e := c.svc.Identities.Get(c.ctx, ident.ID); return e }()},
	}
	for _, g := range gone {
		if !errors.Is(g.err, store.ErrNotFound) {
			t.Errorf("%s survived the cascade: %v", g.name, g.err)
		}
	}
	for _, k := range []model.Kind{model.KindUser, model.KindGroup, model.KindMember, model.KindClient, model.KindProvider} {
		if n, _ := c.svc.Store.Count(c.ctx, k, org.ID); n != 0 {
			t.Errorf("%d %s records left in org scope", n, k)
		}
	}
	if _, err := c.svc.Users.Get(c.ctx, keep.ID); err != nil {
		t.Errorf("other org's user was deleted: %v", err)
	}
	if _, _, err := c.svc.ValidateAPIToken(c.ctx, plain); !errors.Is(err, service.ErrBadToken) {
		t.Errorf("token of deleted org still validates: %v", err)
	}
}
