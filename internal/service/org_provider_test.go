package service_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// orgProviderEnv is a cast whose server has a public address, which the redirect URI of an organization provider's
// client is made from.
func orgProviderEnv(t *testing.T) *cast {
	c := newCast(t)
	c.svc.Cfg.Server.PublicURL = "https://idp.example.com"
	return c
}

func orgProvider(source string) service.ProviderInput {
	return service.ProviderInput{Type: ptr(model.ProviderOrganization), SourceOrg: &source}
}

// clientsOf returns the clients of an organization, including the ones the console does not list.
func clientsOf(t *testing.T, c *cast, orgID string) []*model.Client {
	t.Helper()
	l, _, err := c.svc.Clients.List(c.ctx, store.ListQuery{Scope: orgID})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// An organization provider signs in with a client of its source organization that is made for it: confidential, of the
// default tenant, with the provider's callback address as its only redirect URI, trusted so nobody is asked for consent,
// and its secret sealed into the provider. The issuer is the source organization's, and nothing is typed in.
func TestOrganizationProviderMakesItsClient(t *testing.T) {
	c := orgProviderEnv(t)
	typed := service.ProviderInput{Type: ptr(model.ProviderOrganization), SourceOrg: &c.primary.Name, Issuer: ptr("https://evil.example"),
		ClientID: ptr("typed"), ClientSecret: ptr("typed"), Scopes: &[]string{"groups"}}
	p, err := c.svc.CreateProvider(c.ctx, actor(c.super), c.a.ID, typed)
	if err != nil {
		t.Fatal(err)
	}
	if p.SourceOrg != c.primary.ID || p.Issuer != c.svc.Cfg.OrgIssuer(c.primary.ID) || p.Name != c.primary.DisplayName ||
		!slices.Equal(p.Scopes, []string{"openid", "profile", "email"}) {
		t.Errorf("provider: %+v", p)
	}
	if p.AutoProvision || p.TrustMFA || p.LinkByEmail || !p.Enabled {
		t.Errorf("defaults: auto-provision %v trust-mfa %v link-by-email %v enabled %v", p.AutoProvision, p.TrustMFA, p.LinkByEmail, p.Enabled)
	}
	cl, err := c.svc.Clients.Get(c.ctx, p.ClientID)
	if err != nil || p.ClientID == "typed" {
		t.Fatalf("client %q: %v", p.ClientID, err)
	}
	def, _ := c.svc.DefaultTenant(c.ctx, c.primary.ID)
	if cl.OrgID != c.primary.ID || cl.TenantID != def.ID || !cl.FirstParty || cl.Public() || !cl.Enabled || cl.ProviderID != p.ID ||
		cl.Name != "Sign-in to "+c.a.DisplayName ||
		!slices.Equal(cl.RedirectURIs, []string{"https://idp.example.com" + model.ProviderCallbackPath(c.a.ID, p.ID)}) ||
		!slices.Equal(cl.GrantTypes, []string{"authorization_code"}) || !slices.Equal(cl.Scopes, []string{"openid", "profile", "email"}) {
		t.Errorf("client: %+v", cl)
	}
	secret, err := c.svc.Sealer.OpenFor(service.ProviderSecretBinding(p.ID), p.ClientSecret)
	if err != nil || !service.VerifyClientSecret(cl, string(secret)) {
		t.Errorf("the provider does not hold the client's secret: %v", err)
	}
	if cl.Created.IsZero() || len(clientsOf(t, c, c.primary.ID)) != 1 || len(clientsOf(t, c, c.a.ID)) != 0 {
		t.Errorf("clients: primary %d, org-a %d", len(clientsOf(t, c, c.primary.ID)), len(clientsOf(t, c, c.a.ID)))
	}
}

// The source organization's managers, administrators and SCIM clients can mark any address they give a user verified,
// so an organization provider does not link guests to existing users by email unless a super admin turns that on:
// not on creation, and not when an existing provider becomes one. Other types keep linking by default.
func TestOrganizationProviderDoesNotLinkByEmailByDefault(t *testing.T) {
	c := orgProviderEnv(t)
	other, err := c.svc.CreateProvider(c.ctx, actor(c.super), c.a.ID, goodProvider("Corp"))
	if err != nil || !other.LinkByEmail {
		t.Fatalf("an OpenID Connect provider: link-by-email %v, %v", other != nil && other.LinkByEmail, err)
	}
	// becoming an organization provider switches it off, as a new one is; switching it on again is the admin's call
	in := orgProvider(c.primary.ID)
	made, err := c.svc.UpdateProvider(c.ctx, actor(c.super), other.ID, in)
	if err != nil || made.LinkByEmail {
		t.Fatalf("converted: link-by-email %v, %v", made != nil && made.LinkByEmail, err)
	}
	if on, err := c.svc.UpdateProvider(c.ctx, actor(c.super), other.ID, service.ProviderInput{LinkByEmail: ptr(true)}); err != nil || !on.LinkByEmail {
		t.Fatalf("switched on: %v", err)
	}
	// an update that says nothing about it leaves the choice alone
	if kept, err := c.svc.UpdateProvider(c.ctx, actor(c.super), other.ID, service.ProviderInput{Name: ptr("Guests")}); err != nil || !kept.LinkByEmail {
		t.Fatalf("renamed: %v", err)
	}
	explicit := orgProvider(c.primary.ID)
	explicit.Name, explicit.LinkByEmail = ptr("Trusted"), ptr(true)
	if p, err := c.svc.CreateProvider(c.ctx, actor(c.super), c.b.ID, explicit); err != nil || !p.LinkByEmail {
		t.Fatalf("created with link-by-email on: %v", err)
	}
}

// Only a super admin may create, change or delete one: it writes an application into another organization. An
// organization's own administrator may still read it.
func TestOrganizationProviderIsSuperAdminOnly(t *testing.T) {
	c := orgProviderEnv(t)
	if _, err := c.svc.CreateProvider(c.ctx, actor(c.aAdmin), c.a.ID, orgProvider(c.primary.ID)); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("admin creating: %v", err)
	}
	if _, err := c.svc.CreateProvider(c.ctx, actor(c.pAdmin), c.a.ID, orgProvider(c.primary.ID)); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("primary admin creating in another organization: %v", err)
	}
	if n := len(clientsOf(t, c, c.primary.ID)); n != 0 {
		t.Fatalf("a refused create left %d clients", n)
	}
	// an ordinary provider cannot be turned into one by an administrator either
	plain, err := c.svc.CreateProvider(c.ctx, actor(c.aAdmin), c.a.ID, goodProvider("okta"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.UpdateProvider(c.ctx, actor(c.aAdmin), plain.ID, orgProvider(c.primary.ID)); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("admin converting: %v", err)
	}
	p, err := c.svc.CreateProvider(c.ctx, actor(c.super), c.a.ID, orgProvider(c.primary.ID))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.svc.GetProvider(c.ctx, actor(c.aAdmin), p.ID); err != nil || got.SourceOrg != c.primary.ID {
		t.Errorf("admin reading: %v", err)
	}
	if _, err := c.svc.UpdateProvider(c.ctx, actor(c.aAdmin), p.ID, service.ProviderInput{Name: ptr("renamed")}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("admin changing: %v", err)
	}
	if err := c.svc.DeleteProvider(c.ctx, actor(c.aAdmin), p.ID); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("admin deleting: %v", err)
	}
	if n := len(clientsOf(t, c, c.primary.ID)); n != 1 {
		t.Errorf("clients %d", n)
	}
	if got, err := c.svc.UpdateProvider(c.ctx, actor(c.super), p.ID, service.ProviderInput{TrustMFA: ptr(true), AutoProvision: ptr(true)}); err != nil ||
		!got.TrustMFA || !got.AutoProvision {
		t.Errorf("super changing: %v", err)
	}
}

// The source organization must be given, exist and be another one; a refused request makes no client.
func TestOrganizationProviderSourceValidation(t *testing.T) {
	c := orgProviderEnv(t)
	for name, in := range map[string]service.ProviderInput{
		"none":    {Type: ptr(model.ProviderOrganization)},
		"blank":   orgProvider(" "),
		"unknown": orgProvider("no-such-organization"),
		"itself":  orgProvider(c.a.ID),
	} {
		_, err := c.svc.CreateProvider(c.ctx, actor(c.super), c.a.ID, in)
		var fe *service.FieldError
		if !errors.As(err, &fe) || fe.Field != "source_org" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := len(clientsOf(t, c, c.primary.ID)) + len(clientsOf(t, c, c.b.ID)); n != 0 {
		t.Errorf("refused requests left %d clients", n)
	}
	// a name that duplicates another provider's fails after validation, and takes its client with it
	if _, err := c.svc.CreateProvider(c.ctx, actor(c.super), c.a.ID, orgProvider(c.primary.ID)); err != nil {
		t.Fatal(err)
	}
	_, err := c.svc.CreateProvider(c.ctx, actor(c.super), c.a.ID, orgProvider(c.primary.ID))
	if !errors.Is(err, service.ErrConflict) {
		t.Fatalf("a second provider of the same name: %v", err)
	}
	if n := len(clientsOf(t, c, c.primary.ID)); n != 1 {
		t.Errorf("the refused create left a client: %d clients", n)
	}
}

// Deleting the provider deletes its client; changing the source organization moves the client; making it another type
// removes it. Each is audited in the organization where the client is.
func TestOrganizationProviderClientFollowsTheProvider(t *testing.T) {
	c := orgProviderEnv(t)
	p, err := c.svc.CreateProvider(c.ctx, actor(c.super), c.a.ID, orgProvider(c.primary.ID))
	if err != nil {
		t.Fatal(err)
	}
	first := p.ClientID
	user := c.user(c.a.ID, "guest", model.RoleUser)
	if err := c.svc.Identities.Create(c.ctx, model.NewIdentity(user, p, "sub-1", "guest@example.com", "email")); err != nil {
		t.Fatal(err)
	}

	moved, err := c.svc.UpdateProvider(c.ctx, actor(c.super), p.ID, service.ProviderInput{SourceOrg: &c.b.Name})
	if err != nil {
		t.Fatal(err)
	}
	if moved.SourceOrg != c.b.ID || moved.Issuer != c.svc.Cfg.OrgIssuer(c.b.ID) || moved.ClientID == first {
		t.Errorf("moved: %+v", moved)
	}
	if n := len(clientsOf(t, c, c.primary.ID)); n != 0 {
		t.Errorf("the old source organization keeps %d clients", n)
	}
	cl, err := c.svc.Clients.Get(c.ctx, moved.ClientID)
	if err != nil || cl.OrgID != c.b.ID || cl.ProviderID != p.ID {
		t.Fatalf("the new client: %+v %v", cl, err)
	}
	if secret, err := c.svc.Sealer.OpenFor(service.ProviderSecretBinding(p.ID), moved.ClientSecret); err != nil || !service.VerifyClientSecret(cl, string(secret)) {
		t.Errorf("the provider holds the old secret: %v", err)
	}
	// the people of the old organization are not the people of the new one: the links go
	if _, err := c.svc.Identities.GetByUnique(c.ctx, model.IdentityKey(p.ID, "sub-1")); err == nil {
		t.Error("a link to a subject of the old source organization survived")
	}
	// the same source again: the client stays
	same, err := c.svc.UpdateProvider(c.ctx, actor(c.super), p.ID, service.ProviderInput{SourceOrg: &c.b.ID, Name: ptr("Guests")})
	if err != nil || same.ClientID != moved.ClientID || len(clientsOf(t, c, c.b.ID)) != 1 {
		t.Errorf("unchanged source: %v", err)
	}

	if err := c.svc.DeleteProvider(c.ctx, actor(c.super), p.ID); err != nil {
		t.Fatal(err)
	}
	if n := len(clientsOf(t, c, c.b.ID)); n != 0 {
		t.Errorf("a deleted provider's client remains: %d", n)
	}

	// becoming an ordinary provider releases the client (the new issuer needs its own secret)
	p2, err := c.svc.CreateProvider(c.ctx, actor(c.super), c.a.ID, orgProvider(c.primary.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.UpdateProvider(c.ctx, actor(c.super), p2.ID, service.ProviderInput{Type: ptr(model.ProviderOIDC),
		Issuer: ptr("https://login.example.com")}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("another type without the new provider's own client ID and secret: %v", err)
	}
	if n := len(clientsOf(t, c, c.primary.ID)); n != 1 {
		t.Errorf("a refused change touched the client: %d", n)
	}
	in := goodProvider("okta")
	in.Type, in.Name = ptr(model.ProviderOIDC), ptr("Okta")
	if got, err := c.svc.UpdateProvider(c.ctx, actor(c.super), p2.ID, in); err != nil || got.SourceOrg != "" || got.Issuer != "https://login.example.com" ||
		got.ClientID != "cid" {
		t.Fatalf("another type: %v %+v", err, got)
	}
	if n := len(clientsOf(t, c, c.primary.ID)); n != 0 {
		t.Errorf("a provider of another type keeps a client: %d", n)
	}
	made, removed := 0, 0
	for _, a := range c.audits("client.create") {
		if a.OrgID == c.primary.ID || a.OrgID == c.b.ID {
			made++
		}
	}
	for _, a := range c.audits("client.delete") {
		if a.OrgID == c.primary.ID || a.OrgID == c.b.ID {
			removed++
		}
	}
	if made != 3 || removed != 3 {
		t.Errorf("audit: %d clients made in the source organizations, %d removed", made, removed)
	}
}

// What the provider's own writes could not clean up, the orphan sweep removes: a client whose provider is gone, and
// the one a provider no longer uses (its source organization changed while the old client's removal failed); a client
// its provider still uses is kept.
func TestSweepRemovesOrphanedSignInClients(t *testing.T) {
	c := orgProviderEnv(t)
	gone, err := c.svc.CreateProvider(c.ctx, actor(c.super), c.a.ID, orgProvider(c.primary.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.svc.Providers.Delete(c.ctx, gone.ID); err != nil { // the provider alone, as a failed removal of its client leaves it
		t.Fatal(err)
	}
	kept, err := c.svc.CreateProvider(c.ctx, actor(c.super), c.b.ID, orgProvider(c.a.ID))
	if err != nil {
		t.Fatal(err)
	}
	stale, err := c.svc.CreateProvider(c.ctx, actor(c.super), c.b.ID, service.ProviderInput{Type: ptr(model.ProviderOrganization),
		SourceOrg: &c.primary.ID, Name: ptr("Other")})
	if err != nil {
		t.Fatal(err)
	}
	oldClient := stale.ClientID
	stale.ClientID = "c_replaced" // the provider moved on to another client, whose old one was not removed
	if err := c.svc.Providers.Update(c.ctx, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.SweepAll(c.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.Clients.Get(c.ctx, gone.ClientID); err == nil {
		t.Error("the client of a deleted provider was kept")
	}
	if _, err := c.svc.Clients.Get(c.ctx, oldClient); err == nil {
		t.Error("the client its provider no longer uses was kept")
	}
	if _, err := c.svc.Clients.Get(c.ctx, kept.ClientID); err != nil {
		t.Errorf("the client of a live provider was swept: %v", err)
	}
}

// The application an organization provider made is the provider's: changing, re-keying or deleting it on its own is
// refused (the provider's redirect URI and secret would no longer match it); the provider's own changes move it.
func TestOrganizationProviderClientIsNotChangedAlone(t *testing.T) {
	c := orgProviderEnv(t)
	p, err := c.svc.CreateProvider(c.ctx, actor(c.super), c.a.ID, orgProvider(c.primary.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.UpdateClient(c.ctx, actor(c.super), p.ClientID, service.ClientInput{Name: ptr("renamed")}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("update: %v", err)
	}
	if _, err := c.svc.RotateClientSecret(c.ctx, actor(c.super), p.ClientID); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("rotate: %v", err)
	}
	if err := c.svc.DeleteClient(c.ctx, actor(c.super), p.ClientID); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("delete: %v", err)
	}
	if _, err := c.svc.Clients.Get(c.ctx, p.ClientID); err != nil {
		t.Fatalf("the provider's application: %v", err)
	}
}

// An organization provider's groups are groups of its source organization: chosen ones are checked (another
// organization's, or one that does not exist, is refused), repeats are dropped, at most 20 are kept, [] clears them, and
// choosing another source organization needs groups of that one: another organization's never carry over.
func TestOrganizationProviderGroups(t *testing.T) {
	c := orgProviderEnv(t)
	staff, ops := c.group(c.primary.ID, "staff"), c.group(c.primary.ID, "ops")
	elsewhere := c.group(c.b.ID, "b-staff")
	in := orgProvider(c.primary.ID)
	in.SourceGroups = &[]string{staff.ID, staff.ID, " " + ops.ID + " "}
	p, err := c.svc.CreateProvider(c.ctx, actor(c.super), c.a.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.SourceGroups, []string{staff.ID, ops.ID}) {
		t.Fatalf("groups %v", p.SourceGroups)
	}
	invalid := func(name string, in service.ProviderInput) {
		t.Helper()
		var inv *service.FieldError
		if _, err := c.svc.UpdateProvider(c.ctx, actor(c.super), p.ID, in); !errors.As(err, &inv) || inv.Field != "source_groups" {
			t.Errorf("%s: %v", name, err)
		}
	}
	invalid("another organization's group", service.ProviderInput{SourceGroups: &[]string{elsewhere.ID}})
	invalid("no such group", service.ProviderInput{SourceGroups: &[]string{model.NewID()}})
	many := make([]string, 21)
	for i := range many {
		many[i] = model.NewID()
	}
	invalid("too many", service.ProviderInput{SourceGroups: &many})
	invalid("another source organization, the old groups kept", service.ProviderInput{SourceOrg: &c.b.ID})

	// an unrelated change does not look the groups up again: one deleted since stays chosen, admitting nobody
	if err := c.svc.DeleteGroup(c.ctx, service.System, ops.ID); err != nil {
		t.Fatal(err)
	}
	p, err = c.svc.UpdateProvider(c.ctx, actor(c.super), p.ID, service.ProviderInput{Name: ptr("Staff")})
	if err != nil || !slices.Equal(p.SourceGroups, []string{staff.ID, ops.ID}) {
		t.Fatalf("an unrelated change: %v %v", p.SourceGroups, err)
	}
	// another source organization with its own groups
	p, err = c.svc.UpdateProvider(c.ctx, actor(c.super), p.ID, service.ProviderInput{SourceOrg: &c.b.ID, SourceGroups: &[]string{elsewhere.ID}})
	if err != nil || p.SourceOrg != c.b.ID || !slices.Equal(p.SourceGroups, []string{elsewhere.ID}) {
		t.Fatalf("moved: %+v %v", p, err)
	}
	p, err = c.svc.UpdateProvider(c.ctx, actor(c.super), p.ID, service.ProviderInput{SourceGroups: &[]string{}})
	if err != nil || p.SourceGroups != nil {
		t.Fatalf("cleared: %v %v", p.SourceGroups, err)
	}
}
