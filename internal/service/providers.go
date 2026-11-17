package service

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// domainRe is a DNS name with at least two labels (letters, digits and hyphens; no leading or trailing hyphen).
var domainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// ProviderInput is the editable part of an upstream sign-in provider.
type ProviderInput struct {
	// ID may be chosen by the caller on create (an id as model.NewID makes them), so the provider's callback address
	// can be registered with the provider before its client ID and secret exist. Ignored on update.
	ID             *string   `json:"id"`
	Type           *string   `json:"type"`
	Name           *string   `json:"name"`
	Issuer         *string   `json:"issuer"`
	ClientID       *string   `json:"client_id"`
	ClientSecret   *string   `json:"client_secret"` // write-only
	Scopes         *[]string `json:"scopes"`
	AutoProvision  *bool     `json:"auto_provision"`
	TrustMFA       *bool     `json:"trust_mfa"`
	LinkByEmail    *bool     `json:"link_by_email"`
	AllowedDomains *[]string `json:"allowed_domains"`
	Enabled        *bool     `json:"enabled"`
	// Microsoft only: a tenant ID or "organizations", and the tenant IDs allowed to sign in.
	Tenant         *string   `json:"tenant"`
	AllowedTenants *[]string `json:"allowed_tenants"`
	// Organization only: the organization (id or name) whose users sign in, and the groups of it (ids) whose members
	// alone may (empty: all of its users). Super admins only.
	SourceOrg    *string   `json:"source_org"`
	SourceGroups *[]string `json:"source_groups"`
	// SourceTenant is the tenant of the source organization (id or name) that holds the sign-in application: its access
	// list decides who of that organization may sign in this way, and until when. Empty: its default tenant. Choosing
	// another organization without one starts again from that organization's default tenant.
	SourceTenant *string `json:"source_tenant"`
}

// maxSourceGroups bounds the groups an organization provider admits (Provider.SourceGroups).
const maxSourceGroups = 20

// providerDefaultName is a new provider's button label when none is given.
var providerDefaultName = map[string]string{model.ProviderOIDC: "Single sign-on", model.ProviderGitHub: "GitHub",
	model.ProviderGoogle: "Google", model.ProviderGitLab: "GitLab", model.ProviderAuth0: "Auth0", model.ProviderMicrosoft: "Microsoft"}

// tenantIDRe is a Microsoft Entra tenant (directory) ID.
var tenantIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// providerIssuer works out the issuer of the OpenID Connect types: given for "oidc", fixed for Google, the GitLab
// address (gitlab.com by default) for GitLab, https://<domain>/ for Auth0 (its issuer ends with a slash), and the
// tenant's address for Microsoft. raw is what the administrator entered in the issuer / address field.
func providerIssuer(typ, raw, tenant string) (string, error) {
	raw = strings.TrimSpace(raw)
	httpsBase := func(field, v string) (string, error) {
		if v != "" && !strings.Contains(v, "://") {
			v = "https://" + v
		}
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return "", Invalid(field, "must be an https address")
		}
		return strings.TrimSuffix(u.Scheme+"://"+u.Host+u.Path, "/"), nil
	}
	switch typ {
	case model.ProviderOIDC:
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return "", Invalid("issuer", "must be the provider's https issuer URL")
		}
		return strings.TrimSuffix(raw, "/"), nil
	case model.ProviderGoogle:
		return "https://accounts.google.com", nil
	case model.ProviderGitLab:
		if raw == "" {
			return "https://gitlab.com", nil
		}
		return httpsBase("issuer", raw)
	case model.ProviderAuth0:
		if raw == "" {
			return "", Invalid("issuer", "enter your Auth0 domain, such as acme.eu.auth0.com")
		}
		v, err := httpsBase("issuer", raw)
		if err != nil {
			return "", err
		}
		return v + "/", nil
	case model.ProviderMicrosoft:
		return model.MicrosoftAuthority + "/" + tenant + "/v2.0", nil
	}
	return "", nil
}

// orgProviderScopes are what an organization provider asks its source organization for, and what the client made for
// it there may be given: the identity and the email address that links a guest to the account they were added with.
var orgProviderScopes = []string{"openid", "profile", "email"}

func (s *Service) applyProvider(ctx context.Context, a *Actor, p *model.Provider, in ProviderInput) error {
	wasOrg := p.Type == model.ProviderOrganization
	if in.Type != nil {
		if !slices.Contains(model.ProviderTypes, *in.Type) {
			return Invalid("type", "must be one of "+strings.Join(model.ProviderTypes, ", "))
		}
		p.Type = *in.Type
	}
	org := p.Type == model.ProviderOrganization
	if org && !a.IsSuper() {
		return ErrForbidden // it writes an application into another organization
	}
	if !org && p.SourceOrg != "" {
		p.ClientID, p.ClientSecret = "", "" // no longer an organization provider: those were the made client's, not the new provider's
	}
	if in.Name != nil {
		v := strings.TrimSpace(*in.Name)
		switch {
		case v == "" && p.Name == "": // a new provider: the type's own name (CreateProvider)
		case v == "" || len(v) > 100:
			return Invalid("name", "required, at most 100 characters")
		default:
			p.Name = v
		}
	}
	issuer := p.Issuer
	if in.Issuer != nil {
		issuer = *in.Issuer
	}
	// An organization provider's client is made for it (issueSignInClient): the credentials are never typed in.
	if in.ClientID != nil && !org {
		p.ClientID = strings.TrimSpace(*in.ClientID)
	}
	if in.ClientSecret != nil && *in.ClientSecret != "" && !org {
		p.ClientSecret = s.Sealer.SealFor(ProviderSecretBinding(p.ID), []byte(*in.ClientSecret))
	}
	if in.Scopes != nil && !org {
		// The same rule as a client's scopes: each one goes into the upstream authorization request, where a space
		// would split it in two.
		scopes, err := checkScopes(*in.Scopes)
		if err != nil {
			return err
		}
		p.Scopes = scopes
	}
	// The source organization's managers, administrators and SCIM clients can set a user's email address and mark it
	// verified, so linking a guest by email would let any of them sign in to this organization as its user with that
	// address. An organization provider therefore starts with linking off; a super admin may switch it on, trusting
	// the source organization's staff with the addresses they assert.
	if in.LinkByEmail != nil {
		p.LinkByEmail = *in.LinkByEmail
	} else if org && !wasOrg {
		p.LinkByEmail = false
	}
	if in.TrustMFA != nil && *in.TrustMFA != p.TrustMFA {
		// Trusting a provider's second factor weakens every sign-in through it: a super-admin decision.
		if !a.IsSuper() {
			return ErrForbidden
		}
		p.TrustMFA = *in.TrustMFA
	}
	if in.AutoProvision != nil {
		p.AutoProvision = *in.AutoProvision
	}
	if in.AllowedDomains != nil {
		d := []string{}
		for _, v := range *in.AllowedDomains {
			raw := strings.TrimSpace(v)
			if v = strings.ToLower(strings.TrimPrefix(raw, "@")); v == "" || slices.Contains(d, v) {
				continue
			}
			if !domainRe.MatchString(v) {
				return Invalid("allowed_domains", raw+" is not a domain name, such as example.com")
			}
			d = append(d, v)
		}
		if len(d) > 100 {
			return Invalid("allowed_domains", "at most 100 domains are allowed")
		}
		p.AllowedDomains = d
	}
	if in.Enabled != nil {
		p.Enabled = *in.Enabled
	}
	if in.Tenant != nil {
		p.Tenant = strings.ToLower(strings.TrimSpace(*in.Tenant))
	}
	if in.AllowedTenants != nil {
		t := []string{}
		for _, v := range *in.AllowedTenants {
			raw := strings.TrimSpace(v)
			if v = strings.ToLower(raw); v == "" || slices.Contains(t, v) {
				continue
			}
			if !tenantIDRe.MatchString(v) {
				return Invalid("allowed_tenants", raw+" is not a tenant ID (a GUID, such as 72f988bf-86f1-41af-91ab-2d7cd011db47)")
			}
			t = append(t, v)
		}
		p.AllowedTenants = t
	}
	if p.Type == model.ProviderMicrosoft {
		switch {
		case p.Tenant == "":
			return Invalid("tenant", "enter your directory (tenant) ID, or organizations")
		case p.Tenant == "organizations":
			if len(p.AllowedTenants) == 0 {
				return Invalid("allowed_tenants", "list the tenant IDs allowed to sign in")
			}
		case tenantIDRe.MatchString(p.Tenant):
			p.AllowedTenants = nil // only the tenant itself
		default:
			return Invalid("tenant", "must be a tenant ID or organizations (personal Microsoft accounts are not supported)")
		}
	} else {
		p.Tenant, p.AllowedTenants = "", nil
	}
	if org {
		if err := s.applySourceOrg(ctx, p, in.SourceOrg, in.SourceGroups, in.SourceTenant); err != nil {
			return err
		}
		if ok, err := s.ownerMaySource(ctx, a, p.SourceOrg); err != nil {
			return err
		} else if !ok {
			return Invalid("source_org", "choose the primary organization or another organization this account created")
		}
		return nil
	}
	p.SourceOrg, p.SourceGroups, p.SourceTenant = "", nil, ""
	if p.OIDC() {
		iss, err := providerIssuer(p.Type, issuer, p.Tenant)
		if err != nil {
			return err
		}
		p.Issuer = iss
	} else {
		p.Issuer = ""
	}
	if p.ClientID == "" {
		return Invalid("client_id", "required")
	}
	if p.ClientSecret == "" {
		return Invalid("client_secret", "required")
	}
	return nil
}

// ownerMaySource reports whether a may have an organization provider whose source is organization srcID: the
// provider's client lives in its source (issueSignInClient), so making, moving or removing it is a write there. Every
// actor that gets this far is a super admin; an organization's owner (OwnerActor) is one only in the organizations it
// created, so its sources are the primary organization (its own) and those. A source that no longer exists holds
// nothing to write to.
func (s *Service) ownerMaySource(ctx context.Context, a *Actor, srcID string) (bool, error) {
	if a.Owner == "" || srcID == "" {
		return true, nil
	}
	src, err := s.Orgs.Get(ctx, srcID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return true, nil
	case err != nil:
		return false, mapStore(err)
	}
	return src.Primary || src.CreatedBy == a.ClientID, nil
}

// applySourceOrg settles an organization provider: its source organization must exist and be another one (an
// organization's own users sign in to it directly), the issuer is that organization's (never typed in), the scopes are
// fixed, and an unnamed provider is named after the source organization, which the sign-in page offers as "Continue
// with <name>". Its groups, when chosen, must be groups of that organization. Its client credentials come later
// (issueSignInClient), once everything else is known to be valid.
func (s *Service) applySourceOrg(ctx context.Context, p *model.Provider, ref *string, groups *[]string, tenant *string) error {
	was, wasGroups := p.SourceOrg, p.SourceGroups
	if ref != nil {
		p.SourceOrg = strings.TrimSpace(*ref)
	}
	if p.SourceOrg == "" {
		return Invalid("source_org", "choose the organization whose users sign in")
	}
	src, err := s.OrgByRef(ctx, p.SourceOrg)
	switch {
	case errors.Is(err, ErrNotFound):
		return Invalid("source_org", "choose an organization of this server")
	case err != nil:
		return err
	case src.ID == p.OrgID:
		return Invalid("source_org", "choose another organization: the users of this one sign in to it directly")
	}
	p.SourceOrg, p.Issuer, p.Scopes = src.ID, s.Cfg.OrgIssuer(src.ID), slices.Clone(orgProviderScopes)
	if p.Name == "" {
		p.Name = src.DisplayName
	}
	if err := s.applySourceTenant(ctx, p, src, src.ID != was, tenant); err != nil {
		return err
	}
	if groups != nil {
		gs := []string{}
		for _, id := range *groups {
			if id = strings.TrimSpace(id); id != "" && !slices.Contains(gs, id) {
				gs = append(gs, id)
			}
		}
		if len(gs) > maxSourceGroups {
			return Invalid("source_groups", "choose at most "+itoa(maxSourceGroups)+" groups")
		}
		p.SourceGroups = gs
	}
	if len(p.SourceGroups) == 0 {
		p.SourceGroups = nil
		return nil
	}
	// Only groups being chosen are looked up (a group deleted since does not stop other changes being saved: its
	// members just no longer sign in), and every group when the organization changes: another's groups never carry over.
	if src.ID == was && slices.Equal(p.SourceGroups, wasGroups) {
		return nil
	}
	for _, id := range p.SourceGroups {
		g, err := s.Groups.Get(ctx, id)
		if errors.Is(err, store.ErrNotFound) || err == nil && g.OrgID != src.ID {
			return Invalid("source_groups", "choose groups of "+src.DisplayName+": "+id+" is not one")
		} else if err != nil {
			return mapStore(err)
		}
	}
	return nil
}

// applySourceTenant settles an organization provider's source tenant (Provider.SourceTenant): a tenant of src named by
// id or name; or, when none is named (a new provider, one whose organization changed, or "" asked for), a tenant of its
// own (Tenant.ProviderID): the one it has in src already, or "" for one to be made before the provider is written
// (issueSourceTenant). Another organization's tenant never carries over, and another provider's own is not taken.
func (s *Service) applySourceTenant(ctx context.Context, p *model.Provider, src *model.Org, orgChanged bool, ref *string) error {
	v := ""
	switch {
	case ref != nil:
		v = strings.TrimSpace(*ref)
	case !orgChanged:
		v = p.SourceTenant
	}
	if v == "" {
		if !orgChanged && p.SourceTenant != "" {
			if t, err := s.Tenants.Get(ctx, p.SourceTenant); err == nil && t.OrgID == src.ID && t.ProviderID == p.ID {
				return nil // its own already
			}
		}
		p.SourceTenant = ""
		return nil
	}
	var t *model.Tenant
	var err error
	if model.IsID(v) {
		t, err = s.Tenants.Get(ctx, v)
	} else {
		t, err = s.Tenants.GetByUnique(ctx, model.TenantNameKey(src.ID, v))
	}
	if errors.Is(err, store.ErrNotFound) || err == nil && t.OrgID != src.ID {
		return Invalid("source_tenant", "choose a tenant of "+src.DisplayName)
	}
	if err != nil {
		return mapStore(err)
	}
	if t.ProviderID != "" && t.ProviderID != p.ID {
		return Invalid("source_tenant", "choose another tenant: "+t.DisplayName+" was made for another provider's sign-ins")
	}
	p.SourceTenant = t.ID
	return nil
}

// issueSourceTenant makes the tenant of its own an organization provider signs in through, when it is to have one
// (applySourceTenant left Provider.SourceTenant empty): a members-only tenant of the source organization named after
// the organization the provider is in, with nobody on its access list, so nobody of the source organization signs in
// to that one until an administrator (or the API) gives them access there, for good or until a time. It reports whether
// it made one. Like the sign-in client it is a write in another organization, made before the provider is written:
// callers remove it (removeSourceTenant) when they know the provider was not written, and the orphan sweep when they
// cannot tell.
func (s *Service) issueSourceTenant(ctx context.Context, a *Actor, p *model.Provider) (bool, error) {
	if p.SourceTenant != "" {
		return false, nil
	}
	dest, err := s.Orgs.Get(ctx, p.OrgID)
	if err != nil {
		return false, mapStore(err)
	}
	set := model.DefaultTenantSettings()
	set.MembersOnly = true
	base := dest.Name
	if len(base) > 59 {
		base = strings.TrimRight(base[:59], "-")
	}
	for i := 1; i <= 20; i++ { // the organization's name, or with a number when a tenant of the source has it already
		name := base
		if i > 1 {
			name = base + "-" + itoa(i)
		}
		t := &model.Tenant{OrgID: p.SourceOrg, Name: name, DisplayName: dest.DisplayName, ProviderID: p.ID, Settings: set,
			Description: "Who of this organization signs in to " + dest.DisplayName + " (provider " + p.Name + "), and until when: " +
				"this tenant's access list. Made and removed with that provider."}
		err := s.audited(ctx, a, p.SourceOrg, "tenant.create", t.Name, map[string]string{"provider": p.ID, "for_org": dest.ID},
			func() error { return s.Tenants.Create(ctx, t) })
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		if err != nil {
			return false, mapStore(err)
		}
		p.SourceTenant = t.ID
		return true, nil
	}
	return false, Invalid("source_tenant", "the source organization has tenants named "+base+" to "+base+"-20: choose a tenant")
}

// removeSourceTenant deletes the tenant tenantID of organization orgID that was made for provider providerID
// (issueSourceTenant), when it is that tenant: once the provider no longer signs in through it (deleted, or pointed
// elsewhere) and its sign-in client is gone. Its access entries stand on it and go with the orphan sweep. A failure is
// only logged: the sweep removes the tenant once its provider no longer uses it.
func (s *Service) removeSourceTenant(ctx context.Context, a *Actor, orgID, tenantID, providerID string) {
	t, err := s.Tenants.Get(ctx, tenantID)
	if err != nil || t.OrgID != orgID || t.ProviderID == "" || t.ProviderID != providerID {
		return
	}
	if err := s.audited(ctx, a, t.OrgID, "tenant.delete", t.Name, map[string]string{"provider": providerID},
		func() error { return s.Tenants.Delete(ctx, t.ID) }); err != nil {
		s.Log.Warn("an unused provider tenant could not be removed; the orphan sweep removes it later",
			"tenant", t.ID, "organization", orgID, "provider", providerID, "error", err)
	}
}

// issueSignInClient makes the application of p's source organization that p signs in with: a confidential client of
// p's source tenant (Provider.SourceTenant), whose only redirect URI is p's callback address, trusted (first party) so its
// users are not asked for consent, as a super admin set it up. Its secret is sealed into p. It is a write in another
// organization, apart from the write of p: callers make it first, so a failure leaves at most an unused client, which
// they remove (removeSignInClient) when they know p was not written, and the orphan sweep removes when they cannot tell.
func (s *Service) issueSignInClient(ctx context.Context, a *Actor, p *model.Provider) error {
	dest, err := s.Orgs.Get(ctx, p.OrgID)
	if err != nil {
		return mapStore(err)
	}
	name := "Sign-in to " + dest.DisplayName
	desc := "Lets the users of this organization sign in to " + dest.DisplayName + " (provider " + p.Name + "). Made and removed with that provider."
	firstParty := true
	tenant := p.SourceTenant
	in := ClientInput{Name: &name, Description: &desc, FirstParty: &firstParty, TenantID: &tenant,
		RedirectURIs: &[]string{s.Cfg.Server.PublicURL + model.ProviderCallbackPath(p.OrgID, p.ID)},
		GrantTypes:   &[]string{"authorization_code"}, Scopes: &orgProviderScopes}
	c, secret, err := s.createClient(ctx, a, p.SourceOrg, in, clientMade{provider: p.ID})
	if err != nil {
		return err
	}
	p.ClientID, p.ClientSecret = c.ID, s.Sealer.SealFor(ProviderSecretBinding(p.ID), []byte(secret))
	return nil
}

// removeSignInClient deletes the client clientID that served provider providerID in organization orgID, when it still
// is that client. A failure is only logged: the client is unused, and the orphan sweep removes it once its provider no
// longer uses it (sweep.go), so a provider's change or deletion never fails for it.
func (s *Service) removeSignInClient(ctx context.Context, a *Actor, orgID, clientID, providerID string) {
	c, err := s.Clients.Get(ctx, clientID)
	if err != nil || c.OrgID != orgID || c.ProviderID != providerID {
		return
	}
	if err := s.audited(ctx, a, c.OrgID, "client.delete", c.Name, map[string]string{"client_id": c.ID},
		func() error { return s.Clients.Delete(ctx, c.ID) }); err != nil {
		s.Log.Warn("an unused sign-in client could not be removed; the orphan sweep removes it later",
			"client", c.ID, "organization", orgID, "provider", providerID, "error", err)
	}
}

func providerConflict(err error) error {
	if errors.Is(err, store.ErrConflict) {
		return &conflictErr{Invalid("name", "a provider with this name already exists")}
	}
	return mapStore(err)
}

func (s *Service) ListProviders(ctx context.Context, a *Actor, orgID string, q store.ListQuery) ([]*model.Provider, int, error) {
	if a != nil && !s.canAdminOrg(a, orgID) {
		return nil, 0, ErrForbidden
	}
	q.Scope = orgID
	l, n, err := s.Providers.List(ctx, q)
	return l, n, mapStore(err)
}

// EnabledProviders returns an org's enabled providers (public: drives the sign-in page).
func (s *Service) EnabledProviders(ctx context.Context, orgID string) ([]*model.Provider, error) {
	l, _, err := s.Providers.List(ctx, store.ListQuery{Scope: orgID, Sort: "name",
		Filters: []store.Filter{{Field: "enabled", Value: true}}})
	return l, mapStore(err)
}

func (s *Service) GetProvider(ctx context.Context, a *Actor, id string) (*model.Provider, error) {
	p, err := s.Providers.Get(ctx, id)
	if err != nil {
		return nil, mapStore(err)
	}
	if a != nil && !s.canAdminOrg(a, p.OrgID) {
		return nil, ErrNotFound
	}
	return p, nil
}

func (s *Service) CreateProvider(ctx context.Context, a *Actor, orgID string, in ProviderInput) (*model.Provider, error) {
	if !s.canAdminOrg(a, orgID) {
		return nil, ErrForbidden
	}
	id := model.NewID()
	if in.ID != nil && *in.ID != "" {
		if !model.IsID(*in.ID) {
			return nil, Invalid("id", "must be an id: 22 letters and digits, such as 034nmRmWuXazwvCcdrmRxu")
		}
		if _, err := s.Providers.Get(ctx, *in.ID); err == nil {
			return nil, &conflictErr{Invalid("id", "a provider with this id already exists")}
		}
		id = *in.ID
	}
	p := &model.Provider{Meta: model.Meta{ID: id}, OrgID: orgID, Type: model.ProviderOIDC, Enabled: true, LinkByEmail: true,
		Scopes: []string{"openid", "profile", "email"}}
	if err := s.applyProvider(ctx, a, p, in); err != nil {
		return nil, err
	}
	if p.Type == model.ProviderGitHub && in.Scopes == nil {
		p.Scopes = []string{"read:user", "user:email"}
	}
	if p.Name == "" {
		p.Name = providerDefaultName[p.Type]
	}
	madeTenant := false
	if p.Type == model.ProviderOrganization {
		var err error
		if madeTenant, err = s.issueSourceTenant(ctx, a, p); err != nil {
			return nil, err
		}
		if err := s.issueSignInClient(ctx, a, p); err != nil {
			if madeTenant {
				s.removeSourceTenant(ctx, a, p.SourceOrg, p.SourceTenant, p.ID)
			}
			return nil, err
		}
	}
	if err := s.audited(ctx, a, orgID, "provider.create", p.Name, nil, func() error { return s.Providers.Create(ctx, p) }); err != nil {
		if p.Type == model.ProviderOrganization && !outcomeUnknown(err) {
			s.removeSignInClient(ctx, a, p.SourceOrg, p.ClientID, p.ID)
			if madeTenant {
				s.removeSourceTenant(ctx, a, p.SourceOrg, p.SourceTenant, p.ID)
			}
		}
		return nil, providerConflict(err)
	}
	return p, nil
}

func (s *Service) UpdateProvider(ctx context.Context, a *Actor, id string, in ProviderInput) (*model.Provider, error) {
	p, err := s.GetProvider(ctx, a, id)
	if err != nil {
		return nil, err
	}
	if p.Type == model.ProviderOrganization && !a.IsSuper() {
		return nil, ErrForbidden // its client is in another organization
	}
	if p.Type == model.ProviderOrganization {
		if ok, err := s.ownerMaySource(ctx, a, p.SourceOrg); err != nil {
			return nil, err
		} else if !ok {
			return nil, ErrForbidden // its client is in an organization the owner has no say in
		}
	}
	before := model.ProviderAuthority(p)
	was := snapshot(p)
	oldSource, oldClient, oldTenant := p.SourceOrg, p.ClientID, ""
	if p.Type != model.ProviderOrganization {
		oldSource, oldClient = "", ""
	} else if c, err := s.Clients.Get(ctx, oldClient); err == nil && c.OrgID == oldSource {
		oldTenant = c.TenantID // where its sign-in application is: the tenant it was made in
	}
	if err := s.applyProvider(ctx, a, p, in); err != nil {
		return nil, err
	}
	// An organization provider whose source organization or tenant changed (or that just became one) signs in with a
	// client of the new source tenant, made before the provider is written, and the old one is removed after: the
	// guests signed in through the old one stop counting with it (their sign-ins stand on it: SourcesHold).
	orgNow := p.Type == model.ProviderOrganization
	madeTenant := false
	if orgNow {
		if madeTenant, err = s.issueSourceTenant(ctx, a, p); err != nil {
			return nil, err
		}
	}
	newClient := orgNow && (oldClient == "" || p.SourceOrg != oldSource || p.SourceTenant != oldTenant)
	if newClient {
		if err := s.issueSignInClient(ctx, a, p); err != nil {
			if madeTenant {
				s.removeSourceTenant(ctx, a, p.SourceOrg, p.SourceTenant, p.ID)
			}
			return nil, err
		}
	}
	// Pointing the provider at another issuer, type or tenant needs that provider's own secret: the old one is
	// never sent to the new issuer. (An organization provider's secret is made, not entered.)
	if !orgNow && model.ProviderAuthority(p) != before && (in.ClientSecret == nil || *in.ClientSecret == "") {
		return nil, Invalid("client_secret", "enter the client secret issued by the new provider")
	}
	detail := addChanges(map[string]string{}, was, p)
	if in.ClientSecret != nil && *in.ClientSecret != "" && !orgNow {
		detail["client_secret"] = "replaced" // never the value, sealed or not
	}
	if err := s.audited(ctx, a, p.OrgID, "provider.update", p.Name, detail, func() error {
		if err := s.Providers.Update(ctx, p); err != nil {
			return err
		}
		if model.ProviderAuthority(p) != before {
			// Another type, issuer or directory: its subjects name other people now. Every link goes.
			detail["identities_unlinked"] = itoa(s.purgeIdentities(ctx, p.ID))
		}
		return nil
	}); err != nil {
		if newClient && !outcomeUnknown(err) {
			s.removeSignInClient(ctx, a, p.SourceOrg, p.ClientID, p.ID)
			if madeTenant {
				s.removeSourceTenant(ctx, a, p.SourceOrg, p.SourceTenant, p.ID)
			}
		}
		return nil, providerConflict(err)
	}
	if oldClient != "" && (newClient || !orgNow) {
		s.removeSignInClient(ctx, a, oldSource, oldClient, p.ID)
	}
	if oldTenant != "" && (!orgNow || oldSource != p.SourceOrg || oldTenant != p.SourceTenant) {
		s.removeSourceTenant(ctx, a, oldSource, oldTenant, p.ID) // its own tenant, when it was: no longer signed in through
	}
	return p, nil
}

func (s *Service) DeleteProvider(ctx context.Context, a *Actor, id string) error {
	p, err := s.GetProvider(ctx, a, id)
	if err != nil {
		return err
	}
	if p.Type == model.ProviderOrganization && !a.IsSuper() {
		return ErrForbidden // its client is in another organization
	}
	if p.Type == model.ProviderOrganization {
		if ok, err := s.ownerMaySource(ctx, a, p.SourceOrg); err != nil {
			return err
		} else if !ok {
			return ErrForbidden // its client is in an organization the owner has no say in
		}
	}
	// The links to it stand on it: sign-in through a deleted provider is impossible, and the orphan sweep removes them.
	if err := s.audited(ctx, a, p.OrgID, "provider.delete", p.Name, nil, func() error { return s.Providers.Delete(ctx, id) }); err != nil {
		return mapStore(err)
	}
	if p.Type == model.ProviderOrganization {
		s.removeSignInClient(ctx, a, p.SourceOrg, p.ClientID, p.ID)
		s.removeSourceTenant(ctx, a, p.SourceOrg, p.SourceTenant, p.ID)
	}
	return nil
}

// purgeIdentities deletes every link to provider id and reports how many went. Sign-in also ignores links whose
// authority no longer matches, so a link missed here (a node that was away) still cannot be used.
func (s *Service) purgeIdentities(ctx context.Context, id string) int {
	l, _, err := s.Identities.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "provider_id", Value: id}}})
	if err != nil {
		return 0
	}
	n := 0
	for _, i := range l {
		if s.Identities.Delete(ctx, i.ID) == nil {
			n++
		}
	}
	return n
}

// ProviderSource is an organization and one of its tenants that an organization provider may take its users from
// (Provider.SourceOrg and SourceTenant): what the provider form's picker offers, as "organization (tenant)".
type ProviderSource struct {
	OrgID             string `json:"org_id"`
	OrgName           string `json:"org_name"`
	OrgDisplayName    string `json:"org_display_name"`
	TenantID          string `json:"tenant_id"`
	TenantName        string `json:"tenant_name"`
	TenantDisplayName string `json:"tenant_display_name"`
	MembersOnly       bool   `json:"members_only"`
	// OwnTenant is the choice of a tenant of the provider's own in this organization (no TenantID: made with the
	// provider, members only, nobody on it), offered first for each organization.
	OwnTenant bool `json:"own_tenant,omitempty"`
}

// maxSourceOrgs and maxSourceTenants bound one answer of ProviderSources: a few organizations matching what was typed,
// each with its tenants, never a listing of the whole server.
const (
	maxSourceOrgs    = 20
	maxSourceTenants = 50
)

// ProviderSources returns what an organization provider of orgID may take its users from, as (organization, tenant)
// pairs, for a super admin choosing one in the provider form; an organization's owner (OwnerActor) gets only the
// organizations it may source from (ownerMaySource). q matches the start of a name or display name, either:
//
//   - of an organization (up to limit of them, by name), giving each of its tenants;
//   - of a tenant, of any organization (up to maxSourceTenants), giving it with its organization;
//   - or both, written "organization (tenant": the tenants of the matching organizations whose names start so.
//
// orgID itself is never offered. total counts the organizations and tenants whose names match (a pair may count under
// both), so a caller seeing more than it got can say to type more.
func (s *Service) ProviderSources(ctx context.Context, a *Actor, orgID, q string, limit int) ([]ProviderSource, int, error) {
	if !s.canAdminOrg(a, orgID) || !a.IsSuper() {
		return nil, 0, ErrForbidden
	}
	if limit <= 0 || limit > maxSourceOrgs {
		limit = maxSourceOrgs
	}
	q = strings.TrimSpace(q)
	orgQ, tenantQ, both := q, "", false
	if i := strings.Index(q, "("); i >= 0 {
		orgQ = strings.TrimSpace(q[:i])
		tenantQ = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(q[i+1:]), ")")))
		both = true
	}
	allowed := func(o *model.Org) (bool, error) {
		if o.ID == orgID {
			return false, nil
		}
		return s.ownerMaySource(ctx, a, o.ID)
	}
	out := []ProviderSource{}
	seen := map[string]bool{}
	// own offers a tenant of the provider's own in o, once, before o's tenants
	own := func(o *model.Org) {
		if seen["own:"+o.ID] {
			return
		}
		seen["own:"+o.ID] = true
		out = append(out, ProviderSource{OrgID: o.ID, OrgName: o.Name, OrgDisplayName: o.DisplayName, MembersOnly: true, OwnTenant: true})
	}
	add := func(o *model.Org, t *model.Tenant) {
		if seen[t.ID] || t.ProviderID != "" { // a tenant made for a provider is that provider's alone
			return
		}
		own(o)
		seen[t.ID] = true
		out = append(out, ProviderSource{OrgID: o.ID, OrgName: o.Name, OrgDisplayName: o.DisplayName, TenantID: t.ID,
			TenantName: t.Name, TenantDisplayName: t.DisplayName, MembersOnly: t.Settings.MembersOnly})
	}
	tenantMatches := func(t *model.Tenant) bool {
		return tenantQ == "" || strings.HasPrefix(strings.ToLower(t.Name), tenantQ) || strings.HasPrefix(strings.ToLower(t.DisplayName), tenantQ)
	}

	// organizations whose names match, each with its tenants
	orgs, orgTotal, err := s.Orgs.List(ctx, store.ListQuery{Search: orgQ, Sort: "name", Limit: limit + 1})
	if err != nil {
		return nil, 0, mapStore(err)
	}
	n := 0
	for _, o := range orgs {
		if ok, err := allowed(o); err != nil {
			return nil, 0, err
		} else if !ok {
			orgTotal--
			continue
		}
		if n == limit {
			break
		}
		n++
		if tenantQ == "" {
			own(o) // even when every tenant it has is a provider's
		}
		ts, _, err := s.Tenants.List(ctx, store.ListQuery{Scope: o.ID, Sort: "name", Limit: maxSourceTenants})
		if err != nil {
			return nil, 0, mapStore(err)
		}
		for _, t := range ts {
			if tenantMatches(t) {
				add(o, t)
			}
		}
	}

	// tenants whose names match, of any organization (not when the organization was written out)
	tenantTotal := 0
	if !both && q != "" {
		ts, total, err := s.Tenants.List(ctx, store.ListQuery{Search: q, Sort: "name", Limit: maxSourceTenants})
		if err != nil {
			return nil, 0, mapStore(err)
		}
		tenantTotal = total
		for _, t := range ts {
			o, err := s.Org(ctx, t.OrgID)
			if errors.Is(err, ErrNotFound) || errors.Is(err, store.ErrNotFound) {
				tenantTotal--
				continue
			}
			if err != nil {
				return nil, 0, err
			}
			if ok, err := allowed(o); err != nil {
				return nil, 0, err
			} else if !ok {
				tenantTotal--
				continue
			}
			add(o, t)
		}
	}
	total := orgTotal + tenantTotal
	if a.Owner != "" {
		// an owner may source from a few organizations only: a count of every match would tell it how many others
		// there are
		total = len(out)
	}
	return out, max(total, len(out)), nil
}
