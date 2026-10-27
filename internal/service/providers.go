package service

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// domainRe is a DNS name with at least two labels (letters, digits and hyphens; no leading or trailing hyphen).
var domainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// ProviderInput is the editable part of an upstream sign-in provider.
type ProviderInput struct {
	// ID may be chosen by the caller on create (a UUID), so the provider's callback address can be registered with the
	// provider before its client ID and secret exist. Ignored on update.
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
	// Organization only: the organization (id or name) whose users sign in. Super admins only.
	SourceOrg *string `json:"source_org"`
}

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
	if in.LinkByEmail != nil {
		p.LinkByEmail = *in.LinkByEmail
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
		return s.applySourceOrg(ctx, p, in.SourceOrg)
	}
	p.SourceOrg = ""
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

// applySourceOrg settles an organization provider: its source organization must exist and be another one (an
// organization's own users sign in to it directly), the issuer is that organization's (never typed in), the scopes are
// fixed, and an unnamed provider is named after the source organization, which the sign-in page offers as "Continue
// with <name>". Its client credentials come later (issueSignInClient), once everything else is known to be valid.
func (s *Service) applySourceOrg(ctx context.Context, p *model.Provider, ref *string) error {
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
	return nil
}

// issueSignInClient makes the application of p's source organization that p signs in with: a confidential client of
// the organization's default tenant, whose only redirect URI is p's callback address, trusted (first party) so its
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
	in := ClientInput{Name: &name, Description: &desc, FirstParty: &firstParty,
		RedirectURIs: &[]string{s.Cfg.Server.PublicURL + model.ProviderCallbackPath(p.OrgID, p.ID)},
		GrantTypes:   &[]string{"authorization_code"}, Scopes: &orgProviderScopes}
	c, secret, err := s.createClient(ctx, a, p.SourceOrg, in, p.ID)
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
		u, err := uuid.Parse(*in.ID)
		if err != nil || u.String() != *in.ID {
			return nil, Invalid("id", "must be a UUID in lower case, such as 0192f3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b")
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
	if p.Type == model.ProviderOrganization {
		if err := s.issueSignInClient(ctx, a, p); err != nil {
			return nil, err
		}
	}
	if err := s.audited(ctx, a, orgID, "provider.create", p.Name, nil, func() error { return s.Providers.Create(ctx, p) }); err != nil {
		if p.Type == model.ProviderOrganization && !outcomeUnknown(err) {
			s.removeSignInClient(ctx, a, p.SourceOrg, p.ClientID, p.ID)
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
	before := model.ProviderAuthority(p)
	was := snapshot(p)
	oldSource, oldClient := p.SourceOrg, p.ClientID
	if p.Type != model.ProviderOrganization {
		oldSource, oldClient = "", ""
	}
	if err := s.applyProvider(ctx, a, p, in); err != nil {
		return nil, err
	}
	// An organization provider whose source organization changed (or that just became one) signs in with a client of
	// the new source organization, made before the provider is written, and the old one is removed after.
	orgNow := p.Type == model.ProviderOrganization
	newClient := orgNow && (oldClient == "" || p.SourceOrg != oldSource)
	if newClient {
		if err := s.issueSignInClient(ctx, a, p); err != nil {
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
		}
		return nil, providerConflict(err)
	}
	if oldClient != "" && (newClient || !orgNow) {
		s.removeSignInClient(ctx, a, oldSource, oldClient, p.ID)
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
	// The links to it stand on it: sign-in through a deleted provider is impossible, and the orphan sweep removes them.
	if err := s.audited(ctx, a, p.OrgID, "provider.delete", p.Name, nil, func() error { return s.Providers.Delete(ctx, id) }); err != nil {
		return mapStore(err)
	}
	if p.Type == model.ProviderOrganization {
		s.removeSignInClient(ctx, a, p.SourceOrg, p.ClientID, p.ID)
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
