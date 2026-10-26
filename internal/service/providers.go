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

func (s *Service) applyProvider(a *Actor, p *model.Provider, in ProviderInput) error {
	if in.Type != nil {
		if !slices.Contains(model.ProviderTypes, *in.Type) {
			return Invalid("type", "must be one of "+strings.Join(model.ProviderTypes, ", "))
		}
		p.Type = *in.Type
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
	if in.ClientID != nil {
		p.ClientID = strings.TrimSpace(*in.ClientID)
	}
	if in.ClientSecret != nil && *in.ClientSecret != "" {
		p.ClientSecret = s.Sealer.SealFor(ProviderSecretBinding(p.ID), []byte(*in.ClientSecret))
	}
	if in.Scopes != nil {
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
	if err := s.applyProvider(a, p, in); err != nil {
		return nil, err
	}
	if p.Type == model.ProviderGitHub && in.Scopes == nil {
		p.Scopes = []string{"read:user", "user:email"}
	}
	if p.Name == "" {
		p.Name = providerDefaultName[p.Type]
	}
	if err := s.audited(ctx, a, orgID, "provider.create", p.Name, nil, func() error { return s.Providers.Create(ctx, p) }); err != nil {
		return nil, providerConflict(err)
	}
	return p, nil
}

func (s *Service) UpdateProvider(ctx context.Context, a *Actor, id string, in ProviderInput) (*model.Provider, error) {
	p, err := s.GetProvider(ctx, a, id)
	if err != nil {
		return nil, err
	}
	before := model.ProviderAuthority(p)
	was := snapshot(p)
	if err := s.applyProvider(a, p, in); err != nil {
		return nil, err
	}
	// Pointing the provider at another issuer, type or tenant needs that provider's own secret: the old one is
	// never sent to the new issuer.
	if model.ProviderAuthority(p) != before && (in.ClientSecret == nil || *in.ClientSecret == "") {
		return nil, Invalid("client_secret", "enter the client secret issued by the new provider")
	}
	detail := addChanges(map[string]string{}, was, p)
	if in.ClientSecret != nil && *in.ClientSecret != "" {
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
		return nil, providerConflict(err)
	}
	return p, nil
}

func (s *Service) DeleteProvider(ctx context.Context, a *Actor, id string) error {
	p, err := s.GetProvider(ctx, a, id)
	if err != nil {
		return err
	}
	// The links to it stand on it: sign-in through a deleted provider is impossible, and the orphan sweep removes them.
	return mapStore(s.audited(ctx, a, p.OrgID, "provider.delete", p.Name, nil, func() error { return s.Providers.Delete(ctx, id) }))
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
