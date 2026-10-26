package service

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

var ErrTenantInUse = errors.New("the tenant still has clients")

// TenantInput is the editable part of a tenant.
type TenantInput struct {
	Name        *string               `json:"name"`
	DisplayName *string               `json:"display_name"`
	Description *string               `json:"description"`
	Settings    *model.TenantSettings `json:"settings"`
	// Resources are the APIs the tenant owns (resource indicators: an MCP server's URL, say), unique server-wide.
	Resources *[]string `json:"resources"`
}

func tenantConflict(err error) error {
	var fe *FieldError
	if errors.As(err, &fe) {
		return err
	}
	if errors.Is(err, store.ErrConflict) {
		return &conflictErr{Invalid("name", "a tenant with this name already exists, or one of its resources belongs to another tenant")}
	}
	return mapStore(err)
}

func (s *Service) applyTenant(ctx context.Context, t *model.Tenant, in TenantInput) error {
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if !model.ValidOrgName(name) {
			return Invalid("name", "use 1–63 lowercase letters, digits and hyphens, not starting or ending with a hyphen")
		}
		t.Name = name
	}
	if in.DisplayName != nil {
		v := strings.TrimSpace(*in.DisplayName)
		if v == "" || len(v) > 200 {
			return Invalid("display_name", "required, at most 200 characters")
		}
		t.DisplayName = v
	}
	if in.Description != nil {
		v := strings.TrimSpace(*in.Description)
		if len(v) > 1000 {
			return Invalid("description", "at most 1000 characters")
		}
		t.Description = v
	}
	if in.Settings != nil {
		set := *in.Settings
		ids := []string{}
		for _, id := range set.Providers {
			p, err := s.Providers.Get(ctx, id)
			if err != nil || p.OrgID != t.OrgID {
				return Invalid("settings", "unknown sign-in provider "+id)
			}
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
		set.Providers = ids
		if set.AllProviders {
			set.Providers = nil
		}
		t.Settings = set
	}
	if in.Resources != nil {
		res, err := checkResources(*in.Resources)
		if err != nil {
			return err
		}
		var seen []string
		for _, r := range res {
			u, _ := url.Parse(r)
			loopback := u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
			if (u.Scheme != "https" && !loopback) || u.RawQuery != "" || u.User != nil {
				return Invalid("resources", r+": use an https URL without a query (http only on 127.0.0.1 or [::1])")
			}
			k := model.CanonicalResource(r)
			if slices.Contains(seen, k) {
				return Invalid("resources", r+" is listed twice (letter case and a trailing slash do not count)")
			}
			seen = append(seen, k)
		}
		for _, r := range res {
			if other, err := s.Tenants.GetByUnique(ctx, model.TenantResourceKey(r)); err == nil && other.ID != t.ID {
				return &conflictErr{Invalid("resources", r+" belongs to another tenant (each resource has one)")}
			}
		}
		t.Resources = res
	}
	if t.DisplayName == "" {
		t.DisplayName = t.Name
	}
	return nil
}

// TenantForResources returns the tenant that owns the resources (all of them one tenant's), for a self-registered
// application: ErrNotFound when none is named, one is no tenant's, they span tenants, or the tenant does not allow
// self-registered applications. A read that fails is returned as such (not ErrNotFound): whether a resource still
// accepts an application is an authorization decision, and its callers must not take "could not read" for "no".
func (s *Service) TenantForResources(ctx context.Context, resources []string) (*model.Tenant, error) {
	var t *model.Tenant
	for _, r := range resources {
		got, err := s.Tenants.GetByUnique(ctx, model.TenantResourceKey(r))
		if err != nil {
			return nil, mapStore(err)
		}
		if t != nil && got.ID != t.ID {
			return nil, ErrNotFound
		}
		t = got
	}
	if t == nil || !t.Settings.SelfRegistration {
		return nil, ErrNotFound
	}
	return t, nil
}

// ListTenants lists an org's tenants (org admins and super admins).
func (s *Service) ListTenants(ctx context.Context, a *Actor, orgID string, q store.ListQuery) ([]*model.Tenant, int, error) {
	if !s.canAdminOrg(a, orgID) {
		return nil, 0, ErrForbidden
	}
	q.Scope = orgID
	l, n, err := s.Tenants.List(ctx, q)
	return l, n, mapStore(err)
}

// GetTenant returns a tenant the actor may administer (a == nil: internal, no check).
func (s *Service) GetTenant(ctx context.Context, a *Actor, id string) (*model.Tenant, error) {
	t, err := s.Tenants.Get(ctx, id)
	if err != nil {
		return nil, mapStore(err)
	}
	if a != nil && !s.canAdminOrg(a, t.OrgID) {
		return nil, ErrNotFound
	}
	return t, nil
}

// CreateTenant creates a tenant in an org.
func (s *Service) CreateTenant(ctx context.Context, a *Actor, orgID string, in TenantInput) (*model.Tenant, error) {
	if !s.canAdminOrg(a, orgID) {
		return nil, ErrForbidden
	}
	if in.Name == nil {
		return nil, Invalid("name", "required")
	}
	// A new tenant is for members only unless its settings say otherwise (the organization's default tenant, made
	// with the organization, is open to everyone so its applications work at once).
	t := &model.Tenant{OrgID: orgID, Settings: model.DefaultTenantSettings()}
	t.Settings.MembersOnly = true
	if err := s.applyTenant(ctx, t, in); err != nil {
		return nil, err
	}
	if err := s.Tenants.Create(ctx, t); err != nil {
		s.auditUnknown(ctx, err, a, orgID, "tenant.create", t.Name, nil)
		return nil, tenantConflict(err)
	}
	s.Audit(ctx, a, orgID, "tenant.create", t.Name, nil)
	return t, nil
}

// UpdateTenant changes a tenant.
func (s *Service) UpdateTenant(ctx context.Context, a *Actor, id string, in TenantInput) (*model.Tenant, error) {
	t, err := s.GetTenant(ctx, a, id)
	if err != nil {
		return nil, err
	}
	was := snapshot(t)
	if err := s.applyTenant(ctx, t, in); err != nil {
		return nil, err
	}
	if err := s.Tenants.Update(ctx, t); err != nil {
		s.auditUnknown(ctx, err, a, t.OrgID, "tenant.update", t.Name, addChanges(nil, was, t))
		return nil, tenantConflict(err)
	}
	s.Audit(ctx, a, t.OrgID, "tenant.update", t.Name, addChanges(nil, was, t))
	return t, nil
}

// DeleteTenant deletes a tenant that has no clients.
func (s *Service) DeleteTenant(ctx context.Context, a *Actor, id string) error {
	t, err := s.GetTenant(ctx, a, id)
	if err != nil {
		return err
	}
	_, n, err := s.Clients.List(ctx, store.ListQuery{Scope: t.OrgID, Limit: 1,
		Filters: []store.Filter{{Field: "tenant_id", Value: t.ID}}})
	if err != nil {
		return err
	}
	if n > 0 {
		return ErrTenantInUse
	}
	// Its access entries stand on it: a deleted tenant has no clients (ErrTenantInUse above), so nothing decides access
	// from them, and the orphan sweep removes them.
	if err := s.Tenants.Delete(ctx, id); err != nil {
		s.auditUnknown(ctx, err, a, t.OrgID, "tenant.delete", t.Name, nil)
		return mapStore(err)
	}
	s.Audit(ctx, a, t.OrgID, "tenant.delete", t.Name, nil)
	return nil
}

// DefaultTenant returns the org's "default" tenant, creating it if missing (an org whose default tenant was renamed
// or deleted gets a fresh one when a client is created without a tenant).
func (s *Service) DefaultTenant(ctx context.Context, orgID string) (*model.Tenant, error) {
	if t, err := s.Tenants.GetByUnique(ctx, model.TenantNameKey(orgID, model.DefaultTenantName)); err == nil {
		return t, nil
	}
	t := &model.Tenant{OrgID: orgID, Name: model.DefaultTenantName, DisplayName: "Default",
		Settings: model.DefaultTenantSettings()}
	err := s.Tenants.Create(ctx, t)
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrStale) { // created concurrently
		return s.Tenants.GetByUnique(ctx, model.TenantNameKey(orgID, model.DefaultTenantName))
	}
	return t, mapStore(err)
}

// ClientTenant returns the tenant of a client: ErrNotFound when it is gone (or, which cannot happen, another
// organization's: every client is created with a tenant of its own org), the read's own error when it failed, so
// that an access decision made from the tenant is not made from its absence.
func (s *Service) ClientTenant(ctx context.Context, c *model.Client) (*model.Tenant, error) {
	t, err := s.Tenants.Get(ctx, c.TenantID)
	if err != nil {
		return nil, mapStore(err)
	}
	if t.OrgID != c.OrgID {
		return nil, ErrNotFound
	}
	return t, nil
}

// SignInMethods is what a user may sign in with for an org (and optionally a tenant): the intersection of the
// org's and the tenant's settings.
type SignInMethods struct {
	Password bool
	// PasswordReset offers "forgot password" (only with Password; the tenant may turn it off).
	PasswordReset bool
	Passkey       bool
	Providers     []*model.Provider // enabled org providers the tenant allows, sorted by name
	RequireMFA    bool
	EmailCodes    bool // the organization's EmailCodes (a second factor by email)
}

// AllowsProvider reports whether providerID is among the allowed providers.
func (m *SignInMethods) AllowsProvider(providerID string) bool {
	for _, p := range m.Providers {
		if p.ID == providerID {
			return true
		}
	}
	return false
}

// EffectiveSignIn computes the sign-in methods for org and tenant (tenant nil: the org's own methods, used when
// signing in directly rather than for an application).
func (s *Service) EffectiveSignIn(ctx context.Context, org *model.Org, t *model.Tenant) (*SignInMethods, error) {
	providers, err := s.EnabledProviders(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	m := &SignInMethods{Password: org.Settings.PasswordLogin, Passkey: org.Settings.PasskeyLogin,
		RequireMFA: org.Settings.RequireMFA, Providers: providers, EmailCodes: org.Settings.EmailCodes}
	m.PasswordReset = m.Password && org.Settings.PasswordReset
	if t == nil {
		return m, nil
	}
	m.Password = m.Password && t.Settings.PasswordLogin
	m.PasswordReset = m.PasswordReset && m.Password && t.Settings.PasswordReset
	m.Passkey = m.Passkey && t.Settings.PasskeyLogin
	m.RequireMFA = m.RequireMFA || t.Settings.RequireMFA
	if !t.Settings.AllProviders {
		m.Providers = slices.DeleteFunc(m.Providers, func(p *model.Provider) bool {
			return !slices.Contains(t.Settings.Providers, p.ID)
		})
	}
	return m, nil
}
