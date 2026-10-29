package service

import (
	"context"
	"slices"
	"strings"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

// Service account scopes. A service account is a non-human principal of one organization (model.Client.ServiceAccount)
// that calls the management API and SCIM with client_credentials tokens, and holds only the scopes it was granted:
// each management route names the one it needs, and a route that names none is closed to it (the organization's
// settings, the audit log, the server's keys and backups). It acts as an administrator of its own organization within
// those scopes, and never as a super admin: without ScopeManageAdmins it manages users and managers only, as SCIM does.
const (
	// ScopeOrgsCreate creates organizations, each with an optional first service account (CreateOrgWithServiceAccount).
	ScopeOrgsCreate = "orgs:create"
	// ScopeOrgsDelete deletes the organizations the account created (model.Org.CreatedBy).
	ScopeOrgsDelete   = "orgs:delete"
	ScopeUsers        = "users"         // users and managers: their details, emails, provider links, sessions, tokens
	ScopeManageAdmins = "manage_admins" // with users: the organization's administrators too
	ScopeGroups       = "groups"        // groups and their members
	ScopeProviders    = "providers"     // sign-in providers
	ScopeTenants      = "tenants"       // tenants
	ScopeClients      = "clients"       // applications (OAuth clients), and the self-registered ones
	ScopeAccess       = "access"        // tenants' access lists
	// ScopeServiceAccounts manages the organization's service accounts, giving none more than the account holds.
	ScopeServiceAccounts = "service_accounts"
)

// ServiceAccountScopes are the scopes a service account of any organization may hold (ScopeImport with ScopeUsers or
// ScopeSCIM); PrimaryServiceAccountScopes only one of the primary organization.
var (
	ServiceAccountScopes = []string{ScopeUsers, ScopeManageAdmins, ScopeGroups, ScopeProviders, ScopeTenants, ScopeClients,
		ScopeAccess, ScopeImport, ScopeSCIM, ScopeServiceAccounts}
	PrimaryServiceAccountScopes = []string{ScopeOrgsCreate, ScopeOrgsDelete}
)

// ServiceAccountInput is the editable part of a service account; nil leaves a field as it is.
type ServiceAccountInput struct {
	Name        *string   `json:"name"`
	Description *string   `json:"description"`
	Scopes      *[]string `json:"scopes"`
	// AuthMethod is how it authenticates at the token endpoint: client_secret_post or client_secret_basic (a secret
	// Quisora issues), or private_key_jwt (keys it holds, given as jwks or jwks_uri: no secret is ever issued).
	AuthMethod *string `json:"token_endpoint_auth_method"`
	JWKS       *string `json:"jwks"`
	JWKSURI    *string `json:"jwks_uri"`
	// FAPI applies the FAPI 2.0 Security Profile (private_key_jwt and DPoP-bound tokens, presented with the DPoP
	// scheme: SCIM takes them, the management API does not).
	FAPI    *bool `json:"fapi2_security_profile"`
	Enabled *bool `json:"enabled"`
}

// ActorForServiceAccount builds the actor of a request made with a service account's access token: an administrator
// of its organization holding the scopes both the token and the account still have, so a scope taken away stops
// working at once, not when the token expires.
func ActorForServiceAccount(c *model.Client, tokenScopes []string, ip string) *Actor {
	scopes := slices.DeleteFunc(slices.Clone(tokenScopes), func(sc string) bool { return !slices.Contains(c.Scopes, sc) })
	return &Actor{OrgID: c.OrgID, Role: model.RoleAdmin, Name: ServiceAccountName(c), ClientID: c.ID, Scopes: scopes, IP: ip}
}

// ServiceAccountName is how the audit log names a service account.
func ServiceAccountName(c *model.Client) string { return "service:" + c.Name }

// mayGrant reports whether a may give a service account of org the scope sc. first: the account made with a new
// organization by whoever creates it, which may hold any of the organization's scopes (granting orgs:create is
// trusting its holder with that). Otherwise a service account gives only scopes it holds itself, and only super
// admins give import; orgs:create and orgs:delete are super admins' to give, on the primary organization alone.
func mayGrant(a *Actor, org *model.Org, sc string, first bool) bool {
	switch {
	case slices.Contains(PrimaryServiceAccountScopes, sc):
		return org.Primary && a.IsSuper()
	case first:
		return true
	case a.ClientID != "":
		return a.HasScope(sc)
	case sc == ScopeImport:
		return a.IsSuper()
	}
	return true
}

// mayManageServiceAccount reports whether a may change, rotate or delete c: an administrator of its organization (a
// service account with the service_accounts scope) who could have granted every scope it holds, so none is reached
// through an account that holds more than its manager.
func (s *Service) mayManageServiceAccount(a *Actor, org *model.Org, c *model.Client) bool {
	if !s.canAdminOrg(a, org.ID) {
		return false
	}
	for _, sc := range c.Scopes {
		if !mayGrant(a, org, sc, false) {
			return false
		}
	}
	return true
}

// applyServiceAccount sets the fields of c that in carries, each checked; a scope it adds must be one a may grant.
func (s *Service) applyServiceAccount(ctx context.Context, a *Actor, org *model.Org, c *model.Client, in ServiceAccountInput, first bool) error {
	if in.AuthMethod != nil && *in.AuthMethod == model.AuthMethodNone {
		return Invalid("token_endpoint_auth_method", "must be client_secret_post, client_secret_basic or private_key_jwt")
	}
	if in.Scopes != nil {
		out := []string{}
		for _, sc := range *in.Scopes {
			sc = strings.TrimSpace(sc)
			switch {
			case slices.Contains(out, sc):
				continue
			case !slices.Contains(ServiceAccountScopes, sc) && !slices.Contains(PrimaryServiceAccountScopes, sc):
				return Invalid("scopes", "unknown scope "+sc)
			case slices.Contains(PrimaryServiceAccountScopes, sc) && !org.Primary:
				return Invalid("scopes", sc+" is only for a service account of the primary organization")
			case !slices.Contains(c.Scopes, sc) && !mayGrant(a, org, sc, first):
				return Invalid("scopes", "you cannot grant the "+sc+" scope")
			}
			out = append(out, sc)
		}
		if len(out) == 0 {
			return Invalid("scopes", "choose at least one scope")
		}
		c.Scopes = out
	}
	return s.applyClient(ctx, a, c, ClientInput{Name: in.Name, Description: in.Description, AuthMethod: in.AuthMethod,
		JWKS: in.JWKS, JWKSURI: in.JWKSURI, FAPI: in.FAPI, Enabled: in.Enabled})
}

// newServiceAccount checks in for a new service account of org, which a creates, and returns it with its secret (none
// for private_key_jwt); nothing is written.
func (s *Service) newServiceAccount(ctx context.Context, a *Actor, org *model.Org, in ServiceAccountInput, first bool) (*model.Client, string, error) {
	if in.Name == nil {
		return nil, "", Invalid("name", "required")
	}
	if in.Scopes == nil {
		return nil, "", Invalid("scopes", "choose at least one scope")
	}
	c := &model.Client{Meta: model.Meta{ID: model.NewClientID()}, OrgID: org.ID, ServiceAccount: true, Enabled: true,
		AuthMethod: model.AuthMethodSecretPost, GrantTypes: []string{"client_credentials"}}
	if err := s.applyServiceAccount(ctx, a, org, c, in, first); err != nil {
		return nil, "", err
	}
	secret := ""
	if c.AuthMethod != model.AuthMethodPrivateJWT {
		secret = "qsrs_" + secure.RandomToken(32)
		c.SecretHash = string(secure.HashSecret(secret))
	}
	return c, secret, nil
}

// createServiceAccount writes c, made by newServiceAccount.
func (s *Service) createServiceAccount(ctx context.Context, a *Actor, c *model.Client) error {
	return mapStore(s.audited(ctx, a, c.OrgID, "service_account.create", c.Name,
		map[string]string{"client_id": c.ID, "scopes": strings.Join(c.Scopes, " ")}, func() error { return s.Clients.Create(ctx, c) }))
}

// ListServiceAccounts lists the service accounts of organization orgID: its administrators' to see.
func (s *Service) ListServiceAccounts(ctx context.Context, a *Actor, orgID string, q store.ListQuery) ([]*model.Client, int, error) {
	if !s.canAdminOrg(a, orgID) {
		return nil, 0, ErrForbidden
	}
	q.Scope = orgID
	q.Filters = append(slices.Clone(q.Filters), store.Filter{Field: "service_account", Value: true})
	l, n, err := s.Clients.List(ctx, q)
	return l, n, mapStore(err)
}

// GetServiceAccount returns service account id of organization orgID.
func (s *Service) GetServiceAccount(ctx context.Context, a *Actor, orgID, id string) (*model.Client, error) {
	c, err := s.Clients.Get(ctx, id)
	if err != nil {
		return nil, mapStore(err)
	}
	if !c.ServiceAccount || c.OrgID != orgID || !s.canAdminOrg(a, orgID) {
		return nil, ErrNotFound
	}
	return c, nil
}

// CreateServiceAccount creates a service account of organization orgID and returns it with its secret (shown once;
// none for private_key_jwt).
func (s *Service) CreateServiceAccount(ctx context.Context, a *Actor, orgID string, in ServiceAccountInput) (*model.Client, string, error) {
	if !s.canAdminOrg(a, orgID) {
		return nil, "", ErrForbidden
	}
	org, err := s.Org(ctx, orgID)
	if err != nil {
		return nil, "", mapStore(err)
	}
	c, secret, err := s.newServiceAccount(ctx, a, org, in, false)
	if err != nil {
		return nil, "", err
	}
	if err := s.createServiceAccount(ctx, a, c); err != nil {
		return nil, "", err
	}
	return c, secret, nil
}

// managedServiceAccount returns service account id of organization orgID for a change a may make to it.
func (s *Service) managedServiceAccount(ctx context.Context, a *Actor, orgID, id string) (*model.Org, *model.Client, error) {
	c, err := s.GetServiceAccount(ctx, a, orgID, id)
	if err != nil {
		return nil, nil, err
	}
	org, err := s.Org(ctx, orgID)
	if err != nil {
		return nil, nil, mapStore(err)
	}
	if !s.mayManageServiceAccount(a, org, c) {
		return nil, nil, ErrForbidden
	}
	return org, c, nil
}

// UpdateServiceAccount changes a service account.
func (s *Service) UpdateServiceAccount(ctx context.Context, a *Actor, orgID, id string, in ServiceAccountInput) (*model.Client, error) {
	org, c, err := s.managedServiceAccount(ctx, a, orgID, id)
	if err != nil {
		return nil, err
	}
	was := snapshot(c)
	if err := s.applyServiceAccount(ctx, a, org, c, in, false); err != nil {
		return nil, err
	}
	if c.AuthMethod == model.AuthMethodPrivateJWT {
		c.SecretHash = "" // its keys are its credential now: a secret it had no longer works
	}
	if err := s.audited(ctx, a, orgID, "service_account.update", c.Name, addChanges(map[string]string{"client_id": c.ID}, was, c),
		func() error { return s.Clients.Update(ctx, c) }); err != nil {
		return nil, mapStore(err)
	}
	return c, nil
}

// RotateServiceAccountSecret issues a new secret; the old one stops working at once. An account that authenticates
// with private_key_jwt has none: its keys are rotated where it publishes them (jwks_uri) or by an update.
func (s *Service) RotateServiceAccountSecret(ctx context.Context, a *Actor, orgID, id string) (string, error) {
	_, c, err := s.managedServiceAccount(ctx, a, orgID, id)
	if err != nil {
		return "", err
	}
	if c.AuthMethod == model.AuthMethodPrivateJWT {
		return "", Invalid("token_endpoint_auth_method", "a service account that uses private_key_jwt has no secret: change its keys instead")
	}
	secret := "qsrs_" + secure.RandomToken(32)
	c.SecretHash = string(secure.HashSecret(secret))
	if err := s.audited(ctx, a, orgID, "service_account.secret.rotate", c.Name, map[string]string{"client_id": c.ID},
		func() error { return s.Clients.Update(ctx, c) }); err != nil {
		return "", mapStore(err)
	}
	return secret, nil
}

// DeleteServiceAccount deletes a service account; its tokens stop working at once.
func (s *Service) DeleteServiceAccount(ctx context.Context, a *Actor, orgID, id string) error {
	_, c, err := s.managedServiceAccount(ctx, a, orgID, id)
	if err != nil {
		return err
	}
	return mapStore(s.audited(ctx, a, orgID, "service_account.delete", c.Name, map[string]string{"client_id": c.ID},
		func() error { return s.Clients.Delete(ctx, id) }))
}
