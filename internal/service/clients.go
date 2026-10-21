package service

import (
	"context"
	"net/url"
	"slices"
	"strings"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

// ClientInput is the editable part of an OAuth client.
type ClientInput struct {
	TenantID       *string   `json:"tenant_id"`
	Name           *string   `json:"name"`
	Description    *string   `json:"description"`
	RedirectURIs   *[]string `json:"redirect_uris"`
	PostLogoutURIs *[]string `json:"post_logout_redirect_uris"`
	BackchannelURI *string   `json:"backchannel_logout_uri"`
	GrantTypes     *[]string `json:"grant_types"`
	Scopes         *[]string `json:"scopes"`
	Resources      *[]string `json:"resources"` // resource indicators (RFC 8707) the client may ask for
	AuthMethod     *string   `json:"token_endpoint_auth_method"`
	SigningAlg     *string   `json:"id_token_signed_response_alg"`
	JWKS           *string   `json:"jwks"`
	JWKSURI        *string   `json:"jwks_uri"`
	FirstParty     *bool     `json:"first_party"`
	SCIM           *bool     `json:"scim"`
	RotateRefresh  *bool     `json:"rotate_refresh_tokens"`
	IntrospectOrg  *bool     `json:"introspect_org"`
	RequirePKCE    *bool     `json:"require_pkce"` // false only for confidential clients
	RequirePAR     *bool     `json:"require_pushed_authorization_requests"`
	Enabled        *bool     `json:"enabled"`
}

// GrantTokenExchange is the RFC 8693 token exchange grant type.
const GrantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

var (
	validGrants      = []string{"authorization_code", "refresh_token", "client_credentials", GrantTokenExchange}
	validAuthMethods = []string{model.AuthMethodSecretPost, model.AuthMethodSecretBasic, model.AuthMethodPrivateJWT,
		model.AuthMethodNone}
	validAlgs = []string{"", "ES256", "EdDSA", "RS256"}
)

func validRedirect(raw string, allowHTTPLoopback bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.Host == "" && u.Scheme == "https" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return allowHTTPLoopback && (h == "localhost" || h == "127.0.0.1" || h == "::1")
	case "":
		return false
	}
	// Private-use URI scheme for native apps (RFC 8252 §7.1): must be a reverse domain name, e.g. com.example.app.
	return strings.Contains(u.Scheme, ".") && u.Opaque == "" && u.Host == "" && strings.HasPrefix(u.Path, "/")
}

// httpsURL reports whether raw is an absolute https URL with a host, no user info and no fragment: the addresses
// Quisora itself calls (back-channel logout, a client's JWKS).
func httpsURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == "" && !strings.Contains(raw, "#")
}

// maxClientScopes bounds a client's scope list.
const maxClientScopes = 50

// validScopeToken reports whether v is an OAuth scope token (RFC 6749 §3.3): printable ASCII except space, " and \,
// at most 100 characters.
func validScopeToken(v string) bool {
	if v == "" || len(v) > 100 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// maxClientResources bounds a client's resource list.
const maxClientResources = 20

// ValidResource reports whether v is a resource indicator (RFC 8707 §2): an absolute URI without a fragment, such as
// https://api.example.com/ or urn:example:api, at most 512 characters.
func ValidResource(v string) bool {
	u, err := url.Parse(v)
	return err == nil && u.IsAbs() && u.Fragment == "" && !strings.Contains(v, "#") && (u.Host != "" || u.Opaque != "") &&
		len(v) <= 512 && strings.TrimSpace(v) == v
}

// checkResources trims, validates and de-duplicates a client's resource list.
func checkResources(list []string) ([]string, error) {
	out := []string{}
	for _, v := range list {
		v = strings.TrimSpace(v)
		if v == "" || slices.Contains(out, v) {
			continue
		}
		if !ValidResource(v) {
			return nil, Invalid("resources", v+" is not a resource indicator: use an absolute URI without a fragment, such as https://api.example.com/")
		}
		out = append(out, v)
	}
	if len(out) > maxClientResources {
		return nil, Invalid("resources", "at most "+itoa(maxClientResources)+" resources are allowed")
	}
	return out, nil
}

// checkScopes trims, validates and de-duplicates a scope list, keeping the given order.
func checkScopes(list []string) ([]string, error) {
	out := []string{}
	for _, v := range list {
		v = strings.TrimSpace(v)
		if v == "" || slices.Contains(out, v) {
			continue
		}
		if !validScopeToken(v) {
			return nil, Invalid("scopes", v+" is not a valid scope: use printable characters without spaces, quotes or backslashes (at most 100)")
		}
		out = append(out, v)
	}
	if len(out) > maxClientScopes {
		return nil, Invalid("scopes", "at most 50 scopes are allowed")
	}
	return out, nil
}

func (s *Service) applyClient(ctx context.Context, a *Actor, c *model.Client, in ClientInput) error {
	if in.TenantID != nil {
		t, err := s.Tenants.Get(ctx, *in.TenantID)
		if err != nil || t.OrgID != c.OrgID {
			return Invalid("tenant_id", "choose a tenant of this organization")
		}
		c.TenantID = t.ID
	}
	if in.Name != nil {
		v := strings.TrimSpace(*in.Name)
		if v == "" || len(v) > 200 {
			return Invalid("name", "required, at most 200 characters")
		}
		c.Name = v
	}
	if in.Description != nil {
		c.Description = strings.TrimSpace(*in.Description)
	}
	checkURIs := func(field string, list []string) ([]string, error) {
		out := []string{}
		for _, r := range list {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}
			if !validRedirect(r, true) {
				return nil, Invalid(field, r+" must be an https URL (http only for localhost) or a reverse-domain app scheme such as com.example.app:/callback, without a fragment")
			}
			out = append(out, r)
		}
		return out, nil
	}
	var err error
	if in.RedirectURIs != nil {
		if c.RedirectURIs, err = checkURIs("redirect_uris", *in.RedirectURIs); err != nil {
			return err
		}
	}
	if in.PostLogoutURIs != nil {
		if c.PostLogoutURIs, err = checkURIs("post_logout_redirect_uris", *in.PostLogoutURIs); err != nil {
			return err
		}
	}
	if in.BackchannelURI != nil {
		v := strings.TrimSpace(*in.BackchannelURI)
		if v != "" && !httpsURL(v) {
			return Invalid("backchannel_logout_uri", "must be an https URL (https://host/path, without a fragment)")
		}
		c.BackchannelURI = v
	}
	if in.GrantTypes != nil {
		for _, g := range *in.GrantTypes {
			if !slices.Contains(validGrants, g) {
				return Invalid("grant_types", "unsupported grant type "+g)
			}
		}
		c.GrantTypes = slices.Clone(*in.GrantTypes)
	}
	if in.Scopes != nil {
		scopes, err := checkScopes(*in.Scopes)
		if err != nil {
			return err
		}
		c.Scopes = scopes
	}
	if in.Resources != nil {
		res, err := checkResources(*in.Resources)
		if err != nil {
			return err
		}
		c.Resources = res
	}
	if in.AuthMethod != nil {
		if !slices.Contains(validAuthMethods, *in.AuthMethod) {
			return Invalid("token_endpoint_auth_method", "must be client_secret_post, client_secret_basic, private_key_jwt or none")
		}
		c.AuthMethod = *in.AuthMethod
	}
	if in.SigningAlg != nil {
		if !slices.Contains(validAlgs, *in.SigningAlg) {
			return Invalid("id_token_signed_response_alg", "must be ES256, EdDSA or RS256")
		}
		c.SigningAlg = *in.SigningAlg
	}
	if in.JWKS != nil {
		c.JWKS = strings.TrimSpace(*in.JWKS)
	}
	if in.JWKSURI != nil {
		v := strings.TrimSpace(*in.JWKSURI)
		if v != "" && !httpsURL(v) {
			return Invalid("jwks_uri", "must be an https URL (https://host/path, without a fragment)")
		}
		c.JWKSURI = v
	}
	// first_party skips the consent screen: its redirect URIs receive any user's code from one link they open, which
	// would let an administrator act as a peer they may not reset. Super admins only, like SCIM.
	if in.FirstParty != nil && *in.FirstParty != c.FirstParty {
		if !a.IsSuper() {
			return ErrForbidden
		}
		c.FirstParty = *in.FirstParty
	}
	if in.RotateRefresh != nil {
		c.RotateRefresh = *in.RotateRefresh
	}
	if in.IntrospectOrg != nil {
		c.IntrospectOrg = *in.IntrospectOrg
	}
	if in.RequirePKCE != nil {
		c.PKCEOptional = !*in.RequirePKCE
	}
	if in.RequirePAR != nil {
		c.RequirePAR = *in.RequirePAR
	}
	if in.Enabled != nil {
		c.Enabled = *in.Enabled
	}
	// SCIM (provisioning) is a super-admin-only flag.
	if in.SCIM != nil && *in.SCIM != c.SCIM {
		if !a.IsSuper() { // super admins only
			return ErrForbidden
		}
		c.SCIM = *in.SCIM
	}
	if c.Public() {
		switch {
		case slices.Contains(c.GrantTypes, "client_credentials"):
			return Invalid("grant_types", "a public client cannot use the client credentials grant")
		case slices.Contains(c.GrantTypes, GrantTokenExchange):
			return Invalid("grant_types", "a public client cannot use the token exchange grant")
		case c.SCIM:
			return Invalid("scim", "a public client cannot use SCIM")
		case c.PKCEOptional:
			return Invalid("require_pkce", "a public client must use PKCE")
		}
		c.RotateRefresh = true  // public clients always get one-time refresh tokens
		c.IntrospectOrg = false // and cannot introspect at all
	}
	if c.AuthMethod == model.AuthMethodPrivateJWT && c.JWKS == "" && c.JWKSURI == "" {
		return Invalid("jwks", "private_key_jwt needs the client's public keys (jwks or jwks_uri)")
	}
	if slices.Contains(c.GrantTypes, "authorization_code") && len(c.RedirectURIs) == 0 {
		return Invalid("redirect_uris", "at least one redirect URI is required for the authorization code grant")
	}
	return nil
}

func (s *Service) ListClients(ctx context.Context, a *Actor, orgID string, q store.ListQuery) ([]*model.Client, int, error) {
	if !s.canAdminOrg(a, orgID) {
		return nil, 0, ErrForbidden
	}
	q.Scope = orgID
	l, n, err := s.Clients.List(ctx, q)
	return l, n, mapStore(err)
}

func (s *Service) GetClient(ctx context.Context, a *Actor, id string) (*model.Client, error) {
	c, err := s.Clients.Get(ctx, id)
	if err != nil {
		return nil, mapStore(err)
	}
	if !s.canAdminOrg(a, c.OrgID) {
		return nil, ErrNotFound
	}
	return c, nil
}

// CreateClient creates a client and returns it with its secret (shown once).
func (s *Service) CreateClient(ctx context.Context, a *Actor, orgID string, in ClientInput) (*model.Client, string, error) {
	if !s.canAdminOrg(a, orgID) {
		return nil, "", ErrForbidden
	}
	// Refresh tokens rotate by default: a copy that is used after the client used the token is detected and ends the
	// grant (rotate_refresh_tokens: false turns it off for a client that cannot keep the latest token).
	c := &model.Client{Meta: model.Meta{ID: model.NewClientID()}, OrgID: orgID, AuthMethod: model.AuthMethodSecretPost, Enabled: true,
		RotateRefresh: true, GrantTypes: []string{"authorization_code", "refresh_token"}, Scopes: []string{"openid", "profile", "email", "groups", "org", "offline_access"}}
	if in.Name == nil {
		return nil, "", Invalid("name", "required")
	}
	if err := s.applyClient(ctx, a, c, in); err != nil {
		return nil, "", err
	}
	if c.TenantID == "" {
		t, err := s.DefaultTenant(ctx, orgID)
		if err != nil {
			return nil, "", err
		}
		c.TenantID = t.ID
	}
	secret := ""
	if !c.Public() {
		secret = "qsrs_" + secure.RandomToken(32)
		c.SecretHash = string(secure.HashSecret(secret))
	}
	if err := s.Clients.Create(ctx, c); err != nil {
		return nil, "", mapStore(err)
	}
	s.Audit(ctx, a, orgID, "client.create", c.Name, map[string]string{"client_id": c.ID})
	return c, secret, nil
}

func (s *Service) UpdateClient(ctx context.Context, a *Actor, id string, in ClientInput) (*model.Client, error) {
	c, err := s.GetClient(ctx, a, id)
	if err != nil {
		return nil, err
	}
	if superOnly(c) && !a.IsSuper() {
		return nil, ErrForbidden // provisioning and first-party clients are managed by super admins only
	}
	was := snapshot(c)
	if err := s.applyClient(ctx, a, c, in); err != nil {
		return nil, err
	}
	if err := s.Clients.Update(Durable(ctx), c); err != nil {
		return nil, mapStore(err)
	}
	s.Audit(ctx, a, c.OrgID, "client.update", c.Name, addChanges(map[string]string{"client_id": c.ID}, was, c))
	return c, nil
}

// superOnly reports whether c carries a capability only super admins grant (SCIM provisioning, skipping consent), so
// only they change, rotate or delete it.
func superOnly(c *model.Client) bool { return c.SCIM || c.FirstParty }

// RotateClientSecret issues a new secret; the old one stops working immediately.
func (s *Service) RotateClientSecret(ctx context.Context, a *Actor, id string) (string, error) {
	c, err := s.GetClient(ctx, a, id)
	if err != nil {
		return "", err
	}
	if c.Public() {
		return "", Invalid("token_endpoint_auth_method", "a public client has no secret")
	}
	if superOnly(c) && !a.IsSuper() {
		return "", ErrForbidden // the credential of a super-admin-only capability stays with super admins
	}
	secret := "qsrs_" + secure.RandomToken(32)
	c.SecretHash = string(secure.HashSecret(secret))
	if err := s.Clients.Update(Durable(ctx), c); err != nil {
		return "", mapStore(err)
	}
	s.Audit(ctx, a, c.OrgID, "client.secret.rotate", c.Name, map[string]string{"client_id": c.ID})
	return secret, nil
}

func (s *Service) DeleteClient(ctx context.Context, a *Actor, id string) error {
	c, err := s.GetClient(ctx, a, id)
	if err != nil {
		return err
	}
	if superOnly(c) && !a.IsSuper() {
		return ErrForbidden
	}
	if err := s.Clients.Delete(Durable(ctx), id); err != nil {
		return mapStore(err)
	}
	s.Audit(ctx, a, c.OrgID, "client.delete", c.Name, map[string]string{"client_id": c.ID})
	return nil
}

// VerifyClientSecret checks a presented secret against the client (constant time). Public clients have none.
func VerifyClientSecret(c *model.Client, secret string) bool {
	return !c.Public() && c.SecretHash != "" && secure.EqualSecret(secret, []byte(c.SecretHash))
}

// NewGrantKey gives g a new refresh token key: random, stored sealed with the master key, so the database alone can
// neither produce nor recognise a refresh token. Being a sealed secret like any other, it is re-sealed by a master
// key rotation (ResealSecrets) while the tokens made from it stay the same.
func (s *Service) NewGrantKey(g *model.Grant) {
	g.Key, g.Secret = s.Sealer.SealFor(GrantKeyBinding(g.ID), secure.RandomBytes(32)), nil
}

// GrantRefreshKeys returns the keys g's refresh tokens may be made from: its own (Key), or, for a grant from before
// grants had one, the key derived from the master key over its seed, under each key of the master keyring (only
// one of them made it). legacy says it is the latter: ConvertGrantKey stores the one that matched as the grant's own.
func (s *Service) GrantRefreshKeys(g *model.Grant) (keys [][]byte, legacy bool, err error) {
	if g.Key != "" {
		k, err := s.Sealer.OpenFor(GrantKeyBinding(g.ID), g.Key)
		if err != nil {
			return nil, false, err
		}
		return [][]byte{k}, false, nil
	}
	if len(g.Secret) == 0 {
		return nil, false, nil
	}
	return s.Sealer.MACs("refresh", g.ID, string(g.Secret)), true, nil
}

// ConvertGrantKey makes key (the legacy key g's tokens are made from) g's own sealed key, so its tokens no longer
// depend on the master key that derived it. The tokens stay the same. The caller saves g.
func (s *Service) ConvertGrantKey(g *model.Grant, key []byte) {
	g.Key, g.Secret = s.Sealer.SealFor(GrantKeyBinding(g.ID), key), nil
}
