package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

// Self-registered applications: AI clients (and other tools) that connect to an MCP server register themselves with
// the authorization server instead of being set up by an administrator, either by dynamic client registration
// (RFC 7591) or with a client_id that is the URL of their Client ID Metadata Document. They belong to no
// organization: each authorization request names resources (RFC 8707), and the tenant that owns them
// (Tenant.Resources), if it allows self-registered applications, governs the sign-in as for any of its clients.
//
// They are public clients with PKCE (no secret to keep), for user scopes only, with redirect URIs that are https, the
// loopback interface or a private-use scheme; consent is always asked. Registration is unauthenticated, so it is
// limited per address (by the caller) and capped in total, and a registration never used is removed after a day.

const (
	// MaxSelfRegistered caps self-registered applications nobody has used yet: registration is refused beyond it
	// until unused ones expire (used ones do not count).
	MaxSelfRegistered = 10000
	// selfRegUnusedTTL is how long a self-registered application never used to sign anyone in is kept.
	selfRegUnusedTTL = 24 * time.Hour
	// MetadataRefresh is how old a metadata document may get before it is read again; MetadataStale, how old one
	// may be used while its URL cannot be read.
	MetadataRefresh = 24 * time.Hour
	MetadataStale   = 7 * 24 * time.Hour
	// MaxMetadataBytes bounds a Client ID Metadata Document.
	MaxMetadataBytes = 5 << 10
	// MaxMetadataURL bounds a metadata-document client_id (it is the client's id everywhere).
	MaxMetadataURL   = 190
	maxSelfRedirects = 10
)

// SelfRegScopes are the scopes a self-registered application may have: signing in and the basic profile.
var SelfRegScopes = []string{"openid", "profile", "email", "offline_access"}

// RegistrationInput is client metadata (RFC 7591 §2), as registered or as read from a metadata document.
type RegistrationInput struct {
	ClientID      string   `json:"client_id"` // a metadata document's own URL
	ClientName    string   `json:"client_name"`
	RedirectURIs  []string `json:"redirect_uris"`
	AuthMethod    string   `json:"token_endpoint_auth_method"`
	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
	Scope         string   `json:"scope"`
}

// selfRegRedirect reports whether a self-registered application may use ru: https; http on the loopback interface
// (localhost, 127.0.0.1 or [::1], any port at sign-in, RFC 8252 §7.3); or a private-use scheme in reverse domain
// name form (§7.1: it holds a dot, which none of http, javascript, data or file do). Never with a fragment or
// credentials, and at most 2000 characters.
func selfRegRedirect(ru string) bool {
	u, err := url.Parse(ru)
	if err != nil || len(ru) > 2000 || u.Fragment != "" || u.User != nil || u.Opaque != "" {
		return false
	}
	switch {
	case u.Scheme == "https":
		return u.Host != ""
	case u.Scheme == "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	default:
		return strings.Contains(u.Scheme, ".") && (u.Host != "" || strings.HasPrefix(u.Path, "/"))
	}
}

// RegistrationError is an RFC 7591 §3.2.2 error: Code is invalid_redirect_uri or invalid_client_metadata.
type RegistrationError struct{ Code, Description string }

func (e *RegistrationError) Error() string { return e.Description }

func regErr(code, desc string) error { return &RegistrationError{Code: code, Description: desc} }

// selfRegClient checks metadata and returns the client it describes (id not set).
func selfRegClient(in RegistrationInput) (*model.Client, error) {
	if in.AuthMethod != "" && in.AuthMethod != model.AuthMethodNone {
		return nil, regErr("invalid_client_metadata", "only public clients (token_endpoint_auth_method none) may register")
	}
	for _, g := range in.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			return nil, regErr("invalid_client_metadata", "unsupported grant type "+g+": authorization_code and refresh_token only")
		}
	}
	for _, rt := range in.ResponseTypes {
		if rt != "code" {
			return nil, regErr("invalid_client_metadata", "unsupported response type "+rt)
		}
	}
	if len(in.RedirectURIs) == 0 || len(in.RedirectURIs) > maxSelfRedirects {
		return nil, regErr("invalid_redirect_uri", "between 1 and 10 redirect_uris are required")
	}
	var redirects []string
	for _, ru := range in.RedirectURIs {
		if !selfRegRedirect(ru) {
			return nil, regErr("invalid_redirect_uri", ru+": use https, http on localhost, 127.0.0.1 or [::1], or a "+
				"private-use scheme named after a domain, such as com.example.app:/callback (RFC 8252)")
		}
		if !slices.Contains(redirects, ru) {
			redirects = append(redirects, ru)
		}
	}
	scopes := slices.Clone(SelfRegScopes)
	if s := strings.Fields(in.Scope); len(s) > 0 {
		scopes = slices.DeleteFunc(slices.Clone(s), func(v string) bool { return !slices.Contains(SelfRegScopes, v) })
		if !slices.Contains(scopes, "openid") {
			scopes = append([]string{"openid"}, scopes...)
		}
	}
	name := strings.TrimSpace(in.ClientName)
	if name == "" || len([]rune(name)) > 100 {
		name = "Unnamed application"
	}
	return &model.Client{Name: name, RedirectURIs: redirects, GrantTypes: []string{"authorization_code", "refresh_token"},
		Scopes: dedupeStrings(scopes), AuthMethod: model.AuthMethodNone, Enabled: true, RotateRefresh: true,
		SelfRegistered: true}, nil
}

func dedupeStrings(l []string) []string {
	var out []string
	for _, v := range l {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// unusedSelfRegistered is how many self-registered applications nobody has let sign in yet (the cap applies to
// these only: applications people use are never crowded out by a flood of registrations).
func (s *Service) unusedSelfRegistered(ctx context.Context) (int, error) {
	l, _, err := s.Clients.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "self_registered", Value: true}}})
	if err != nil {
		return 0, mapStore(err)
	}
	n := 0
	for _, c := range l {
		if c.LastUsed.IsZero() {
			n++
		}
	}
	return n, nil
}

// RegisterClient registers an application by dynamic client registration (RFC 7591). The caller limits it per
// address; here it is checked and capped in total.
func (s *Service) RegisterClient(ctx context.Context, in RegistrationInput) (*model.Client, error) {
	c, err := selfRegClient(in)
	if err != nil {
		return nil, err
	}
	if n, err := s.unusedSelfRegistered(ctx); err != nil {
		return nil, err
	} else if n >= MaxSelfRegistered {
		return nil, ErrLimit
	}
	c.ID = "dyn-" + secure.RandomToken(16)
	if err := s.Clients.Create(Durable(ctx), c); err != nil {
		return nil, mapStore(err)
	}
	s.Audit(ctx, System, "", "client.self_register", c.Name, map[string]string{"client_id": c.ID,
		"redirect_uris": strings.Join(c.RedirectURIs, " ")})
	return c, nil
}

// ParseMetadata checks a Client ID Metadata Document (id is the URL it was read from, doc its body) and returns the
// application it describes, not stored: one is stored only once a user lets it sign in (NoteSelfRegisteredUse), so
// requests that name made-up documents cost no storage. A document must name itself as its client_id.
func ParseMetadata(id string, doc []byte) (*model.Client, error) {
	var in RegistrationInput
	if err := json.Unmarshal(doc, &in); err != nil {
		return nil, regErr("invalid_client_metadata", "the client metadata document is not JSON")
	}
	if in.ClientID != id {
		return nil, regErr("invalid_client_metadata", "the client metadata document does not name its own URL as client_id")
	}
	c, err := selfRegClient(in)
	if err != nil {
		return nil, err
	}
	c.ID, c.MetadataFetched = id, time.Now().UTC()
	return c, nil
}

// RefreshMetadataClient replaces a stored metadata-document application's details with a newly read copy of its
// document (keeping its use and tenants). An administrator's client of that id is never touched.
func (s *Service) RefreshMetadataClient(ctx context.Context, fresh *model.Client) (*model.Client, error) {
	cur, err := s.Clients.Get(ctx, fresh.ID)
	if err != nil {
		return nil, mapStore(err)
	}
	if !cur.SelfRegistered {
		return nil, ErrNotFound
	}
	c := *fresh
	c.Meta, c.LastUsed, c.UsedIn, c.Enabled = cur.Meta, cur.LastUsed, cur.UsedIn, cur.Enabled
	if err := s.Clients.Update(ctx, &c); err != nil {
		return nil, mapStore(err)
	}
	return &c, nil
}

// InTenant returns a self-registered application as the tenant t sees it: a client of t's organization and t, for
// t's resources. Everything after the resolution (sign-in rules, access, tokens) then treats it as t's client.
func InTenant(c *model.Client, t *model.Tenant) *model.Client {
	cp := *c
	cp.OrgID, cp.TenantID, cp.Resources = t.OrgID, t.ID, slices.Clone(t.Resources)
	cp.FirstParty, cp.IntrospectOrg, cp.SCIM = false, false, false
	return &cp
}

// NoteSelfRegisteredUse records that a self-registered application was authorized in tenant t (its last use, and
// t among the tenants whose administrators list it). A metadata-document application is stored here, on its first
// authorization: app is the application as its document describes it.
func (s *Service) NoteSelfRegisteredUse(ctx context.Context, app *model.Client, t *model.Tenant) {
	c, err := s.Clients.Get(ctx, app.ID)
	if errors.Is(err, store.ErrNotFound) && app.IsMetadataClient() {
		nc := *app
		nc.OrgID, nc.TenantID, nc.Resources = "", "", nil
		nc.UsedIn, nc.LastUsed = []string{t.ID}, time.Now().UTC()
		if err := s.Clients.Create(Durable(ctx), &nc); err == nil {
			s.Audit(ctx, System, t.OrgID, "client.self_register", nc.Name, map[string]string{"client_id": nc.ID,
				"metadata": "document", "tenant": t.Name})
		}
		return
	}
	if err != nil || !c.SelfRegistered {
		return
	}
	if slices.Contains(c.UsedIn, t.ID) && time.Since(c.LastUsed) < time.Hour {
		return // one write an hour at most
	}
	if !slices.Contains(c.UsedIn, t.ID) {
		c.UsedIn = append(c.UsedIn, t.ID)
	}
	c.LastUsed = time.Now().UTC()
	_ = s.Clients.Update(ctx, c)
}

// PurgeSelfRegistered removes the self-registered applications never used to sign anyone in within a day of
// registering. It returns how many went.
func (s *Service) PurgeSelfRegistered(ctx context.Context, now time.Time) int {
	l, _, err := s.Clients.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "self_registered", Value: true}}})
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range l {
		if c.LastUsed.IsZero() && now.Sub(c.Created) > selfRegUnusedTTL {
			if err := s.Clients.Delete(ctx, c.ID); err == nil {
				n++
			}
		}
	}
	return n
}

// SelfRegApp is a self-registered application as a tenant's administrators see it.
type SelfRegApp struct {
	ClientID     string    `json:"client_id"`
	Name         string    `json:"name"`
	Metadata     bool      `json:"metadata_document"` // client_id is the URL of its metadata document
	RedirectURIs []string  `json:"redirect_uris"`
	Created      time.Time `json:"created"`
	LastUsed     time.Time `json:"last_used"`
	Users        int       `json:"users"` // users of the organization it holds live grants for
}

// SelfRegisteredApps lists the self-registered applications authorized in the tenant, with how many of the
// organization's users they hold access for.
func (s *Service) SelfRegisteredApps(ctx context.Context, a *Actor, tenantID string) ([]SelfRegApp, error) {
	t, err := s.GetTenant(ctx, a, tenantID)
	if err != nil {
		return nil, err
	}
	l, _, err := s.Clients.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "self_registered", Value: true}}})
	if err != nil {
		return nil, mapStore(err)
	}
	out := []SelfRegApp{}
	for _, c := range l {
		if !slices.Contains(c.UsedIn, t.ID) {
			continue
		}
		users, _ := s.selfRegUsers(ctx, c.ID, t.OrgID)
		out = append(out, SelfRegApp{ClientID: c.ID, Name: c.Name, Metadata: c.IsMetadataClient(),
			RedirectURIs: c.RedirectURIs, Created: c.Created, LastUsed: c.LastUsed, Users: len(users)})
	}
	slices.SortFunc(out, func(x, y SelfRegApp) int { return strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name)) })
	return out, nil
}

// selfRegUsers returns the users of the organization the application holds live grants for.
func (s *Service) selfRegUsers(ctx context.Context, clientID, orgID string) ([]string, error) {
	gs, _, err := s.Grants.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "client_id", Value: clientID}}})
	if err != nil {
		return nil, mapStore(err)
	}
	var users []string
	for _, g := range gs {
		if g.OrgID == orgID && !slices.Contains(users, g.UserID) {
			users = append(users, g.UserID)
		}
	}
	return users, nil
}

// RevokeSelfRegisteredApp ends a self-registered application's access in the tenant's organization: every user's
// grants to it go (the application is told by back-channel logout where it has one) and the tenant no longer lists
// it. It can come back only by asking the users again (consent).
func (s *Service) RevokeSelfRegisteredApp(ctx context.Context, a *Actor, tenantID, clientID string) error {
	t, err := s.GetTenant(ctx, a, tenantID)
	if err != nil {
		return err
	}
	c, err := s.Clients.Get(ctx, clientID)
	if err != nil || !c.SelfRegistered || !slices.Contains(c.UsedIn, t.ID) {
		return ErrNotFound
	}
	users, err := s.selfRegUsers(ctx, c.ID, t.OrgID)
	if err != nil {
		return err
	}
	for _, u := range users {
		if _, err := s.RevokeAppAccess(ctx, u, c.ID); err != nil {
			return err
		}
	}
	c.UsedIn = slices.DeleteFunc(c.UsedIn, func(id string) bool { return id == t.ID })
	if err := s.Clients.Update(Durable(ctx), c); err != nil {
		return mapStore(err)
	}
	s.Audit(ctx, a, t.OrgID, "client.self_registered.revoke", c.Name, map[string]string{"client_id": c.ID,
		"tenant": t.Name, "users": itoa(len(users))})
	return nil
}
