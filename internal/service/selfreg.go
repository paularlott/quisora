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
// (RFC 7591) or with a client_id that is the URL of their Client ID Metadata Document. They belong to the organization
// they registered at or were authorized in (the same document in two organizations is two records, each limited to its
// organization): each authorization request names resources (RFC 8707), and the tenant of the organization that owns
// them (Tenant.Resources), if it allows self-registered applications, governs the sign-in as for any of its clients.
//
// They are public clients with PKCE (no secret to keep), for user scopes only, with redirect URIs that are https, the
// loopback interface or a private-use scheme; consent is always asked. Registration is unauthenticated, so it is
// limited per address (by the caller) and capped per organization, a registration never used is removed after a day,
// and one no longer used after selfRegIdleTTL.

const (
	// MaxSelfRegistered caps an organization's self-registered applications nobody has used yet: registration is
	// refused beyond it until unused ones expire (used ones do not count), so one organization's flood does not
	// stop another's registrations.
	MaxSelfRegistered = 10000
	// selfRegUnusedTTL is how long a self-registered application never used to sign anyone in is kept.
	selfRegUnusedTTL = 24 * time.Hour
	// selfRegIdleTTL is how long one is kept after its last use (at least the refresh token lifetime, so it holds no
	// grant that still works: a grant ends that long after it was made, and each was made at a use).
	selfRegIdleTTL = 90 * 24 * time.Hour
	// selfRegPurgePage is how many applications the purge reads at a time.
	selfRegPurgePage = 500
	// MetadataRefresh is how old a metadata document may get before it is read again; MetadataStale, how old one
	// may be used while its URL cannot be read.
	MetadataRefresh = 24 * time.Hour
	MetadataStale   = 7 * 24 * time.Hour
	// MaxMetadataBytes bounds a Client ID Metadata Document.
	MaxMetadataBytes = 5 << 10
	// MaxMetadataURL bounds a client_id a request names. A metadata-document application's is a URL that every token,
	// grant and audit event of it repeats (its record id is a digest, model.ClientRecordID, so no store limit
	// applies to it); any other client's is its record id, which a store holds up to store.MaxIDLength (191).
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

// unusedSelfRegistered is how many of organization orgID's self-registered applications nobody has let sign in yet
// (the cap applies to these only: applications people use are never crowded out by a flood of registrations): the
// total of a listing of one, so no application is read.
func (s *Service) unusedSelfRegistered(ctx context.Context, orgID string) (int, error) {
	_, n, err := s.Clients.IDs(ctx, store.ListQuery{Scope: orgID, Limit: 1,
		Filters: []store.Filter{{Field: "unused_self_registered", Value: true}}})
	return n, mapStore(err)
}

// RegisterClient registers an application of organization orgID by dynamic client registration (RFC 7591). The caller
// limits it per address; here it is checked and capped (MaxSelfRegistered).
func (s *Service) RegisterClient(ctx context.Context, orgID string, in RegistrationInput) (*model.Client, error) {
	c, err := selfRegClient(in)
	if err != nil {
		return nil, err
	}
	if n, err := s.unusedSelfRegistered(ctx, orgID); err != nil {
		return nil, err
	} else if n >= MaxSelfRegistered {
		return nil, ErrLimit
	}
	c.ID, c.OrgID = model.DynamicClientPrefix+secure.RandomToken(16), orgID
	if err := s.audited(ctx, System, orgID, "client.self_register", c.Name, map[string]string{"client_id": c.ID,
		"redirect_uris": strings.Join(c.RedirectURIs, " ")}, func() error { return s.Clients.Create(ctx, c) }); err != nil {
		return nil, mapStore(err)
	}
	return c, nil
}

// ParseMetadata checks a Client ID Metadata Document (id is the URL it was read from, doc its body) and returns the
// application of organization orgID it describes, not stored: one is stored only once a user lets it sign in
// (NoteSelfRegisteredUse), so requests that name made-up documents cost no storage. A document must name itself as its
// client_id.
func ParseMetadata(orgID, id string, doc []byte) (*model.Client, error) {
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
	c.ID, c.OrgID, c.MetadataURL, c.MetadataFetched = model.ClientRecordID(orgID, id), orgID, id, time.Now().UTC()
	return c, nil
}

// RefreshMetadataClient replaces a stored metadata-document application's details with a newly read copy of its
// document (keeping its use). An administrator's client of that id is never touched.
func (s *Service) RefreshMetadataClient(ctx context.Context, fresh *model.Client) (*model.Client, error) {
	cur, err := s.Clients.Get(ctx, fresh.ID)
	if err != nil {
		return nil, mapStore(err)
	}
	if !cur.SelfRegistered {
		return nil, ErrNotFound
	}
	c := *fresh
	c.Meta, c.LastUsed, c.Enabled = cur.Meta, cur.LastUsed, cur.Enabled
	if err := s.Clients.Update(ctx, &c); err != nil {
		return nil, mapStore(err)
	}
	return &c, nil
}

// InTenant returns a self-registered application as the tenant t sees it: a client of t and its resources (t is of the
// application's organization). Everything after the resolution (sign-in rules, access, tokens) then treats it as t's
// client.
func InTenant(c *model.Client, t *model.Tenant) *model.Client {
	cp := *c
	cp.TenantID, cp.Resources = t.ID, slices.Clone(t.Resources)
	cp.FirstParty, cp.IntrospectOrg, cp.SCIM = false, false, false
	return &cp
}

// NoteSelfRegisteredUse records that a self-registered application was authorized in tenant t (its last use, which
// keeps it from being purged). A metadata-document application is stored here, on its first authorization: app is the
// application as its document describes it (or as the tenant sees it, InTenant).
func (s *Service) NoteSelfRegisteredUse(ctx context.Context, app *model.Client, t *model.Tenant) {
	c, err := s.Clients.Get(ctx, app.ID)
	if errors.Is(err, store.ErrNotFound) && app.IsMetadataClient() {
		nc := *app
		nc.TenantID, nc.Resources, nc.LastUsed = "", nil, time.Now().UTC()
		_ = s.audited(ctx, System, t.OrgID, "client.self_register", nc.Name, map[string]string{"client_id": nc.ClientID(),
			"metadata": "document", "tenant": t.Name}, func() error { return s.Clients.Create(ctx, &nc) })
		return
	}
	if err != nil || !c.SelfRegistered || time.Since(c.LastUsed) < time.Hour {
		return // one write an hour at most
	}
	c.LastUsed = time.Now().UTC()
	_ = s.Clients.Update(ctx, c)
}

// PurgeSelfRegistered removes the self-registered applications never used to sign anyone in within a day of
// registering, and those not used for selfRegIdleTTL (or the refresh token lifetime, if longer): registration is
// unauthenticated, and nothing else would ever remove one. It returns how many went.
func (s *Service) PurgeSelfRegistered(ctx context.Context, now time.Time) int {
	idle := max(selfRegIdleTTL, s.Cfg.Tokens.Refresh()+24*time.Hour)
	n, after := 0, ""
	for { // a page at a time, by id: a server holds as many as the organizations let register
		l, _, err := s.Clients.List(ctx, store.ListQuery{After: after, Limit: selfRegPurgePage,
			Filters: []store.Filter{{Field: "self_registered", Value: true}}})
		if err != nil {
			return n
		}
		for _, c := range l {
			if c.LastUsed.IsZero() && now.Sub(c.Created) > selfRegUnusedTTL || !c.LastUsed.IsZero() && now.Sub(c.LastUsed) > idle {
				if err := s.Clients.Delete(ctx, c.ID); err == nil {
					n++
				}
			}
		}
		if len(l) < selfRegPurgePage {
			return n
		}
		after = l[len(l)-1].ID
	}
}

// SelfRegApp is a self-registered application as an organization's administrators see it.
type SelfRegApp struct {
	ClientID     string    `json:"client_id"`
	Name         string    `json:"name"`
	Metadata     bool      `json:"metadata_document"` // client_id is the URL of its metadata document
	RedirectURIs []string  `json:"redirect_uris"`
	Created      time.Time `json:"created"`
	LastUsed     time.Time `json:"last_used"`
	Users        int       `json:"users"` // users of the organization it holds live grants for
}

// SelfRegisteredApps lists the self-registered applications of organization orgID, with how many of its users they
// hold access for.
func (s *Service) SelfRegisteredApps(ctx context.Context, a *Actor, orgID string) ([]SelfRegApp, error) {
	if !s.canAdminOrg(a, orgID) {
		return nil, ErrForbidden
	}
	l, _, err := s.Clients.List(ctx, store.ListQuery{Scope: orgID, Filters: []store.Filter{{Field: "self_registered", Value: true}}})
	if err != nil {
		return nil, mapStore(err)
	}
	out := []SelfRegApp{}
	for _, c := range l {
		users, _ := s.selfRegUsers(ctx, c.ID)
		out = append(out, SelfRegApp{ClientID: c.ClientID(), Name: c.Name, Metadata: c.IsMetadataClient(),
			RedirectURIs: c.RedirectURIs, Created: c.Created, LastUsed: c.LastUsed, Users: len(users)})
	}
	slices.SortFunc(out, func(x, y SelfRegApp) int { return strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name)) })
	return out, nil
}

// selfRegUsers returns the users the application (its record id) holds live grants for: all of its organization's,
// as a grant names the client of the organization its user signed in to.
func (s *Service) selfRegUsers(ctx context.Context, recordID string) ([]string, error) {
	gs, _, err := s.Grants.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "client_id", Value: recordID}}})
	if err != nil {
		return nil, mapStore(err)
	}
	var users []string
	seen := map[string]bool{}
	for _, g := range gs {
		if !seen[g.UserID] {
			seen[g.UserID] = true
			users = append(users, g.UserID)
		}
	}
	return users, nil
}

// RevokeSelfRegisteredApp removes a self-registered application from organization orgID: every user's grants to it go
// (the application is told by back-channel logout where it has one), then the application itself. clientID is the
// client_id the application sends (SelfRegApp.ClientID). A metadata-document application can come back by asking the
// users again (consent); a registered one has to register again.
func (s *Service) RevokeSelfRegisteredApp(ctx context.Context, a *Actor, orgID, clientID string) error {
	if !s.canAdminOrg(a, orgID) {
		return ErrForbidden
	}
	c, err := s.Clients.Get(ctx, model.ClientRecordID(orgID, clientID))
	if err != nil || !c.SelfRegistered || c.OrgID != orgID {
		return ErrNotFound
	}
	users, err := s.selfRegUsers(ctx, c.ID)
	if err != nil {
		return err
	}
	for _, u := range users {
		if _, err := s.RevokeAppAccess(ctx, u, c.ID); err != nil {
			return err
		}
	}
	return mapStore(s.audited(ctx, a, orgID, "client.self_registered.revoke", c.Name, map[string]string{"client_id": c.ClientID(),
		"users": itoa(len(users))}, func() error { return s.Clients.Delete(ctx, c.ID) }))
}
