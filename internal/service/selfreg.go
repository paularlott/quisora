package service

import (
	"bytes"
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
// loopback interface or a private-use scheme; consent is always asked. Registration is unauthenticated, so it is open
// only at an organization with a tenant that accepts self-registered applications, limited per address and per
// organization (by the caller) and capped per organization, a registration never used is removed after a day, and one
// no longer used after selfRegIdleTTL.

const (
	// MaxSelfRegistered caps an organization's self-registered applications nobody has used yet (used ones do not
	// count): at it, a registration makes room by removing one of them picked at random, among those registered over
	// an hour ago (evictUnusedSelfRegistered), so a flood neither grows storage nor stops the next registration, nor
	// removes one just made before its first sign-in, and is one organization's alone.
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
	// MaxSelfRedirectLen bounds each redirect URI of a self-registered application, and MaxSelfRedirectsLen all of
	// them together (as their audit event records them, separated by spaces). Anyone may register, and each
	// registration is audited with its redirect URIs, kept for the audit retention (90 days by default): bounded, a
	// flood at the organization's registration rate adds a bounded few hundred megabytes a day at most, where 10 URIs
	// of 2000 characters each made it several gigabytes. An application's redirect URIs are short (a loopback port,
	// an app scheme, a callback path).
	MaxSelfRedirectLen  = 512
	MaxSelfRedirectsLen = 2048
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
// credentials, and at most MaxSelfRedirectLen bytes.
func selfRegRedirect(ru string) bool {
	u, err := url.Parse(ru)
	if err != nil || len(ru) > MaxSelfRedirectLen || u.Fragment != "" || u.User != nil || u.Opaque != "" {
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
type RegistrationError struct {
	Code, Description string
	cause             error // what kind of refusal, when one is told apart (ErrRedirectCaps)
}

func (e *RegistrationError) Error() string { return e.Description }

func (e *RegistrationError) Unwrap() error { return e.cause }

func regErr(code, desc string) error { return &RegistrationError{Code: code, Description: desc} }

// ErrRedirectCaps is the cause of a RegistrationError for redirect URIs over the length caps (MaxSelfRedirectLen each,
// MaxSelfRedirectsLen together). The caps apply to a metadata document read again for a stored application as to any
// other: one whose document is over them is no longer refreshed, and is unknown once its stored copy is MetadataStale
// old. A deliberate limit (each registration is audited with its redirect URIs, and anyone may register), which the
// caller logs apart from other refusals so that an administrator can tell why an application went.
var ErrRedirectCaps = errors.New("redirect URIs over the length caps")

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
		if len(ru) > MaxSelfRedirectLen {
			return nil, &RegistrationError{Code: "invalid_redirect_uri", cause: ErrRedirectCaps, Description: clip(ru, 64) +
				"…: a redirect URI is at most " + itoa(MaxSelfRedirectLen) + " characters (this one is " + itoa(len(ru)) + ")"}
		}
		if !selfRegRedirect(ru) {
			return nil, regErr("invalid_redirect_uri", ru+": use https, http on localhost, 127.0.0.1 or [::1], or a "+
				"private-use scheme named after a domain, such as com.example.app:/callback (RFC 8252)")
		}
		if !slices.Contains(redirects, ru) {
			redirects = append(redirects, ru)
		}
	}
	if len(strings.Join(redirects, " ")) > MaxSelfRedirectsLen {
		return nil, &RegistrationError{Code: "invalid_redirect_uri", cause: ErrRedirectCaps,
			Description: "the redirect_uris are too long together: at most " + itoa(MaxSelfRedirectsLen) + " characters"}
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

// selfRegEvictAge is how old an unused registration must be before the cap may remove it while older ones are there:
// time for its first sign-in. The cap turns over at the organization's registration rate, at most 60 a minute (the
// caller's limit), so at least MaxSelfRegistered - 60*60 of a full organization's unused registrations are older than
// this, and one of them is there to go; should none be (a sample of only fresh ones), the oldest goes instead: a
// registration is never refused for the age rule.
const selfRegEvictAge = time.Hour

// selfRegEvictSample is how many unused registrations eviction reads to find one old enough.
const selfRegEvictSample = 16

// evictUnusedSelfRegistered removes one of organization orgID's self-registered applications nobody has used, picked
// at random among those older than selfRegEvictAge (of a sample: the first selfRegEvictSample by id after a random one;
// ids are random), or, should the sample hold none that old, the oldest of it: refusing registrations at the cap
// instead would let anyone hold an organization there, nobody else able to register, and a flood (at most 60 a
// minute) cannot make the registrations of the last hour more than about a third of a full organization's, so a fresh
// registration waiting for its first sign-in is not what goes (a sample of 16 all that fresh is about one in 10^7).
// An application in use is never removed: the removal applies only to the record as read, unused (a use recorded
// since, NoteSelfRegisteredUse, stops it). As RevokeSelfRegisteredApp does, it ends the grants users hold to the
// application, should any have been made in the moment around its removal; an application never used has none.
func (s *Service) evictUnusedSelfRegistered(ctx context.Context, orgID string) error {
	q := store.ListQuery{Scope: orgID, Limit: selfRegEvictSample, After: model.DynamicClientPrefix + secure.RandomToken(16),
		Filters: []store.Filter{{Field: "unused_self_registered", Value: true}}}
	l, _, err := s.Clients.List(ctx, q)
	if err == nil && len(l) < selfRegEvictSample { // past the last: the first ones make up the sample
		q.After, q.Limit = "", selfRegEvictSample-len(l)
		var more []*model.Client
		more, _, err = s.Clients.List(ctx, q)
		l = append(l, more...)
	}
	if err != nil {
		return mapStore(err)
	}
	var c *model.Client
	for _, cand := range l {
		if !cand.SelfRegistered || !cand.LastUsed.IsZero() {
			continue // used since the listing's index was written: the cap is a bound, not an exact count
		}
		if time.Since(cand.Created) >= selfRegEvictAge {
			c = cand
			break
		}
		if c == nil || cand.Created.Before(c.Created) {
			c = cand
		}
	}
	if c == nil {
		return nil
	}
	err = s.audited(ctx, System, orgID, "client.self_registered.evict", c.Name, map[string]string{"client_id": c.ID},
		func() error { return s.Clients.DeleteIf(ctx, c.ID, c.Version) })
	if errors.Is(err, store.ErrStale) || errors.Is(err, store.ErrNotFound) {
		return nil // used (or removed) since it was read: it stays, or is gone already
	}
	if err != nil {
		return mapStore(err)
	}
	// Removed: no grant to it may outlive it. The registration that made room goes on whatever happens here; a grant
	// whose application is gone is refused anyway, and the orphan sweep removes it (SweepOrphans).
	users, err := s.selfRegUsers(ctx, c.ID)
	if err == nil {
		for _, u := range users {
			if _, rerr := s.RevokeAppAccess(ctx, u, c.ID); rerr != nil {
				err = rerr
			}
		}
	}
	if err != nil {
		s.Log.WithError(err).Error("not every grant to an evicted self-registered application could be ended", "client", c.ID)
	}
	return nil
}

// acceptsSelfRegistered reports whether a tenant of organization orgID lets self-registered applications sign in
// for resources it owns (TenantSettings.SelfRegistration, TenantForResources): where none does, a registration could
// never be used, and is refused rather than stored.
func (s *Service) acceptsSelfRegistered(ctx context.Context, orgID string) (bool, error) {
	const page = 200
	for after := ""; ; { // an organization's tenants are its administrators' own, a page at a time
		l, _, err := s.Tenants.List(ctx, store.ListQuery{Scope: orgID, After: after, Limit: page})
		if err != nil {
			return false, mapStore(err)
		}
		for _, t := range l {
			if t.Settings.SelfRegistration && len(t.Resources) > 0 {
				return true, nil
			}
		}
		if len(l) < page {
			return false, nil
		}
		after = l[len(l)-1].ID
	}
}

// RegisterClient registers an application of organization orgID by dynamic client registration (RFC 7591). The caller
// limits it per address and organization; here it is checked, refused (ErrForbidden) unless a tenant of the
// organization accepts self-registered applications, and capped (MaxSelfRegistered): at the cap, one unused
// registration picked at random makes room (evictUnusedSelfRegistered).
func (s *Service) RegisterClient(ctx context.Context, orgID string, in RegistrationInput) (*model.Client, error) {
	if ok, err := s.acceptsSelfRegistered(ctx, orgID); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrForbidden
	}
	c, err := selfRegClient(in)
	if err != nil {
		return nil, err
	}
	if n, err := s.unusedSelfRegistered(ctx, orgID); err != nil {
		return nil, err
	} else if n >= MaxSelfRegistered {
		if err := s.evictUnusedSelfRegistered(ctx, orgID); err != nil {
			return nil, err
		}
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

// MetadataSummary is what a sign-in keeps of the metadata document that c, an application not stored yet, was made
// from (ParseMetadata): a document of the fields an application is made from and nothing else (its URL, name,
// redirect URIs and scopes, as they were accepted), from which ParseMetadata makes the same application again. The
// document itself is whatever its author wrote, up to MaxMetadataBytes, and would be held once for every sign-in
// that names it. It is encoded without HTML escaping (six bytes for each <, > and &), and is nil when it would still
// be longer than MaxMetadataBytes (redirect URIs full of bytes that are not UTF-8, each three once decoded): such an
// application is not signed in to.
//
// It also says when the document was read (c.MetadataFetched), which ParseMetadataSummary gives the application made
// from it again: the application stored at consent, maybe many minutes later, is as old as the document it was made
// from, and is read again a day after that read, not after the consent.
func MetadataSummary(c *model.Client) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	sum := metadataSummary{RegistrationInput: RegistrationInput{ClientID: c.MetadataURL, ClientName: c.Name,
		RedirectURIs: c.RedirectURIs, Scope: strings.Join(c.Scopes, " ")}}
	if !c.MetadataFetched.IsZero() {
		sum.Read = c.MetadataFetched.Unix()
	}
	if enc.Encode(sum) != nil || buf.Len() > MaxMetadataBytes {
		return nil
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})
}

// metadataSummary is the form of MetadataSummary: the fields of a document, and when it was read.
type metadataSummary struct {
	RegistrationInput
	Read int64 `json:"read_at,omitempty"` // unix seconds
}

// ParseMetadataSummary is ParseMetadata of a summary that MetadataSummary made (sum, kept by this server, never a
// document as read: a document cannot set its own read time, as ParseMetadata takes no such field), with the
// application's MetadataFetched the time the document was read, when the summary says and it is in the past.
func ParseMetadataSummary(orgID, id string, sum []byte) (*model.Client, error) {
	c, err := ParseMetadata(orgID, id, sum)
	if err != nil {
		return nil, err
	}
	var s metadataSummary
	if json.Unmarshal(sum, &s) == nil && s.Read > 0 {
		if read := time.Unix(s.Read, 0).UTC(); read.Before(c.MetadataFetched) {
			c.MetadataFetched = read
		}
	}
	return c, nil
}

// RefreshMetadataClient replaces a stored metadata-document application's details with a newly read copy of its
// document (keeping its use and its consent generation). An administrator's client of that id is never touched.
//
// A document is not pinned: whoever serves its URL may change it, and the application then is what the new copy
// says. Where its codes go is what users allowed, though, so a copy that changes the redirect URIs moves the consent
// generation on (model.Client.RememberGen), as an administrator's change of them does (credentialsChanged): a code
// issued for the application as it was is not redeemed (the user signs in again, and is asked, as always), and nothing
// a user allowed before stands in for consent to the new destinations.
func (s *Service) RefreshMetadataClient(ctx context.Context, fresh *model.Client) (*model.Client, error) {
	cur, err := s.Clients.Get(ctx, fresh.ID)
	if err != nil {
		return nil, mapStore(err)
	}
	if !cur.SelfRegistered {
		return nil, ErrNotFound
	}
	c := *fresh
	c.Meta, c.LastUsed, c.Enabled, c.RememberGen = cur.Meta, cur.LastUsed, cur.Enabled, cur.RememberGen
	if !sameRedirects(cur.RedirectURIs, c.RedirectURIs) {
		c.RememberGen++
	}
	if err := s.Clients.Update(ctx, &c); err != nil {
		return nil, mapStore(err)
	}
	return &c, nil
}

// sameRedirects reports whether a and b hold the same redirect URIs, in any order.
func sameRedirects(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// InTenant returns a self-registered application as the tenant t sees it: a client of t and its resources (t is of the
// application's organization). Everything after the resolution (sign-in rules, access, tokens) then treats it as t's
// client.
func InTenant(c *model.Client, t *model.Tenant) *model.Client {
	cp := *c
	cp.TenantID, cp.Resources = t.ID, slices.Clone(t.Resources)
	cp.FirstParty, cp.IntrospectOrg, cp.RememberConsent = false, false, false
	return &cp
}

// NoteSelfRegisteredUse records that a self-registered application was authorized in tenant t (its last use, which
// keeps it from being purged). A metadata-document application is stored here, on its first authorization: app is the
// application as its document describes it (or as the tenant sees it, InTenant).
//
// The caller records the use before it issues anything, and issues nothing when this returns an error: an application
// whose first use is not on record counts as never used, which the cap on unused registrations may remove at any
// moment (evictUnusedSelfRegistered) and the purge removes after a day, so a first use must be recorded, or not
// happen. The error is ErrNotFound when the application is gone (removed since the sign-in began), else the store's.
// A later use's record only keeps the application from the idle purge for months yet: one that cannot be written is
// logged, not refused.
func (s *Service) NoteSelfRegisteredUse(ctx context.Context, app *model.Client, t *model.Tenant) error {
	for attempt := 0; ; attempt++ {
		c, err := s.Clients.Get(ctx, app.ID)
		if errors.Is(err, store.ErrNotFound) && app.IsMetadataClient() {
			nc := *app
			nc.TenantID, nc.Resources, nc.LastUsed = "", nil, time.Now().UTC()
			err = s.audited(ctx, System, t.OrgID, "client.self_register", nc.Name, map[string]string{"client_id": nc.ClientID(),
				"metadata": "document", "tenant": t.Name}, func() error { return s.Clients.Create(ctx, &nc) })
			if errors.Is(err, store.ErrStale) && attempt < 2 {
				continue // another first use stored it meanwhile: read it again
			}
			return mapStore(err)
		}
		if err != nil {
			return mapStore(err)
		}
		if !c.SelfRegistered {
			return nil
		}
		if time.Since(c.LastUsed) < time.Hour {
			return nil // one write an hour at most
		}
		first := c.LastUsed.IsZero()
		c.LastUsed = time.Now().UTC()
		err = s.Clients.Update(ctx, c)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, store.ErrStale) && attempt < 2:
			continue // changed meanwhile (used, refreshed, or removed): read it again
		case first:
			return mapStore(err)
		}
		s.Log.WithError(err).Warn("a self-registered application's use could not be recorded", "client", c.ID)
		return nil
	}
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

// SelfRegisteredApps lists a page of the self-registered applications of organization orgID (q's offset, limit,
// search and sort; by name unless it asks otherwise), each with how many of its users it holds access for, and says
// how many there are. Only the page is read and counted: an organization may hold up to MaxSelfRegistered unused ones.
func (s *Service) SelfRegisteredApps(ctx context.Context, a *Actor, orgID string, q store.ListQuery) ([]SelfRegApp, int, error) {
	if !s.canAdminOrg(a, orgID) {
		return nil, 0, ErrForbidden
	}
	q.Scope, q.Filters, q.After = orgID, []store.Filter{{Field: "self_registered", Value: true}}, ""
	if q.Sort == "" {
		q.Sort = "name"
	}
	l, total, err := s.Clients.List(ctx, q)
	if err != nil {
		return nil, 0, mapStore(err)
	}
	out := []SelfRegApp{}
	for _, c := range l {
		users, _ := s.selfRegUsers(ctx, c.ID)
		out = append(out, SelfRegApp{ClientID: c.ClientID(), Name: c.Name, Metadata: c.IsMetadataClient(),
			RedirectURIs: c.RedirectURIs, Created: c.Created, LastUsed: c.LastUsed, Users: len(users)})
	}
	return out, total, nil
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
	return s.endSelfRegistered(ctx, a, c, nil)
}

// endSelfRegistered ends self-registered application c for actor a: every user's grants to it, then the application
// (client.self_registered.revoke, with detail besides).
func (s *Service) endSelfRegistered(ctx context.Context, a *Actor, c *model.Client, detail map[string]string) error {
	users, err := s.selfRegUsers(ctx, c.ID)
	if err != nil {
		return err
	}
	for _, u := range users {
		if _, err := s.RevokeAppAccess(ctx, u, c.ID); err != nil {
			return err
		}
	}
	d := map[string]string{"client_id": c.ClientID(), "users": itoa(len(users))}
	for k, v := range detail {
		d[k] = v
	}
	return mapStore(s.audited(ctx, a, c.OrgID, "client.self_registered.revoke", c.Name, d,
		func() error { return s.Clients.Delete(ctx, c.ID) }))
}

// EndGoneMetadataApp ends organization orgID's stored metadata-document application whose document URL (its
// client_id, url) this server read and was answered 404 Not Found or 410 Gone by that URL's own server (reason says
// which): as RevokeSelfRegisteredApp does, every user's grants to it end and it is removed, by the system, the event's
// reason naming the answer. Its author took the document down, which is how such an application is withdrawn; were the
// stored copy kept, it would go on signing users in for up to MetadataStale. Only the caller's own read of that exact
// URL decides it (anyone can make a sign-in name a URL, but not what its server answers); a network error, a timeout
// or another answer never does. ErrNotFound when the organization has no such application stored (or the id is an
// administrator's client, which is never touched).
func (s *Service) EndGoneMetadataApp(ctx context.Context, orgID, url, reason string) error {
	c, err := s.Clients.Get(ctx, model.ClientRecordID(orgID, url))
	if err != nil || !c.SelfRegistered || !c.IsMetadataClient() || c.OrgID != orgID || c.MetadataURL != url {
		return ErrNotFound
	}
	return s.endSelfRegistered(ctx, System, c, map[string]string{"reason": "metadata document gone: " + reason})
}
