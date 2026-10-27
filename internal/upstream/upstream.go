// Package upstream signs users in with an external identity provider: a generic OpenID Connect provider (discovery,
// authorization code + PKCE, nonce, ID token verified against the provider's JWKS) or GitHub (OAuth 2 plus the
// /user and /user/emails APIs).
//
// Linking rules (security-critical):
//   - An upstream account is bound to a local user by the (provider id, subject) pair stored as model.Identity.
//     Once bound, only that pair signs the user in; the email address is never consulted again.
//   - The binding is created on the first sign-in, by email, only when the provider has not turned that off
//     (Provider.LinkByEmail) AND the provider reports an address as verified (OIDC email_verified; GitHub: any
//     address of /user/emails with verified=true) AND that address is a VERIFIED primary or verified linked address
//     of exactly one user of the provider's organization. Unverified addresses never link, on either side, and an
//     ambiguous match (several users) links nothing and refuses the sign-in. When AllowedDomains is set the
//     matching address's domain must be listed too. Every such link is audited ("identity.link.email").
//   - A user is auto-provisioned only when no existing user matched, the provider has AutoProvision on, the provider
//     reports the primary email as verified, and (when AllowedDomains is set) the address's domain is listed. If the
//     address already belongs to a local user (verified or not) the sign-in is refused rather than duplicated.
//
// The authorization "state" is a single-use ephemeral entry (namespace "upstream") which also carries the PKCE
// verifier and nonce; the caller additionally binds it to the browser with a cookie (login CSRF protection).
package upstream

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// Namespace is the ephemeral namespace for authorization state.
const Namespace = "upstream"

// StateTTL is how long a started sign-in may take.
const StateTTL = 10 * time.Minute

var (
	// ErrPrivileged: the provider's address belongs to a manager or administrator, who are never linked by email.
	ErrPrivileged      = errors.New("upstream: privileged accounts connect providers themselves")
	ErrState           = errors.New("upstream: invalid or expired state")
	ErrUpstream        = errors.New("upstream: the provider did not complete the sign-in")
	ErrNotLinked       = errors.New("upstream: no account is linked to this identity")
	ErrUnverifiedEmail = errors.New("upstream: the provider did not verify the email address")
	ErrDomain          = errors.New("upstream: email domain is not allowed")
	ErrExists          = errors.New("upstream: an account with this email address already exists")
	ErrDisabled        = errors.New("upstream: provider or account is disabled")
)

// Claims are the identity facts taken from the provider.
type Claims struct {
	Subject       string
	Email         string
	EmailVerified bool
	// VerifiedEmails are all the addresses the provider vouches for (including Email when EmailVerified); they are
	// what first-sign-in linking matches against users' verified addresses.
	VerifiedEmails []string
	Name           string
	GivenName      string
	FamilyName     string
	Username       string
}

// Result is a completed upstream sign-in.
type Result struct {
	User        *model.User
	Org         *model.Org
	Provider    *model.Provider
	Next        string
	Tenant      string // tenant name the sign-in was started for (may be empty)
	Provisioned bool
	Claims      Claims
	// Connect is the user who started connecting this provider to their account (BeginConnect); the user was not
	// resolved and nobody is signed in: the caller attaches the identity.
	Connect string
}

// Service runs upstream sign-ins.
type Service struct {
	Svc       *service.Service
	Eph       ephemeral.Store
	PublicURL string
	// HTTP performs every request to providers (tests substitute a client that trusts their certificates).
	HTTP *http.Client
	// GitHub endpoints; the defaults are github.com's (tests point them at a fake).
	GitHubAuthURL  string
	GitHubTokenURL string
	GitHubAPIURL   string
	// MicrosoftAuthority is the Microsoft identity platform (tests substitute a fake).
	MicrosoftAuthority string
	// Now is the clock used for token validity checks.
	Now func() time.Time

	mu        sync.Mutex
	disc      map[string]*discovery
	discCalls map[string]*discoveryCall // fetching, or failed recently (see discover)
	cache     map[string]*keyCache
}

// New returns a service. publicURL is the server's own origin (each provider's redirect URI is
// publicURL + "/login/callback/<provider id>"). client makes every request to a provider: provider addresses are
// entered by organization administrators, so it is the guarded outbound client (secure.OutboundClient), which the
// caller must give: there is no unguarded default to fall back to.
func New(svc *service.Service, eph ephemeral.Store, publicURL string, client *http.Client) *Service {
	return &Service{
		Svc: svc, Eph: eph, PublicURL: strings.TrimSuffix(publicURL, "/"), HTTP: client,
		GitHubAuthURL: "https://github.com/login/oauth/authorize", GitHubTokenURL: "https://github.com/login/oauth/access_token",
		GitHubAPIURL: "https://api.github.com", MicrosoftAuthority: model.MicrosoftAuthority, Now: time.Now,
		disc: map[string]*discovery{}, discCalls: map[string]*discoveryCall{}, cache: map[string]*keyCache{},
	}
}

// CallbackURL is the redirect URI to register with provider providerID. Each provider has its own, so a response can
// only arrive at the address of the provider it is for: the callback checks that the state was started for that
// provider (the recommended defence against IdP mix-up, RFC 9700 §4.4).
func (s *Service) CallbackURL(providerID string) string {
	return s.PublicURL + CallbackPath(providerID)
}

// CallbackPath is the path of provider providerID's callback address.
func CallbackPath(providerID string) string { return "/login/callback/" + url.PathEscape(providerID) }

type state struct {
	ProviderID string `json:"p"`
	OrgID      string `json:"o"`
	Connect    string `json:"u,omitempty"` // user id connecting this provider to their account
	Next       string `json:"n"`
	Tenant     string `json:"t,omitempty"`
	Nonce      string `json:"c"`
	Verifier   string `json:"v"`
}

func s256(v string) string {
	h := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// BeginTenant starts a sign-in with p for org (on behalf of a tenant, by name, or ""; carried through the state to
// Finish) and returns the provider URL to send the browser to plus the state value, which the caller must also set
// as a cookie and present to Finish.
func (s *Service) BeginTenant(ctx context.Context, org *model.Org, p *model.Provider, next, tenant string) (string, string, error) {
	return s.begin(ctx, org, p, state{Next: next, Tenant: tenant})
}

// BeginConnect starts connecting provider p to user u's account (u is signed in): Finish then returns the verified
// identity in Result.Claims with Result.Connect set, instead of signing anyone in.
func (s *Service) BeginConnect(ctx context.Context, org *model.Org, p *model.Provider, u *model.User, next string) (string, string, error) {
	if u.OrgID != org.ID {
		return "", "", ErrDisabled
	}
	return s.begin(ctx, org, p, state{Next: next, Connect: u.ID})
}

func (s *Service) begin(ctx context.Context, org *model.Org, p *model.Provider, st state) (string, string, error) {
	if !p.Enabled || p.OrgID != org.ID {
		return "", "", ErrDisabled
	}
	// Discovery first: a provider that cannot be reached leaves no state behind.
	var d *discovery
	switch p.Type {
	case model.ProviderOIDC, model.ProviderGoogle, model.ProviderGitLab, model.ProviderAuth0, model.ProviderMicrosoft:
		var err error
		if d, err = s.discoverFor(ctx, p); err != nil {
			return "", "", err
		}
	}
	st.ProviderID, st.OrgID, st.Nonce, st.Verifier = p.ID, org.ID, secure.RandomToken(24), secure.RandomToken(32)
	b, _ := json.Marshal(st)
	id, err := s.Eph.New(ctx, Namespace, b, StateTTL)
	if err != nil {
		return "", "", err
	}
	q := url.Values{
		"client_id": {p.ClientID}, "redirect_uri": {s.CallbackURL(p.ID)}, "response_type": {"code"}, "state": {id},
		"code_challenge": {s256(st.Verifier)}, "code_challenge_method": {"S256"},
	}
	var base string
	switch p.Type {
	case model.ProviderOIDC, model.ProviderGoogle, model.ProviderGitLab, model.ProviderAuth0, model.ProviderMicrosoft:
		base = d.AuthorizationEndpoint
		scopes := p.Scopes
		if !contains(scopes, "openid") {
			scopes = append([]string{"openid"}, scopes...)
		}
		q.Set("scope", strings.Join(scopes, " "))
		q.Set("nonce", st.Nonce)
	case model.ProviderGitHub:
		base = s.GitHubAuthURL
		q.Set("scope", strings.Join(p.Scopes, " "))
		q.Del("response_type")
	default:
		return "", "", fmt.Errorf("upstream: unknown provider type %q", p.Type)
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + q.Encode(), id, nil
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// Finish completes a sign-in: providerID is the provider named by the callback address, state the "state" query
// parameter, browserState the value of the cookie set at Begin, code the authorization code. The state is consumed
// whatever the outcome; a state started for another provider is refused (ErrState).
//
// When the state was valid but the sign-in failed, the returned Result is non-nil with only Org, Provider and Next
// set, so the caller can send the user back to the right sign-in page; on ErrState it is nil.
func (s *Service) Finish(ctx context.Context, providerID, stateID, browserState, code string) (*Result, error) {
	b, err := s.Eph.Take(ctx, Namespace, stateID)
	if err != nil {
		return nil, ErrState
	}
	var st state
	if json.Unmarshal(b, &st) != nil || subtle.ConstantTimeCompare([]byte(stateID), []byte(browserState)) != 1 ||
		st.ProviderID != providerID {
		return nil, ErrState
	}
	org, err := s.Svc.Orgs.Get(ctx, st.OrgID)
	if err != nil {
		return nil, ErrState
	}
	fail := &Result{Org: org, Next: st.Next, Tenant: st.Tenant}
	p, err := s.Svc.Providers.Get(ctx, st.ProviderID)
	if err != nil || p.OrgID != st.OrgID || !p.Enabled {
		return fail, ErrDisabled
	}
	fail.Provider = p
	if code == "" {
		return fail, ErrUpstream
	}
	secret, err := s.Svc.Sealer.OpenFor(service.ProviderSecretBinding(p.ID), p.ClientSecret)
	if err != nil {
		return fail, fmt.Errorf("upstream: provider secret: %w", err)
	}
	var claims Claims
	var refresh string
	switch p.Type {
	case model.ProviderOIDC, model.ProviderGoogle, model.ProviderGitLab, model.ProviderAuth0, model.ProviderMicrosoft:
		claims, refresh, err = s.oidcSignIn(ctx, p, string(secret), code, st)
	case model.ProviderGitHub:
		claims, err = s.githubClaims(ctx, p, string(secret), code, st)
	default:
		err = fmt.Errorf("upstream: unknown provider type %q", p.Type)
	}
	if err != nil {
		return fail, err
	}
	if st.Connect != "" {
		if claims.Subject == "" {
			return fail, ErrUpstream
		}
		return &Result{Org: org, Provider: p, Next: st.Next, Claims: claims, Connect: st.Connect}, nil
	}
	u, provisioned, err := s.resolve(ctx, org, p, claims)
	if err != nil {
		return fail, err
	}
	if refresh != "" {
		s.keepRefresh(ctx, p, claims.Subject, refresh)
	}
	return &Result{User: u, Org: org, Provider: p, Next: st.Next, Tenant: st.Tenant, Provisioned: provisioned, Claims: claims}, nil
}

// CancelTenant consumes the state of a sign-in the provider reported as denied or failed (error= on the callback)
// and returns the org, next path and tenant it was started for, for redirecting back. ok is false for an unknown
// state or one that does not match the browser's cookie.
func (s *Service) CancelTenant(ctx context.Context, providerID, stateID, browserState string) (org *model.Org, next, tenant string, ok bool) {
	b, err := s.Eph.Take(ctx, Namespace, stateID)
	if err != nil {
		return nil, "", "", false
	}
	var st state
	if json.Unmarshal(b, &st) != nil || subtle.ConstantTimeCompare([]byte(stateID), []byte(browserState)) != 1 ||
		st.ProviderID != providerID {
		return nil, "", "", false
	}
	o, err := s.Svc.Orgs.Get(ctx, st.OrgID)
	if err != nil {
		return nil, "", "", false
	}
	return o, st.Next, st.Tenant, true
}

// resolve finds the user bound to the identity, or provisions one when the provider allows it.
func (s *Service) resolve(ctx context.Context, org *model.Org, p *model.Provider, c Claims) (*model.User, bool, error) {
	if c.Subject == "" {
		return nil, false, ErrUpstream
	}
	ident, err := s.Svc.Identities.GetByUnique(ctx, model.IdentityKey(p.ID, c.Subject))
	if err == nil && ident.Authority != model.ProviderAuthority(p) {
		// Linked when the provider pointed at another type, issuer or directory: the subject now names someone
		// else (GitHub and GitLab ids are public numbers). The link goes; the sign-in carries on as unlinked.
		_ = s.Svc.Identities.Delete(ctx, ident.ID)
		actor := &service.Actor{OrgID: org.ID, Role: model.RoleManager, Name: "provider:" + p.Name}
		s.Svc.Audit(ctx, actor, org.ID, "identity.unlink", ident.UserID, map[string]string{"provider": p.Name, "reason": "provider changed"})
		err = store.ErrNotFound
	}
	if err == nil && !DomainAllowed(p, c) {
		return nil, false, ErrDomain // the provider's allowed domains apply to linked identities too
	}
	switch {
	case err == nil:
		u, uerr := s.Svc.Users.Get(ctx, ident.UserID)
		if uerr == nil && u.Counts(ident) {
			if u.OrgID != org.ID || !u.Enabled(time.Now()) {
				return nil, false, ErrDisabled
			}
			return u, false, nil
		}
		if uerr != nil && !errors.Is(uerr, store.ErrNotFound) {
			return nil, false, uerr
		}
		// The user was deleted, or linked this before the account's sign-in was reset (model.User.CredEpoch): the
		// link counts for nothing and goes, and the sign-in carries on as unlinked. A link the owners still count
		// (this node is behind) is refused for now.
		if freed, err := s.Svc.ReleaseUnique(ctx, model.KindIdentity, model.IdentityKey(p.ID, c.Subject)); err != nil {
			return nil, false, err
		} else if !freed {
			return nil, false, service.ErrUnavailable
		}
	case !errors.Is(err, store.ErrNotFound):
		return nil, false, err
	}

	if p.LinkByEmail {
		u, err := s.linkByEmail(ctx, org, p, c)
		if err != nil || u != nil {
			return u, false, err
		}
	}
	if !p.AutoProvision {
		return nil, false, ErrNotLinked
	}
	email := strings.TrimSpace(c.Email)
	if email == "" || !c.EmailVerified {
		return nil, false, ErrUnverifiedEmail
	}
	if len(p.AllowedDomains) > 0 {
		at := strings.LastIndex(email, "@")
		if at < 0 || !contains(p.AllowedDomains, strings.ToLower(email[at+1:])) {
			return nil, false, ErrDomain
		}
	}
	given, family := c.GivenName, c.FamilyName
	if given == "" {
		// Only a full name (or nothing but a login) is known: the first word is the first name, the rest the last.
		full := strings.TrimSpace(c.Name)
		if full == "" {
			full = c.Username
		}
		if full == "" {
			full, _, _ = strings.Cut(email, "@")
		}
		given, family, _ = strings.Cut(full, " ")
		if family == "" {
			family = c.FamilyName
		}
	}
	verified := true
	in := service.UserInput{Email: &email, Verified: &verified, GivenName: &given}
	if family != "" {
		in.FamilyName = &family
	}
	// The least privileged actor that may create plain users in the org. The account and its link are one transaction
	// (CreateUserLinked): a sign-in that fails part-way leaves neither, and its retry starts again; one whose outcome was
	// not known finds the link it made, if it was made, and signs in through it.
	actor := &service.Actor{OrgID: org.ID, Role: model.RoleManager, Name: "provider:" + p.Name}
	u, err := s.Svc.CreateUserLinked(ctx, actor, org.ID, in, func(u *model.User) *model.Identity {
		return model.NewIdentity(u, p, c.Subject, email, "provision")
	})
	if errors.Is(err, service.ErrConflict) {
		return nil, false, ErrExists
	}
	if err != nil {
		return nil, false, err
	}
	s.Svc.Audit(ctx, actor, org.ID, "user.provision", u.Username, map[string]string{"provider": p.Name})
	return u, true, nil
}

// linkByEmail binds the (provider, subject) identity to the one user whose verified address the provider also
// verified. It returns nil, nil when there is nothing to link (the caller then falls back to auto-provisioning).
func (s *Service) linkByEmail(ctx context.Context, org *model.Org, p *model.Provider, c Claims) (*model.User, error) {
	addrs := slices.Clone(c.VerifiedEmails)
	if c.EmailVerified && c.Email != "" {
		addrs = append(addrs, c.Email)
	}
	if len(p.AllowedDomains) > 0 {
		addrs = slices.DeleteFunc(addrs, func(a string) bool {
			at := strings.LastIndex(a, "@")
			return at < 0 || !contains(p.AllowedDomains, strings.ToLower(a[at+1:]))
		})
	}
	if len(addrs) == 0 {
		return nil, nil
	}
	users, err := s.Svc.UsersByVerifiedEmail(ctx, org.ID, addrs)
	if err != nil {
		return nil, err
	}
	switch len(users) {
	case 0:
		return nil, nil
	case 1:
	default:
		return nil, fmt.Errorf("%w (more than one account matches)", ErrExists)
	}
	u := users[0]
	if !u.Enabled(time.Now()) {
		return nil, ErrDisabled
	}
	if u.Role.Privileged() {
		// Managers and administrators are never linked by email: a provider that an organization administrator
		// set up could otherwise claim any of their addresses and become them. They connect providers themselves,
		// signed in (account page).
		actor := &service.Actor{OrgID: org.ID, Role: model.RoleManager, Name: "provider:" + p.Name}
		s.Svc.Audit(ctx, actor, org.ID, "identity.link.refused", u.Username, map[string]string{"provider": p.Name,
			"reason": "privileged account"})
		return nil, ErrPrivileged
	}
	// A new way into an existing account, as connecting a provider from the account page: what is in flight for the
	// account (sign-in steps, enrolment, links) ends first (the security generation), then the link is made.
	u, err = s.Svc.AdvanceSecurity(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	id := model.NewIdentity(u, p, c.Subject, c.Email, "email")
	if err := s.Svc.Identities.Create(ctx, id); err != nil {
		return nil, err
	}
	actor := &service.Actor{OrgID: org.ID, Role: model.RoleManager, Name: "provider:" + p.Name}
	s.Svc.Audit(ctx, actor, org.ID, "identity.link.email", u.Username, map[string]string{"provider": p.Name, "subject": c.Subject})
	return u, nil
}

// ---------------------------------------------------------------------------------------------------------------
// HTTP helpers

const maxBody = 1 << 20

func (s *Service) do(req *http.Request, v any) error {
	res, err := s.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("%w: %s returned %d", ErrUpstream, req.URL.Host, res.StatusCode)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%w: bad response from %s", ErrUpstream, req.URL.Host)
	}
	return nil
}

func (s *Service) getJSON(ctx context.Context, u string, v any, hdr map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	for k, val := range hdr {
		req.Header.Set(k, val)
	}
	return s.do(req, v)
}

func (s *Service) postForm(ctx context.Context, u string, form url.Values, basic [2]string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basic[0] != "" {
		req.SetBasicAuth(url.QueryEscape(basic[0]), url.QueryEscape(basic[1]))
	}
	return s.do(req, v)
}

// ---------------------------------------------------------------------------------------------------------------
// GitHub

func (s *Service) githubClaims(ctx context.Context, p *model.Provider, secret, code string, st state) (Claims, error) {
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	err := s.postForm(ctx, s.GitHubTokenURL, url.Values{
		"client_id": {p.ClientID}, "client_secret": {secret}, "code": {code}, "redirect_uri": {s.CallbackURL(p.ID)},
		"code_verifier": {st.Verifier},
	}, [2]string{}, &tok)
	if err != nil {
		return Claims{}, err
	}
	if tok.AccessToken == "" || tok.Error != "" {
		return Claims{}, fmt.Errorf("%w: no access token", ErrUpstream)
	}
	hdr := map[string]string{"Authorization": "Bearer " + tok.AccessToken, "Accept": "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28", "User-Agent": "quisora"}
	var user struct {
		ID    json.Number `json:"id"`
		Login string      `json:"login"`
		Name  string      `json:"name"`
	}
	if err := s.getJSON(ctx, s.GitHubAPIURL+"/user", &user, hdr); err != nil {
		return Claims{}, err
	}
	if _, err := strconv.ParseInt(user.ID.String(), 10, 64); err != nil {
		return Claims{}, fmt.Errorf("%w: bad user id", ErrUpstream)
	}
	c := Claims{Subject: user.ID.String(), Name: user.Name, Username: user.Login}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := s.getJSON(ctx, s.GitHubAPIURL+"/user/emails", &emails, hdr); err != nil {
		return Claims{}, err
	}
	for _, e := range emails {
		if e.Verified && e.Email != "" {
			c.VerifiedEmails = append(c.VerifiedEmails, e.Email)
			if e.Primary && !c.EmailVerified {
				c.Email, c.EmailVerified = e.Email, true
			}
		}
	}
	return c, nil
}

// DomainAllowed reports whether a sign-in passes p's allowed email domains: with none, any; otherwise a verified
// address of the provider's must be at one of them.
func DomainAllowed(p *model.Provider, c Claims) bool {
	if len(p.AllowedDomains) == 0 {
		return true
	}
	addrs := slices.Clone(c.VerifiedEmails)
	if c.EmailVerified && c.Email != "" {
		addrs = append(addrs, c.Email)
	}
	for _, a := range addrs {
		if at := strings.LastIndex(a, "@"); at >= 0 && contains(p.AllowedDomains, strings.ToLower(a[at+1:])) {
			return true
		}
	}
	return false
}
