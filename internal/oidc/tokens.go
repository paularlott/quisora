package oidc

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
)

// Authentication context.
//
// amr values (RFC 8176) set by the sign-in module and copied to tokens: "pwd" password, "otp" TOTP code, "hwk"
// hardware-bound passkey, "swk" software/synced passkey, "user" the passkey verified its user, "mfa" two or more
// factors were used. A session satisfies an organization's RequireMFA policy when its amr shows two factors
// (model.MFA). After an upstream provider, the tokens' amr adds what the provider said (model.TokenAMR), which
// decides nothing here.
//
// acr is "urn:quisora:acr:mfa" when that predicate holds of Quisora's own amr and "urn:quisora:acr:basic" otherwise.
const (
	acrMFA   = "urn:quisora:acr:mfa"
	acrBasic = "urn:quisora:acr:basic"
)

// MFASatisfied reports whether amr shows two factors (model.MFA).
func MFASatisfied(amr []string) bool { return model.MFA(amr) }

func acrFor(amr []string) string {
	if MFASatisfied(amr) {
		return acrMFA
	}
	return acrBasic
}

// signAlg is the algorithm for tokens issued to c.
func (p *Provider) signAlg(c *model.Client) string {
	if c.SigningAlg != "" {
		return c.SigningAlg
	}
	return p.cfg.Tokens.SigningAlg
}

// issue describes the tokens to mint.
type issue struct {
	client    *model.Client
	user      *model.User // nil for client_credentials
	org       *model.Org
	scopes    []string
	resources []string
	sid, gid  string
	authTime  time.Time
	amr       []string
	idp       string // type of the upstream provider signed in through (the idp claim; Grant.IdP)
	// upstreamAMR is how that provider said the person signed in (Grant.UpstreamAMR): added to amr in the tokens
	// (model.TokenAMR), never to what acr is decided from (amr, Quisora's own)
	upstreamAMR []string
	// upstream is the account at that provider the person signed in with (Grant.Upstream): the idp scope's claims
	upstream *model.UpstreamAccount
	nonce    string
	tenant   *model.Tenant      // the client's tenant (resolved by mint when nil)
	app      *service.AppAccess // the user's access to the client (decided by mint when nil)
	claimsUI []string           // claims requested individually for userinfo (carried in the access token)
	claimsID []string           // ... and for the ID token
	act      string             // act claim, raw JSON (token exchange)
	expires  time.Time          // the access token expires no later than this (zero: its usual lifetime)
	jkt      string             // DPoP key thumbprint the access token is bound to (cnf.jkt)
	// adTypes are the authorization details types the request asked for (authdetails.go); nil: it asked for none,
	// and the token carries every type the client is registered for.
	adTypes []string
	details []byte // the access token's authorization_details (authDetails), set by mint
}

// accessExpiry is when the access token of is expires.
func (p *Provider) accessExpiry(is *issue, now time.Time) time.Time {
	exp := now.Add(p.cfg.Tokens.Access())
	if !is.expires.IsZero() && is.expires.Before(exp) {
		return is.expires
	}
	return exp
}

func (is *issue) has(scope string) bool { return slices.Contains(is.scopes, scope) }

func newJTI() string { return secure.RandomToken(16) }

func (is *issue) audience() []string {
	return append([]string{is.client.ClientID()}, is.resources...)
}

func (p *Provider) accessToken(ctx context.Context, key *keyEntry, is *issue, now time.Time) (string, error) {
	o := newObj(768)
	o.str("iss", p.issuer(is.client.OrgID))
	if is.user != nil {
		o.str("sub", is.user.ID)
	} else {
		o.str("sub", is.client.ClientID())
	}
	if aud := is.audience(); len(aud) == 1 {
		o.str("aud", aud[0])
	} else {
		o.strs("aud", aud)
	}
	o.str("client_id", is.client.ClientID())
	o.str("scope", joinScope(is.scopes))
	o.num("exp", p.accessExpiry(is, now).Unix())
	o.num("iat", now.Unix())
	o.str("jti", newJTI())
	if is.act != "" {
		o.raw("act", is.act)
	}
	if is.jkt != "" {
		c := newObj(64)
		c.str("jkt", is.jkt)
		o.raw("cnf", string(c.bytes()))
	}
	if is.details != nil {
		o.raw("authorization_details", string(is.details))
	}
	if is.user != nil {
		o.num("auth_time", is.authTime.Unix())
		o.str("acr", acrFor(is.amr))
		o.strs("amr", nonNil(model.TokenAMR(is.amr, is.upstreamAMR)))
		o.strIf("sid", is.sid)
		o.strIf("gid", is.gid)
		if len(is.claimsUI) > 0 {
			o.strs("userinfo_claims", is.claimsUI)
		}
		p.orgClaims(o, is)
		o.str("org_role", string(is.user.Role))
		p.appClaims(ctx, o, is)
		if is.has("groups") {
			o.strs("groups", p.groupNames(ctx, is.user))
		}
		if is.has("enterprise") {
			enterpriseClaim(o, is.user)
		}
		if is.wantsUpstream() {
			upstreamClaims(o, is.idp, is.upstream, nil)
		}
	} else {
		p.orgClaims(o, is)
	}
	return key.sign(typAccess, o.bytes())
}

// appClaims adds "tags" (the user's, their groups' and their access's) and "roles" (the application roles of their
// access to this client).
func (p *Provider) appClaims(ctx context.Context, o *obj, is *issue) {
	if tags := p.userTags(ctx, is.user, is.app); len(tags) > 0 {
		o.strs("tags", tags)
	}
	if is.app != nil && len(is.app.Roles) > 0 {
		o.strs("roles", is.app.Roles)
	}
}

func (p *Provider) orgClaims(o *obj, is *issue) {
	if is.org != nil {
		o.str("org", is.org.ID)
		o.str("org_name", is.org.Name)
	}
	if is.tenant != nil {
		o.str("tenant", is.tenant.ID)
		o.str("tenant_name", is.tenant.Name)
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func joinScope(s []string) string {
	n := len(s)
	for _, v := range s {
		n += len(v)
	}
	b := make([]byte, 0, n)
	for i, v := range s {
		if i > 0 {
			b = append(b, ' ')
		}
		b = append(b, v...)
	}
	return string(b)
}

func (p *Provider) groupNames(ctx context.Context, u *model.User) []string {
	return p.groupInfo(ctx, u).names
}

// userTags is the "tags" claim: the user's own tags, those of their groups and those of their access to the
// application (app may be nil), sorted and deduplicated.
func (p *Provider) userTags(ctx context.Context, u *model.User, app *service.AppAccess) []string {
	var atags []string
	if app != nil {
		atags = app.Tags
	}
	return model.MergeTags(u.Tags, p.groupInfo(ctx, u).tags, atags)
}

// groupInfo returns the ids, names and merged tags of the user's groups from the per-node cache (one store lookup
// serves the claims and the access check). When the groups cannot be read the claims go out without them (logged);
// the access check uses groupsRead instead, which reports the failure: a user allowed through a group would
// otherwise be refused, and told their access was taken away, by a store hiccup.
func (p *Provider) groupInfo(ctx context.Context, u *model.User) groupEntry {
	e, err := p.groupsRead(ctx, u)
	if err != nil {
		p.log.Warn("oidc: loading groups", "user", u.ID, "error", err)
		return groupEntry{names: []string{}}
	}
	return e
}

// groupsRead is groupInfo with the read's failure instead of an empty answer.
func (p *Provider) groupsRead(ctx context.Context, u *model.User) (groupEntry, error) {
	gen := p.membershipGen(u.OrgID)
	if e, ok := p.groups.Get(u.ID); ok && e.gen == gen {
		return e, nil
	}
	gs, err := p.svc.UserGroups(ctx, u)
	if err != nil {
		return groupEntry{}, err
	}
	e := groupEntry{ids: make([]string, 0, len(gs)), names: make([]string, 0, len(gs)), gen: gen}
	var lists [][]string
	for _, g := range gs {
		e.ids = append(e.ids, g.ID)
		e.names = append(e.names, g.DisplayName)
		lists = append(lists, g.Tags)
	}
	slices.Sort(e.names)
	e.tags = model.MergeTags(lists...)
	p.groups.Put(u.ID, e)
	return e, nil
}

// errNoAccess: the user may not use the application (its tenant is members-only and no live access covers it).
var errNoAccess = errors.New("the user has no access to this application")

// appAccess decides a user's access to client c (tenant t, resolved when nil): see service.ClientAccess. An error
// is a read that failed (the tenant, the user's groups or their access entries): no decision, which every caller
// answers as such (503), never as "allowed" nor as "taken away". A tenant that is gone is service.ErrNotFound.
func (p *Provider) appAccess(ctx context.Context, c *model.Client, t *model.Tenant, u *model.User) (*service.AppAccess, error) {
	if t == nil {
		var err error
		if t, err = p.clientTenant(ctx, c); err != nil {
			return nil, err
		}
	}
	groups, err := p.groupsRead(ctx, u)
	if err != nil {
		return nil, err
	}
	return p.svc.ClientAccess(ctx, t, c, u, groups.ids)
}

// idToken mints the OIDC ID token (claims by scope).
func (p *Provider) idToken(ctx context.Context, key *keyEntry, is *issue, now time.Time, accessToken string) (string, error) {
	u := is.user
	o := newObj(768)
	o.str("iss", p.issuer(is.client.OrgID))
	o.str("sub", u.ID)
	o.str("aud", is.client.ClientID())
	o.num("exp", now.Add(p.cfg.Tokens.IDToken()).Unix())
	o.num("iat", now.Unix())
	o.num("auth_time", is.authTime.Unix())
	o.strIf("nonce", is.nonce)
	o.str("acr", acrFor(is.amr))
	o.strs("amr", nonNil(model.TokenAMR(is.amr, is.upstreamAMR)))
	o.strIf("sid", is.sid)
	// The organization, tenant and Quisora role are claims of the "org" scope, the tags and application roles of the
	// "roles" scope (as at userinfo); access tokens always carry them all, for resource servers.
	if is.has("org") {
		p.orgClaims(o, is)
		o.str("org_role", string(u.Role))
	}
	if is.has("roles") {
		p.appClaims(ctx, o, is)
	}
	if accessToken != "" {
		o.str("at_hash", atHash(key.alg, accessToken))
	}
	p.profileClaims(ctx, o, is, u, is.claimsID)
	return key.sign(typJWT, o.bytes())
}

// profileClaims adds the identity claims shared by the ID token and userinfo: those of the scopes, and the claims
// requested one by one (already limited to the client's scopes).
func (p *Provider) profileClaims(ctx context.Context, o *obj, is *issue, u *model.User, requested []string) {
	want := func(claim string) bool { return is.has(claimScopes[claim]) || slices.Contains(requested, claim) }
	if want("name") {
		o.strIf("name", u.FullName())
	}
	if want("preferred_username") {
		o.str("preferred_username", u.Username)
	}
	if want("given_name") {
		o.strIf("given_name", u.GivenName)
	}
	if want("family_name") {
		o.strIf("family_name", u.FamilyName)
	}
	if want("locale") {
		o.strIf("locale", u.Locale)
	}
	if want("zoneinfo") {
		o.strIf("zoneinfo", u.ZoneInfo)
	}
	if want("picture") {
		o.strIf("picture", p.svc.PictureURL(u)) // an image's absolute URL (Core §5.1), of a picture the user has
	}
	if want("updated_at") && !u.Updated.IsZero() {
		o.num("updated_at", u.Updated.Unix())
	}
	if u.Email != "" {
		if want("email") {
			o.str("email", u.Email)
		}
		if want("email_verified") {
			o.boolean("email_verified", u.EmailVerified)
		}
	}
	if u.PhoneNumber != "" {
		if want("phone_number") {
			o.str("phone_number", u.PhoneNumber)
		}
		if want("phone_number_verified") {
			o.boolean("phone_number_verified", u.PhoneVerified)
		}
	}
	if want("groups") {
		o.strs("groups", p.groupNames(ctx, u))
	}
	if want("enterprise") {
		enterpriseClaim(o, u)
	}
	upstreamClaims(o, is.idp, is.upstream, want)
}

// wantsUpstream reports whether the access token of is carries the idp scope's claims: the scope was granted, or one
// of them was requested by name for userinfo, which reads them from the access token.
func (is *issue) wantsUpstream() bool {
	if is.idp == "" && is.upstream == nil {
		return false
	}
	return is.has("idp") || slices.ContainsFunc(is.claimsUI, func(c string) bool { return claimScopes[c] == "idp" })
}

// upstream is the account at the upstream provider the token's idp scope claims name (upstreamClaims); nil for none.
func (c *Claims) upstream() *model.UpstreamAccount {
	if c.IdPSub == "" {
		return nil
	}
	return &model.UpstreamAccount{Subject: c.IdPSub, Tenant: c.IdPTenant, Login: c.IdPLogin}
}

// upstreamClaims adds the idp scope's claims, those want allows (nil: all), after a sign-in through an upstream
// provider of type idp as account a (model.UpstreamAccount; nil when not known): idp the provider's type, idp_sub its
// ID of the account, idp_tenant its Microsoft directory (or the organization, for an organization provider),
// idp_login the name it signs in with. A sign-in of Quisora's own has none of them.
func upstreamClaims(o *obj, idp string, a *model.UpstreamAccount, want func(string) bool) {
	if want == nil || want("idp") {
		o.strIf("idp", idp)
	}
	if a == nil {
		return
	}
	if want == nil || want("idp_sub") {
		o.str("idp_sub", a.Subject)
	}
	if want == nil || want("idp_tenant") {
		o.strIf("idp_tenant", a.Tenant)
	}
	if want == nil || want("idp_login") {
		o.strIf("idp_login", a.Login)
	}
}

// allowedClaims keeps the requested claims whose scope the client may still use.
func allowedClaims(names, clientScopes []string) []string {
	var out []string
	for _, n := range names {
		if slices.Contains(clientScopes, claimScopes[n]) {
			out = append(out, n)
		}
	}
	return out
}

// enterpriseClaim adds the "enterprise" claim of the enterprise scope: the user's work details (the SCIM enterprise
// extension), user type and end date, as one object so the names cannot clash with other claims. Empty values are
// left out; with nothing set the claim is absent.
func enterpriseClaim(o *obj, u *model.User) {
	e := newObj(256)
	w := u.Work
	for _, f := range [][2]string{{"title", w.Title}, {"department", w.Department}, {"organization", w.Organization},
		{"division", w.Division}, {"cost_center", w.CostCenter}, {"employee_number", w.EmployeeNumber},
		{"manager", w.ManagerID}, {"user_type", u.UserType}} {
		e.strIf(f[0], f[1])
	}
	if u.ValidUntil != nil {
		e.num("valid_until", u.ValidUntil.Unix())
	}
	if b := e.bytes(); len(b) > 2 {
		o.raw("enterprise", string(b))
	}
}

// tokenResponse is the body of a successful token endpoint response.
type tokenResponse struct {
	access, refresh, id string
	expiresIn           int
	scopes              []string
	issuedType          string // issued_token_type (token exchange)
	dpop                bool   // token_type DPoP: the access token is bound to a key
	// details is the authorization_details issued (RFC 9396 §7): a JSON array, nil to leave it out
	details []byte
}

func writeTokens(w http.ResponseWriter, t *tokenResponse) {
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	b := make([]byte, 0, len(t.access)+len(t.refresh)+len(t.id)+160)
	b = append(b, `{"access_token":"`...)
	b = append(b, t.access...)
	if t.dpop {
		b = append(b, `","token_type":"DPoP","expires_in":`...)
	} else {
		b = append(b, `","token_type":"Bearer","expires_in":`...)
	}
	b = strconv.AppendInt(b, int64(t.expiresIn), 10)
	b = append(b, `,"scope":`...)
	b = appendJSONString(b, joinScope(t.scopes))
	if t.issuedType != "" {
		b = append(b, `,"issued_token_type":`...)
		b = appendJSONString(b, t.issuedType)
	}
	if t.details != nil {
		b = append(b, `,"authorization_details":`...)
		b = append(b, t.details...)
	}
	if t.refresh != "" {
		b = append(b, `,"refresh_token":"`...)
		b = append(b, t.refresh...)
		b = append(b, '"')
	}
	if t.id != "" {
		b = append(b, `,"id_token":"`...)
		b = append(b, t.id...)
		b = append(b, '"')
	}
	b = append(b, '}')
	_, _ = w.Write(b)
}

// mint signs the access token and, when the scopes include openid for a user, the ID token.
func (p *Provider) mint(ctx context.Context, is *issue, withID bool) (*tokenResponse, error) {
	key, err := p.signingKey(ctx, p.signAlg(is.client))
	if err != nil {
		return nil, err
	}
	if is.tenant == nil && is.client != nil {
		if t, err := p.clientTenant(ctx, is.client); err == nil {
			is.tenant = t
		}
	}
	if is.user != nil && is.app == nil {
		if is.tenant == nil {
			return nil, errNoAccess // a client without a tenant serves nobody
		}
		app, err := p.svc.ClientAccess(ctx, is.tenant, is.client, is.user, p.groupInfo(ctx, is.user).ids)
		if err != nil {
			return nil, err
		}
		if !app.Allowed {
			return nil, errNoAccess
		}
		is.app = app
	}
	is.details = p.authDetails(is)
	now := time.Now()
	at, err := p.accessToken(ctx, key, is, now)
	if err != nil {
		return nil, err
	}
	tr := &tokenResponse{access: at, expiresIn: int(p.accessExpiry(is, now).Sub(now) / time.Second), scopes: is.scopes,
		dpop: is.jkt != "", details: is.details}
	if tr.details == nil && is.adTypes != nil {
		tr.details = []byte("[]") // asked for, none granted
	}
	if withID && is.user != nil && is.has("openid") {
		if tr.id, err = p.idToken(ctx, key, is, now, at); err != nil {
			return nil, err
		}
	}
	return tr, nil
}
