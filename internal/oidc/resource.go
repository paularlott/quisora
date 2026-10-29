package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func isAccessTokenTyp(typ string) bool {
	t := strings.ToLower(typ)
	return t == "at+jwt" || t == "application/at+jwt"
}

// verifyAccessToken validates an access token issued by this provider, for any of its organizations (the issuer says
// which: verifyIn requires one): signature (kid lookup, algorithm bound to the key), RFC 9068 typ, issuer, expiry, and
// that the subject is still allowed (user active, refresh grant not
// revoked and not ended by an emergency sign-out, client enabled). SCIM and other resource servers in this process
// call it directly.
//
// It does not check the audience (aud): which token a caller may accept is the caller's decision, and each one
// makes it. Userinfo takes any user token with the openid scope (OIDC: the token is the client's, not userinfo's);
// introspection answers only for an audience or an introspect_org client; revocation only for the client the token
// was issued to; SCIM only for client_credentials tokens with the scim scope from a provisioning client. A new caller
// must check aud (or the client) itself. Nor does it decide the user's access to the application (a members-only
// tenant, a self-registered application's resource): tokenAccess does, for userinfo and introspection alike.
//
// An error that is service.ErrUnavailable means a read the verdict depends on failed (the client, the user, the
// grant or the sign-out counters): the token is neither good nor bad, and the caller answers 503, never 401 (which
// would make the client discard a token that may be good) and never as verified. Every other error is a refusal.
func (p *Provider) verifyAccessToken(ctx context.Context, tok string) (*Claims, error) {
	now := time.Now()
	k := tokenKey(tok)
	cl, kid, alg, cached := p.verified.get(k, now)
	if cached {
		// Verified before: only that its key is still published needs checking again (a retired key's tokens stop).
		if key := p.keyByKID(ctx, kid); key == nil || key.alg != alg {
			return nil, badToken("unknown key")
		}
	} else {
		pj, err := ParseJWT(tok)
		if err != nil {
			return nil, err
		}
		if !isAccessTokenTyp(pj.Header.Typ) {
			return nil, badToken("not an access token")
		}
		key := p.keyByKID(ctx, pj.Header.Kid)
		if key == nil || key.alg != pj.Header.Alg {
			return nil, badToken("unknown key")
		}
		if err := pj.Verify(key.pub); err != nil {
			return nil, err
		}
		cl = &Claims{}
		if err := json.Unmarshal(pj.Payload, cl); err != nil {
			return nil, badToken("claims")
		}
		if _, ok := p.issuerOrg(cl.Iss); ok && cl.Exp != 0 && now.Before(time.Unix(int64(cl.Exp), 0)) {
			p.verified.put(k, pj.Header.Kid, pj.Header.Alg, cl, time.Unix(int64(cl.Exp), 0), now)
		}
	}
	orgID, ok := p.issuerOrg(cl.Iss)
	if !ok || cl.Exp == 0 || now.After(time.Unix(int64(cl.Exp), 0)) ||
		cl.Nbf != 0 && time.Unix(int64(cl.Nbf), 0).After(now.Add(leeway)) ||
		cl.Iat != 0 && time.Unix(int64(cl.Iat), 0).After(now.Add(leeway)) || cl.Sub == "" || cl.ClientID == "" {
		return nil, badToken("claims")
	}
	ce, err := p.client(ctx, orgID, cl.ClientID)
	if err != nil && !gone(err) {
		return nil, unavailable(err)
	}
	if err != nil || !ce.c.Enabled {
		return nil, badToken("client disabled") // a disabled or deleted application's tokens stop working at once
	}
	if cl.Sub == cl.ClientID { // client_credentials token: the client is the subject, and there is no grant
		return cl, nil
	}
	u, err := p.user(ctx, cl.Sub)
	if err != nil && !gone(err) {
		return nil, unavailable(err)
	}
	if err != nil || u.OrgID != orgID {
		return nil, badToken("user inactive")
	}
	if ok, err := p.svc.UserUsable(ctx, u); err != nil {
		return nil, unavailable(err)
	} else if !ok { // disabled, or its organization deleted
		return nil, badToken("user inactive")
	}
	if cl.GID != "" {
		alive, err := p.grantAlive(ctx, cl.GID, u)
		if err != nil {
			return nil, err
		}
		if !alive {
			return nil, badToken("session ended")
		}
	}
	return cl, nil
}

// verifyIn is verifyAccessToken for a token that must be organization orgID's: one issued by another organization is
// no token here, whoever presents it (clients of two organizations may have the same client_id, a metadata document's
// URL, and users the same names).
func (p *Provider) verifyIn(ctx context.Context, orgID, tok string) (*Claims, error) {
	cl, err := p.verifyAccessToken(ctx, tok)
	if err != nil {
		return nil, err
	}
	if cl.Iss != p.issuer(orgID) {
		return nil, badToken("another organization's token")
	}
	return cl, nil
}

// tokenAccess decides whether the user of access token cl may still use the application it was issued to, as a
// sign-in to it now would: the resource still accepts the application (a self-registered one, placed in the
// tenant that owns the resources in aud) and the user still has access to it in its tenant (members-only). Userinfo
// and introspection make the decision here, so a token one refuses the other reports inactive, and a token
// exchange, a refresh and the token endpoint's grants make the same one through appAccess. ok is false when the
// user may not (access taken away or expired, the client gone, the resource closed); app is their access when they
// may. An error is a read that failed: no decision, which the caller answers as 503 and never as either verdict.
func (p *Provider) tokenAccess(ctx context.Context, cl *Claims, u *model.User) (app *service.AppAccess, ok bool, err error) {
	orgID, _ := p.issuerOrg(cl.Iss) // verified: the token's issuer is an organization's
	ce, err := p.client(ctx, orgID, cl.ClientID)
	if err != nil {
		if gone(err) {
			return nil, false, nil
		}
		return nil, false, unavailable(err)
	}
	c, _, err := p.forResources(ctx, ce.c, slices.DeleteFunc(slices.Clone([]string(cl.Aud)), func(a string) bool { return a == cl.ClientID }))
	if err != nil {
		if gone(err) {
			return nil, false, nil // the resource no longer accepts the application
		}
		return nil, false, unavailable(err)
	}
	app, err = p.appAccess(ctx, c, nil, u)
	if err != nil {
		if gone(err) {
			return nil, false, nil // the client's tenant is gone
		}
		return nil, false, unavailable(err)
	}
	return app, app.Allowed, nil
}

// ---------------------------------------------------------------------------------------------------------------
// userinfo

// bearer returns the request's access token (RFC 6750 §2.1 header or §2.2 form body, or the DPoP scheme of RFC 9449
// §7.1) and its scheme ("Bearer" or "DPoP"). ok is false when the client used more than one method, which §2 forbids.
func bearer(r *http.Request) (tok, scheme string, ok bool) {
	var form string
	if r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		r.Body = http.MaxBytesReader(nil, r.Body, 64<<10)
		if r.ParseForm() == nil {
			if len(r.PostForm["access_token"]) > 1 {
				return "", "", false
			}
			form = r.PostForm.Get("access_token")
		}
	}
	if r.URL.Query().Has("access_token") { // §2.3 query tokens leak into logs and history; not supported
		return "", "", false
	}
	if h := r.Header.Get("Authorization"); h != "" {
		if form != "" {
			return "", "", false
		}
		scheme, t, _ := strings.Cut(h, " ")
		switch {
		case strings.EqualFold(scheme, "Bearer"):
			return strings.TrimSpace(t), "Bearer", true
		case strings.EqualFold(scheme, "DPoP"):
			return strings.TrimSpace(t), "DPoP", true
		}
		return "", "", true
	}
	return form, "Bearer", true
}

func bearerError(w http.ResponseWriter, status int, code string) {
	setNoStore(w)
	h := `Bearer realm="quisora"`
	if code != "" {
		h += `, error="` + code + `"`
	}
	w.Header().Set("WWW-Authenticate", h)
	w.WriteHeader(status)
}

// bearerUnavailable answers a bearer request whose authorization could not be decided because a read failed: 503
// with Retry-After and the token endpoint's error body (temporarily_unavailable), and no WWW-Authenticate challenge,
// since the token is not known to be bad (RFC 6750 §3 has no code for "not now", and a client given invalid_token
// discards the token and signs the user in again). The profile is never released on an undecided authorization.
func bearerUnavailable(w http.ResponseWriter, err error) {
	writeOAuthError(w, serverError(unavailable(err)))
}

func (p *Provider) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	p.corsActual(w, r)
	tok, scheme, ok := bearer(r)
	if !ok {
		bearerError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if tok == "" {
		bearerError(w, http.StatusUnauthorized, "")
		return
	}
	cl, err := p.VerifyRequestToken(r, scheme, tok)
	switch {
	case errors.Is(err, ErrDPoPProof):
		p.dpopChallenge(w, http.StatusUnauthorized, "invalid_dpop_proof")
		return
	case service.IsUnavailable(err):
		bearerUnavailable(w, err) // the token could not be checked: not refused, not served
		return
	case err != nil && scheme == "DPoP":
		p.dpopChallenge(w, http.StatusUnauthorized, "invalid_token")
		return
	case err != nil || cl.Sub == cl.ClientID:
		bearerError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	p.corsRestrict(w, r, cl.ClientID)
	if !cl.HasScope("openid") {
		bearerError(w, http.StatusForbidden, "insufficient_scope")
		return
	}
	u, err := p.user(r.Context(), cl.Sub)
	if err != nil {
		if !gone(err) {
			bearerUnavailable(w, err)
			return
		}
		bearerError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	// The user's access to the application, as it is now (tokenAccess: the same decision introspection makes). An
	// access that cannot be read is not released on: the profile waits for the decision (503), it is not served
	// because the check could not be made.
	app, ok, err := p.tokenAccess(r.Context(), cl, u)
	if err != nil {
		bearerUnavailable(w, err)
		return
	}
	if !ok {
		bearerError(w, http.StatusUnauthorized, "invalid_token") // access taken away since the token was issued
		return
	}
	is := &issue{scopes: cl.Scopes()}
	o := newObj(384)
	o.str("sub", u.ID)
	p.profileClaims(r.Context(), o, is, u, cl.UserinfoClaims)
	if is.has("org") {
		if org, err := p.svc.Org(r.Context(), u.OrgID); err == nil {
			o.str("org", org.ID)
			o.str("org_name", org.Name)
		}
		o.strIf("tenant", cl.Tenant)
		o.strIf("tenant_name", cl.TenantName)
		o.str("role", string(u.Role))
		if tags := p.userTags(r.Context(), u, app); len(tags) > 0 {
			o.strs("tags", tags)
		}
		if app != nil && len(app.Roles) > 0 {
			o.strs("roles", app.Roles)
		}
	}
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(o.bytes())
}

// ---------------------------------------------------------------------------------------------------------------
// introspection (RFC 7662)

func (p *Provider) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, oerr("invalid_request", "the request body could not be read"))
		return
	}
	ce, e := p.authenticateClient(r, false)
	if e != nil {
		writeOAuthError(w, e)
		return
	}
	tok := r.PostForm.Get("token")
	if tok == "" {
		writeOAuthError(w, oerr("invalid_request", "token is required"))
		return
	}
	body, oe := p.introspect(r.Context(), ce.c, tok)
	if oe != nil {
		writeOAuthError(w, oe)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(body)
}

var inactive = []byte(`{"active":false}`)

// introspect answers for a token of any of the three kinds. "active": false is a verdict: the token is not one the
// caller may see, or it has ended. A read the verdict needs that failed is no verdict, and is answered as 503
// (temporarily_unavailable) instead: a resource server told "inactive" would refuse the user, who would then be
// signed in again for a store hiccup, and told "active" it would serve a token that may have been revoked.
func (p *Provider) introspect(ctx context.Context, caller *model.Client, tok string) ([]byte, *oauthError) {
	var body []byte
	var err error
	switch {
	case service.IsAPIToken(tok):
		body, err = p.introspectAPIToken(ctx, caller, tok)
	case strings.HasPrefix(tok, "ey") && strings.Count(tok, ".") == 2:
		body, err = p.introspectJWT(ctx, caller, tok)
	default:
		body, err = p.introspectRefresh(ctx, caller, tok)
	}
	if err != nil {
		return nil, serverError(unavailable(err))
	}
	return body, nil
}

// introspectAPIToken answers for a personal API token made for the user's own applications (the api scope), and
// only to a caller in the owner's organization that accepts api tokens (Client.AcceptsAPITokens) and is in the token's
// audience (when it has one). A token holding only Quisora's own scopes (scim, admin, backup) is no business of an
// application: it is inactive to every caller, as is one whose owner the organization no longer lets use api tokens
// (ValidateAPIToken) and anything else that does not qualify, so introspection is no oracle across organizations or
// applications.
//
// The caller is the application the token is used with, so the answer carries what a sign-in to it would: the
// user's application roles for it and their access's tags (their own entry and their groups', in its tenant). A user
// without access to a members-only tenant's application could not sign in to it, so the token is inactive there too.
func (p *Provider) introspectAPIToken(ctx context.Context, caller *model.Client, tok string) ([]byte, error) {
	t, u, err := p.svc.ValidateAPIToken(ctx, tok)
	if errors.Is(err, service.ErrUnavailable) {
		return nil, err
	}
	if err != nil || u.OrgID != caller.OrgID || !caller.AcceptsAPITokens || !slices.Contains(t.Scopes, service.ScopeAPI) ||
		(len(t.Audience) > 0 && !slices.Contains(t.Audience, caller.ClientID())) {
		return inactive, nil
	}
	app, err := p.appAccess(ctx, caller, nil, u)
	if err != nil && !gone(err) {
		return nil, err
	}
	if err != nil || !app.Allowed {
		return inactive, nil
	}
	// A token narrowed to application scopes reports those of the caller's; one narrowed to none of the caller's is
	// not for it (else "api" alone, which means full access, would be all it saw).
	scope := service.ScopeAPI
	if len(t.AppScopes) > 0 {
		own := service.AppScopesOf(caller)
		var mine []string
		for _, sc := range t.AppScopes {
			if slices.Contains(own, sc) {
				mine = append(mine, sc)
			}
		}
		if len(mine) == 0 {
			return inactive, nil
		}
		scope += " " + strings.Join(mine, " ")
	}
	o := newObj(256)
	o.boolean("active", true)
	o.str("token_type", "Bearer")
	o.str("token_kind", "api_token") // Quisora's own field: which kind of credential this is
	o.str("sub", u.ID)
	o.str("username", u.Username)
	o.str("scope", scope) // api, and the application scopes it is narrowed to (none: full access)
	if len(t.Audience) == 1 {
		o.str("aud", t.Audience[0])
	} else if len(t.Audience) > 1 {
		o.strs("aud", t.Audience)
	}
	o.str("org", u.OrgID)
	if org, err := p.svc.Org(ctx, u.OrgID); err == nil {
		o.str("org_name", org.Name)
	}
	o.str("role", string(u.Role))
	if tags := p.userTags(ctx, u, app); len(tags) > 0 {
		o.strs("tags", tags)
	}
	if len(app.Roles) > 0 {
		o.strs("roles", app.Roles)
	}
	if !t.Expires.IsZero() {
		o.num("exp", t.Expires.Unix())
	}
	o.num("iat", t.Created.Unix())
	return o.bytes(), nil
}

// introspectJWT answers for an access token only if the caller is an audience of it, or is allowed to introspect
// every token of the token's organization (introspect_org).
func (p *Provider) introspectJWT(ctx context.Context, caller *model.Client, tok string) ([]byte, error) {
	cl, err := p.verifyIn(ctx, caller.OrgID, tok)
	if err != nil {
		if errors.Is(err, service.ErrUnavailable) {
			return nil, err
		}
		return inactive, nil
	}
	// Active for the client the token was issued to (its id is in aud), or for a client allowed to introspect every
	// token of its organization (introspect_org). The RFC 8707 resources a token names are in aud as URIs, not client
	// ids: a resource server that introspects tokens issued to other clients needs introspect_org.
	if !slices.Contains(cl.Aud, caller.ClientID()) && !(caller.IntrospectOrg && cl.Org == caller.OrgID) {
		return inactive, nil
	}
	// A service account's token holds Quisora's own scopes (the management API, SCIM), as an API token with them
	// does: no business of an application, introspect_org or not, whose own scopes may share their names.
	if cl.Sub == cl.ClientID && cl.ClientID != caller.ClientID() {
		ce, err := p.client(ctx, caller.OrgID, cl.ClientID)
		if err != nil {
			if gone(err) {
				return inactive, nil
			}
			return nil, unavailable(err)
		}
		if ce.c.ServiceAccount {
			return inactive, nil
		}
	}
	// A user's token is active only while the user may still use the application (tokenAccess, as userinfo decides
	// it): access to a members-only tenant's application taken away, or a self-registered application's resource
	// closed to it, ends it here at once, not when it expires. A client_credentials token has no user to decide for.
	if cl.Sub != cl.ClientID {
		u, err := p.user(ctx, cl.Sub)
		if err != nil {
			if gone(err) {
				return inactive, nil
			}
			return nil, unavailable(err)
		}
		if _, ok, err := p.tokenAccess(ctx, cl, u); err != nil {
			return nil, err
		} else if !ok {
			return inactive, nil
		}
	}
	o := newObj(512)
	o.boolean("active", true)
	if cl.Cnf != nil && cl.Cnf.JKT != "" {
		o.str("token_type", "DPoP") // RFC 9449 §6.2
		c := newObj(64)
		c.str("jkt", cl.Cnf.JKT)
		o.raw("cnf", string(c.bytes()))
	} else {
		o.str("token_type", "Bearer")
	}
	o.str("token_kind", "access_token")
	o.str("iss", cl.Iss)
	o.str("sub", cl.Sub)
	if len(cl.Aud) == 1 {
		o.str("aud", cl.Aud[0])
	} else {
		o.strs("aud", cl.Aud)
	}
	o.str("client_id", cl.ClientID)
	o.str("scope", cl.Scope)
	o.num("exp", int64(cl.Exp))
	o.num("iat", int64(cl.Iat))
	o.strIf("jti", cl.Jti)
	if len(cl.Act) > 0 { // signed by this server: embedded as it is
		o.raw("act", string(cl.Act))
	}
	o.strIf("org", cl.Org)
	o.strIf("org_name", cl.OrgName)
	o.strIf("tenant", cl.Tenant)
	o.strIf("tenant_name", cl.TenantName)
	if cl.Sub != cl.ClientID {
		if u, err := p.user(ctx, cl.Sub); err == nil {
			o.str("username", u.Username)
		}
		o.num("auth_time", int64(cl.AuthTime))
		o.strIf("acr", cl.ACR)
		o.strs("amr", nonNil(cl.AMR))
		o.strIf("sid", cl.SID)
		o.strIf("role", cl.Role)
		if cl.Groups != nil {
			o.strs("groups", cl.Groups)
		}
		if len(cl.Tags) > 0 {
			o.strs("tags", cl.Tags)
		}
		if len(cl.Roles) > 0 {
			o.strs("roles", cl.Roles)
		}
	}
	return o.bytes(), nil
}

// introspectRefresh answers for a refresh token; only the client the token was issued to may ask.
func (p *Provider) introspectRefresh(ctx context.Context, caller *model.Client, tok string) ([]byte, error) {
	g, current, err := p.readRefresh(ctx, caller, tok)
	if err != nil {
		return nil, err
	}
	if g == nil || !current {
		return inactive, nil
	}
	u, live, err := p.grantLive(ctx, g)
	if err != nil {
		return nil, err
	} else if !live {
		return inactive, nil
	}
	app, err := p.appAccess(ctx, caller, nil, u)
	if err != nil && !gone(err) {
		return nil, unavailable(err)
	}
	if err != nil || !app.Allowed {
		return inactive, nil
	}
	o := newObj(256)
	o.boolean("active", true)
	// RFC 7662 token_type names how the token is presented (RFC 6749 §7.1); a refresh token is never presented
	// to a resource, so it has none.
	o.str("token_kind", "refresh_token")
	o.str("client_id", caller.ClientID())
	o.str("sub", g.UserID)
	o.str("username", u.Username)
	o.str("scope", joinScope(g.Scopes))
	o.num("exp", g.Expires.Unix())
	o.num("iat", g.Created.Unix())
	o.strIf("sid", g.SessionID)
	o.str("org", g.OrgID)
	if tags := p.userTags(ctx, u, app); len(tags) > 0 {
		o.strs("tags", tags)
	}
	if len(app.Roles) > 0 {
		o.strs("roles", app.Roles)
	}
	return o.bytes(), nil
}

// readRefresh loads and authenticates a refresh token's grant without changing anything. The grant is nil for a token
// that is not an authentic one of the caller's live grant; current says whether it is also the grant's current token
// (not one an earlier rotation replaced, which still proves that the caller was once given the grant). An error means
// the grant could not be read, which is neither.
func (p *Provider) readRefresh(ctx context.Context, caller *model.Client, tok string) (g *model.Grant, current bool, err error) {
	pr, ok := parseRefresh(tok)
	if !ok {
		return nil, false, nil
	}
	g, err = p.svc.Grants.GetIn(ctx, caller.OrgID, pr.gid) // in the caller's organization's partition, as refresh reads it
	if err != nil && !gone(err) {
		return nil, false, unavailable(err)
	}
	if err != nil || g.ClientID != caller.ID || time.Now().After(g.Expires) || !p.authentic(pr, g) {
		return nil, false, nil
	}
	superseded := pr.counted && pr.counter != g.Counter || !pr.counted && g.Counter != 0
	return g, !superseded, nil
}

// ---------------------------------------------------------------------------------------------------------------
// revocation (RFC 7009)

func (p *Provider) handleRevoke(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	p.corsActual(w, r)
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, oerr("invalid_request", "the request body could not be read"))
		return
	}
	ce, e := p.authenticateClient(r, true)
	if e != nil {
		writeOAuthError(w, e)
		return
	}
	p.corsRestrict(w, r, ce.c.ClientID())
	tok := r.PostForm.Get("token")
	if tok == "" {
		writeOAuthError(w, oerr("invalid_request", "token is required"))
		return
	}
	ctx := r.Context()
	switch {
	case service.IsAPIToken(tok):
		// Personal API tokens belong to their owner; they are revoked from the account page, not here. Say so
		// (RFC 7009 §2.2.1) rather than answer 200, which a client would take to mean the token is dead.
		writeOAuthError(w, oerr("unsupported_token_type", "personal API tokens are revoked from the account page"))
		return
	case strings.HasPrefix(tok, "ey") && strings.Count(tok, ".") == 2:
		// A JWT cannot be recalled, but revoking one of this client's user tokens ends the grant it came from,
		// which stops refreshing and makes introspection report it inactive. A token from a token exchange carries
		// the grant of the application the user signed in to: its holder (acting for the user) cannot end that.
		cl, err := p.verifyIn(ctx, ce.c.OrgID, tok)
		if errors.Is(err, service.ErrUnavailable) {
			writeOAuthError(w, serverError(err)) // whether there is a grant to end could not be read
			return
		}
		if err == nil && cl.ClientID == ce.c.ClientID() && cl.GID == "" && len(cl.Act) == 0 {
			// A client credentials token has no grant to end, and a JWT cannot be recalled: say so (RFC 7009
			// §2.2.1) rather than answer 200, which the client would take to mean the token is dead.
			writeOAuthError(w, oerr("unsupported_token_type", "a client credentials token cannot be revoked: it lasts until it expires"))
			return
		}
		if err == nil && cl.ClientID == ce.c.ClientID() && cl.GID != "" && len(cl.Act) == 0 {
			// RFC 7009 §2.2.1: the client retries; nothing is audited as done (a revocation of unknown outcome, as such)
			if err := p.auditedClient(ctx, ce.c, p.svc.AuditTargetUser(ctx, ce.c.OrgID, cl.Sub), "oauth.revoke", map[string]string{"grant": cl.GID, "token": "access"},
				func() error { return p.revokeGrant(ctx, cl.GID) }); err != nil {
				writeOAuthError(w, serverError(err))
				return
			}
		}
	default:
		// A token an earlier rotation replaced revokes the grant too: whoever holds the current token (an attacker
		// who rotated a stolen one, say) must not outlive the revocation the client made with the token it kept
		// (RFC 9700 §4.14: the token family ends, as when the token endpoint is shown an old token).
		g, current, err := p.readRefresh(ctx, ce.c, tok)
		if err != nil {
			writeOAuthError(w, serverError(err))
			return
		}
		if g != nil {
			detail := map[string]string{"grant": g.ID, "user_id": g.UserID, "token": "refresh"}
			if !current {
				detail["superseded"] = "true"
			}
			if err := p.auditedClient(ctx, ce.c, p.svc.AuditTargetUser(ctx, ce.c.OrgID, g.UserID), "oauth.revoke", detail,
				func() error { return p.revokeGrant(ctx, g.ID) }); err != nil {
				writeOAuthError(w, serverError(err))
				return
			}
		}
	}
	// 200 for a token that was revoked here, and for one there was nothing to revoke for (unknown, expired, another
	// client's: RFC 7009 §2.2): either way the client's token is dead. A revocation that could not be made is
	// answered above, never here.
	w.WriteHeader(http.StatusOK)
}
