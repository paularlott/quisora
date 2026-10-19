package oidc

import (
	"context"
	"encoding/json"
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

// VerifyAccessToken validates an access token issued by this provider: signature (kid lookup, algorithm bound to
// the key), RFC 9068 typ, issuer, expiry, and that the subject is still allowed (user active, refresh grant not
// revoked, client enabled). SCIM and other resource servers in this process call it directly.
//
// It does not check the audience (aud): which token a caller may accept is the caller's decision, and each one
// makes it. Userinfo takes any user token with the openid scope (OIDC: the token is the client's, not userinfo's);
// introspection answers only for an audience or an introspect_org client; revocation only for the client the token
// was issued to; SCIM only for client_credentials tokens with the scim scope from a provisioning client. A new caller
// must check aud (or the client) itself.
func (p *Provider) VerifyAccessToken(ctx context.Context, tok string) (*Claims, error) {
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
		if cl.Iss == p.issuer && cl.Exp != 0 && now.Before(time.Unix(int64(cl.Exp), 0)) {
			p.verified.put(k, pj.Header.Kid, pj.Header.Alg, cl, time.Unix(int64(cl.Exp), 0), now)
		}
	}
	if cl.Iss != p.issuer || cl.Exp == 0 || now.After(time.Unix(int64(cl.Exp), 0)) ||
		cl.Nbf != 0 && time.Unix(int64(cl.Nbf), 0).After(now.Add(leeway)) ||
		cl.Iat != 0 && time.Unix(int64(cl.Iat), 0).After(now.Add(leeway)) || cl.Sub == "" || cl.ClientID == "" {
		return nil, badToken("claims")
	}
	if cl.Sub == cl.ClientID { // client_credentials token
		ce, err := p.client(ctx, cl.ClientID)
		if err != nil || !ce.c.Enabled {
			return nil, badToken("client disabled")
		}
		return cl, nil
	}
	if ce, err := p.client(ctx, cl.ClientID); err != nil || !ce.c.Enabled {
		return nil, badToken("client disabled") // a disabled or deleted application's tokens stop working at once
	}
	u, err := p.user(ctx, cl.Sub)
	if err != nil || !u.Enabled(time.Now()) {
		return nil, badToken("user inactive")
	}
	if cl.GID != "" && !p.grantAlive(ctx, cl.GID) {
		return nil, badToken("session ended")
	}
	return cl, nil
}

// ---------------------------------------------------------------------------------------------------------------
// userinfo

// bearer returns the request's access token (RFC 6750 §2.1 header or §2.2 form body). ok is false when the client
// used more than one method, which §2 forbids.
func bearer(r *http.Request) (tok string, ok bool) {
	var form string
	if r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		r.Body = http.MaxBytesReader(nil, r.Body, 64<<10)
		if r.ParseForm() == nil {
			if len(r.PostForm["access_token"]) > 1 {
				return "", false
			}
			form = r.PostForm.Get("access_token")
		}
	}
	if r.URL.Query().Has("access_token") { // §2.3 query tokens leak into logs and history; not supported
		return "", false
	}
	if h := r.Header.Get("Authorization"); h != "" {
		if form != "" {
			return "", false
		}
		scheme, t, _ := strings.Cut(h, " ")
		if strings.EqualFold(scheme, "Bearer") {
			return strings.TrimSpace(t), true
		}
		return "", true
	}
	return form, true
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

func (p *Provider) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	p.corsActual(w, r)
	tok, ok := bearer(r)
	if !ok {
		bearerError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if tok == "" {
		bearerError(w, http.StatusUnauthorized, "")
		return
	}
	cl, err := p.VerifyAccessToken(r.Context(), tok)
	if err != nil || cl.Sub == cl.ClientID {
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
		bearerError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	var app *service.AppAccess
	if ce, err := p.client(r.Context(), cl.ClientID); err == nil {
		if app, err = p.appAccess(r.Context(), ce.c, nil, u); err == nil && !app.Allowed {
			bearerError(w, http.StatusUnauthorized, "invalid_token") // access taken away since the token was issued
			return
		}
	}
	is := &issue{scopes: cl.Scopes()}
	o := newObj(384)
	o.str("sub", u.ID)
	p.profileClaims(r.Context(), o, is, u, cl.UserinfoClaims)
	if is.has("org") {
		if org, err := p.org(r.Context(), u.OrgID); err == nil {
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
	body := p.introspect(r.Context(), ce.c, tok)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(body)
}

var inactive = []byte(`{"active":false}`)

func (p *Provider) introspect(ctx context.Context, caller *model.Client, tok string) []byte {
	switch {
	case service.IsAPIToken(tok):
		return p.introspectAPIToken(ctx, caller, tok)
	case strings.HasPrefix(tok, "ey") && strings.Count(tok, ".") == 2:
		return p.introspectJWT(ctx, caller, tok)
	}
	return p.introspectRefresh(ctx, caller, tok)
}

// introspectAPIToken answers for a personal API token made for the user's own applications (the api scope), and
// only to a caller in the owner's organization that is in the token's audience (when it has one). A token holding
// only Quisora's own scopes (scim, admin, backup) is no business of an application: it is inactive to every caller, as
// is anything else that does not qualify, so introspection is no oracle across organizations or applications.
func (p *Provider) introspectAPIToken(ctx context.Context, caller *model.Client, tok string) []byte {
	t, u, err := p.svc.ValidateAPIToken(ctx, tok)
	if err != nil || u.OrgID != caller.OrgID || !slices.Contains(t.Scopes, service.ScopeAPI) ||
		(len(t.Audience) > 0 && !slices.Contains(t.Audience, caller.ID)) {
		return inactive
	}
	o := newObj(256)
	o.boolean("active", true)
	o.str("token_type", "Bearer")
	o.str("token_kind", "api_token") // Quisora's own field: which kind of credential this is
	o.str("sub", u.ID)
	o.str("username", u.Username)
	o.str("scope", service.ScopeAPI) // only the scope applications act on, whatever else a token was given
	if len(t.Audience) == 1 {
		o.str("aud", t.Audience[0])
	} else if len(t.Audience) > 1 {
		o.strs("aud", t.Audience)
	}
	o.str("org", u.OrgID)
	if org, err := p.org(ctx, u.OrgID); err == nil {
		o.str("org_name", org.Name)
	}
	o.str("role", string(u.Role))
	if tags := p.userTags(ctx, u, nil); len(tags) > 0 { // personal API tokens are not tied to an application
		o.strs("tags", tags)
	}
	if !t.Expires.IsZero() {
		o.num("exp", t.Expires.Unix())
	}
	o.num("iat", t.Created.Unix())
	return o.bytes()
}

// introspectJWT answers for an access token only if the caller is an audience of it, or is allowed to introspect
// every token of the token's organization (introspect_org).
func (p *Provider) introspectJWT(ctx context.Context, caller *model.Client, tok string) []byte {
	cl, err := p.VerifyAccessToken(ctx, tok)
	if err != nil {
		return inactive
	}
	// Active for the client the token was issued to (its id is in aud), or for a client allowed to introspect every
	// token of its organization (introspect_org). The RFC 8707 resources a token names are in aud as URIs, not client
	// ids: a resource server that introspects tokens issued to other clients needs introspect_org.
	if !slices.Contains(cl.Aud, caller.ID) && !(caller.IntrospectOrg && cl.Org == caller.OrgID) {
		return inactive
	}
	o := newObj(512)
	o.boolean("active", true)
	o.str("token_type", "Bearer")
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
	return o.bytes()
}

// introspectRefresh answers for a refresh token; only the client the token was issued to may ask.
func (p *Provider) introspectRefresh(ctx context.Context, caller *model.Client, tok string) []byte {
	g, ok := p.readRefresh(ctx, caller, tok)
	if !ok || !p.grantLive(ctx, g) {
		return inactive
	}
	u, err := p.user(ctx, g.UserID)
	if err != nil || !u.Enabled(time.Now()) || u.OrgID != g.OrgID {
		return inactive
	}
	app, err := p.appAccess(ctx, caller, nil, u)
	if err != nil || !app.Allowed {
		return inactive
	}
	o := newObj(256)
	o.boolean("active", true)
	// RFC 7662 token_type names how the token is presented (RFC 6749 §7.1); a refresh token is never presented
	// to a resource, so it has none.
	o.str("token_kind", "refresh_token")
	o.str("client_id", g.ClientID)
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
	return o.bytes()
}

// readRefresh loads and authenticates a refresh token's grant without changing anything.
func (p *Provider) readRefresh(ctx context.Context, caller *model.Client, tok string) (*model.Grant, bool) {
	pr, ok := parseRefresh(tok)
	if !ok {
		return nil, false
	}
	g, err := p.svc.Grants.Get(ctx, pr.gid)
	if err != nil || g.ClientID != caller.ID || g.Revoked || time.Now().After(g.Expires) {
		return nil, false
	}
	if ok, _ := p.authentic(pr, g); !ok { // (a legacy grant is converted when it is next refreshed)
		return nil, false
	}
	if pr.counted && pr.counter != g.Counter || !pr.counted && g.Counter != 0 {
		return nil, false
	}
	return g, true
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
	p.corsRestrict(w, r, ce.c.ID)
	tok := r.PostForm.Get("token")
	if tok == "" {
		writeOAuthError(w, oerr("invalid_request", "token is required"))
		return
	}
	ctx := r.Context()
	switch {
	case service.IsAPIToken(tok):
		// Personal API tokens belong to their owner; they are revoked from the account page, not here.
	case strings.HasPrefix(tok, "ey") && strings.Count(tok, ".") == 2:
		// A JWT cannot be recalled, but revoking one of this client's user tokens ends the grant it came from,
		// which stops refreshing and makes introspection report it inactive.
		if cl, err := p.VerifyAccessToken(ctx, tok); err == nil && cl.ClientID == ce.c.ID && cl.GID != "" {
			p.revokeGrant(ctx, cl.GID)
			p.auditClient(ctx, ce.c, cl.Sub, "oauth.revoke", map[string]string{"grant": cl.GID, "token": "access"})
		}
	default:
		if g, ok := p.readRefresh(ctx, ce.c, tok); ok {
			p.revokeGrant(ctx, g.ID)
			target := g.UserID
			if u, err := p.user(ctx, g.UserID); err == nil {
				target = u.Username
			}
			p.auditClient(ctx, ce.c, target, "oauth.revoke", map[string]string{"grant": g.ID, "user_id": g.UserID,
				"token": "refresh"})
		}
	}
	w.WriteHeader(http.StatusOK)
}
