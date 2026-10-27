package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Token exchange (RFC 8693). A confidential client with the token exchange grant trades a user's access token for a
// new access token issued to itself, acting for that user: an API passing the user's identity on to the services it
// calls, or an agent working for the user. Only impersonation-style exchanges of this server's own access tokens are
// supported; the calling client is the actor (no actor_token), and it is named in the new token's act claim.
//
// Who may exchange a token: a client it was issued for (its id is in aud: the application itself, narrowing its own
// token, or another client it was issued for), or a client of the same organization allowed to introspect every
// token there (introspect_org: a resource server, whose tokens name it by resource URI rather than client id). The
// user must have access to the calling client, as for a sign-in to it. The new token carries no more than the
// subject token's scopes and the calling client's, names only resources registered for the calling client, never
// outlives the subject token, and belongs to the same grant: signing the user out ends it too. No refresh or ID token
// is issued.
const (
	tokenTypeAccess = "urn:ietf:params:oauth:token-type:access_token"
	tokenTypeJWT    = "urn:ietf:params:oauth:token-type:jwt"
	maxActDepth     = 4 // actors in a chain of exchanges
)

func (p *Provider) tokenExchange(ctx context.Context, c *model.Client, form url.Values, jkt string) (*tokenResponse, *oauthError) {
	st := form.Get("subject_token")
	if st == "" {
		return nil, oerr("invalid_request", "subject_token is required")
	}
	if t := form.Get("subject_token_type"); t != tokenTypeAccess && t != tokenTypeJWT {
		return nil, oerr("invalid_request", "subject_token_type must be "+tokenTypeAccess)
	}
	if form.Get("actor_token") != "" || form.Get("actor_token_type") != "" {
		return nil, oerr("invalid_request", "actor_token is not supported: the authenticated client is the actor")
	}
	if t := form.Get("requested_token_type"); t != "" && t != tokenTypeAccess {
		return nil, oerr("invalid_request", "only access tokens can be requested")
	}
	invalid := oerr("invalid_grant", "the subject token is invalid, expired or revoked")
	cl, err := p.verifyIn(ctx, c.OrgID, st)
	if err != nil {
		if errors.Is(err, service.ErrUnavailable) {
			return nil, serverError(err) // not known to be bad: the caller keeps the subject token and retries
		}
		return nil, invalid
	}
	if cl.Sub == cl.ClientID {
		return nil, oerr("invalid_grant", "the subject token must be a user's token")
	}
	if !slices.Contains(cl.Aud, c.ClientID()) && !(c.IntrospectOrg && cl.Org == c.OrgID) {
		return nil, oerr("invalid_grant", "the subject token was not issued for this client")
	}
	u, err := p.user(ctx, cl.Sub)
	if err != nil && !gone(err) {
		return nil, serverError(unavailable(err))
	}
	if err != nil || !u.Enabled(time.Now()) || u.OrgID != c.OrgID {
		return nil, invalid
	}
	org, err := p.org(ctx, u.OrgID)
	if err != nil {
		if !gone(err) {
			return nil, serverError(unavailable(err))
		}
		return nil, invalid
	}
	// The user's access to the calling client, as a sign-in to it would need.
	app, err := p.appAccess(ctx, c, nil, u)
	if err != nil {
		return nil, serverError(unavailable(err))
	}
	if !app.Allowed {
		return nil, oerr("invalid_grant", errNoAccess.Error())
	}
	// Scopes: those of the subject token that the calling client may use; offline_access means nothing without a
	// refresh token.
	var avail []string
	for _, s := range cl.Scopes() {
		if s != "offline_access" && slices.Contains(c.Scopes, s) {
			avail = append(avail, s)
		}
	}
	scopes := avail
	if scope := form.Get("scope"); scope != "" {
		scopes = dedupe(splitScope(scope))
		if !subset(scopes, avail) {
			return nil, oerr("invalid_scope", "the requested scope exceeds the subject token's or this client's")
		}
	}
	// RFC 8693 audience is a logical name; here it is a resource indicator like resource. Either way, only the
	// resources registered for the calling client.
	res, err := parseResources(append(slices.Clone(form["resource"]), form["audience"]...))
	if err != nil {
		return nil, oerr("invalid_target", err.Error())
	}
	if !subset(res, c.Resources) {
		return nil, oerr("invalid_target", "the resource is not registered for this client")
	}
	act, oe := exchangeActor(c, cl)
	if oe != nil {
		return nil, oe
	}
	is := &issue{client: c, user: u, org: org, scopes: scopes, resources: res, sid: cl.SID, gid: cl.GID,
		authTime: time.Unix(int64(cl.AuthTime), 0), amr: cl.AMR, app: app, act: act,
		expires: time.Unix(int64(cl.Exp), 0), jkt: jkt}
	tr, err := p.mint(ctx, is, false)
	if err != nil {
		return nil, serverError(err)
	}
	tr.issuedType = tokenTypeAccess
	p.auditClient(ctx, c, u.Username, "oauth.token_exchange", map[string]string{"user_id": u.ID,
		"subject_client_id": cl.ClientID, "scopes": strings.Join(scopes, " "), "resources": strings.Join(res, " ")})
	return tr, nil
}

// exchangeActor is the act claim of a token exchanged by c for subject token cl: c, with the subject token's actor
// (if any) nested inside. A client narrowing a token issued to itself adds no actor.
func exchangeActor(c *model.Client, cl *Claims) (string, *oauthError) {
	prev := cl.Act
	if depth := actDepth(prev); depth < 0 || depth >= maxActDepth && cl.ClientID != c.ClientID() {
		return "", oerr("invalid_grant", "the subject token's chain of actors is too long")
	}
	if cl.ClientID == c.ClientID() {
		return string(prev), nil
	}
	o := newObj(128)
	o.str("sub", c.ClientID())
	o.str("client_id", c.ClientID())
	if len(prev) > 0 {
		o.raw("act", string(prev))
	}
	return string(o.bytes()), nil
}

// actDepth counts the actors in an act claim (0 for none, -1 for one that is not an object).
func actDepth(act json.RawMessage) int {
	n := 0
	for len(act) > 0 && n <= maxActDepth {
		var a struct {
			Act json.RawMessage `json:"act"`
		}
		if json.Unmarshal(act, &a) != nil {
			return -1
		}
		n++
		act = a.Act
	}
	return n
}
