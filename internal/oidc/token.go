package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// userScopes are scopes that only make sense for a signed-in user, never for client_credentials.
var userScopes = []string{"openid", "profile", "email", "phone", "groups", "org", "enterprise", "offline_access"}

// codeData is what an authorization code stands for (kept in ephemeral state, single use).
type codeData struct {
	ClientID    string   `json:"c"`
	RedirectURI string   `json:"r"`
	Challenge   string   `json:"cc"`
	Nonce       string   `json:"n,omitempty"`
	SessionID   string   `json:"s"`
	UserID      string   `json:"u"`
	OrgID       string   `json:"o"`
	AuthTime    int64    `json:"at"`
	AMR         []string `json:"amr"`
	Scopes      []string `json:"sc"`
	Resources   []string `json:"res,omitempty"`
	ClaimsUI    []string `json:"cu,omitempty"`
	ClaimsID    []string `json:"ci,omitempty"`
	DPoPJKT     string   `json:"jkt,omitempty"` // dpop_jkt of the authorization request
}

func (p *Provider) handleToken(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	p.corsActual(w, r)
	p.setDPoPNonce(w)
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, oerr("invalid_request", "the request body could not be read"))
		return
	}
	if dup := repeated(r.Form); dup != "" {
		writeOAuthError(w, oerr("invalid_request", dup+" is repeated"))
		return
	}
	ce, e := p.authenticateClient(r, true)
	if e != nil {
		writeOAuthError(w, e)
		return
	}
	p.corsRestrict(w, r, ce.c.ID)
	gt := r.PostForm.Get("grant_type")
	switch gt {
	case "authorization_code", "refresh_token", "client_credentials", service.GrantTokenExchange, service.GrantDeviceCode:
	default:
		writeOAuthError(w, oerr("unsupported_grant_type", "unsupported grant_type"))
		return
	}
	if !slices.Contains(ce.c.GrantTypes, gt) || ((gt == "client_credentials" || gt == service.GrantTokenExchange) && ce.c.Public()) {
		writeOAuthError(w, oerr("unauthorized_client", "the client may not use this grant type"))
		return
	}
	jkt, e := p.tokenProof(r, ce.c)
	if e != nil {
		writeOAuthError(w, e)
		return
	}
	var (
		tr *tokenResponse
		oe *oauthError
	)
	switch gt {
	case "authorization_code":
		tr, oe = p.exchangeCode(r.Context(), ce.c, r.PostForm.Get("code"), r.PostForm.Get("redirect_uri"),
			r.PostForm.Get("code_verifier"), r.PostForm["resource"], jkt)
	case "refresh_token":
		tr, oe = p.refresh(r.Context(), ce.c, r.PostForm.Get("refresh_token"), r.PostForm.Get("scope"), r.PostForm["resource"], jkt)
	case service.GrantTokenExchange:
		tr, oe = p.tokenExchange(r.Context(), ce.c, r.PostForm, jkt)
	case service.GrantDeviceCode:
		tr, oe = p.deviceToken(r.Context(), ce.c, r.PostForm.Get("device_code"), jkt)
	default:
		tr, oe = p.clientCredentials(r.Context(), ce.c, r.PostForm.Get("scope"), r.PostForm["resource"], jkt)
	}
	if oe != nil {
		writeOAuthError(w, oe)
		return
	}
	writeTokens(w, tr)
}

func serverError(err error) *oauthError {
	if errors.Is(err, store.ErrNotWritable) || errors.Is(err, store.ErrUnconfirmed) {
		// This node cannot write now (cut off from the majority of its cluster, within the grace that keeps the
		// token endpoint answering what needs no write): the client retries, here or elsewhere.
		return &oauthError{status: http.StatusServiceUnavailable, code: "temporarily_unavailable",
			desc: "this server cannot make changes now; try again shortly", retry: true}
	}
	if errors.Is(err, service.ErrUnavailable) {
		// A read that an authorization decision needs failed (unavailable): the answer is neither "allowed" nor
		// "revoked" but "not now", so the client keeps its tokens and retries, rather than discarding them as an
		// invalid_grant would make it, or going on as a 200 would.
		return &oauthError{status: http.StatusServiceUnavailable, code: "temporarily_unavailable",
			desc: "this server cannot check the request now; try again shortly", retry: true}
	}
	return &oauthError{status: http.StatusInternalServerError, code: "server_error", desc: "temporary failure (" + errString(err) + ")"}
}

// unavailable marks a store read that an authorization, liveness or revocation decision depends on as failed: the
// decision cannot be made, and every caller answers with that (serverError: 503 temporarily_unavailable; userinfo
// and SCIM the same in their own shape), never with the answer it would have given had the read succeeded. Only a
// failed read qualifies: a read that found nothing is an answer (the grant, user or client is gone), kept as it is.
func unavailable(err error) error {
	if err == nil || gone(err) || errors.Is(err, service.ErrUnavailable) {
		return err
	}
	return fmt.Errorf("%w: %v", service.ErrUnavailable, err)
}

// gone reports whether a lookup's error says the record does not exist (as opposed to the read having failed).
func gone(err error) bool {
	return errors.Is(err, store.ErrNotFound) || errors.Is(err, service.ErrNotFound)
}

func errString(err error) string {
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	return "internal"
}

// ---------------------------------------------------------------------------------------------------------------
// authorization_code

var verifierOK = func() [256]bool {
	var t [256]bool
	for _, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~" {
		t[c] = true
	}
	return t
}()

// pkceOK checks an RFC 7636 S256 code_verifier against the stored challenge.
func pkceOK(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for i := 0; i < len(verifier); i++ {
		if !verifierOK[verifier[i]] {
			return false
		}
	}
	h := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(b64.EncodeToString(h[:])), []byte(challenge)) == 1
}

func (p *Provider) exchangeCode(ctx context.Context, c *model.Client, code, redirectURI, verifier string, resource []string, jkt string) (*tokenResponse, *oauthError) {
	if code == "" || len(code) > 200 {
		return nil, oerr("invalid_request", "code is required")
	}
	raw, err := p.s.Eph.Take(ctx, nsCode, code)
	if err != nil {
		if errors.Is(err, ephemeral.ErrNotFound) {
			// A code presented twice: everything issued from the first use must die (RFC 6749 §4.1.2). The mark goes
			// first, then the grant is looked for; the first use records its grant, then looks for the mark (both
			// under the code's id, on one node, in order): whichever comes second sees the other, so a replay racing
			// the first use's grant still ends it.
			_ = p.s.Eph.Set(ctx, nsReplayed, code, []byte{1}, usedTTL)
			if gid, err := p.s.Eph.Get(ctx, nsUsed, code); err == nil {
				// The replay is refused either way; whether the grant could be ended is recorded as it happened.
				rerr := p.revokeGrant(ctx, string(gid))
				p.log.Warn("oidc: authorization code replayed; grant revoked", "client", c.ID, "grant", string(gid), "revoke_error", rerr)
				p.auditClient(ctx, c, "", "oauth.code.replay", map[string]string{"grant": string(gid), "grant_revoked": strconv.FormatBool(rerr == nil)})
			}
			return nil, oerr("invalid_grant", "the authorization code is invalid, expired or already used")
		}
		return nil, serverError(err)
	}
	var cd codeData
	if json.Unmarshal(raw, &cd) != nil || cd.ClientID != c.ID {
		return nil, oerr("invalid_grant", "the authorization code was not issued to this client")
	}
	if redirectURI != cd.RedirectURI {
		return nil, oerr("invalid_grant", "redirect_uri does not match the authorization request")
	}
	// A code issued with a challenge needs its verifier; one issued without (a confidential client allowed to omit
	// PKCE) must not be given one: a verifier there means the request was tampered with.
	if cd.Challenge == "" {
		if verifier != "" || c.RequirePKCE() {
			return nil, oerr("invalid_grant", "PKCE verification failed")
		}
	} else if !pkceOK(verifier, cd.Challenge) {
		return nil, oerr("invalid_grant", "PKCE verification failed")
	}
	// A code requested for a DPoP key (dpop_jkt) is only redeemed with a proof of that key (RFC 9449 §10).
	if cd.DPoPJKT != "" && cd.DPoPJKT != jkt {
		return nil, oerr("invalid_grant", "the DPoP proof is not made with the key the authorization request named (dpop_jkt)")
	}
	res, err := parseResources(resource)
	if err != nil {
		return nil, oerr("invalid_target", err.Error())
	}
	// RFC 8707 §2.2: the exchange may name the resources the user authorized, or fewer; never others — and none at
	// all when the authorization request named none (the user never saw them).
	if len(res) == 0 {
		res = cd.Resources
	} else if !subset(res, cd.Resources) {
		return nil, oerr("invalid_target", "resource was not part of the authorization request")
	}
	if c, _, err = p.forResources(ctx, c, cd.Resources); err != nil {
		if !gone(err) {
			return nil, serverError(unavailable(err))
		}
		return nil, oerr("invalid_grant", "the resource no longer accepts this application")
	}
	tr, gid, oe := p.userGrant(ctx, c, &cd, res, jkt, "")
	switch {
	case oe != nil && oe.status >= 500:
		// Nothing was decided (a store that could not be read or written): the code is put back for the client's
		// retry, rather than spent on our failure.
		_ = p.s.Eph.Set(ctx, nsCode, code, raw, p.codeTTL(c))
	case oe == nil:
		_ = p.s.Eph.Set(ctx, nsUsed, code, []byte(gid), usedTTL)
		if _, err := p.s.Eph.Get(ctx, nsReplayed, code); err == nil { // presented again while this one ran
			rerr := p.revokeGrant(ctx, gid)
			p.log.Warn("oidc: authorization code replayed; grant revoked", "client", c.ID, "grant", gid, "revoke_error", rerr)
			p.auditClient(ctx, c, "", "oauth.code.replay", map[string]string{"grant": gid, "grant_revoked": strconv.FormatBool(rerr == nil)})
			return nil, oerr("invalid_grant", "the authorization code is invalid, expired or already used")
		}
	}
	return tr, oe
}

// userGrant makes the grant a user authorized (cd: from an authorization code, or an approved device sign-in, via
// naming its grant type) and issues its tokens for res, checking again that the user, their session and their access
// to the application are still there. It returns the grant's id.
func (p *Provider) userGrant(ctx context.Context, c *model.Client, cd *codeData, res []string, jkt, via string) (*tokenResponse, string, *oauthError) {
	// Each of these is a decision: a read that fails (as opposed to one that finds the record gone) makes none, and
	// says so (503), rather than telling the client the user, session or organization is gone.
	u, err := p.user(ctx, cd.UserID)
	if err != nil && !gone(err) {
		return nil, "", serverError(unavailable(err))
	}
	if err != nil || !u.Enabled(time.Now()) || u.OrgID != cd.OrgID {
		return nil, "", oerr("invalid_grant", "the user is no longer active")
	}
	// The grant is the session's authorization carried on: only a session that still signs the user in (not ended by
	// a password reset, a reset of the account's sign-in or an emergency sign-out, service.SessionUsable) gives one,
	// and the grant takes the session's epoch and sign-out stamp, never the current ones, so a code redeemed after its
	// session ended cannot renew what that session lost.
	sess, err := p.svc.Sessions.Get(ctx, cd.SessionID)
	if err != nil && !gone(err) {
		return nil, "", serverError(unavailable(err))
	}
	usable := false
	if err == nil {
		if usable, err = p.svc.SessionUsable(ctx, sess, u); err != nil {
			return nil, "", serverError(unavailable(err)) // not known to have ended: the client retries
		}
	}
	if !usable {
		return nil, "", oerr("invalid_grant", "the user's session has ended")
	}
	org, err := p.org(ctx, cd.OrgID)
	if err != nil {
		if !gone(err) {
			return nil, "", serverError(unavailable(err))
		}
		return nil, "", oerr("invalid_grant", "the organization no longer exists")
	}
	// Access is checked again: it may have been taken away (or expired) since the user was sent back with the code.
	app, err := p.appAccess(ctx, c, nil, u)
	if err != nil {
		return nil, "", serverError(unavailable(err))
	}
	if !app.Allowed {
		return nil, "", oerr("invalid_grant", errNoAccess.Error())
	}
	now := time.Now().UTC()
	g := &model.Grant{ClientID: c.ID, UserID: u.ID, OrgID: u.OrgID, Epoch: sess.Epoch, Stamp: sess.Stamp, SessionID: cd.SessionID, Scopes: cd.Scopes, AMR: cd.AMR, Resources: cd.Resources,
		ClaimsUI: cd.ClaimsUI, ClaimsID: cd.ClaimsID, AuthTime: time.Unix(cd.AuthTime, 0).UTC(),
		Expires: now.Add(p.cfg.Tokens.Refresh())}
	if c.Public() {
		g.DPoPJKT = jkt // a public client's refresh tokens need the same key from now on (RFC 9449 §5)
	}
	g.ID = model.NewID() // the key is sealed bound to the id
	p.svc.NewGrantKey(g)
	if err := p.svc.Grants.Create(ctx, g); err != nil {
		return nil, "", serverError(err)
	}
	detail := map[string]string{"grant": g.ID, "user_id": u.ID, "scopes": strings.Join(g.Scopes, " "), "auth_session": g.SessionID}
	if via != "" {
		detail["grant_type"] = via
	}
	p.auditClient(ctx, c, u.Username, "oauth.grant", detail)
	if c.BackchannelURI != "" {
		p.noteSessionClient(ctx, cd.SessionID, c.ID)
	}
	is := &issue{client: c, user: u, org: org, scopes: cd.Scopes, resources: res, sid: cd.SessionID, gid: g.ID,
		authTime: g.AuthTime, amr: cd.AMR, nonce: cd.Nonce, app: app, claimsUI: cd.ClaimsUI, claimsID: cd.ClaimsID, jkt: jkt}
	tr, err := p.mint(ctx, is, true)
	if err != nil {
		return nil, "", serverError(err)
	}
	if slices.Contains(c.GrantTypes, "refresh_token") {
		if tr.refresh, err = p.refreshToken(g, c.RotateRefresh || c.Public()); err != nil {
			return nil, "", serverError(err)
		}
	}
	return tr, g.ID, nil
}

// grantLive is the one test of whether a refresh grant still stands for its user, wherever one is used (a refresh, an
// introspection of a refresh token): its user is active and in its organization (read here: also returned), it was
// granted in the user's current session epoch (model.User.SessionEpoch: not ended by a password reset or a reset of
// the account's sign-in), it is not ended by an emergency sign-out (its stamp), and one made without the
// offline_access scope lasts only as long as the browser session it was granted in (OIDC Core §11: refreshing while
// the user is away needs offline_access), which must still sign the user in (service.SessionUsable). Ending the
// session (sign-out, revocation) deletes the grant too. An error means the answer could not be read (the user, the
// sign-out counters or the session): the caller answers 503, not "ended".
func (p *Provider) grantLive(ctx context.Context, g *model.Grant) (*model.User, bool, error) {
	u, err := p.user(ctx, g.UserID)
	if err != nil {
		if gone(err) {
			return nil, false, nil
		}
		return nil, false, unavailable(err)
	}
	if u.OrgID != g.OrgID || !u.SessionHolds(g.Epoch) {
		return u, false, nil
	}
	if ok, err := p.svc.UserUsable(ctx, u); err != nil {
		return nil, false, unavailable(err)
	} else if !ok {
		return u, false, nil
	}
	want, err := p.svc.SessionStamp(ctx, g.OrgID) // read once: the grant's stamp and its session's are judged by it
	if err != nil {
		return nil, false, unavailable(err)
	}
	if !g.Stamp.Current(want) { // ended by an emergency sign-out
		return u, false, nil
	}
	if slices.Contains(g.Scopes, "offline_access") {
		return u, true, nil
	}
	s, err := p.svc.Sessions.Get(ctx, g.SessionID)
	if err != nil {
		if gone(err) {
			return u, false, nil
		}
		return nil, false, unavailable(err)
	}
	return u, service.SessionUsableAt(s, u, want), nil
}

// revokeGrant deletes a grant (tombstone) and forgets cached knowledge of it. The error is the deletion's: a
// revocation that did not persist is reported to whoever asked for it (RFC 7009 §2.2.1: 503, the client retries),
// never answered or audited as done. The cache is told "gone" before the deletion (a check racing it must not keep
// the grant alive on a copy read just before), and emptied when the deletion fails: the grant is still in the
// store, and the retry must find it there to end it, not answer 200 to a cached "nothing to revoke".
func (p *Provider) revokeGrant(ctx context.Context, id string) error {
	p.grants.put(id, grantState{})
	err := p.svc.Grants.Delete(service.Durable(context.WithoutCancel(ctx)), id)
	if err != nil && !store.Applied(err) {
		p.grants.del(id)
		p.log.Warn("oidc: revoking grant", "grant", id, "error", err)
		return unavailable(err)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------------------
// refresh_token

// Refresh token formats:
//
//	default:        <grantID>.<base64url(key)>                    pure read, never changes
//	RotateRefresh:  <grantID>.<counter>.<base64url(HMAC(key, grantID, counter))>
//
// where key is the grant's own random key, stored sealed with the master key (model.Grant.Key): a copy of the
// database without the master key cannot produce or recognise a refresh token, and a master key rotation re-seals
// the key without changing the tokens.
func (p *Provider) refreshToken(g *model.Grant, rotate bool) (string, error) {
	if rotate {
		return p.counterToken(g)
	}
	key, err := p.grantKey(g)
	if err != nil {
		return "", err
	}
	return g.ID + "." + b64.EncodeToString(key), nil
}

var errNoGrantKey = errors.New("oidc: the grant has no refresh token key")

// refreshRetryGrace is how long after a rotation the token before it still gets the new one again (refresh).
const refreshRetryGrace = 30 * time.Second

// grantKey is the grant's refresh token key (see refreshToken).
func (p *Provider) grantKey(g *model.Grant) ([]byte, error) {
	key, err := p.svc.GrantRefreshKey(g)
	switch {
	case err != nil:
		return nil, err
	case key == nil:
		return nil, errNoGrantKey
	}
	return key, nil
}

func (p *Provider) counterToken(g *model.Grant) (string, error) {
	key, err := p.grantKey(g)
	if err != nil {
		return "", err
	}
	c := strconv.FormatUint(g.Counter, 10)
	return g.ID + "." + c + "." + b64.EncodeToString(secure.MAC(key, g.ID, c)), nil
}

// parsedRefresh is a refresh token split into its parts.
type parsedRefresh struct {
	gid     string
	secret  []byte // static format
	counter uint64 // counter format
	mac     []byte
	counted bool
}

func parseRefresh(tok string) (parsedRefresh, bool) {
	var pr parsedRefresh
	i := strings.IndexByte(tok, '.')
	if i <= 0 || len(tok) > 300 {
		return pr, false
	}
	pr.gid = tok[:i]
	rest := tok[i+1:]
	if j := strings.IndexByte(rest, '.'); j >= 0 {
		c, err := strconv.ParseUint(rest[:j], 10, 64)
		if err != nil {
			return pr, false
		}
		mac, err := b64strict.DecodeString(rest[j+1:])
		if err != nil {
			return pr, false
		}
		pr.counted, pr.counter, pr.mac = true, c, mac
		return pr, true
	}
	sec, err := b64strict.DecodeString(rest)
	if err != nil {
		return pr, false
	}
	pr.secret = sec
	return pr, true
}

// authentic verifies the token's secret or MAC against the grant (nothing about counters yet).
func (p *Provider) authentic(pr parsedRefresh, g *model.Grant) bool {
	key, err := p.grantKey(g)
	if err != nil {
		return false
	}
	if pr.counted {
		return hmac.Equal(secure.MAC(key, g.ID, strconv.FormatUint(pr.counter, 10)), pr.mac)
	}
	return subtle.ConstantTimeCompare(pr.secret, key) == 1
}

func (p *Provider) refresh(ctx context.Context, c *model.Client, token, scope string, resource []string, jkt string) (*tokenResponse, *oauthError) {
	invalid := oerr("invalid_grant", "the refresh token is invalid, expired or revoked")
	pr, ok := parseRefresh(token)
	if !ok {
		return nil, invalid
	}
	g, err := p.svc.Grants.Get(ctx, pr.gid)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, invalid
		}
		return nil, serverError(unavailable(err)) // not known to be revoked: the client keeps the token and retries
	}
	if g.ClientID != c.ID || g.Revoked || time.Now().After(g.Expires) || !p.authentic(pr, g) {
		return nil, invalid
	}
	u, live, err := p.grantLive(ctx, g)
	if err != nil {
		return nil, serverError(err) // not known to have ended: the client keeps the token and retries
	} else if !live {
		return nil, invalid
	}
	if c, _, err = p.forResources(ctx, c, g.Resources); err != nil {
		if !gone(err) {
			return nil, serverError(unavailable(err))
		}
		return nil, invalid // a self-registered application whose resource no longer accepts it
	}
	if g.DPoPJKT != "" && g.DPoPJKT != jkt { // checked before any counter moves: a stolen token alone does nothing
		return nil, oerr("invalid_grant", "the refresh token is bound to a DPoP key: send a proof made with it")
	}
	// Authentic token for this client. A static token only works while the grant has never rotated.
	if !pr.counted && g.Counter != 0 {
		if c.RotateRefresh || c.Public() { // a pre-rotation token again: someone kept a copy; kill the family
			rerr := p.revokeGrant(ctx, g.ID)
			p.log.Warn("oidc: stale static refresh token reuse; grant revoked", "client", c.ID, "grant", g.ID, "user", g.UserID, "revoke_error", rerr)
			p.auditReuse(ctx, c, g, "a refresh token from before rotation was presented again", rerr == nil)
		}
		return nil, invalid
	}
	org, err := p.org(ctx, g.OrgID)
	if err != nil {
		if !gone(err) {
			return nil, serverError(unavailable(err))
		}
		return nil, invalid
	}
	// Access that was taken away or has expired ends the application's refresh tokens; access that cannot be read
	// now ends nothing, and issues nothing (503).
	app, err := p.appAccess(ctx, c, nil, u)
	if err != nil {
		return nil, serverError(unavailable(err))
	}
	if !app.Allowed {
		return nil, oerr("invalid_grant", errNoAccess.Error())
	}
	// Scopes the grant still carries and the client may still use.
	granted := make([]string, 0, len(g.Scopes))
	for _, s := range g.Scopes {
		if slices.Contains(c.Scopes, s) {
			granted = append(granted, s)
		}
	}
	scopes := granted
	if scope != "" {
		scopes = dedupe(splitScope(scope))
		if !subset(scopes, granted) {
			return nil, oerr("invalid_scope", "the requested scope exceeds the original grant")
		}
	}
	res, err := parseResources(resource)
	if err != nil {
		return nil, oerr("invalid_target", err.Error())
	}
	// RFC 8707 §2.2: a refresh may ask for the resources the user authorized, or fewer, never others; and never one
	// the client is no longer registered for.
	if len(res) == 0 {
		res = slices.DeleteFunc(slices.Clone(g.Resources), func(r string) bool { return !slices.Contains(c.Resources, r) })
	} else if !subset(res, g.Resources) || !subset(res, c.Resources) {
		return nil, oerr("invalid_target", "resource was not part of the authorization")
	}
	var newRefresh string
	switch {
	case (c.RotateRefresh || c.Public()) && pr.counted && pr.counter+1 == g.Counter && time.Since(g.Updated) < refreshRetryGrace &&
		(!c.Public() || g.DPoPJKT != ""):
		// The token just before the current one, moments after it was rotated, from a caller that also proved who it
		// is (a confidential client's credentials, or the DPoP key the grant is bound to: a copied token alone is not
		// enough): the client did not get the answer (a lost response, or a rotation the cluster confirmed late) and
		// tries again. It gets the same answer — the current token, made from the grant's key and counter — and
		// nothing rotates. A public client without DPoP has nothing but the token, so for it any old token is reuse.
		if newRefresh, err = p.counterToken(g); err != nil {
			return nil, serverError(err)
		}
	case c.RotateRefresh || c.Public():
		if pr.counted && pr.counter != g.Counter {
			if pr.counter < g.Counter { // an old token again: someone kept a copy; kill the family
				rerr := p.revokeGrant(ctx, g.ID)
				p.log.Warn("oidc: refresh token reuse; grant revoked", "client", c.ID, "grant", g.ID, "user", g.UserID, "revoke_error", rerr)
				p.auditReuse(ctx, c, g, "an old refresh token was presented again", rerr == nil)
			}
			return nil, invalid
		}
		for attempt := 1; ; attempt++ {
			g.Counter++
			err := p.svc.Grants.Update(ctx, g)
			if err == nil {
				break
			}
			if !errors.Is(err, store.ErrStale) {
				return nil, serverError(err)
			}
			// The grant changed since it was read. A higher counter is another presentation of the same token (kept
			// by someone else): the family ends. The same counter is another change (a re-seal during a master key
			// rotation, say): the refresh goes ahead on the new copy.
			fresh, ferr := p.svc.Grants.Get(ctx, g.ID)
			if ferr != nil || fresh.Revoked {
				return nil, invalid
			}
			if fresh.Counter > pr.counter {
				rerr := p.revokeGrant(ctx, g.ID)
				p.log.Warn("oidc: concurrent refresh token reuse; grant revoked", "client", c.ID, "grant", g.ID, "revoke_error", rerr)
				p.auditReuse(ctx, c, g, "the same refresh token was presented twice at once", rerr == nil)
				return nil, invalid
			}
			if attempt == 3 {
				return nil, invalid
			}
			g = fresh
		}
		if newRefresh, err = p.counterToken(g); err != nil {
			return nil, serverError(err)
		}
	case pr.counted && pr.counter != g.Counter:
		return nil, invalid
	}
	is := &issue{client: c, user: u, org: org, scopes: scopes, resources: res, sid: g.SessionID, gid: g.ID,
		authTime: g.AuthTime, amr: g.AMR, app: app, claimsUI: allowedClaims(g.ClaimsUI, c.Scopes),
		claimsID: allowedClaims(g.ClaimsID, c.Scopes), jkt: jkt}
	tr, err := p.mint(ctx, is, true)
	if err != nil {
		return nil, serverError(err)
	}
	tr.refresh = newRefresh
	if p.cfg.Audit.Tokens {
		p.auditClient(ctx, c, u.Username, "oauth.refresh", map[string]string{"grant": g.ID, "user_id": u.ID,
			"scopes": strings.Join(scopes, " ")})
	}
	return tr, nil
}

// ---------------------------------------------------------------------------------------------------------------
// client_credentials

func (p *Provider) clientCredentials(ctx context.Context, c *model.Client, scope string, resource []string, jkt string) (*tokenResponse, *oauthError) {
	allowed := make([]string, 0, len(c.Scopes)+1)
	for _, s := range c.Scopes {
		if !slices.Contains(userScopes, s) {
			allowed = append(allowed, s)
		}
	}
	if c.SCIM && !slices.Contains(allowed, service.ScopeSCIM) {
		allowed = append(allowed, service.ScopeSCIM)
	}
	scopes := allowed
	if scope != "" {
		scopes = dedupe(splitScope(scope))
		if !subset(scopes, allowed) {
			return nil, oerr("invalid_scope", "the requested scope is not available to this client")
		}
	}
	res, err := parseResources(resource)
	if err != nil {
		return nil, oerr("invalid_target", err.Error())
	}
	if !subset(res, c.Resources) {
		return nil, oerr("invalid_target", "the resource is not registered for this client")
	}
	org, err := p.org(ctx, c.OrgID)
	if err != nil {
		if !gone(err) {
			return nil, serverError(unavailable(err))
		}
		return nil, oerr("invalid_client", "the client's organization no longer exists")
	}
	tr, err := p.mint(ctx, &issue{client: c, org: org, scopes: scopes, resources: res, jkt: jkt}, false)
	if err == nil && p.cfg.Audit.Tokens {
		p.auditClient(ctx, c, "", "oauth.client_credentials", map[string]string{"scopes": strings.Join(scopes, " ")})
	}
	if err != nil {
		return nil, serverError(err)
	}
	return tr, nil
}

// auditClient records an OAuth event made by client c (the actor) about target (a username, or "").
func (p *Provider) auditClient(ctx context.Context, c *model.Client, target, action string, detail map[string]string) {
	if detail == nil {
		detail = map[string]string{}
	}
	detail["client_id"] = c.ID
	if target == "" {
		target = c.Name
	}
	p.svc.Audit(ctx, &service.Actor{OrgID: c.OrgID, Name: "client:" + c.Name, ClientID: c.ID}, c.OrgID, action, target, detail)
}

// auditReuse records a refresh token presented after it was replaced: someone kept a copy, and the grant is revoked
// (revoked says whether that deletion persisted; a failed one is logged, and the token is refused either way).
func (p *Provider) auditReuse(ctx context.Context, c *model.Client, g *model.Grant, why string, revoked bool) {
	target := g.UserID
	if u, err := p.user(ctx, g.UserID); err == nil {
		target = u.Username
	}
	p.auditClient(ctx, c, target, "oauth.refresh.reuse", map[string]string{"grant": g.ID, "user_id": g.UserID,
		"grant_revoked": strconv.FormatBool(revoked), "reason": why})
}
