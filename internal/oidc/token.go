package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
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
var userScopes = []string{"openid", "profile", "email", "phone", "groups", "org", "roles", "enterprise", "idp", "offline_access"}

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
	IdP         string   `json:"idp,omitempty"`  // upstream provider type (Grant.IdP)
	UpstreamAMR []string `json:"uamr,omitempty"` // how the provider said the person signed in (Grant.UpstreamAMR)
	// Upstream is the account at that provider the person signed in with (Grant.Upstream).
	Upstream  *model.UpstreamAccount `json:"upa,omitempty"`
	Scopes    []string               `json:"sc"`
	Resources []string               `json:"res,omitempty"`
	ADTypes   []string               `json:"adt,omitempty"` // authorization details types the authorization request named
	ClaimsUI  []string               `json:"cu,omitempty"`
	ClaimsID  []string               `json:"ci,omitempty"`
	DPoPJKT   string                 `json:"jkt,omitempty"` // dpop_jkt of the authorization request
	// GrantID is the id of the grant the exchange of the code makes, chosen with the code: an exchange that failed on
	// our side and is retried makes the same grant, and finds it made (userGrant), never a second one.
	GrantID string `json:"g,omitempty"`
	// ConsentGen is the client's consent generation (Client.RememberGen) when the code was issued, which the grant
	// takes (Grant.ConsentGen). A code issued before the client's redirect URIs or credentials changed is not redeemed
	// after (userGrant): what the user allowed was the client as it was.
	ConsentGen int64 `json:"cg"`
	// AppFence is the session's count of removals of the client's access when the code was issued
	// (model.Session.AppFence): a removal since, and the code makes no grant (userGrant).
	AppFence uint32 `json:"af,omitempty"`
}

// tokenFailuresPerClientMin bounds the token requests per confidential client, grant type and minute that fail on what
// they present (an invalid_grant or a refused DPoP proof, as for failuresPerIPMin). Such a client proved its secret,
// so the failures are its own and throttle only it: a backend that refreshes for thousands of users after an
// organization's sessions were revoked gets invalid_grant for each, and must not lock out other clients behind the
// same address. They still cost (see failuresPerIPMin), so a client that keeps failing is held back, at ten times the
// budget of an address anyone can name a client from. Counted per client, not per client and address: its failures
// cost the same from wherever they come, and the limit then holds however many addresses it is served from. Counted
// per grant type too: after such a revocation the backend's stale refresh tokens fail by the thousand, and that must
// not stop the code exchanges of the users signing back in, which is when they must work. Past the limit the client
// is refused that grant type before any of that for the rest of the minute. Successful requests and the DPoP nonce
// round trip do not count.
const tokenFailuresPerClientMin = 3000

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
	p.corsRestrict(w, r, ce.c.ClientID())
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
	// A public client is admitted by its client_id alone, so anyone can fail as it: its failures count against the
	// address (read by authenticateClient above). A confidential client's count against itself.
	failKey := failIPKey(r)
	if !ce.c.Public() {
		failKey = "token-fail|" + ce.c.ID + "|" + gt
		if n, err := p.s.Eph.Incr(r.Context(), nsRateOIDC, failKey, 0, time.Minute); err != nil {
			writeOAuthError(w, serverError(unavailable(err))) // refused, but as "try again": the limit was not reached
			return
		} else if n >= tokenFailuresPerClientMin {
			writeOAuthError(w, &oauthError{status: http.StatusTooManyRequests, code: "temporarily_unavailable",
				desc: "too many failed token requests of this grant type from this client; try again in a minute", retry: true})
			return
		}
	}
	jkt, e := p.tokenProof(r, ce.c)
	if e != nil {
		p.tokenFailed(r, failKey, e)
		writeOAuthError(w, e)
		return
	}
	ad, e := parseAuthDetailsParam(r.PostForm.Get("authorization_details"), ce.c)
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
			r.PostForm.Get("code_verifier"), r.PostForm["resource"], ad, jkt)
	case "refresh_token":
		tr, oe = p.refresh(r.Context(), ce.c, r.PostForm.Get("refresh_token"), r.PostForm.Get("scope"), r.PostForm["resource"], ad, jkt)
	case service.GrantTokenExchange:
		tr, oe = p.tokenExchange(r.Context(), ce.c, r.PostForm, ad, jkt)
	case service.GrantDeviceCode:
		tr, oe = p.deviceToken(r.Context(), ce.c, r.PostForm.Get("device_code"), ad, jkt)
	default:
		tr, oe = p.clientCredentials(r.Context(), ce.c, r.PostForm.Get("scope"), r.PostForm["resource"], ad, jkt)
	}
	if oe != nil {
		p.tokenFailed(r, failKey, oe)
		writeOAuthError(w, oe)
		return
	}
	writeTokens(w, tr)
}

// tokenFailed counts a token request that failed on what it presented in failKey (the address of a public client, the
// confidential client itself). The request fails whatever the counter answers.
func (p *Provider) tokenFailed(r *http.Request, failKey string, e *oauthError) {
	if e.code == "invalid_grant" || e.code == "invalid_dpop_proof" {
		_, _ = p.s.Eph.Incr(context.WithoutCancel(r.Context()), nsRateOIDC, failKey, 1, time.Minute)
	}
}

func serverError(err error) *oauthError {
	if errors.Is(err, store.ErrUnavailable) || errors.Is(err, store.ErrUnconfirmed) {
		// The store cannot make the change now (or may have made it: unconfirmed): the client retries, here or
		// elsewhere.
		return &oauthError{status: http.StatusServiceUnavailable, code: "temporarily_unavailable",
			desc: "this server cannot make changes now; try again shortly", retry: true}
	}
	if errors.Is(err, ephemeral.ErrFull) {
		// This node's short-lived state is full (counted and logged by the store): not a failure, the client retries.
		return &oauthError{status: http.StatusServiceUnavailable, code: "temporarily_unavailable",
			desc: "this server is busy; try again shortly", retry: true}
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
	return fmt.Errorf("%w: %w", service.ErrUnavailable, err) // the cause stays visible: an unknown outcome is audited as one
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

// grantAttempts bounds the writes of a code's grant (userGrant): each makes the grant together with its session, and
// is refused when the session changed meanwhile, as it does when several codes of one browser session (applications
// signed in to at once) are exchanged at the same moment. The pauses between them add up to well under a second.
const grantAttempts = 6

// sleepCtx waits for d, or until ctx is done (its error).
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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

// replayKey is the id of a code's records of use and of replay (nsUsed, nsReplayed): they are kept per client, so a
// client that presents a code it was not issued to neither finds the grant made from it (and revokes it) nor leaves a
// mark that makes the rightful client's redemption under way revoke its own grant.
func replayKey(c *model.Client, code string) string {
	return c.ID + "\x00" + code
}

// codeReplayed answers the presentation of a code that is no longer there: unknown, expired or used. A code presented
// twice by its client: everything issued from the first use must die (RFC 6749 §4.1.2). The mark goes first, then the
// grant is looked for; the first use records its grant, then looks for the mark (both under the code's id, on one
// node, in order): whichever comes second sees the other, so a replay racing the first use's grant still ends it.
// Both are the client's own (replayKey): another client's presentation of the code finds no grant of its own to end,
// and is refused alone. It is not audited either: it ends nothing, and anyone can make it, so it would only fill the
// audit log.
func (p *Provider) codeReplayed(ctx context.Context, c *model.Client, code string) *oauthError {
	key := replayKey(c, code)
	_ = p.s.Eph.Set(ctx, nsReplayed, key, []byte{1}, replayMarkTTL)
	if used, err := p.s.Eph.Get(ctx, nsUsed, key); err == nil {
		// The replay is refused either way; whether the grant could be ended is recorded as it happened.
		if f := strings.Split(string(used), "\x00"); len(f) == 3 {
			org, user, gid := f[0], f[1], f[2]
			rerr := p.revokeGrant(ctx, org, user, c.SSHApp, gid)
			p.log.Warn("oidc: authorization code replayed; grant revoked", "client", c.ID, "grant", gid, "revoke_error", rerr)
			p.auditClient(ctx, c, nil, "oauth.code.replay", map[string]string{"grant": gid, "grant_revoked": revokedText(rerr)})
		}
	}
	return oerr("invalid_grant", "the authorization code is invalid, expired or already used")
}

func (p *Provider) exchangeCode(ctx context.Context, c *model.Client, code, redirectURI, verifier string, resource, ad []string, jkt string) (*tokenResponse, *oauthError) {
	if code == "" || len(code) > 200 {
		return nil, oerr("invalid_request", "code is required")
	}
	// The code is read before it is taken: a client it was not issued to (one that came by the value from a leaked
	// redirect, say) must not be able to spend it, nor make its rightful client's exchange look like a replay.
	raw, err := p.s.Eph.Get(ctx, nsCode, code)
	if errors.Is(err, ephemeral.ErrNotFound) {
		return nil, p.codeReplayed(ctx, c, code)
	}
	if err != nil {
		return nil, serverError(err)
	}
	var cd codeData
	if json.Unmarshal(raw, &cd) != nil || cd.ClientID != c.ID {
		return nil, oerr("invalid_grant", "the authorization code was not issued to this client")
	}
	if _, err := p.s.Eph.Take(ctx, nsCode, code); err != nil {
		if errors.Is(err, ephemeral.ErrNotFound) { // another request took it since it was read
			return nil, p.codeReplayed(ctx, c, code)
		}
		return nil, serverError(err)
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
	ad, oe := narrowAuthDetails(ad, cd.ADTypes)
	if oe != nil {
		return nil, oe
	}
	if c, _, err = p.forResources(ctx, c, cd.Resources); err != nil {
		if !gone(err) {
			return nil, serverError(unavailable(err))
		}
		return nil, oerr("invalid_grant", "the resource no longer accepts this application")
	}
	tr, gid, oe := p.userGrant(ctx, c, &cd, resource, ad, jkt, "")
	switch {
	case oe != nil && oe.status >= 500:
		// Nothing was decided (a store that could not be read or written): the code is put back for the client's
		// retry, rather than spent on our failure (its retry makes the same grant: codeData.GrantID).
		_ = p.s.Eph.Set(ctx, nsCode, code, raw, p.codeTTL(c))
	case oe == nil:
		_ = p.s.Eph.Set(ctx, nsUsed, replayKey(c, code), []byte(cd.OrgID+"\x00"+cd.UserID+"\x00"+gid), usedTTL)
		if _, err := p.s.Eph.Get(ctx, nsReplayed, replayKey(c, code)); err == nil { // presented again while this one ran
			rerr := p.revokeGrant(ctx, cd.OrgID, cd.UserID, c.SSHApp, gid)
			p.log.Warn("oidc: authorization code replayed; grant revoked", "client", c.ID, "grant", gid, "revoke_error", rerr)
			p.auditClient(ctx, c, nil, "oauth.code.replay", map[string]string{"grant": gid, "grant_revoked": revokedText(rerr)})
			return nil, oerr("invalid_grant", "the authorization code is invalid, expired or already used")
		}
	}
	return tr, oe
}

// userGrant makes the grant a user authorized (cd: from an authorization code, or an approved device sign-in, via
// naming its grant type) and issues its tokens for res, checking again that the user, their session and their access
// to the application are still there. It returns the grant's id. The grant's id is cd.GrantID, so a retry of an
// exchange that failed on our side makes the same grant, and issues its tokens from the one an earlier attempt made.
// userGrant makes the refresh grant of an approved authorization (cd) and issues its tokens, for the resources the
// request names (resource, narrowed by grantResources) and the authorization details types ad (nil: those of the
// grant, which keeps cd's).
func (p *Provider) userGrant(ctx context.Context, c *model.Client, cd *codeData, resource, ad []string, jkt, via string) (*tokenResponse, string, *oauthError) {
	res, oe := grantResources(resource, cd.Resources, c)
	if oe != nil {
		return nil, "", oe
	}
	// The scopes the user authorized that the client (c, as it is now) may still use: one taken off the application
	// after the code was issued is in neither the grant nor its tokens, as a refresh narrows them.
	scopes := slices.DeleteFunc(slices.Clone(cd.Scopes), func(s string) bool { return !slices.Contains(c.Scopes, s) })
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
	// session ended cannot renew what that session lost. The grant is written only while the session is as checked
	// here (service.CreateSessionGrant), so a revocation of it that is under way meanwhile ends the grant too.
	session := func() (*model.Session, *oauthError) {
		sess, err := p.svc.Sessions.Get(ctx, cd.SessionID)
		if err != nil && !gone(err) {
			return nil, serverError(unavailable(err))
		}
		usable := false
		if err == nil {
			if usable, err = p.svc.SessionUsableWith(ctx, sess, u, p.user); err != nil {
				return nil, serverError(unavailable(err)) // not known to have ended: the client retries
			}
		}
		if !usable {
			return nil, oerr("invalid_grant", "the user's session has ended")
		}
		// The user removed the application's access since approving (service.RevokeAppAccess): the approval went with it.
		if sess.AppFence(c.ID) != cd.AppFence {
			return nil, oerr("invalid_grant", "the user removed this application's access: sign in again")
		}
		return sess, nil
	}
	sess, oe := session()
	if oe != nil {
		return nil, "", oe
	}
	org, err := p.svc.Org(ctx, cd.OrgID)
	if err != nil {
		if !gone(err) {
			return nil, "", serverError(unavailable(err))
		}
		return nil, "", oerr("invalid_grant", "the organization no longer exists")
	}
	// Access is checked again: it may have been taken away (or expired) since the user was sent back with the code.
	app, err := p.appAccess(ctx, c, nil, u)
	if gone(err) { // the application's tenant no longer exists
		return nil, "", oerr("invalid_grant", "the application no longer exists")
	}
	if err != nil {
		return nil, "", serverError(unavailable(err))
	}
	if !app.Allowed {
		return nil, "", oerr("invalid_grant", errNoAccess.Error())
	}
	if cd.ConsentGen != c.RememberGen {
		return nil, "", oerr("invalid_grant", "the application changed since the user authorized it: sign in again")
	}
	now := time.Now().UTC()
	g := &model.Grant{ClientID: c.ID, ConsentGen: cd.ConsentGen, UserID: u.ID, OrgID: u.OrgID, Epoch: sess.Epoch, Stamp: sess.Stamp, SessionID: cd.SessionID, Scopes: scopes, AMR: cd.AMR, IdP: cd.IdP, UpstreamAMR: cd.UpstreamAMR, Upstream: cd.Upstream, Sources: sess.Sources, Resources: cd.Resources,
		AuthDetailTypes: cd.ADTypes, ClaimsUI: cd.ClaimsUI, ClaimsID: cd.ClaimsID, AuthTime: time.Unix(cd.AuthTime, 0).UTC(),
		Expires: now.Add(p.cfg.Tokens.Refresh())}
	if c.Public() {
		g.DPoPJKT = jkt // a public client's refresh tokens need the same key from now on (RFC 9449 §5)
	}
	g.ID = cd.GrantID // chosen with the code: a retry of this exchange makes the same grant
	if g.ID == "" {
		g.ID = model.NewID()
	}
	p.svc.NewGrantKey(g) // the key is sealed bound to the id
	for attempt := 0; ; attempt++ {
		err := p.svc.CreateSessionGrant(ctx, g, sess)
		if err == nil {
			break
		}
		if !errors.Is(err, store.ErrStale) {
			return nil, "", serverError(err)
		}
		made, gerr := p.svc.Grants.Get(ctx, g.ID)
		if gerr == nil {
			// Made by an earlier attempt of this exchange, which failed on our side after it (only the code names the
			// id): its tokens are issued now, from it.
			if made.ClientID != c.ID || made.SessionID != cd.SessionID {
				return nil, "", serverError(unavailable(errors.New("the grant of this code is another's")))
			}
			g = made
			break
		}
		if !gone(gerr) || attempt == grantAttempts-1 {
			return nil, "", serverError(unavailable(fmt.Errorf("the grant of this code: %v", err)))
		}
		// The session changed since it was checked (a sign-in noted on it, a revocation under way, or another code
		// of it exchanged at the same moment, which writes it too): check it again, after a short random pause so
		// exchanges racing on one session take turns rather than colliding again.
		if err := sleepCtx(ctx, time.Duration(1+rand.IntN(4<<attempt))*time.Millisecond); err != nil {
			return nil, "", serverError(err)
		}
		if sess, oe = session(); oe != nil {
			return nil, "", oe
		}
		g.Epoch, g.Stamp, g.Sources = sess.Epoch, sess.Stamp, sess.Sources
	}
	p.noteGrant(ctx, g.OrgID, g.UserID, g.ID)
	detail := map[string]string{"grant": g.ID, "user_id": u.ID, "scopes": strings.Join(g.Scopes, " "), "auth_session": g.SessionID}
	if via != "" {
		detail["grant_type"] = via
	}
	p.auditClient(ctx, c, u, "oauth.grant", detail)
	if c.BackchannelURI != "" {
		p.noteSessionClient(ctx, cd.SessionID, c.ID)
	}
	is := &issue{client: c, user: u, org: org, scopes: scopes, resources: res, sid: cd.SessionID, gid: g.ID,
		authTime: g.AuthTime, amr: cd.AMR, idp: cd.IdP, upstreamAMR: cd.UpstreamAMR, upstream: cd.Upstream, nonce: cd.Nonce, app: app, claimsUI: cd.ClaimsUI, claimsID: cd.ClaimsID, jkt: jkt, adTypes: ad}
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

// grantResources are the resources a token of an authorization is issued for (RFC 8707 §2.2): those the request names
// (asked), which must be among those the user authorized, or else all of those (none when the authorization named
// none: the user never saw them); and never one the client (c, as it is now) is no longer registered for, so a
// resource taken from a client is not in its tokens from then on, whether issued from a code, a device sign-in or a
// refresh.
func grantResources(asked, authorized []string, c *model.Client) ([]string, *oauthError) {
	res, err := parseResources(asked)
	if err != nil {
		return nil, oerr("invalid_target", err.Error())
	}
	if len(res) == 0 {
		return slices.DeleteFunc(slices.Clone(authorized), func(r string) bool { return !slices.Contains(c.Resources, r) }), nil
	}
	if !subset(res, authorized) || !subset(res, c.Resources) {
		return nil, oerr("invalid_target", "resource was not part of the authorization")
	}
	return res, nil
}

// grantLive is the one test of whether a refresh grant still stands for its user, wherever one is used (a refresh, an
// introspection of a refresh token): its user is active and in its organization (read here: also returned), it was
// granted in the user's current session epoch (model.User.SessionEpoch: not ended by a password reset or a reset of
// the account's sign-in), it is not ended by an emergency sign-out (its stamp), and one made without the
// offline_access scope lasts only as long as the browser session it was granted in (OIDC Core §11: refreshing while
// the user is away needs offline_access), which must still sign the user in (service.SessionUsable). A guest's grant
// stands on the accounts its sign-in came from too, offline access or not (service.SourcesHold). Ending the
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
	// a guest's grant stands on the accounts its sign-in came from, offline access or not (model.Grant.Sources)
	if ok, err := p.svc.SourcesHold(ctx, g.Sources, p.user); err != nil {
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

// revokeGrant deletes grants ids (tombstones) of user userID of organization orgID, revokes the SSH certificates issued
// under them, and forgets cached knowledge of them. The error is the deletions' or the certificates': a revocation that
// did not persist is reported to whoever asked for it (RFC 7009 §2.2.1: 503, the client retries), never answered or
// audited as done. The cache is told "gone" before each deletion (a check racing it must not keep the grant alive on a
// copy read just before), and emptied when the deletion fails: the grant is still in the store, and the retry must
// find it there to end it, not answer 200 to a cached "nothing to revoke".
//
// Only grants of an SSH application (sshApp: Client.SSHApp) can have certificates: the sign endpoint takes only the
// tenant's SSH application's tokens. For any other client none are listed, and no record of the grant taken back is
// written.
func (p *Provider) revokeGrant(ctx context.Context, orgID, userID string, sshApp bool, ids ...string) error {
	ctx = context.WithoutCancel(ctx)
	// The grants are deleted first, whatever their certificates do: the end of a grant (a replayed refresh token's
	// family, say) never waits on them. They are revoked after, as endSessions explains: a certificate signed under one
	// meanwhile either is listed then or finds the grant gone and is revoked by its signer (Service.SignUserSSH); in a
	// gossip cluster, where the two can miss each other while replicating, the record of the grant taken back revokes it
	// once both have replicated (Service.RevokeSSHCertsFrom). Whose they are comes from the caller, not the grant, so a retry after a
	// failure to revoke them does so again though the grant is gone by then (a grant already gone counts as deleted).
	// The certificates of all the grants are listed once.
	from := make(map[string]bool, len(ids))
	var errs []error
	for _, id := range ids {
		from[id] = true
		p.grants.Put(id, grantState{})
		if err := p.svc.Grants.Delete(ctx, id); err != nil && !gone(err) {
			p.grants.Del(id) // may still be in the store: the retry ends it
			errs = append(errs, err)
		}
	}
	if sshApp {
		errs = append(errs, p.svc.RevokeSSHCertsFrom(ctx, orgID, userID, from))
	}
	if err := errors.Join(errs...); err != nil {
		p.log.Warn("oidc: revoking grants", "grants", ids, "error", err)
		return unavailable(err)
	}
	return nil
}

// revokedText is how an audit event says whether a revocation (revokeGrant's error) took effect: "unknown" for a
// deletion that may have landed.
func revokedText(err error) string {
	switch {
	case err == nil:
		return "true"
	case errors.Is(err, store.ErrUnconfirmed) || errors.Is(err, service.ErrOutcomeUnknown):
		return service.OutcomeUnknown
	}
	return "false"
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

// retryAfter is the Retry-After of a 503 the client should retry. It fits well inside refreshRetryGrace: a rotation
// whose outcome was not known (it may have landed) is retried with the same token, and must find it still a retry of
// the last rotation, not an old token presented again (reuse, which revokes the grant).
const retryAfter = 10 * time.Second

// isRefreshRetry reports whether a refresh token presented with counter is the token just before the grant g's current
// one, moments after it was rotated, from a caller that also proved who it is (a confidential client's credentials, or
// the DPoP key the grant is bound to: a copied token alone is not enough): the client did not get the answer (a lost
// response) and tries again. A public client without DPoP has nothing but the token, so for it any old token is reuse.
func isRefreshRetry(c *model.Client, g *model.Grant, counter uint64) bool {
	return counter+1 == g.Counter && time.Since(g.Rotated) < refreshRetryGrace && (!c.Public() || g.DPoPJKT != "")
}

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

func (p *Provider) refresh(ctx context.Context, c *model.Client, token, scope string, resource, ad []string, jkt string) (*tokenResponse, *oauthError) {
	invalid := oerr("invalid_grant", "the refresh token is invalid, expired or revoked")
	pr, ok := parseRefresh(token)
	if !ok {
		return nil, invalid
	}
	// Read in the client's organization's partition (a grant is its user's, who signs in only to applications of their
	// own organization): an unknown or purged grant is then "not found" whatever other partitions are doing.
	g, err := p.svc.Grants.GetIn(ctx, c.OrgID, pr.gid)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, invalid
		}
		return nil, serverError(unavailable(err)) // not known to be revoked: the client keeps the token and retries
	}
	if g.ClientID != c.ID || time.Now().After(g.Expires) || !p.authentic(pr, g) {
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
			rerr := p.revokeGrant(ctx, g.OrgID, g.UserID, c.SSHApp, g.ID)
			p.log.Warn("oidc: stale static refresh token reuse; grant revoked", "client", c.ID, "grant", g.ID, "user", g.UserID, "revoke_error", rerr)
			p.auditReuse(ctx, c, g, "a refresh token from before rotation was presented again", revokedText(rerr))
		}
		return nil, invalid
	}
	org, err := p.svc.Org(ctx, g.OrgID)
	if err != nil {
		if !gone(err) {
			return nil, serverError(unavailable(err))
		}
		return nil, invalid
	}
	// Access that was taken away or has expired ends the application's refresh tokens; access that cannot be read
	// now ends nothing, and issues nothing (503).
	app, err := p.appAccess(ctx, c, nil, u)
	if gone(err) { // the application's tenant no longer exists
		return nil, oerr("invalid_grant", "the application no longer exists")
	}
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
	res, oe := grantResources(resource, g.Resources, c)
	if oe != nil {
		return nil, oe
	}
	if ad, oe = narrowAuthDetails(ad, g.AuthDetailTypes); oe != nil {
		return nil, oe
	}
	var newRefresh string
	switch {
	case (c.RotateRefresh || c.Public()) && pr.counted && isRefreshRetry(c, g, pr.counter):
		// A retry of the last rotation (isRefreshRetry): it gets the same answer — the current token, made from the
		// grant's key and counter — and nothing rotates.
		if newRefresh, err = p.counterToken(g); err != nil {
			return nil, serverError(err)
		}
	case c.RotateRefresh || c.Public():
		if pr.counted && pr.counter != g.Counter {
			if pr.counter < g.Counter { // an old token again: someone kept a copy; kill the family
				rerr := p.revokeGrant(ctx, g.OrgID, g.UserID, c.SSHApp, g.ID)
				p.log.Warn("oidc: refresh token reuse; grant revoked", "client", c.ID, "grant", g.ID, "user", g.UserID, "revoke_error", rerr)
				p.auditReuse(ctx, c, g, "an old refresh token was presented again", revokedText(rerr))
			}
			return nil, invalid
		}
		for attempt := 1; ; attempt++ {
			g.Counter++
			g.Rotated = time.Now().UTC()
			err := p.svc.Grants.Update(ctx, g)
			if err == nil {
				break
			}
			if !errors.Is(err, store.ErrStale) {
				if errors.Is(err, store.ErrUnconfirmed) {
					// The rotation may have landed: the client retries with the same token, within refreshRetryGrace
					// (retryAfter), and gets the new one (isRefreshRetry). Recorded as a rotation of unknown outcome.
					_ = p.auditedClient(ctx, c, u, "oauth.refresh", map[string]string{"grant": g.ID, "user_id": u.ID},
						func() error { return err })
				}
				return nil, serverError(err)
			}
			// The grant changed since it was read. A higher counter is another presentation of the same token (kept
			// by someone else): the family ends. The same counter is another change (a re-seal during a master key
			// rotation, say): the refresh goes ahead on the new copy.
			fresh, ferr := p.svc.Grants.Get(ctx, g.ID)
			if ferr != nil {
				if gone(ferr) {
					return nil, invalid
				}
				return nil, serverError(unavailable(ferr)) // not known to be revoked: the client keeps the token and retries
			}
			// The token was rotated moments ago elsewhere: a store that answers stale answers reads with the copy that
			// made it stale, so fresh is the grant as it is now, and a retry is judged on it as in the first case above:
			// the client gets the token it missed, and nothing rotates again.
			if isRefreshRetry(c, fresh, pr.counter) {
				g = fresh
				break
			}
			if fresh.Counter > pr.counter {
				rerr := p.revokeGrant(ctx, g.OrgID, g.UserID, c.SSHApp, g.ID)
				p.log.Warn("oidc: concurrent refresh token reuse; grant revoked", "client", c.ID, "grant", g.ID, "revoke_error", rerr)
				p.auditReuse(ctx, c, g, "the same refresh token was presented twice at once", revokedText(rerr))
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
		authTime: g.AuthTime, amr: g.AMR, idp: g.IdP, upstreamAMR: g.UpstreamAMR, upstream: g.Upstream, app: app, claimsUI: allowedClaims(g.ClaimsUI, c.Scopes),
		claimsID: allowedClaims(g.ClaimsID, c.Scopes), jkt: jkt, adTypes: ad}
	tr, err := p.mint(ctx, is, true)
	if err != nil {
		return nil, serverError(err)
	}
	tr.refresh = newRefresh
	if p.cfg.Audit.Tokens {
		p.auditClient(ctx, c, u, "oauth.refresh", map[string]string{"grant": g.ID, "user_id": u.ID,
			"scopes": strings.Join(scopes, " ")})
	}
	return tr, nil
}

// ---------------------------------------------------------------------------------------------------------------
// client_credentials

func (p *Provider) clientCredentials(ctx context.Context, c *model.Client, scope string, resource, ad []string, jkt string) (*tokenResponse, *oauthError) {
	// A service account's scopes are all Quisora's own, whatever they share a name with: its groups is the management
	// API's, not the OpenID Connect scope a token without a user never carries.
	allowed := make([]string, 0, len(c.Scopes))
	for _, s := range c.Scopes {
		if c.ServiceAccount || !slices.Contains(userScopes, s) {
			allowed = append(allowed, s)
		}
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
	org, err := p.svc.Org(ctx, c.OrgID)
	if err != nil {
		if !gone(err) {
			return nil, serverError(unavailable(err))
		}
		return nil, oerr("invalid_client", "the client's organization no longer exists")
	}
	tr, err := p.mint(ctx, &issue{client: c, org: org, scopes: scopes, resources: res, jkt: jkt, adTypes: ad}, false)
	if err == nil && p.cfg.Audit.Tokens {
		p.auditClient(ctx, c, nil, "oauth.client_credentials", map[string]string{"scopes": strings.Join(scopes, " ")})
	}
	if err != nil {
		return nil, serverError(err)
	}
	return tr, nil
}

// clientActorName is how the audit log names client c as an actor.
func clientActorName(c *model.Client) string {
	if c.ServiceAccount {
		return service.ServiceAccountName(c)
	}
	return "client:" + c.Name
}

// auditClient records an OAuth event made by client c (the actor) about the user u (nil: about c itself).
func (p *Provider) auditClient(ctx context.Context, c *model.Client, u *model.User, action string, detail map[string]string) {
	if detail == nil {
		detail = map[string]string{}
	}
	detail["client_id"] = c.ClientID()
	a := &service.Actor{OrgID: c.OrgID, Name: clientActorName(c), ClientID: c.ID}
	if u == nil {
		p.svc.Audit(ctx, a, c.OrgID, action, c.Name, detail)
		return
	}
	p.svc.AuditUser(ctx, a, u, action, detail)
}

// auditedClient is auditClient for a change made by client c: the event is written when write succeeds, and (with
// outcome "unknown") when its outcome is not known; a change known not to have happened is not audited as done.
func (p *Provider) auditedClient(ctx context.Context, c *model.Client, u *model.User, action string, detail map[string]string, write func() error) error {
	if detail == nil {
		detail = map[string]string{}
	}
	detail["client_id"] = c.ClientID()
	a := &service.Actor{OrgID: c.OrgID, Name: clientActorName(c), ClientID: c.ID}
	if u == nil {
		return p.svc.Audited(ctx, a, c.OrgID, action, c.Name, detail, write)
	}
	return p.svc.AuditedUser(ctx, a, u, action, detail, write)
}

// auditReuse records a refresh token presented after it was replaced: someone kept a copy, and the grant is revoked
// (revoked says whether that deletion persisted; a failed one is logged, and the token is refused either way).
func (p *Provider) auditReuse(ctx context.Context, c *model.Client, g *model.Grant, why, revoked string) {
	p.auditClient(ctx, c, p.svc.AuditTargetUser(ctx, c.OrgID, g.UserID), "oauth.refresh.reuse", map[string]string{"grant": g.ID, "user_id": g.UserID,
		"grant_revoked": revoked, "reason": why})
}
