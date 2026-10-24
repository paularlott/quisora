package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/paularlott/quisora/internal/store"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/web"
)

const backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"

// logoutReq is a pending RP-initiated logout awaiting the user's confirmation (ephemeral, ns "oauth.logout").
type logoutReq struct {
	Redirect string `json:"r,omitempty"` // fully built post_logout_redirect_uri (with state)
	Client   string `json:"c,omitempty"` // client name for the confirmation page
}

// errHintKeyGone: a well-formed ID token hint signed with one of our algorithms by a key that is no longer kept
// (retired keys are deleted once the tokens they signed have expired, but relying parties keep ID tokens for as long
// as their own sessions last). Such a hint is treated as absent: the user is asked to confirm.
var errHintKeyGone = errors.New("oidc: id_token_hint signed with a retired key")

// verifyIDTokenHint checks an ID token this provider issued. Expiry is not enforced: RP-initiated logout accepts
// expired ID tokens as hints. With errHintKeyGone it also returns the hint's unverified claims.
func (p *Provider) verifyIDTokenHint(ctx context.Context, tok string) (*Claims, error) {
	pj, err := ParseJWT(tok)
	if err != nil {
		return nil, err
	}
	if isAccessTokenTyp(pj.Header.Typ) || strings.EqualFold(pj.Header.Typ, typLogout) {
		return nil, badToken("not an ID token")
	}
	key := p.keyByKID(ctx, pj.Header.Kid)
	if key == nil && pj.Header.Kid != "" && ValidAlg(pj.Header.Alg) {
		cl := &Claims{}
		if json.Unmarshal(pj.Payload, cl) == nil && cl.Iss == p.issuer && len(cl.Aud) > 0 {
			return cl, errHintKeyGone
		}
	}
	if key == nil || key.alg != pj.Header.Alg {
		return nil, badToken("unknown key")
	}
	if err := pj.Verify(key.pub); err != nil {
		return nil, err
	}
	cl := &Claims{}
	if err := json.Unmarshal(pj.Payload, cl); err != nil || cl.Iss != p.issuer || len(cl.Aud) == 0 || cl.Sub == "" {
		return nil, badToken("claims")
	}
	return cl, nil
}

func (p *Provider) logoutInvalid(w http.ResponseWriter, r *http.Request, body string) {
	p.message(w, r, http.StatusBadRequest, "Invalid request", "The sign-out request is not valid", body)
}

func (p *Provider) handleLogout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		p.logoutInvalid(w, r, "")
		return
	}
	q := r.Form
	ctx := r.Context()
	if r.Method == http.MethodPost {
		if _, err := r.Cookie(web.SessionCookie); err != nil {
			// A relying party's cross-site form POST carries no SameSite=Lax session cookie: as a top-level GET
			// navigation it does, so continue there (otherwise the user would be "logged out" without their session
			// ending or back-channel notices going out).
			v := url.Values{}
			for _, k := range []string{"id_token_hint", "client_id", "post_logout_redirect_uri", "state", "logout_hint", "ui_locales"} {
				if x := q.Get(k); x != "" {
					v.Set(k, x)
				}
			}
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, "/oauth/logout?"+v.Encode(), http.StatusSeeOther)
			return
		}
	}
	var hint *Claims
	clientID := q.Get("client_id")
	if h := q.Get("id_token_hint"); h != "" {
		var err error
		hint, err = p.verifyIDTokenHint(ctx, h)
		switch {
		case errors.Is(err, errHintKeyGone):
			// Not proof of anything: the user confirms (as without a hint). Its audience still names the client
			// whose registered post-logout addresses the redirect is checked against.
			if clientID == "" {
				clientID = hint.Aud[0]
			}
			hint = nil
		case err != nil:
			p.logoutInvalid(w, r, "")
			return
		}
	}
	if hint != nil {
		if clientID != "" && !hint.Aud.Has(clientID) {
			p.logoutInvalid(w, r, "")
			return
		}
		clientID = hint.Aud[0]
	}
	var client *model.Client
	if clientID != "" {
		ce, err := p.client(ctx, clientID)
		if err != nil || !ce.c.Enabled {
			p.logoutInvalid(w, r, "")
			return
		}
		client = ce.c
	}
	redirect := ""
	if uri := q.Get("post_logout_redirect_uri"); uri != "" {
		if client == nil || !slices.Contains(client.PostLogoutURIs, uri) {
			p.logoutInvalid(w, r, "The address to return to is not registered for this application.")
			return
		}
		u, err := url.Parse(uri)
		if err != nil {
			p.logoutInvalid(w, r, "")
			return
		}
		if st := q.Get("state"); st != "" && len(st) <= 2048 {
			v := u.Query()
			v.Set("state", st)
			u.RawQuery = v.Encode()
		}
		redirect = u.String()
	}

	sess, user := p.s.Sessions.Current(r)
	if sess == nil {
		// Nothing to end, so nothing to confirm. The redirect needs no id_token_hint: RP-Initiated Logout §2 defines
		// client_id for exactly this (a post_logout_redirect_uri without a hint), and its only condition on the
		// redirect is an exact match with an address the client registered (checked above). An attacker can at most
		// send a browser to a page the application itself listed as its signed-out page.
		p.finishLogout(w, r, redirect)
		return
	}
	if hint == nil || hint.Sub != user.ID || (hint.SID != "" && hint.SID != sess.ID) {
		// Without a valid hint for this session anyone could sign the user out with a link: ask first.
		lr := logoutReq{Redirect: redirect}
		if client != nil {
			lr.Client = client.Name
		}
		b, _ := json.Marshal(lr)
		id, err := p.s.Eph.New(ctx, nsLogout, b, 10*time.Minute)
		if err != nil {
			p.message(w, r, http.StatusServiceUnavailable, "Unavailable", "Please try again", "")
			return
		}
		pg := p.s.Page(w, r, "Sign out", "", LogoutData{ID: id, Username: user.FullName(), Client: lr.Client})
		pg.CSRF = sess.CSRF // this route runs outside the session middleware: the form posts the session's token
		p.s.Render.Render(w, http.StatusOK, "oauth-logout", pg)
		return
	}
	p.endSession(ctx, w, r, sess)
	p.finishLogout(w, r, redirect)
}

func (p *Provider) finishLogout(w http.ResponseWriter, r *http.Request, redirect string) {
	if redirect != "" {
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	p.message(w, r, http.StatusOK, "Signed out", "You have been signed out", "You can close this window.")
}

// endSession ends the browser session (and its refresh grants). The clients that had one are notified through
// the service's OnSessionsEnding hook, which the session manager calls for every ended session.
func (p *Provider) endSession(ctx context.Context, w http.ResponseWriter, r *http.Request, sess *model.Session) {
	p.s.Sessions.End(ctx, w, r)
}

// handleLogoutConfirm handles POST /oauth/logout/confirm, the confirmation page's plain form (it works without
// JavaScript): {id, csrf}. It ends the session and sends the browser to the client's post-logout address, or shows
// the signed-out page.
func (p *Provider) handleLogoutConfirm(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		p.logoutInvalid(w, r, "")
		return
	}
	sess := web.Session(r)
	if sess != nil {
		r.Header.Set("X-CSRF-Token", r.PostForm.Get("csrf"))
		if !p.s.CheckCSRF(r, sess.CSRF) {
			p.logoutInvalid(w, r, "Open the sign-out page again and confirm there.")
			return
		}
	}
	raw, err := p.s.Eph.Take(r.Context(), nsLogout, r.PostForm.Get("id"))
	if err != nil {
		p.message(w, r, http.StatusBadRequest, "Request expired", "This sign-out request has expired",
			"Return to the application you were using and sign out again.")
		return
	}
	var lr logoutReq
	_ = json.Unmarshal(raw, &lr)
	if sess != nil {
		p.endSession(r.Context(), w, r, sess)
	}
	if lr.Redirect != "" {
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, lr.Redirect, http.StatusSeeOther)
		return
	}
	p.message(w, r, http.StatusOK, "Signed out", "You have been signed out", "You can close this window.")
}

// ---------------------------------------------------------------------------------------------------------------
// Back-channel logout (OpenID Connect Back-Channel Logout 1.0)

type bcTarget struct {
	client *model.Client
	sub    string
	sid    string
}

// collect finds the clients that hold a refresh grant on the user's sessions (all of the user's sessions when
// sessionIDs is empty) and that registered a back-channel logout URI. It also forgets cached grant liveness so
// token checks notice the end of the sessions at once.
func (p *Provider) collect(ctx context.Context, userID string, sessionIDs []string) []bcTarget {
	var out []bcTarget
	seen := map[string]bool{}
	add := func(clientID, sid string) {
		k := clientID + "|" + sid
		if seen[k] {
			return
		}
		seen[k] = true
		ce, err := p.client(ctx, clientID)
		if err != nil || ce.c.BackchannelURI == "" || !ce.c.Enabled {
			return
		}
		out = append(out, bcTarget{client: ce.c, sub: userID, sid: sid})
	}
	// The applications each session issued tokens to (also those whose refresh grant was revoked since) ...
	sessions, err := p.svc.Sessions.All(ctx, userID)
	if err != nil {
		p.log.Warn("oidc: listing sessions for back-channel logout", "user", userID, "error", err)
	}
	for _, s := range sessions {
		if len(sessionIDs) > 0 && !slices.Contains(sessionIDs, s.ID) {
			continue
		}
		for _, cid := range s.Clients {
			add(cid, s.ID)
		}
	}
	// ... and every live grant on them.
	grants, err := p.svc.Grants.All(ctx, userID)
	if err != nil {
		p.log.Warn("oidc: listing grants for back-channel logout", "user", userID, "error", err)
	}
	for _, g := range grants {
		if len(sessionIDs) > 0 && !slices.Contains(sessionIDs, g.SessionID) {
			continue
		}
		p.grants.del(g.ID)
		add(g.ClientID, g.SessionID)
	}
	return out
}

// noteSessionClient records on the session that clientID was issued tokens for it (see collect).
func (p *Provider) noteSessionClient(ctx context.Context, sessionID, clientID string) {
	for range 5 {
		s, err := p.svc.Sessions.Get(ctx, sessionID)
		if err != nil || slices.Contains(s.Clients, clientID) {
			return
		}
		if len(s.Clients) >= 100 {
			return // bounded: the grants still name the rest
		}
		s.Clients = append(s.Clients, clientID)
		if err := p.svc.Sessions.Update(ctx, s); !errors.Is(err, store.ErrStale) {
			return
		}
	}
}

// BackchannelLogout notifies the relying parties that hold grants on the given sessions that those sessions ended.
// Call it BEFORE deleting the sessions: the targets are found from the session and grant records, then delivery
// happens asynchronously (bounded timeout, best effort, failures logged).
func (p *Provider) BackchannelLogout(ctx context.Context, sessionIDs ...string) {
	byUser := map[string][]string{}
	for _, id := range sessionIDs {
		s, err := p.svc.Sessions.Get(ctx, id)
		if err != nil {
			continue
		}
		byUser[s.UserID] = append(byUser[s.UserID], id)
	}
	for uid, ids := range byUser {
		p.dispatch(p.collect(ctx, uid, ids))
	}
}

// BackchannelLogoutClient tells one relying party that the user removed its access (the account page): a logout
// token for each session it was issued tokens on. The client's refresh grants stop working at once, before they are
// deleted, so a refresh racing the removal cannot slip through on a cached answer. Call it before the grants go.
func (p *Provider) BackchannelLogoutClient(ctx context.Context, userID, clientID string) {
	var out []bcTarget
	for _, t := range p.collect(ctx, userID, nil) {
		if t.client.ID == clientID {
			out = append(out, t)
		}
	}
	if grants, err := p.svc.Grants.All(ctx, userID); err == nil {
		for _, g := range grants {
			if g.ClientID == clientID {
				p.grants.put(g.ID, grantState{})
			}
		}
	}
	p.dispatch(out)
}

// BackchannelLogoutUser is BackchannelLogout for every session (grant) of a user: sign out everywhere, user
// disabled or deleted. Call it before the records are removed.
func (p *Provider) BackchannelLogoutUser(ctx context.Context, userID string) {
	p.dispatch(p.collect(ctx, userID, nil))
}

// Back-channel logouts are sent from a bounded queue by at most bcWorkersMax senders, started as the queue fills and
// gone when it is empty: an emergency sign-out of a whole server (or a bulk expiry) with hundreds of thousands of
// sessions queues targets, not goroutines. A logout that finds the queue full is not sent (logged with the count):
// the sessions and grants end on this server either way; the relying party is only not told at once.
const (
	bcWorkersMax   = 32
	bcQueueMax     = 10_000
	bcShutdownWait = 10 * time.Second
)

func (p *Provider) dispatch(targets []bcTarget) {
	dropped := 0
	for _, t := range targets {
		p.bcWG.Add(1)
		select {
		case p.bcQueue <- t:
		default:
			p.bcWG.Done()
			dropped++
		}
	}
	if dropped > 0 {
		p.log.Warn("oidc: back-channel logout queue full: logouts not sent (the sessions ended here all the same)",
			"dropped", dropped, "queue", bcQueueMax)
	}
	p.bcMu.Lock()
	for p.bcWorkers < bcWorkersMax && p.bcWorkers < len(p.bcQueue) {
		p.bcWorkers++
		go p.bcWorker()
	}
	p.bcMu.Unlock()
}

// bcWorker sends queued logouts until the queue is empty.
func (p *Provider) bcWorker() {
	for {
		select {
		case t := <-p.bcQueue:
			if err := p.sendLogoutToken(t); err != nil {
				p.log.Warn("oidc: back-channel logout failed", "client", t.client.ID, "uri", t.client.BackchannelURI, "error", err)
			}
			p.bcWG.Done()
		default:
			p.bcMu.Lock()
			if len(p.bcQueue) == 0 { // checked under bcMu: dispatch starts a sender for anything queued after
				p.bcWorkers--
				p.bcMu.Unlock()
				return
			}
			p.bcMu.Unlock()
		}
	}
}

func (p *Provider) sendLogoutToken(t bcTarget) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	key, err := p.signingKey(ctx, p.signAlg(t.client))
	if err != nil {
		return err
	}
	now := time.Now()
	o := newObj(384)
	o.str("iss", p.issuer)
	o.str("sub", t.sub)
	o.str("aud", t.client.ID)
	o.num("iat", now.Unix())
	o.num("exp", now.Add(2*time.Minute).Unix())
	o.str("jti", newJTI())
	o.raw("events", `{"`+backchannelEvent+`":{}}`)
	o.strIf("sid", t.sid)
	tok, err := key.sign(typLogout, o.bytes())
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.client.BackchannelURI,
		strings.NewReader(url.Values{"logout_token": {tok}}.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cache-Control", "no-store")
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &statusError{resp.StatusCode}
	}
	return nil
}

type statusError struct{ code int }

func (e *statusError) Error() string { return "relying party answered " + http.StatusText(e.code) }
