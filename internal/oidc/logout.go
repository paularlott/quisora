package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/metrics"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/queue"
	"github.com/paularlott/quisora/internal/store"
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

// verifyIDTokenHint checks an ID token this provider issued for organization orgID. Expiry is not enforced: RP-initiated logout accepts
// expired ID tokens as hints. With errHintKeyGone it also returns the hint's unverified claims.
func (p *Provider) verifyIDTokenHint(ctx context.Context, orgID, tok string) (*Claims, error) {
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
		if json.Unmarshal(pj.Payload, cl) == nil && cl.Iss == p.issuer(orgID) && len(cl.Aud) > 0 {
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
	if err := json.Unmarshal(pj.Payload, cl); err != nil || cl.Iss != p.issuer(orgID) || len(cl.Aud) == 0 || cl.Sub == "" {
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
	org := web.Org(r)
	if r.Method == http.MethodPost {
		if _, err := r.Cookie(web.SessionCookieFor(org.ID)); err != nil {
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
			http.Redirect(w, r, web.OrgPath(org.ID, "/oauth/logout?"+v.Encode()), http.StatusSeeOther)
			return
		}
	}
	var hint *Claims
	clientID := q.Get("client_id")
	if h := q.Get("id_token_hint"); h != "" {
		var err error
		hint, err = p.verifyIDTokenHint(ctx, org.ID, h)
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
		ce, err := p.client(ctx, org.ID, clientID)
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

	sess, user, err := p.s.Sessions.Check(r)
	if err != nil {
		// The store could not say whether there is a session to end: not "nothing to end", which would send the
		// browser on to the relying party's signed-out page with the session still alive.
		p.logoutUnchecked(w, r)
		return
	}
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
	if !p.endSession(ctx, w, r, sess) {
		return
	}
	p.finishLogout(w, r, redirect)
}

// logoutUnchecked answers a sign-out whose session could not be checked: try again.
func (p *Provider) logoutUnchecked(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Retry-After", "5")
	p.message(w, r, http.StatusServiceUnavailable, "Unavailable", "You could not be signed out",
		"This server cannot check your session right now. Please try again shortly.")
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
// the service's OnSessionsEnding hook, which the session manager calls for every ended session. It reports false
// when the session could not be ended: the user has then been told (503), not sent on to the relying party's
// signed-out page as though they were, since the session (or a refresh grant of it) still works in the store.
func (p *Provider) endSession(ctx context.Context, w http.ResponseWriter, r *http.Request, sess *model.Session) bool {
	if _, err := p.s.Sessions.End(ctx, w, r); err != nil {
		p.log.Warn("oidc: logout: the session could not be ended", "session", sess.ID, "error", err)
		p.message(w, r, http.StatusServiceUnavailable, "Sign-out incomplete", "You could not be fully signed out",
			"This server could not end your session just now. Please try again shortly.")
		return false
	}
	return true
}

// handleLogoutConfirm handles POST /o/<org>/oauth/logout/confirm, the confirmation page's plain form (it works without
// JavaScript): {id, csrf}. It ends the session and sends the browser to the client's post-logout address, or shows
// the signed-out page.
func (p *Provider) handleLogoutConfirm(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		p.logoutInvalid(w, r, "")
		return
	}
	if web.SessionUnchecked(r) {
		// Before the request is taken: the page is submitted again once the store answers.
		p.logoutUnchecked(w, r)
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
	if sess != nil && !p.endSession(r.Context(), w, r, sess) {
		return
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
	// jti identifies this logout to the relying party: chosen once, when the logout is collected, and sent in the
	// token of every attempt, so a relying party that has acted on it can tell a retry (or a replay) from a new logout
	// and does not act again (Back-Channel Logout 2.6). Empty only for a retry queued before it was kept; one is
	// chosen per attempt then.
	jti string
}

// retry is the target as an item of the retry queue.
func (t bcTarget) retry() LogoutRetry {
	return LogoutRetry{OrgID: t.client.OrgID, ClientID: t.client.ID, Sub: t.sub, SID: t.sid, JTI: t.jti}
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
		ce, err := p.recordClient(ctx, clientID)
		if err != nil || ce.c.BackchannelURI == "" || !ce.c.Enabled {
			return
		}
		out = append(out, bcTarget{client: ce.c, sub: userID, sid: sid, jti: newJTI()})
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
		p.grants.Del(g.ID)
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
				p.grants.Put(g.ID, grantState{})
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
// sessions queues targets, not goroutines. The queue is fair between organizations: each holds at most
// bcOrgQueueMax logouts in it and has at most bcOrgWorkersMax being sent, and the senders serve the organizations in
// turn, so one whose applications answer slowly or never (it costs a sender for the 8 s timeout each time) cannot
// delay the logouts of the others, only its own. A logout that finds its organization's share (or the whole queue)
// full goes to this node's durable retry queue at once instead (OpenLogoutQueue; without one, or when that holds
// logoutRetryOrgMax of the organization's, it is dropped and logged): the sessions and grants end on this server
// either way, and the relying party is told a little later. A logout the relying party does not take goes to the
// retry queue too, tried again after each delay of logoutBackoff, then given up on with a warning
// (quisora_backchannel_logout_failed_total). Only failures and overflow are written to the store, so a burst of
// logouts that succeed costs no writes.
const (
	bcWorkersMax    = 32
	bcQueueMax      = 10_000
	bcOrgQueueMax   = 2_500 // of one organization in the queue
	bcOrgWorkersMax = 8     // senders working for one organization at a time
	bcShutdownWait  = 10 * time.Second
	logoutQueueMax  = 10_000
)

// logoutRetryOrgMax is how many logouts of one organization this node's retry queue holds. An organization whose applications
// never answer (or an emergency sign-out of a big one) fills its share and then loses only its own further logouts,
// where one cap for the whole queue would let it take every place and drop the failures of all the others. The share
// is the size of the in-memory queue's (bcOrgQueueMax), a quarter of the retry queue: four such organizations at once
// are needed to fill it.
const logoutRetryOrgMax = bcOrgQueueMax

// bcOrg is an organization's share of the back-channel logout queue.
type bcOrg struct {
	id      string
	queue   []bcTarget // waiting, oldest first
	sending int        // being sent now
}

// logoutBackoff are the delays before each retry of a failed back-channel logout, the first after the attempt made
// at once.
var logoutBackoff = []time.Duration{5 * time.Second, 30 * time.Second, 5 * time.Minute, 15 * time.Minute, time.Hour}

// LogoutRetry is a back-channel logout waiting in the retry queue: the client is read again for each attempt (one
// since disabled, deleted, or without a back-channel URI any more is not told).
type LogoutRetry struct {
	OrgID    string `json:"o"` // the client's organization: the retry queue gives each a share of its senders
	ClientID string `json:"c"`
	Sub      string `json:"s"`
	SID      string `json:"i,omitempty"`
	JTI      string `json:"j,omitempty"` // the logout's token id, the same for every attempt (see bcTarget)
}

// The retry queue sends by logoutRetryWorkers at once, of which one organization has at most logoutRetryPerOrg: an
// organization whose applications never answer (each retry holds a sender for the 8 s timeout) would otherwise hold
// the one sender it had, and with it every other organization's retried notices, for hours. Retries are background
// work, so eight senders are a quarter of the first attempts' bcWorkersMax; two for each organization leave at least
// six for the others however many applications of one never answer (that organization's own retries then go two per
// 8 s, and its backlog takes longer, which is its own).
const (
	logoutRetryWorkers = 8
	logoutRetryPerOrg  = 2
)

// OpenLogoutQueue opens node's retry queue of failed back-channel logouts, in the service's store (see dispatch).
// Without one a failed logout is logged and not retried.
func (p *Provider) OpenLogoutQueue(node string) *queue.Queue[LogoutRetry] {
	q := queue.Open(queue.Options[LogoutRetry]{
		Name: "logout", Log: p.log, Store: p.svc.Store, Node: node, Sealer: p.svc.Sealer, Binding: "oidc/logout-queue",
		Backoff: logoutBackoff, Max: logoutQueueMax, MaxPerKey: logoutRetryOrgMax,
		Workers: logoutRetryWorkers, PerKey: logoutRetryPerOrg, Key: func(r LogoutRetry) string { return r.OrgID },
		Deliver: func(ctx context.Context, r LogoutRetry) error {
			ce, err := p.recordClient(ctx, r.ClientID)
			if errors.Is(err, store.ErrNotFound) || err == nil && (!ce.c.Enabled || ce.c.BackchannelURI == "") {
				return nil // nobody to tell any more
			} else if err != nil {
				return err
			}
			return p.sendLogoutToken(bcTarget{client: ce.c, sub: r.Sub, sid: r.SID, jti: r.JTI})
		},
		Failed: func(r LogoutRetry, attempt int, retry time.Duration, err error) {
			if retry == 0 {
				metrics.BackchannelFailed.Inc()
				p.log.Warn("oidc: back-channel logout failed, giving up", "client", r.ClientID, "attempts", attempt+1, "error", err)
			}
		},
		Dropped: func() { metrics.BackchannelFailed.Inc() }})
	p.bcRetry = q
	return q
}

func (p *Provider) dispatch(targets []bcTarget) {
	var full []bcTarget
	p.bcMu.Lock()
	for _, t := range targets {
		o := p.bcOrgs[t.client.OrgID]
		if p.bcQueued >= bcQueueMax || o != nil && len(o.queue) >= bcOrgQueueMax {
			full = append(full, t)
			continue
		}
		if o == nil {
			o = &bcOrg{id: t.client.OrgID}
			p.bcOrgs[o.id] = o
		}
		if len(o.queue) == 0 {
			p.bcTurn = append(p.bcTurn, o)
		}
		o.queue = append(o.queue, t)
		p.bcQueued++
		p.bcWG.Add(1)
	}
	for p.bcWorkers < bcWorkersMax && p.bcWorkers < p.bcQueued {
		p.bcWorkers++
		go p.bcWorker()
	}
	if len(full) > 0 {
		p.bcWG.Add(1)
		go p.spill(full)
	}
	p.bcMu.Unlock()
}

// spill hands logouts that found the queue full to the retry queue, away from the caller: each is written to the
// store, which takes a while for many. One that finds its organization's share of the retry queue full (or the
// queue) is lost, counted in the one warning for the whole batch.
func (p *Provider) spill(targets []bcTarget) {
	defer p.bcWG.Done()
	lost := 0
	for _, t := range targets {
		if p.bcRetry == nil || p.bcRetry.Add(t.retry(), logoutBackoff[0], 0) != nil {
			lost++
		}
	}
	metrics.BackchannelFailed.Add(uint64(lost)) // as retryLogout counts one that could not be queued
	p.log.Warn("oidc: back-channel logout queue full: logouts sent later from the retry queue, or not at all if that is full too"+
		" (the sessions ended here all the same)", "logouts", len(targets), "lost", lost, "organization_share", bcOrgQueueMax,
		"queue", bcQueueMax, "retry_organization_share", logoutRetryOrgMax, "retry_queue", logoutQueueMax)
}

// bcWorker sends queued logouts until none can be sent.
func (p *Provider) bcWorker() {
	for {
		o, t, ok := p.bcNext()
		if !ok {
			return
		}
		if err := p.sendLogoutToken(t); err != nil {
			p.retryLogout(t, err)
		}
		p.bcDone(o)
		p.bcWG.Done()
	}
}

// bcNext takes the next logout to send: the oldest of the first organization in turn that has no more than its share
// of senders busy, which then goes to the back of the line. When there is none the sender is no longer counted (one
// finishing for an organization at its limit takes up its next logout itself).
func (p *Provider) bcNext() (*bcOrg, bcTarget, bool) {
	p.bcMu.Lock()
	defer p.bcMu.Unlock()
	for i, o := range p.bcTurn {
		if o.sending >= bcOrgWorkersMax {
			continue
		}
		t := o.queue[0]
		o.queue = o.queue[1:]
		o.sending++
		p.bcQueued--
		p.bcTurn = slices.Delete(p.bcTurn, i, i+1)
		if len(o.queue) > 0 {
			p.bcTurn = append(p.bcTurn, o)
		}
		return o, t, true
	}
	p.bcWorkers--
	return nil, bcTarget{}, false
}

// bcDone ends a logout of o, forgetting the organization when nothing of it is left.
func (p *Provider) bcDone(o *bcOrg) {
	p.bcMu.Lock()
	defer p.bcMu.Unlock()
	o.sending--
	if o.sending == 0 && len(o.queue) == 0 {
		delete(p.bcOrgs, o.id)
	}
}

// retryLogout queues a logout that failed for retrying (see dispatch).
func (p *Provider) retryLogout(t bcTarget, err error) {
	if p.bcRetry != nil {
		qerr := p.bcRetry.Add(t.retry(), logoutBackoff[0], 1)
		if qerr == nil {
			return
		}
		err = fmt.Errorf("%w (not queued for retrying: %v)", err, qerr)
	}
	metrics.BackchannelFailed.Inc()
	p.log.Warn("oidc: back-channel logout failed", "client", t.client.ID, "uri", t.client.BackchannelURI, "error", err)
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
	o.str("iss", p.issuer(t.client.OrgID))
	o.str("sub", t.sub)
	o.str("aud", t.client.ClientID())
	o.num("iat", now.Unix())
	o.num("exp", now.Add(2*time.Minute).Unix())
	jti := t.jti
	if jti == "" {
		jti = newJTI()
	}
	o.str("jti", jti)
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
