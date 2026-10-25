package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Emergency sign-out ("break glass", model/signout.go). Pulling a lever increments a counter on the organization (or,
// for the whole server, on the primary organization): every session, refresh grant and (optionally) personal API
// token stamped before it stops working at once, everywhere, because each use compares its stamp with the counters
// (SignOutCurrent). A sweep then deletes what was ended and tells applications (back-channel logout); it is only
// cleanup, so it runs in the background.

// signOutCacheTTL bounds how long a node trusts the counters it read. Org changes evict them at once on this node and,
// through the cluster's change notices, on the others; the bound covers nodes that share a database without gossip.
const signOutCacheTTL = 5 * time.Second

type signOutCache struct {
	mu      sync.Mutex
	orgs    map[string]cachedCounters
	server  model.SignOutCounters
	hasSrv  bool
	fetched time.Time // of server
}

type cachedCounters struct {
	c       model.SignOutCounters
	fetched time.Time
}

// InvalidateSignOut drops the cached sign-out counters (an organization changed, here or on another node).
func (s *Service) InvalidateSignOut() {
	s.signOut.mu.Lock()
	s.signOut.orgs = nil
	s.signOut.hasSrv = false
	s.signOut.mu.Unlock()
}

// signOutCounters returns the organization's and the server's counters, from the cache when fresh. On a read error
// the last values read are used if there are any: a store hiccup must not sign everyone out.
// signOutMaxStale bounds how long counters read before keep serving while they cannot be read again: a short store
// blip does not fail every token check, but an emergency sign-out made meanwhile is never ignored for longer than
// this. Past it the check fails (the caller answers 503), as the grant and session reads it goes with do.
const signOutMaxStale = 30 * time.Second

func (s *Service) signOutCounters(ctx context.Context, orgID string) (org, server model.SignOutCounters, err error) {
	now := time.Now()
	c := &s.signOut
	c.mu.Lock()
	co, okOrg := c.orgs[orgID]
	srv, okSrv := c.server, c.hasSrv
	srvAt := c.fetched
	c.mu.Unlock()
	if !okOrg || now.Sub(co.fetched) > signOutCacheTTL {
		o, gerr := s.Orgs.Get(ctx, orgID)
		switch {
		case gerr == nil:
			co = cachedCounters{c: o.SignOut, fetched: now}
			c.mu.Lock()
			if c.orgs == nil {
				c.orgs = map[string]cachedCounters{}
			}
			c.orgs[orgID] = co
			c.mu.Unlock()
		case !okOrg || now.Sub(co.fetched) > signOutMaxStale:
			return org, server, gerr
		}
	}
	if !okSrv || now.Sub(srvAt) > signOutCacheTTL {
		p, perr := s.PrimaryOrg(ctx)
		switch {
		case perr == nil:
			srv = p.ServerSignOut
			c.mu.Lock()
			c.server, c.hasSrv, c.fetched = srv, true, now
			c.mu.Unlock()
		case !okSrv || now.Sub(srvAt) > signOutMaxStale:
			return org, server, perr
		}
	}
	return co.c, srv, nil
}

// SessionStamp is the stamp for a session or refresh grant made now in orgID.
func (s *Service) SessionStamp(ctx context.Context, orgID string) (model.SignOutStamp, error) {
	org, srv, err := s.signOutCounters(ctx, orgID)
	return model.SignOutStamp{Server: srv.Sessions, Org: org.Sessions}, err
}

// apiTokenStamp is the stamp for a personal API token made now in orgID.
func (s *Service) apiTokenStamp(ctx context.Context, orgID string) (model.SignOutStamp, error) {
	org, srv, err := s.signOutCounters(ctx, orgID)
	return model.SignOutStamp{Server: srv.APITokens, Org: org.APITokens}, err
}

// SessionCurrent reports whether a session or refresh grant of orgID with stamp st has not been signed out.
// SessionUsable is the one test of whether a session still signs its user in, wherever it is used (a browser
// request, an authorization code or device sign-in redeemed from it): unexpired, its user enabled, made in the
// account's session epoch (model.User.SessionEpoch: not ended by a password reset or a reset of the account's
// sign-in), and not ended by an emergency sign-out (its stamp). u must be the session's user, as recently read. An
// error is the sign-out counters that could not be read: no verdict (the caller answers 503), never "ended".
func (s *Service) SessionUsable(ctx context.Context, sess *model.Session, u *model.User) (bool, error) {
	if ok, err := s.UserUsable(ctx, u); err != nil || !ok {
		return false, err
	}
	want, err := s.SessionStamp(ctx, sess.OrgID)
	if err != nil {
		return false, err
	}
	return SessionUsableAt(sess, u, want), nil
}

// UserUsable is the one test of whether a user may be signed in or act (a browser session, a refresh grant, an access
// or API token): enabled (active, within its dates) and its organization still there. Deleting an organization (or a
// user) deletes that one record: everything that belonged to it stops counting at once, as it stands on its parent,
// and the orphan sweep removes the records later (sweep.go). An error is a read that failed: no verdict.
func (s *Service) UserUsable(ctx context.Context, u *model.User) (bool, error) {
	if !u.Enabled(time.Now()) {
		return false, nil
	}
	if _, err := s.Orgs.Get(ctx, u.OrgID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return false, mapStore(err)
	}
	return true, nil
}

// SessionUsableAt is SessionUsable given the organization's sign-out counters as just read (want), for a caller that
// read them already.
func SessionUsableAt(sess *model.Session, u *model.User, want model.SignOutStamp) bool {
	now := time.Now()
	return sess.UserID == u.ID && sess.Valid(now) && u.Enabled(now) && u.SessionHolds(sess.Epoch) && sess.Stamp.Current(want)
}

func (s *Service) SessionCurrent(ctx context.Context, orgID string, st model.SignOutStamp) bool {
	want, err := s.SessionStamp(ctx, orgID)
	return err == nil && st.Current(want)
}

// SignOutOptions are the choices of an emergency sign-out.
type SignOutOptions struct {
	Reason    string
	APITokens bool // personal API tokens end too
	// KeepSession is the session of whoever pulls the lever (re-stamped, so they are not locked out mid-incident);
	// "" for a command or an API caller.
	KeepSession string
}

// SignOutOrg ends every session and refresh grant of an organization at once (and its personal API tokens with
// opt.APITokens): its administrators and super admins; the primary organization's, which holds the super admins,
// super admins only (its administrators would otherwise sign out, and end the API tokens of, those above them). The
// caller should then run SweepSignOut (in the background).
func (s *Service) SignOutOrg(ctx context.Context, a *Actor, orgID string, opt SignOutOptions) (*model.SignOutEvent, error) {
	if !s.canAdminOrg(a, orgID) {
		return nil, ErrForbidden
	}
	if !a.IsSuper() {
		if p, err := s.PrimaryOrg(ctx); err != nil {
			return nil, mapStore(err)
		} else if p.ID == orgID {
			return nil, ErrForbidden
		}
	}
	return s.pullSignOut(ctx, a, orgID, false, opt)
}

// SignOutServer ends every session and refresh grant of every organization at once (and every personal API token
// with opt.APITokens): super admins only.
func (s *Service) SignOutServer(ctx context.Context, a *Actor, opt SignOutOptions) (*model.SignOutEvent, error) {
	if !a.IsSuper() {
		return nil, ErrForbidden
	}
	p, err := s.PrimaryOrg(ctx)
	if err != nil {
		return nil, mapStore(err)
	}
	return s.pullSignOut(ctx, a, p.ID, true, opt)
}

func (s *Service) pullSignOut(ctx context.Context, a *Actor, orgID string, server bool, opt SignOutOptions) (*model.SignOutEvent, error) {
	reason := strings.TrimSpace(opt.Reason)
	if reason == "" {
		return nil, Invalid("reason", "say why: it is recorded in the audit log")
	}
	if len(reason) > model.MaxSignOutReason {
		return nil, Invalid("reason", "at most "+strconv.Itoa(model.MaxSignOutReason)+" characters")
	}
	ctx = Durable(ctx)
	ev := &model.SignOutEvent{At: time.Now().UTC(), By: a.Name, Reason: reason, APITokens: opt.APITokens}
	var org *model.Org
	for attempt := 0; ; attempt++ {
		o, err := s.Orgs.Get(ctx, orgID)
		if err != nil {
			return nil, mapStore(err)
		}
		c := &o.SignOut
		if server {
			c = &o.ServerSignOut
			o.LastServerSignOut = ev
		} else {
			o.LastSignOut = ev
		}
		c.Sessions++
		if opt.APITokens {
			c.APITokens++
		}
		err = s.Orgs.Update(ctx, o)
		if store.Applied(err) {
			org = o
			break
		}
		if !errors.Is(err, store.ErrStale) || attempt == 4 {
			return nil, mapStore(err)
		}
	}
	s.InvalidateSignOut()
	// Whoever pulled it keeps the session they did it from.
	if opt.KeepSession != "" {
		if sess, err := s.Sessions.Get(ctx, opt.KeepSession); err == nil {
			if sess.Stamp, err = s.SessionStamp(ctx, sess.OrgID); err == nil {
				if err := s.Sessions.Update(ctx, sess); !store.Applied(err) {
					s.Log.WithError(err).Warn("emergency sign-out: could not keep the actor's session", "session", sess.ID)
				}
			}
		}
	}
	action, target, auditOrg := "org.signout", org.Name, org.ID
	if server {
		action, target = "server.signout", "every organization"
	}
	s.Audit(ctx, a, auditOrg, action, target, map[string]string{"reason": reason,
		"api_tokens": strconv.FormatBool(opt.APITokens)})
	return ev, nil
}

// SignOutSweep counts what a sweep removed.
type SignOutSweep struct {
	Sessions, Grants, APITokens int
}

// SweepSignOut deletes the sessions, refresh grants and (with apiTokens) personal API tokens that an emergency sign-out
// ended, in orgID or ("" ) every organization, and tells applications the sessions ended (back-channel logout). They
// stopped working when the lever was pulled; this is cleanup. Credentials made since are left alone.
func (s *Service) SweepSignOut(ctx context.Context, a *Actor, orgID string, apiTokens bool) (SignOutSweep, error) {
	var total SignOutSweep
	var orgs []string
	if orgID != "" {
		orgs = []string{orgID}
	} else {
		for after := ""; ; {
			page, _, err := s.Orgs.List(ctx, store.ListQuery{After: after, Limit: 500})
			if err != nil {
				return total, mapStore(err)
			}
			for _, o := range page {
				orgs = append(orgs, o.ID)
			}
			if len(page) < 500 {
				break
			}
			after = page[len(page)-1].ID
		}
	}
	var errs sweepErrs
	for _, id := range orgs {
		n, err := s.sweepOrg(ctx, id, apiTokens)
		total.Sessions += n.Sessions
		total.Grants += n.Grants
		total.APITokens += n.APITokens
		if err != nil {
			errs.add(err)
		}
	}
	err := errs.err()
	detail := map[string]string{"sessions": strconv.Itoa(total.Sessions), "grants": strconv.Itoa(total.Grants),
		"api_tokens": strconv.Itoa(total.APITokens)}
	if err != nil {
		detail["result"] = "incomplete"
		detail["error"] = err.Error()
		s.Log.WithError(err).Error("emergency sign-out: the sweep did not finish (everything it missed already stopped working)")
	}
	auditOrg, target := orgID, "every organization"
	if orgID != "" {
		if o, gerr := s.Orgs.Get(ctx, orgID); gerr == nil {
			target = o.Name
		}
	} else if p, perr := s.PrimaryOrg(ctx); perr == nil {
		auditOrg = p.ID
	}
	s.Audit(ctx, a, auditOrg, "signout.sweep", target, detail)
	return total, err
}

func (s *Service) sweepOrg(ctx context.Context, orgID string, apiTokens bool) (SignOutSweep, error) {
	var n SignOutSweep
	sess, err := s.SessionStamp(ctx, orgID)
	if err != nil {
		return n, err
	}
	tok, err := s.apiTokenStamp(ctx, orgID)
	if err != nil {
		return n, err
	}
	var errs sweepErrs
	tomb := func(k model.Kind, id string) bool {
		if err := s.Store.Put(Durable(ctx), store.Tombstone(k, id)); !store.Applied(err) && !errors.Is(err, store.ErrStale) {
			errs.add(err)
			return false
		}
		return true
	}
	for after := ""; ; {
		users, _, err := s.Users.List(ctx, store.ListQuery{Scope: orgID, After: after, Limit: 500})
		if err != nil {
			errs.add(err)
			return n, errs.err()
		}
		for _, u := range users {
			sessions, err := s.Sessions.All(ctx, u.ID)
			if err != nil {
				errs.add(err)
				continue
			}
			var ended []string
			for _, x := range sessions {
				if !x.Stamp.Current(sess) {
					ended = append(ended, x.ID)
				}
			}
			if len(ended) > 0 {
				s.sessionsEnding(ctx, u.ID, ended) // back-channel logout, before the records go
				for _, id := range ended {
					if tomb(model.KindSession, id) {
						n.Sessions++
					}
				}
			}
			grants, err := s.Grants.All(ctx, u.ID)
			if err != nil {
				errs.add(err)
			}
			for _, g := range grants {
				if !g.Stamp.Current(sess) && tomb(model.KindGrant, g.ID) {
					n.Grants++
				}
			}
			if apiTokens {
				tokens, err := s.APITokens.All(ctx, u.ID)
				if err != nil {
					errs.add(err)
				}
				for _, t := range tokens {
					if !t.Stamp.Current(tok) && tomb(model.KindAPIToken, t.ID) {
						n.APITokens++
					}
				}
			}
		}
		if len(users) < 500 {
			break
		}
		after = users[len(users)-1].ID
	}
	return n, errs.err()
}

// sweepErrs counts a sweep's failures and keeps the first few: a store failing every write of a sweep over a
// million records must not become a million-error message (and audit detail).
type sweepErrs struct {
	n     int
	first []error
}

func (e *sweepErrs) add(err error) {
	if err == nil {
		return
	}
	e.n++
	if len(e.first) < 5 {
		e.first = append(e.first, err)
	}
}

func (e *sweepErrs) err() error {
	if e.n == 0 {
		return nil
	}
	if e.n > len(e.first) {
		return fmt.Errorf("%d failures, the first %d: %w", e.n, len(e.first), errors.Join(e.first...))
	}
	return errors.Join(e.first...)
}

// Background runs f on its own goroutine with a context that outlives the request; WaitBackground waits for every
// such run (tests, shutdown).
func (s *Service) Background(ctx context.Context, f func(ctx context.Context)) {
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		f(context.WithoutCancel(ctx))
	}()
}

// WaitBackground waits for the work started with Background.
func (s *Service) WaitBackground() { s.bg.Wait() }
