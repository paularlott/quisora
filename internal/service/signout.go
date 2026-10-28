package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Emergency sign-out ("break glass", model/signout.go). Pulling a lever increments a counter on the organization (or,
// for the whole server, on the primary organization): every session, refresh grant and (optionally) personal API
// token stamped before it stops working at once, everywhere, because each use compares its stamp with the counters
// (SignOutCurrent). A sweep then deletes what was ended and tells applications (back-channel logout); it is only
// cleanup, so it runs in the background.

// signOutCounters returns the organization's counters and the server's (the primary organization's ServerSignOut) as
// Org reads them: no older than its bound (orgTTL), or the store's error, which the caller answers as no verdict (503):
// counters an emergency sign-out may have moved are never served past that bound, nor guessed.
func (s *Service) signOutCounters(ctx context.Context, orgID string) (org, server model.SignOutCounters, err error) {
	o, err := s.Org(ctx, orgID)
	if err != nil {
		return org, server, err
	}
	p, err := s.Org(ctx, model.PrimaryOrgID)
	if err != nil {
		return org, server, err
	}
	return o.SignOut, p.ServerSignOut, nil
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
// sign-in), not ended by an emergency sign-out (its stamp), and, signed in with a passkey, that passkey still the
// user's and still able to sign in (model.Passkey.Usable: not disabled by a detected clone): a session stands on the
// passkey it was signed in with, so removing or disabling it ends the session wherever and whenever it was made (a
// sign-in verified before the removal and finished after it, a session the removal's listing did not see yet). u must be the session's user, as recently read. An error is a read that failed (the sign-out counters, the
// passkey): no verdict (the caller answers 503), never "ended".
func (s *Service) SessionUsable(ctx context.Context, sess *model.Session, u *model.User) (bool, error) {
	if ok, err := s.UserUsable(ctx, u); err != nil || !ok {
		return false, err
	}
	want, err := s.SessionStamp(ctx, sess.OrgID)
	if err != nil {
		return false, err
	}
	if !SessionUsableAt(sess, u, want) {
		return false, nil
	}
	if sess.Passkey != "" {
		pk, err := s.Passkeys.Get(ctx, sess.Passkey)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, mapStore(err)
		}
		if pk.UserID != u.ID || !pk.Usable() {
			return false, nil
		}
	}
	return true, nil
}

// CreateSessionGrant writes g, a refresh grant carrying on session sess, in one transaction with a write of sess
// unchanged that holds only while sess is as it was read (its version): the grant is made only while the session it
// was checked on stands as checked, and a revocation of the session that listed its grants before (EndSession) finds
// the session changed and lists them again, so no grant outlives a revocation that reported success. ErrStale: the
// grant exists already (an earlier attempt of the same exchange made it), or the session changed since it was read
// (read it and check it again).
func (s *Service) CreateSessionGrant(ctx context.Context, g *model.Grant, sess *model.Session) error {
	if g.SessionID != sess.ID || g.OrgID != sess.OrgID {
		return fmt.Errorf("%w: a grant of another session", ErrInvalid)
	}
	expect := sess.Version // (Encode stamps a new one)
	gr, err := store.Encode(g)
	if err == nil {
		var sr *store.Record
		if sr, err = store.Encode(sess); err == nil {
			if err = s.Grants.S.Tx(ctx, []store.Op{{Rec: gr, Match: true}, {Rec: sr, Match: true, Expect: expect}}); err == nil {
				g.Version, sess.Version = gr.Version, sr.Version
				return nil
			}
		}
	}
	g.Version, sess.Version = 0, expect
	return err
}

// EndSession ends session sess with its refresh grants (EndSessions), and reports whether the session itself ended.
func (s *Service) EndSession(ctx context.Context, sess *model.Session) (ended bool, err error) {
	n, err := s.EndSessions(ctx, sess.UserID, []*model.Session{sess})
	return n == 1, err
}

// EndSessions ends sessions, all of userID, with their refresh grants: the grants first, then each session, only while
// it is as read (its version). A grant made meanwhile changed its session in the same transaction
// (CreateSessionGrant), so that session's deletion is refused as stale, and the sessions so refused are read again and
// their grants listed again: none is left behind by a revocation that reports success. The user's grants are listed
// once a round, whatever the number of sessions. Every deletion is attempted even when one fails (a session a
// compromised passkey signed in ends whatever its grants do), and the failures are returned together; ended counts
// the sessions that ended (one already gone included).
func (s *Service) EndSessions(ctx context.Context, userID string, sessions []*model.Session) (ended int, err error) {
	var errs []error
	pending := sessions
	for attempt := 0; len(pending) > 0; attempt++ {
		ids := make(map[string]bool, len(pending))
		for _, ss := range pending {
			ids[ss.ID] = true
		}
		grants, err := s.Grants.All(ctx, userID)
		if err != nil {
			errs = append(errs, fmt.Errorf("list refresh grants: %w", mapStore(err)))
		}
		for _, g := range grants {
			if ids[g.SessionID] {
				if err := s.Grants.Delete(ctx, g.ID); err != nil && !errors.Is(err, store.ErrStale) {
					errs = append(errs, fmt.Errorf("end refresh grant %s: %w", g.ID, mapStore(err)))
				}
			}
		}
		var again []*model.Session
		for _, ss := range pending {
			err := s.Sessions.DeleteIf(ctx, ss.ID, ss.Version)
			switch {
			case err == nil || errors.Is(err, store.ErrNotFound):
				ended++
				continue
			case !errors.Is(err, store.ErrStale) || attempt == 4:
				errs = append(errs, fmt.Errorf("end session %s: %w", ss.ID, mapStore(err)))
				continue
			}
			// Changed since it was read (a grant made, a sign-in noted): read it again, and its grants next round.
			cur, err := s.Sessions.Get(ctx, ss.ID)
			switch {
			case errors.Is(err, store.ErrNotFound):
				ended++
			case err != nil:
				errs = append(errs, fmt.Errorf("end session %s: %w", ss.ID, mapStore(err)))
			default:
				again = append(again, cur)
			}
		}
		pending = again
	}
	return ended, errors.Join(errs...)
}

// UserUsable is the one test of whether a user may be signed in or act (a browser session, a refresh grant, an access
// or API token): enabled (active, within its dates) and its organization still there. Deleting an organization (or a
// user) deletes that one record: everything that belonged to it stops counting at once, as it stands on its parent,
// and the orphan sweep removes the records later (sweep.go). An error is a read that failed: no verdict.
//
// The organization is read through its cache (Org): this runs on every authenticated request, and organizations are
// in the cluster's one global partition, so an uncached read would make every session check, token check and refresh
// of every organization wait on that partition, and fail while it changes owner. A deletion counts at once on the node
// that made it (the cache is cleared) and within the cache's 5 s elsewhere.
func (s *Service) UserUsable(ctx context.Context, u *model.User) (bool, error) {
	if !u.Enabled(time.Now()) {
		return false, nil
	}
	if _, err := s.Org(ctx, u.OrgID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
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
	by := a.Name
	if cmd, _ := ctx.Value(commandKey{}).(commandInfo); cmd.name != "" && a == System { // as the audit log names it
		by = "command:" + cmd.name
	}
	ev := &model.SignOutEvent{At: time.Now().UTC(), By: by, Reason: reason, APITokens: opt.APITokens}
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
		if errors.Is(err, store.ErrStale) && attempt < 4 {
			continue
		}
		action, target := "org.signout", o.Name
		if server {
			action, target = "server.signout", "every organization"
		}
		s.auditOutcome(ctx, a, err, change{o.ID, action, target, map[string]string{"reason": reason,
			"api_tokens": strconv.FormatBool(opt.APITokens)}, nil})
		if err != nil {
			return nil, mapStore(err)
		}
		break
	}
	// The lever counts on this node at once; the other nodes hear of the change (InvalidateOrgs), or count it within
	// orgTTL whatever.
	s.InvalidateOrgs()
	// Whoever pulled it keeps the session they did it from.
	if opt.KeepSession != "" {
		if sess, err := s.Sessions.Get(ctx, opt.KeepSession); err == nil {
			if sess.Stamp, err = s.SessionStamp(ctx, sess.OrgID); err == nil {
				if err := s.Sessions.Update(ctx, sess); err != nil {
					s.Log.WithError(err).Warn("emergency sign-out: could not keep the actor's session", "session", sess.ID)
				}
			}
		}
	}
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

// A sign-out sweep writes its removals in transactions of up to signOutSweepBatch (everything it removes in one
// organization is that organization's, so one transaction holds any of them), one at a time across every organization,
// with a pause of signOutSweepGap after each: at most 10,000 removals a second. The sweep is cleanup (everything it
// ends stopped working when the lever was pulled), so it is paced: a sweep that wrote as fast as the store answers
// would keep the store busy for its whole run and queue every sign-in behind it. Variables for tests.
var (
	signOutSweepBatch = 100
	signOutSweepGap   = 10 * time.Millisecond
)

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
	var batch []store.Op
	var pending SignOutSweep // what batch removes
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := ctx.Err(); err != nil { // cancelled: what is left is found by the next sweep
			errs.add(err)
		} else if err := s.Store.Tx(ctx, batch); err != nil {
			errs.add(err)
		} else {
			n.Sessions += pending.Sessions
			n.Grants += pending.Grants
			n.APITokens += pending.APITokens
		}
		batch, pending = nil, SignOutSweep{}
		pause(ctx, signOutSweepGap)
	}
	tomb := func(k model.Kind, id string, count *int) {
		batch = append(batch, store.Op{Rec: store.Tombstone(k, id)})
		*count++
		if len(batch) >= signOutSweepBatch {
			flush()
		}
	}
	for after := ""; ; {
		users, _, err := s.Users.List(ctx, store.ListQuery{Scope: orgID, After: after, Limit: 500})
		if err != nil {
			errs.add(err)
			flush()
			return n, errs.err()
		}
		for _, u := range users {
			if err := ctx.Err(); err != nil { // cancelled (the server is stopping): what is left is found by the next sweep
				errs.add(err)
				return n, errs.err()
			}
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
					tomb(model.KindSession, id, &pending.Sessions)
				}
			}
			grants, err := s.Grants.All(ctx, u.ID)
			if err != nil {
				errs.add(err)
			}
			for _, g := range grants {
				if !g.Stamp.Current(sess) {
					tomb(model.KindGrant, g.ID, &pending.Grants)
				}
			}
			if apiTokens {
				tokens, err := s.APITokens.All(ctx, u.ID)
				if err != nil {
					errs.add(err)
				}
				for _, t := range tokens {
					if !t.Stamp.Current(tok) {
						tomb(model.KindAPIToken, t.ID, &pending.APITokens)
					}
				}
			}
		}
		if len(users) < 500 {
			break
		}
		after = users[len(users)-1].ID
	}
	flush()
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
