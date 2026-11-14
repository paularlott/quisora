package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
	pid, err := s.PrimaryOrgID(ctx)
	if err != nil {
		return org, server, err
	}
	p, err := s.Org(ctx, pid)
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
// passkey): no verdict (the caller answers 503), never "ended". A guest's session stands on the accounts it came from
// too (model.Session.Sources, SourcesHold), read from the store here: SessionUsableWith reads them through the
// caller's cache.
func (s *Service) SessionUsable(ctx context.Context, sess *model.Session, u *model.User) (bool, error) {
	return s.SessionUsableWith(ctx, sess, u, s.storeUser)
}

// SessionUsableWith is SessionUsable reading the users a guest's session stands on with users.
func (s *Service) SessionUsableWith(ctx context.Context, sess *model.Session, u *model.User, users UserGetter) (bool, error) {
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
	if ok, err := s.SourcesHold(ctx, sess.Sources, users); err != nil || !ok {
		return false, err
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

// EndSession revokes session sess with everything it gave (EndSessions), and reports whether the session itself ended.
func (s *Service) EndSession(ctx context.Context, sess *model.Session) (ended bool, err error) {
	n, err := s.EndSessions(ctx, sess.UserID, []*model.Session{sess})
	return n == 1, err
}

// SignOutSession is the user signing session sess out themselves (the sign-out page, an application's RP-initiated
// logout, another user signing in in the same browser): the session ends with the grants that last only as long as it
// does (no offline_access), while those granted offline access go on (to their own expiry), and so do the SSH
// certificates it was used for, like the access tokens it issued. Revoking a session (EndSession) ends them all. It
// reports whether the session itself ended.
func (s *Service) SignOutSession(ctx context.Context, sess *model.Session) (ended bool, err error) {
	n, err := s.endSessions(ctx, sess.UserID, []*model.Session{sess}, true)
	return n == 1, err
}

// EndSessions ends sessions, all of userID, with their refresh grants: the grants first, then each session, only while
// it is as read (its version). A grant made meanwhile changed its session in the same transaction
// (CreateSessionGrant), so that session's deletion is refused as stale, and the sessions so refused are read again and
// their grants listed again: none is left behind by a revocation that reports success. The user's grants are listed
// once a round, whatever the number of sessions. Every deletion is attempted even when one fails (a session a
// compromised passkey signed in ends whatever its grants do), and the failures are returned together; ended counts
// the sessions that ended (one already gone included). It revokes: every grant goes, offline access or not, and the
// SSH certificates issued under the sessions or their grants are revoked once they are deleted (RevokeSSHCertsFrom).
func (s *Service) EndSessions(ctx context.Context, userID string, sessions []*model.Session) (ended int, err error) {
	return s.endSessions(ctx, userID, sessions, false)
}

// endSessions is EndSessions, or with signOut the sessions' own sign-out (SignOutSession): the grants with offline
// access and the SSH certificates are left.
func (s *Service) endSessions(ctx context.Context, userID string, sessions []*model.Session, signOut bool) (ended int, err error) {
	var errs []error
	// The sign-ins whose SSH certificates are revoked: the sessions and the grants ended with them. They are revoked
	// after the deletions, never before. A certificate signed at the same moment is created, and then its sign-in read
	// again from the store (SignUserSSH); here the sign-in is deleted, and then the certificates listed. On a shared
	// database, or a single node, whichever comes second sees the other: the listing finds a certificate created before
	// the deletion, and a certificate created after it finds its sign-in gone and is revoked by its signer. In a gossip
	// cluster each node reads its own copy, so the two can miss each other while either write is replicating: such a
	// certificate is revoked by the record of its sign-in taken back (RevokeSSHCertsFrom) once both have replicated.
	// Revoking first would leave it open for the seconds a node still trusts its cached copy of the session or grant
	// (one signed between the listing and the deletion would be missed).
	from := map[string]bool{}
	pending := sessions
	for attempt := 0; len(pending) > 0; attempt++ {
		ids := make(map[string]bool, len(pending))
		for _, ss := range pending {
			ids[ss.ID] = true
			from[ss.ID] = true
		}
		grants, err := s.Grants.All(ctx, userID)
		if err != nil {
			errs = append(errs, fmt.Errorf("list refresh grants: %w", mapStore(err)))
		}
		ending := func(g *model.Grant) bool {
			return ids[g.SessionID] && !(signOut && slices.Contains(g.Scopes, "offline_access"))
		}
		for _, g := range grants {
			if ending(g) {
				from[g.ID] = true
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
	if !signOut && len(sessions) > 0 {
		if err := s.RevokeSSHCertsFrom(ctx, sessions[0].OrgID, userID, from); err != nil {
			errs = append(errs, fmt.Errorf("revoke SSH certificates: %w", err))
		}
	}
	return ended, errors.Join(errs...)
}

// SessionsPerUser is how many browser sessions one user may hold at once: limits.sessions_per_user (100 by default).
func (s *Service) SessionsPerUser() int { return s.Cfg.LiveLimits().SessionsPerUser }

// maxEvictions is how many sessions one CapSessions run ends at most: a cap lowered below what users hold is reached
// over their next few sign-ins, a bounded amount of work each, instead of by one sign-in's background work running past
// its time.
const maxEvictions = 100

// CapSessions ends user u's browser sessions past the cap (SessionsPerUser), the least recently used first, and
// returns how many it ended. Each sign-in in a browser without a session makes one, and every listing of the user's
// sessions (their account page, sign out everywhere, an administrator's revoke) reads them all: without a cap a script
// signing in over and over would leave the account with thousands, until they expire. A sign-in is never refused for
// the cap: the newest sessions are kept, so nobody is locked out by sessions of their own they forgot.
//
// It never ends keep (the session the sign-in just made), nor any session signed in at the same moment or later
// (AuthTime): those are other sign-ins', each capped by its own run. So sign-ins at once, more of them than the cap,
// cannot end each other's sessions, leaving none: the latest is always kept, and the user may stay a few past the cap
// until their next sign-in counts again.
//
// Only live sessions count (model.Session.Valid: neither expired nor idle too long); dead ones sign nobody in, and the
// store drops them at their end of life. Those past the cap end one at a time as a sign-out ends a session
// (SignOutSession, after the OnSessionsEnding hook tells their applications by back-channel logout, as the sign-out
// page does): their refresh grants without offline_access go with them, as when a session expires, while those
// granted offline access and the SSH certificates go on; nothing else of the user is touched. Each session ended is
// audited (login.session.evict). At most maxEvictions end in one run, and the run stops when ctx ends: the rest end at
// the user's next sign-in, and no application is told of a session that is not then being ended.
//
// The count is the store's as this node reads it: in a gossip cluster, sign-ins on several nodes at once can take the
// user a few past the cap until the next sign-in counts again. Each deletion holds only while the session is as read
// (EndSessions), so a refresh grant made on it meanwhile is found and ended with it.
func (s *Service) CapSessions(ctx context.Context, u *model.User, keep *model.Session) (int, error) {
	limit := s.SessionsPerUser()
	if limit <= 0 {
		return 0, nil
	}
	all, err := s.Sessions.All(ctx, u.ID)
	if err != nil {
		return 0, mapStore(err)
	}
	now := time.Now()
	live := slices.DeleteFunc(all, func(x *model.Session) bool { return !x.Valid(now) })
	if len(live) <= limit {
		return 0, nil
	}
	slices.SortFunc(live, func(a, b *model.Session) int { // least recently used first; then the earliest signed in
		if c := a.LastSeen.Compare(b.LastSeen); c != 0 {
			return c
		}
		return a.AuthTime.Compare(b.AuthTime)
	})
	excess := min(len(live)-limit, maxEvictions)
	var victims []*model.Session
	for _, x := range live {
		if len(victims) == excess {
			break
		}
		if x.ID != keep.ID && x.AuthTime.Before(keep.AuthTime) {
			victims = append(victims, x)
		}
	}
	ended := 0
	var errs []error
	for _, x := range victims {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		s.sessionsEnding(ctx, u.ID, []string{x.ID}) // back-channel logout, before the record goes
		n, err := s.endSessions(ctx, u.ID, []*model.Session{x}, true)
		if err != nil {
			errs = append(errs, err)
		}
		if n == 0 {
			continue
		}
		ended++
		detail := map[string]string{"ip": x.IP, "signed_in": x.AuthTime.UTC().Format(time.RFC3339),
			"last_seen": x.LastSeen.UTC().Format(time.RFC3339), "cap": strconv.Itoa(limit), "result": "ended"}
		if err != nil {
			detail["error"] = err.Error() // the session ended; a refresh grant of it did not
		}
		s.AuditUser(ctx, System, u, "login.session.evict", detail)
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

// Background timeouts: a touch or a single write, and a sign-out sweep that deletes every ended record of an
// organization and tells applications.
const (
	BackgroundShort = 10 * time.Second
	BackgroundSweep = 10 * time.Minute
)

// Background runs f on its own goroutine with a context that outlives the request but ends after timeout; WaitBackground
// waits for every such run (tests, shutdown). The deadline keeps a stalled store (a standalone store's commit waits
// on its context only) from piling up one goroutine per request for as long as the stall lasts.
func (s *Service) Background(ctx context.Context, timeout time.Duration, f func(ctx context.Context)) {
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()
		f(ctx)
	}()
}

// WaitBackground waits for the work started with Background.
func (s *Service) WaitBackground() { s.bg.Wait() }
