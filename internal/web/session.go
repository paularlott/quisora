package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/paularlott/quisora/internal/evictgen"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// SessionCookie is the browser session cookie. The __Host- prefix pins it to this origin over HTTPS.
const SessionCookie = "__Host-quisora_session"

const (
	sessionCacheTTL   = 5 * time.Second
	lastSeenThrottle  = 5 * time.Minute
	sessionCacheLimit = 100_000
)

// cachedSession is never changed once it is in the cache (lookups read it without the lock): a newer copy of the
// session replaces the whole entry.
type cachedSession struct {
	sess    *model.Session
	user    *model.User
	fetched time.Time
}

// Sessions creates, looks up and ends browser sessions. Lookups are cached per node for a short time; Evict is
// called when this node hears that a session or user record changed.
type Sessions struct {
	// CacheTTL bounds how long a node trusts a cached session (default 5s): a change made elsewhere counts here within
	// it, whatever the store; one this node hears of (Evict) counts at once.
	CacheTTL time.Duration
	svc      *service.Service
	mu       sync.RWMutex
	cache    map[string]*cachedSession
	byUser   map[string]map[string]struct{} // user id -> cached session ids, so evicting a user is O(their sessions)
	swept    time.Time                      // when entries past CacheTTL were last dropped (mu)
	// gens: a fill that began before an eviction is not stored after it (evictgen). Keys: the session id, and "u:" and
	// the user id for evictions of a user.
	gens     evictgen.Gens
	touching sync.Map // session ids whose last use is being recorded: one write at a time per session
}

func NewSessions(svc *service.Service) *Sessions {
	return &Sessions{CacheTTL: sessionCacheTTL, svc: svc, cache: map[string]*cachedSession{}, byUser: map[string]map[string]struct{}{}}
}

// Evict drops a cached session (by session id) — and, given a user id, every cached session of that user.
func (m *Sessions) Evict(sessionID, userID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sessionID != "" {
		m.gens.Bump(sessionID)
		m.drop(sessionID)
	}
	if userID != "" {
		m.gens.Bump("u:" + userID)
	}
	for id := range m.byUser[userID] {
		m.drop(id)
	}
}

// drop removes one cached session; the lock must be held.
func (m *Sessions) drop(id string) {
	cs, ok := m.cache[id]
	if !ok {
		return
	}
	delete(m.cache, id)
	if set := m.byUser[cs.user.ID]; set != nil {
		delete(set, id)
		if len(set) == 0 {
			delete(m.byUser, cs.user.ID)
		}
	}
}

// SessionOptions are the optional facts of a sign-in recorded on the session.
type SessionOptions struct {
	AMR      []string
	Provider string // upstream provider id for federated sign-ins
	Passkey  string // passkey id, when a passkey was used
}

// Create starts a session for u after a successful sign-in and sets the cookie.
func (m *Sessions) Create(ctx context.Context, w http.ResponseWriter, r *http.Request, u *model.User, org *model.Org,
	amr []string) (*model.Session, error) {
	return m.CreateWith(ctx, w, r, u, org, SessionOptions{AMR: amr})
}

// CreateWith is Create with extra options (the upstream provider).
func (m *Sessions) CreateWith(ctx context.Context, w http.ResponseWriter, r *http.Request, u *model.User, org *model.Org,
	opt SessionOptions) (*model.Session, error) {
	amr := opt.AMR
	now := time.Now().UTC()
	ttl, idle := m.lifetime(org, u)
	raw := secure.RandomToken(32)
	s := &model.Session{Meta: model.Meta{ID: SessionID(raw)}, UserID: u.ID, OrgID: u.OrgID, AMR: amr, Epoch: u.SessionEpoch,
		AuthTime: now, Expires: now.Add(time.Duration(ttl) * time.Second), IdleTTL: idle, LastSeen: now, Provider: opt.Provider, Passkey: opt.Passkey,
		IP: ClientIP(r), UserAgent: truncate(r.UserAgent(), 300), CSRF: secure.RandomToken(24)}
	stamp, err := m.svc.SessionStamp(ctx, u.OrgID)
	if err != nil {
		return nil, err
	}
	s.Stamp = stamp
	if err := m.svc.Sessions.Create(ctx, s); err != nil {
		return nil, err
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: raw, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Expires: s.Expires})
	return s, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Current returns the request's valid session and active user, or nil, nil.
func (m *Sessions) Current(r *http.Request) (*model.Session, *model.User) {
	s, u, _ := m.Check(r)
	return s, u
}

// Check is Current that also says when the session could not be checked: the error is the store's refusal
// (store.ErrUnavailable), no verdict, and the session and user are then nil.
func (m *Sessions) Check(r *http.Request) (*model.Session, *model.User, error) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || len(c.Value) < 20 || len(c.Value) > 100 {
		return nil, nil, nil
	}
	s, u, err := m.lookup(r.Context(), SessionID(c.Value))
	if s == nil || !cookieMatches(s, c.Value) {
		return nil, nil, err
	}
	return s, u, nil
}

// cookieMatches checks the secret part of an upgraded session's cookie ("<id>.<secret>"); a session never upgraded
// takes only its original cookie (whose hash is its id), an upgraded one only its current cookie.
func cookieMatches(s *model.Session, cookie string) bool {
	_, secret, upgraded := strings.Cut(cookie, ".")
	if !upgraded {
		return len(s.CookieHash) == 0
	}
	return len(s.CookieHash) > 0 && secure.EqualSecret(secret, s.CookieHash)
}

// SessionID derives the stored session id from the cookie value. Only the hash of the original cookie is stored
// (and appears as "sid" in tokens), so a copy of the database or a token never yields a usable session cookie. An
// upgraded session's cookie is "<id>.<secret>" (Upgrade): its id is the part before the dot, and only the hash of
// the secret is stored.
func SessionID(cookie string) string {
	if id, _, ok := strings.Cut(cookie, "."); ok {
		return id
	}
	return base64.RawURLEncoding.EncodeToString(secure.HashSecret(cookie))
}

// Upgrade records a new sign-in of the same user on their existing session (a re-authentication for prompt=login,
// max_age, a second factor, or signing in again): the sign-in time, methods and provider are the new ones, the
// lifetime starts again, and the browser gets a new cookie value (the old one stops working: no session fixation).
// The session id, and so the refresh grants made in it and the "sid" applications know it by, stay. It returns
// the upgraded session; the caller makes a new session instead when it cannot be upgraded.
func (m *Sessions) Upgrade(ctx context.Context, w http.ResponseWriter, r *http.Request, old *model.Session, u *model.User,
	org *model.Org, opt SessionOptions) (*model.Session, error) {
	if old.UserID != u.ID {
		return nil, errors.New("web: a session is upgraded only by its own user")
	}
	ttl, idle := m.lifetime(org, u)
	secret := secure.RandomToken(32)
	for range 5 {
		s, err := m.svc.Sessions.Get(ctx, old.ID)
		if err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		s.AMR, s.AuthTime, s.Provider, s.Passkey = opt.AMR, now, opt.Provider, opt.Passkey
		s.Expires, s.IdleTTL, s.LastSeen = now.Add(time.Duration(ttl)*time.Second), idle, now
		s.IP, s.UserAgent, s.CSRF = ClientIP(r), truncate(r.UserAgent(), 300), secure.RandomToken(24)
		s.CookieHash = secure.HashSecret(secret)
		err = m.svc.Sessions.Update(ctx, s)
		if errors.Is(err, store.ErrStale) {
			continue
		}
		if err != nil {
			return nil, err
		}
		m.Evict(s.ID, "")
		http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: s.ID + "." + secret, Path: "/", Secure: true, HttpOnly: true,
			SameSite: http.SameSiteLaxMode, Expires: s.Expires})
		return s, nil
	}
	return nil, store.ErrStale
}

// lifetime is the session lifetime and idle timeout (seconds) of u in org: the organization's, never longer than
// the server's (session.ttl, session.idle), and for managers and above never longer than session.privileged_ttl and
// session.privileged_idle. An idle timeout of 0 is none.
func (m *Sessions) lifetime(org *model.Org, u *model.User) (ttl, idle int) {
	cfg := m.svc.Cfg.Session
	ttl, idle = cfg.TTL, cfg.Idle
	if org != nil && org.Settings.SessionTTL > 0 {
		ttl = min(org.Settings.SessionTTL, ttl)
	}
	if org != nil && org.Settings.SessionIdle > 0 && (idle == 0 || org.Settings.SessionIdle < idle) {
		idle = org.Settings.SessionIdle
	}
	if u != nil && u.Role.Privileged() {
		if cfg.PrivilegedTTL > 0 {
			ttl = min(ttl, cfg.PrivilegedTTL)
		}
		if cfg.PrivilegedIdle > 0 && (idle == 0 || cfg.PrivilegedIdle < idle) {
			idle = cfg.PrivilegedIdle
		}
	}
	return ttl, idle
}

// Lookup returns a valid session and its active user by stored session id (see SessionID).
func (m *Sessions) Lookup(ctx context.Context, id string) (*model.Session, *model.User) {
	s, u, _ := m.lookup(ctx, id)
	return s, u
}

// lookup is Lookup that also returns the store's refusal (store.ErrUnavailable) when it could not check the session.
func (m *Sessions) lookup(ctx context.Context, id string) (*model.Session, *model.User, error) {
	now := time.Now()
	m.mu.RLock()
	cs := m.cache[id]
	m.mu.RUnlock()
	// An emergency sign-out ends a session whose stamp is no longer current (service/signout.go). A cached copy may
	// predate the session's re-stamping (the one the lever was pulled from is kept), so it is read again before
	// being refused.
	if cs != nil && now.Sub(cs.fetched) <= m.CacheTTL && !m.svc.SessionCurrent(ctx, cs.sess.OrgID, cs.sess.Stamp) {
		cs = nil
	}
	if cs == nil || now.Sub(cs.fetched) > m.CacheTTL {
		sessTok := m.gens.Token(id)
		s, err := m.svc.Sessions.Get(ctx, id)
		if err != nil {
			m.Evict(id, "")
			return nil, nil, refused(err)
		}
		userTok := m.gens.Token("u:" + s.UserID)
		u, err := m.svc.Users.Get(ctx, s.UserID)
		if err != nil {
			return nil, nil, refused(err)
		}
		cs = &cachedSession{sess: s, user: u, fetched: now}
		m.fill(id, cs, sessTok, userTok)
	}
	if ok, err := m.svc.SessionUsable(ctx, cs.sess, cs.user); !ok {
		return nil, nil, refused(err)
	}
	if now.Sub(cs.sess.LastSeen) > lastSeenThrottle {
		m.touchLater(ctx, cs)
	}
	return cs.sess, cs.user, nil
}

// refused keeps err only when it is the store's refusal (store.ErrUnavailable): anything else (the session or user
// gone, a record that does not decode) is no session.
func refused(err error) error {
	if errors.Is(err, store.ErrUnavailable) || errors.Is(err, service.ErrUnavailable) {
		return err
	}
	return nil
}

// fill puts cs, read from the store, in the cache and makes room for it, unless the session or its user was evicted
// since the tokens were taken (before the reads): what was read may predate the change that evicted it. It is then
// served to the request that read it, as a read made a moment earlier would have been, and not kept.
func (m *Sessions) fill(id string, cs *cachedSession, sessTok, userTok uint64) {
	now, u := cs.fetched, cs.user
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.gens.Valid(id, sessTok) || !m.gens.Valid("u:"+u.ID, userTok) {
		return
	}
	if now.Sub(m.swept) > m.CacheTTL {
		// Entries past CacheTTL are read afresh anyway: dropped once a period, so the cache holds the sessions in
		// use, not sessionCacheLimit of them.
		m.swept = now
		for k, c := range m.cache {
			if now.Sub(c.fetched) > m.CacheTTL {
				m.drop(k)
			}
		}
	}
	if len(m.cache) >= sessionCacheLimit {
		for k := range m.cache { // drop an arbitrary tenth; cheap and bounded
			m.drop(k)
			if len(m.cache) < sessionCacheLimit*9/10 {
				break
			}
		}
	}
	m.drop(id)
	m.cache[id] = cs
	set := m.byUser[u.ID]
	if set == nil {
		set = map[string]struct{}{}
		m.byUser[u.ID] = set
	}
	set[id] = struct{}{}
}

// touchLater records that the session is in use, in the background: the request does not wait for a write it does
// not need. One write at a time per session: a request that finds one running skips it, and the next one that finds
// the stamp old tries again.
func (m *Sessions) touchLater(ctx context.Context, cs *cachedSession) {
	id := cs.sess.ID
	if _, busy := m.touching.LoadOrStore(id, struct{}{}); busy {
		return
	}
	m.svc.Background(ctx, func(ctx context.Context) {
		defer m.touching.Delete(id)
		m.touch(ctx, cs)
	})
}

// touch writes the session's last use (best effort: a lost race or a failed write only delays it). It replaces the
// cached entry with the written copy unless that was evicted or replaced meanwhile.
func (m *Sessions) touch(ctx context.Context, cs *cachedSession) {
	s := *cs.sess
	s.LastSeen = time.Now().UTC()
	if err := m.svc.Sessions.Update(ctx, &s); err != nil {
		return
	}
	m.mu.Lock()
	if m.cache[s.ID] == cs { // not evicted or replaced meanwhile
		m.cache[s.ID] = &cachedSession{sess: &s, user: cs.user, fetched: cs.fetched}
	}
	m.mu.Unlock()
}

// End deletes the request's session and clears the cookie. The error is Delete's: a session (or a refresh grant of
// it) that could not be deleted still works for whoever holds it, so the caller tells the user the sign-out did not
// finish rather than that they are signed out. The cookie then stays while the session record does: the user is
// told to try again, and the retry needs it to find the session to end (a cookie cleared over a session left alive
// would leave it, and its grants, running until they expire with no way to end them from this browser).
func (m *Sessions) End(ctx context.Context, w http.ResponseWriter, r *http.Request) (*model.Session, error) {
	clear := func() {
		http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", Secure: true, HttpOnly: true,
			SameSite: http.SameSiteLaxMode, MaxAge: -1})
	}
	sess, _ := m.Current(r)
	if sess == nil {
		clear()
		return nil, nil
	}
	err := m.Delete(ctx, sess.ID)
	if err == nil {
		clear()
		return sess, nil
	}
	if _, gerr := m.svc.Sessions.Get(ctx, sess.ID); errors.Is(gerr, store.ErrNotFound) {
		clear() // the session itself went; only a refresh grant of it did not (reported)
	}
	return sess, err
}

// Delete ends a session by id, with its refresh grants (service.EndSession): a grant made with offline_access outlives
// its session, so one left behind would keep refreshing after a sign-out that reported success, and one an exchange
// makes while the session ends is found too. (A grant without it dies with the session, grantLive.)
func (m *Sessions) Delete(ctx context.Context, id string) error {
	s, err := m.svc.Sessions.Get(ctx, id)
	if err != nil {
		return err
	}
	m.Evict(id, "")
	m.svc.SessionsEnding(ctx, s.UserID, id)
	_, err = m.svc.EndSession(ctx, s)
	return err
}

// SessionHandle is the opaque name a session is shown and ended by (a session's id is its secret's key, so it is never
// sent to a browser).
func SessionHandle(id string) string {
	h := sha256.Sum256([]byte("session-handle:" + id))
	return base64.RawURLEncoding.EncodeToString(h[:16])
}
