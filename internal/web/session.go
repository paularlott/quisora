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

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// SessionCookie is the browser session cookie. The __Host- prefix pins it to this origin over HTTPS.
const SessionCookie = "__Host-quisora_session"

const (
	sessionCacheTTL   = 30 * time.Second
	lastSeenThrottle  = 5 * time.Minute
	sessionCacheLimit = 100_000
)

type cachedSession struct {
	sess    *model.Session
	user    *model.User
	fetched time.Time
}

// Sessions creates, looks up and ends browser sessions. Lookups are cached per node for a short time; Evict is
// called by the cluster layer when a session or user record changes.
type Sessions struct {
	// CacheTTL bounds how long a node trusts a cached session (default 30s; nodes that share a database without
	// gossip get no eviction messages, so they use a shorter one).
	CacheTTL time.Duration
	svc      *service.Service
	mu       sync.RWMutex
	cache    map[string]*cachedSession
	byUser   map[string]map[string]struct{} // user id -> cached session ids, so evicting a user is O(their sessions)
}

func NewSessions(svc *service.Service) *Sessions {
	return &Sessions{CacheTTL: sessionCacheTTL, svc: svc, cache: map[string]*cachedSession{}, byUser: map[string]map[string]struct{}{}}
}

// Evict drops a cached session (by session id) — and, given a user id, every cached session of that user.
func (m *Sessions) Evict(sessionID, userID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sessionID != "" {
		m.drop(sessionID)
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
	s := &model.Session{Meta: model.Meta{ID: SessionID(raw)}, UserID: u.ID, OrgID: u.OrgID, AMR: amr,
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
	c, err := r.Cookie(SessionCookie)
	if err != nil || len(c.Value) < 20 || len(c.Value) > 100 {
		return nil, nil
	}
	s, u := m.Lookup(r.Context(), SessionID(c.Value))
	if s == nil || !cookieMatches(s, c.Value) {
		return nil, nil
	}
	return s, u
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
		err = m.svc.Sessions.Update(service.Durable(ctx), s)
		if errors.Is(err, store.ErrStale) {
			continue
		}
		if !store.Applied(err) {
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
	if u != nil && u.Role.Rank() >= model.RoleManager.Rank() {
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
		s, err := m.svc.Sessions.Get(ctx, id)
		if err != nil {
			m.Evict(id, "")
			return nil, nil
		}
		u, err := m.svc.Users.Get(ctx, s.UserID)
		if err != nil {
			return nil, nil
		}
		cs = &cachedSession{sess: s, user: u, fetched: now}
		m.mu.Lock()
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
		m.mu.Unlock()
	}
	if !cs.sess.Valid(now) || !cs.user.Enabled(time.Now()) {
		return nil, nil
	}
	if !m.svc.SessionCurrent(ctx, cs.sess.OrgID, cs.sess.Stamp) {
		return nil, nil
	}
	if now.Sub(cs.sess.LastSeen) > lastSeenThrottle {
		m.touch(ctx, cs)
	}
	return cs.sess, cs.user
}

// touch records that the session is in use (best effort). A node that may not change replicated data now (catching
// up, cut off from the majority) skips it: the session record is not changed here at all.
func (m *Sessions) touch(ctx context.Context, cs *cachedSession) {
	if !m.svc.CanWrite() {
		return
	}
	s := *cs.sess
	s.LastSeen = time.Now().UTC()
	if err := m.svc.Sessions.Update(context.WithoutCancel(ctx), &s); err == nil {
		m.mu.Lock()
		cs.sess = &s
		m.mu.Unlock()
	}
}

// End deletes the request's session and clears the cookie.
func (m *Sessions) End(ctx context.Context, w http.ResponseWriter, r *http.Request) *model.Session {
	sess, _ := m.Current(r)
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
	if sess == nil {
		return nil
	}
	_ = m.Delete(ctx, sess.ID)
	return sess
}

// Delete ends a session by id, with its refresh grants.
func (m *Sessions) Delete(ctx context.Context, id string) error {
	s, err := m.svc.Sessions.Get(ctx, id)
	if err != nil {
		return err
	}
	m.Evict(id, "")
	m.svc.SessionsEnding(ctx, s.UserID, id)
	grants, err := m.svc.Grants.All(ctx, s.UserID)
	if err == nil {
		for _, g := range grants {
			if g.SessionID == id {
				_ = m.svc.Grants.Delete(service.Durable(ctx), g.ID)
			}
		}
	}
	if err := m.svc.Sessions.Delete(service.Durable(ctx), id); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// SessionHandle is the opaque name a session is shown and ended by (a session's id is its secret's key, so it is never
// sent to a browser).
func SessionHandle(id string) string {
	h := sha256.Sum256([]byte("session-handle:" + id))
	return base64.RawURLEncoding.EncodeToString(h[:16])
}
