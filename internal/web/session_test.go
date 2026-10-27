package web

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// sessionFixture makes a service over st with a primary organization, a user of it and a session of that user (not yet
// stored, so a test can arrange the store first) last used at lastSeen.
func sessionFixture(t *testing.T, st store.Store, lastSeen time.Time) (*service.Service, *model.User, *model.Session) {
	t.Helper()
	ctx := context.Background()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svc := service.New(config.Default(), st, sealer)
	org := &model.Org{Name: "org1", Primary: true}
	if err := svc.Orgs.Create(ctx, org); err != nil {
		t.Fatal(err)
	}
	u := &model.User{OrgID: org.ID, Username: "user1", Email: "user1@example.com", Role: model.RoleUser, Active: true}
	if err := svc.Users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	s := &model.Session{Meta: model.Meta{ID: "sess-1"}, UserID: u.ID, OrgID: org.ID, Epoch: u.SessionEpoch,
		AuthTime: lastSeen, LastSeen: lastSeen, Expires: time.Now().Add(time.Hour)}
	return svc, u, s
}

// The session id stored is a hash of the cookie, and the handle shown for a session a hash of its id: neither can be
// turned back into what it was made from.
func TestSessionIdentifiersAreOneWayHashes(t *testing.T) {
	raw := "cookie-value-abcdefghijklmnopqrstuvwxyz"
	if id := SessionID(raw); id == raw || id != SessionID(raw) || len(id) != 43 {
		t.Fatalf("SessionID must be a stable hash, got %q", id)
	}
	a, b := SessionHandle("sess-1"), SessionHandle("sess-2")
	if a == b || a != SessionHandle("sess-1") || strings.Contains(a, "sess-1") || len(a) != 22 {
		t.Fatalf("handles %q %q", a, b)
	}
}

// Evicting a user drops every cached session of theirs and their entry in the by-user index (which would otherwise
// only grow); evicting a session drops it and an index entry left empty.
func TestSessionCacheEvictByUser(t *testing.T) {
	m := &Sessions{cache: map[string]*cachedSession{}, byUser: map[string]map[string]struct{}{}}
	add := func(id, uid string) {
		m.cache[id] = &cachedSession{sess: &model.Session{}, user: &model.User{Meta: model.Meta{ID: uid}}}
		if m.byUser[uid] == nil {
			m.byUser[uid] = map[string]struct{}{}
		}
		m.byUser[uid][id] = struct{}{}
	}
	add("s1", "u1")
	add("s2", "u1")
	add("s3", "u2")
	m.Evict("", "u1")
	if len(m.cache) != 1 || m.cache["s3"] == nil || m.byUser["u1"] != nil {
		t.Fatalf("evict by user: %v %v", m.cache, m.byUser)
	}
	m.Evict("s3", "")
	if len(m.cache) != 0 || len(m.byUser) != 0 {
		t.Fatal("evict by session")
	}
}

// A session lives as long as its organization says, never longer than the server allows, and for managers and above
// never longer than the privileged limits.
func TestSessionLifetime(t *testing.T) {
	cfg := config.Default()
	cfg.Session.TTL, cfg.Session.Idle, cfg.Session.PrivilegedTTL, cfg.Session.PrivilegedIdle = 7*86400, 86400, 12*3600, 3600
	m := &Sessions{svc: &service.Service{Cfg: cfg}}
	user, admin := &model.User{Role: model.RoleUser}, &model.User{Role: model.RoleAdmin}
	org := func(ttl, idle int) *model.Org {
		return &model.Org{Settings: model.OrgSettings{SessionTTL: ttl, SessionIdle: idle}}
	}
	for _, tc := range []struct {
		name      string
		org       *model.Org
		u         *model.User
		ttl, idle int
	}{
		{"server defaults", org(0, 0), user, 7 * 86400, 86400},
		{"shorter org", org(3600, 600), user, 3600, 600},
		{"org above the server is capped", org(30*86400, 7*86400), user, 7 * 86400, 86400},
		{"privileged", org(0, 0), admin, 12 * 3600, 3600},
		{"privileged under a shorter org", org(1800, 300), admin, 1800, 300},
	} {
		if ttl, idle := m.lifetime(tc.org, tc.u); ttl != tc.ttl || idle != tc.idle {
			t.Errorf("%s: %d/%d, want %d/%d", tc.name, ttl, idle, tc.ttl, tc.idle)
		}
	}
}

// A session made in an earlier session epoch stops working at the user write that moves the epoch on (a password
// reset, an accepted invitation, a reset of the account's sign-in), whether or not its record has been removed yet.
func TestSessionOfPassedEpoch(t *testing.T) {
	ctx := context.Background()
	svc, u, sess := sessionFixture(t, memstore.New(), time.Now())
	if err := svc.Sessions.Create(ctx, sess); err != nil {
		t.Fatal(err)
	}
	m := NewSessions(svc)
	if got, _ := m.Lookup(ctx, sess.ID); got == nil {
		t.Fatal("a session of the current epoch is refused")
	}
	u.SessionEpoch = service.NewCredEpoch()
	if err := svc.Users.Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	m.Evict("", u.ID) // as the cluster's change notice does
	if got, _ := m.Lookup(ctx, sess.ID); got != nil {
		t.Fatal("a session of a passed epoch still works")
	}
}

type failGrantDeletes struct{ store.Store }

func (s failGrantDeletes) Put(ctx context.Context, r *store.Record) error {
	if r.Kind == model.KindGrant && r.Deleted {
		return errors.New("grant deletion failed")
	}
	return s.Store.Put(ctx, r)
}

// Ending a session deletes its refresh grants too; a grant that could not be deleted (one with offline_access keeps
// refreshing without its session) is reported, not swallowed, so a sign-out is never answered as done when part of
// it did not persist. The session itself still goes.
func TestSessionDeleteReportsGrantDeletionFailure(t *testing.T) {
	ctx := context.Background()
	svc, u, s := sessionFixture(t, memstore.New(), time.Now().UTC())
	if err := svc.Sessions.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	g := &model.Grant{Meta: model.Meta{ID: "grant-end"}, UserID: u.ID, OrgID: u.OrgID, ClientID: "c1", SessionID: s.ID,
		Scopes: []string{"openid", "offline_access"}, Expires: time.Now().Add(time.Hour)}
	if err := svc.Grants.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	svc.Grants.S = failGrantDeletes{svc.Grants.S}
	m := NewSessions(svc)
	if err := m.Delete(ctx, s.ID); err == nil {
		t.Fatal("Delete reported success while the grant deletion failed")
	}
	if _, err := svc.Sessions.Get(ctx, s.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the session should be gone all the same: %v", err)
	}
	if _, err := svc.Grants.Get(ctx, g.ID); err != nil {
		t.Fatalf("control: the grant should still exist: %v", err)
	}
}

// A cached session counts for at most the cache's bound after it was read: a session revoked where this node did not
// hear of it (no eviction) is refused once the bound has passed, whatever the store.
func TestSessionCacheBoundedByItsTTL(t *testing.T) {
	ctx := context.Background()
	svc, _, s := sessionFixture(t, memstore.New(), time.Now().UTC())
	if err := svc.Sessions.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	m := NewSessions(svc)
	if got, _ := m.Lookup(ctx, s.ID); got == nil {
		t.Fatal("control: the session should be found")
	}
	if err := svc.Sessions.Delete(ctx, s.ID); err != nil { // revoked elsewhere: no eviction reached this node
		t.Fatal(err)
	}
	if got, _ := m.Lookup(ctx, s.ID); got == nil {
		t.Fatal("control: the cache should serve the session within its bound")
	}
	if m.CacheTTL > 5*time.Second {
		t.Fatalf("sessions are cached for %v, more than the 5s bound", m.CacheTTL)
	}
	m.mu.Lock()
	m.cache[s.ID].fetched = time.Now().Add(-m.CacheTTL - time.Millisecond)
	m.mu.Unlock()
	if got, _ := m.Lookup(ctx, s.ID); got != nil {
		t.Fatal("a cached session was served past the cache's bound")
	}
}
