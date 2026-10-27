package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// pacedSweepFixture is an organization whose sessions an emergency sign-out ended: a sweep has them to delete.
type pacedSweepFixture struct {
	s   *Service
	org *model.Org
}

func newPacedSweep(t *testing.T, sessions int) *pacedSweepFixture {
	t.Helper()
	ctx := context.Background()
	s := newInternalService(t, memstore.New())
	if _, _, err := s.Bootstrap(ctx, "root@example.com"); err != nil {
		t.Fatal(err)
	}
	org := &model.Org{Name: "acme"}
	if err := s.Orgs.Create(ctx, org); err != nil {
		t.Fatal(err)
	}
	u := &model.User{OrgID: org.ID, Username: "u", Email: "u@example.test", Active: true}
	if err := s.Users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	for range sessions {
		stamp, err := s.SessionStamp(ctx, org.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Sessions.Create(ctx, &model.Session{UserID: u.ID, OrgID: org.ID, Stamp: stamp, Expires: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SignOutOrg(ctx, System, org.ID, SignOutOptions{Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	return &pacedSweepFixture{s: s, org: org}
}

// The sweep writes its tombstones one at a time with a pause between them, so it cannot keep the partitions of the
// organizations it walks busy.
func TestSignOutSweepIsPaced(t *testing.T) {
	saved := signOutSweepGap
	signOutSweepGap = 5 * time.Millisecond
	defer func() { signOutSweepGap = saved }()
	f := newPacedSweep(t, 6)
	start := time.Now()
	n, err := f.s.SweepSignOut(context.Background(), System, f.org.ID, false)
	took := time.Since(start)
	if err != nil || n.Sessions != 6 {
		t.Fatalf("%+v %v", n, err)
	}
	if took < 6*5*time.Millisecond*8/10 {
		t.Fatalf("six tombstones in %v: not paced", took)
	}
}

// A cancelled sweep stops, rather than walking on: what is left is found by the next one.
func TestSignOutSweepStopsWhenCancelled(t *testing.T) {
	saved := signOutSweepGap
	signOutSweepGap = 15 * time.Millisecond
	defer func() { signOutSweepGap = saved }()
	f := newPacedSweep(t, 40)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	n, err := f.s.SweepSignOut(ctx, System, f.org.ID, false)
	if err == nil {
		t.Fatal("a cancelled sweep reported success")
	}
	if n.Sessions >= 40 || time.Since(start) > 2*time.Second {
		t.Fatalf("the sweep went on after it was cancelled: %d sessions in %v", n.Sessions, time.Since(start))
	}
}

// The tidying after a change of the session epoch removes the sessions of the epoch that change replaced and no
// other: run late (after the user signed in again under the new epoch), it leaves the new session alone.
func TestEndSessionsOfOnlyTheReplacedEpoch(t *testing.T) {
	ctx := context.Background()
	s := newInternalService(t, memstore.New())
	u := &model.User{OrgID: "org", Username: "s", Email: "s@example.com", Role: model.RoleUser, Active: true, SessionEpoch: 1}
	if err := s.Users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	mk := func(epoch uint64) *model.Session {
		sess := &model.Session{UserID: u.ID, OrgID: "org", Epoch: epoch, Expires: time.Now().Add(time.Hour)}
		if err := s.Sessions.Create(ctx, sess); err != nil {
			t.Fatal(err)
		}
		return sess
	}
	old, later := mk(1), mk(2) // signed in before the reset, and after it (the account's epoch is now 2)
	if err := s.endSessionsOf(ctx, u.ID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sessions.Get(ctx, old.ID); err == nil {
		t.Fatal("the replaced epoch's session stays")
	}
	if _, err := s.Sessions.Get(ctx, later.ID); err != nil {
		t.Fatal("the late tidying ended a session of the new epoch")
	}
}

type failingOrgs struct {
	store.Store
	fail bool
}

func (f *failingOrgs) Get(ctx context.Context, k model.Kind, id string) (*store.Record, error) {
	if f.fail && k == model.KindOrg {
		return nil, errors.New("store unavailable")
	}
	return f.Store.Get(ctx, k, id)
}

// Sign-out counters are served from the cache within signOutCacheTTL; past it they are read again, and a store that
// cannot answer fails the check (503): counters an emergency sign-out may have moved are never served past the bound.
func TestSignOutCountersStaleBound(t *testing.T) {
	ctx := context.Background()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	st := &failingOrgs{Store: memstore.New()}
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 1
	s := New(cfg, st, sealer)
	if _, _, err := s.Bootstrap(ctx, "root@example.com"); err != nil {
		t.Fatal(err)
	}
	p, err := s.PrimaryOrg(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionStamp(ctx, p.ID); err != nil { // read and cached
		t.Fatal(err)
	}
	st.fail = true
	age := func(d time.Duration) {
		s.signOut.mu.Lock()
		co := s.signOut.orgs[p.ID]
		co.fetched = time.Now().Add(-d)
		s.signOut.orgs[p.ID] = co
		s.signOut.fetched = time.Now().Add(-d)
		s.signOut.mu.Unlock()
	}
	if _, err := s.SessionStamp(ctx, p.ID); err != nil {
		t.Fatalf("counters within the cache's bound: %v", err)
	}
	age(signOutCacheTTL + time.Second) // due for a refresh, which fails
	if _, err := s.SessionStamp(ctx, p.ID); err == nil {
		t.Fatal("counters past signOutCacheTTL served while the store could not be read")
	}
}

// The cache holds the organizations read lately, not every one ever read: once a generation is older than any entry
// is of use, the next read starts a new one and the generation before it goes.
func TestSignOutCacheKeepsRecentOrganizationsOnly(t *testing.T) {
	ctx := context.Background()
	s := newInternalService(t, memstore.New())
	if _, _, err := s.Bootstrap(ctx, "root@example.com"); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, name := range []string{"one", "two", "three"} {
		o, err := s.CreateOrg(ctx, System, OrgInput{Name: &name})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, o.ID)
	}
	read := func(id string) {
		t.Helper()
		if _, err := s.SessionStamp(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	age := func() {
		s.signOut.mu.Lock()
		s.signOut.genAt = s.signOut.genAt.Add(-2 * signOutGeneration)
		s.signOut.mu.Unlock()
	}
	s.InvalidateSignOut()
	read(ids[0])
	age()
	read(ids[1]) // a new generation: ids[0] moves to the one before
	if _, ok := s.signOut.prev[ids[0]]; !ok {
		t.Fatal("the previous generation was dropped at once")
	}
	age()
	read(ids[2]) // and another: ids[0] goes
	s.signOut.mu.Lock()
	defer s.signOut.mu.Unlock()
	_, inOrgs := s.signOut.orgs[ids[0]]
	_, inPrev := s.signOut.prev[ids[0]]
	if inOrgs || inPrev || len(s.signOut.orgs)+len(s.signOut.prev) != 2 {
		t.Fatalf("held: %d now, %d before", len(s.signOut.orgs), len(s.signOut.prev))
	}
}
