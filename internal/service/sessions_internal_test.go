package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
	"github.com/paularlott/quisora/internal/ttlcache"
)

// pacedSweepFixture is an organization whose sessions an emergency sign-out ended: a sweep has them to delete.
type pacedSweepFixture struct {
	s   *Service
	org *model.Org
	uid string
	txs *countTx
}

// countTx counts the transactions written through it.
type countTx struct {
	store.Store
	n atomic.Int64
}

func (c *countTx) Tx(ctx context.Context, ops []store.Op) error {
	c.n.Add(1)
	return c.Store.Tx(ctx, ops)
}

func newPacedSweep(t *testing.T, sessions int) *pacedSweepFixture {
	t.Helper()
	ctx := context.Background()
	txs := &countTx{Store: memstore.New()}
	s := newInternalService(t, txs)
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
	txs.n.Store(0)
	return &pacedSweepFixture{s: s, org: org, uid: u.ID, txs: txs}
}

// sweepPace sets the sweep's batch and pause for one test.
func sweepPace(t *testing.T, batch int, gap time.Duration) {
	b, g := signOutSweepBatch, signOutSweepGap
	signOutSweepBatch, signOutSweepGap = batch, gap
	t.Cleanup(func() { signOutSweepBatch, signOutSweepGap = b, g })
}

// The sweep writes its removals in transactions of up to a batch, with a pause after each, so it cannot keep the
// store busy: seven sessions in batches of three are three transactions and three pauses.
func TestSignOutSweepIsBatchedAndPaced(t *testing.T) {
	sweepPace(t, 3, 10*time.Millisecond)
	f := newPacedSweep(t, 7)
	start := time.Now()
	n, err := f.s.SweepSignOut(context.Background(), System, f.org.ID, false)
	took := time.Since(start)
	if err != nil || n.Sessions != 7 {
		t.Fatalf("%+v %v", n, err)
	}
	if got := f.txs.n.Load(); got != 3 {
		t.Fatalf("seven removals in batches of three written in %d transactions, want 3", got)
	}
	if took < 3*10*time.Millisecond*8/10 {
		t.Fatalf("three transactions in %v: not paced", took)
	}
	if left, err := f.s.Sessions.Count(context.Background(), f.uid); err != nil || left != 0 {
		t.Fatalf("%d sessions left (%v)", left, err)
	}
}

// A cancelled sweep stops, rather than walking on: what is left is found by the next one.
func TestSignOutSweepStopsWhenCancelled(t *testing.T) {
	sweepPace(t, 2, 15*time.Millisecond)
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

// Sign-out counters are served from the organization cache within its bound; past it they are read again, and a store
// that cannot answer fails the check (503): counters an emergency sign-out may have moved are never served past the
// bound. (The cache's bound is shortened here; the server's is orgTTL.)
func TestSignOutCountersStaleBound(t *testing.T) {
	if orgTTL > 5*time.Second {
		t.Fatalf("organizations are cached for %v, more than the 5s bound", orgTTL)
	}
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
	const bound = time.Second
	s.orgCache = ttlcache.New[*model.Org](bound, 10)
	if _, err := s.SessionStamp(ctx, p.ID); err != nil { // read and cached
		t.Fatal(err)
	}
	st.fail = true
	if _, err := s.SessionStamp(ctx, p.ID); err != nil {
		t.Fatalf("counters within the cache's bound: %v", err)
	}
	time.Sleep(bound) // due for a refresh, which fails
	if _, err := s.SessionStamp(ctx, p.ID); err == nil {
		t.Fatal("counters past the cache's bound served while the store could not be read")
	}
}

// An emergency sign-out pulled on another node counts here within the cache's bound, though this node is not told of it.
// (The bound is shortened here; the server's is orgTTL.)
func TestSignOutCountsElsewhereWithinTheBound(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	s := newInternalService(t, st)
	if _, _, err := s.Bootstrap(ctx, "root@example.com"); err != nil {
		t.Fatal(err)
	}
	other := New(s.Cfg, st, s.Sealer) // a second node over the same data, which hears of no change
	const bound = time.Second
	other.orgCache = ttlcache.New[*model.Org](bound, 10)
	stamp, err := other.SessionStamp(ctx, model.PrimaryOrgID) // a session made before the pull, its counters cached
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SignOutServer(ctx, System, SignOutOptions{Reason: "x"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(bound)
	if other.SessionCurrent(ctx, model.PrimaryOrgID, stamp) {
		t.Fatal("past the cache's bound, the other node still accepts a session the server-wide sign-out ended")
	}
}

// Whether a user may act reads the organization through its cache: organizations are in the cluster's global
// partition, and every session check, token check and refresh asks, so while that partition cannot be read (its owner
// changing) users of every organization go on within the cache's bound instead of all getting "try again". Past the
// bound the read fails closed; a deleted organization still stops its users.
func TestUserUsableReadsTheOrganizationThroughItsCache(t *testing.T) {
	ctx := context.Background()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	st := &failingOrgs{Store: memstore.New()}
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 1
	s := New(cfg, st, sealer)
	admin, _, err := s.Bootstrap(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	const bound = time.Second
	s.orgCache = ttlcache.New[*model.Org](bound, 10)
	if ok, err := s.UserUsable(ctx, admin); !ok || err != nil { // read and cached
		t.Fatalf("usable: %v %v", ok, err)
	}
	st.fail = true
	if ok, err := s.UserUsable(ctx, admin); !ok || err != nil {
		t.Fatalf("within the cache's bound, the organization unreadable: %v %v", ok, err)
	}
	time.Sleep(bound)
	if ok, err := s.UserUsable(ctx, admin); ok || err == nil {
		t.Fatalf("past the bound, the organization unreadable: %v %v, want an error", ok, err)
	}
	st.fail = false
	name, given, email := "gone", "Pat", "pat@example.com"
	org, err := s.CreateOrg(ctx, System, OrgInput{Name: &name, DisplayName: &name})
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.CreateUser(ctx, System, org.ID, UserInput{Username: &given, GivenName: &given, Email: &email})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.UserUsable(ctx, u); !ok {
		t.Fatal("a user of a live organization is not usable")
	}
	if err := s.DeleteOrg(ctx, System, org.ID, true); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.UserUsable(ctx, u); ok || err != nil {
		t.Fatalf("a user of a deleted organization: %v %v", ok, err)
	}
}
