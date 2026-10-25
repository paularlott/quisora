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

// While the organization cannot be read again, sign-out counters read before keep serving for signOutMaxStale, then
// the check fails: an emergency sign-out is never ignored for longer than that.
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
	age(signOutCacheTTL + time.Second) // due for a refresh, which fails: the recent counters serve
	if _, err := s.SessionStamp(ctx, p.ID); err != nil {
		t.Fatalf("a short outage failed the check: %v", err)
	}
	age(signOutMaxStale + time.Second)
	if _, err := s.SessionStamp(ctx, p.ID); err == nil {
		t.Fatal("counters past signOutMaxStale still served while the store could not be read")
	}
}

// The cache holds the organizations read lately, not every one ever read: once a generation is older than any entry
// is of use, the next read starts a new one and the generation before it goes.
func TestSignOutCacheKeepsRecentOrganizationsOnly(t *testing.T) {
	ctx := context.Background()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	s := New(config.Default(), memstore.New(), sealer)
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
		s.signOut.genAt = s.signOut.genAt.Add(-2 * signOutMaxStale)
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
