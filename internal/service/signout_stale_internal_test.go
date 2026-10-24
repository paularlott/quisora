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
