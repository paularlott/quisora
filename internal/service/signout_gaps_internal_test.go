package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// orgReads is a store whose reads of an organization can fail, or call a hook once the record is read (a change landing
// while the read is in flight).
type orgReads struct {
	store.Store
	err   error
	after func()
}

func (o *orgReads) Get(ctx context.Context, k model.Kind, id string) (*store.Record, error) {
	if k != model.KindOrg {
		return o.Store.Get(ctx, k, id)
	}
	if o.err != nil {
		return nil, o.err
	}
	r, err := o.Store.Get(ctx, k, id)
	if o.after != nil {
		o.after()
	}
	return r, err
}

// A node that cannot vouch for its copy (the staleness gate refuses the read) does not go on with cached counters,
// where a store error does for a short while: the emergency sign-out it may have missed counts.
func TestSignOutCountersDoNotFallBackOnAGateRefusal(t *testing.T) {
	ctx := context.Background()
	st := &orgReads{Store: memstore.New()}
	s := newInternalService(t, st)
	if _, _, err := s.Bootstrap(ctx, "root@example.com"); err != nil {
		t.Fatal(err)
	}
	p, err := s.PrimaryOrg(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionStamp(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	age := func() {
		s.signOut.mu.Lock()
		co := s.signOut.orgs[p.ID]
		co.fetched = time.Now().Add(-signOutCacheTTL - time.Second)
		s.signOut.orgs[p.ID] = co
		s.signOut.mu.Unlock()
	}
	age()
	st.err = errors.New("store unavailable")
	if _, err := s.SessionStamp(ctx, p.ID); err != nil {
		t.Fatalf("a short store failure failed the check: %v", err)
	}
	age()
	st.err = store.ErrNotWritable
	if _, err := s.SessionStamp(ctx, p.ID); !errors.Is(err, store.ErrNotWritable) {
		t.Fatalf("counters served although the node cannot vouch for them: %v", err)
	}
}

// Counters read before an invalidation (an organization changed) are not stored when the read ends after it.
func TestSignOutCountersReadBeforeAnInvalidationAreNotKept(t *testing.T) {
	ctx := context.Background()
	st := &orgReads{Store: memstore.New()}
	s := newInternalService(t, st)
	if _, _, err := s.Bootstrap(ctx, "root@example.com"); err != nil {
		t.Fatal(err)
	}
	p, err := s.PrimaryOrg(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s.InvalidateSignOut()
	st.after = s.InvalidateSignOut // the change lands between the read and the cache fill
	if _, err := s.SessionStamp(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	st.after = nil
	s.signOut.mu.Lock()
	defer s.signOut.mu.Unlock()
	if _, ok := s.signOut.orgs[p.ID]; ok || s.signOut.hasSrv {
		t.Fatal("counters read before the invalidation were cached after it")
	}
}

// A sweep that fails part-way through a batch (an owner cannot be read) leaves its position where it was: the next run
// reads the batch again instead of skipping what it did not reach until the next lap.
func TestSweepKeepsItsPositionOnAnError(t *testing.T) {
	ctx := context.Background()
	st := &orgReads{Store: memstore.New()}
	s := newInternalService(t, st)
	org := &model.Org{Name: "acme"}
	if err := s.Orgs.Create(ctx, org); err != nil {
		t.Fatal(err)
	}
	if err := s.Users.Create(ctx, &model.User{OrgID: org.ID, Username: "u", Email: "u@example.com", Role: model.RoleUser, Active: true}); err != nil {
		t.Fatal(err)
	}
	withSweepAge(t)
	sw := sweepStartingAt(model.KindUser)
	start := *sw
	st.err = store.ErrNotWritable // the organization (the owner of the user) cannot be read
	if _, err := s.SweepOrphans(ctx, sw, 100); err == nil {
		t.Fatal("a sweep that could not read an owner succeeded")
	}
	if *sw != start {
		t.Fatalf("the sweep moved from %+v to %+v although its batch was not judged", start, *sw)
	}
	st.err = nil
	if _, err := s.SweepOrphans(ctx, sw, 100); err != nil || *sw == start {
		t.Fatalf("the next run: %v, position %+v", err, *sw)
	}
}
