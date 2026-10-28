package service

import (
	"context"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// orgReads is a store whose reads of an organization (by id or by name) can fail, or call a hook once the record is
// read (a change landing while the read is in flight).
type orgReads struct {
	store.Store
	err   error
	after func()
}

func (o *orgReads) Get(ctx context.Context, k model.Kind, id string) (*store.Record, error) {
	if k != model.KindOrg {
		return o.Store.Get(ctx, k, id)
	}
	return o.read(func() (*store.Record, error) { return o.Store.Get(ctx, k, id) })
}

func (o *orgReads) GetByUnique(ctx context.Context, k model.Kind, value string) (*store.Record, error) {
	if k != model.KindOrg {
		return o.Store.GetByUnique(ctx, k, value)
	}
	return o.read(func() (*store.Record, error) { return o.Store.GetByUnique(ctx, k, value) })
}

func (o *orgReads) read(get func() (*store.Record, error)) (*store.Record, error) {
	if o.err != nil {
		return nil, o.err
	}
	r, err := get()
	if o.after != nil {
		o.after()
	}
	return r, err
}

// An organization read before an invalidation (it changed) is not kept when the read ends after it, by id (the sign-out
// counters) or by name (an /o/<name> path): it may predate the change, and would answer for it until the cache's bound.
func TestOrgReadBeforeAnInvalidationIsNotKept(t *testing.T) {
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
	for name, read := range map[string]func() error{
		"sign-out counters": func() error { _, err := s.SessionStamp(ctx, p.ID); return err },
		"by name":           func() error { _, err := s.OrgByRef(ctx, p.Name); return err },
	} {
		st.after = s.InvalidateOrgs // the change lands between the read and the cache fill
		if err := read(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		st.after, st.err = nil, store.ErrUnavailable
		if read() == nil {
			t.Fatalf("%s: what was read before the invalidation was cached after it", name)
		}
		st.err = nil
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
	st.err = store.ErrUnavailable // the organization (the owner of the user) cannot be read
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
