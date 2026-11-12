package service

import (
	"context"
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// countedOrgReads counts the lookups of an organization by name that reach the store.
type countedOrgReads struct {
	orgReads
	n int
}

func (c *countedOrgReads) GetByUnique(ctx context.Context, k model.Kind, v string) (*store.Record, error) {
	if k == model.KindOrg {
		c.n++
	}
	return c.orgReads.GetByUnique(ctx, k, v)
}

// An organization that does not exist is read from the store once, not for every request; an organization created
// afterwards is found at once (InvalidateOrgs, as the change feed calls it), and an error other than "not found" is
// never kept.
func TestMissingOrgIsCached(t *testing.T) {
	ctx := context.Background()
	st := &countedOrgReads{orgReads: orgReads{Store: memstore.New()}}
	s := newInternalService(t, st)
	for range 3 {
		if _, err := s.OrgByRef(ctx, "ghost"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing organization: %v", err)
		}
	}
	if st.n != 1 {
		t.Fatalf("%d store reads for 3 requests of a missing organization", st.n)
	}
	if err := s.Orgs.Create(ctx, &model.Org{Name: "ghost"}); err != nil {
		t.Fatal(err)
	}
	s.InvalidateOrgs()
	if _, err := s.OrgByRef(ctx, "ghost"); err != nil {
		t.Fatalf("a new organization is not found at once: %v", err)
	}
	st.err = store.ErrUnavailable
	for range 2 {
		if _, err := s.OrgByRef(ctx, "other"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("store down: %v", err)
		}
	}
	st.err = nil
	if _, err := s.OrgByRef(ctx, "other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after the outage: %v", err)
	}
}
