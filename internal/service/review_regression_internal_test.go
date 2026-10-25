package service

// Regression tests from the external code reviews, one per finding: each states the failure it guards against.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/kvstore"
	"github.com/paularlott/quisora/internal/store/memstore"
)

type freshReviewSweepReads struct {
	store.Store
	calls int
}

func (p *freshReviewSweepReads) Fresh(ctx context.Context, kind model.Kind, ids []string) (map[string]*store.Record, error) {
	p.calls++
	out := map[string]*store.Record{}
	for _, id := range ids {
		r, err := p.Store.Get(ctx, kind, id)
		if err != nil {
			return nil, err
		}
		out[id] = r
	}
	return out, nil
}

func TestFreshReviewSweepReadsSameEpochOwnerPerCredential(t *testing.T) {
	ctx := context.Background()
	st := &freshReviewSweepReads{Store: memstore.New()}
	defer st.Close()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	s := New(config.Default(), st, sealer)
	org := &model.Org{Name: "sweep"}
	if err := s.Orgs.Create(ctx, org); err != nil {
		t.Fatal(err)
	}
	u := &model.User{OrgID: org.ID, Username: "owner", Email: "owner@example.test", CredEpoch: 7, SessionEpoch: 7}
	if err := s.Users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		sess := &model.Session{UserID: u.ID, OrgID: org.ID, Epoch: 7, Expires: time.Now().Add(time.Hour)}
		if err := s.Sessions.Create(ctx, sess); err != nil {
			t.Fatal(err)
		}
	}
	saved := sweepMinAge
	sweepMinAge = -time.Hour
	defer func() { sweepMinAge = saved }()
	var sw Sweep
	for i, k := range sweepKinds {
		if k == model.KindSession {
			sw.kind = i
		}
	}
	n, err := s.SweepOrphans(ctx, &sw, 20000)
	if err != nil || n != 0 {
		t.Fatalf("removed=%d err=%v", n, err)
	}
	t.Logf("valid sessions=100, distinct owners=1, serial quorum Fresh calls=%d", st.calls)
	if st.calls != 0 { // the batch's owners are read once, from this node; a quorum read only confirms a removal
		t.Fatalf("%d quorum reads for a batch of current sessions", st.calls)
	}
}

func TestFreshReviewSweepObsoleteSessionsRepeatOwnerConfirmation(t *testing.T) {
	ctx := context.Background()
	st := &freshReviewSweepReads{Store: memstore.New()}
	defer st.Close()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	s := New(config.Default(), st, sealer)
	org := &model.Org{Name: "sweep"}
	if err := s.Orgs.Create(ctx, org); err != nil {
		t.Fatal(err)
	}
	u := &model.User{OrgID: org.ID, Username: "owner", Email: "owner@example.test", SessionEpoch: 8}
	if err := s.Users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		sess := &model.Session{UserID: u.ID, OrgID: org.ID, Epoch: 7, Expires: time.Now().Add(time.Hour)}
		if err := s.Sessions.Create(ctx, sess); err != nil {
			t.Fatal(err)
		}
	}
	saved := sweepMinAge
	sweepMinAge = -time.Hour
	defer func() { sweepMinAge = saved }()
	var sw Sweep
	for i, k := range sweepKinds {
		if k == model.KindSession {
			sw.kind = i
		}
	}
	n, err := s.SweepOrphans(ctx, &sw, 20000)
	if err != nil || n != 100 {
		t.Fatalf("removed=%d err=%v", n, err)
	}
	t.Logf("obsolete sessions=100, distinct owners=1, serial quorum Fresh calls=%d", st.calls)
	if st.calls > 1 { // the batch's suspect owners are confirmed together
		t.Fatalf("%d quorum reads to confirm one owner", st.calls)
	}
}

// Isolate owner collection with distinct owners absent locally, so no quorum
// reads or decoding obscure the deduplication work.
func BenchmarkFreshReviewSweepDistinctOwners(b *testing.B) {
	for _, n := range []int{2000, 20000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			st := memstore.New()
			defer st.Close()
			sealer, _ := secure.NewSealer(secure.RandomBytes(32))
			s := New(config.Default(), st, sealer)
			ents := make([]model.Entity, n)
			for i := range n {
				ents[i] = &model.Session{Meta: model.Meta{ID: model.NewID()}, UserID: model.NewID()}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := s.passedEpochs(context.Background(), ents); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// DeleteUser always calls clearManagerOf, even for an account with no reports.
func BenchmarkFreshReviewDeletedUserManagerCleanup(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			ctx := context.Background()
			st, err := kvstore.OpenBadger(ctx, b.TempDir(), kvstore.BadgerOptions{InMemory: true})
			if err != nil {
				b.Fatal(err)
			}
			defer st.Close()
			sealer, _ := secure.NewSealer(secure.RandomBytes(32))
			s := New(config.Default(), st, sealer)
			recs := make([]*store.Record, n)
			for i := range n {
				u := &model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: "org", Username: fmt.Sprintf("user-%06d", i), Email: fmt.Sprintf("user-%06d@example.test", i)}
				recs[i], err = store.Encode(u)
				if err != nil {
					b.Fatal(err)
				}
			}
			if _, _, err := st.PutReplicatedBatch(ctx, recs); err != nil {
				b.Fatal(err)
			}
			deleted := &model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: "org"}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				s.clearManagerOf(ctx, deleted)
			}
		})
	}
}
