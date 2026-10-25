package service

import (
	"context"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
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
