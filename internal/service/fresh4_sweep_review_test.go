package service

import (
	"context"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store/memstore"
)

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
}
