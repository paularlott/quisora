package web

// Regression tests from the external code reviews, one per finding: each states the failure it guards against.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// Concurrent requests for an aged cached session must safely refresh LastSeen.
func TestReviewConcurrentSessionTouch(t *testing.T) {
	ctx := context.Background()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svc := service.New(config.Default(), memstore.New(), sealer)
	org := &model.Org{Name: "review", Primary: true}
	if err := svc.Orgs.Create(ctx, org); err != nil {
		t.Fatal(err)
	}
	u := &model.User{OrgID: org.ID, Username: "review", Email: "review@example.com", Role: model.RoleUser, Active: true}
	if err := svc.Users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute).UTC()
	sess := &model.Session{Meta: model.Meta{ID: "review-session"}, UserID: u.ID, OrgID: org.ID, AuthTime: old, LastSeen: old, Expires: time.Now().Add(time.Hour)}
	if err := svc.Sessions.Create(ctx, sess); err != nil {
		t.Fatal(err)
	}
	m := NewSessions(svc)
	svc.Writable = func() bool { return false }
	if got, _ := m.Lookup(ctx, sess.ID); got == nil {
		t.Fatal("session missing")
	}
	svc.Writable = func() bool { return true }
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			<-start
			if got, _ := m.Lookup(ctx, sess.ID); got == nil {
				t.Error("session missing")
			}
		})
	}
	close(start)
	wg.Wait()
}
