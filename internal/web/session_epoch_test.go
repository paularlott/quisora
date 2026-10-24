package web

import (
	"context"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// A session made in an earlier credential epoch stops working at the user write that moves the epoch on (an accepted
// invitation, a reset of the account's sign-in), whether or not its record has been removed yet.
func TestSessionOfPassedEpoch(t *testing.T) {
	ctx := context.Background()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svc := service.New(config.Default(), memstore.New(), sealer)
	org := &model.Org{Name: "epoch", Primary: true}
	if err := svc.Orgs.Create(ctx, org); err != nil {
		t.Fatal(err)
	}
	u := &model.User{OrgID: org.ID, Username: "e", Email: "e@example.com", Role: model.RoleUser, Active: true}
	if err := svc.Users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	sess := &model.Session{Meta: model.Meta{ID: "epoch-session"}, UserID: u.ID, OrgID: org.ID, Epoch: u.CredEpoch,
		AuthTime: time.Now(), LastSeen: time.Now(), Expires: time.Now().Add(time.Hour)}
	if err := svc.Sessions.Create(ctx, sess); err != nil {
		t.Fatal(err)
	}
	m := NewSessions(svc)
	if got, _ := m.Lookup(ctx, sess.ID); got == nil {
		t.Fatal("a session of the current epoch is refused")
	}
	u.CredEpoch = service.NewCredEpoch()
	if err := svc.Users.Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	m.Evict("", u.ID) // as the cluster's change notice does
	if got, _ := m.Lookup(ctx, sess.ID); got != nil {
		t.Fatal("a session of a passed epoch still works")
	}
}
