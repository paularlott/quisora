package web

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

type failGrantDeletes struct{ store.Store }

func (s failGrantDeletes) Put(ctx context.Context, r *store.Record) error {
	if r.Kind == model.KindGrant && r.Deleted {
		return errors.New("review: grant deletion failed")
	}
	return s.Store.Put(ctx, r)
}

// Ending a session deletes its refresh grants too; a grant that could not be deleted (one with offline_access keeps
// refreshing without its session) is reported, not swallowed, so a sign-out is never answered as done when part of
// it did not persist. The session itself still goes.
func TestSessionDeleteReportsGrantDeletionFailure(t *testing.T) {
	ctx := context.Background()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svc := service.New(config.Default(), memstore.New(), sealer)
	org := &model.Org{Name: "org1", Primary: true}
	if err := svc.Orgs.Create(ctx, org); err != nil {
		t.Fatal(err)
	}
	u := &model.User{OrgID: org.ID, Username: "ender", Email: "ender@example.com", Role: model.RoleUser, Active: true}
	if err := svc.Users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	s := &model.Session{Meta: model.Meta{ID: "sess-end"}, UserID: u.ID, OrgID: u.OrgID, AuthTime: now, LastSeen: now,
		Expires: now.Add(time.Hour)}
	if err := svc.Sessions.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	g := &model.Grant{Meta: model.Meta{ID: "grant-end"}, UserID: u.ID, OrgID: u.OrgID, ClientID: "c1", SessionID: s.ID,
		Scopes: []string{"openid", "offline_access"}, Expires: now.Add(time.Hour)}
	if err := svc.Grants.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	svc.Grants.S = failGrantDeletes{svc.Grants.S}
	m := NewSessions(svc)
	if err := m.Delete(ctx, s.ID); err == nil {
		t.Fatal("Delete reported success while the grant deletion failed")
	}
	if _, err := svc.Sessions.Get(ctx, s.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the session should be gone all the same: %v", err)
	}
	if _, err := svc.Grants.Get(ctx, g.ID); err != nil {
		t.Fatalf("control: the grant should still exist: %v", err)
	}
}
