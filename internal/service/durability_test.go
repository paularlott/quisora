package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// unconfirmed is a store whose durable writes apply but are never acknowledged by a peer (a lone cluster node).
type unconfirmed struct{ store.Store }

func (s unconfirmed) Put(ctx context.Context, rec *store.Record) error {
	if err := s.Store.Put(ctx, rec); err != nil {
		return err
	}
	if store.IsDurable(ctx) {
		return store.ErrNotReplicated
	}
	return nil
}

func (s unconfirmed) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	if err := s.Store.CompareAndPut(ctx, rec, expect); err != nil {
		return err
	}
	if store.IsDurable(ctx) {
		return store.ErrNotReplicated
	}
	return nil
}

// A security write that applied but was not confirmed by a peer still has its consequences: removing a password
// ends the user's sessions and is audited; disabling a user ends their sessions; the caller hears it was unconfirmed.
func TestUnconfirmedWritesStillTakeEffect(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 2
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	inner := memstore.New()
	svc := service.New(cfg, inner, sealer)
	ctx := context.Background()
	super, _, err := svc.Bootstrap(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	u, err := svc.CreateUser(ctx, service.System, super.OrgID, service.UserInput{Username: ptr("pat"), Email: ptr("pat@example.com"), GivenName: ptr("Pat"), FamilyName: ptr("Lee"),
		Password: ptr("correct horse battery staple 9")})
	if err != nil {
		t.Fatal(err)
	}
	session := func() {
		t.Helper()
		if err := svc.Sessions.Create(ctx, &model.Session{Meta: model.Meta{ID: secure.RandomToken(16)}, UserID: u.ID, OrgID: u.OrgID}); err != nil {
			t.Fatal(err)
		}
	}
	live := func() int { l, _ := svc.Sessions.All(ctx, u.ID); return len(l) }

	svc = service.New(cfg, unconfirmed{inner}, sealer) // from here durable writes go unconfirmed
	session()
	actor := &service.Actor{UserID: super.ID, OrgID: super.OrgID, Role: model.RoleSuperAdmin, Name: "root"}
	if err := svc.RemovePassword(ctx, actor, u.ID); !errors.Is(err, service.ErrNotReplicated) {
		t.Fatalf("remove password: %v", err)
	}
	if fresh, _ := svc.Users.Get(ctx, u.ID); fresh.PasswordHash != "" || live() != 0 {
		t.Fatalf("password removed %v, sessions left %d", fresh.PasswordHash == "", live())
	}
	session()
	if _, err := svc.UpdateUser(ctx, actor, u.ID, service.UserInput{Active: ptr(false)}); !errors.Is(err, service.ErrNotReplicated) {
		t.Fatalf("disable: %v", err)
	}
	if live() != 0 {
		t.Fatal("sessions survived an unconfirmed disable")
	}
	session()
	if err := svc.ResetCredentials(ctx, u.ID, ""); err != nil {
		t.Fatalf("reset with unconfirmed writes: %v", err)
	}
}

// staleOnce makes the first CompareAndPut of a user record lose to a concurrent write (it bumps the stored record
// first), as a profile edit landing during an invitation would.
type staleOnce struct {
	store.Store
	done bool
}

func (s *staleOnce) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	if rec.Kind == model.KindUser && !s.done {
		s.done = true
		cur, err := s.Store.Get(ctx, rec.Kind, rec.ID)
		if err == nil {
			cur.Version = store.Clock.Now()
			_ = s.Store.Put(ctx, cur)
		}
	}
	return s.Store.CompareAndPut(ctx, rec, expect)
}

// Resetting credentials clears the password even when the user record changed underneath (it retries).
func TestResetCredentialsRetriesConcurrentChange(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 2
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	inner := memstore.New()
	svc := service.New(cfg, inner, sealer)
	ctx := context.Background()
	super, _, err := svc.Bootstrap(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	u, err := svc.CreateUser(ctx, service.System, super.OrgID, service.UserInput{Username: ptr("pat"), Email: ptr("pat@example.com"),
		GivenName: ptr("Pat"), Password: ptr("correct horse battery staple 9")})
	if err != nil {
		t.Fatal(err)
	}
	svc = service.New(cfg, &staleOnce{Store: inner}, sealer)
	if err := svc.ResetCredentials(ctx, u.ID, ""); err != nil {
		t.Fatalf("reset with a concurrent change: %v", err)
	}
	if fresh, _ := svc.Users.Get(ctx, u.ID); fresh.PasswordHash != "" {
		t.Fatal("the password survived the reset")
	}
}

// staleUser is a store whose copy of one user is an older one (a node that has not received the latest change yet).
type staleUser struct {
	store.Store
	rec *store.Record
}

func (s *staleUser) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if s.rec != nil && kind == model.KindUser && id == s.rec.ID {
		return s.rec, nil
	}
	return s.Store.Get(ctx, kind, id)
}

// A user deleted from a copy that is not the newest is not deleted: here the copy predates the user's promotion to
// administrator, so neither the admin lock nor the last-admin check would have applied to the deletion.
func TestDeleteFromStaleCopyIsRefused(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 1
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	st := &staleUser{Store: memstore.New()}
	svc := service.New(cfg, st, sealer)
	ctx := context.Background()
	if _, _, err := svc.Bootstrap(ctx, "root@example.com"); err != nil {
		t.Fatal(err)
	}
	org, err := svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("acme")})
	if err != nil {
		t.Fatal(err)
	}
	u, err := svc.CreateUser(ctx, service.System, org.ID, service.UserInput{Username: ptr("pat"), Email: ptr("pat@example.com"),
		GivenName: ptr("Pat")})
	if err != nil {
		t.Fatal(err)
	}
	old, err := st.Store.Get(ctx, model.KindUser, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	admin := model.RoleAdmin
	if _, err := svc.UpdateUser(ctx, service.System, u.ID, service.UserInput{Role: &admin}); err != nil {
		t.Fatal(err)
	}
	st.rec = old
	if err := svc.DeleteUser(ctx, service.System, u.ID); err == nil {
		t.Fatal("deleted from a stale copy")
	}
	st.rec = nil
	if cur, err := svc.Users.Get(ctx, u.ID); err != nil || cur.Role != model.RoleAdmin {
		t.Fatalf("the administrator is gone: %v %+v", err, cur)
	}
}
