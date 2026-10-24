package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// failKindReads fails every Get of one kind.
type failKindReads struct {
	store.Store
	kind model.Kind
}

func (s failKindReads) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == s.kind {
		return nil, errors.New("consistency: read failed")
	}
	return s.Store.Get(ctx, kind, id)
}

func (s failKindReads) GetByUnique(ctx context.Context, kind model.Kind, value string) (*store.Record, error) {
	if kind == s.kind {
		return nil, errors.New("consistency: read failed")
	}
	return s.Store.GetByUnique(ctx, kind, value)
}

// failOneDelete fails the deletion (tombstone) of one record.
type failOneDelete struct {
	store.Store
	id string
}

func (s failOneDelete) Put(ctx context.Context, r *store.Record) error {
	if r.Deleted && r.ID == s.id {
		return errors.New("consistency: deletion failed")
	}
	return s.Store.Put(ctx, r)
}

// The emergency sign-out counters a token's stamp is compared with that cannot be read: the token is neither good
// nor "ended by an emergency sign-out" (which would be audited as a refusal), but unchecked: ErrUnavailable.
func TestAPITokenUnavailableWhenSignOutCountersCannotBeRead(t *testing.T) {
	e := newEnv(t)
	_, plain, err := e.svc.CreateAPIToken(e.ctx, actor(e.super), service.APITokenInput{Name: "t", Scopes: []string{"admin"}})
	if err != nil {
		t.Fatal(err)
	}
	good := e.svc.Orgs.S
	e.svc.Orgs.S = failKindReads{Store: good, kind: model.KindOrg}
	e.svc.InvalidateSignOut() // the counters read when the token was made must not answer for the store
	_, _, err = e.svc.ValidateAPIToken(e.ctx, plain)
	if !errors.Is(err, service.ErrUnavailable) || errors.Is(err, service.ErrBadToken) {
		t.Fatalf("unreadable sign-out counters: %v, want ErrUnavailable", err)
	}
	if n := len(auditsOf(t, e, "apitoken.refused")); n != 0 {
		t.Fatalf("a refusal was audited for a token that was not refused (%d)", n)
	}
	e.svc.Orgs.S = good
	if _, _, err := e.svc.ValidateAPIToken(e.ctx, plain); err != nil {
		t.Fatalf("once the store answers again: %v", err)
	}
}

func auditsOf(t testing.TB, e *env, action string) []*model.Audit {
	t.Helper()
	l, _, err := e.svc.Audits.List(e.ctx, store.ListQuery{Filters: []store.Filter{{Field: "action", Value: action}}})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// Removing an application's access deletes every grant the user gave it; when one deletion fails the count of those
// removed and the failure are both returned, so the caller can say the removal is partly done (the grant left behind
// still refreshes).
func TestRevokeAppAccessReportsPartialRemoval(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "grantee", model.RoleUser)
	now := time.Now().UTC()
	var ids []string
	for i := range 2 {
		g := &model.Grant{Meta: model.Meta{ID: "grant-" + itoa(i)}, UserID: u.ID, OrgID: u.OrgID, ClientID: "app",
			SessionID: "sess", Scopes: []string{"openid"}, Expires: now.Add(time.Hour)}
		if err := e.svc.Grants.Create(e.ctx, g); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, g.ID)
	}
	good := e.svc.Grants.S
	e.svc.Grants.S = failOneDelete{Store: good, id: ids[1]}
	n, err := e.svc.RevokeAppAccess(e.ctx, u.ID, "app")
	if err == nil || n != 1 {
		t.Fatalf("partly failed removal: n=%d err=%v, want 1 and an error", n, err)
	}
	if _, err := e.svc.Grants.Get(e.ctx, ids[0]); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the grant whose deletion worked should be gone: %v", err)
	}
	if _, err := e.svc.Grants.Get(e.ctx, ids[1]); err != nil {
		t.Fatalf("control: the other grant should still exist: %v", err)
	}
	e.svc.Grants.S = good
	if n, err := e.svc.RevokeAppAccess(e.ctx, u.ID, "app"); err != nil || n != 1 {
		t.Fatalf("retry: n=%d err=%v", n, err)
	}
}

// The sessions a compromised passkey signed in that could not all be ended: reported, not counted as fewer.
func TestEndPasskeySessionsReportsFailures(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "keyed", model.RoleUser)
	now := time.Now().UTC()
	s := &model.Session{Meta: model.Meta{ID: "sess-pk"}, UserID: u.ID, OrgID: u.OrgID, Passkey: "pk1", AuthTime: now,
		LastSeen: now, Expires: now.Add(time.Hour)}
	if err := e.svc.Sessions.Create(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	g := &model.Grant{Meta: model.Meta{ID: "grant-pk"}, UserID: u.ID, OrgID: u.OrgID, ClientID: "app", SessionID: s.ID,
		Scopes: []string{"openid", "offline_access"}, Expires: now.Add(time.Hour)}
	if err := e.svc.Grants.Create(e.ctx, g); err != nil {
		t.Fatal(err)
	}
	e.svc.Grants.S = failOneDelete{Store: e.svc.Grants.S, id: g.ID}
	n, err := e.svc.EndPasskeySessions(e.ctx, u.ID, "pk1")
	if err == nil {
		t.Fatalf("the grant's deletion failed but nothing was reported (ended %d)", n)
	}
	if n != 1 {
		t.Fatalf("the session itself should have ended: %d", n)
	}
}

// A client's tenant that cannot be read is a failed read, not a missing tenant: the access decision made from it
// must not be made from its absence.
func TestClientTenantReportsReadFailure(t *testing.T) {
	e := newEnv(t)
	tn, err := e.svc.DefaultTenant(e.ctx, e.primary.ID)
	if err != nil {
		t.Fatal(err)
	}
	c := &model.Client{OrgID: e.primary.ID, TenantID: tn.ID}
	e.svc.Tenants.S = failKindReads{Store: e.svc.Tenants.S, kind: model.KindTenant}
	if _, err := e.svc.ClientTenant(e.ctx, c); err == nil || errors.Is(err, service.ErrNotFound) {
		t.Fatalf("unreadable tenant: %v, want a read failure", err)
	}
	if _, err := e.svc.TenantForResources(e.ctx, []string{"https://api.example"}); err == nil || errors.Is(err, service.ErrNotFound) {
		t.Fatalf("unreadable tenant by resource: %v, want a read failure", err)
	}
}
