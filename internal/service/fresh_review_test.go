package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestFreshReviewLastWayGuardRejectsDisabledProvider(t *testing.T) {
	e := newEnv(t)
	e.primary.Settings.RequireMFA = false
	if err := e.svc.Orgs.Update(e.ctx, e.primary); err != nil {
		t.Fatal(err)
	}
	u := e.user(e.primary.ID, "disabled-provider-last-way", model.RoleUser)
	p := &model.Provider{OrgID: u.OrgID, Name: "Disabled SSO", Type: model.ProviderOIDC, Issuer: "https://issuer.example", Enabled: false}
	if err := e.svc.Providers.Create(e.ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Identities.Create(e.ctx, model.NewIdentity(u, p, "last-way-sub", u.Email, "connect")); err != nil {
		t.Fatal(err)
	}
	pk := &model.Passkey{UserID: u.ID, OrgID: u.OrgID, Name: "Only working way", Epoch: u.CredEpoch, UserVerified: true, CredentialID: []byte("last-way-key")}
	if err := e.svc.Passkeys.Create(e.ctx, pk); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.RemovePasskey(service.SelfService(e.ctx), actor(u), u.ID, pk.ID, "")
	if !errors.Is(err, service.ErrConflict) {
		t.Fatalf("self-removal counted a disabled provider as another way in: %v", err)
	}
}

type freshReviewQuorumDisabledKey struct {
	store.Store
	key *store.Record
}

func (s freshReviewQuorumDisabledKey) Fresh(ctx context.Context, kind model.Kind, ids []string) (map[string]*store.Record, error) {
	out := make(map[string]*store.Record, len(ids))
	for _, id := range ids {
		if kind == model.KindPasskey && id == s.key.ID {
			out[id] = s.key
			continue
		}
		r, err := s.Store.Lookup(ctx, kind, id)
		if err != nil {
			return nil, err
		}
		out[id] = r
	}
	return out, nil
}

func TestFreshReviewLastWayGuardUsesQuorumCredentialContents(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "quorum-disabled-key", model.RoleUser)
	keys := make([]*model.Passkey, 0, 2)
	for _, name := range []string{"working", "cloned"} {
		pk := &model.Passkey{UserID: u.ID, OrgID: u.OrgID, Name: name, Epoch: u.CredEpoch, UserVerified: true, CredentialID: []byte(name)}
		if err := e.svc.Passkeys.Create(e.ctx, pk); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, pk)
	}
	newer := *keys[1]
	newer.Disabled = true
	r, err := store.Encode(&newer)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.Store = freshReviewQuorumDisabledKey{Store: e.svc.Store, key: r}
	_, err = e.svc.RemovePasskey(service.SelfService(e.ctx), actor(u), u.ID, keys[0].ID, "")
	if !errors.Is(err, service.ErrConflict) {
		t.Fatalf("self-removal counted a key disabled in the quorum's copy as another way in: %v", err)
	}
}
