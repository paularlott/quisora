package oidc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// keyCASFail fails the creation of signing keys.
type keyCASFail struct{ store.Store }

func (s keyCASFail) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindKey {
		return errors.New("keys: store refused")
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

func TestCoverageKeysUnreadable(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	ctx := context.Background()
	good := h.env.Svc.Keys.S

	// with a key set already loaded, a failed reload keeps serving it
	h.env.Svc.Keys.S = failLists{Store: good, kind: model.KindKey}
	if ks, err := h.p.reloadKeys(ctx, true); err != nil || len(ks.list) == 0 {
		t.Fatalf("reload with a failing store: %v", err)
	}

	// with none, nothing can be signed or verified, and the key set cannot be published
	h.p.Invalidate()
	h.p.jwksCache.Store(nil)
	if _, err := h.p.signingKey(ctx, AlgES256); err == nil {
		t.Fatal("signing key without a store")
	}
	if h.p.keyByKID(ctx, "any") != nil {
		t.Fatal("key found without a store")
	}
	rec := httptest.NewRecorder()
	h.p.handleJWKS(rec, httptest.NewRequest(http.MethodGet, "/oauth/jwks", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("jwks: %d", rec.Code)
	}
	if r := h.token(url.Values{"grant_type": {"client_credentials"}}, cl, secret); r.status != 500 {
		t.Fatalf("token: %d %v", r.status, r.m)
	}
	for name, err := range map[string]error{"ensure": h.p.EnsureKeys(ctx), "rotate": h.p.RotateKeys(ctx), "remove": h.p.RemoveKey(ctx, "x")} {
		if err == nil {
			t.Errorf("%s succeeded without a store", name)
		}
	}
	h.env.Svc.Keys.S = good
	h.p.Invalidate()
	if r := h.token(url.Values{"grant_type": {"client_credentials"}}, cl, secret); r.status != 200 {
		t.Fatalf("token after: %d %v", r.status, r.m)
	}
}

func TestCoverageKeyCreationFailures(t *testing.T) {
	h := setup(t, nil)
	ctx := context.Background()
	good := h.env.Svc.Keys.S
	h.env.Svc.Keys.S = keyCASFail{Store: good}
	if err := h.p.RotateKeys(ctx); err == nil {
		t.Fatal("rotation with a refusing store")
	}
	// a key for an algorithm that is not in the store is created on demand: here it cannot be, or is not one
	if _, err := h.p.signingKey(ctx, AlgRS256); err == nil {
		t.Fatal("RS256 key created on a refusing store")
	}
	if _, err := h.p.signingKey(ctx, "HS256"); err == nil {
		t.Fatal("unsupported algorithm")
	}
	h.p.keyMu.Lock()
	_, err := h.p.createKey(ctx, "HS256", time.Now())
	h.p.keyMu.Unlock()
	if err == nil {
		t.Fatal("createKey with an unsupported algorithm")
	}
	h.env.Svc.Keys.S = good
	if _, err := h.p.signingKey(ctx, AlgPS256); err != nil {
		t.Fatalf("on demand: %v", err)
	}
}

func TestCoverageKeyRecordsSkipped(t *testing.T) {
	h := setup(t, func(c *config.Config) { c.Tokens.KeyRotationDays = 1 })
	ctx := context.Background()
	// a key whose tokens have all expired, a key that cannot be opened, and a key whose algorithm is not its record's
	h.p.keyMu.Lock()
	expired, err := h.p.createKey(ctx, AlgES256, time.Now().Add(-200*time.Hour))
	h.p.keyMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	garbage := &model.SigningKey{Meta: model.Meta{ID: model.NewID()}, Alg: AlgES256, PrivateKey: "not sealed",
		PublicJWK: []byte(`{}`), NotBefore: time.Now().UTC(), RetireAt: time.Now().Add(time.Hour).UTC(), Expires: time.Now().Add(2 * time.Hour).UTC()}
	if err := h.env.Svc.Keys.Create(ctx, garbage); err != nil {
		t.Fatal(err)
	}
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := marshalPrivate(edPriv)
	id := model.NewID()
	mismatch := &model.SigningKey{Meta: model.Meta{ID: id}, Alg: AlgES256, PrivateKey: h.p.svc.Sealer.SealFor(service.SigningKeyBinding(id), der),
		PublicJWK: []byte(`{}`), NotBefore: time.Now().UTC(), RetireAt: time.Now().Add(time.Hour).UTC(), Expires: time.Now().Add(2 * time.Hour).UTC()}
	if err := h.env.Svc.Keys.Create(ctx, mismatch); err != nil {
		t.Fatal(err)
	}
	ks, err := h.p.loadKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{expired.ID, garbage.ID, mismatch.ID} {
		if ks.byKID[k] != nil {
			t.Errorf("key %s was loaded", k)
		}
	}
	if len(ks.list) == 0 {
		t.Fatal("no usable key left")
	}
}

func TestCoverageRemoveKeyRefusals(t *testing.T) {
	h := setup(t, nil)
	ctx := context.Background()
	h.p.keyMu.Lock()
	future, err := h.p.createKey(ctx, AlgES256, time.Now().Add(time.Hour))
	h.p.keyMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	h.p.Invalidate()
	if err := h.p.RemoveKey(ctx, future.ID); outcomeOf(err) != "invalid" {
		t.Fatalf("a key that has not started: %v", err)
	}
	// a key that no longer signs, whose deletion fails
	if err := h.p.RotateKeys(ctx); err != nil {
		t.Fatal(err)
	}
	ks, _ := h.p.keys(ctx)
	var old string
	for _, k := range ks.list {
		if ks.signer(k.alg, time.Now()) != k && !k.rec.NotBefore.After(time.Now()) {
			old = k.kid
		}
	}
	if old == "" {
		t.Fatal("no retired key")
	}
	good := h.env.Svc.Keys.S
	h.env.Svc.Keys.S = failDeletes{Store: good, kind: model.KindKey}
	if err := h.p.RemoveKey(ctx, old); err == nil {
		t.Fatal("removal reported success though the deletion failed")
	}
	h.env.Svc.Keys.S = good
	if err := h.p.RemoveKey(ctx, old); err != nil {
		t.Fatal(err)
	}
}
