package admin_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// The signing keys are listed newest first, each with its state, never with its private key.
func TestSigningKeyListing(t *testing.T) {
	w := newWorld(t)
	su := w.as("super")
	now := time.Now()
	for _, k := range []*model.SigningKey{
		{Meta: model.Meta{ID: "k-prev"}, Alg: "ES256", NotBefore: now.Add(-60 * 24 * time.Hour), RetireAt: now.Add(-time.Hour), Expires: now.Add(time.Hour)},
		{Meta: model.Meta{ID: "k-sign"}, Alg: "ES256", NotBefore: now.Add(-time.Hour), RetireAt: now.Add(29 * 24 * time.Hour), Expires: now.Add(30 * 24 * time.Hour)},
		{Meta: model.Meta{ID: "k-next"}, Alg: "ES256", NotBefore: now.Add(10 * time.Minute), RetireAt: now.Add(40 * 24 * time.Hour), Expires: now.Add(41 * 24 * time.Hour)},
	} {
		if err := w.env.Svc.Keys.Create(context.Background(), k); err != nil {
			t.Fatal(err)
		}
	}
	r := su.get("/api/keys")
	want(t, r, 200)
	states := map[string]string{}
	for _, it := range r.items() {
		m := it.(map[string]any)
		states[m["id"].(string)] = m["state"].(string)
		if _, leaked := m["private_key"]; leaked {
			t.Fatal("private key in the listing")
		}
	}
	if states["k-sign"] != "signing" || states["k-next"] != "next" || states["k-prev"] != "previous" {
		t.Fatalf("states: %v", states)
	}
	if first := r.items()[0].(map[string]any)["id"]; first != "k-next" {
		t.Fatalf("not newest first: %v", first)
	}
}

// Rotating and removing keys go through hooks the server wires: unwired they are not available, errors from them
// surface, successes are audited.
func TestKeyRotationHooks(t *testing.T) {
	w := newWorld(t)
	su := w.as("super")
	want(t, su.post("/api/keys/rotate", nil), 501)
	want(t, su.delete("/api/keys/old"), 501)

	w.mod.RotateKeys = func(context.Context) error { return errors.New("hsm down") }
	w.mod.RemoveKey = func(context.Context, string) error { return service.ErrNotFound }
	want(t, su.post("/api/keys/rotate", nil), 500)
	want(t, su.delete("/api/keys/old"), 404)

	w.mod.RotateKeys = func(context.Context) error { return nil }
	w.mod.RemoveKey = func(context.Context, string) error { return nil }
	r := su.post("/api/keys/rotate", nil)
	want(t, r, 200)
	if r.JSON["rotated"] != true {
		t.Errorf("rotate response: %s", r.Raw)
	}
	want(t, su.delete("/api/keys/old"), 200)
	for _, a := range []string{"keys.rotate", "keys.remove"} {
		if n := len(auditActions(t, w, a)); n != 1 {
			t.Errorf("%s audited %d times", a, n)
		}
	}
}
