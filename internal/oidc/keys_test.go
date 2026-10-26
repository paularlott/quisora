package oidc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestKeyLifecycle(t *testing.T) {
	t.Parallel()
	h := setup(t, func(c *config.Config) { c.Tokens.KeyRotationDays = 1 })
	ctx := context.Background()
	p := h.p
	ks, _ := p.keys(ctx)
	if len(ks.list) != 1 || ks.list[0].alg != AlgES256 {
		t.Fatalf("expected one ES256 key at start, got %d", len(ks.list))
	}
	if err := p.EnsureKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.EnsureKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if ks, _ = p.keys(ctx); len(ks.list) != 1 {
		t.Fatalf("rotated too early: %d keys", len(ks.list))
	}
	first := ks.list[0].kid
	// age the key: pretend it became active 25 hours ago
	k, _ := h.env.Svc.Keys.Get(ctx, first)
	k.NotBefore = time.Now().Add(-25 * time.Hour)
	k.RetireAt = k.NotBefore.Add(24*time.Hour + keyOverlap)
	if err := h.env.Svc.Keys.Update(ctx, k); err != nil {
		t.Fatal(err)
	}
	p.Invalidate()
	if err := p.EnsureKeys(ctx); err != nil {
		t.Fatal(err)
	}
	ks, _ = p.keys(ctx)
	if len(ks.list) != 2 {
		t.Fatalf("expected a successor, have %d keys", len(ks.list))
	}
	succ := ks.list[1]
	if !succ.rec.NotBefore.After(time.Now().Add(keyOverlap - time.Minute)) {
		t.Fatalf("successor active too early: %v", succ.rec.NotBefore)
	}
	// published at once, signs only after the overlap; the retired key keeps signing until then
	var set JWKS
	_ = json.Unmarshal([]byte(body(h.get(h.http, "/oauth/jwks"))), &set)
	if len(set.Keys) != 2 {
		t.Fatalf("jwks has %d keys", len(set.Keys))
	}
	if got := ks.signer(AlgES256, time.Now()); got.kid != first {
		t.Fatal("successor signs before its NotBefore")
	}
	if got := ks.signer(AlgES256, time.Now().Add(keyOverlap+time.Minute)); got.kid != succ.kid {
		t.Fatal("successor does not take over")
	}
	// the old key outlives the last token it signed
	if !ks.list[0].rec.Expires.After(ks.list[0].rec.RetireAt.Add(p.cfg.Tokens.Access())) {
		t.Fatal("old key expires before its tokens do")
	}
	// a second scheduled check is a no-op
	if err := p.EnsureKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if ks, _ = p.keys(ctx); len(ks.list) != 2 {
		t.Fatalf("rotated twice: %d", len(ks.list))
	}
}

// An administrator's rotation takes effect at once: the new key signs from now on, the old one stays published so
// the tokens it signed keep verifying.
func TestForcedKeyRotation(t *testing.T) {
	t.Parallel()
	h := setup(t, nil) // no scheduled rotation configured
	ctx := context.Background()
	cl, secret := h.newClient(nil)
	before, _ := h.login(cl, secret, nil)
	oldKID := headerOf(t, before.str("access_token"))["kid"]
	if err := h.p.RotateKeys(ctx); err != nil {
		t.Fatal(err)
	}
	var set JWKS
	_ = json.Unmarshal([]byte(body(h.get(h.http, "/oauth/jwks"))), &set)
	if len(set.Keys) != 2 {
		t.Fatalf("jwks after rotation has %d keys", len(set.Keys))
	}
	after, _ := h.login(cl, secret, nil)
	if kid := headerOf(t, after.str("access_token"))["kid"]; kid == oldKID {
		t.Fatal("the old key still signs after a forced rotation")
	}
	if _, err := h.p.VerifyAccessToken(ctx, before.str("access_token")); err != nil {
		t.Fatalf("token signed by the previous key: %v", err)
	}
}

func TestSigningAlgorithms(t *testing.T) {
	t.Parallel()
	// EdDSA default; client-requested RS256 generated lazily
	h := setup(t, func(c *config.Config) { c.Tokens.SigningAlg = "EdDSA" })
	cl, secret := h.newClient(nil)
	rs, rsecret := h.newClient(func(in *service.ClientInput) { in.SigningAlg = ptr("RS256") })
	ks, _ := h.p.keys(context.Background())
	for _, k := range ks.list {
		if k.alg == AlgRS256 {
			t.Fatal("RS256 key generated eagerly")
		}
	}
	r, _ := h.login(cl, secret, nil)
	if headerOf(t, r.str("access_token"))["alg"] != "EdDSA" || headerOf(t, r.str("id_token"))["alg"] != "EdDSA" {
		t.Fatal("default alg")
	}
	r2, _ := h.login(rs, rsecret, nil)
	if headerOf(t, r2.str("id_token"))["alg"] != "RS256" || headerOf(t, r2.str("access_token"))["alg"] != "RS256" {
		t.Fatal("RS256 client")
	}
	jw, _ := ParseJWKS([]byte(body(h.get(h.http, "/oauth/jwks"))))
	algs := map[string]bool{}
	for _, j := range jw {
		algs[j.Alg] = true
		if j.Alg == AlgRS256 || j.Alg == AlgEdDSA {
			pub, err := j.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			tok := r2.str("id_token")
			if j.Alg == AlgEdDSA {
				tok = r.str("id_token")
			}
			decodeIndependently(t, tok, pub)
		}
	}
	if !algs[AlgRS256] || !algs[AlgEdDSA] {
		t.Fatalf("jwks algs %v", algs)
	}
	// RS256 at_hash uses SHA-256 left half; EdDSA uses SHA-512 left half
	sum := sha256.Sum256([]byte(r2.str("access_token")))
	if claimsOf(t, r2.str("id_token"))["at_hash"] != b64.EncodeToString(sum[:16]) {
		t.Fatal("RS256 at_hash")
	}
	if h.introspect(rs, rsecret, r2.str("access_token"))["active"] != true {
		t.Fatal("RS256 token does not verify")
	}
}

func TestUnknownKIDTriggersReload(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	// another node rotates: this node's cache does not know the new key yet
	h.p.keyMu.Lock()
	nk, err := h.p.createKey(context.Background(), AlgES256, time.Now().Add(-time.Minute))
	h.p.keyMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	ks, _ := h.p.keys(context.Background())
	if ks.byKID[nk.ID] != nil {
		t.Fatal("cache already knew the key")
	}
	if h.p.keyByKID(context.Background(), nk.ID) == nil {
		t.Fatal("unknown kid did not trigger a reload")
	}
	// unknown kids do not hammer the store: within the throttle window none is read, and a window that has passed lets
	// the next one through
	reads := &faultStore{Store: h.env.Svc.Keys.S}
	h.env.Svc.Keys.S = reads
	h.p.lastKIDReload.Store(time.Now().UnixNano())
	for range 3 {
		if h.p.keyByKID(context.Background(), "nope") != nil {
			t.Fatal("bogus kid found")
		}
	}
	if n := reads.lists.Load(); n != 0 {
		t.Fatalf("unknown kids read the store %d times within the throttle window", n)
	}
	h.p.lastKIDReload.Store(time.Now().Add(-time.Hour).UnixNano())
	if h.p.keyByKID(context.Background(), "nope") != nil {
		t.Fatal("bogus kid found")
	}
	if reads.lists.Load() == 0 {
		t.Fatal("an unknown kid after the throttle window did not reload")
	}
}

func TestKeysFailClosedWithoutStore(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	ctx := context.Background()
	good := h.env.Svc.Keys.S

	// with a key set already loaded, a failed reload keeps serving it
	h.env.Svc.Keys.S = failLists(good, model.KindKey)
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

func TestKeyCreationFailures(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	good := h.env.Svc.Keys.S
	h.env.Svc.Keys.S = failCAS(good, model.KindKey, func() error { return errors.New("keys: store refused") })
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

func TestKeyRecordsNotLoaded(t *testing.T) {
	t.Parallel()
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

// Removing a signing key refuses the one that signs and one that has not started, reports a failed deletion, and
// leaves the tokens of other keys alone.
func TestRemoveSigningKey(t *testing.T) {
	t.Parallel()
	// A key that may have been exposed: rotate, then remove the old key at once. Its tokens stop verifying; the refresh
	// token still works and its new access token is signed with the new key. The key that signs cannot be removed.
	t.Run("retired key", func(t *testing.T) {
		h := setup(t, nil)
		cl, secret := h.newClient(nil)
		r, _ := h.login(cl, secret, nil)
		at, rt := r.str("access_token"), r.str("refresh_token")
		ctx := context.Background()
		pj, err := ParseJWT(at)
		if err != nil {
			t.Fatal(err)
		}
		old := pj.Header.Kid
		if err := h.p.RemoveKey(ctx, old); outcomeOf(err) != "invalid" {
			t.Fatalf("removing the key that signs: %v", err)
		}
		if err := h.p.RotateKeys(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := h.p.VerifyAccessToken(ctx, at); err != nil {
			t.Fatalf("a rotation alone stopped the old key's token: %v", err)
		}
		if err := h.p.RemoveKey(ctx, "no-such-key"); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("unknown key: %v", err)
		}
		if err := h.p.RemoveKey(ctx, old); err != nil {
			t.Fatal(err)
		}
		if _, err := h.p.VerifyAccessToken(ctx, at); err == nil {
			t.Error("the removed key's token still verifies")
		}
		if resp := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+at); resp.StatusCode != 401 {
			t.Errorf("userinfo with the removed key's token: %d", resp.StatusCode)
		}
		x := h.refreshWith(cl, secret, rt)
		if x.status != 200 {
			t.Fatalf("refresh after removing the key: %d %v", x.status, x.m)
		}
		nat, _ := x.m["access_token"].(string)
		if npj, err := ParseJWT(nat); err != nil || npj.Header.Kid == old {
			t.Errorf("the new token: %v %+v", err, npj)
		}
		if resp := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+nat); resp.StatusCode != 200 {
			t.Errorf("userinfo with the new token: %d", resp.StatusCode)
		}
	})

	t.Run("refusals", func(t *testing.T) {
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
		h.env.Svc.Keys.S = failDeletes(good, model.KindKey)
		if err := h.p.RemoveKey(ctx, old); err == nil {
			t.Fatal("removal reported success though the deletion failed")
		}
		h.env.Svc.Keys.S = good
		if err := h.p.RemoveKey(ctx, old); err != nil {
			t.Fatal(err)
		}
	})
}

// A node whose master key cannot open the stored signing keys still publishes and verifies with them (the public key is
// stored in clear; other nodes sign with them), never signs with them, and never makes a key of its own while they
// exist: a key sealed with the wrong master key would replicate to every node.
func TestKeysThisNodeCannotOpen(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	ks, err := h.p.keys(ctx)
	if err != nil || len(ks.list) != 1 {
		t.Fatalf("keys: %v %d", err, len(ks.list))
	}
	kid, pub := ks.list[0].kid, ks.list[0].pub
	count := func() int {
		recs, _, err := h.env.Svc.Keys.List(ctx, store.ListQuery{})
		if err != nil {
			t.Fatal(err)
		}
		return len(recs)
	}
	good := h.env.Svc.Sealer
	wrong, err := secure.NewSealer(randBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	h.env.Svc.Sealer = wrong
	t.Cleanup(func() { h.env.Svc.Sealer = good })
	h.p.Invalidate()
	h.p.jwksCache.Store(nil)

	jwks, err := h.p.jwksJSON(ctx)
	if err != nil || !strings.Contains(string(jwks), kid) {
		t.Fatalf("the key this node cannot open is missing from the JWKS: %v %s", err, jwks)
	}
	k := h.p.keyByKID(ctx, kid)
	if k == nil || k.priv != nil || !reflect.DeepEqual(k.pub, pub) {
		t.Fatalf("verification key: %+v", k)
	}
	if _, err := h.p.signingKey(ctx, AlgES256); !errors.Is(err, errMasterKey) {
		t.Fatalf("signing with keys this node cannot open: %v", err)
	}
	if err := h.p.RotateKeys(ctx); !errors.Is(err, errMasterKey) {
		t.Fatalf("rotate: %v", err)
	}
	if err := h.p.EnsureKeys(ctx); err != nil { // nothing is due: nothing to make, nothing to refuse
		t.Fatalf("ensure: %v", err)
	}
	if n := count(); n != 1 {
		t.Fatalf("%d keys stored: a key was made over the ones this node cannot open", n)
	}

	h.env.Svc.Sealer = good
	h.p.Invalidate()
	if _, err := h.p.signingKey(ctx, AlgES256); err != nil {
		t.Fatalf("with the right master key: %v", err)
	}
	if n := count(); n != 1 {
		t.Fatalf("%d keys stored", n)
	}
}

// afterList runs after the first List of a kind, as the store answers.
type afterList struct {
	store.Store
	kind model.Kind
	once sync.Once
	do   func()
}

func (s *afterList) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	r, err := s.Store.List(ctx, kind, q)
	if kind == s.kind {
		s.once.Do(s.do)
	}
	return r, err
}

// A key change applied (Invalidate) while the keys are being read must not be undone by that read: the set read before
// the change is not installed, it is read again.
func TestKeyReloadRacingInvalidate(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	good := h.env.Svc.Keys.S
	t.Cleanup(func() { h.env.Svc.Keys.S = good })
	h.env.Svc.Keys.S = &afterList{Store: good, kind: model.KindKey, do: func() {
		// reloadKeys holds keyMu here, as createKey's callers do: a key is created and its change applied
		if _, err := h.p.createKey(ctx, AlgES256, time.Now()); err != nil {
			t.Error(err)
		}
		h.p.Invalidate()
	}}
	ks, err := h.p.reloadKeys(ctx, true)
	if err != nil || len(ks.list) != 2 {
		t.Fatalf("the reload returned the set read before the change: %v %d keys", err, len(ks.list))
	}
	if cached := h.p.keySet.Load(); cached == nil || len(cached.list) != 2 {
		t.Fatalf("the cached set predates the change: %+v", cached)
	}
}
