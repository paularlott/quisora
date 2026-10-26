package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/paularlott/quisora/internal/service"
	"slices"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

var randReader = rand.Reader

const (
	// keyOverlap is how long a freshly published key waits before it signs, so every relying party that caches the
	// JWKS (max-age 5 minutes) has seen it first.
	keyOverlap = 15 * time.Minute
	// keyRefresh is the backstop interval for re-reading signing keys from the store (Invalidate evicts sooner).
	keyRefresh = 60 * time.Second
	// unknownKIDRefresh bounds how often a token naming an unknown kid may force a reload.
	unknownKIDRefresh = 5 * time.Second
)

// keyEntry is one loaded signing key.
type keyEntry struct {
	rec    *model.SigningKey
	kid    string
	alg    string
	priv   crypto.Signer
	pub    crypto.PublicKey
	jwk    []byte
	hdrJWT string // base64url JOSE header for ID tokens and generic JWTs
	hdrAT  string // ... for RFC 9068 access tokens (typ at+jwt)
	hdrLT  string // ... for logout tokens (typ logout+jwt)
}

func (k *keyEntry) header(typ string) string {
	switch typ {
	case typAccess:
		return k.hdrAT
	case typLogout:
		return k.hdrLT
	}
	return k.hdrJWT
}

func (k *keyEntry) sign(typ string, payload []byte) (string, error) {
	return signJWT(k.alg, k.priv, k.header(typ), payload)
}

const (
	typJWT    = "JWT"
	typAccess = "at+jwt"
	typLogout = "logout+jwt"
)

func mkHeader(alg, kid, typ string) string {
	b := newObj(96)
	b.str("alg", alg)
	b.str("kid", kid)
	b.str("typ", typ)
	return b64.EncodeToString(b.bytes())
}

// keySet is an immutable snapshot of the stored signing keys.
type keySet struct {
	byKID  map[string]*keyEntry
	list   []*keyEntry // sorted by NotBefore ascending
	loaded time.Time
	// unopened counts the keys whose private part this node cannot open (another master key sealed it): they are
	// published and verify tokens (the public key is stored in clear) but never sign, and while any exists no new key
	// is made (it would be sealed with this node's master key, and replicated to the nodes that hold the right one).
	unopened int
}

// errMasterKey is the answer to making a signing key while stored keys cannot be opened.
var errMasterKey = errors.New("oidc: stored signing keys cannot be opened with this node's master key (master key mismatch); no signing key is made")

// signer picks the key that should sign now for alg: the most recently activated key that is within its signing
// window; failing that (housekeeping late) the newest key that has activated at all.
func (ks *keySet) signer(alg string, now time.Time) *keyEntry {
	var best, fallback *keyEntry
	for _, k := range ks.list {
		if k.alg != alg || k.priv == nil || k.rec.NotBefore.After(now) {
			continue
		}
		fallback = k
		if now.Before(k.rec.RetireAt) {
			best = k
		}
	}
	if best != nil {
		return best
	}
	return fallback
}

func (p *Provider) loadKeys(ctx context.Context) (*keySet, error) {
	recs, _, err := p.svc.Keys.List(ctx, store.ListQuery{})
	if err != nil {
		return nil, err
	}
	ks := &keySet{byKID: make(map[string]*keyEntry, len(recs)), loaded: time.Now()}
	for _, r := range recs {
		if time.Now().After(r.Expires) && !r.Expires.IsZero() {
			continue
		}
		der, err := p.svc.Sealer.OpenFor(service.SigningKeyBinding(r.ID), r.PrivateKey)
		if err != nil {
			// Not ours to sign with, but still published and verified: the public key is stored in clear, and the
			// nodes that can open it sign with it.
			e := publicOnly(r)
			if e == nil { // no public key to publish either: nobody can use the record
				p.log.Warn("oidc: cannot open signing key", "kid", r.ID, "error", err)
				continue
			}
			p.log.Error("oidc: cannot open signing key: master key mismatch", "kid", r.ID, "error", err)
			ks.byKID[r.ID] = e
			ks.list = append(ks.list, e)
			ks.unopened++
			continue
		}
		priv, pub, alg, err := parsePrivate(der)
		if err == nil && alg == AlgRS256 && r.Alg == AlgPS256 {
			alg = AlgPS256 // the same RSA key type, used with PSS
		}
		if err != nil || alg != r.Alg {
			p.log.Warn("oidc: bad signing key", "kid", r.ID, "error", err)
			continue
		}
		e := &keyEntry{rec: r, kid: r.ID, alg: alg, priv: priv, pub: pub, jwk: r.PublicJWK,
			hdrJWT: mkHeader(alg, r.ID, typJWT), hdrAT: mkHeader(alg, r.ID, typAccess), hdrLT: mkHeader(alg, r.ID, typLogout)}
		ks.byKID[r.ID] = e
		ks.list = append(ks.list, e)
	}
	slices.SortFunc(ks.list, func(a, b *keyEntry) int {
		if c := a.rec.NotBefore.Compare(b.rec.NotBefore); c != 0 {
			return c
		}
		return a.rec.Created.Compare(b.rec.Created)
	})
	return ks, nil
}

// publicOnly is the entry of a key whose private part cannot be opened: it verifies and is published, never signs.
func publicOnly(r *model.SigningKey) *keyEntry {
	var j JWK
	if json.Unmarshal(r.PublicJWK, &j) != nil {
		return nil
	}
	pub, err := j.PublicKey()
	if err != nil {
		return nil
	}
	return &keyEntry{rec: r, kid: r.ID, alg: r.Alg, pub: pub, jwk: r.PublicJWK}
}

// canMint reports whether a signing key may be made from ks: not while stored keys exist that this node cannot open.
func (p *Provider) canMint(ks *keySet) error {
	if ks.unopened > 0 {
		p.log.Error("oidc: not making a signing key: stored keys cannot be opened with this node's master key", "unopened", ks.unopened)
		return errMasterKey
	}
	return nil
}

// vouched refuses (store.ErrNotWritable) while this node cannot vouch for the signing keys (service GlobalReadable):
// nothing cached is served then, whatever its age.
func (p *Provider) vouched() error {
	if f := p.svc.GlobalReadable; f != nil && !f() {
		return fmt.Errorf("%w: this node trails the cluster's signing keys", store.ErrNotWritable)
	}
	return nil
}

// keys returns the cached key set, reloading it when stale.
func (p *Provider) keys(ctx context.Context) (*keySet, error) {
	if err := p.vouched(); err != nil {
		return nil, err
	}
	if ks := p.keySet.Load(); ks != nil && time.Since(ks.loaded) < p.keyMaxAge() {
		return ks, nil
	}
	return p.reloadKeys(ctx, false)
}

func (p *Provider) reloadKeys(ctx context.Context, force bool) (*keySet, error) {
	p.keyMu.Lock()
	defer p.keyMu.Unlock()
	if ks := p.keySet.Load(); ks != nil && !force && time.Since(ks.loaded) < p.keyMaxAge() {
		return ks, nil
	}
	for {
		gen := p.generation()
		ks, err := p.loadKeys(ctx)
		if err != nil {
			// The keys last loaded stand in while the store cannot be read, but not when this node cannot vouch for them
			// (it trails the cluster: a key may have been revoked since): it answers unavailable rather than publish them.
			if old := p.keySet.Load(); old != nil && !errors.Is(err, store.ErrNotWritable) {
				return old, nil
			}
			return nil, err
		}
		if p.install(ks, gen) {
			return ks, nil
		}
		// A key changed while the store was read (Invalidate): what was read may predate the change (a removed key
		// would be published again), so it is read again.
	}
}

// generation is the key set's generation: take it before reading the store, and install the result with it.
func (p *Provider) generation() uint64 {
	p.genMu.Lock()
	defer p.genMu.Unlock()
	return p.keyGen
}

// install caches ks, a key set read after generation gen was taken, unless Invalidate ran since: it says whether it did.
func (p *Provider) install(ks *keySet, gen uint64) bool {
	p.genMu.Lock()
	defer p.genMu.Unlock()
	if p.keyGen != gen {
		return false
	}
	p.keySet.Store(ks)
	return true
}

// Invalidate drops the cached signing keys (called by the cluster layer when a key record changes).
func (p *Provider) Invalidate() {
	p.genMu.Lock()
	p.keyGen++
	p.keySet.Store(nil)
	p.genMu.Unlock()
	p.verified.clear()
}

// signingKey returns the key that signs for alg, creating one on first use (RS256 and PS256 are only ever created this
// way).
func (p *Provider) signingKey(ctx context.Context, alg string) (*keyEntry, error) {
	ks, err := p.keys(ctx)
	if err != nil {
		return nil, err
	}
	if k := ks.signer(alg, time.Now()); k != nil {
		return k, nil
	}
	if !ValidAlg(alg) {
		return nil, fmt.Errorf("oidc: unsupported signing algorithm %q", alg)
	}
	p.keyMu.Lock()
	gen := p.generation()
	ks, err = p.loadKeys(ctx) // another node or request may have created it meanwhile
	if err == nil {
		p.install(ks, gen)
		if k := ks.signer(alg, time.Now()); k != nil {
			p.keyMu.Unlock()
			return k, nil
		}
		if err = p.canMint(ks); err == nil {
			_, err = p.createKey(ctx, alg, time.Now())
		}
	}
	p.keyMu.Unlock()
	if err != nil {
		return nil, err
	}
	ks, err = p.reloadKeys(ctx, true)
	if err != nil {
		return nil, err
	}
	if k := ks.signer(alg, time.Now()); k != nil {
		return k, nil
	}
	return nil, errors.New("oidc: no signing key available")
}

// keyByKID finds a published key for verification, reloading (rate limited) when the kid is unknown: another
// node may have rotated since this one last read the store.
func (p *Provider) keyByKID(ctx context.Context, kid string) *keyEntry {
	ks, err := p.keys(ctx)
	if err != nil {
		return nil
	}
	if k := ks.byKID[kid]; k != nil {
		return k
	}
	last := p.lastKIDReload.Load()
	now := time.Now().UnixNano()
	if now-last < int64(unknownKIDRefresh) || !p.lastKIDReload.CompareAndSwap(last, now) {
		return nil
	}
	if ks, err = p.reloadKeys(ctx, true); err != nil {
		return nil
	}
	return ks.byKID[kid]
}

func (p *Provider) maxTokenTTL() time.Duration {
	return max(p.cfg.Tokens.Access(), p.cfg.Tokens.IDToken(), 10*time.Minute)
}

func (p *Provider) rotation() time.Duration {
	return time.Duration(p.cfg.Tokens.KeyRotationDays) * 24 * time.Hour
}

// createKey generates, seals and stores a key that starts signing at notBefore. Callers hold keyMu.
func (p *Provider) createKey(ctx context.Context, alg string, notBefore time.Time) (*model.SigningKey, error) {
	var (
		priv crypto.Signer
		err  error
	)
	switch alg {
	case AlgES256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgEdDSA:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case AlgRS256, AlgPS256:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		err = fmt.Errorf("oidc: unsupported signing algorithm %q", alg)
	}
	if err != nil {
		return nil, err
	}
	der, err := marshalPrivate(priv)
	if err != nil {
		return nil, err
	}
	id := model.NewID()
	jwk, err := EncodeJWK(priv.Public(), id, alg)
	if err != nil {
		return nil, err
	}
	jb, _ := json.Marshal(jwk)
	retire := notBefore.Add(p.rotation() + keyOverlap)
	if p.rotation() <= 0 {
		retire = notBefore.AddDate(100, 0, 0)
	}
	k := &model.SigningKey{Meta: model.Meta{ID: id}, Alg: alg, PrivateKey: p.svc.Sealer.SealFor(service.SigningKeyBinding(id), der), PublicJWK: jb,
		NotBefore: notBefore.UTC(), RetireAt: retire.UTC(), Expires: retire.Add(p.maxTokenTTL() + 5*time.Minute).UTC()}
	org := model.PrimaryOrgID
	if o, err := p.svc.PrimaryOrg(ctx); err == nil {
		org = o.ID
	}
	if err := p.svc.Audited(ctx, service.System, org, "keys.create", id, map[string]string{"alg": alg,
		"not_before": k.NotBefore.Format(time.RFC3339), "retire_at": k.RetireAt.Format(time.RFC3339)},
		func() error { return p.svc.Keys.Create(ctx, k) }); err != nil {
		return nil, err
	}
	p.log.Info("oidc: signing key created", "kid", id, "alg", alg, "not_before", k.NotBefore)
	return k, nil
}

// EnsureKeys makes sure a current signing key exists for the configured algorithm (creating the first one) and
// rotates keys that are due. Safe to call on every node at start-up; only the elected leader needs to call
// RotateKeys periodically.
func (p *Provider) EnsureKeys(ctx context.Context) error { return p.rotate(ctx, false) }

// RotateKeys rotates now (the administrator's "rotate keys"): every algorithm in use gets a new key that signs from
// this moment. The previous keys stay published until the tokens they signed have expired (their Expires), so those
// tokens keep verifying; relying parties fetch the new key when they first see its kid.
//
// Scheduled rotation is EnsureKeys: a successor for every key that is due, published at once and signing after
// keyOverlap, and the default algorithm's first key. Expired keys disappear from the store by themselves.
func (p *Provider) RotateKeys(ctx context.Context) error { return p.rotate(ctx, true) }

func (p *Provider) rotate(ctx context.Context, force bool) error {
	p.keyMu.Lock()
	defer p.keyMu.Unlock()
	gen := p.generation()
	ks, err := p.loadKeys(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	algs := []string{p.cfg.Tokens.SigningAlg}
	for _, k := range ks.list {
		if !slices.Contains(algs, k.alg) {
			algs = append(algs, k.alg)
		}
	}
	created := false
	for _, alg := range algs {
		var newest *keyEntry
		for _, k := range ks.list {
			if k.alg == alg {
				newest = k
			}
		}
		var notBefore time.Time
		switch {
		case newest == nil, force:
			notBefore = now
		case p.rotation() > 0 && !now.Before(newest.rec.NotBefore.Add(p.rotation()-keyOverlap)):
			notBefore = now.Add(keyOverlap)
		default:
			continue
		}
		if err = p.canMint(ks); err == nil {
			_, err = p.createKey(ctx, alg, notBefore)
		}
		if err != nil {
			return err
		}
		created = true
	}
	if created {
		if ks, err = p.loadKeys(ctx); err != nil {
			return err
		}
	}
	p.install(ks, gen)
	return nil
}

// RemoveKey removes a signing key that no longer signs, at once rather than when the tokens it signed expire: they stop
// verifying here now, and relying parties stop accepting them once they fetch the key set again. For a key that may
// have been exposed (rotate first: the key that signs now, or will, cannot be removed). The caller audits it.
func (p *Provider) RemoveKey(ctx context.Context, id string) error {
	p.keyMu.Lock()
	defer p.keyMu.Unlock()
	ks, err := p.loadKeys(ctx)
	if err != nil {
		return err
	}
	k := ks.byKID[id]
	if k == nil {
		return service.ErrNotFound
	}
	now := time.Now()
	switch {
	case k.rec.NotBefore.After(now):
		return service.Invalid("id", "this key has not started signing yet; only a key that no longer signs can be removed")
	case ks.signer(k.alg, now) == k:
		return service.Invalid("id", "this key signs tokens now: rotate the keys first, then remove it")
	}
	if err := p.svc.Keys.Delete(ctx, id); err != nil {
		return err
	}
	gen := p.generation()
	if ks, err = p.loadKeys(ctx); err == nil {
		p.install(ks, gen)
	}
	return nil
}

// jwksJSON returns the published key set: every unexpired key (including ones that have not started signing).
func (p *Provider) jwksJSON(ctx context.Context) ([]byte, error) {
	if err := p.vouched(); err != nil {
		return nil, err
	}
	if c := p.jwksCache.Load(); c != nil && time.Since(c.at) < 30*time.Second && c.loaded == p.keySet.Load() {
		return c.body, nil
	}
	ks, err := p.keys(ctx)
	if err != nil {
		return nil, err
	}
	b := []byte(`{"keys":[`)
	for i, k := range ks.list {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, k.jwk...)
	}
	b = append(b, ']', '}')
	p.jwksCache.Store(&jwksSnapshot{body: b, at: time.Now(), loaded: ks})
	return b, nil
}

type jwksSnapshot struct {
	body   []byte
	at     time.Time
	loaded *keySet
}

// atHash is the OIDC at_hash for an access token signed with alg (left half of the SHA-256/512 digest).
func atHash(alg, accessToken string) string {
	if alg == AlgEdDSA {
		h := sha512.Sum512([]byte(accessToken))
		return b64.EncodeToString(h[:32])
	}
	h := sha256.Sum256([]byte(accessToken))
	return b64.EncodeToString(h[:16])
}

// keyMaxAge is how long the loaded key set is trusted before it is read again (ShortCaches shortens it).
func (p *Provider) keyMaxAge() time.Duration {
	if p.shortKeys.Load() {
		return shortTTL
	}
	return keyRefresh
}
