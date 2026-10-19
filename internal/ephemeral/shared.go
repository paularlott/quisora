package ephemeral

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

// Shared is a Store kept in a database that every node uses (clusters without gossip, on PostgreSQL, MySQL,
// MariaDB or Valkey), so a sign-in started on one node can finish on any other. Single use and counters rely on the
// store's CompareAndPut: of two nodes taking the same code, exactly one wins. Records expire with their TTL and are
// purged with the other expired records.
type Shared struct {
	st store.Store
	t  *store.Table[model.Ephemeral, *model.Ephemeral]
}

var _ Store = (*Shared)(nil)

// NewShared returns a Shared store over st.
func NewShared(st store.Store) *Shared {
	return &Shared{st: st, t: store.NewTable[model.Ephemeral](st)}
}

// casRetries bounds the retries of a counter update that lost a race with another node; between attempts the
// caller backs off for a random 0.5–5 ms, so writers on one hot key spread out.
const casRetries = 40

// Contended is what Incr reports for a counter it could not update after casRetries attempts: more than any limit,
// so every caller fails closed (a rate limit trips, a jti counts as replayed). Only a key hammered by many writers
// at once gets there — which is what a rate limit is for.
const Contended = int64(1) << 40

// rid is the record id of ns/key: a hash, so ids have a fixed length and the key never appears in the database.
func rid(ns, key string) string {
	h := sha256.Sum256([]byte(ns + "\x00" + key))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func (s *Shared) New(ctx context.Context, ns string, value []byte, ttl time.Duration) (string, error) {
	id := secure.RandomToken(24)
	e := &model.Ephemeral{Meta: model.Meta{ID: rid(ns, id)}, Value: value, Expires: time.Now().Add(ttl)}
	return id, s.t.Create(ctx, e)
}

func (s *Shared) Set(ctx context.Context, ns, id string, value []byte, ttl time.Duration) error {
	return s.t.Put(ctx, &model.Ephemeral{Meta: model.Meta{ID: rid(ns, id)}, Value: value, Expires: time.Now().Add(ttl)})
}

func (s *Shared) Get(ctx context.Context, ns, id string) ([]byte, error) {
	e, err := s.t.Get(ctx, rid(ns, id))
	if err != nil {
		return nil, notFound(err)
	}
	return e.Value, nil
}

// Take reads the item and deletes it on the condition that nobody changed it since: the one node whose delete
// succeeds gets the value.
func (s *Shared) Take(ctx context.Context, ns, id string) ([]byte, error) {
	r, err := s.st.Get(ctx, model.KindEphemeral, rid(ns, id))
	if err != nil {
		return nil, notFound(err)
	}
	e := &model.Ephemeral{}
	if err := store.Decode(r, e); err != nil {
		return nil, err
	}
	if err := s.st.CompareAndPut(ctx, store.Tombstone(model.KindEphemeral, r.ID), r.Version); err != nil {
		return nil, notFound(err)
	}
	return e.Value, nil
}

func (s *Shared) Delete(ctx context.Context, ns, id string) error {
	err := s.st.Put(ctx, store.Tombstone(model.KindEphemeral, rid(ns, id)))
	if errors.Is(err, store.ErrStale) {
		return nil
	}
	return err
}

func (s *Shared) Incr(ctx context.Context, ns, key string, delta int64, window time.Duration) (int64, error) {
	id := rid(ns, key)
	for range casRetries {
		e, err := s.t.Get(ctx, id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			if delta == 0 {
				return 0, nil
			}
			e = &model.Ephemeral{Meta: model.Meta{ID: id}, N: delta, Expires: time.Now().Add(window)}
			err = s.t.Create(ctx, e)
		case err != nil:
			return 0, err
		case delta == 0:
			return e.N, nil
		default:
			e.N += delta
			err = s.t.Update(ctx, e)
		}
		if err == nil {
			return e.N, nil
		}
		if !errors.Is(err, store.ErrStale) && !errors.Is(err, store.ErrConflict) && !errors.Is(err, store.ErrNotFound) {
			return 0, err
		}
		// another node changed the counter (or created it, or it just expired): read it again, a little later
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(time.Duration(500+rand.IntN(4500)) * time.Microsecond):
		}
	}
	return Contended, nil
}

func notFound(err error) error {
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrStale) {
		return ErrNotFound
	}
	return err
}
