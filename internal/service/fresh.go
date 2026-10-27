package service

import (
	"context"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Reads are of this node's copy, as the store answers them: current within its bound (StaleAfter in a gossip
// cluster), or refused (store.ErrUnavailable). A decision that must be exact is made by a write (compare-and-swap), not
// by a read.

// getMany reads the live records of kind with these ids: missing, expired and deleted ones are left out.
func (s *Service) getMany(ctx context.Context, kind model.Kind, ids []string) (map[string]*store.Record, error) {
	out := make(map[string]*store.Record, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	recs, err := store.GetMany(ctx, s.Store, kind, ids)
	if err != nil {
		return nil, mapStore(err)
	}
	now := time.Now()
	for _, r := range recs {
		if r.Live(now) {
			out[r.ID] = r
		}
	}
	return out, nil
}

// getUser reads user id (ErrNotFound when there is none).
func (s *Service) getUser(ctx context.Context, id string) (*model.User, error) {
	u, err := s.Users.Get(ctx, id)
	return u, mapStore(err)
}

// UserByID reads user id for the sign-in steps (ErrNotFound when there is none).
func (s *Service) UserByID(ctx context.Context, id string) (*model.User, error) {
	return s.getUser(ctx, id)
}

// PasskeyByID reads passkey id (ErrNotFound when there is none).
func (s *Service) PasskeyByID(ctx context.Context, id string) (*model.Passkey, error) {
	pk, err := s.Passkeys.Get(ctx, id)
	return pk, mapStore(err)
}
