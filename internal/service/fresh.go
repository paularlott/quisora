package service

import (
	"context"
	"errors"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// freshMany reads the live records of kind with these ids in one read of a quorum's copies (store.QuorumReader: a
// change a majority confirmed before the read is seen, wherever it was made, even before it reached this node), or
// of this store without a cluster (it is the only copy). Missing, expired and deleted records are left out.
func (s *Service) freshMany(ctx context.Context, kind model.Kind, ids []string) (map[string]*store.Record, error) {
	out := make(map[string]*store.Record, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	now := time.Now()
	if qr, ok := s.Store.(store.QuorumReader); ok {
		recs, err := qr.Fresh(ctx, kind, ids)
		if err != nil {
			return nil, mapStore(err)
		}
		for id, r := range recs {
			if r.Live(now) {
				out[id] = r
			}
		}
		return out, nil
	}
	for _, id := range ids {
		r, err := s.Store.Get(ctx, kind, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, mapStore(err)
		}
		out[id] = r
	}
	return out, nil
}

// FreshUser reads user id from a quorum's copies (freshMany): a change of the account that a majority confirmed
// anywhere is seen, even before it has reached this node.
func (s *Service) FreshUser(ctx context.Context, id string) (*model.User, error) {
	recs, err := s.freshMany(ctx, model.KindUser, []string{id})
	if err != nil {
		return nil, err
	}
	r, ok := recs[id]
	if !ok {
		return nil, ErrNotFound
	}
	u := &model.User{}
	return u, store.Decode(r, u)
}
