package service

import (
	"context"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// freshMany reads the live records of kind with these ids in one read of the owners' copies (store.QuorumReader: a
// change committed before the read is seen, wherever it was made, even before it reached this node), or
// of this store without a cluster (it is the only copy). Missing, expired and deleted records are left out. part is the
// partition key of the records (the organization's id, for organization data) when the caller knows it, "" when it does
// not: with it the owner of that partition is asked (store.PartitionReader), without it an id this node does not hold
// is asked of every owner.
func (s *Service) freshMany(ctx context.Context, kind model.Kind, part string, ids []string) (map[string]*store.Record, error) {
	out := make(map[string]*store.Record, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	now := time.Now()
	if qr, ok := s.Store.(store.QuorumReader); ok {
		var recs map[string]*store.Record
		var err error
		if pr, ok := qr.(store.PartitionReader); ok && part != "" {
			recs, err = pr.FreshIn(ctx, kind, part, ids)
		} else {
			recs, err = qr.Fresh(ctx, kind, ids)
		}
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
	recs, err := store.GetMany(ctx, s.Store, kind, ids)
	if err != nil {
		return nil, mapStore(err)
	}
	for _, r := range recs {
		out[r.ID] = r
	}
	return out, nil
}

// FreshUser reads user id from the owners' copies (freshMany): a change of the account that a majority confirmed
// anywhere is seen, even before it has reached this node. The caller that knows the user's organization says it
// (FreshUserIn).
func (s *Service) FreshUser(ctx context.Context, id string) (*model.User, error) {
	return s.FreshUserIn(ctx, "", id)
}

// FreshUserIn is FreshUser for a user of organization orgID ("": not known), whose owner it asks directly.
func (s *Service) FreshUserIn(ctx context.Context, orgID, id string) (*model.User, error) {
	recs, err := s.freshMany(ctx, model.KindUser, orgID, []string{id})
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

// FreshPasskeyIn reads passkey id of organization orgID as its owner has it (freshMany): a sign-in that another node
// stored a moment ago is seen.
func (s *Service) FreshPasskeyIn(ctx context.Context, orgID, id string) (*model.Passkey, error) {
	recs, err := s.freshMany(ctx, model.KindPasskey, orgID, []string{id})
	if err != nil {
		return nil, err
	}
	r, ok := recs[id]
	if !ok {
		return nil, ErrNotFound
	}
	pk := &model.Passkey{}
	return pk, store.Decode(r, pk)
}
