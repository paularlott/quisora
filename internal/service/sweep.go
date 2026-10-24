package service

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Records that belong to another one (a user's passkeys, a group's memberships, an organization's groups...) are
// removed with it, but some removals are best effort (a store failure part-way through deleting a user, a node that
// was away, a stalled group writer materializing a membership after its group went), and a record that does not
// expire would then stay for ever. The sweep finds them: housekeeping reads every record of the kinds that do not
// expire on their own, a batch at a time, and removes those whose owner is gone. Kinds that expire (sessions,
// refresh grants, links, keys, audit entries, replay records, removed memberships) need nothing more, and are read
// only when their owner can go before they expire.

// sweepKinds are the kinds the sweep reads, in turn.
var sweepKinds = []model.Kind{model.KindUser, model.KindGroup, model.KindMember, model.KindTenant, model.KindAccess,
	model.KindClient, model.KindProvider, model.KindPasskey, model.KindIdentity, model.KindAPIToken, model.KindSignIn,
	model.KindSession, model.KindGrant, model.KindLock}

// sweepMinAge is how old a record must be before the sweep may remove it: its owner, created on another node, may
// not have reached this one yet.
var sweepMinAge = time.Hour

// lockRetention is how long a lock record outlives its holder's lease (a holder that died; a node reporting its
// master keys that is gone) before the sweep removes it.
const lockRetention = 24 * time.Hour

// Sweep is the position of the orphan sweep (Service.SweepOrphans): kept by the caller between runs.
type Sweep struct {
	kind  int
	after string
}

type ownerRef struct {
	kind model.Kind
	id   string
}

// owners returns what r belongs to: it is an orphan once any of them is gone.
func owners(e model.Entity) []ownerRef {
	switch v := e.(type) {
	case *model.User:
		return []ownerRef{{model.KindOrg, v.OrgID}}
	case *model.Group:
		return []ownerRef{{model.KindOrg, v.OrgID}}
	case *model.Tenant:
		return []ownerRef{{model.KindOrg, v.OrgID}}
	case *model.Client:
		return []ownerRef{{model.KindOrg, v.OrgID}}
	case *model.Provider:
		return []ownerRef{{model.KindOrg, v.OrgID}}
	case *model.Member:
		if !v.Active() {
			return nil // a removed membership expires on its own
		}
		return []ownerRef{{model.KindGroup, v.GroupID}, {model.KindUser, v.UserID}}
	case *model.TenantAccess:
		subject := model.KindUser
		if v.SubjectType == model.SubjectGroup {
			subject = model.KindGroup
		}
		return []ownerRef{{model.KindTenant, v.TenantID}, {subject, v.SubjectID}}
	case *model.Passkey:
		return []ownerRef{{model.KindUser, v.UserID}}
	case *model.Identity:
		return []ownerRef{{model.KindUser, v.UserID}}
	case *model.APIToken:
		return []ownerRef{{model.KindUser, v.UserID}}
	case *model.SignIn:
		return []ownerRef{{model.KindUser, v.ID}}
	case *model.Session:
		return []ownerRef{{model.KindUser, v.UserID}}
	case *model.Grant:
		return []ownerRef{{model.KindUser, v.UserID}}
	}
	return nil
}

// SweepOrphans reads up to batch records from where sw stands, removes those whose owner is gone (and lock records
// long past their lease), and moves sw on; a whole pass over every kind takes as many runs as it needs. It returns
// how many records it removed. Only the housekeeping leader runs it.
func (s *Service) SweepOrphans(ctx context.Context, sw *Sweep, batch int) (int, error) {
	kind := sweepKinds[sw.kind%len(sweepKinds)]
	res, err := s.Store.List(ctx, kind, store.ListQuery{After: sw.after, Limit: batch})
	if err != nil {
		return 0, mapStore(err)
	}
	if len(res.Records) < batch {
		sw.kind, sw.after = (sw.kind+1)%len(sweepKinds), ""
	} else {
		sw.after = res.Records[len(res.Records)-1].ID
	}
	now := time.Now()
	known := map[ownerRef]bool{} // owners seen to exist in this batch
	removed := 0
	for _, r := range res.Records {
		e := model.NewEntity(kind)
		if store.Decode(r, e) != nil {
			continue
		}
		if l, ok := e.(*model.Lock); ok { // judged by its lease alone
			if now.Sub(l.Until) > lockRetention && store.Applied(s.Locks.DeleteIf(ctx, l.ID, l.Version)) {
				removed++
			}
			continue
		}
		if now.Sub(e.GetMeta().Updated) < sweepMinAge {
			continue
		}
		for _, o := range owners(e) {
			if known[o] {
				continue
			}
			gone, err := s.ownerGone(ctx, o)
			if err != nil {
				return removed, err
			}
			if !gone {
				known[o] = true
				continue
			}
			if err := s.removeOrphan(ctx, e); err != nil {
				return removed, err
			}
			s.Log.Info("removed a record whose owner is gone", "kind", kind, "id", r.ID, "owner", string(o.kind)+" "+o.id)
			removed++
			break
		}
	}
	return removed, nil
}

// ownerGone reports whether o no longer exists: missing here, and missing or deleted in a quorum's copies (a record
// a majority has is never taken for gone because this node has not received it).
func (s *Service) ownerGone(ctx context.Context, o ownerRef) (bool, error) {
	if o.id == "" {
		return false, nil
	}
	_, err := s.Store.Get(ctx, o.kind, o.id)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return false, mapStore(err)
	}
	qr, ok := s.Store.(store.QuorumReader)
	if !ok {
		return true, nil
	}
	recs, err := qr.Fresh(ctx, o.kind, []string{o.id})
	if err != nil {
		return false, mapStore(err)
	}
	r, ok := recs[o.id]
	return !ok || !r.Live(time.Now()), nil
}

// removeOrphan removes e. A membership is marked removed, not tombstoned, with a sequence no writer can pass, so a
// writer of its group that stalled cannot bring it back (model.Member); it then expires like any removed one.
func (s *Service) removeOrphan(ctx context.Context, e model.Entity) error {
	if m, ok := e.(*model.Member); ok {
		m.Removed, m.Seq = time.Now().UTC(), math.MaxUint64
		err := s.Members.Update(ctx, m)
		if errors.Is(err, store.ErrStale) || errors.Is(err, store.ErrNotFound) || store.Applied(err) {
			return nil // changed meanwhile: the next pass looks again
		}
		return mapStore(err)
	}
	err := s.Store.Put(ctx, store.Tombstone(e.Kind(), e.GetMeta().ID))
	if errors.Is(err, store.ErrStale) || store.Applied(err) {
		return nil
	}
	return mapStore(err)
}
