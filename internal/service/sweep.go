package service

import (
	"context"
	"errors"
	"maps"
	"math"
	"slices"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Records that belong to another one (a user's passkeys, a group's memberships, an organization's groups...) are not
// removed with it: deleting an organization, user, group, tenant or provider deletes that one record, and everything
// that was its stops counting at once, because it stands on its parent (a user on its organization:
// service.UserUsable; a credential on its user and epoch; a membership on its group; a link on its provider; an
// application on its organization). The sweep is the one cascade, also for what a stalled writer left behind (a group
// writer materializing a membership after its group went). Housekeeping reads every record of the kinds below, a
// batch at a time, and removes those whose owner is gone, and the credentials, sessions and refresh grants of an
// epoch their account has moved past (model.User.Counts). Kinds that expire soon on their own (links, keys, audit
// entries, replay records, removed memberships) need nothing more.

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

// partOf is the partition key of the record o names, given the entity e it owns: every owner but an organization and
// a self-registered client is of e's organization (and so in e's partition); an organization's own record is global
// ("": its partition is known from its kind), and so is a self-registered application's (it belongs to no organization,
// whoever's grant names it).
func (o ownerRef) partOf(e model.Entity) string {
	if o.kind == model.KindOrg || o.kind == model.KindClient && model.SelfRegisteredClientID(o.id) {
		return ""
	}
	return e.Index().Partition
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
		return []ownerRef{{model.KindUser, v.UserID}, {model.KindProvider, v.ProviderID}}
	case *model.APIToken:
		return []ownerRef{{model.KindUser, v.UserID}}
	case *model.SignIn:
		return []ownerRef{{model.KindUser, v.ID}}
	case *model.Session:
		return []ownerRef{{model.KindUser, v.UserID}}
	case *model.Grant:
		return []ownerRef{{model.KindUser, v.UserID}, {model.KindClient, v.ClientID}}
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
	removed := 0
	var ents []model.Entity // decoded once, those old enough to judge
	for _, r := range res.Records {
		e := model.NewEntity(kind)
		if store.Decode(r, e) != nil {
			continue
		}
		if l, ok := e.(*model.Lock); ok { // judged by its lease alone
			if now.Sub(l.Until) > lockRetention && s.Locks.DeleteIf(ctx, l.ID, l.Version) == nil {
				removed++
			}
			continue
		}
		if now.Sub(e.GetMeta().Updated) >= sweepMinAge {
			ents = append(ents, e)
		}
	}
	passed, err := s.passedEpochs(ctx, ents)
	if err != nil {
		return removed, err
	}
	known := map[ownerRef]bool{} // owners seen to exist in this batch
	for _, e := range ents {
		if passed[e.GetMeta().ID] { // of an epoch its account has moved past: counts for nothing
			if err := s.removeOrphan(ctx, e); err != nil {
				return removed, err
			}
			removed++
			continue
		}
		for _, o := range owners(e) {
			if known[o] {
				continue
			}
			gone, err := s.ownerGone(ctx, o, o.partOf(e))
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
			s.Log.Info("removed a record whose owner is gone", "kind", kind, "id", e.GetMeta().ID, "owner", string(o.kind)+" "+o.id)
			removed++
			break
		}
	}
	return removed, nil
}

// passedEpochs returns the ids of the credentials, sessions and refresh grants among ents made in an epoch their
// account has moved past (model.User.Counts: its sign-in was reset, its password reset, or an invitation acceptance
// that lost stored it). This node's copies of the accounts (one read) say which look passed; the owners' copies of
// those accounts confirm them, a chunk at a time, keeping only their epochs, so an epoch this node has not received
// yet never removes a record that counts, and a batch of 20,000 never holds 20,000 accounts. An account gone here is
// left to the owner check.
func (s *Service) passedEpochs(ctx context.Context, ents []model.Entity) (map[string]bool, error) {
	owners := map[string]bool{}
	for _, e := range ents {
		if c, ok := e.(model.Credential); ok {
			owners[c.Owner()] = true
		}
	}
	out := map[string]bool{}
	if len(owners) == 0 {
		return out, nil
	}
	local, err := s.Users.GetMany(ctx, slices.Collect(maps.Keys(owners)))
	if err != nil {
		return nil, mapStore(err)
	}
	here := make(map[string]*model.User, len(local))
	for _, u := range local {
		here[u.ID] = u
	}
	suspect := map[string]map[string]bool{} // by organization: accounts with a credential that looks passed here
	for _, e := range ents {
		if c, ok := e.(model.Credential); ok {
			if u := here[c.Owner()]; u != nil && !u.Counts(c) {
				if suspect[u.OrgID] == nil {
					suspect[u.OrgID] = map[string]bool{}
				}
				suspect[u.OrgID][u.ID] = true
			}
		}
	}
	here = nil
	fresh := map[string]*model.User{} // the epochs only
	for org, ids := range suspect {
		for chunk := range slices.Chunk(slices.Collect(maps.Keys(ids)), 500) {
			recs, err := s.freshMany(ctx, model.KindUser, org, chunk)
			if err != nil {
				return nil, err
			}
			for id, r := range recs {
				u := &model.User{}
				if err := store.Decode(r, u); err != nil {
					return nil, err
				}
				fresh[id] = &model.User{CredEpoch: u.CredEpoch, SessionEpoch: u.SessionEpoch}
			}
		}
	}
	for _, e := range ents {
		if c, ok := e.(model.Credential); ok {
			if u := fresh[c.Owner()]; u != nil && !u.Counts(c) {
				out[e.GetMeta().ID] = true
			}
		}
	}
	return out, nil
}

// ownerGone reports whether o no longer exists: missing here, and missing or deleted in the owners' copies (a record
// a majority has is never taken for gone because this node has not received it).
func (s *Service) ownerGone(ctx context.Context, o ownerRef, part string) (bool, error) {
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
	recs, err := s.freshMany(ctx, o.kind, part, []string{o.id})
	if err != nil {
		return false, err
	}
	_, live := recs[o.id]
	return !live, nil
}

// removeOrphan removes e. A membership is marked removed, not tombstoned, with a sequence no writer can pass, so a
// writer of its group that stalled cannot bring it back (model.Member); it then expires like any removed one.
func (s *Service) removeOrphan(ctx context.Context, e model.Entity) error {
	if m, ok := e.(*model.Member); ok {
		m.Removed, m.Seq = time.Now().UTC(), math.MaxUint64
		err := s.Members.Update(ctx, m)
		if errors.Is(err, store.ErrStale) || errors.Is(err, store.ErrNotFound) || err == nil {
			return nil // changed meanwhile: the next pass looks again
		}
		return mapStore(err)
	}
	err := s.Store.Put(ctx, store.Tombstone(e.Kind(), e.GetMeta().ID))
	if errors.Is(err, store.ErrStale) || err == nil {
		return nil
	}
	return mapStore(err)
}

// ReleaseUnique frees a unique value of kind held by a record that counts for nothing (dead): the record is removed
// now, as the sweep would remove it later, and ReleaseUnique answers true (also when the value was freed meanwhile),
// so the caller may try its create again once. A holder that counts keeps the value.
func (s *Service) ReleaseUnique(ctx context.Context, kind model.Kind, value string) (bool, error) {
	r, err := s.Store.GetByUnique(ctx, kind, value)
	if errors.Is(err, store.ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, mapStore(err)
	}
	e := model.NewEntity(kind)
	if e == nil {
		return false, nil
	}
	if err := store.Decode(r, e); err != nil {
		return false, err
	}
	if dead, err := s.dead(ctx, e); err != nil || !dead {
		return false, err
	}
	return true, s.removeOrphan(ctx, e)
}

// dead says whether e counts for nothing, from the owners' copies of its owners: an owner is gone, an owning user's
// organization is gone, or e is a credential of an epoch its account has moved past (model.User.Counts; judged, as
// the sweep judges it, only once e is sweepMinAge old: one stored for an invitation still in flight is of an epoch
// the account has not committed yet).
func (s *Service) dead(ctx context.Context, e model.Entity) (bool, error) {
	for _, o := range owners(e) {
		if o.id == "" {
			continue
		}
		recs, err := s.freshMany(ctx, o.kind, o.partOf(e), []string{o.id})
		if err != nil {
			return false, err
		}
		r, ok := recs[o.id]
		if !ok {
			return true, nil
		}
		if o.kind != model.KindUser {
			continue
		}
		u := &model.User{}
		if err := store.Decode(r, u); err != nil {
			return false, err
		}
		if c, ok := e.(model.Credential); ok && !u.Counts(c) && time.Since(e.GetMeta().Updated) >= sweepMinAge {
			return true, nil
		}
		if gone, err := s.ownerGone(ctx, ownerRef{model.KindOrg, u.OrgID}, ""); err != nil || gone {
			return gone, err
		}
	}
	return false, nil
}
