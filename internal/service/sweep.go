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

// sweepMinAge is how old a record must be before the sweep may remove it: well past the store's staleness bound, so
// its owner, made elsewhere at the same time, is visible here.
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
	// uses, for a provider that owns a sign-in client (Client.ProviderID), is that client: the provider must still
	// use it, or the client is a leftover of a change of the provider's source organization.
	uses string
}

// owners returns what r belongs to: it is an orphan once any of them is gone.
func owners(e model.Entity) []ownerRef {
	switch v := e.(type) {
	case *model.User:
		return []ownerRef{{kind: model.KindOrg, id: v.OrgID}}
	case *model.Group:
		return []ownerRef{{kind: model.KindOrg, id: v.OrgID}}
	case *model.Tenant:
		return []ownerRef{{kind: model.KindOrg, id: v.OrgID}}
	case *model.Client:
		if v.ProviderID != "" {
			return []ownerRef{{kind: model.KindOrg, id: v.OrgID}, {kind: model.KindProvider, id: v.ProviderID, uses: v.ID}}
		}
		return []ownerRef{{kind: model.KindOrg, id: v.OrgID}}
	case *model.Provider:
		return []ownerRef{{kind: model.KindOrg, id: v.OrgID}}
	case *model.Member:
		if !v.Active() {
			return nil // a removed membership expires on its own
		}
		return []ownerRef{{kind: model.KindGroup, id: v.GroupID}, {kind: model.KindUser, id: v.UserID}}
	case *model.TenantAccess:
		subject := model.KindUser
		if v.SubjectType == model.SubjectGroup {
			subject = model.KindGroup
		}
		return []ownerRef{{kind: model.KindTenant, id: v.TenantID}, {kind: subject, id: v.SubjectID}}
	case *model.Passkey:
		return []ownerRef{{kind: model.KindUser, id: v.UserID}}
	case *model.Identity:
		return []ownerRef{{kind: model.KindUser, id: v.UserID}, {kind: model.KindProvider, id: v.ProviderID}}
	case *model.APIToken:
		return []ownerRef{{kind: model.KindUser, id: v.UserID}}
	case *model.SignIn:
		return []ownerRef{{kind: model.KindUser, id: v.ID}}
	case *model.Session:
		if v.Passkey != "" { // signed in with a passkey: it stands on it (SessionUsable)
			return []ownerRef{{kind: model.KindUser, id: v.UserID}, {kind: model.KindPasskey, id: v.Passkey}}
		}
		return []ownerRef{{kind: model.KindUser, id: v.UserID}}
	case *model.Grant:
		return []ownerRef{{kind: model.KindUser, id: v.UserID}, {kind: model.KindClient, id: v.ClientID}}
	case *model.Lock: // an organization's open deletion guard (SweepOrphans judges every other lock by its lease)
		return []ownerRef{{kind: model.KindOrg, id: v.ID}}
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
	// The position moves on only once the whole batch is judged: an error part-way leaves it, and the next run reads
	// the batch again (what was removed is gone from it) instead of skipping what was not reached.
	nextKind, nextAfter := (sw.kind+1)%len(sweepKinds), ""
	if len(res.Records) >= batch {
		nextKind, nextAfter = sw.kind, res.Records[len(res.Records)-1].ID
	}
	now := time.Now()
	removed := 0
	var ents []model.Entity // decoded once, those old enough to judge
	for _, r := range res.Records {
		e := model.NewEntity(kind)
		if store.Decode(r, e) != nil {
			continue
		}
		// A lock is judged by its lease, except an organization's open deletion guard (no holder: see orgDeleting),
		// which is kept while its organization exists: the organization's creations of users assert it, and would
		// otherwise have to write it again (and those in flight try again).
		if l, ok := e.(*model.Lock); ok && l.Holder != "" {
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
		orphan := false
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
			s.Log.Info("removed a record whose owner is gone", "kind", kind, "id", e.GetMeta().ID, "owner", string(o.kind)+" "+o.id)
			removed++
			orphan = true
			break
		}
		if u, ok := e.(*model.User); ok && !orphan {
			if err := s.clearDanglingManager(ctx, u, known); err != nil {
				return removed, err
			}
		}
	}
	sw.kind, sw.after = nextKind, nextAfter
	return removed, nil
}

// clearDanglingManager gives u no manager when the manager is gone: the deletion of a user clears the manager of their
// reports as a follow-up (clearManagerOf) that an interruption can leave undone, and nothing else would.
func (s *Service) clearDanglingManager(ctx context.Context, u *model.User, known map[ownerRef]bool) error {
	m := ownerRef{kind: model.KindUser, id: u.Work.ManagerID}
	if m.id == "" || known[m] {
		return nil
	}
	gone, err := s.ownerGone(ctx, m)
	if err != nil {
		return err
	}
	if !gone {
		known[m] = true
		return nil
	}
	u.Work.ManagerID = ""
	err = s.Users.Update(ctx, u)
	if errors.Is(err, store.ErrStale) || errors.Is(err, store.ErrNotFound) {
		return nil // changed meanwhile: the next pass looks again
	}
	return mapStore(err)
}

// passedEpochs returns the ids of the credentials, sessions and refresh grants among ents made in an epoch their
// account has moved past (model.User.Counts: its sign-in was reset, its password reset, or an invitation acceptance
// that lost stored it). The accounts are read once (this node's copy, within the store's bound: the records judged are
// sweepMinAge old, so any epoch they were made in reached it long ago); an account gone is left to the owner check.
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
	users, err := s.Users.GetMany(ctx, slices.Collect(maps.Keys(owners)))
	if err != nil {
		return nil, mapStore(err)
	}
	byID := make(map[string]*model.User, len(users))
	for _, u := range users {
		byID[u.ID] = u
	}
	for _, e := range ents {
		if c, ok := e.(model.Credential); ok {
			if u := byID[c.Owner()]; u != nil && !u.Counts(c) {
				out[e.GetMeta().ID] = true
			}
		}
	}
	return out, nil
}

// ownerGone reports whether o no longer exists, as the store answers (a miss is answered only while this node is
// current within the store's bound, so an owner older than that is never taken for gone because it is missing here).
func (s *Service) ownerGone(ctx context.Context, o ownerRef) (bool, error) {
	if o.id == "" {
		return false, nil
	}
	r, err := s.Store.Get(ctx, o.kind, o.id)
	if errors.Is(err, store.ErrNotFound) {
		return true, nil
	}
	if err != nil || o.uses == "" {
		return false, mapStore(err)
	}
	var p model.Provider
	if err := store.Decode(r, &p); err != nil {
		return false, err
	}
	return p.ClientID != o.uses, nil
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
		recs, err := s.getMany(ctx, o.kind, []string{o.id})
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
		if gone, err := s.ownerGone(ctx, ownerRef{kind: model.KindOrg, id: u.OrgID}); err != nil || gone {
			return gone, err
		}
	}
	return false, nil
}
