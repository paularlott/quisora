package service

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Access that ends. An access entry with an end (TenantAccess.Expires) stops counting at that instant, on every node,
// because every access decision reads the entries again (ClientAccess): nothing has to run for that. What runs is the
// tidying that makes the end felt by the applications too, the same as when an administrator removes an entry
// (RemoveAccess) or narrows one (UpdateAccess): the people the entry let in are signed out of each application they no
// longer have (back-channel logout, their refresh grants and SSH certificates for it removed), and of the guest accounts
// they signed in to through it when it is an organization provider's sign-in client. Then the entry goes
// (ExpireAccess, run by the housekeeping leader).

// endLostAccessLater runs endLostAccess on its own goroutine: a group's entry can stand for thousands of people, more
// than a request should wait for. The decision has already changed, so this is only the applications being told.
func (s *Service) endLostAccessLater(ctx context.Context, t *model.Tenant, was *model.TenantAccess) {
	s.Background(ctx, BackgroundSweep, func(ctx context.Context) {
		if err := s.endLostAccess(ctx, t, was); err != nil {
			s.Log.WithError(err).Error("not everyone whose access ended could be signed out of the applications",
				"tenant", t.ID, "access", was.ID)
		}
	})
}

// endLostAccess signs the people access entry was (removed, ended, or as it was before it was narrowed) let in out of
// each of tenant t's applications it covered that they may no longer use, deciding each again (ClientAccess): another
// entry of theirs, or one of a group of theirs, may still let them in. Nothing to do in a tenant open to everyone.
func (s *Service) endLostAccess(ctx context.Context, t *model.Tenant, was *model.TenantAccess) error {
	if !t.Settings.MembersOnly {
		return nil
	}
	t, err := s.Tenants.Get(ctx, t.ID) // as it is now: made open since, it lets everyone in
	if errors.Is(err, store.ErrNotFound) {
		return nil // gone: its applications went with it
	}
	if err != nil {
		return mapStore(err)
	}
	if !t.Settings.MembersOnly {
		return nil
	}
	clients, err := s.coveredClients(ctx, t, was)
	if err != nil || len(clients) == 0 {
		return err
	}
	var ids []string
	switch was.SubjectType {
	case model.SubjectUser:
		ids = []string{was.SubjectID}
	case model.SubjectGroup:
		g, err := s.Groups.Get(ctx, was.SubjectID)
		if errors.Is(err, store.ErrNotFound) {
			return nil // a deleted group's entry let nobody in since the group went
		}
		if err != nil {
			return mapStore(err)
		}
		if ids, err = s.memberIDs(ctx, g); err != nil {
			return err
		}
	}
	var errs sweepErrs
	for chunk := range slices.Chunk(ids, 100) {
		users, err := s.Users.GetMany(ctx, chunk)
		if err != nil {
			errs.add(mapStore(err))
			continue
		}
		users = slices.DeleteFunc(users, func(u *model.User) bool { return u == nil || u.OrgID != t.OrgID })
		groupsOf, err := s.UserGroupsOf(ctx, users)
		if err != nil {
			errs.add(err)
			continue
		}
		entries := map[string]*model.TenantAccess{} // read once for the chunk
		for _, u := range users {
			gids := make([]string, 0, len(groupsOf[u.ID]))
			for _, g := range groupsOf[u.ID] {
				gids = append(gids, g.ID)
			}
			for _, c := range clients {
				app, err := s.clientAccess(ctx, t, c, u, gids, entries)
				if err != nil {
					errs.add(mapStore(err))
					continue
				}
				if app.Allowed {
					continue
				}
				if _, err := s.revokeAppAccess(ctx, u.ID, c.ID, false); err != nil {
					errs.add(err)
				}
				if c.ProviderID != "" {
					s.endGuestThrough(ctx, c, u.ID)
				}
			}
		}
		if ctx.Err() != nil {
			errs.add(ctx.Err())
			break
		}
	}
	return errs.err()
}

// coveredClients returns the applications of tenant t that access entry was covered.
func (s *Service) coveredClients(ctx context.Context, t *model.Tenant, was *model.TenantAccess) ([]*model.Client, error) {
	all, _, err := s.Clients.List(ctx, store.ListQuery{Scope: t.OrgID, Filters: []store.Filter{{Field: "tenant_id", Value: t.ID}}})
	if err != nil {
		return nil, mapStore(err)
	}
	return slices.DeleteFunc(all, func(c *model.Client) bool {
		return c.TenantID != t.ID || c.ServiceAccount || !was.Covers(c.ID)
	}), nil
}

// ExpireAccess removes every access entry whose end has passed, after signing the people it let in out of what they no
// longer have (endLostAccess), and records each in the organization's audit log. Run by the housekeeping leader.
// Returns how many entries went.
func (s *Service) ExpireAccess(ctx context.Context) (int, error) {
	now := time.Now()
	n := 0
	// Entries this pass could not remove (a write that failed, or a change that raced it) stay at the front of the
	// due list: they are skipped, and each read asks for that many more, so they never hide the ones behind them.
	stuck := map[string]bool{}
	for {
		limit := 200 + len(stuck)
		due, err := s.dueAccess(ctx, now, limit)
		if err != nil {
			return n, mapStore(err)
		}
		progress := false
		for _, acc := range due {
			if acc.Expires.IsZero() || acc.Expires.After(now) {
				return n, nil // sorted by end: the rest end later
			}
			if stuck[acc.ID] {
				continue
			}
			progress = true
			if err := s.expireEntry(ctx, acc); err != nil {
				stuck[acc.ID] = true
				if !errors.Is(err, store.ErrStale) && !errors.Is(err, store.ErrNotFound) {
					s.Log.WithError(err).Error("an access entry past its end could not be removed", "access", acc.ID)
				}
				continue
			}
			n++
		}
		if len(due) < limit || !progress {
			return n, nil
		}
	}
}

// expireEntry removes acc, an access entry past its end, as it was read: one changed meanwhile (given a later end) is
// left for the next pass to decide again (ErrStale). The people it let in are signed out first, so a failure there
// leaves the entry for the next pass to try again.
func (s *Service) expireEntry(ctx context.Context, acc *model.TenantAccess) error {
	t, err := s.Tenants.Get(ctx, acc.TenantID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return mapStore(err)
	}
	if t != nil {
		if err := s.endLostAccess(ctx, t, acc); err != nil {
			return err
		}
	}
	name, subject := acc.TenantID, acc.SubjectID
	if t != nil {
		name = t.Name
	}
	if n, _, err := s.accessSubject(ctx, System, acc.OrgID, acc.SubjectType, acc.SubjectID); err == nil {
		subject = n
	}
	return s.audited(ctx, System, acc.OrgID, "tenant.access.expire", name,
		map[string]string{acc.SubjectType: subject, "expires": acc.Expires.UTC().Format(time.RFC3339)},
		func() error { return s.Access.DeleteIf(ctx, acc.ID, acc.Version) })
}

// dueAccess returns up to limit access entries with an end, earliest end first: from the store's due index where it
// keeps one (the key-value stores, whose filtered queries would read every entry), else by a query (SQL answers it
// from its indexes).
func (s *Service) dueAccess(ctx context.Context, now time.Time, limit int) ([]*model.TenantAccess, error) {
	if dl, ok := s.Access.S.(store.DueLister); ok {
		recs, err := dl.ListDue(ctx, model.KindAccess, now, limit)
		if !errors.Is(err, store.ErrNoDueIndex) {
			if err != nil {
				return nil, err
			}
			out := make([]*model.TenantAccess, 0, len(recs))
			for _, r := range recs {
				var acc model.TenantAccess
				if err := store.Decode(r, &acc); err != nil {
					return nil, err
				}
				out = append(out, &acc)
			}
			return out, nil
		}
	}
	due, _, err := s.Access.List(ctx, store.ListQuery{Sort: "ends", Limit: limit, Filters: []store.Filter{
		{Field: "expiring", Value: true}}})
	return due, err
}
