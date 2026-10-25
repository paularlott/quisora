package service

import (
	"context"
	"errors"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Master key rotation: every secret sealed at rest (TOTP secrets, password hashes, sign-in provider client secrets, signing keys'
// private keys, upstream refresh tokens, relying parties' refresh token keys) is re-sealed with the active master key
// once it was sealed with a previous one (or before sealed values named their key). The housekeeping leader runs it
// until a pass finds nothing left: from then on nothing the server holds needs the previous keys, and they are
// removed from the configuration (only backups made before the rotation still need them, to be restored).

// ResealResult is the outcome of one ResealSecrets pass.
type ResealResult struct {
	Resealed int // values re-sealed with the active key
	Pending  int // stale values left for the next pass (the write limit was reached, or a concurrent change)
	Failed   int // values no key of the ring opens: sealed with a master key that is not configured, or damaged
}

// Done reports whether nothing the server holds needs anything but the active key.
func (r ResealResult) Done() bool { return r.Pending == 0 && r.Failed == 0 }

// ResealSecrets walks every sealed value and re-seals at most limit of them with the active master key.
func (s *Service) ResealSecrets(ctx context.Context, limit int) (ResealResult, error) {
	return s.resealSecrets(ctx, limit, false)
}

// resealSecrets is ResealSecrets; dry only counts (Pending: what a pass would re-seal; Failed) and writes
// nothing.
func (s *Service) resealSecrets(ctx context.Context, limit int, dry bool) (ResealResult, error) {
	var r ResealResult
	reseal := func(binding string, v *string, save func() error) error {
		if !s.Sealer.Stale(*v) {
			return nil
		}
		if dry {
			if _, err := s.Sealer.OpenFor(binding, *v); err != nil {
				r.Failed++
			} else {
				r.Pending++
			}
			return nil
		}
		if r.Resealed >= limit {
			r.Pending++
			return nil
		}
		nv, err := s.Sealer.Reseal(binding, *v)
		if err != nil {
			r.Failed++
			return nil
		}
		old := *v
		*v = nv
		if err := save(); err != nil {
			*v = old
			if errors.Is(err, store.ErrStale) || errors.Is(err, store.ErrNotFound) {
				r.Pending++ // changed meanwhile: the next pass sees the new value
				return nil
			}
			return mapStore(err)
		}
		r.Resealed++
		return nil
	}
	if err := walk(ctx, s.Users, func(u *model.User) error {
		save := func() error { return s.Users.Update(Durable(ctx), u) }
		if err := reseal(TOTPBinding(u.ID), &u.TOTPSecret, save); err != nil {
			return err
		}
		return reseal(PasswordBinding(u.ID), &u.PasswordHash, save)
	}); err != nil {
		return r, err
	}
	if err := walk(ctx, s.Providers, func(p *model.Provider) error {
		return reseal(ProviderSecretBinding(p.ID), &p.ClientSecret, func() error { return s.Providers.Update(Durable(ctx), p) })
	}); err != nil {
		return r, err
	}
	if err := walk(ctx, s.Keys, func(k *model.SigningKey) error {
		return reseal(SigningKeyBinding(k.ID), &k.PrivateKey, func() error { return s.Keys.Update(Durable(ctx), k) })
	}); err != nil {
		return r, err
	}
	if err := walk(ctx, s.Identities, func(id *model.Identity) error {
		return reseal(IdentityRefreshBinding(id.ID), &id.Refresh, func() error { return s.Identities.Update(ctx, id) })
	}); err != nil {
		return r, err
	}
	now := time.Now()
	err := walk(ctx, s.Grants, func(g *model.Grant) error {
		if g.Revoked || now.After(g.Expires) {
			return nil // never refreshed again
		}
		return reseal(GrantKeyBinding(g.ID), &g.Key, func() error { return s.Grants.Update(ctx, g) })
	})
	return r, err
}

// walk calls fn for every record of t, every organization, paging by key.
func walk[T any, PT interface {
	*T
	model.Entity
}](ctx context.Context, t *store.Table[T, PT], fn func(PT) error) error {
	after := ""
	for {
		page, _, err := t.List(ctx, store.ListQuery{After: after, Limit: 500})
		if err != nil {
			return mapStore(err)
		}
		for _, e := range page {
			if err := fn(e); err != nil {
				return err
			}
		}
		if len(page) < 500 {
			return nil
		}
		after = page[len(page)-1].GetMeta().ID
	}
}
