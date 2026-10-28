package service

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Master key rotation: every secret sealed at rest (TOTP secrets, password hashes, sign-in provider client secrets, signing keys'
// private keys, upstream refresh tokens, relying parties' refresh token keys) is re-sealed with the active master key
// once it was sealed with a previous one (or before sealed values named their key). The housekeeping leader runs it
// in passes, each for a bounded time, walking the stored records from where the previous pass stopped. A walk over
// all of them that leaves nothing stale ends the work: from then on nothing the server holds needs the previous keys,
// no pass reads a record again until the keys change, and they are removed from the configuration (only backups made
// before the rotation still need them, to be restored).
//
// Where it stands is published after every pass (resealRecordID), so any node's status reads one record rather than
// every stored secret.

// resealRecordID is the id of the record (a Lock, which is replicated and never expires: Until is far ahead) the
// leader publishes its ResealProgress in.
const resealRecordID = "master-key-reseal"

// ResealProgress is where the leader's re-seal stands for one active master key.
type ResealProgress struct {
	Key     string    `json:"key"`     // the active key's id: what the progress is about, and nothing else
	Started time.Time `json:"started"` // when the leader began re-sealing for it
	Total   int       `json:"total"`   // values re-sealed with it so far
	// Checked is when the last walk over every stored record ended (zero: none has yet). Stale is what that walk found
	// still sealed with a previous key and did not re-seal (the record changed meanwhile), Unopenable what no key of the
	// ring opens (sealed with a master key that is not configured, or damaged): both are as of Checked.
	Checked    time.Time `json:"checked"`
	Stale      int       `json:"stale"`
	Unopenable int       `json:"unopenable"`
}

// Done reports whether a walk over every stored record found nothing that needs anything but the active key.
func (p ResealProgress) Done() bool { return !p.Checked.IsZero() && p.Stale == 0 && p.Unopenable == 0 }

// ResealResult is the outcome of one ResealSecrets pass.
type ResealResult struct {
	Resealed int // values this pass re-sealed with the active key
	ResealProgress
}

// resealState is the leader's progress, in memory: the published ResealProgress, and the walk it is in the middle of.
type resealState struct {
	mu     sync.Mutex
	prog   ResealProgress
	synced bool // prog is what is published (not so at first: another leader's report may be there)
	// The walk in progress: the table (resealSteps) and the last record of it done, and what the records so far
	// turned out to be.
	step              int
	after             string
	stale, unopenable int
}

// ResealSecrets re-seals stale values with the active master key, walking the stored records from where the
// previous pass stopped, and stops once budget has passed (after the record it is on: every pass makes progress). A
// walk ends when every record has been seen; the next pass starts a new one only if that one found something left.
// A pass that finds the work done reads nothing.
func (s *Service) ResealSecrets(ctx context.Context, budget time.Duration) (res ResealResult, err error) {
	st := &s.reseal
	st.mu.Lock()
	defer st.mu.Unlock()
	pass := &resealPass{s: s, ctx: ctx, deadline: time.Now().Add(budget)}
	defer func() { res.Resealed, res.ResealProgress = pass.resealed, st.prog }()
	if key := s.Sealer.ActiveKeyID(); st.prog.Key != key {
		// The keys changed (or this process just began leading): what was found before says nothing of them. Say so
		// before reading anything: the status must not go on showing a finished re-seal for a moment that is over.
		st.begin(ResealProgress{Key: key, Started: time.Now()})
	}
	if err := s.flushReseal(ctx); err != nil || st.prog.Done() {
		return res, err
	}
	steps := s.resealSteps(pass)
	for st.step < len(steps) {
		end, err := steps[st.step]()
		if err != nil {
			return res, err
		}
		if !end {
			break
		}
		st.step, st.after = st.step+1, ""
	}
	if st.step == len(steps) { // every record has been seen: the walk is over
		st.prog.Checked, st.prog.Stale, st.prog.Unopenable = time.Now(), st.stale, st.unopenable
		st.step, st.stale, st.unopenable, st.synced = 0, 0, 0, false
	}
	return res, s.flushReseal(ctx)
}

// ResealRestart forgets what the re-seal found, so the next pass walks every record again, and says so. The leader
// calls it while a node seals with another key: whatever that node seals meanwhile is not covered by a walk made
// before.
func (s *Service) ResealRestart(ctx context.Context) error {
	st := &s.reseal
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.prog.Key != "" {
		st.begin(ResealProgress{})
	}
	return s.flushReseal(ctx)
}

// begin starts over with progress p.
func (st *resealState) begin(p ResealProgress) {
	st.prog, st.synced = p, false
	st.step, st.after, st.stale, st.unopenable = 0, "", 0, 0
}

// flushReseal publishes the progress unless it is published already.
func (s *Service) flushReseal(ctx context.Context) error {
	st := &s.reseal
	if st.synced {
		return nil
	}
	b, err := json.Marshal(st.prog)
	if err != nil {
		return err
	}
	if err := s.putLock(ctx, resealRecordID, string(b), time.Now().AddDate(10, 0, 0)); err != nil {
		return err
	}
	st.synced = true
	return nil
}

// resealProgress returns the progress the leader published for this node's active key (zero when there is none, or
// it is about another key or unreadable: nothing is known then).
func (s *Service) resealProgress(ctx context.Context) (ResealProgress, error) {
	l, err := s.Locks.Get(ctx, resealRecordID)
	if errors.Is(err, store.ErrNotFound) {
		return ResealProgress{}, nil
	}
	if err != nil {
		return ResealProgress{}, mapStore(err)
	}
	var p ResealProgress
	if json.Unmarshal([]byte(l.Holder), &p) != nil || p.Key != s.Sealer.ActiveKeyID() {
		return ResealProgress{}, nil
	}
	return p, nil
}

// resealPass is one ResealSecrets call.
type resealPass struct {
	s        *Service
	ctx      context.Context
	deadline time.Time
	resealed int
}

// sealedValue is a sealed value of a record and what it is bound to.
type sealedValue struct {
	binding string
	v       *string
}

// resealSteps returns the walks over each table that holds sealed values, in the order a cycle takes them.
func (s *Service) resealSteps(p *resealPass) []func() (bool, error) {
	now := time.Now()
	return []func() (bool, error){
		resealTable(p, s.Users, func(u *model.User) []sealedValue {
			return []sealedValue{{TOTPBinding(u.ID), &u.TOTPSecret}, {PasswordBinding(u.ID), &u.PasswordHash}}
		}),
		resealTable(p, s.Providers, func(v *model.Provider) []sealedValue {
			return []sealedValue{{ProviderSecretBinding(v.ID), &v.ClientSecret}}
		}),
		resealTable(p, s.Keys, func(k *model.SigningKey) []sealedValue {
			return []sealedValue{{SigningKeyBinding(k.ID), &k.PrivateKey}}
		}),
		resealTable(p, s.Identities, func(id *model.Identity) []sealedValue {
			return []sealedValue{{IdentityRefreshBinding(id.ID), &id.Refresh}}
		}),
		resealTable(p, s.Grants, func(g *model.Grant) []sealedValue {
			if now.After(g.Expires) {
				return nil // never refreshed again
			}
			return []sealedValue{{GrantKeyBinding(g.ID), &g.Key}}
		}),
	}
}

// resealTable returns the walk over t from the cursor: it re-seals the values of each record (values) and writes the
// record once, and reports whether it reached the end of t (false: the pass is out of time).
func resealTable[T any, PT interface {
	*T
	model.Entity
}](p *resealPass, t *store.Table[T, PT], values func(PT) []sealedValue) func() (bool, error) {
	return func() (bool, error) {
		st := &p.s.reseal
		return walk(p.ctx, t, &st.after, func(e PT) (bool, error) {
			changed := 0
			for _, sv := range values(e) {
				if !p.s.Sealer.Stale(*sv.v) {
					continue
				}
				nv, err := p.s.Sealer.Reseal(sv.binding, *sv.v)
				if err != nil {
					st.unopenable++
					continue
				}
				*sv.v = nv
				changed++
			}
			if changed > 0 {
				switch err := t.Update(p.ctx, e); {
				case err == nil:
					p.resealed += changed
					st.prog.Total += changed
					st.synced = false
				case errors.Is(err, store.ErrStale) || errors.Is(err, store.ErrNotFound):
					st.stale += changed // changed meanwhile: the next walk sees the new value
				default:
					return false, mapStore(err)
				}
			}
			return time.Now().After(p.deadline), nil
		})
	}
}

// walk calls fn for every record of t after the id *after, every organization, paging by key, and advances *after
// past each record fn is done with. It stops when fn returns true (the record it returned for is done), reporting
// whether it reached the end of t.
func walk[T any, PT interface {
	*T
	model.Entity
}](ctx context.Context, t *store.Table[T, PT], after *string, fn func(PT) (bool, error)) (bool, error) {
	for {
		page, _, err := t.List(ctx, store.ListQuery{After: *after, Limit: 500})
		if err != nil {
			return false, mapStore(err)
		}
		for _, e := range page {
			stop, err := fn(e)
			if err != nil {
				return false, err
			}
			*after = e.GetMeta().ID
			if stop {
				return false, nil
			}
		}
		if len(page) < 500 {
			return true, nil
		}
	}
}
