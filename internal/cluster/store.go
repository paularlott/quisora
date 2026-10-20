package cluster

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Store wraps a store.Store and implements store.Store. Local writes go to the inner store and are then pushed to the
// peers (the whole record when data replication is on, else a small invalidation); records received from peers are
// applied with PutReplicated. Every write, local or replicated, also fires the Node's OnChange hooks.
type Store struct {
	n     *Node
	inner store.Store
}

var _ store.Store = (*Store)(nil)

// Inner returns the wrapped store.
func (s *Store) Inner() store.Store { return s.inner }

func (s *Store) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	return s.inner.Get(ctx, kind, id)
}

func (s *Store) GetByUnique(ctx context.Context, kind model.Kind, value string) (*store.Record, error) {
	return s.inner.GetByUnique(ctx, kind, value)
}

// Put writes rec (stamping this node as its Origin). For a security-sensitive kind (model.QuorumCAS) in a gossip
// cluster it is a quorum compare-and-swap against whatever this node holds (quorumWrite): a majority of the nodes
// confirms it before it succeeds. Otherwise, with store.WithDurable(ctx) in replicated mode it returns once a
// majority holds the record, or once the peers failed to confirm it (logged, counted in Status.Unconfirmed: the
// write stands and ErrNotReplicated is not returned; with cluster.strict_durability it is undone where possible and
// store.ErrUnconfirmed is returned). A node that cannot know its data is current refuses (store.ErrNotWritable, see
// Node.allowWrite).
func (s *Store) Put(ctx context.Context, rec *store.Record) error {
	if s.quorumKind(rec) {
		return s.quorumWrite(ctx, rec, modeUpsert, 0)
	}
	return s.write(ctx, rec, func() error { return s.inner.Put(ctx, rec) })
}

// CompareAndPut writes rec if the stored version is expect (0: no live record). For a security-sensitive kind in a
// gossip cluster the comparison is made by a majority of the nodes, not only this one (quorumWrite): a write based
// on a copy that another node has changed meanwhile fails with store.ErrStale everywhere, and the caller retries
// from fresh data.
func (s *Store) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	if s.quorumKind(rec) {
		return s.quorumWrite(ctx, rec, modeMatch, expect)
	}
	return s.write(ctx, rec, func() error { return s.inner.CompareAndPut(ctx, rec, expect) })
}

// quorumKind reports whether rec is written with a quorum compare-and-swap: a security-sensitive kind
// (model.QuorumCAS) in a gossip cluster. The records "quisora bootstrap" creates keep their fixed, oldest version
// (model.BootstrapVersion: anything that exists anywhere wins over them) and are written as they are.
func (s *Store) quorumKind(rec *store.Record) bool {
	return s.n.gc != nil && model.QuorumCAS(rec.Kind) && !model.IsBootstrapRecord(rec.Kind, rec.ID, rec.Version)
}

// Lookup returns the stored record whatever its state (store.Store).
func (s *Store) Lookup(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	return s.inner.Lookup(ctx, kind, id)
}

// Snapshot delegates to the wrapped store when it has point-in-time views (store.Snapshotter).
func (s *Store) Snapshot(ctx context.Context) (store.Reader, error) {
	if sn, ok := s.inner.(store.Snapshotter); ok {
		return sn.Snapshot(ctx)
	}
	return nil, store.ErrNoSnapshot
}

// write runs one local write: the writability gate, the write itself, then hooks, broadcast and (durable) the
// majority acknowledgement.
func (s *Store) write(ctx context.Context, rec *store.Record, do func() error) error {
	n := s.n
	if err := n.allowWrite(ctx, rec); err != nil {
		return err
	}
	strict := n.strict(ctx, rec)
	var prev *store.Record
	if strict {
		// Refused before anything is applied when a majority cannot possibly confirm it.
		if err := n.canConfirm(); err != nil {
			return fmt.Errorf("%w: %v", store.ErrUnconfirmed, err)
		}
		prev, _ = s.inner.Get(ctx, rec.Kind, rec.ID) // what to put back if a majority does not confirm
	}
	rec.Origin = n.id
	n.noteScope(ctx, rec)
	if err := do(); err != nil {
		n.forgetScope(rec)
		return err
	}
	err := s.afterWrite(ctx, rec)
	if strict && errors.Is(err, ErrNotReplicated) {
		s.undo(ctx, rec, prev)
		return fmt.Errorf("%w: %v", store.ErrUnconfirmed, err)
	}
	if errors.Is(err, ErrNotReplicated) {
		return nil // applied; reaches the peers through the broadcast and anti-entropy (counted, logged)
	}
	return err
}

// undo reverses a strict durable write a majority did not confirm, with a newer write that replicates like any
// other: a created record is deleted, an updated one gets its previous content back. A deletion cannot be undone
// (a tombstone beats the record it deleted): it stands, and the caller is told it is unconfirmed. (Kinds whose
// writes are quorum compare-and-swaps never get here: nothing is applied before a majority has granted them.)
func (s *Store) undo(ctx context.Context, rec, prev *store.Record) {
	n := s.n
	if rec.Deleted {
		n.log.Warn("a deletion a majority did not confirm stands (it cannot be undone)", "kind", string(rec.Kind), "id", rec.ID)
		return
	}
	var back *store.Record
	if prev == nil {
		back = store.Tombstone(rec.Kind, rec.ID)
	} else {
		cp := *prev
		cp.Version = store.Clock.Now()
		back = &cp
	}
	back.Origin = n.id
	if err := s.inner.CompareAndPut(ctx, back, rec.Version); err != nil {
		n.log.WithError(err).Warn("could not undo an unconfirmed write (changed again since)", "kind",
			string(rec.Kind), "id", rec.ID)
		return
	}
	n.log.Warn("undid a write a majority did not confirm (cluster.strict_durability)", "kind", string(rec.Kind),
		"id", rec.ID)
	if err := s.afterWrite(context.WithoutCancel(store.WithoutDurable(ctx)), back); err != nil {
		n.log.WithError(err).Warn("broadcast undo", "kind", string(rec.Kind), "id", rec.ID)
	}
}

// PutReplicated is for the cluster layer; calling it directly applies the record locally and fires the hooks only.
func (s *Store) PutReplicated(ctx context.Context, rec *store.Record) (bool, []string, error) {
	applied, losers, err := s.inner.PutReplicated(ctx, rec)
	if applied {
		s.n.fire(rec, false)
	}
	return applied, losers, err
}

func (s *Store) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	return s.inner.List(ctx, kind, q)
}

func (s *Store) Count(ctx context.Context, kind model.Kind, scope string) (int, error) {
	return s.inner.Count(ctx, kind, scope)
}

func (s *Store) FeedID() string { return s.inner.FeedID() }

func (s *Store) Changes(ctx context.Context, since uint64, limit int) ([]store.Change, uint64, error) {
	return s.inner.Changes(ctx, since, limit)
}

func (s *Store) Purge(ctx context.Context, tombstonesBefore, expiredBefore time.Time) (int, error) {
	return s.inner.Purge(ctx, tombstonesBefore, expiredBefore)
}

func (s *Store) Close() error { return s.inner.Close() }

// afterWrite runs the hooks and tells the peers about a local write. A durable write then waits for a majority;
// ErrNotReplicated (wrapped) when it does not come (the write stands: counted and logged).
func (s *Store) afterWrite(ctx context.Context, rec *store.Record) error {
	n := s.n
	// the hooks, then (with a deletion's scope added) the notice to the nodes sharing the database (cluster.notify)
	n.notice(n.fire(rec, true))
	if n.gc == nil || localOnly(rec.Kind) { // node-local: never replicated
		return nil
	}
	b, err := encodeRecord(rec)
	if err != nil {
		return err
	}
	if err := n.gc.Send(msgRecord, &recordMsg{B: b}); err != nil {
		n.log.WithError(err).Warn("broadcast record")
	}
	if store.IsDurable(ctx) {
		// Applied here whatever the peers say: a write that a majority has not confirmed (yet) is still done, and
		// reaches the peers through the broadcast and anti-entropy. The wait outlives the request: a client that
		// disconnects does not undo a write that is already done.
		if err := n.ackPeers(context.WithoutCancel(ctx), b); err != nil {
			if !errors.Is(err, ErrNotReplicated) {
				return err
			}
			n.unconfirmed.Add(1)
			n.log.WithError(err).Warn("security change applied here but not yet confirmed by a majority",
				"kind", string(rec.Kind), "id", rec.ID)
			return err
		}
	}
	return nil
}

// localOnly reports whether records of kind k stay on the node that writes them in a gossip cluster: short-lived
// state (KindEphemeral) and audit events (each node keeps its own; the audit pages ask every node, or VictoriaLogs).
func localOnly(k model.Kind) bool { return k == model.KindEphemeral || k == model.KindAudit }

// errRefused: the record was not applied (from a separately bootstrapped cluster). A push is then not acknowledged.
var errRefused = errors.New("cluster: record refused")

// applyReplica applies a record received from a peer (the higher rank wins, store.Newer) and reports whether it
// was applied. A record that took a unique value from another (or lost one to it) is reported to the OnConflict
// hook; nothing is deleted over a unique clash.
func (s *Store) applyReplica(ctx context.Context, rec *store.Record) (bool, error) {
	n := s.n
	if localOnly(rec.Kind) {
		return false, nil // node-local (markers, leases, audit events) that reached a peer's feed
	}
	if s.otherBootstrap(ctx, rec) {
		return false, errRefused
	}
	n.checkSkew(rec)
	n.noteScope(ctx, rec)
	applied, losers, err := s.inner.PutReplicated(ctx, rec)
	if err != nil || !applied {
		n.forgetScope(rec)
	}
	if err != nil {
		return false, err
	}
	if applied {
		n.holdsData.Store(true)
		n.fire(rec, false)
	}
	for _, id := range losers {
		s.reportLoser(ctx, rec.Kind, id)
	}
	return applied, nil
}

// applyBatch applies the records of one feed page, in a single transaction where the backend supports it
// (store.BatchReplicator), with the same handling as applyReplica.
func (s *Store) applyBatch(ctx context.Context, recs []*store.Record) error {
	br, ok := s.inner.(store.BatchReplicator)
	if !ok {
		for _, r := range recs {
			if _, err := s.applyReplica(ctx, r); err != nil {
				return err
			}
		}
		return nil
	}
	n := s.n
	keep := slices.DeleteFunc(slices.Clone(recs), func(r *store.Record) bool {
		return localOnly(r.Kind) || s.otherBootstrap(ctx, r)
	})
	for _, r := range keep {
		n.checkSkew(r)
		n.noteScope(ctx, r)
	}
	applied, losers, err := br.PutReplicatedBatch(ctx, keep)
	if err != nil {
		for _, r := range keep {
			n.forgetScope(r)
		}
		return err
	}
	for i, rec := range keep {
		if !applied[i] {
			n.forgetScope(rec)
		}
		if applied[i] {
			n.holdsData.Store(true)
			n.fire(rec, false)
		}
		for _, id := range losers[i] {
			s.reportLoser(ctx, rec.Kind, id)
		}
	}
	return nil
}

// createdOf decodes a record's entity and returns its creation time.
func createdOf(r *store.Record) (time.Time, bool) {
	e := model.NewEntity(r.Kind)
	if e == nil || store.Decode(r, e) != nil {
		return time.Time{}, false
	}
	return e.GetMeta().Created, true
}

// otherBootstrap reports whether rec is one of the records "quisora bootstrap" creates (primary organization, its
// default tenant, the first administrator: fixed ids) but from another bootstrap than this node's — two clusters set
// up separately. It is never applied: both carry the same oldest version, so they would not resolve, and the other
// administrator's invitation would open this one. A node that has never copied from a peer is the newcomer and stops;
// a node that has keeps its records.
func (s *Store) otherBootstrap(ctx context.Context, rec *store.Record) bool {
	if rec.Deleted || !model.IsBootstrapID(rec.Kind, rec.ID) {
		return false
	}
	local, err := s.inner.Get(ctx, rec.Kind, rec.ID)
	if err != nil {
		return false
	}
	// The creation times come from the records' own data, which every backend keeps byte for byte (index columns do
	// not: SQL keeps microseconds, the key-value stores nanoseconds).
	a, aok := createdOf(local)
	b, bok := createdOf(rec)
	if !aok || !bok || a.Equal(b) {
		return false
	}
	n := s.n
	n.refused.Add(1)
	n.log.Warn("a record from a separately bootstrapped cluster was not applied", "kind", string(rec.Kind), "id", rec.ID)
	if why := n.ForcedStart(); why != "" {
		// This node's data was declared the cluster's by the operator: it is not the newcomer, and must not be
		// emptied on the strength of another cluster's records.
		n.log.Error("a node of a separately set-up cluster is in contact with this one (check cluster.peers and " +
			"cluster.key on every node): its records are refused; do not empty this node, it was forced as the " +
			"cluster's data")
		return true
	}
	if !n.joined.Load() {
		n.setBehind("this node was set up with \"quisora bootstrap\" on its own, but the cluster it joined was set up " +
			"separately: a node that joins an existing cluster needs no bootstrap. Start it with an empty database")
	}
	return true
}

// reportLoser handles a record that lost a unique value to another record created before it (store.KeepsUnique):
// it is kept — never deleted — and every node reports it to the OnConflict hook, which strips the value from it and
// flags it for an administrator (an audit event). Until then the record is simply not found by that value.
func (s *Store) reportLoser(ctx context.Context, kind model.Kind, id string) {
	n := s.n
	loser, err := s.inner.Get(ctx, kind, id)
	if err != nil {
		return
	}
	n.log.Warn("unique value clash: the record created first keeps the value, the other is kept without it",
		"kind", string(kind), "id", id)
	if fn := n.onConflict.Load(); fn != nil {
		(*fn)(loser)
	}
}
