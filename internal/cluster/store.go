package cluster

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/gossip/partition"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Store wraps a store.Store and implements store.Store.
//
// In a gossip cluster every write of a replicated kind (everything but short-lived KindEphemeral state) is a change
// sent to the owner of the record's partition (partition.Manager.Write): the owner checks it against the committed
// data, stamps its version and commits it on a majority of the cluster, and every node applies it (pstore.Commit).
// Reads are of this node's committed copy; Fresh reads through the owners. Without gossip (standalone, or nodes
// sharing one database) a write goes to the wrapped store, and the change hooks (and, for nodes sharing a database,
// the notices) run after it.
type Store struct {
	n      *Node
	inner  store.Store
	closed atomic.Bool
}

// open refuses every call once the store is closed (store.Store: ErrUnavailable), whatever node it would reach.
func (s *Store) open() error {
	if s.closed.Load() {
		return fmt.Errorf("%w: %w", store.ErrUnavailable, store.ErrClosed)
	}
	return nil
}

var (
	_ store.Store = (*Store)(nil)
)

// Inner returns the wrapped store.
func (s *Store) Inner() store.Store { return s.inner }

// Get returns the live record kind/id from this node's copy; in a gossip cluster, only while this node can vouch for the
// copy of the record's partition (the staleness gate, partstatus.go: store.ErrUnavailable otherwise).
func (s *Store) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if err := s.open(); err != nil {
		return nil, err
	}
	return s.gated(ctx, kind, id, func() (*store.Record, error) { return s.inner.Get(ctx, kind, id) })
}

// gated passes a single-record read of kind/id through the staleness gate: in a gossip cluster a record found is
// served only while its partition is readable here, and one not found only while the partition its kind and id name,
// if they name one, is (otherwise, while the node holds its data at all). Node-local kinds are exempt. The partition is
// known only from what read finds, so read runs first; a copy found behind is waited for (readable) and then read
// again, since what read returned before the wait is the copy the wait was for. So is one the gate found current
// only after a change landed here since the read (Node.applies): what read returned may predate that change.
func (s *Store) gated(ctx context.Context, kind model.Kind, id string, read func() (*store.Record, error)) (*store.Record, error) {
	before := s.n.applies.Load()
	r, err := read()
	if s.n.gc == nil || localOnly(kind) {
		return r, err
	}
	part := func(r *store.Record, err error) (int, error) {
		switch {
		case err == nil && r != nil:
			return recPartition(r), nil
		case errors.Is(err, store.ErrNotFound):
			if hp, ok := partitionHint(kind, id); ok {
				return hp, nil
			}
			// A record expired or deleted here still names its partition; only one never received does not (any).
			if id != "" {
				if old, lerr := s.inner.Lookup(ctx, kind, id); lerr == nil {
					return recPartition(old), nil
				}
			}
			return -1, nil
		}
		return 0, err
	}
	p, perr := part(r, err)
	if perr != nil {
		return r, err
	}
	if s.n.readableWithin(ctx, p, 0) == nil {
		if s.n.applies.Load() == before {
			return r, err
		}
	} else if gerr := s.n.readable(ctx, p); gerr != nil {
		return nil, gerr
	}
	r, err = read()
	if p2, perr := part(r, err); perr != nil {
		return r, err
	} else if p2 != p {
		if gerr := s.n.readableWithin(ctx, p2, 0); gerr != nil {
			return nil, gerr
		}
	}
	return r, err
}

// GetByUnique returns the live record of kind holding the unique value, through the staleness gate (Get). A unique
// value is unique within its kind and organization (model.Index.Unique), so it is indexed in the partition of the
// record that holds it.
func (s *Store) GetByUnique(ctx context.Context, kind model.Kind, value string) (*store.Record, error) {
	if err := s.open(); err != nil {
		return nil, err
	}
	return s.gated(ctx, kind, "", func() (*store.Record, error) { return s.inner.GetByUnique(ctx, kind, value) })
}

// Put writes rec (stamping this node as its Origin), replacing the record: in a gossip cluster the owner of its
// partition stamps the version, and refuses a live write over a tombstone (store.ErrDeleted) or a unique value held by
// another record (store.ErrConflict). rec.Version, Epoch and Created are the stored ones afterwards. A node that
// cannot know that its data is current refuses (store.ErrUnavailable, see Node.allowWrite); a write whose outcome is
// not known (the owner was lost mid-write) is store.ErrUnconfirmed.
func (s *Store) Put(ctx context.Context, rec *store.Record) error {
	if err := s.open(); err != nil {
		return err
	}
	return s.write(ctx, rec, modeUpsert, 0)
}

// CompareAndPut writes rec if the stored version is expect (0: no live record): in a gossip cluster the owner of the
// record's partition makes the comparison, so a write based on a copy that another node has changed meanwhile fails
// with store.ErrStale everywhere and the caller retries from fresh data.
func (s *Store) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	if err := s.open(); err != nil {
		return err
	}
	return s.write(ctx, rec, modeMatch, uint64(expect))
}

// GetMany reads several records in one round trip of the wrapped store (store.MultiGetter), or one by one. In a gossip
// cluster it is refused (the staleness gate, Get) when a record found is in a partition this node cannot read now.
func (s *Store) GetMany(ctx context.Context, kind model.Kind, ids []string) ([]*store.Record, error) {
	if err := s.open(); err != nil {
		return nil, err
	}
	before := s.n.applies.Load()
	recs, err := store.GetMany(ctx, s.inner, kind, ids)
	if err != nil || s.n.gc == nil || localOnly(kind) {
		return recs, err
	}
	if len(recs) < len(ids) { // a miss may be in any partition (gated)
		if err := s.n.readable(ctx, -1); err != nil {
			return nil, err
		}
	}
	// As gated: a partition found behind is waited for, and then everything is read again; so is a read a change landed
	// after (checked once the gates are passed).
	waited := false
	for p := range recPartitions(recs) {
		if s.n.readableWithin(ctx, p, 0) == nil {
			continue
		}
		if err := s.n.readable(ctx, p); err != nil {
			return nil, err
		}
		waited = true
	}
	if !waited && s.n.applies.Load() == before {
		return recs, nil
	}
	if recs, err = store.GetMany(ctx, s.inner, kind, ids); err != nil {
		return nil, err
	}
	for p := range recPartitions(recs) {
		if err := s.n.readableWithin(ctx, p, 0); err != nil {
			return nil, err
		}
	}
	return recs, nil
}

// recPartitions is the set of the partitions of recs.
func recPartitions(recs []*store.Record) map[int]struct{} {
	ps := make(map[int]struct{}, 1)
	for _, r := range recs {
		ps[recPartition(r)] = struct{}{}
	}
	return ps
}

// ListDue lists the records due from the wrapped store's due index (store.DueLister), or ErrNoDueIndex, through the
// staleness gate as an unscoped listing of kind is (gatedScope).
func (s *Store) ListDue(ctx context.Context, kind model.Kind, before time.Time, limit int) ([]*store.Record, error) {
	if err := s.open(); err != nil {
		return nil, err
	}
	dl, ok := s.inner.(store.DueLister)
	if !ok {
		return nil, store.ErrNoDueIndex
	}
	if err := s.gatedScope(ctx, kind, ""); err != nil {
		return nil, err
	}
	return dl.ListDue(ctx, kind, before, limit)
}

// Lookup returns the stored record whatever its state (store.Store), through the staleness gate (Get).
func (s *Store) Lookup(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if err := s.open(); err != nil {
		return nil, err
	}
	return s.gated(ctx, kind, id, func() (*store.Record, error) { return s.inner.Lookup(ctx, kind, id) })
}

// Snapshot delegates to the wrapped store when it has point-in-time views (store.Snapshotter). In a gossip cluster it
// is refused (store.ErrUnavailable) when the view may hold a partition part-way through a full import, which reset it
// first: a backup of it would be complete and verifiable, and miss that partition's records. That is when one is
// importing as the snapshot is asked for, or one began meanwhile (the view may be after its reset).
func (s *Store) Snapshot(ctx context.Context) (store.Reader, error) {
	if err := s.open(); err != nil {
		return nil, err
	}
	sn, ok := s.inner.(store.Snapshotter)
	if !ok {
		return nil, store.ErrNoSnapshot
	}
	if s.n.gc == nil || s.n.pst == nil {
		return sn.Snapshot(ctx)
	}
	return s.snapshotOf(ctx, sn)
}

// snapshotOf is Snapshot of sn, the wrapped store, in a gossip cluster.
func (s *Store) snapshotOf(ctx context.Context, sn store.Snapshotter) (store.Reader, error) {
	// Every partition must be readable here (none importing, behind or diverged): a snapshot is of one committed
	// point of all of them, or refused. A full import that begins meanwhile is the backend's to refuse: its view then
	// holds the import's marker (store.Snapshotter).
	if err := s.n.readableWithin(ctx, -1, 0); err != nil {
		return nil, err
	}
	return sn.Snapshot(ctx)
}

// PutReplicated applies a record as it is. Nothing in the cluster layer calls it: a gossip cluster's records arrive
// through partition writes only (a restore is made before the node starts, and then seeds its partitions: see
// StartNewCluster). Without gossip it applies locally and runs the hooks.
func (s *Store) PutReplicated(ctx context.Context, rec *store.Record) (bool, error) {
	if err := s.open(); err != nil {
		return false, err
	}
	if s.n.gc != nil {
		return false, errors.New("cluster: a gossip cluster's records arrive through its partitions")
	}
	applied, err := s.inner.PutReplicated(ctx, rec)
	if applied {
		s.n.fire(rec, false)
	}
	return applied, err
}

func (s *Store) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if err := s.open(); err != nil {
		return nil, err
	}
	if err := store.ValidateQuery(kind, q); err != nil { // a query that is wrong is wrong on any copy
		return nil, err
	}
	if err := s.gatedScope(ctx, kind, q.Scope); err != nil {
		return nil, err
	}
	return s.inner.List(ctx, kind, q)
}

// gatedScope passes a listing or count of the records of kind in scope through the staleness gate: a node that trails
// a partition must not answer "none" or a short list to a caller that decides on it (deleting a non-empty
// organization, ending a user's sessions). The kinds held only in the global partition need it readable; a scope that
// is an organization (users, groups, memberships, tenants, access entries, applications and providers are scoped by
// their organization, which is their partition) needs that partition; any other listing (a user's credentials and
// sessions, an unscoped one) may hold records of any partition, and needs every one (readable, p < 0). Node-local kinds
// are exempt.
func (s *Store) gatedScope(ctx context.Context, kind model.Kind, scope string) error {
	switch {
	case s.n.gc == nil || localOnly(kind):
		return nil
	case globalOnly(kind):
		return s.n.readable(ctx, globalPartition)
	}
	switch kind {
	case model.KindUser, model.KindGroup, model.KindMember, model.KindTenant, model.KindAccess, model.KindClient, model.KindProvider:
		if scope != "" {
			return s.n.readable(ctx, partitionNum(scope))
		}
	default:
		// A user's records (sessions, grants, credentials, tokens) are scoped by the user and in the user's partition.
		if scope != "" {
			if u, err := s.inner.Lookup(ctx, model.KindUser, scope); err == nil {
				return s.n.readable(ctx, recPartition(u))
			}
		}
	}
	return s.n.readable(ctx, -1)
}

// globalOnly reports whether every record of kind is in the global partition (model: an empty partition key).
func globalOnly(kind model.Kind) bool { return kind == model.KindOrg || kind == model.KindKey }

func (s *Store) Count(ctx context.Context, kind model.Kind, scope string) (int, error) {
	if err := s.open(); err != nil {
		return 0, err
	}
	if err := s.gatedScope(ctx, kind, scope); err != nil {
		return 0, err
	}
	return s.inner.Count(ctx, kind, scope)
}

func (s *Store) FeedID() string { return s.inner.FeedID() }

// Purge removes from this node's copy what expired before expiredBefore, and, without gossip, the tombstones written
// before tombstonesBefore. A gossip cluster's tombstones are its partitions' (a node catching up by sequence needs
// them): their owners purge them, as writes every node applies (purgeTombstones), and Purge leaves them alone.
func (s *Store) Purge(ctx context.Context, tombstonesBefore, expiredBefore time.Time) (int, error) {
	if err := s.open(); err != nil {
		return 0, err
	}
	if s.n.gc != nil {
		tombstonesBefore = time.Time{}
	}
	return s.inner.Purge(ctx, tombstonesBefore, expiredBefore)
}

func (s *Store) Close() error {
	s.closed.Store(true)
	return s.inner.Close()
}

// write runs one write of rec.
func (s *Store) write(ctx context.Context, rec *store.Record, mode uint8, expect uint64) (err error) {
	if err := store.Ended(ctx); err != nil {
		return err
	}
	if err := store.CheckRecord(rec); err != nil {
		return err
	}
	// Before the first attempt: every retry of the write carries the same request id, and a failed write leaves the
	// caller's record as it was passed (store.EnsureReq).
	defer store.EnsureReq(rec, &err)()
	if s.n.gc == nil || localOnly(rec.Kind) {
		return s.writeLocal(ctx, rec, mode, expect)
	}
	return s.writePartitioned(ctx, rec, mode, expect)
}

// localOnly reports whether records of kind k stay on the node that writes them in a gossip cluster: short-lived state
// and audit events (an audit page asks every node: AuditQuery). They are local writes, never part of a partition write,
// an export, an import or the seeding of a new cluster.
func localOnly(k model.Kind) bool { return k == model.KindEphemeral || k == model.KindAudit }

// writeLocal is a write to the wrapped store alone: standalone, nodes sharing a database (where the notices tell the
// others), and the node-local kinds (localOnly), which every node keeps for itself.
func (s *Store) writeLocal(ctx context.Context, rec *store.Record, mode uint8, expect uint64) error {
	n := s.n
	if err := n.allowWrite(ctx, rec); err != nil {
		return err
	}
	rec.Origin = n.id
	n.noteScope(ctx, rec)
	var err error
	if mode == modeMatch {
		err = s.inner.CompareAndPut(ctx, rec, hlc.Timestamp(expect))
	} else {
		err = s.inner.Put(ctx, rec)
	}
	if err != nil {
		n.forgetScope(rec)
		return err
	}
	n.notice(n.fire(rec, true))
	return nil
}

// applyWait bounds how long a write waits for this node to have applied it (the owner's commit notice reaches the other
// nodes a message after the commit): the write is committed whether or not it is seen here yet.
const applyWait = 5 * time.Second

// writePartitioned makes a change of rec on the owner of its partition (an organization's, or the global one).
func (s *Store) writePartitioned(ctx context.Context, rec *store.Record, mode uint8, expect uint64) error {
	n := s.n
	if err := n.allowWrite(ctx, rec); err != nil {
		return err
	}
	rec.Origin = n.id
	if rec.Deleted && mode == modeUpsert {
		mode = modeBlind // a deletion of a record that is not live writes nothing (store.Store.Put)
	}
	old, err := s.lookup(ctx, rec.Kind, rec.ID)
	if err != nil {
		return err
	}
	if rec.Deleted {
		// A tombstone carries the partition key of the record it deletes. A record this node does not hold yet may
		// be held by the owners.
		if old == nil {
			fresh, err := s.Fresh(ctx, rec.Kind, []string{rec.ID})
			if err != nil {
				return err
			}
			old = fresh[rec.ID]
		}
		if old == nil {
			if mode == modeMatch && expect != 0 {
				return store.ErrNotFound
			}
			return nil // nothing to delete
		}
		rec.Partition, rec.Scope = old.Partition, old.Scope
	} else if err := store.CheckMove(rec, old != nil, partitionOf(old)); err != nil {
		// (the owner refuses it too, when its copy holds the record; this node holds the writes it made itself)
		return err
	}
	provisional(rec)
	b, err := encodeRecord(rec)
	if err != nil {
		return err
	}
	p := recPartition(rec)
	res, err := s.submit(ctx, p, &change{Op: opWrite, Mode: mode, Expect: expect, Rec: b, Base: versionOf(old)})
	switch {
	case isDone(err): // a retry of this request's write, which landed (submit settled it)
		if err := s.settleDone(ctx, []*store.Record{rec}); err != nil {
			return err
		}
	case err != nil:
		var re *partition.RefusedError
		if errors.As(err, &re) && re.Code == whyNothing {
			return nil // deleted already
		}
		if behind := s.awaitRefused(ctx, p, err); behind != nil {
			return behind
		}
		return storeErr(err)
	default:
		var rep writeReply
		if err := decodeMsg(res.Reply, &rep); err != nil {
			return err
		}
		rec.Version, rec.Epoch, rec.Created = hlc.Timestamp(rep.Version), hlc.Timestamp(rep.Epoch), hlc.Timestamp(rep.Created)
		s.waitWritten(ctx, p, res.Pos)
	}
	return nil
}

// partitionOf is r's partition key ("" for nil).
func partitionOf(r *store.Record) string {
	if r == nil {
		return ""
	}
	return r.Partition
}

// lookup returns the record of kind and id this node holds in any state, or nil.
func (s *Store) lookup(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	r, err := s.inner.Lookup(ctx, kind, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return r, err
}

// submit sends a change to the owner of partition p and counts the outcome. The error is the library's. A write is
// seen through whatever the caller does (a client that disconnects does not leave a write half done): the library
// bounds it with its own write timeout.
// submitOnce writes change c to partition p once (submit settles its outcome).
func (s *Store) submitOnce(ctx context.Context, p int, c *change) (partition.Result, error) {
	n := s.n
	b, err := encodeMsg(c)
	if err != nil {
		return partition.Result{}, err
	}
	pm := n.manager()
	if pm == nil {
		return partition.Result{}, partition.ErrUnavailable
	}
	res, err := pm.Write(context.WithoutCancel(ctx), p, b)
	if err == nil && n.faults.lostReply() {
		err = fmt.Errorf("%w: the reply was lost (a test)", partition.ErrUnknown) // the write landed
	}
	switch {
	case err == nil:
		n.stats.writes.Add(1)
	case errors.Is(err, partition.ErrRefused):
		n.stats.refused.Add(1)
	case errors.Is(err, partition.ErrUnknown):
		n.stats.unknown.Add(1)
		err = fmt.Errorf("%w: %w", store.ErrUnconfirmed, err)
	default:
		n.stats.unavailable.Add(1)
	}
	return res, err
}

// waitApplied waits until this node has applied the committed write at pos, for at most bound (or until the Manager
// stops), and returns the wait's error.
func (s *Store) waitApplied(ctx context.Context, p int, pos partition.Pos, bound time.Duration) error {
	pm := s.n.manager()
	if pm == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bound)
	defer cancel()
	return pm.WaitApplied(ctx, p, pos)
}

// waitWritten waits until this node has applied the write it just made at pos, so that the writer reads its own write
// here. The write is committed whether or not this node sees it in time: that is not an error.
func (s *Store) waitWritten(ctx context.Context, p int, pos partition.Pos) {
	if err := s.waitApplied(ctx, p, pos, applyWait); err != nil {
		s.n.log.Debug("a committed write has not reached this node yet", "partition", p, "position", pos.String())
	}
}

// awaitRefused waits, after the owner refused a change of partition p (a version had moved, a unique value is held, the
// record is gone), until this node has applied what the owner had committed when it refused (RefusedError.Pos): the
// caller's next step is to read again, and a copy that is a message behind would show it the same stale state, on which
// it would build the retry, or from which it would miss what made the change stale (a refresh token presented again
// after its rotation, say). It waits for the partition's staleness bound (partition.Config.StaleAfter, past which this
// node refuses its reads of the partition anyway) and fails closed: a node that cannot catch up by then returns
// store.ErrUnavailable, to be retried, instead of the refusal the caller would judge by a copy it cannot trust. nil: the
// copy is current (or the error was not a refusal).
func (s *Store) awaitRefused(ctx context.Context, p int, err error) error {
	var re *partition.RefusedError
	if !errors.As(err, &re) {
		return nil
	}
	if werr := s.waitApplied(ctx, p, re.Pos, time.Duration(s.n.staleAfter.Load())); werr != nil {
		return fmt.Errorf("%w: this node is behind on partition %d", store.ErrUnavailable, p)
	}
	return nil
}

// storeErr turns what the partition protocol returned into what the store's callers expect.
func storeErr(err error) error {
	var re *partition.RefusedError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &re):
		switch re.Code {
		case whyStale:
			return store.ErrStale
		case whyConflict:
			return store.ErrConflict
		case whyDeleted:
			return store.ErrDeleted
		case whyNotFound:
			return store.ErrNotFound
		case whyMoved:
			return fmt.Errorf("%w: %s", store.ErrBadRecord, re.Msg)
		}
		return fmt.Errorf("cluster: the write was refused: %w", err)
	case errors.Is(err, store.ErrUnavailable):
		return err
	}
	return fmt.Errorf("%w: %v", store.ErrUnavailable, err)
}

// ---- fresh reads ----

// readChunk is the most ids one read of a partition asks for.
const readChunk = 100

// partitionHint is the partition of a record known from its kind and id alone.
func partitionHint(kind model.Kind, id string) (int, bool) {
	switch kind {
	case model.KindOrg, model.KindKey:
		return 0, true
	case model.KindLock, model.KindReplay:
		return partitionNum(id), true
	}
	return 0, false
}

// Fresh returns the committed state of the records kind/ids as the owners of their partitions have it: every write
// committed before the call is reflected (partition.Manager.Read). The ids are grouped by partition from this node's
// copy of each record (a record never changes partition); an id this node does not hold is asked of every partition's
// owner (FreshIn, which is told the partition, asks one). Tombstones are returned too (Deleted). Without gossip (a single
// node, or a shared database, which is the only copy) it is a local read.
func (s *Store) Fresh(ctx context.Context, kind model.Kind, ids []string) (map[string]*store.Record, error) {
	if err := s.open(); err != nil {
		return nil, err
	}
	out := map[string]*store.Record{}
	if len(ids) == 0 {
		return out, nil
	}
	if s.n.gc == nil {
		return s.freshLocal(ctx, kind, ids)
	}
	byPart := map[int][]string{}
	for _, id := range ids {
		if p, ok := partitionHint(kind, id); ok {
			byPart[p] = append(byPart[p], id)
			continue
		}
		r, err := s.lookup(ctx, kind, id)
		switch {
		case err != nil:
			return nil, err
		case r != nil:
			byPart[recPartition(r)] = append(byPart[recPartition(r)], id)
		default:
			for p := range partitions {
				byPart[p] = append(byPart[p], id)
			}
		}
	}
	return s.freshParts(ctx, kind, byPart)
}

// FreshIn is Fresh for records that are all in the partition of partitionKey (store.Record.Partition: an organization's
// id for its data): the owner of that one partition is asked, wherever this node holds the records or not. A key of ""
// means the caller does not know it (or the records are global): Fresh.
//
// The hint is the caller's: an id the hinted partition does not hold, but that this node holds in another partition,
// is read from that one's owner too. Absence is never concluded from the wrong partition (a caller that finds a record
// absent may delete what depends on it).
func (s *Store) FreshIn(ctx context.Context, kind model.Kind, partitionKey string, ids []string) (map[string]*store.Record, error) {
	if err := s.open(); err != nil {
		return nil, err
	}
	if partitionKey == "" || s.n.gc == nil {
		return s.Fresh(ctx, kind, ids)
	}
	if len(ids) == 0 {
		return map[string]*store.Record{}, nil
	}
	hint := partitionNum(partitionKey)
	out, err := s.freshParts(ctx, kind, map[int][]string{hint: ids})
	if err != nil {
		return nil, err
	}
	elsewhere := map[int][]string{}
	for _, id := range ids {
		if out[id] != nil {
			continue
		}
		r, err := s.lookup(ctx, kind, id)
		if err != nil {
			return nil, err
		}
		if r != nil && recPartition(r) != hint {
			elsewhere[recPartition(r)] = append(elsewhere[recPartition(r)], id)
		}
	}
	more, err := s.freshParts(ctx, kind, elsewhere)
	if err != nil {
		return nil, err
	}
	maps.Copy(out, more)
	return out, nil
}

// freshLocal reads from this store alone: without gossip it is the only copy.
func (s *Store) freshLocal(ctx context.Context, kind model.Kind, ids []string) (map[string]*store.Record, error) {
	out := map[string]*store.Record{}
	for _, id := range ids {
		if r, err := s.lookup(ctx, kind, id); err != nil {
			return nil, err
		} else if r != nil {
			out[id] = r
		}
	}
	return out, nil
}

// freshParts reads the ids of each partition from its owner, the partitions at once.
func (s *Store) freshParts(ctx context.Context, kind model.Kind, byPart map[int][]string) (map[string]*store.Record, error) {
	out := map[string]*store.Record{}
	if len(byPart) == 0 {
		return out, nil
	}
	if err := s.n.allowRead(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	var first error
	for p, pids := range byPart {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recs, err := s.readPartition(ctx, p, kind, pids)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if first == nil {
					first = err
					cancel()
				}
				return
			}
			for _, r := range recs {
				out[r.ID] = r
			}
		}()
	}
	wg.Wait()
	if first != nil {
		return nil, storeErr(first)
	}
	return out, nil
}

// readPartition reads ids of one kind from the owner of partition p, in chunks (a reply too large for one message is
// asked again in halves).
func (s *Store) readPartition(ctx context.Context, p int, kind model.Kind, ids []string) ([]*store.Record, error) {
	pm := s.n.manager()
	if pm == nil {
		return nil, partition.ErrUnavailable
	}
	var out []*store.Record
	for chunk := range slices.Chunk(ids, readChunk) {
		recs, err := s.readOwner(ctx, pm, p, kind, chunk)
		if err != nil {
			return nil, err
		}
		out = append(out, recs...)
	}
	return out, nil
}

func (s *Store) readOwner(ctx context.Context, pm *partition.Manager, p int, kind model.Kind, ids []string) ([]*store.Record, error) {
	req, err := encodeMsg(&readReq{Kind: string(kind), IDs: ids})
	if err != nil {
		return nil, err
	}
	s.n.stats.reads.Add(1)
	b, err := pm.Read(ctx, p, req)
	var re *partition.RefusedError
	if errors.As(err, &re) && re.Code == whyLarge && len(ids) > 1 {
		half := len(ids) / 2
		a, err := s.readOwner(ctx, pm, p, kind, ids[:half])
		if err != nil {
			return nil, err
		}
		c, err := s.readOwner(ctx, pm, p, kind, ids[half:])
		return append(a, c...), err
	}
	if err != nil {
		s.n.stats.readFailed.Add(1)
		return nil, err
	}
	var raw [][]byte
	if err := decodeMsg(b, &raw); err != nil {
		return nil, err
	}
	out := make([]*store.Record, 0, len(raw))
	for _, rb := range raw {
		r, err := decodeRecord(rb)
		if err != nil {
			return nil, err
		}
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out, nil
}
