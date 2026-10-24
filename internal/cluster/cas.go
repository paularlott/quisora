package cluster

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Quorum compare-and-swap (docs/REPLICATION.md, "Quorum compare-and-swap").
//
// Writes of security-sensitive kinds (model.QuorumCAS) are not applied first and replicated after: they are
// two-phase commits validated by a majority of the cluster, so that of two concurrent writes from the same base at
// most one takes effect anywhere, and a write made from a copy that is no longer the newest is refused everywhere.
//
//  1. Stamp: the writer checks its local precondition (the version it read is still the one it holds, or there is no
//     live record for a create), mints a fresh version, and sets the generation (Epoch: kept from the record read; a
//     re-creation takes the version of the tombstone it read) and Created.
//  2. Prepare, on this node and every alive peer in parallel. Each voter validates the write against what it holds:
//     its copy must not rank above the base the writer read (a voter that lags behind may grant; one holding anything
//     newer answers stale, and sends its copy back so the writer repairs its own); a live write onto a deletion of a
//     later generation is refused (deleted); the version must exceed everything the voter holds or has granted for
//     the record (low: the writer witnesses the voter's floor and retries with a new stamp); a live write onto a
//     record the voter granted a deletion of must be of a generation at least that deletion's version (low, with
//     the epoch to take: the deletion may be in effect somewhere, and the later write must outrank it); a record
//     another write holds an intent on answers busy. A voter that grants records an intent (exclusive, expiring
//     after intentTTL) and raises its high-water mark for the record. Nothing is written. A voter that is catching
//     up answers not ready and is not counted.
//  3. Decide: grants from a quorum (this node included) commit the write. A stale or deleted answer before that fails
//     it (store.ErrStale / store.ErrDeleted: the caller retries from fresh data; an upsert re-bases by itself); busy,
//     low and not-ready answers make the writer retry with a new stamp after a short random pause, for at most
//     intentTTL+1s; anything else fails it with store.ErrUnconfirmed. Intents of a write that does not commit are
//     released (abort, naming the stamp: a late abort of one attempt never releases the next attempt's intent).
//  4. Commit to every voter that granted: each applies the record only while it still holds the intent ("applied
//     this exact version over the base"), then releases it. The write succeeds once a quorum (this node included)
//     has applied it; the record is then broadcast to the other nodes, and anti-entropy heals anything missed.
//
// Safety: two writes from one base need grants from two quorums, which share a voter; it grants one and refuses the
// other (busy while the first holds its intent, stale once it applied it). A write that fails in prepare is applied
// nowhere. A write whose commit reached fewer than a quorum (a voter died mid-commit) is reported as failed
// (store.ErrUnconfirmed) but may be in effect on some nodes; a later conflicting write must prepare at a quorum that
// shares a voter with the first write's grants, whose high-water mark forces the later write to a higher version
// (and, over a partial deletion, a generation at least the deletion's), so the later write ranks above the partial
// one everywhere. That holds across a restart of the voter without anything on disk, because clocks are
// synchronised: a voter grants nothing more than voteAhead ahead of its clock and votes again only restartPause after
// it starts, past every version it granted before (see the voter type).

// Write modes.
const (
	modeMatch  uint8 = iota + 1 // compare-and-swap: the base is the version the caller read (CompareAndPut, Update)
	modeUpsert                  // whole-record write over whatever this node holds; re-based when stale (Put)
	modeBlind                   // a deletion: no base (a tombstone outranks every earlier generation anyway)
)

// Voter answers.
const (
	stGrant    uint8 = iota // prepare: granted; commit: applied this exact version
	stStale                 // the voter holds a newer copy than the writer's base
	stDeleted               // a live write onto a deletion the writer had not seen
	stBusy                  // another write holds an intent on the record
	stLow                   // the version does not exceed what the voter holds or has granted (prepareResp.Floor)
	stNotReady              // the voter is catching up (or out of date): it takes no part
	stFailed                // anything else (decode or store error; commit: intent no longer held)
)

// intentTTL is how long a granted intent holds a record. A writer that dies after prepare blocks the record for at
// most this long.
const intentTTL = 5 * time.Second

// hwKeep is how long a record's high-water mark is kept before it is folded into the voter's floor.
const hwKeep = time.Minute

type prepareReq struct {
	Op          string // the write's identity: a retry supersedes its own earlier intent
	Rec         []byte // encodeRecord
	Mode        uint8
	BaseEpoch   uint64 // the rank of the copy the writer based the write on (0, 0: none)
	BaseVersion uint64
}

type prepareResp struct {
	St    uint8
	Floor uint64 // stLow: the version the write must exceed
	Epoch uint64 // stLow: the generation a live write must be at least (a deletion of the record was granted)
	Cur   []byte // stStale, stDeleted: the voter's copy (read repair)
}

type commitReq struct {
	Op  string
	Rec []byte
}

type commitResp struct {
	St uint8
}

type abortReq struct {
	Op      string
	Version uint64 // the attempt aborted: an intent re-granted to a later stamp of the same write stays
}

type readReq struct {
	Kind string
	IDs  []string
}

type readResp struct {
	NotReady bool
	Failed   bool     // a copy could not be read: the answer proves nothing and is not counted
	Recs     [][]byte // the voter's copies (tombstones included); absent ids are left out
}

type intent struct {
	op      string
	version hlc.Timestamp
	exp     time.Time
}

type hwMark struct {
	v  hlc.Timestamp
	at time.Time
}

// voter is this node's side of quorum compare-and-swap: the intents it granted, the high-water marks of the versions
// it granted, and the deletions it granted but has not applied. All live in memory, but for a deletion that stays
// unapplied past intentTTL (its commit never came: voterstate.go). A restart is made safe by the clocks, which every
// node keeps synchronised (NTP): a voter never grants a version more than voteAhead ahead of its own clock, and a
// voter that starts takes part in no quorum write for restartPause, by when its clock has passed every version it
// granted before. Its floor, the clock at start, then refuses all of them, with nothing on disk.
type voter struct {
	n         *Node
	stripes   [64]sync.Mutex // serialise prepare and commit of one record
	mu        sync.Mutex     // guards the fields below
	intents   map[string]*intent
	hw        map[string]hwMark
	floor     hlc.Timestamp
	resumeAt  time.Time          // votes only from then on (restartPause after it started)
	deletions map[string]delMark // deletions granted and not applied here, by record
	broken    string             // the saved deletions could not be read: this node does not vote
}

// delMark is a deletion a voter granted and has not applied (yet).
type delMark struct {
	op    string
	v     hlc.Timestamp
	at    time.Time
	saved bool // in voterFile
	done  bool // applied here or aborted since it was saved: the prune loop forgets it and rewrites the file
}

// voteAhead is how far ahead of the voter's clock a granted version may be. Versions come from the writers' clocks,
// which may run up to store.MaxSkew ahead of the machine's (store.Witness), and the machines' clocks agree within
// NTP's milliseconds: twice that bound is far above anything a healthy cluster mints, and a writer whose versions go
// past it has a clock the cluster must not follow.
var voteAhead = 2 * store.MaxSkew

// restartPause is how long a voter takes no part in quorum writes after it starts: at least voteAhead, so every
// version it granted before a restart is behind its clock when it votes again. Its peers form the quorum meanwhile;
// a whole cluster that starts at once accepts quorum writes once it has passed.
var restartPause = voteAhead

func newVoter(n *Node) *voter {
	v := &voter{n: n, intents: map[string]*intent{}, hw: map[string]hwMark{}, floor: store.Clock.Now(),
		resumeAt: time.Now().Add(restartPause), deletions: map[string]delMark{}}
	if n.dir == "" {
		return v
	}
	dels, err := loadVoterState(n.dir, n.maxDowntime())
	if err != nil {
		// It cannot know what it promised before: it takes no part in quorum writes (it answers not ready, and
		// the others decide without it) until the file is repaired or removed.
		v.broken = err.Error()
		n.log.WithError(err).Error("quorum voter state unreadable: this node takes no part in quorum writes until "+
			"the file is repaired or removed", "dir", n.dir)
		return v
	}
	v.deletions = dels
	return v
}

func recKey(kind model.Kind, id string) string { return string(kind) + "/" + id }

func (v *voter) stripe(k string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(k))
	return &v.stripes[h.Sum32()%uint32(len(v.stripes))]
}

// votes reports whether this node takes part in quorum writes: it holds the cluster's data (it has caught up since
// it started and is neither out of date nor misconfigured).
func (n *Node) votes() bool {
	return n.refusal() == "" && !n.catchingUp.Load() && !n.bootstrap.Load()
}

// prepare validates rec (stamped by the writer) against this node's copy and, when it may commit, grants it an
// intent (see the package comment above).
func (v *voter) prepare(ctx context.Context, op string, rec *store.Record, mode uint8, base store.Rank) prepareResp {
	n := v.n
	if !n.votes() || v.broken != "" || time.Now().Before(v.resumeAt) {
		return prepareResp{St: stNotReady}
	}
	k := recKey(rec.Kind, rec.ID)
	sm := v.stripe(k)
	sm.Lock()
	defer sm.Unlock()
	cur, err := n.st.inner.Lookup(ctx, rec.Kind, rec.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		cur = nil
	case err != nil:
		return prepareResp{St: stFailed}
	}
	now := time.Now()
	if rec.Version > hlc.FromTime(now.Add(voteAhead)) {
		n.checkSkew(rec) // logged and counted (clock_skewed)
		return prepareResp{St: stFailed}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if in := v.intents[k]; in != nil && in.op != op && now.Before(in.exp) {
		return prepareResp{St: stBusy}
	}
	if cur != nil {
		refuse := uint8(0)
		switch {
		case !rec.Deleted && cur.Deleted && rec.Epoch < cur.Version:
			refuse = stDeleted // a live write onto a deletion its writer had not seen
		case !rec.Deleted && !cur.Deleted && rec.Epoch < cur.Epoch:
			refuse = stStale // a write of an older generation than the one held here
		case mode != modeBlind && base.Less(cur.Rank()):
			refuse = stStale // this node holds a newer copy than the one the write is based on
		}
		if refuse != 0 {
			b, _ := encodeRecord(cur)
			return prepareResp{St: refuse, Cur: b}
		}
	}
	floor := max(v.floor, v.hw[k].v)
	if cur != nil {
		floor = max(floor, cur.Version)
	}
	// A deletion this voter granted may be in effect somewhere even though it holds the record live (the deletion's
	// commit reached fewer than a quorum): a later live write must outrank it, by its generation.
	epoch := hlc.Timestamp(0)
	if d, ok := v.deletions[k]; ok && !d.done && !rec.Deleted && rec.Epoch < d.v {
		epoch = d.v
	}
	if rec.Version <= floor || epoch != 0 {
		return prepareResp{St: stLow, Floor: uint64(floor), Epoch: uint64(epoch)}
	}
	if rec.Deleted {
		v.deletions[k] = delMark{op: op, v: rec.Version, at: now} // until it is applied here (commit) or aborted
	}
	v.intents[k] = &intent{op: op, version: rec.Version, exp: now.Add(intentTTL)}
	v.hw[k] = hwMark{v: rec.Version, at: now}
	store.Witness(rec.Version)
	return prepareResp{St: stGrant}
}

// commit applies rec while this node still holds the intent op was granted, and releases it. stGrant: this node now
// holds exactly rec's version.
func (v *voter) commit(ctx context.Context, op string, rec *store.Record, local bool) uint8 {
	n := v.n
	k := recKey(rec.Kind, rec.ID)
	sm := v.stripe(k)
	sm.Lock()
	defer sm.Unlock()
	v.mu.Lock()
	in := v.intents[k]
	held := in != nil && in.op == op && in.version == rec.Version && time.Now().Before(in.exp)
	if held {
		delete(v.intents, k)
	}
	v.mu.Unlock()
	if !held {
		return stFailed // expired (another write may have been granted since) or never granted
	}
	applied, err := n.st.applyCommitted(ctx, rec, local)
	if err != nil {
		n.log.WithError(err).Warn("apply a committed write", "kind", string(rec.Kind), "id", rec.ID)
		return stFailed // a deletion's mark stays: it may be in effect elsewhere
	}
	if applied || n.holds(rec) {
		if rec.Deleted {
			v.forgetDeletion(k, op, rec.Version)
		}
		return stGrant
	}
	return stFailed
}

// forgetDeletion drops the mark of the deletion op granted at version, once it is applied here or aborted.
func (v *voter) forgetDeletion(k, op string, version hlc.Timestamp) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if m, ok := v.deletions[k]; ok && m.op == op && m.v == version {
		if m.saved {
			m.done = true // the prune loop forgets it and rewrites the file
			v.deletions[k] = m
		} else {
			delete(v.deletions, k)
		}
	}
}

// release drops the intents op holds for the stamp version (abort). An intent a later attempt of op was granted
// (another stamp) stays: the abort of an earlier attempt can arrive after it.
func (v *voter) release(op string, version hlc.Timestamp) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for k, in := range v.intents {
		if in.op == op && in.version == version {
			delete(v.intents, k)
		}
	}
	// An aborted deletion was applied nowhere, or (a late grant released after the decision) by a quorum without
	// this node: either way no later write needs to outrank it here.
	for k, m := range v.deletions {
		if m.op == op && m.v == version {
			if m.saved {
				m.done = true
				v.deletions[k] = m
			} else {
				delete(v.deletions, k)
			}
		}
	}
}

// pruneLoop drops expired intents, folds old high-water marks into the floor, and saves or forgets deletion marks
// (pruneDeletions).
func (v *voter) pruneLoop() {
	defer v.n.wg.Done()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-v.n.ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		v.mu.Lock()
		for k, in := range v.intents {
			if !now.Before(in.exp) {
				delete(v.intents, k)
			}
		}
		for k, m := range v.hw {
			if now.Sub(m.at) > hwKeep {
				v.floor = max(v.floor, m.v)
				delete(v.hw, k)
			}
		}
		v.pruneDeletions(now)
		v.mu.Unlock()
	}
}

// pruneDeletions (v.mu held) saves the deletion marks still unapplied past intentTTL — the deletion's commit never
// came here, and it may be in effect on the nodes it did reach — and forgets those applied or aborted since, those
// whose deletion has reached this node since (anti-entropy), and those older than a node may stay away (a partial
// deletion older than that cannot come back). The file is rewritten only when that changes what it holds: rarely.
func (v *voter) pruneDeletions(now time.Time) {
	n, changed := v.n, false
	for k, d := range v.deletions {
		old := now.Sub(d.at) > intentTTL
		if !d.done && (old || d.saved) { // once the deletion is here, nothing needs the mark
			if kind, id, ok := strings.Cut(k, "/"); ok {
				if cur, err := n.st.inner.Lookup(n.ctx, model.Kind(kind), id); err == nil && cur.Deleted && cur.Version >= d.v {
					d.done = true // arrived since
				}
			}
		}
		switch {
		case d.done || now.Sub(d.at) > n.maxDowntime():
			delete(v.deletions, k)
			changed = changed || d.saved
		case !d.saved && old:
			d.saved = true
			v.deletions[k] = d
			changed = true
		}
	}
	if !changed || n.dir == "" {
		return
	}
	if err := saveVoterState(n.dir, v.deletions); err != nil {
		n.log.WithError(err).Error("quorum voter state not saved (retried)", "dir", n.dir)
		for k, d := range v.deletions {
			if d.saved {
				d.saved = false // saved again at the next prune
				v.deletions[k] = d
			}
		}
	}
}

// ---- handlers ----

func (n *Node) handlePrepare(_ *gossip.Node, pkt *gossip.Packet) (any, error) {
	var req prepareReq
	if err := pkt.Unmarshal(&req); err != nil {
		return nil, err
	}
	rec, err := decodeRecord(req.Rec)
	if err != nil || !model.QuorumCAS(rec.Kind) {
		return &prepareResp{St: stFailed}, nil
	}
	base := store.Rank{Epoch: hlc.Timestamp(req.BaseEpoch), Version: hlc.Timestamp(req.BaseVersion)}
	resp := n.voter.prepare(n.ctx, req.Op, rec, req.Mode, base)
	return &resp, nil
}

func (n *Node) handleCommit(_ *gossip.Node, pkt *gossip.Packet) (any, error) {
	var req commitReq
	if err := pkt.Unmarshal(&req); err != nil {
		return nil, err
	}
	rec, err := decodeRecord(req.Rec)
	if err != nil {
		return &commitResp{St: stFailed}, nil
	}
	return &commitResp{St: n.voter.commit(n.ctx, req.Op, rec, false)}, nil
}

func (n *Node) handleAbort(_ *gossip.Node, pkt *gossip.Packet) error {
	var req abortReq
	if err := pkt.Unmarshal(&req); err != nil {
		return err
	}
	n.voter.release(req.Op, hlc.Timestamp(req.Version))
	return nil
}

// handleRead answers a quorum read with this node's copies (tombstones included).
func (n *Node) handleRead(_ *gossip.Node, pkt *gossip.Packet) (any, error) {
	var req readReq
	if err := pkt.Unmarshal(&req); err != nil {
		return nil, err
	}
	if !n.votes() {
		return &readResp{NotReady: true}, nil
	}
	resp := &readResp{}
	for _, id := range req.IDs {
		r, err := n.st.inner.Lookup(n.ctx, model.Kind(req.Kind), id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			// Leaving the record out would claim this node has none: a quorum read could then certify a copy
			// older than one this node holds.
			n.log.WithError(err).Warn("quorum read: record unreadable", "kind", req.Kind, "id", id)
			return &readResp{Failed: true}, nil
		}
		if b, err := encodeRecord(r); err == nil {
			resp.Recs = append(resp.Recs, b)
		}
	}
	return resp, nil
}

// ---- writer ----

// applyCommitted applies a committed quorum write on this node (the writer's own commit when local).
func (s *Store) applyCommitted(ctx context.Context, rec *store.Record, local bool) (bool, error) {
	n := s.n
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
		n.fire(rec, local)
	}
	for _, id := range losers {
		s.reportLoser(ctx, rec.Kind, id)
	}
	return applied, nil
}

// stamp checks the local precondition of a quorum write, stamps rec (version, generation, Created) and returns the
// base the write is validated against: the rank of the copy this node holds.
func (s *Store) stamp(ctx context.Context, rec *store.Record, mode uint8, expect, epoch hlc.Timestamp) (store.Rank, error) {
	cur, err := s.inner.Lookup(ctx, rec.Kind, rec.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		cur = nil
	case err != nil:
		return store.Rank{}, err
	}
	live := cur != nil && cur.Live(time.Now())
	switch mode {
	case modeMatch:
		if expect == 0 && live {
			return store.Rank{}, store.ErrStale
		}
		if expect != 0 && !live {
			return store.Rank{}, store.ErrNotFound
		}
		if expect != 0 && cur.Version != expect {
			return store.Rank{}, store.ErrStale
		}
	case modeUpsert:
		if cur != nil && cur.Deleted {
			return store.Rank{}, store.ErrDeleted
		}
	}
	rec.Version = store.Clock.Now()
	var head *store.Head
	var base store.Rank
	if cur != nil {
		head, base = cur.Head(), cur.Rank()
	}
	if err := store.StampLocal(rec, head, !live); err != nil {
		return base, err
	}
	if !rec.Deleted && rec.Epoch < epoch {
		rec.Epoch = epoch // a voter granted a deletion of the record: this write must outrank it (prepare)
	}
	if !rec.Deleted {
		for _, u := range rec.Unique {
			if h, err := s.inner.GetByUnique(ctx, rec.Kind, u); err == nil && h.ID != rec.ID {
				return base, store.ErrConflict
			}
		}
	}
	return base, nil
}

type vote struct {
	mb   *member // nil: this node
	resp prepareResp
	err  error
}

// quorumWrite runs a quorum compare-and-swap (see the package comment above). mode is modeMatch (expect: the
// version the caller read, 0 for a create) or modeUpsert; a deletion is blind unless it is conditional (modeMatch:
// DeleteIf), when it is validated against expect like any compare-and-swap.
func (s *Store) quorumWrite(ctx context.Context, rec *store.Record, mode uint8, expect hlc.Timestamp) error {
	n := s.n
	if err := n.allowWrite(ctx, rec); err != nil {
		return err
	}
	if rec.Deleted && mode == modeUpsert {
		mode = modeBlind
	}
	rec.Origin = n.id
	ctx = context.WithoutCancel(ctx) // a client that goes away mid-write must not leave intents or a half commit
	op := model.NewID()
	deadline := time.Now().Add(intentTTL + time.Second)
	var epoch hlc.Timestamp // the generation a voter requires (it granted a deletion of the record)
	for attempt := 1; ; attempt++ {
		base, err := s.stamp(ctx, rec, mode, expect, epoch)
		if err != nil {
			return err
		}
		b, err := encodeRecord(rec)
		if err != nil {
			return err
		}
		granted, outcome, low, repair := s.prepareAll(ctx, op, rec, b, mode, base)
		floor := hlc.Timestamp(low.Floor)
		epoch = max(epoch, hlc.Timestamp(low.Epoch))
		switch outcome {
		case stGrant:
			return s.commitAll(ctx, op, rec, b, granted)
		case stStale, stDeleted:
			s.abort(op, rec.Version, granted)
			n.refused.Add(1)
			for _, r := range repair {
				_, _ = s.applyReplica(ctx, r) // read repair: this node now holds the newer copy
			}
			if outcome == stStale && mode == modeUpsert && attempt < 8 {
				continue // a whole-record write re-bases on the newer copy: the later commit wins, by design
			}
			if outcome == stDeleted {
				return store.ErrDeleted
			}
			return store.ErrStale
		case stBusy, stLow, stNotReady:
			s.abort(op, rec.Version, granted)
			if floor > 0 {
				store.Witness(floor)
				if store.Clock.Now() <= floor {
					return fmt.Errorf("%w: a peer's version is more than %s ahead of this node's clock (keep every "+
						"node's clock in sync)", store.ErrUnconfirmed, store.MaxSkew)
				}
			}
			if time.Now().After(deadline) {
				n.unconfirmed.Add(1)
				return fmt.Errorf("%w: the record stayed busy, or too few nodes were ready to take part",
					store.ErrUnconfirmed)
			}
			time.Sleep(time.Duration(1+rand.IntN(min(1<<min(attempt, 6), 50))) * time.Millisecond)
		default:
			s.abort(op, rec.Version, granted)
			n.unconfirmed.Add(1)
			return fmt.Errorf("%w: %d of the %d nodes needed granted the write", store.ErrUnconfirmed, len(granted),
				n.Quorum())
		}
	}
}

// prepareAll asks this node and every alive peer to grant the write. It returns the voters that granted (nil member:
// this node) and the outcome: stGrant once a quorum granted, stStale/stDeleted when such an answer came before
// that (with the voters' copies for read repair), a retryable answer (stBusy, stLow — with the floor to exceed and
// the generation to take in low —, stNotReady), or stFailed.
func (s *Store) prepareAll(ctx context.Context, op string, rec *store.Record, b []byte, mode uint8,
	base store.Rank) (granted []*member, outcome uint8, low prepareResp, repair []*store.Record) {
	n := s.n
	// This node votes first: the writer always takes part in its own commit, and a conflict it can see itself
	// costs no round trip.
	switch own := n.voter.prepare(ctx, op, rec, mode, base); own.St {
	case stGrant:
		granted = append(granted, nil)
	case stStale, stDeleted:
		if r, err := decodeRecord(own.Cur); err == nil {
			repair = append(repair, r)
		}
		return nil, own.St, low, repair
	default:
		return nil, own.St, own, nil
	}
	if len(granted) >= n.Quorum() {
		return granted, stGrant, low, nil
	}
	peers := n.otherPeers()
	votes := make(chan vote, len(peers))
	req := &prepareReq{Op: op, Rec: b, Mode: mode, BaseEpoch: uint64(base.Epoch), BaseVersion: uint64(base.Version)}
	for _, mb := range peers {
		go func(mb *member) {
			var resp prepareResp
			err := n.gc.SendToWithResponse(mb.node, msgPrepare, req, &resp)
			votes <- vote{mb: mb, resp: resp, err: err}
		}(mb)
	}
	retry := uint8(0)
	pending := len(peers)
	for pending > 0 {
		v := <-votes
		pending--
		if v.err != nil {
			continue
		}
		switch v.resp.St {
		case stGrant:
			granted = append(granted, v.mb)
			if len(granted) >= n.Quorum() {
				go s.settleLate(op, rec.Version, votes, pending) // late grants are released
				return granted, stGrant, prepareResp{}, nil
			}
		case stStale, stDeleted:
			if r, err := decodeRecord(v.resp.Cur); err == nil {
				repair = append(repair, r)
			}
			go s.settleLate(op, rec.Version, votes, pending)
			return granted, v.resp.St, prepareResp{}, repair
		case stLow:
			retry = stLow
			low.Floor = max(low.Floor, v.resp.Floor)
			low.Epoch = max(low.Epoch, v.resp.Epoch)
		case stBusy, stNotReady:
			if retry == 0 {
				retry = v.resp.St
			}
		}
	}
	if retry != 0 {
		return granted, retry, low, nil
	}
	return granted, stFailed, low, nil
}

// settleLate waits for the answers still outstanding when a write was decided and releases the intents they
// granted: their voters are not part of the commit (they get the record from the broadcast).
func (s *Store) settleLate(op string, version hlc.Timestamp, votes <-chan vote, pending int) {
	var late []*member
	for range pending {
		if v := <-votes; v.err == nil && v.resp.St == stGrant {
			late = append(late, v.mb)
		}
	}
	s.abort(op, version, late)
}

// abort releases the intents op was granted for the stamp version.
func (s *Store) abort(op string, version hlc.Timestamp, granted []*member) {
	n := s.n
	for _, mb := range granted {
		if mb == nil {
			n.voter.release(op, version)
			continue
		}
		if err := n.gc.SendTo(mb.node, msgAbort, &abortReq{Op: op, Version: uint64(version)}); err != nil {
			n.log.WithError(err).Debug("abort a quorum write", "peer", mb.id) // the intent expires by itself
		}
	}
}

// commitAll commits a granted write on this node and on every peer that granted it, and succeeds once a quorum
// (this node included) has applied it. The record is then broadcast to every node.
func (s *Store) commitAll(ctx context.Context, op string, rec *store.Record, b []byte, granted []*member) error {
	n := s.n
	if st := n.voter.commit(ctx, op, rec, true); st != stGrant {
		s.abort(op, rec.Version, granted)
		n.unconfirmed.Add(1)
		return fmt.Errorf("%w: this node's intent expired before the commit", store.ErrUnconfirmed)
	}
	applied := 1
	var peers []*member
	for _, mb := range granted {
		if mb != nil {
			peers = append(peers, mb)
		}
	}
	results := make(chan bool, len(peers))
	req := &commitReq{Op: op, Rec: b}
	for _, mb := range peers {
		go func(mb *member) {
			var resp commitResp
			err := n.gc.SendToWithResponse(mb.node, msgCommit, req, &resp)
			results <- err == nil && resp.St == stGrant
		}(mb)
	}
	for range peers {
		if <-results {
			applied++
		}
		if applied >= n.Quorum() {
			break
		}
	}
	if err := n.gc.Send(msgRecord, &recordMsg{B: b}); err != nil {
		n.log.WithError(err).Debug("broadcast a committed write")
	}
	if applied < n.Quorum() {
		n.unconfirmed.Add(1)
		n.log.Warn("a quorum write was applied by fewer than a majority (a node failed mid-commit): it may be in "+
			"effect on some nodes", "kind", string(rec.Kind), "id", rec.ID, "applied", applied, "quorum", n.Quorum())
		return fmt.Errorf("%w: %d of the %d nodes needed applied the write", store.ErrUnconfirmed, applied, n.Quorum())
	}
	// A write a quorum applied proves the cluster has formed, whatever gossip metadata (which can lag under load)
	// has shown of the nodes' readiness: this node is never an origin again.
	n.markFormed()
	return nil
}

// Fresh returns the newest copies of the records kind/ids held by a quorum of the cluster (this node included):
// every write a majority confirmed before the call is reflected. Copies newer than this node's are applied here
// (read repair). Tombstones are returned too (Deleted). Without gossip (a single node, or a shared database, which
// is the only copy) it is a local read. It implements store.QuorumReader.
func (s *Store) Fresh(ctx context.Context, kind model.Kind, ids []string) (map[string]*store.Record, error) {
	n := s.n
	out := map[string]*store.Record{}
	for _, id := range ids {
		if r, err := s.inner.Lookup(ctx, kind, id); err == nil {
			out[id] = r
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	if n.gc == nil || len(ids) == 0 {
		return out, nil
	}
	if !n.votes() {
		return nil, fmt.Errorf("%w: this node is not caught up", store.ErrNotWritable)
	}
	peers := n.otherPeers()
	type answer struct {
		resp readResp
		err  error
	}
	answers := make(chan answer, len(peers))
	req := &readReq{Kind: string(kind), IDs: ids}
	for _, mb := range peers {
		go func(mb *member) {
			var resp readResp
			err := n.gc.SendToWithResponse(mb.node, msgRead, req, &resp)
			answers <- answer{resp, err}
		}(mb)
	}
	got := 1
	for range peers {
		a := <-answers
		if a.err != nil || a.resp.NotReady || a.resp.Failed {
			continue
		}
		got++
		for _, b := range a.resp.Recs {
			r, err := decodeRecord(b)
			if err != nil || r.Kind != kind {
				continue
			}
			if cur := out[r.ID]; cur == nil || store.Newer(r, cur) {
				out[r.ID] = r
				_, _ = s.applyReplica(ctx, r)
			}
		}
		if got >= n.Quorum() {
			break
		}
	}
	if got < n.Quorum() {
		return nil, fmt.Errorf("%w: %d of the %d nodes needed answered", store.ErrUnconfirmed, got, n.Quorum())
	}
	return out, nil
}
