package cluster

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/paularlott/gossip/partition"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Leadership without gossip (nodes sharing one database): a lease record in the database names the node that runs
// housekeeping (key rotation, purge, end dates). The holder renews it well before it expires; when the holder stops,
// another node takes it over once it has expired. A node counts itself leader only while comfortably inside its
// lease (leaseMargin).
//
// In a gossip cluster the owner of partition 0 runs housekeeping instead (Node.IsLeader) and the tenure fenced is its
// ownership at the epoch the pass started under (Node.fence); the rest of this comment is about the lease.
//
// Fencing: every takeover creates the lease record anew, so its creation version (store.Record.Created) is a token
// unique to that tenure. Housekeeping runs with the token in its context (Node.fence), and every write it makes
// first checks that the lease record still names this node with that token (Node.fenced): a node that lost the
// lease — paused, partitioned from the database, or with a clock so far off that it believes it still holds an
// expired lease — has its housekeeping writes refused rather than racing the new holder's. What remains is the
// moment between that check and the write itself; every housekeeping task is safe to run twice at once (key rotation
// at worst publishes a spare key, end dates are compare-and-swap updates, purging is idempotent).
const leaseID = "lease/housekeeping"

// Lease timing (variables so tests can run it faster).
var (
	leaseTTL    = 30 * time.Second
	leaseRenew  = 10 * time.Second
	leaseMargin = 10 * time.Second
)

type lease struct {
	st    *store.Table[model.Ephemeral, *model.Ephemeral]
	self  string
	until atomic.Int64  // unix nanos until which this node holds the lease (0: not held)
	ok    atomic.Int64  // unix nanos of the last tick that reached the database
	token atomic.Uint64 // fencing token of the tenure this node holds: the lease record's Created (0: none)
}

// reachable reports whether the database answered a lease tick recently.
func (l *lease) reachable() bool {
	return time.Since(time.Unix(0, l.ok.Load())) < 2*leaseRenew+5*time.Second
}

func (l *lease) held() bool {
	u := l.until.Load()
	return u != 0 && time.Now().Before(time.Unix(0, u).Add(-leaseMargin))
}

// tick takes the lease when nobody holds it and renews it when this node does.
func (l *lease) tick(ctx context.Context) error {
	now := time.Now()
	e, err := l.st.Get(ctx, leaseID)
	switch {
	case errors.Is(err, store.ErrNotFound): // free, or the holder's lease ran out
		e = &model.Ephemeral{Meta: model.Meta{ID: leaseID}, Value: []byte(l.self), Expires: now.Add(leaseTTL)}
		err = l.st.Create(ctx, e)
	case err != nil:
	case string(e.Value) != l.self:
		l.until.Store(0) // someone else leads
		l.ok.Store(now.UnixNano())
		return nil
	default:
		e.Expires = now.Add(leaseTTL)
		err = l.st.Update(ctx, e)
	}
	if err == nil || errors.Is(err, store.ErrStale) || errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
		l.ok.Store(now.UnixNano()) // the database answered
	}
	if err != nil {
		l.until.Store(0)
		l.token.Store(0)
		if errors.Is(err, store.ErrStale) || errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
			return nil // another node got there first
		}
		return err
	}
	// The tenure's fencing token: the creation version of the record this node took over (renewals keep it).
	r, err := l.st.S.Get(ctx, model.KindEphemeral, leaseID)
	if err != nil || r.Created == 0 {
		l.until.Store(0)
		l.token.Store(0)
		return err
	}
	l.token.Store(uint64(r.Created))
	l.until.Store(e.Expires.UnixNano())
	return nil
}

// current reports whether the lease record still names this node for the tenure token (re-read from the database).
func (l *lease) current(ctx context.Context, token uint64) bool {
	r, err := l.st.S.Get(ctx, model.KindEphemeral, leaseID)
	if err != nil || uint64(r.Created) != token {
		return false
	}
	e := &model.Ephemeral{}
	return store.Decode(r, e) == nil && string(e.Value) == l.self && time.Now().Before(e.Expires)
}

type fenceKey struct{}

// fence marks ctx for housekeeping run under the tenure this node holds now: the lease (nodes sharing a database) or
// the ownership of partition 0 at its current epoch (a gossip cluster). Writes made with it are refused once that
// tenure has passed to another node (fenced). Without either (standalone) nothing is marked.
func (n *Node) fence(ctx context.Context) context.Context {
	var held func(context.Context) bool // whether the tenure taken now still stands
	switch {
	case n.lease != nil:
		token := n.lease.token.Load()
		held = func(ctx context.Context) bool {
			return token != 0 && n.lease.held() && n.lease.current(ctx, token)
		}
	case n.gc != nil:
		epoch, ok := n.globalEpoch()
		held = func(context.Context) bool {
			cur, still := n.globalEpoch()
			return ok && still && cur == epoch
		}
	default:
		return ctx
	}
	return context.WithValue(ctx, fenceKey{}, held)
}

// globalEpoch is the epoch of the tenure under which this node owns partition 0, and whether it owns it.
func (n *Node) globalEpoch() (partition.Epoch, bool) {
	pm := n.manager()
	if pm == nil || !pm.IsOwner(globalPartition) {
		return partition.Epoch{}, false
	}
	st, err := pm.PartitionStatus(globalPartition)
	return st.Epoch, err == nil && st.Leading
}

// fenced refuses a housekeeping write (ctx from fence) when this node no longer holds the tenure it started under.
func (n *Node) fenced(ctx context.Context) error {
	held, ok := ctx.Value(fenceKey{}).(func(context.Context) bool)
	if !ok || held(ctx) {
		return nil
	}
	return fmt.Errorf("%w: housekeeping has passed to another node", store.ErrNotWritable)
}

// release gives the lease up on shutdown so another node takes over at once.
func (l *lease) release(ctx context.Context) {
	if l.until.Swap(0) == 0 {
		return
	}
	if e, err := l.st.Get(ctx, leaseID); err == nil && string(e.Value) == l.self {
		_ = l.st.S.CompareAndPut(ctx, store.Tombstone(model.KindEphemeral, leaseID), e.Version)
	}
}

func (n *Node) runLease() {
	defer n.wg.Done()
	t := time.NewTicker(leaseRenew)
	defer t.Stop()
	for {
		if err := n.lease.tick(n.ctx); err != nil && n.ctx.Err() == nil {
			n.log.WithError(err).Warn("housekeeping lease")
		}
		n.checkNoGossip(n.ctx)
		select {
		case <-n.ctx.Done():
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			n.lease.release(ctx)
			cancel()
			return
		case <-t.C:
		}
	}
}

// Mixed set-ups are refused: a gossip node sharing its database with nodes that run without gossip would hold records no
// partition write made (the other nodes write the database directly) and both kinds of node would run housekeeping. Each kind leaves a short-lived record in its database — gossip nodes a marker, nodes without
// gossip the housekeeping lease — and a node that finds the other kind's record stops serving.
const gossipMarkerID = "marker/gossip"

// markGossip writes this gossip node's marker into its own database (directly: it is not replicated) and checks
// for a node without gossip's lease there.
func (n *Node) markGossip(ctx context.Context) {
	t := store.NewTable[model.Ephemeral](n.st.inner)
	for _, id := range []string{gossipMarkerID, gossipMarkerID + "/" + n.id} { // any gossip node; this one
		if err := t.Put(ctx, &model.Ephemeral{Meta: model.Meta{ID: id}, Value: []byte(n.id),
			Expires: time.Now().Add(leaseTTL)}); err != nil && n.ctx.Err() == nil {
			n.log.WithError(err).Warn("gossip marker")
		}
	}
	if e, err := t.Get(ctx, leaseID); err == nil {
		n.mixedDatabase("node " + string(e.Value) + " runs without gossip on this node's database")
	} else if errors.Is(err, store.ErrNotFound) {
		n.mixedGone()
	}
}

// checkNoGossip is the other side: a node without gossip finding a gossip node's marker in the shared database.
func (n *Node) checkNoGossip(ctx context.Context) {
	if e, err := n.lease.st.Get(ctx, gossipMarkerID); err == nil {
		n.mixedDatabase("node " + string(e.Value) + " runs with gossip on this shared database")
	} else if errors.Is(err, store.ErrNotFound) {
		n.mixedGone()
	}
}

func (n *Node) mixedDatabase(detail string) {
	why := detail + ": a database is either shared by nodes without gossip, or belongs to one gossip node"
	if n.mixed.Swap(&why) == nil {
		n.log.Error("refusing to serve", "reason", why)
	}
}

// mixedGone lifts the refusal once the other kind's record has expired (the other node was reconfigured or
// stopped: a deployment moving between the two modes passes through this).
func (n *Node) mixedGone() {
	if n.mixed.Swap(nil) != nil {
		n.log.Info("the database is no longer shared with the other kind of node")
	}
}

func (n *Node) runGossipMarker() {
	defer n.wg.Done()
	t := time.NewTicker(leaseRenew)
	defer t.Stop()
	for {
		n.checkOwner(n.ctx)
		n.markGossip(n.ctx)
		select {
		case <-n.ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ownerID names the record in which a gossip node's database records the node it belongs to.
const ownerID = "owner"

// checkOwner runs before a gossip node joins and then with every marker tick. A database records the node it
// belongs to. One that names another node is either a copy of that node's (a cloned disk or volume), that node's
// own database opened by a node whose id changed (a data directory that was not kept), or one shared by two nodes.
// Nothing here can tell those apart, and a wrong guess loses data, so the node never wipes anything: it refuses to
// serve, saying how to resolve it (set cluster.node_id to the owner, or empty the copy). A database without an owner
// (new, wiped or restored) becomes this node's.
func (n *Node) checkOwner(ctx context.Context) {
	t := store.NewTable[model.Ephemeral](n.st.inner)
	e, err := t.Get(ctx, ownerID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if err := t.Put(ctx, &model.Ephemeral{Meta: model.Meta{ID: ownerID}, Value: []byte(n.id)}); err != nil {
			n.log.WithError(err).Warn("database owner")
		}
		n.ownerOK()
	case err != nil:
		n.log.WithError(err).Warn("database owner")
	case string(e.Value) == n.id:
		n.ownerOK()
	default:
		why := "this database belongs to node " + string(e.Value) + ", not to this node (" + n.id + "): if this is that " +
			"node, set cluster.node_id to " + string(e.Value) + " or keep its data directory; if the database is a copy " +
			"of another node's, empty it and this node copies everything from its peers; if two nodes share it, give " +
			"each its own database"
		if n.foreign.Swap(&why) == nil {
			n.log.Error("refusing to serve", "reason", why)
		}
	}
}

func (n *Node) ownerOK() {
	if n.foreign.Swap(nil) != nil {
		n.log.Info("the database belongs to this node again")
	}
}
