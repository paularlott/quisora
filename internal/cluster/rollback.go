package cluster

import (
	"encoding/json"
	"errors"
	"maps"
	"strconv"

	"github.com/paularlott/gossip"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Rollback detection. A node restored in place from a snapshot of itself (a VM or disk snapshot, a database restored to
// a point in time, a database file copied back) keeps its node id and its database's feed id, so it passes as intact;
// but it has forgotten the promises it gave and the writes it acknowledged since the snapshot, which the partition
// protocol's safety rests on (a node that reports itself intact with a stale store breaks it). So every start is
// counted:
//
//   - The count is kept in cluster-state.json and in the database (startsID), and raised at every start, durably,
//     before the partition protocol starts: the database first, then the file. A database older than the file (its
//     count is lower) was restored by itself: the node is not intact, and resyncs.
//   - The count is published in gossip metadata (metaStarts), and every node remembers the highest count it has seen
//     each peer publish (persisted in its own cluster-state.json) and publishes what it remembers (metaStartsSeen). A
//     node that finds, at start, a peer of its data set remembering a count of its own at least as high as this start's
//     came back from a snapshot of itself (both its database and its file are old): it is not intact, and resyncs.
//   - A peer that was not in view at the start may reveal it later: the node then refuses to serve and stops taking part
//     in the protocol (it may already have promised from its forgotten state), and resyncs at its next start.
//
// A node that was never restored never trips it: each start's count is above every count it published before.

// Gossip metadata of the start counts.
const (
	metaStarts     = "quisora.starts"      // this start's count
	metaStartsSeen = "quisora.starts_seen" // the highest count seen of each peer: a JSON object, node id -> count
)

// startsID is the record that keeps the start count in the database (a node-local short-lived state record: never in a
// partition, a backup or a catch-up).
const startsID = "cluster/starts"

// dbStarts reads the start count kept in the database (0: none).
func (n *Node) dbStarts() uint64 {
	e, err := store.NewTable[model.Ephemeral](n.st.inner).Get(n.ctx, startsID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			n.log.WithError(err).Warn("reading the start count")
		}
		return 0
	}
	c, _ := strconv.ParseUint(string(e.Value), 10, 64)
	return c
}

// countStart raises the start count above the one in the file (fromFile) and the database's, and keeps it: the database
// first, then the file (a crash between the two leaves the database ahead, which is no sign of anything). It reports
// whether the database is older than the file (it was restored by itself).
func (n *Node) countStart(fromFile uint64) (dbOlder bool) {
	inDB := n.dbStarts()
	n.starts.Store(max(fromFile, inDB) + 1)
	n.saveStarts()
	return inDB < fromFile
}

// saveStarts keeps this start's count in the database and in cluster-state.json.
func (n *Node) saveStarts() {
	e := &model.Ephemeral{Meta: model.Meta{ID: startsID}, Value: []byte(strconv.FormatUint(n.starts.Load(), 10))}
	if err := store.NewTable[model.Ephemeral](n.st.inner).Put(n.ctx, e); err != nil {
		n.log.WithError(err).Warn("keeping the start count in the database")
	}
	n.saveState()
}

// publishStarts publishes this start's count and what this node remembers of its peers'.
func (n *Node) publishStarts() {
	if n.gc == nil {
		return
	}
	n.gc.LocalMetadata().SetUint64(metaStarts, n.starts.Load())
	n.publishStartsSeen()
	n.startsShown.Store(true)
}

func (n *Node) publishStartsSeen() {
	n.startsMu.Lock()
	b, _ := json.Marshal(n.peerStarts)
	n.startsMu.Unlock()
	if md := n.gc.LocalMetadata(); md.GetString(metaStartsSeen) != string(b) {
		md.SetString(metaStartsSeen, string(b))
	}
}

// rememberStarts raises what this node remembers of each peer's start count to what the peer publishes, and keeps it
// (cluster-state.json) before publishing it.
func (n *Node) rememberStarts(members []*member) {
	changed := false
	n.startsMu.Lock()
	for _, mb := range members {
		if mb.id == n.id || mb.node == nil || mb.node.Metadata == nil || !mb.node.Metadata.Exists(metaStarts) {
			continue
		}
		if c := mb.node.Metadata.GetUint64(metaStarts); c > n.peerStarts[mb.id] {
			if n.peerStarts == nil {
				n.peerStarts = map[string]uint64{}
			}
			n.peerStarts[mb.id] = c
			changed = true
		}
	}
	n.startsMu.Unlock()
	if changed {
		n.saveState()
		if n.startsShown.Load() {
			n.publishStartsSeen()
		}
	}
}

// remembered returns the highest start count of this node that a peer of its data set publishes having seen, and the
// peer ("": none).
func (n *Node) remembered() (count uint64, by string) {
	own := n.genesis.Load()
	if own == nil {
		return 0, ""
	}
	for _, mb := range n.mem.Load().all {
		nd := mb.node
		if mb.id == n.id || nd == nil || nd.Metadata == nil || mb.state != gossip.NodeAlive ||
			nd.Metadata.GetString(metaGenesis) != *own {
			continue
		}
		var seen map[string]uint64
		if json.Unmarshal([]byte(nd.Metadata.GetString(metaStartsSeen)), &seen) != nil {
			continue
		}
		if c := seen[n.id]; c > count {
			count, by = c, mb.id
		}
	}
	return count, by
}

// checkRollback compares this start's count with the highest a peer remembers of this node. Before the count is
// published, a peer remembering one at least as high means this node came back from a snapshot of itself; once it is
// published, the peers remember it, and only a higher one does. A node found restored is not intact: before the partition
// protocol starts it resyncs; after, it refuses to serve and leaves the protocol until it is restarted (and then
// resyncs). Either way its count moves above the remembered one, so the next start of a node that has resynced is clean.
func (n *Node) checkRollback() {
	mine := n.starts.Load()
	seen, by := n.remembered()
	shown := n.startsShown.Load()
	if seen < mine || (shown && seen == mine) {
		return
	}
	n.starts.Store(seen + 1)
	wasIntact := n.intact.Swap(false)
	n.saveStarts()
	if shown {
		n.gc.LocalMetadata().SetUint64(metaStarts, seen+1)
	}
	switch {
	case !shown && wasIntact:
		n.log.Warn("this node was restored from a snapshot of itself (a peer remembers a later start of it): it has "+
			"forgotten what it promised and stored since, so it copies everything from the other nodes before it takes part",
			"peer", by, "remembered", seen, "this_start", mine)
	case shown && n.startedIntact.Load():
		n.setUnfit("this node was restored from a snapshot of itself (peer " + by + " remembers a later start of it) and " +
			"has taken part with what it had forgotten: it no longer serves or takes part; restart it, and it copies " +
			"everything from the other nodes")
		n.pmMu.Lock()
		if pm := n.manager(); pm != nil {
			pm.Stop()
		}
		n.pmMu.Unlock()
	}
}

// startsSnapshot copies what this node remembers of its peers' start counts (for saveState).
func (n *Node) startsSnapshot() map[string]uint64 {
	n.startsMu.Lock()
	defer n.startsMu.Unlock()
	if len(n.peerStarts) == 0 {
		return nil
	}
	return maps.Clone(n.peerStarts)
}
