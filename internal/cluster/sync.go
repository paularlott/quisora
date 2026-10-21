package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// maxPageBytes bounds the encoded size of one feed page (the gossip packet limit is 4MB).
const maxPageBytes = 1 << 20

type cursor struct {
	Feed string `json:"feed"`
	Seq  uint64 `json:"seq"`
}

type peerState struct {
	running chan struct{} // capacity 1: held while a sync of this peer is in flight
	cur     cursor        // guarded by running
	pulled  int64         // start of the last complete pull of its data with a majority in view (guarded by peersMu)
}

// persisted is the replication state kept in cluster-state.json.
//
// Nothing is ever wiped or deleted to "resynchronise": a node merges what its peers send (store.Newer: a tombstone
// beats every write of a generation started before it, otherwise the higher rank wins) and they merge what it has.
// The one thing a merge cannot settle is a deletion whose tombstone is gone — a node that still holds the record
// would hand it back — and tombstones are purged after the retention. So a node whose sync point (LastSync, or
// CopiedAt) is older than maxDowntime does not serve its data: it stops, and at start it refuses unless its database
// is empty (it then copies everything) or "quisora force-start" left its one-shot marker (an operator's decision, as
// after a whole-cluster outage: force the node with the newest data, empty the others). See docs/REPLICATION.md.
type persisted struct {
	// LastSync is this node's sync point (unix nanos): by then it had completed pulls from enough peers to make a
	// majority with it, each started with a majority in view (recomputeSync).
	LastSync int64 `json:"last_sync"`
	// CopiedAt is the age of data this node copied while it had no sync point yet (a first copy made without a
	// majority in view, or from fewer peers than a majority): the earlier of the copy's start and the source's own
	// sync point. Until LastSync is set the node ages from it.
	CopiedAt int64             `json:"copied_at,omitempty"`
	Cursors  map[string]cursor `json:"cursors"`
	// Self is this node's own store feed id when the state was saved: a different one now means the database was
	// replaced since, by hand.
	Self string `json:"self"`
	// Joined: this node has copied from a peer that holds data at least once (it is part of a cluster, not only
	// set up on its own).
	Joined bool `json:"joined"`
	// ForceAudit is an operator-forced start not yet written to the audit log (it is once the node is writable).
	ForceAudit *forceRecord `json:"force_audit,omitempty"`
	// Copying: the node's first copy of the cluster's data was under way (it holds part of it). A restart resumes
	// the copy while that data is young enough (CopiedAt), and refuses once it is not.
	Copying bool `json:"copying,omitempty"`
	// Formed: since this state was created this node has seen a quorum of the cluster's nodes ready, caught up
	// as a member of a formed cluster, or completed a quorum write a quorum applied. It is then never an origin for new nodes again (Node.origin), until an
	// operator starts a new formation ("quisora force-start", a restore, a new cluster's bootstrap).
	Formed bool `json:"formed,omitempty"`
}

// forceRecord is one forced start ("quisora force-start"), kept until it is in the audit log.
type forceRecord struct {
	At     int64  `json:"at"`
	Reason string `json:"reason"`
}

func (n *Node) peer(id string) *peerState {
	n.peersMu.Lock()
	defer n.peersMu.Unlock()
	p := n.peers[id]
	if p == nil {
		p = &peerState{running: make(chan struct{}, 1)}
		n.peers[id] = p
	}
	return p
}

// maxDowntime is how long a node may go without syncing before its data can no longer be trusted: the tombstone
// retention less a margin (a day, or a quarter of a shorter retention).
func (n *Node) maxDowntime() time.Duration {
	r := n.opt.TombstoneRetention
	return r - min(24*time.Hour, r/4)
}

// loadState restores the cursors and sync point, and decides how this node starts: empty (it copies everything),
// in sync recently enough to merge, or refused. A force-start marker is consumed here, whatever the outcome, and
// always logged; when it changed how the node starts it is also kept for the audit log (PendingForceStart).
func (n *Node) loadState() {
	// "quisora force-start" applies to this start only, whatever happens: the file goes now.
	forced := n.opt.ForceStart
	if n.dir != "" {
		marker := filepath.Join(n.dir, ForceStartMarker)
		if _, err := os.Stat(marker); err == nil {
			forced = true
			if err := os.Remove(marker); err != nil {
				n.log.WithError(err).Error("could not remove the force-start file: refusing to force", "file", marker)
				forced = false
			}
		}
	}
	var ps persisted
	if n.stateFile != "" {
		if b, err := os.ReadFile(n.stateFile); err == nil {
			if json.Unmarshal(b, &ps) == nil {
				n.hadStateFile = true
			}
		}
	}
	if ps.ForceAudit != nil {
		n.forceAudit.Store(ps.ForceAudit) // an earlier forced start not audited yet
	}
	if n.empty() {
		// Nothing to keep or to hand back: copy everything from a peer that holds data.
		if forced {
			n.log.Warn("quisora force-start ignored: this node's database is empty, it copies everything from its peers")
		}
		n.bootstrap.Store(n.replicate)
		return
	}
	n.holdsData.Store(true)
	replaced := n.hadStateFile && ps.Self != n.st.inner.FeedID()
	if ps.Copying && !replaced && n.replicate && !n.restored.Load() {
		// Stopped during its first copy: it never served, and what it holds is as old as CopiedAt. While that is
		// recent enough every deletion of it is still a tombstone somewhere, so it simply copies everything again
		// (merging is idempotent) and serves only once that copy is complete.
		if ps.CopiedAt > 0 && time.Since(time.Unix(0, ps.CopiedAt)) <= n.maxDowntime() {
			if forced {
				n.log.Warn("quisora force-start ignored: this node's first copy of the cluster's data was interrupted; " +
					"it copies everything again")
			}
			n.log.Info("resuming the interrupted first copy of the cluster's data")
			n.copiedAt.Store(ps.CopiedAt)
			n.joined.Store(false)
			n.bootstrap.Store(true)
			return
		}
		n.setBehind("this node's first copy of the cluster's data was interrupted too long ago: records deleted " +
			"meanwhile may be gone from the other nodes. Start it with an empty database: it copies everything")
		return
	}
	if !replaced {
		for id, c := range ps.Cursors {
			n.peer(id).cur = c
		}
	}
	n.lastSync.Store(ps.LastSync)
	n.copiedAt.Store(ps.CopiedAt)
	n.joined.Store(ps.Joined)
	n.formed.Store(ps.Formed)
	var why string
	point := ps.LastSync
	if point == 0 {
		point = ps.CopiedAt
	}
	switch {
	case n.restored.Load():
		if forced {
			n.log.Warn("quisora force-start ignored: this node was restored from a backup and starts as the cluster's data")
		}
		n.lastSync.Store(time.Now().UnixNano()) // restored from a backup: it goes into an empty cluster
		return
	case !n.hadStateFile:
		why = "this node's database holds data but its cluster state (cluster-state.json) is missing, so how long " +
			"ago it last synced is unknown"
	case replaced:
		why = "this node's database was replaced since it last ran, so how long ago it last synced is unknown"
	case point == 0:
		why = "this node holds data but has never synced with a majority of the cluster, so how long ago its data " +
			"was current is unknown"
	case time.Since(time.Unix(0, point)) > n.maxDowntime():
		why = fmt.Sprintf("this node last synced %s ago (at %s), longer than the tombstone retention allows",
			time.Since(time.Unix(0, point)).Round(time.Minute), time.Unix(0, point).UTC().Format(time.RFC3339))
	}
	if forced {
		n.forceStart(why, point)
		return
	}
	if why != "" {
		n.setBehind(why + ": deletions made meanwhile may be gone from the other nodes, and its copies of those " +
			"records would come back. " + whatToDo)
	}
}

// forceStart applies "quisora force-start" (loadState): this node's data is the cluster's from now on, as a new
// cluster's first node's — its sync point is now and it has not joined anyone, so new, empty peers count towards
// catching up and copy from it. why says why it would not have started otherwise ("" when it was in date: the only
// node with data restarting next to empty ones, which it could not catch up with).
func (n *Node) forceStart(why string, point int64) {
	reason := why
	if why == "" {
		reason = "its data was in date; forced so that new, empty peers count towards catching up (the only node " +
			"with data)"
	} else {
		// Forced while out of date: if a peer turns out to hold the cluster's data more recently, this node is not
		// the one with the newest data after all (syncPeer refuses then).
		n.preForce = point
		if n.preForce == 0 {
			n.preForce = 1
		}
	}
	n.log.Warn("starting with this node's data as the cluster's (quisora force-start): every other node must start "+
		"with an empty database and copy from it", "reason", reason)
	n.forced.Store(&reason)
	n.formed.Store(false) // the operator starts a new formation around this node's data
	n.forceAudit.Store(&forceRecord{At: time.Now().UnixNano(), Reason: reason})
	n.lastSync.Store(time.Now().UnixNano())
	n.copiedAt.Store(0)
	n.joined.Store(false)
	n.dirty.Store(true)
	n.saveState() // the pending audit must survive a crash before the node is writable
}

// ForcedStart reports why this start was forced with "quisora force-start" ("" when it was not).
func (n *Node) ForcedStart() string {
	if p := n.forced.Load(); p != nil {
		return *p
	}
	return ""
}

// PendingForceStart returns a forced start (this one or an earlier one) that is not in the audit log yet. The
// application writes it once the node is writable and then calls ForceStartAudited.
func (n *Node) PendingForceStart() (at time.Time, reason string, ok bool) {
	p := n.forceAudit.Load()
	if p == nil {
		return time.Time{}, "", false
	}
	return time.Unix(0, p.At), p.Reason, true
}

// ForceStartAudited clears the pending forced start once it is in the audit log.
func (n *Node) ForceStartAudited() {
	if n.forceAudit.Swap(nil) != nil {
		n.dirty.Store(true)
		n.saveState()
	}
}

// whatToDo ends every "out of date" refusal.
const whatToDo = "If the other nodes hold the cluster's data, start this node with an empty database: it copies " +
	"everything from them. If this node holds the only copy, or the newest (after a whole-cluster outage), do not " +
	"empty it: run \"quisora force-start\" on it and start it again, then start the others with empty databases"

// ForceStartMarker is the file "quisora force-start" leaves in the data directory: the next start uses this node's
// data even if it may be out of date, and removes the file (it applies to one start only).
const ForceStartMarker = "force-start"

// empty reports whether the store holds no records (short-lived state aside).
func (n *Node) empty() bool {
	for _, k := range model.Kinds() {
		if localOnly(k) {
			continue
		}
		if c, err := n.st.inner.Count(n.ctx, k, ""); err != nil || c > 0 {
			return false
		}
	}
	return true
}

// setBehind stops this node from serving (and from offering its data) until it is restarted: empty, or forced.
func (n *Node) setBehind(why string) {
	if n.behind.CompareAndSwap(nil, &why) {
		n.log.Error("refusing to serve", "reason", why)
	}
}

// syncPoint is the time as of which this node's data is known to hold every deletion a majority acknowledged:
// LastSync, or CopiedAt while it has none. 0: unknown.
func (n *Node) syncPoint() int64 {
	if t := n.lastSync.Load(); t > 0 {
		return t
	}
	return n.copiedAt.Load()
}

// checkDowntime stops a running node that has not synced for too long (cut off from its peers): its sync point,
// or the age of what it copied when it never had one, is older than maxDowntime.
func (n *Node) checkDowntime() {
	if !n.peersExpected() || n.bootstrap.Load() || n.behind.Load() != nil {
		return
	}
	if last := n.syncPoint(); last > 0 && time.Since(time.Unix(0, last)) > n.maxDowntime() {
		n.setBehind(fmt.Sprintf("no sync with the other nodes (with a majority in view) since %s, too long for "+
			"deletions to be sure to reach this node. %s", time.Unix(0, last).UTC().Format(time.RFC3339), whatToDo))
	}
}

// advanceSync moves the sync point forward to t (never back).
func (n *Node) advanceSync(t int64) {
	for {
		cur := n.lastSync.Load()
		if t <= cur || n.lastSync.CompareAndSwap(cur, t) {
			break
		}
	}
	n.dirty.Store(true)
}

// recomputeSync moves the sync point to the newest time t such that pulls started at t or later have completed
// from enough peers to make a majority with this node (each with a majority in view): every write a majority held
// before t is then here, whichever majority that was.
func (n *Node) recomputeSync() {
	need := max(n.Quorum()-1, 1)
	n.peersMu.Lock()
	times := make([]int64, 0, len(n.peers))
	for _, p := range n.peers {
		if p.pulled > 0 {
			times = append(times, p.pulled)
		}
	}
	n.peersMu.Unlock()
	if len(times) < need {
		return
	}
	slices.Sort(times)
	n.advanceSync(times[len(times)-need])
}

// MarkSynced writes the cluster state of a node whose data is the cluster's as of now ("quisora bootstrap
// --new-cluster" on the first node): it then starts like a node that has just synced.
func MarkSynced(dataDir, feedID string) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(persisted{LastSync: time.Now().UnixNano(), Cursors: map[string]cursor{}, Self: feedID})
	return os.WriteFile(filepath.Join(dataDir, "cluster-state.json"), b, 0o600)
}

func (n *Node) saveState() {
	n.saveMu.Lock()
	defer n.saveMu.Unlock()
	if n.stateFile == "" || !n.dirty.Swap(false) {
		return
	}
	ps := persisted{LastSync: n.lastSync.Load(), CopiedAt: n.copiedAt.Load(), Cursors: map[string]cursor{},
		Self: n.st.inner.FeedID(), Joined: n.joined.Load(), ForceAudit: n.forceAudit.Load(), Formed: n.formed.Load(),
		Copying: n.bootstrap.Load() && n.holdsData.Load()}
	n.peersMu.Lock()
	peers := make(map[string]*peerState, len(n.peers))
	for id, p := range n.peers {
		peers[id] = p
	}
	n.peersMu.Unlock()
	for id, p := range peers {
		select {
		case p.running <- struct{}{}:
			ps.Cursors[id] = p.cur
			<-p.running
		default: // mid-sync: the next save picks it up
			n.dirty.Store(true)
		}
	}
	b, _ := json.Marshal(ps)
	tmp := n.stateFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		err = os.Rename(tmp, n.stateFile)
		if err != nil {
			n.log.WithError(err).Warn("save cluster state")
		}
	} else {
		n.log.WithError(err).Warn("save cluster state")
	}
}

func (n *Node) saveLoop() {
	defer n.wg.Done()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-t.C:
			n.saveState()
		}
	}
}

// ---- pulling ----

func (n *Node) syncLoop() {
	defer n.wg.Done()
	t := time.NewTicker(n.opt.SyncInterval)
	defer t.Stop()
	n.syncAll()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-t.C:
		case <-n.trigger:
		}
		n.rebuild()
		n.checkDowntime()
		n.syncAll()
	}
}

func (n *Node) syncAll() {
	peers := n.otherPeers()
	if n.behind.Load() != nil {
		return // takes nothing in either
	}
	if n.bootstrap.Load() {
		n.bootstrapSync(peers)
		return
	}
	for _, mb := range peers {
		p := n.peer(mb.id)
		select {
		case p.running <- struct{}{}:
		default:
			continue
		}
		n.wg.Add(1)
		go func(mb *member, p *peerState) {
			defer n.wg.Done()
			defer func() { <-p.running }()
			if err := n.syncPeer(mb, p); err != nil && n.ctx.Err() == nil {
				n.log.WithError(err).Debug("sync failed", "peer", mb.id)
			}
		}(mb, p)
	}
}

// bootstrapSync does a fresh node's first full copy from one peer at a time: every peer's feed
// holds every record, so pulling from all of them at once would apply each record several times over. Peers are
// tried in turn until one completes; the rest are pulled normally afterwards.
func (n *Node) bootstrapSync(peers []*member) {
	if len(peers) == 0 {
		return
	}
	for _, mb := range peers {
		if len(n.peer(mb.id).running) > 0 {
			return // a bootstrap pull is already in flight
		}
	}
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		start := int(n.bootRR.Add(1)) % len(peers)
		for i := range peers {
			mb := peers[(start+i)%len(peers)]
			p := n.peer(mb.id)
			select {
			case p.running <- struct{}{}:
			default:
				return
			}
			err := n.syncPeer(mb, p)
			<-p.running
			if err == nil || n.ctx.Err() != nil {
				return
			}
			n.log.WithError(err).Debug("bootstrap sync failed", "peer", mb.id)
		}
	}()
}

type feedPage struct {
	resp feedResp
	err  error
}

// fetchPages requests pages back to back, ahead of the applier, until the feed is exhausted or ctx is done.
func (n *Node) fetchPages(ctx context.Context, mb *member, cur cursor, out chan<- feedPage) {
	defer close(out)
	for {
		req := feedReq{FeedID: cur.Feed, Since: cur.Seq, Limit: n.opt.PageSize, Fresh: n.bootstrap.Load()}
		var resp feedResp
		pg := feedPage{}
		if err := n.gc.SendToWithResponse(mb.node, msgFeed, &req, &resp); err != nil {
			pg.err = err
		} else {
			pg.resp = resp
		}
		select {
		case out <- pg:
		case <-ctx.Done():
			return
		}
		if pg.err != nil || resp.Stale || !resp.More {
			return
		}
		cur = cursor{Feed: resp.FeedID, Seq: resp.Next}
	}
}

// syncPeer pulls the peer's change feed from its cursor until caught up, fetching the next page while the current
// one is applied. p.running is held by the caller.
func (n *Node) syncPeer(mb *member, p *peerState) error {
	start := time.Now().UnixNano()
	quorum := n.quorumOK()
	full := p.cur.Seq == 0
	ctx, cancel := context.WithCancel(n.ctx)
	defer cancel()
	pages := make(chan feedPage, 2)
	go n.fetchPages(ctx, mb, p.cur, pages)
	first, origin := true, true
	for pg := range pages {
		if pg.err != nil {
			return pg.err
		}
		resp := pg.resp
		if resp.Stale {
			return fmt.Errorf("peer %s is not serving its data", mb.id)
		}
		if resp.Fresh {
			// A new node holds nothing. A new node does not copy from another new one; and only the first node of a
			// new cluster (one that has never joined, or one forced with "quisora force-start") counts new nodes
			// towards catching up — a node that has joined needs a majority of nodes with data, or it could serve,
			// and seed newcomers with, what may be out of date.
			if n.bootstrap.Load() {
				return fmt.Errorf("peer %s is new too: waiting for a node that holds the data", mb.id)
			}
			if resp.Empty && quorum && n.quorumOK() {
				// It holds nothing, so nothing this node lacks: as good as a complete pull for the sync point.
				n.peersMu.Lock()
				p.pulled = start
				n.peersMu.Unlock()
				n.recomputeSync()
			}
			if !n.joined.Load() && !n.startedEmpty {
				// (an empty node never counts another empty one: two of them make no cluster)
				n.caughtUpWith(mb.id)
			}
			return nil
		}
		if first && n.preForce != 0 && n.catchingUp.Load() && resp.Synced > n.preForce {
			// Forced although out of date, but this peer serves the cluster's data and synced more recently: this
			// node is not the one with the newest data, and its copies of records deleted meanwhile would come back.
			n.setBehind(fmt.Sprintf("this node was started with \"quisora force-start\", but node %s holds the "+
				"cluster's data and synced more recently (at %s): start this node with an empty database instead",
				mb.id, time.Unix(0, resp.Synced).UTC().Format(time.RFC3339)))
			return fmt.Errorf("forced node met a more recent peer")
		}
		first = false
		origin = origin && resp.Origin && full
		if _, ours := n.seeded.Load(mb.id); n.restored.Load() && len(resp.Recs) > 0 && !ours && !n.holdsAll(resp.Recs) {
			// The cluster this node was restored into already holds data: merging an old backup into it would bring
			// back what it has deleted since. Refuse, and take nothing from it.
			why := "this node was restored from a backup, but node " + mb.id + " already holds data: restore into an " +
				"empty cluster (start this node alone, then the others with empty databases)"
			if n.restoredInto.Swap(&why) == nil {
				n.log.Error("refusing to serve", "reason", why)
			}
			return fmt.Errorf("restored node met a cluster with data")
		}
		if resp.FeedID == n.st.inner.FeedID() {
			n.sameDatabase(mb.id)
			return fmt.Errorf("peer %s uses this node's own database", mb.id)
		}
		n.differentDatabase(mb.id)
		if resp.FeedID != p.cur.Feed {
			// The peer's store was replaced or restored (or this is the first contact): its page starts from 0.
			p.cur = cursor{Feed: resp.FeedID}
			full = true
		}
		recs := make([]*store.Record, len(resp.Recs))
		for i, b := range resp.Recs {
			rec, err := decodeRecord(b)
			if err != nil {
				return err
			}
			recs[i] = rec
		}
		if len(recs) > 0 && n.lastSync.Load() == 0 && n.copiedAt.Load() == 0 {
			// No sync point yet (typically a first copy): what it receives is as old as the copy, or as the source's
			// own sync point if older. It ages from that until it has a sync point — even if it never gets one
			// (a copy made without a majority in view: checkDowntime), and across a restart mid-copy (loadState).
			age := start
			if resp.Synced > 0 && resp.Synced < age {
				age = resp.Synced
			}
			n.copiedAt.CompareAndSwap(0, age)
			n.holdsData.Store(true) // (before the save: a restart from here on resumes a copy, see Copying)
			n.dirty.Store(true)
			n.saveState()
		}
		if err := n.st.applyBatch(n.ctx, recs); err != nil {
			return err
		}
		if n.behind.Load() != nil {
			return fmt.Errorf("stopped") // a separately bootstrapped cluster (applyBatch)
		}
		p.cur.Seq = resp.Next
		n.dirty.Store(true)
		if resp.More {
			continue
		}
		if quorum && n.quorumOK() {
			// Pulled with a majority in view throughout: nodes cut off together keep pulling from each other, but
			// deletions made on the majority side cannot reach them, so that is no sync — their sync point ages and
			// they stop once it is too old, like a lone node. The sync point moves once enough peers to make a
			// majority have been pulled (recomputeSync).
			n.peersMu.Lock()
			p.pulled = start
			n.peersMu.Unlock()
			n.recomputeSync()
		}
		n.joined.Store(true)
		switch {
		case n.startedEmpty && origin:
			n.caughtUpWithOrigin(mb.id)
		case !resp.CatchingUp || !n.startedEmpty:
			// A node that started empty holds nothing of its own: only peers that have caught up themselves count
			// towards its own catching up (see caughtUpWith).
			n.caughtUpWith(mb.id)
		}
		if full && n.bootstrap.CompareAndSwap(true, false) {
			n.log.Info("initial copy complete", "peer", mb.id)
		}
		return nil
	}
	return n.ctx.Err()
}

// handleFeed serves a page of the local change feed.
func (n *Node) handleFeed(from *gossip.Node, pkt *gossip.Packet) (any, error) {
	var req feedReq
	if err := pkt.Unmarshal(&req); err != nil {
		return nil, err
	}
	feed := n.st.inner.FeedID()
	stale := &feedResp{FeedID: feed, Stale: true}
	// A node out of date, or whose database belongs to another node or is shared with nodes without gossip, offers
	// nothing to copy.
	if n.behind.Load() != nil || n.foreign.Load() != nil || n.mixed.Load() != nil || n.restoredInto.Load() != nil {
		return stale, nil
	}
	if n.bootstrap.Load() {
		return &feedResp{FeedID: feed, Fresh: true, Empty: !n.holdsData.Load()}, nil
	}
	if req.Fresh && (n.catchingUp.Load() || !n.quorumOK()) {
		// A new node copies only from one that has caught up with the cluster and sees a majority of it: a node cut
		// off from the majority (whatever it holds is ageing) seeds nobody.
		return stale, nil
	}
	if n.restored.Load() {
		if !req.Fresh {
			// Restored from a backup: only new, empty members copy from it (restore goes into an empty cluster).
			return stale, nil
		}
		if from != nil {
			n.seeded.Store(from.ID.String(), true) // its data comes from here: no conflict when this node reads it back
		}
	}
	since := req.Since
	if req.FeedID != feed {
		since = 0
	}
	limit := req.Limit
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	changes, next, err := n.st.inner.Changes(n.ctx, since, limit)
	if err != nil {
		return nil, err
	}
	resp := &feedResp{FeedID: feed, Next: next, More: len(changes) >= limit, Recs: make([][]byte, 0, len(changes)),
		Synced: n.syncPoint(), CatchingUp: n.catchingUp.Load(), Origin: n.origin()}
	size := 0
	for i, c := range changes {
		if localOnly(c.Record.Kind) {
			continue // stays on this node
		}
		b, err := encodeRecord(c.Record)
		if err != nil {
			return nil, err
		}
		if size+len(b) > maxPageBytes && len(resp.Recs) > 0 {
			resp.Next, resp.More = changes[i-1].Seq, true
			break
		}
		size += len(b)
		resp.Recs = append(resp.Recs, b)
	}
	return resp, nil
}

// ---- push (broadcast) handlers ----

func (n *Node) handleRecord(_ *gossip.Node, pkt *gossip.Packet) error {
	var m recordMsg
	if err := pkt.Unmarshal(&m); err != nil {
		return err
	}
	rec, err := decodeRecord(m.B)
	if err != nil {
		return err
	}
	if n.behind.Load() != nil {
		return nil
	}
	if _, err := n.st.applyReplica(n.ctx, rec); err != nil && !errors.Is(err, errRefused) {
		return err
	}
	return nil
}

// handlePush applies a record sent directly by a durable writer and says whether this node now holds exactly that
// version (applyPush).
func (n *Node) handlePush(_ *gossip.Node, pkt *gossip.Packet) (any, error) {
	var m recordMsg
	if err := pkt.Unmarshal(&m); err != nil {
		return nil, err
	}
	rec, err := decodeRecord(m.B)
	if err != nil {
		return nil, err
	}
	st := n.applyPush(rec)
	return &ackMsg{OK: st == pushApplied, St: st}, nil
}

// Push outcomes (ackMsg.St).
const (
	pushApplied    uint8 = iota // this node now holds exactly the pushed version
	pushSuperseded              // not applied: this node holds something that ranks above it (store.Newer)
	pushRefused                 // not applied: this node is out of date, or the record is from another cluster
)

// applyPush applies a pushed record and reports whether this node now holds exactly that version: only then does it
// count towards a durable write's majority. A record this node did not apply because it holds something newer is
// not an acknowledgement (pushSuperseded): the write did not take effect here. Nor is one applied by a node that has
// not caught up (copying, catching up): it applies the record but does not count towards a majority, as it takes
// no part in quorum writes either.
func (n *Node) applyPush(rec *store.Record) uint8 {
	if n.behind.Load() != nil {
		return pushRefused
	}
	applied, err := n.st.applyReplica(n.ctx, rec)
	if err != nil || !n.votes() {
		return pushRefused
	}
	if applied || n.holds(rec) {
		return pushApplied
	}
	return pushSuperseded
}

// holds reports whether this node stores exactly rec's version of the record (from the same writer).
func (n *Node) holds(rec *store.Record) bool {
	cur, err := n.st.inner.Lookup(n.ctx, rec.Kind, rec.ID)
	return err == nil && cur.Version == rec.Version && cur.Origin == rec.Origin && cur.Deleted == rec.Deleted
}

// ackPeers sends the encoded record to every alive peer and waits until enough of them applied it that, with this
// node, a majority of the cluster holds it: the write then survives the loss of any minority of
// nodes. In a three-node cluster that is one peer.
func (n *Node) ackPeers(ctx context.Context, b []byte) error {
	need := n.Quorum() - 1
	peers := n.otherPeers()
	if need <= 0 && len(peers) == 0 {
		if n.peersExpected() {
			return fmt.Errorf("%w: no peer is reachable", ErrNotReplicated)
		}
		return nil
	}
	need = max(need, 1)
	if len(peers) < need {
		return fmt.Errorf("%w: %d peers reachable, %d must confirm", ErrNotReplicated, len(peers), need)
	}
	msg := &recordMsg{B: b}
	results := make(chan error, len(peers))
	for _, mb := range peers {
		go func(mb *member) {
			var ack ackMsg
			err := n.gc.SendToWithResponse(mb.node, msgPush, msg, &ack)
			if err == nil && !ack.OK {
				if ack.St == pushSuperseded {
					// It holds something newer: the write did not take effect there. Not an acknowledgement.
					n.superseded.Add(1)
					err = fmt.Errorf("peer %s holds a newer version: the write did not take effect there", mb.id)
				} else {
					err = fmt.Errorf("peer %s refused the record", mb.id)
				}
			}
			results <- err
		}(mb)
	}
	ok, failed := 0, 0
	var last error
	for range peers {
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %v", ErrNotReplicated, ctx.Err())
		case err := <-results:
			if err == nil {
				if ok++; ok >= need {
					return nil
				}
				continue
			}
			last = err
			if failed++; len(peers)-failed < need {
				return fmt.Errorf("%w: %d of %d needed peers confirmed (%v)", ErrNotReplicated, ok, need, last)
			}
		}
	}
	return fmt.Errorf("%w: %v", ErrNotReplicated, last)
}

// caughtUpWith records that this node has copied everything peer id had. A node that started with its own data
// has caught up once that holds for quorum-1 peers: with itself they make a majority, which shares a node with every
// majority that confirmed a write. A node that started empty holds no write of its own, so it needs a full quorum of
// peers, each caught up itself (syncPeer counts only those): otherwise an empty replacement could serve after copying
// from a single node that lacks a write the others confirmed.
func (n *Node) caughtUpWith(id string) {
	if !n.catchingUp.Load() {
		return
	}
	n.peersMu.Lock()
	n.caughtUp[id] = true
	got := len(n.caughtUp)
	n.peersMu.Unlock()
	need := n.Quorum() - 1
	if n.startedEmpty {
		need = n.Quorum()
	}
	if got >= need && n.catchingUp.CompareAndSwap(true, false) {
		n.log.Info("caught up with the cluster", "peers", got)
		if n.startedEmpty {
			// It caught up with size-quorum+1 caught-up peers: a formed cluster, which it is now a member of.
			n.markFormed()
		}
		if n.restored.Load() && n.restoredInto.Load() == nil { // the cluster formed around the restored data
			n.restored.Store(false)
			_ = os.Remove(filepath.Join(n.dir, RestoredMarker))
			n.log.Info("the cluster now holds the restored data: this node is an ordinary member")
		}
		n.rebuild()
	}
}

// origin reports whether this node is the data of a cluster that is forming (feedResp.Origin): a new cluster's
// first node ("quisora bootstrap --new-cluster"), a node forced with "quisora force-start" or restored from a backup —
// or a node that copied from one — that has caught up, sees a quorum of nodes alive, and has NEVER seen a quorum of
// nodes ready, or confirmed a quorum write, since its cluster state was created (Formed, persisted). Until a quorum is ready no write can be
// confirmed (quorum writes need a quorum of voters, a durable push counts only acknowledgements from nodes that have
// caught up), so it holds every write there is; an empty node that copied everything from it has caught up. This is
// how a cluster forms when all its other nodes start empty. Once a node has seen a quorum ready (or caught up as a
// member of a formed cluster) it is never an origin again, so a formed cluster's node — in particular one cut off
// from the majority — never lets an empty node skip catching up with size-quorum+1 caught-up peers.
func (n *Node) origin() bool {
	if n.catchingUp.Load() || n.bootstrap.Load() || !n.holdsData.Load() || n.refusal() != "" || !n.quorumOK() {
		return false
	}
	return !n.sawQuorumReady()
}

// readyInView counts the nodes this node sees ready (gossip metadata), itself included.
func (n *Node) readyInView() int {
	if n.blindReadiness.Load() {
		return 0
	}
	ready := 0
	if ok, _ := n.Ready(); ok {
		ready++
	}
	for _, mb := range n.mem.Load().routable {
		if mb.id != n.id && mb.state == gossip.NodeAlive && mb.ready {
			ready++
		}
	}
	return ready
}

// sawQuorumReady reports (and records, for good) whether this node has seen a quorum of nodes ready since it caught
// up: from then on writes can be confirmed by majorities without it, so it is no longer an origin even when it later
// sees fewer ready nodes (the others may hold writes it lacks).
func (n *Node) sawQuorumReady() bool {
	if n.formed.Load() {
		return true
	}
	if !n.catchingUp.Load() && !n.bootstrap.Load() && n.readyInView() >= n.Quorum() {
		n.markFormed()
		return true
	}
	return false
}

// markFormed records, for good (cluster-state.json), that this node's cluster has formed: it saw a quorum of nodes
// ready, caught up as a member of a formed cluster, or completed a quorum write that a quorum applied (commitAll).
func (n *Node) markFormed() {
	if !n.formed.Swap(true) {
		n.dirty.Store(true)
		n.log.Debug("cluster formed: a quorum of nodes is ready, or a write was confirmed by a quorum")
	}
}

// caughtUpWithOrigin: a node that started empty has copied everything from a node that holds every write the
// cluster has confirmed (origin): it has caught up.
func (n *Node) caughtUpWithOrigin(id string) {
	if !n.catchingUp.Load() {
		return
	}
	n.peersMu.Lock()
	n.caughtUp[id] = true
	n.peersMu.Unlock()
	if n.catchingUp.CompareAndSwap(true, false) {
		n.log.Info("caught up with the cluster: copied everything from its first node", "peer", id)
		n.rebuild()
	}
}

// sameDatabase stops this node while a peer serves this node's own change feed: the two share one database, which
// gossip clusters never do (each node replicates its own database; nodes sharing one database run without gossip).
// It lifts once that peer's feed differs again (the copy emptied by the operator, or the node's own database back).
func (n *Node) sameDatabase(peer string) {
	why := "node " + peer + " uses the same database as this node: with gossip every node needs its own database " +
		"(nodes that share a database run without gossip)"
	if n.misconfig.Swap(&why) == nil {
		n.log.Error("refusing to serve", "reason", why)
	}
	n.peersMu.Lock()
	n.sameAs = peer
	n.peersMu.Unlock()
}

// differentDatabase lifts sameDatabase when the peer that caused it now serves another feed.
func (n *Node) differentDatabase(peer string) {
	n.peersMu.Lock()
	was := n.sameAs == peer
	if was {
		n.sameAs = ""
	}
	n.peersMu.Unlock()
	if was && n.misconfig.Swap(nil) != nil {
		n.log.Info("no longer sharing a database with node " + peer)
	}
}

// holdsAll reports whether every record of a feed page is already here at the same or a newer version: a peer whose
// data is this node's own (copied from it, directly or through another new member).
func (n *Node) holdsAll(page [][]byte) bool {
	for _, b := range page {
		rec, err := decodeRecord(b)
		if err != nil {
			return false
		}
		if localOnly(rec.Kind) {
			continue
		}
		local, err := n.st.inner.Get(n.ctx, rec.Kind, rec.ID)
		if err != nil || local.Version < rec.Version {
			if !(rec.Deleted && errors.Is(err, store.ErrNotFound)) {
				return false
			}
		}
	}
	return true
}
