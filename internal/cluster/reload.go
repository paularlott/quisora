package cluster

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/paularlott/gossip"
)

// A configuration reload re-reads every node's configuration file at once (ReloadCluster, behind POST
// /api/cluster/reload) — the master keys, the cluster keys and the cluster size — so a key rotation or a change of
// size reaches the whole cluster without a restart. The size changes by one node at a time (see CheckResize): any
// majority of the old size and any majority of the new one then share a node, so every write a majority confirmed
// before the change is seen by every majority after it, and the cluster stays writable throughout.

// reloadWait is how long a node is given to answer each phase of a cluster-wide reload.
const reloadWait = 10 * time.Second

// ReloadReport is one node's answer to a configuration reload.
type ReloadReport struct {
	Node    string   `json:"node"`
	Size    int      `json:"size"`              // the cluster.size its configuration names
	Changes []string `json:"changes,omitempty"` // what applying changed (keys rotated, size changed)
	Error   string   `json:"error,omitempty"`
}

// Reloader re-reads this node's configuration (the application provides it: it knows the configuration file). With
// apply false it only reads and checks it (CheckResize for the size) and reports the size it names; with apply true
// it switches to it — master keys, cluster keys, then Resize — refusing a size other than want (0: any).
type Reloader func(ctx context.Context, apply bool, want int) ReloadReport

type reloadReq struct {
	Apply bool `msgpack:"a"`
	Want  int  `msgpack:"w"`
}

// SetReloader sets how this node re-reads its configuration (for ReloadCluster and its peers' requests).
func (n *Node) SetReloader(fn Reloader) { n.reloader.Store(&fn) }

// Reload re-reads this node's configuration and applies it (SIGHUP), as one node of a cluster-wide reload would.
func (n *Node) Reload(ctx context.Context) ReloadReport { return n.reload(ctx, true, 0) }

func (n *Node) reload(ctx context.Context, apply bool, want int) ReloadReport {
	fn := n.reloader.Load()
	if fn == nil {
		return ReloadReport{Node: n.id, Size: n.Size(), Error: "this node cannot reload its configuration"}
	}
	r := (*fn)(ctx, apply, want)
	r.Node = n.id
	return r
}

func (n *Node) handleReload(_ *gossip.Node, pkt *gossip.Packet) (any, error) {
	var req reloadReq
	if err := pkt.Unmarshal(&req); err != nil {
		return nil, err
	}
	r := n.reload(n.ctx, req.Apply, req.Want)
	return &r, nil
}

// ReloadCluster has every node in view re-read its configuration, in two phases. First each one reads and checks
// it; only if every node can apply it and all name the same cluster size does each one apply it. A node that is
// down is not asked: it reads its configuration when it starts. The reports are sorted by node, and the error says
// why nothing (or not everything) was applied.
//
// The nodes are those of the cluster gossip, or, for nodes sharing a database, of the notice gossip
// (cluster.notify). Nodes sharing a database without it have no way to reach each other: only this one reloads, and
// the error says so.
func (n *Node) ReloadCluster(ctx context.Context) ([]ReloadReport, error) {
	gc, peers := n.gc, []*member(nil)
	switch {
	case n.gc != nil:
		peers = n.otherPeers()
	case n.ngc != nil:
		gc, peers = n.ngc, n.noticePeers()
	default:
		r := n.reload(ctx, true, 0)
		if r.Error != "" {
			return []ReloadReport{r}, errors.New(r.Error)
		}
		if n.shared != nil {
			return []ReloadReport{r}, errors.New("reloaded this node only: nodes sharing the database without " +
				"cluster.notify cannot reach each other; reload each of them (SIGHUP), or set up cluster.notify")
		}
		return []ReloadReport{r}, nil
	}
	n.reloadMu.Lock() // one reload at a time from this node
	defer n.reloadMu.Unlock()
	checks := n.reloadPhase(ctx, gc, peers, reloadReq{})
	want, bad := 0, ""
	for _, r := range checks {
		switch {
		case r.Error != "":
			bad = fmt.Sprintf("node %s: %s", r.Node, r.Error)
		case want == 0:
			want = r.Size
		case r.Size != want:
			bad = fmt.Sprintf("the nodes' configurations name different sizes (%d and %d): set the same cluster.size "+
				"on every node", want, r.Size)
		}
		if bad != "" {
			return checks, errors.New("nothing was reloaded: " + bad)
		}
	}
	applied := n.reloadPhase(ctx, gc, peers, reloadReq{Apply: true, Want: want})
	var failed []string
	for _, r := range applied {
		if r.Error != "" {
			failed = append(failed, fmt.Sprintf("node %s: %s", r.Node, r.Error))
		}
	}
	if len(failed) > 0 {
		return applied, fmt.Errorf("not every node reloaded (reload again once fixed): %s", failed)
	}
	return applied, nil
}

// reloadPhase runs one phase on this node and on peers, and returns every node's report (a node that does not
// answer in time gets one with an error).
func (n *Node) reloadPhase(ctx context.Context, gc *gossip.Cluster, peers []*member, req reloadReq) []ReloadReport {
	replies := make(chan ReloadReport, len(peers))
	for _, mb := range peers {
		go func(mb *member) {
			var resp ReloadReport
			if err := gc.SendToWithResponse(mb.node, msgReload, &req, &resp); err != nil {
				resp = ReloadReport{Error: "did not answer: " + err.Error()}
			}
			resp.Node = mb.id
			replies <- resp
		}(mb)
	}
	out := []ReloadReport{n.reload(ctx, req.Apply, req.Want)}
	timeout := time.NewTimer(reloadWait)
	defer timeout.Stop()
	pending := map[string]bool{}
	for _, mb := range peers {
		pending[mb.id] = true
	}
collect:
	for range peers {
		select {
		case r := <-replies:
			delete(pending, r.Node)
			out = append(out, r)
		case <-timeout.C:
			break collect
		case <-ctx.Done():
			break collect
		}
	}
	for id := range pending {
		out = append(out, ReloadReport{Node: id, Error: "did not answer in time"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

// noticePeers are the other nodes alive in the notice gossip of nodes sharing a database.
func (n *Node) noticePeers() []*member {
	var out []*member
	for _, nd := range n.ngc.Nodes() {
		if id := nd.ID.String(); id != n.id && nd.GetObservedState() == gossip.NodeAlive {
			out = append(out, &member{id: id, node: nd, state: gossip.NodeAlive})
		}
	}
	return out
}

// CheckResize reports whether this node can change to a cluster of size nodes whose peers list is peers (this node
// included, however named), without applying it: nil when size is the current one.
//
//   - The size changes by one at most: any majority of the old size and any majority of the new one share a node,
//     so no write a majority confirmed is missed by a majority after the change.
//   - Growing, the nodes in view must still make a majority of the new size (a new node joins after the change).
//   - Shrinking, the node that leaves must be stopped first: the nodes in view must fit the new size.
func (n *Node) CheckResize(size int, peers []string) error {
	if n.gc == nil {
		if size != 0 {
			return errors.New("cluster.size applies only with cluster.bind")
		}
		return nil
	}
	cur := n.Size()
	if others := n.others(peers); len(others)+1 != size {
		return fmt.Errorf("cluster.size is %d but cluster.peers names %d other nodes (and this one)", size, len(others))
	}
	alive := n.mem.Load().alive
	switch {
	case size == cur:
		return nil
	case size < 2:
		return errors.New("cluster.size must be at least 2")
	case size > cur+1 || size < cur-1:
		return fmt.Errorf("cluster.size can change by one node at a time (now %d, configured %d): change it to %d, "+
			"reload, and repeat", cur, size, cur+sign(size-cur))
	case size > cur && alive < size/2+1:
		return fmt.Errorf("growing to %d nodes needs %d of them in view, %d are", size, size/2+1, alive)
	case size < cur && alive > size:
		return fmt.Errorf("shrinking to %d nodes: %d are in view; stop the node that leaves the cluster first", size,
			alive)
	}
	return nil
}

// Resize changes the cluster size and peers list of the running node (CheckResize first): the quorum, readiness,
// catching up and the leader election follow at once, and the new size is published to the other nodes. Until every
// node in view has the same size none of them serves (the usual size check), so reload every node at once
// (ReloadCluster). It reports whether the size changed.
func (n *Node) Resize(size int, peers []string) (bool, error) {
	if err := n.CheckResize(size, peers); err != nil {
		return false, err
	}
	if n.gc == nil {
		return false, nil
	}
	n.seedMu.Lock()
	n.seeds, n.seedsSet = n.others(peers), true
	n.seedMu.Unlock()
	old := n.Size()
	if size == old {
		return false, nil
	}
	n.nodes.Store(int64(size))
	n.le.SetClusterSize(size, size/2+1)
	n.gc.LocalMetadata().SetInt(metaSize, size)
	n.rebuild()
	n.log.Warn("cluster size changed", "from", old, "to", size, "quorum", size/2+1)
	return true, nil
}

func sign(x int) int {
	if x < 0 {
		return -1
	}
	return 1
}
