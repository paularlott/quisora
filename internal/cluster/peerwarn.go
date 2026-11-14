package cluster

import (
	"strings"
	"time"

	"github.com/paularlott/gossip"
)

// peersWarnEvery bounds how often a node that has not formed the cluster names the peers it cannot see.
const peersWarnEvery = time.Minute

// warnMissingPeers names, at most once per peersWarnEvery, the configured peers (cluster.peers) that are not in
// view while this node has not formed the cluster: it runs no partition protocol yet, or sees fewer than a majority
// of the nodes. It is called from watchLoop, every second.
//
// A peer configured with another cluster.key is one such peer, and the worst to find: each node drops every packet
// of the other as undecryptable, so neither ever joins the other, the nodes wait for a quorum or a data set that does
// not come, and nothing but this line says which address to look at. The gossip library refuses those packets
// before this package sees them, without saying from where (it logs a decryption failure with no address), so the
// line names the peers from the configuration that are not in view, with the causes to check, the key among them. A
// node that has formed the cluster says nothing: a peer missing then shows on the cluster page and in Status.
//
// The check itself runs at most once per peersWarnEvery too, whether it finds a peer missing or not (a node waiting
// for genesis, with an unfit database, or with fewer peers listed than cluster.size, finds none, and would otherwise
// check every second), and off watchLoop: telling a peer from its advertised address may resolve host names
// (isSelfAddr, 2 s a lookup), which during a DNS outage would hold up the loop that forms the cluster. A check still
// waiting on its lookups when the next is due is not doubled.
func (n *Node) warnMissingPeers(now time.Time) {
	if n.manager() != nil && n.quorumOK() {
		return
	}
	if now.Sub(n.peersChecked) < peersWarnEvery || !n.peersChecking.CompareAndSwap(false, true) {
		return
	}
	n.peersChecked = now
	seeds, mem := n.seedPeers(), n.mem.Load()
	go func() {
		defer n.peersChecking.Store(false)
		missing := missingPeers(seeds, mem.all, n.id)
		if len(missing) == 0 {
			return
		}
		n.log.Warn("cluster peers not in view, and the cluster has not formed without them: each is not started, "+
			"not reachable on its cluster address, or configured with another cluster.key (nodes with different keys "+
			"drop each other's packets as undecryptable and never meet): check that every node has the same cluster.key",
			"peers", strings.Join(missing, ", "), "in_view", mem.alive, "size", n.Size())
	}()
}

// missingPeers returns the entries of seeds (cluster.peers, this node's own left out) that no member other than self
// alive or suspect advertises.
func missingPeers(seeds []string, members []*member, self string) []string {
	var missing []string
	for _, seed := range seeds {
		found := false
		for _, mb := range members {
			if mb.id == self || mb.node == nil || (mb.state != gossip.NodeAlive && mb.state != gossip.NodeSuspect) {
				continue
			}
			if adv := mb.node.AdvertisedAddr(); adv != "" && isSelfAddr(seed, adv) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, seed)
		}
	}
	return missing
}
