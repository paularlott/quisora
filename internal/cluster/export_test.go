package cluster

import "github.com/paularlott/quisora/internal/store"

// OwnerOf returns the node an operation on the ephemeral id (or key) is routed to; local reports whether that is this
// node, and dead whether the id belongs to a node that gossip has marked dead.
func (n *Node) OwnerOf(ns, id string) (nodeID string, local, dead bool) {
	mb, dead := n.route(ns, id)
	if dead || mb == nil {
		return "", false, true
	}
	return mb.id, mb.id == n.id, false
}

// Inner returns the wrapped store.
func (s *Store) Inner() store.Store { return s.inner }
