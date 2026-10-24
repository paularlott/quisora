package cluster

import (
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/codec/shamaton"
	"github.com/paularlott/gossip/compression/snappy"
	"github.com/paularlott/gossip/encryption/aes"
	"github.com/paularlott/quisora/internal/build"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Nodes that share one database server do not replicate, and without cluster.bind they are never told about each
// other's writes. cluster.notify gives them a gossip network of their own that carries only change notices (a
// record's kind, id and scope; never its data): each node tells the others of its writes and runs its change hooks
// for theirs, as for a replicated record (cache eviction, live admin pages). A notice is best effort: a lost one
// only waits for a cache to expire (5 seconds on a shared database). A notice that arrives twice runs the hooks
// twice, which is harmless.

// noticeMsg is one change notice.
type noticeMsg struct {
	K string // kind
	I string // id
	S string // scope
	D bool   // deleted
}

// noticeWorthy: the kinds whose changes other nodes care about (not short-lived state, nor the housekeeping lease).
func noticeWorthy(k model.Kind) bool {
	return k != model.KindEphemeral && k != model.KindLock && k != model.KindReplay
}

// buildNotify sets up the notice gossip (cluster.notify) of a node sharing its database.
func (n *Node) buildNotify() error {
	nc := n.cfg.Cluster.Notify
	key, _, err := decodeClusterKeys(nc.Key, nil)
	if err != nil {
		return err
	}
	adv := nc.Advertise
	if adv == "" {
		adv = nc.Bind
	}
	gcfg := gossip.DefaultConfig()
	gcfg.NodeID = n.id
	gcfg.BindAddr = nc.Bind
	gcfg.AdvertiseAddr = adv
	gcfg.EncryptionKey = key
	gcfg.MaxPacketAge = 2 * time.Minute // a captured notice cannot be replayed later
	gcfg.Cipher = aes.New()
	gcfg.MsgCodec = shamaton.New()
	gcfg.Compressor = snappy.New()
	gcfg.Logger = n.opt.Log
	gcfg.TCPDeadline = 2 * time.Second
	gcfg.ApplicationVersion = build.Version
	gcfg.Transport = gossip.NewSocketTransport(gcfg)
	gc, err := gossip.NewCluster(gcfg)
	if err != nil {
		return err
	}
	if err := gc.HandleFunc(msgNotice, n.handleNotice); err != nil {
		return err
	}
	// A configuration reload reaches every node sharing the database through the notice gossip (ReloadCluster).
	if err := gc.HandleFuncWithReply(msgReload, n.handleReload); err != nil {
		return err
	}
	for _, p := range nc.Peers {
		if p != "" && !isSelfAddr(p, adv) {
			n.notifyPeers = append(n.notifyPeers, p)
		}
	}
	n.ngc = gc
	return nil
}

// startNotify joins the other nodes' notice gossip. Peers that are not up yet join this node when they start.
func (n *Node) startNotify() {
	n.ngc.Start()
	if err := n.ngc.Join(n.notifyPeers); err != nil {
		n.log.WithError(err).Info("notice gossip: no other node reachable yet (they join this one when they start)")
	}
}

// notice tells the other nodes sharing the database of a local write.
func (n *Node) notice(rec *store.Record) {
	if n.ngc == nil || !noticeWorthy(rec.Kind) {
		return
	}
	m := &noticeMsg{K: string(rec.Kind), I: rec.ID, S: rec.Scope, D: rec.Deleted}
	if err := n.ngc.Send(msgNotice, m); err != nil {
		n.log.WithError(err).Debug("change notice", "kind", m.K, "id", m.I)
	}
}

// handleNotice runs this node's change hooks for another node's write.
func (n *Node) handleNotice(_ *gossip.Node, pkt *gossip.Packet) error {
	var m noticeMsg
	if err := pkt.Unmarshal(&m); err != nil {
		return err
	}
	if m.K == "" || m.I == "" {
		return nil
	}
	n.fire(&store.Record{Kind: model.Kind(m.K), ID: m.I, Scope: m.S, Deleted: m.D}, false)
	return nil
}
