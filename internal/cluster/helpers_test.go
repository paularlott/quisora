package cluster

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/leader"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/kvstore"
	"github.com/paularlott/quisora/internal/store/memstore"
)

var bg = context.Background()

func testKey() string {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return base64.StdEncoding.EncodeToString(k)
}

// freeAddr returns a 127.0.0.1 address whose TCP and UDP ports are both free.
func freeAddr(t testing.TB) string {
	t.Helper()
	for range 50 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		u, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		l.Close()
		if err != nil {
			continue
		}
		u.Close()
		return fmt.Sprintf("127.0.0.1:%d", port)
	}
	t.Fatal("no free port")
	return ""
}

func fastGossip(c *gossip.Config) {
	c.GossipInterval = 300 * time.Millisecond
	c.GossipMaxInterval = time.Second
	c.MetadataGossipInterval = 200 * time.Millisecond
	c.StateGossipInterval = time.Second
	c.HealthCheckInterval = 300 * time.Millisecond
	c.PingTimeout = 200 * time.Millisecond
	c.SuspectTimeout = 600 * time.Millisecond
	c.SuspectRetryInterval = 300 * time.Millisecond
	c.DeadNodeTimeout = 2 * time.Second
	c.PeerRecoveryInterval = time.Second
}

func fastLeader(c *leader.Config) {
	c.LeaderCheckInterval = 200 * time.Millisecond
	c.LeaderTimeout = time.Second
	c.StabilityPeriod = 3 * time.Second
}

func fastOptions() Options {
	return Options{SyncInterval: 300 * time.Millisecond, JoinWait: 3 * time.Second, Gossip: fastGossip, Leader: fastLeader}
}

type tnode struct {
	n    *Node
	dir  string
	addr string
	cfg  *config.Config
}

func (tn *tnode) st() *Store { return tn.n.Store() }

type backend func(t testing.TB, dir string) store.Store

func memBackend(testing.TB, string) store.Store { return memstore.New() }

func badgerBackend(t testing.TB, dir string) store.Store {
	s, err := kvstore.OpenBadger(bg, filepath.Join(dir, "badger"), kvstore.BadgerOptions{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type tcluster struct {
	t      testing.TB
	key    string
	addrs  []string
	nodes  []*tnode
	mk     backend
	opts   func(*Options)
	noSeed bool // node 0 is not set up as the first node of a new cluster (seedNewCluster)
	// one simulated network per node index (kept across rebuilds of the node): see partition
	netMu sync.Mutex
	nets  map[int]*netsim
	mks   map[int]backend // per-node backend (mixed clusters); mk otherwise
}

// netsim wraps a node's gossip transport: it drops what the node sends to addresses it is cut off from (a network
// partition, with both sides cut off from each other), and can drop or slow single message types.
type netsim struct {
	mu        sync.RWMutex
	inner     gossip.Transport
	cut       map[string]bool
	dropTo    map[string]map[gossip.MessageType]bool
	feedDelay time.Duration
}

func (ns *netsim) tr() gossip.Transport {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.inner
}

func (ns *netsim) Name() string { return ns.tr().Name() }
func (ns *netsim) Start(ctx context.Context, wg *sync.WaitGroup) error {
	return ns.tr().Start(ctx, wg)
}
func (ns *netsim) PacketChannel() chan *gossip.Packet { return ns.tr().PacketChannel() }

func (ns *netsim) blocked(nd *gossip.Node, mt gossip.MessageType) bool {
	if nd == nil {
		return false
	}
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	a := nd.GetAddress()
	for _, addr := range []string{nd.AdvertisedAddr(), a.String()} {
		if ns.cut[addr] || ns.dropTo[addr][mt] {
			return true
		}
	}
	return false
}

func (ns *netsim) Send(tt gossip.TransportType, nd *gossip.Node, p *gossip.Packet) error {
	if ns.blocked(nd, p.MessageType) {
		return errors.New("netsim: unreachable")
	}
	return ns.tr().Send(tt, nd, p)
}

func (ns *netsim) SendWithReply(nd *gossip.Node, p *gossip.Packet) (*gossip.Packet, error) {
	if ns.blocked(nd, p.MessageType) {
		return nil, errors.New("netsim: unreachable")
	}
	ns.mu.RLock()
	d := ns.feedDelay
	ns.mu.RUnlock()
	if d > 0 && p.MessageType == msgFeed {
		time.Sleep(d)
	}
	return ns.tr().SendWithReply(nd, p)
}

func (c *tcluster) net(i int) *netsim {
	c.netMu.Lock()
	defer c.netMu.Unlock()
	if c.nets == nil {
		c.nets = map[int]*netsim{}
	}
	ns := c.nets[i]
	if ns == nil {
		ns = &netsim{cut: map[string]bool{}, dropTo: map[string]map[gossip.MessageType]bool{}}
		c.nets[i] = ns
	}
	return ns
}

// partition cuts the network into the given groups of node indexes: a node reaches only the nodes of its group.
// Nodes in no group reach nobody.
func (c *tcluster) partition(groups ...[]int) {
	group := map[int]int{}
	for g, members := range groups {
		for _, i := range members {
			group[i] = g + 1
		}
	}
	for i := range c.addrs {
		ns := c.net(i)
		ns.mu.Lock()
		ns.cut = map[string]bool{}
		for j, a := range c.addrs {
			if j != i && (group[i] == 0 || group[i] != group[j]) {
				ns.cut[a] = true
			}
		}
		ns.mu.Unlock()
	}
}

// cutBetween cuts the link between node i and each of others (both directions), leaving the rest as it is.
func (c *tcluster) cutBetween(i int, others ...int) {
	for _, j := range others {
		for _, p := range [][2]int{{i, j}, {j, i}} {
			ns := c.net(p[0])
			ns.mu.Lock()
			ns.cut[c.addrs[p[1]]] = true
			ns.mu.Unlock()
		}
	}
}

// heal ends every partition and message drop.
func (c *tcluster) heal() {
	for i := range c.addrs {
		ns := c.net(i)
		ns.mu.Lock()
		ns.cut, ns.dropTo, ns.feedDelay = map[string]bool{}, map[string]map[gossip.MessageType]bool{}, 0
		ns.mu.Unlock()
	}
}

// dropData drops the replication traffic (broadcasts, pushes, feed pulls) between node i and every other node, both
// ways, while membership gossip goes on: it stays in view (and writable) but exchanges no data with the others.
func (c *tcluster) dropData(i int, on bool) {
	data := []gossip.MessageType{msgRecord, msgPush, msgFeed, msgPrepare, msgCommit, msgRead}
	set := func(from int, to string) {
		ns := c.net(from)
		ns.mu.Lock()
		if ns.dropTo[to] == nil {
			ns.dropTo[to] = map[gossip.MessageType]bool{}
		}
		for _, mt := range data {
			ns.dropTo[to][mt] = on
		}
		ns.mu.Unlock()
	}
	for j, a := range c.addrs {
		if j != i {
			set(i, a)
			set(j, c.addrs[i])
		}
	}
}

// dropDataBetween drops (or restores) the replication traffic between nodes i and j, both ways, and nothing else.
func (c *tcluster) dropDataBetween(i, j int, on bool) {
	for _, p := range [][2]int{{i, j}, {j, i}} {
		ns := c.net(p[0])
		ns.mu.Lock()
		to := c.addrs[p[1]]
		if ns.dropTo[to] == nil {
			ns.dropTo[to] = map[gossip.MessageType]bool{}
		}
		for _, mt := range []gossip.MessageType{msgRecord, msgPush, msgFeed, msgPrepare, msgCommit, msgRead} {
			ns.dropTo[to][mt] = on
		}
		ns.mu.Unlock()
	}
}

// dropPushes makes node i's peers ignore its durable-write pushes (they never acknowledge), and nothing else.
func (c *tcluster) dropPushes(i int) {
	ns := c.net(i)
	ns.mu.Lock()
	defer ns.mu.Unlock()
	for j, a := range c.addrs {
		if j != i {
			if ns.dropTo[a] == nil {
				ns.dropTo[a] = map[gossip.MessageType]bool{}
			}
			ns.dropTo[a][msgPush] = true
		}
	}
}

// seedNewCluster makes an empty store the first node of a new cluster, as "quisora bootstrap --new-cluster" does: one
// record (a link token, which the tests never read) and the cluster state saying it is the cluster's data now.
// Without such a node empty nodes wait (a cluster never forms from empty nodes alone).
func seedNewCluster(t testing.TB, st store.Store, dir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, "cluster-state.json")); err == nil {
		return
	}
	if n, _ := st.Count(bg, model.KindLink, ""); n > 0 {
		return
	}
	for _, k := range model.Kinds() {
		if n, _ := st.Count(bg, k, ""); n > 0 && k != model.KindEphemeral {
			return // holds data already (a restore)
		}
	}
	rec := &store.Record{Kind: model.KindLink, ID: "seed", Version: store.Clock.Now(), Scope: "seed", Data: []byte("{}")}
	if _, _, err := st.PutReplicated(bg, rec); err != nil {
		t.Fatal(err)
	}
	if err := MarkSynced(dir, st.FeedID()); err != nil {
		t.Fatal(err)
	}
}

func newTCluster(t testing.TB, size int, mk backend) *tcluster {
	c := &tcluster{t: t, key: testKey(), mk: mk}
	for range size {
		c.addrs = append(c.addrs, freeAddr(t))
	}
	return c
}

func (c *tcluster) config(i int, dir string) *config.Config {
	cfg := config.Default()
	cfg.Server.DataDir = dir
	cfg.Cluster.Bind = c.addrs[i]
	cfg.Cluster.Key = c.key
	cfg.Cluster.Peers = c.addrs
	cfg.Cluster.Size = len(c.addrs)
	return cfg
}

// build creates node i (not started).
func (c *tcluster) build(i int, dir string, tweak func(*config.Config)) *tnode {
	if dir == "" {
		dir = c.t.TempDir()
	}
	cfg := c.config(i, dir)
	if tweak != nil {
		tweak(cfg)
	}
	opt := fastOptions()
	if c.opts != nil {
		c.opts(&opt)
	}
	ns := c.net(i)
	opt.transport = func(tr gossip.Transport) gossip.Transport {
		ns.mu.Lock()
		ns.inner = tr
		ns.mu.Unlock()
		return ns
	}
	mk := c.mk
	if m := c.mks[i]; m != nil {
		mk = m
	}
	st := mk(c.t, dir)
	if i == 0 && !c.noSeed {
		seedNewCluster(c.t, st, dir)
	}
	n, err := New(cfg, st, opt)
	if err != nil {
		c.t.Fatal(err)
	}
	return &tnode{n: n, dir: dir, addr: c.addrs[i], cfg: cfg}
}

// startAll builds and starts every node concurrently.
func (c *tcluster) startAll() {
	for i := range c.addrs {
		c.nodes = append(c.nodes, c.build(i, "", nil))
	}
	c.start(c.nodes...)
	c.t.Cleanup(c.closeAll)
}

func (c *tcluster) start(nodes ...*tnode) {
	errs := make(chan error, len(nodes))
	for _, tn := range nodes {
		go func() { errs <- tn.n.Start(bg) }()
	}
	for range nodes {
		if err := <-errs; err != nil {
			c.t.Fatal(err)
		}
	}
}

func (c *tcluster) closeAll() {
	for _, tn := range c.nodes {
		stop(tn)
	}
}

func stop(tn *tnode) {
	tn.n.Close()
	tn.n.Store().Close()
}

func waitFor(t testing.TB, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// waitReady waits until every node reports Ready.
func (c *tcluster) waitReady(nodes ...*tnode) {
	c.t.Helper()
	if len(nodes) == 0 {
		nodes = c.nodes
	}
	waitFor(c.t, 20*time.Second, "cluster ready", func() bool {
		for _, tn := range nodes {
			if ok, _ := tn.n.Ready(); !ok {
				return false
			}
		}
		return true
	})
}

// The tests write as soon as their nodes are ready: voters take part at once (restartPause has tests of its own).
func init() { restartPause = 0 }

// dataKind is the kind of the plain data records the tests write (newRec): replicated, and not a quorum kind
// (model.QuorumCAS), so its writes are local writes pushed to the peers (durable or not).
const dataKind = model.KindIdentity

func newRec(id, uniq string) *store.Record {
	r := &store.Record{Kind: dataKind, ID: id, Version: store.Clock.Now(), Scope: "org1",
		Fields: map[string]any{"display_name": "group " + id, "created": time.Now().UTC().Truncate(time.Microsecond), "n": int64(7), "b": true},
		Data:   []byte("data-" + id)}
	if uniq != "" {
		r.Unique = []string{uniq}
	}
	return r
}

func newID() string { return uuid.Must(uuid.NewV7()).String() }

func has(s store.Store, id string) bool {
	_, err := s.Get(bg, dataKind, id)
	return err == nil
}

func countAll(s store.Store) int {
	n, _ := s.Count(bg, dataKind, "")
	return n
}
