// Package cluster runs one of the two cluster modes and reports readiness.
//
// With cluster.bind (gossip mode) the node joins a gossip cluster: every node has its own database, and the data is
// replicated by partition (the gossip library's partition package, docs/REPLICATION.md): every partition has one owner
// node that orders its writes and commits each on a majority of the cluster before it is visible, ephemeral state is
// routed to the node that owns it, and the owner of partition 0 runs housekeeping.
//
// Without it there is no gossip. On a database server that several nodes share (PostgreSQL, MySQL, MariaDB) ephemeral
// state lives in that database and a lease there picks the housekeeping node; on badger or sqlite the node is alone,
// keeps ephemeral state in memory and always leads.
package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/codec/shamaton"
	"github.com/paularlott/gossip/compression/snappy"
	"github.com/paularlott/gossip/encryption/aes"
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/gossip/partition"
	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/build"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

var (
	// ErrPrefixCollision is returned by Start when another member has the same ephemeral id prefix.
	ErrPrefixCollision = errors.New("cluster: node id prefix collision")
	// ErrClockBeforeEpoch is returned by New when this machine's clock is set before the version clock's epoch
	// (1 January 2025): versions minted here could not follow time, so the node refuses to start.
	ErrClockBeforeEpoch = errors.New("cluster: this machine's clock is set before 2025: fix the clock (NTP) before starting")
)

// wallNow is this machine's clock (tests set it to check the start-up refusal).
var wallNow = time.Now

// Gossip metadata this node publishes about itself.
const (
	metaSize      = "quisora.size"       // cluster.size: every node must agree
	metaReady     = "quisora.ready"      // the node serves (Ready): owners of hash-routed short-lived state are chosen among these
	metaCompat    = "quisora.compat"     // compat: what this build exchanges with other nodes
	metaMinCompat = "quisora.compat_min" // minCompat: the oldest a peer may speak for this build to work with it
)

// Compatibility of what nodes exchange (the partition protocol's messages and records, ephemeral operations). A build
// speaks compat and still understands peers down to minCompat; two nodes work together only when each one's compat is
// at least the other's minimum. A rolling upgrade from the previous release works when the new build keeps minCompat at
// the previous compat (docs/RUNNING.md, "Upgrading"). Raise compat when what nodes send each other changes; raise
// minCompat when this build no longer understands what the previous compat sent. Builds from before this check publish
// neither (0) and are refused. A node that sees an incompatible peer drops its messages and refuses to serve (Ready)
// until the peer is upgraded or gone, as for a cluster.size mismatch.
//
// 1 was the first release's leaderless gossip mode (quorum compare-and-swap, change feeds); 2 is the partition
// protocol, which that mode's nodes cannot take part in, so a node of either refuses the other.
const (
	compat    = 2
	minCompat = 2
)

// compatible reports whether a peer speaking peerCompat, which understands down to peerMin, works with this build.
func compatible(peerCompat, peerMin int) bool { return peerCompat >= minCompat && compat >= peerMin }

// publishedCompat returns what a peer published about its build (metaCompat, metaMinCompat), and false while it
// has published nothing yet: a peer that has just joined is known before its metadata arrives, and an empty
// metadata set must not read as "compatibility 0".
func publishedCompat(nd *gossip.Node) (c, cm int, ok bool) {
	if nd == nil || nd.Metadata == nil || !nd.Metadata.Exists(metaCompat) {
		return 0, 0, false
	}
	return nd.Metadata.GetInt(metaCompat), nd.Metadata.GetInt(metaMinCompat), true
}

// peerCompatible reports whether messages from sender may be handled: its published compatibility fits, or it has
// published none yet (a peer still joining).
func peerCompatible(sender *gossip.Node) bool {
	c, cm, ok := publishedCompat(sender)
	return !ok || compatible(c, cm)
}

// errIncompatible answers a request from a peer of an incompatible build.
var errIncompatible = errors.New("cluster: the peer runs an incompatible build")

func compatOnlyReply(f gossip.ReplyHandler) gossip.ReplyHandler {
	return func(sender *gossip.Node, p *gossip.Packet) (interface{}, error) {
		if !peerCompatible(sender) {
			return nil, errIncompatible
		}
		return f(sender, p)
	}
}

// Options tunes a Node. The zero value is valid.
type Options struct {
	Log logger.Logger
	// TombstoneRetention is how long tombstones are kept before the owner of a partition purges them (a node that is
	// behind by more than the purged history copies the partition whole). Default (and most) model.TombstoneRetention.
	TombstoneRetention time.Duration
	// ClockInterval is how often each peer's clock is read (the peer clock check, clock.go). Default 5 seconds.
	ClockInterval time.Duration
	// JoinWait is how long Start waits for the first peer to appear before carrying on. Default 2 seconds.
	JoinWait time.Duration
	// ForceStart starts this node as one whose data may not be trusted, like the ForceStartMarker file "quisora
	// force-start" leaves (tests set it directly): it resyncs from the nodes that answer, even fewer than a majority.
	ForceStart bool
	// Gossip and Partition adjust the library configurations before use (tests shorten the failure-detection
	// and heartbeat timings).
	Gossip    func(*gossip.Config)
	Partition func(*partition.Config)

	prefix    func(id string) string                  // tests: override PrefixOf to force collisions
	transport func(gossip.Transport) gossip.Transport // tests: wrap the transport (network partitions)
}

func (o *Options) defaults() {
	if o.Log == nil {
		o.Log = logger.NewNullLogger()
	}
	if o.TombstoneRetention <= 0 || o.TombstoneRetention > model.TombstoneRetention {
		o.TombstoneRetention = model.TombstoneRetention
	}
	if o.ClockInterval <= 0 {
		o.ClockInterval = 5 * time.Second
	}
	if o.JoinWait <= 0 {
		o.JoinWait = 2 * time.Second
	}
}

// nodeStats are the counters of the partition protocol's use by this node (Status).
type nodeStats struct {
	writes      atomic.Int64 // changes committed
	refused     atomic.Int64 // changes an owner refused (a version moved, a unique value in use, ...)
	unknown     atomic.Int64 // changes whose outcome was not known (the owner was lost mid-write)
	unavailable atomic.Int64 // changes that found no owner or no majority
	reads       atomic.Int64 // fresh reads of a partition asked of its owner
	readFailed  atomic.Int64 // of which failed
	takeovers   atomic.Int64 // partitions this node became the owner of
}

// ownerInfo is who this node last heard take a partition, and at which epoch.
type ownerInfo struct {
	node  string
	epoch uint64
}

// Node is this process's membership of the cluster.
type Node struct {
	// applies counts the changes this node has applied to its copy (commits, import batches, purges), each counted
	// after it is readable and before the partition's committed position moves: a read that saw the count unchanged
	// across it and the staleness gate saw no change land in between (Store.gated).
	applies atomic.Uint64

	cfg    *config.Config
	opt    Options
	log    logger.Logger
	id     string
	prefix string
	dir    string

	gc *gossip.Cluster // nil when standalone

	keyMu     sync.Mutex
	clusterKs []string // cluster.key, then cluster.previous_keys, as in use (SetClusterKeys)

	nodes    atomic.Int64             // cluster.size: the number of nodes the cluster is made of (changed only by Resize)
	reloader atomic.Pointer[Reloader] // re-reads the configuration (SetReloader)
	reloadMu sync.Mutex               // one ReloadCluster at a time
	applyMu  sync.Mutex               // one reload of this node's configuration at a time (SIGHUP, a peer, ReloadCluster)
	seedMu   sync.Mutex
	seeds    []string // the configured peers other than this node (seedPeers; replaced by Resize)
	seedsSet bool

	st  *Store
	eph *Ephemeral

	// The partition protocol (gossip only): the node's partition.Store over its database, the Manager (nil until the
	// node holds a data set and starts it: joinDataSet; replaced by Resize, which restarts it with the new size) and
	// what the node knows about the owners.
	pst         *pstore
	pm          atomic.Pointer[partition.Manager]
	pmMu        sync.Mutex // one start or stop of the Manager at a time
	pmStarted   bool       // the Manager has been started (guarded by pmMu)
	pmClosed    bool       // the node is closing: no Manager is started any more (guarded by pmMu)
	owners      [partitions]atomic.Pointer[ownerInfo]
	stats       nodeStats
	intact      atomic.Bool // the database's partition state can be trusted (see loadState); true once a resync is done
	forceResync atomic.Bool // this start resyncs from the nodes that answer (quisora force-start)
	lastScan    [partitions]atomic.Int64

	// Nodes sharing one database without gossip: short-lived state lives in the database and leadership is a lease
	// there (both nil otherwise).
	shared *ephemeral.Shared
	// ngc is the notice gossip of a node sharing its database (cluster.notify; nil otherwise): change notices only.
	ngc         *gossip.Cluster
	notifyPeers []string
	// delScopes holds the scope of a record being deleted (kind/id -> scope) from just before the deletion is
	// applied until the change hooks run: a tombstone carries none, and the hooks need it (which organization's
	// administrators, which user's pages, the notices). Only without gossip: a partition write's tombstone carries it.
	delScopes sync.Map
	lease     *lease

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mem       atomic.Pointer[membership]
	memMu     sync.Mutex
	prefixes  sync.Map // node id -> prefix
	collision atomic.Pointer[string]
	sizeOff   atomic.Pointer[string] // fewer than a majority share this node's cluster.size: not while it lasts
	sizeSeen  atomic.Pointer[string] // a member of another cluster.size is in view (logged once)
	compatOff atomic.Pointer[string] // a member runs an incompatible build: not while it lasts
	clockOff  atomic.Pointer[string] // this node's clock is off from the other nodes': not while it lasts (clock.go)
	clocks    peerClocks             // the latest reading of each peer's clock (clock.go)
	mixed     atomic.Pointer[string] // gossip and non-gossip nodes on one database: not while it lasts (mixedDatabase)
	foreign   atomic.Pointer[string] // the database belongs to another node id: not while it lasts (checkOwner)
	unfit     atomic.Pointer[string] // the database cannot be served: records no partition write made (loadState)
	// otherCluster: this node's data set was set up apart from the cluster it met (checkGenesis); stranger: a node of
	// another data set is in view, which this node's majority ignores (logged once).
	otherCluster atomic.Pointer[string]
	stranger     atomic.Pointer[string]
	genesis      atomic.Pointer[string] // the data set this node holds (persisted.Genesis; nil: none yet)
	dataSetWait  atomic.Pointer[string] // why a node without a data set has not started the partition protocol
	formed       atomic.Bool            // it takes part in its data set's majorities (persisted.Formed, the protocol's)

	hooks  atomic.Pointer[[]func(*store.Record, bool)]
	hookMu sync.Mutex

	// The partitions this node cannot vouch for (partstatus.go): partOff says why it is not ready because of them (a
	// partition diverged here); divergedSeen[p] that p's divergence has been logged.
	partOff      atomic.Pointer[string]
	divergedSeen [partitions]atomic.Bool

	// The start counter (rollback.go): this start's number, the highest number this node has seen each peer publish,
	// whether this node's number is published yet, and whether the running partition protocol started on data this
	// node held as intact (a rollback found later then means it has taken part with a forgotten state).
	starts        atomic.Uint64
	startsMu      sync.Mutex
	peerStarts    map[string]uint64 // guarded by startsMu
	startsShown   atomic.Bool
	startedIntact atomic.Bool

	// staleAfter is the partition protocol's StaleAfter (newManager): how long this node waits to have caught up with
	// a refusal (Store.awaitRefused).
	staleAfter atomic.Int64
	// waiting holds a place for each request waiting in the store (waitSlot): at most maxWaiting at once.
	waiting chan struct{}
	// writing counts the writes of each partition under way from this node (Store.submit): at most maxPartitionWrites.
	writing [partitions]atomic.Int32
	// faults are the faults tests inject (built with the faults tag only: faults.go).
	faults faultHooks
	// tcpDeadline is the gossip transport's TCPDeadline (checked against the partition protocol's need: newManager).
	tcpDeadline time.Duration

	forced      atomic.Pointer[string] // this start was forced (quisora force-start): why
	forceAudit  atomic.Pointer[forceRecord]
	skewWarned  sync.Map // origin -> unix nanos of the last clock-skew warning
	skewed      atomic.Int64
	stateFile   string
	saveMu      sync.Mutex // one saveState at a time
	startedOnce sync.Once
	closeOnce   sync.Once
}

// New builds the node around st. Nothing runs until Start. dataDir persistence (node id, cluster state) is skipped when
// cfg.Server.DataDir is empty.
func New(cfg *config.Config, st store.Store, opt Options) (*Node, error) {
	if hlc.BeforeEpoch(wallNow()) {
		return nil, ErrClockBeforeEpoch
	}
	opt.defaults()
	n := &Node{cfg: cfg, opt: opt, log: opt.Log.WithGroup("cluster"), dir: cfg.Server.DataDir,
		waiting: make(chan struct{}, maxWaiting)}
	n.ctx, n.cancel = context.WithCancel(context.Background())
	if n.dir != "" {
		if err := os.MkdirAll(n.dir, 0o700); err != nil {
			return nil, fmt.Errorf("cluster: data dir: %w", err)
		}
		n.stateFile = filepath.Join(n.dir, "cluster-state.json")
		os.Remove(n.stateFile + ".tmp") // a save a crash cut short: never read, and the next save would replace it
	}
	id, err := loadNodeID(n.dir, cfg.Cluster.NodeID)
	if err != nil {
		return nil, err
	}
	n.id = id
	n.prefix = n.prefixOf(id)
	n.st = &Store{n: n, inner: st}
	n.eph = &Ephemeral{n: n, local: ephemeral.NewLocal(n.prefix)}
	n.eph.local.Budget = int64(cfg.Limits.EphemeralMB) << 20
	n.eph.local.Log = n.log
	n.mem.Store(n.selfOnly())

	if cfg.Cluster.Bind == "" {
		if cfg.SharedStorage() {
			n.shared = ephemeral.NewShared(st)
			n.lease = &lease{st: store.NewTable[model.Ephemeral](st), self: n.id, instance: uuid.NewString()}
			if cfg.Cluster.Notify.Bind != "" {
				if err := n.buildNotify(); err != nil {
					n.eph.local.Close()
					return nil, err
				}
			} else {
				n.log.Info("shared database without cluster.notify: other nodes' changes reach this node's caches within 5 seconds, and its admin pages do not follow them live")
			}
		}
		return n, nil
	}
	if cfg.Cluster.Notify.Bind != "" {
		n.log.Warn("cluster.notify is ignored with cluster.bind: replication delivers every change already")
	}
	if n.pst, err = newPStore(n, st); err != nil {
		n.eph.local.Close()
		return nil, err
	}
	n.loadState()
	if err := n.buildGossip(); err != nil {
		n.eph.local.Close()
		return nil, err
	}
	return n, nil
}

func (n *Node) buildGossip() error {
	cfg := n.cfg
	key, prev, err := decodeClusterKeys(cfg.Cluster.Key, cfg.Cluster.PreviousKeys)
	if err != nil {
		return err
	}
	n.clusterKs = append([]string{cfg.Cluster.Key}, cfg.Cluster.PreviousKeys...)
	adv := cfg.Cluster.Advertise
	if adv == "" {
		adv = cfg.Cluster.Bind
		if host, _, err := net.SplitHostPort(adv); err != nil || host == "" || net.ParseIP(host).IsUnspecified() {
			return errors.New("cluster: cluster.advertise is required when cluster.bind is a wildcard address")
		}
	}
	gcfg := gossip.DefaultConfig()
	gcfg.NodeID = n.id
	gcfg.BindAddr = cfg.Cluster.Bind
	gcfg.AdvertiseAddr = adv
	gcfg.EncryptionKey = key
	gcfg.PreviousEncryptionKeys = prev // a cluster key rotation in progress: they still decrypt, never encrypt
	// A captured packet cannot be replayed later: older (or newer) than this by the receiver's clock it is refused,
	// and until then it is in the duplicate history. A reply carries its request's message id and is taken only as the
	// answer to that request. Far above the clock skew the nodes may have (store.MaxSkew).
	gcfg.MaxPacketAge = 2 * time.Minute
	gcfg.Cipher = aes.New()
	gcfg.MsgCodec = shamaton.New()
	gcfg.Compressor = snappy.New()
	gcfg.Logger = n.opt.Log
	// A request waits for its reply for up to the transport's deadline. A change forwarded to a partition's owner waits
	// up to the protocol's write timeout: with a shorter deadline a change that takes longer (the owner waited for the
	// partition, or for a slow follower) would be reported unknown while the owner commits it. Quisora's own requests
	// (ephemeral operations, clock readings, audit pages, reloads) bound themselves with shorter contexts.
	gcfg.TCPDeadline = transportDeadline(n.partitionConfig())
	// Every request a peer makes of this node (the partition protocol's writes, promises and heartbeats, ephemeral
	// operations) runs on these workers, as do gossip's own pings: the library's 8 would let a few slow disk writes
	// hold up the rest, and a delayed ping makes a healthy node look suspect.
	gcfg.NumIncomingWorkers = 32
	gcfg.NumSendWorkers = 16
	gcfg.IncomingPacketQueueDepth = 4096
	// The partition protocol counts only the nodes gossip holds alive (writes, heartbeats, promises, quorum), so a peer
	// gossip suspects is as good as gone to it: gossip must tolerate the silence ownerTimeout does. Its defaults
	// suspected a peer after 1.5 s without a message and one ping unanswered in 500 ms, which a busy node (saturated
	// CPUs) missed, and the nodes then lost their quorum although every one was up. A ping is sent only after
	// ownerTimeout of silence and gets a second (less than the 2 s health check interval).
	gcfg.SuspectTimeout = ownerTimeout
	gcfg.PingTimeout = time.Second
	gcfg.ApplicationVersion = build.Version // shown per node on the cluster page (compatibility: metaCompat)
	if n.opt.Gossip != nil {
		n.opt.Gossip(gcfg)
	}
	gcfg.Transport = gossip.NewSocketTransport(gcfg)
	if n.opt.transport != nil {
		gcfg.Transport = n.opt.transport(gcfg.Transport)
	}
	others := n.seedPeers()
	n.nodes.Store(int64(cfg.Cluster.Size))
	if n.Size() < 2 {
		return errors.New("cluster: cluster.size is required with cluster.bind (the number of nodes, at least 2)")
	}
	if len(others)+1 != n.Size() {
		return fmt.Errorf("cluster: cluster.size is %d but cluster.peers names %d other nodes (and this one): every "+
			"node lists every other node, and cluster.size counts them all", n.Size(), len(others))
	}
	gc, err := gossip.NewCluster(gcfg)
	if err != nil {
		return fmt.Errorf("cluster: %w", err)
	}
	n.gc = gc
	n.tcpDeadline = gcfg.TCPDeadline
	// The configuration is checked now, not when the node first holds a data set: one the partition protocol cannot run
	// with is refused at start.
	probe, err := partition.New(gc, n.partitionConfig())
	if err != nil {
		return fmt.Errorf("cluster: %w", err)
	}
	if err := n.checkTransport(probe); err != nil {
		return err
	}
	md := gc.LocalMetadata()
	md.SetInt(metaSize, n.Size())
	md.SetInt(metaCompat, compat)
	md.SetInt(metaMinCompat, minCompat)
	md.SetBool(metaReady, false)

	if err := gc.HandleFuncWithReply(msgEph, compatOnlyReply(n.handleEph)); err != nil {
		return err
	}
	if err := gc.HandleFuncWithReply(msgReload, compatOnlyReply(n.handleReload)); err != nil {
		return err
	}
	if err := gc.HandleFuncWithReply(msgAudit, compatOnlyReply(n.handleAudit)); err != nil {
		return err
	}
	if err := gc.HandleFuncWithReply(msgClock, compatOnlyReply(n.handleClock)); err != nil {
		return err
	}
	gc.HandleNodeStateChangeFunc(n.onNodeState)
	gc.HandleNodeMetadataChangeFunc(func(nd *gossip.Node) {
		if nd.ID.String() != n.id { // (this node's own changes are made by rebuild itself)
			n.rebuild()
		}
	})
	return nil
}

// newManager creates the partition Manager for the cluster's current size and this node's data set (not started).
// Nodes of other data sets are ignored by the protocol (Config.ClusterID): nothing passes between them.
func (n *Node) newManager() (*partition.Manager, error) {
	if n.genesis.Load() == nil {
		return nil, errors.New("cluster: no data set") // (joinDataSet starts none before there is one)
	}
	pc := n.partitionConfig()
	n.staleAfter.Store(int64(staleAfter(pc)))
	pm, err := partition.New(n.gc, pc)
	if err != nil {
		return nil, fmt.Errorf("cluster: %w", err)
	}
	if err := n.checkTransport(pm); err != nil {
		return nil, err
	}
	pm.HandleResyncedFunc(n.resynced)
	pm.HandleOwnershipFunc(n.ownerChanged)
	return pm, nil
}

// ownerTimeout is how long a partition's owner may go unheard before the other nodes stop serving their copies of it
// (it is also the protocol's StaleAfter) and one of them takes it over: 5 seconds, as Galera's evs.suspect_timeout. The
// library's default, three heartbeats (1.5 s), lost a cluster whose nodes were busy, not gone: under a flood of password
// sign-ins on saturated CPUs the heartbeats arrived late, the nodes refused reads and stopped being ready although every
// node was up. It bounds how stale a node's answers can be when it is cut off from an owner, the same 5 seconds the
// per-node caches allow a change made elsewhere (oidc cacheTTL, web orgTTL).
const ownerTimeout = 5 * time.Second

// takeoverBackoff is the random pause before a node proposes itself as the owner of a partition whose owner is gone
// (partition.Tuning.BackoffMax; its default would be ownerTimeout): it only spreads the candidates' attempts, which
// their ranks already order, so a lost owner is replaced within about ownerTimeout and this, not twice ownerTimeout.
const takeoverBackoff = 1500 * time.Millisecond

// partitionConfig is the partition protocol's configuration for the cluster's current size and this node's data set.
// The library's defaults stand, Tuning.MaxChangesPerPartition and Tuning.MaxConcurrentCatchUps included: 32 changes of one hot
// partition at once (an organization's sign-ins all go to one owner, one write at a time; more wait a few
// milliseconds and are sent again), and 4 catch-ups at once, which matches the exports a node serves at once
// (exportSlots).
func (n *Node) partitionConfig() partition.Config {
	pc := partition.Config{Partitions: partitions, ClusterSize: n.Size(), Store: n.pst, Logger: n.opt.Log,
		ForceResync: n.forceResync.Load()}
	if g := n.genesis.Load(); g != nil {
		pc.ClusterID = *g
	}
	// Whether this node has formed (it has promised, or synchronised with an intact majority) is kept in
	// cluster-state.json; a new data set forms around the node it was seeded on, whose founder the empty nodes copy.
	pc.Formed, pc.SetFormed = n.formed.Load, n.setFormed
	pc.OwnerTimeout, pc.Tuning.BackoffMax = ownerTimeout, takeoverBackoff
	if n.opt.Partition != nil {
		n.opt.Partition(&pc)
	}
	return pc
}

// transportDeadline is the gossip transport's deadline for a partition protocol configured as pc: its write timeout and
// a heartbeat (partition.Manager.MinTransportDeadline), and a second to spare.
func transportDeadline(pc partition.Config) time.Duration {
	wt, hb := pc.WriteTimeout, pc.HeartbeatInterval
	if wt <= 0 {
		wt = partition.DefaultWriteTimeout
	}
	if hb <= 0 {
		hb = partition.DefaultHeartbeatInterval
	}
	return wt + hb + time.Second
}

// staleAfter is the partition protocol's StaleAfter for a configuration pc (partition.Config's defaulting: the owner
// timeout, else three heartbeats).
func staleAfter(pc partition.Config) time.Duration {
	if pc.StaleAfter > 0 {
		return pc.StaleAfter
	}
	if pc.OwnerTimeout > 0 {
		return pc.OwnerTimeout
	}
	hb := pc.HeartbeatInterval
	if hb <= 0 {
		hb = partition.DefaultHeartbeatInterval
	}
	return 3 * hb
}

// checkTransport refuses a transport deadline shorter than the partition protocol needs: a change forwarded to an owner
// would be reported unknown while the owner commits it.
func (n *Node) checkTransport(pm *partition.Manager) error {
	if need := pm.MinTransportDeadline(); n.tcpDeadline < need {
		return fmt.Errorf("cluster: the gossip transport's deadline (%s) is shorter than the partition protocol's write "+
			"timeout needs (%s): a change forwarded to a partition's owner would be reported unknown while it commits",
			n.tcpDeadline, need)
	}
	return nil
}

// managerStart replaces partition.Manager.Start when set (tests make it fail).
var managerStart atomic.Pointer[func(*partition.Manager) error]

func startManager(pm *partition.Manager) error {
	if f := managerStart.Load(); f != nil {
		return (*f)(pm)
	}
	return pm.Start()
}

// manager returns the running partition Manager (nil without gossip).
func (n *Node) manager() *partition.Manager { return n.pm.Load() }

// ownerChanged notes that this node now believes node owns partition p at epoch (Status), and counts the partitions it
// took over itself.
func (n *Node) ownerChanged(p int, owner gossip.NodeID, epoch partition.Epoch) {
	id := owner.String()
	n.owners[p].Store(&ownerInfo{node: id, epoch: epoch.Counter})
	if id == n.id {
		n.stats.takeovers.Add(1)
	}
}

// seedPeers returns the configured peers other than this node itself. The same peers list is usually given to
// every node, so it names this node too — perhaps by host name while the node advertises an IP address (or the
// reverse). Counting it as another node would make the expected cluster one larger than it is, and a three-node
// cluster could not lose a node. An entry is this node when it has the same port and its host is the advertised
// one, resolves to the same address, or is an address of this machine.
func (n *Node) seedPeers() []string {
	n.seedMu.Lock()
	defer n.seedMu.Unlock()
	if !n.seedsSet {
		n.seeds, n.seedsSet = n.others(n.cfg.Cluster.Peers), true
	}
	return n.seeds
}

// others returns the entries of peers that are not this node (see seedPeers).
func (n *Node) others(peers []string) []string {
	adv := n.cfg.Cluster.Advertise
	if adv == "" {
		adv = n.cfg.Cluster.Bind
	}
	var out []string
	for _, p := range peers {
		if p != "" && !isSelfAddr(p, adv) {
			out = append(out, p)
		}
	}
	return out
}

// isSelfAddr reports whether peer (host:port) names the node advertised as adv (host:port).
func isSelfAddr(peer, adv string) bool {
	if peer == adv {
		return true
	}
	ph, pp, err1 := net.SplitHostPort(peer)
	ah, ap, err2 := net.SplitHostPort(adv)
	if err1 != nil || err2 != nil || pp != ap {
		return false
	}
	if strings.EqualFold(ph, ah) {
		return true
	}
	peerIPs := resolve(ph)
	mine := resolve(ah)
	if ip := net.ParseIP(ah); ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		// a wildcard or loopback advertise address says nothing: compare with this machine's own addresses
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() {
					mine = append(mine, ipn.IP)
				}
			}
		}
		if h, err := os.Hostname(); err == nil && strings.EqualFold(h, ph) {
			return true
		}
	}
	for _, a := range peerIPs {
		for _, b := range mine {
			if a.Equal(b) && !a.IsLoopback() {
				return true
			}
		}
	}
	return false
}

func resolve(host string) []net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	out := make([]net.IP, len(addrs))
	for i, a := range addrs {
		out[i] = a.IP
	}
	return out
}

// Start starts the gossip cluster, joins the configured peers and starts the partition protocol. It fails when
// another member uses the same ephemeral prefix.
func (n *Node) Start(ctx context.Context) error {
	var err error
	if n.gc == nil {
		if n.lease != nil {
			n.startedOnce.Do(func() {
				if err = n.awaitID(ctx); err != nil {
					n.Close()
					return
				}
				if err := n.lease.tick(ctx); err != nil {
					n.log.WithError(err).Warn("housekeeping lease")
				}
				n.checkNoGossip(ctx)
				n.checkDBClock(ctx)
				n.wg.Add(1)
				go n.runLease()
				if n.ngc != nil {
					n.startNotify()
				}
			})
		}
		return err
	}
	n.startedOnce.Do(func() { err = n.start(ctx) })
	return err
}

func (n *Node) start(ctx context.Context) error {
	if len(n.seedPeers()) == 0 {
		// The peers list names only this node (by another name): alone it would be ready and writable after every
		// restart while the others carry on without it.
		return errors.New("cluster: cluster.peers names no other node: every node lists the others")
	}
	n.publishGenesis()
	n.checkOwner(ctx) // a database that belongs to another node is refused before it is served to anyone
	n.markGossip(ctx) // before joining: a mixed set-up is refused from the start
	n.wg.Add(1)
	go n.runGossipMarker()
	n.gc.Start()
	n.rebuild()
	if peers := n.seedPeers(); len(peers) > 0 {
		if err := n.gc.Join(peers); err != nil {
			n.log.WithError(err).Warn("cluster join failed, will retry in the background")
		}
		deadline := time.Now().Add(n.opt.JoinWait)
		for time.Now().Before(deadline) && len(n.mem.Load().routable) < 2 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	n.rebuild()
	if c := n.collision.Load(); c != nil {
		n.Close()
		return fmt.Errorf("%w: %s", ErrPrefixCollision, *c)
	}
	n.awaitMetadata(ctx)
	// Before the partition protocol starts: a node restored in place from a snapshot of itself is found by the start
	// counts its peers remember, and resyncs (rollback.go). Its own count is published only then.
	n.checkRollback()
	n.publishStarts()
	if err := n.joinDataSet(); err != nil {
		n.Close()
		return err
	}
	n.wg.Add(1)
	go n.watchLoop()
	return nil
}

// awaitMetadata waits (a few seconds at most) until every member in view has published its metadata, so that what the
// node reads of them before it starts the partition protocol (the data set they publish: adoptGenesis) is complete.
func (n *Node) awaitMetadata(ctx context.Context) {
	deadline := time.Now().Add(n.opt.JoinWait)
	for time.Now().Before(deadline) {
		n.rebuild()
		complete := true
		for _, mb := range n.mem.Load().all {
			if mb.id != n.id && mb.state == gossip.NodeAlive && (mb.node == nil || mb.node.Metadata == nil || !mb.node.Metadata.Exists(metaCompat)) {
				complete = false
			}
		}
		if complete {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// joinDataSet starts the partition protocol once this node holds a data set: its own (persisted), or, for a node that
// holds none (it started with an empty database), the one the other nodes publish (adoptGenesis), which it then copies
// in resync mode. Until then it waits (Ready says why), and it is called again as the membership changes (watchLoop).
// A node whose database cannot be served (unfit) takes no part at all.
func (n *Node) joinDataSet() error {
	n.pmMu.Lock()
	defer n.pmMu.Unlock()
	if n.pmStarted || n.pmClosed || n.unfit.Load() != nil || !n.adoptGenesis() {
		return nil
	}
	pm, err := n.newManager()
	if err != nil {
		return err
	}
	if err := n.runManager(pm); err != nil {
		return err
	}
	return nil
}

// runManager starts pm and makes it the node's partition protocol (called with pmMu held). A Manager that fails to
// start is not kept: the node runs none, and joinDataSet tries again with a new one.
func (n *Node) runManager(pm *partition.Manager) error {
	n.startedIntact.Store(n.intact.Load())
	pm.SetEligible(n.eligible()) // (before Start: a node with a bad clock never leads, even for a moment)
	if err := startManager(pm); err != nil {
		pm.Stop()
		n.pm.Store(nil)
		n.pmStarted = false
		return fmt.Errorf("cluster: %w", err)
	}
	n.pm.Store(pm)
	n.pmStarted = true
	return nil
}

// restartManager stops the partition protocol and starts it again with the cluster's current size (Resize): the
// protocol carries the size in every message and refuses a peer configured with another, so it is built anew. What the
// node holds stays: only the running state of the protocol is new.
func (n *Node) restartManager() error {
	n.pmMu.Lock()
	defer n.pmMu.Unlock()
	if !n.pmStarted || n.pmClosed {
		return nil // not started yet: joinDataSet builds it for the size of the day
	}
	n.pm.Load().Stop()
	n.pm.Store(nil)
	n.pmStarted = false // until the new one runs: if it cannot be started, joinDataSet tries again
	if n.unfit.Load() != nil {
		return nil // (a node that refuses its database runs no protocol)
	}
	pm, err := n.newManager()
	if err != nil {
		return err
	}
	return n.runManager(pm)
}

// Close stops the partition protocol (handing the partitions this node owns back at once), gossip and the background
// loops. It does not close the store.
func (n *Node) Close() error {
	n.closeOnce.Do(func() {
		n.pmMu.Lock()
		n.pmClosed = true
		if pm := n.manager(); pm != nil {
			pm.Stop()
		}
		n.pmMu.Unlock()
		n.cancel()
		if n.gc != nil {
			n.gc.Stop()
		}
		if n.ngc != nil {
			n.ngc.Stop()
		}
		n.wg.Wait()
		n.eph.local.Close()
	})
	return nil
}

// ID returns the node's id (a UUID).
func (n *Node) ID() string { return n.id }

// Prefix returns the short id embedded in ephemeral ids made on this node.
func (n *Node) Prefix() string { return n.prefix }

// Standalone reports whether this node has no cluster.
func (n *Node) Standalone() bool { return n.gc == nil }

// Store returns the replicated store; it implements store.Store.
func (n *Node) Store() *Store { return n.st }

// Ephemeral returns the owner-routing ephemeral store.
func (n *Node) Ephemeral() *Ephemeral { return n.eph }

// SharedDatabase reports whether this node shares its database with other nodes without gossip (it is not told
// about their writes: caches must stay short).
func (n *Node) SharedDatabase() bool { return n.shared != nil }

// LocalEphemeral is this node's in-memory short-lived state, for its metrics (with a shared database and no gossip the
// state lives in the database, and this holds nothing).
func (n *Node) LocalEphemeral() *ephemeral.Local { return n.eph.local }

// EphemeralStore is the store for short-lived state the application uses: the database when nodes share one without
// gossip (any node can finish what another started), otherwise this node's memory with gossip routing.
func (n *Node) EphemeralStore() ephemeral.Store {
	if n.shared != nil {
		return n.shared
	}
	return n.eph
}

// OnChange registers fn to be called after every local write, every applied replica and every invalidation from
// another node. For an invalidation only rec.Kind and rec.ID are set. fn runs synchronously and must be quick.
func (n *Node) OnChange(fn func(rec *store.Record, local bool)) {
	n.hookMu.Lock()
	defer n.hookMu.Unlock()
	var cur []func(*store.Record, bool)
	if p := n.hooks.Load(); p != nil {
		cur = *p
	}
	next := append(append([]func(*store.Record, bool){}, cur...), fn)
	n.hooks.Store(&next)
}

// fire runs the change hooks for rec and returns the record they were given (a deletion with its scope added).
func (n *Node) fire(rec *store.Record, local bool) *store.Record {
	if rec.Deleted && rec.Scope == "" { // a tombstone has no scope: the hooks get the one noted before (noteScope)
		if v, ok := n.delScopes.LoadAndDelete(scopeKey(rec)); ok {
			cp := *rec
			cp.Scope = v.(string)
			rec = &cp
		}
	}
	if p := n.hooks.Load(); p != nil {
		for _, fn := range *p {
			fn(rec, local)
		}
	}
	return rec
}

// PrefixOf derives the short ephemeral id prefix of a node id: 8 lower-case base32 characters of its hash (no dots).
func PrefixOf(id string) string {
	h := sha256.Sum256([]byte(id))
	return strings.ToLower(base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:5]))
}

// loadNodeID returns the configured node id, else the one persisted in dir, else a new UUIDv7 (persisted).
func loadNodeID(dir, configured string) (string, error) {
	if configured != "" {
		u, err := uuid.Parse(configured)
		if err != nil {
			return "", fmt.Errorf("cluster: node_id must be a UUID: %w", err)
		}
		return u.String(), nil
	}
	if dir == "" {
		return uuid.Must(uuid.NewV7()).String(), nil
	}
	path := filepath.Join(dir, "node_id")
	if b, err := os.ReadFile(path); err == nil {
		if u, err := uuid.Parse(strings.TrimSpace(string(b))); err == nil {
			return u.String(), nil
		}
	}
	id := uuid.Must(uuid.NewV7()).String()
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("cluster: persist node id: %w", err)
	}
	return id, nil
}

// ---- membership ----

type member struct {
	id     string
	prefix string
	seed   uint64
	node   *gossip.Node
	state  gossip.NodeState
	ready  bool // serves (its published metaReady; this node: Ready)
}

// routable reports whether ids owned by or routed to the member are still served (dead nodes' state is lost).
func (m *member) routable() bool { return m.state == gossip.NodeAlive || m.state == gossip.NodeSuspect }

type membership struct {
	self     *member
	all      []*member
	routable []*member // alive or suspect, including self, in a stable order
	byPrefix map[string]*member
	alive    int
}

func hashString(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

func (n *Node) selfOnly() *membership {
	self := &member{id: n.id, prefix: n.prefix, seed: hashString(n.id), state: gossip.NodeAlive, ready: true}
	return &membership{self: self, all: []*member{self}, routable: []*member{self},
		byPrefix: map[string]*member{n.prefix: self}, alive: 1}
}

func (n *Node) prefixOf(id string) string {
	if p, ok := n.prefixes.Load(id); ok {
		return p.(string)
	}
	p := PrefixOf(id)
	if n.opt.prefix != nil {
		p = n.opt.prefix(id)
	}
	n.prefixes.Store(id, p)
	return p
}

// rebuild refreshes the membership snapshot from gossip, re-checks prefix uniqueness, the agreement on cluster.size
// and on the data set, and publishes this node's readiness.
func (n *Node) rebuild() {
	if n.gc == nil {
		return
	}
	n.rebuildMembers()
	// Outside memMu: publishing runs the metadata handlers synchronously, and saving the state writes a file.
	all := n.mem.Load().all
	n.checkGenesis(all)
	n.rememberStarts(all)
	if n.startsShown.Load() {
		n.checkRollback()
	}
	n.syncEligible()
	n.checkPartitions()
	n.publishReady()
}

// eligible reports whether this node may own partitions: not while its clock is off from the others' (it would decide
// whether records are live, and how long an owner has been silent, by a clock the cluster does not keep) or while a
// peer runs a build it cannot work with.
func (n *Node) eligible() bool { return n.clockOff.Load() == nil && n.compatOff.Load() == nil }

// syncEligible tells the partition protocol whether this node may own partitions (Manager.SetEligible): an ineligible
// node steps down from what it leads at once and takes nothing over, but still follows, acknowledges and serves
// catch-up.
func (n *Node) syncEligible() {
	if pm := n.manager(); pm != nil {
		pm.SetEligible(n.eligible())
	}
}

func (n *Node) rebuildMembers() {
	n.memMu.Lock()
	defer n.memMu.Unlock()
	m := &membership{byPrefix: map[string]*member{}}
	var clash, sizes, compats string
	sameSize := 1 // this node, and the alive peers that publish its cluster.size
	for _, nd := range n.gc.Nodes() {
		st := nd.GetObservedState()
		if st == gossip.NodeRemoved || st == gossip.NodeUnknown {
			continue
		}
		id := nd.ID.String()
		mb := &member{id: id, prefix: n.prefixOf(id), seed: hashString(id), node: nd, state: st}
		if id == n.id {
			mb.state, m.self = gossip.NodeAlive, mb
			mb.ready = true // (routing to itself: its own readiness is checked where it matters)
		} else if nd.Metadata != nil {
			mb.ready = nd.Metadata.GetBool(metaReady)
			// (a peer whose metadata has not arrived yet is not judged: it is not ready either, so nothing routes to it)
			if c, cm, known := publishedCompat(nd); known && !compatible(c, cm) && st == gossip.NodeAlive {
				compats = fmt.Sprintf("node %s runs %s, which this build cannot work with (it speaks %d and needs at "+
					"least %d; this build speaks %d and needs at least %d): upgrade one release at a time, every node "+
					"before the next release (see docs/RUNNING.md, \"Upgrading\")", id, nd.ApplicationVersion, c, cm,
					compat, minCompat)
			}
			switch sz := nd.Metadata.GetInt(metaSize); {
			case sz == 0 || st != gossip.NodeAlive:
			case sz == n.Size():
				sameSize++
			default:
				sizes = fmt.Sprintf("node %s has cluster.size %d, this node %d", id, sz, n.Size())
			}
		}
		if other, dup := m.byPrefix[mb.prefix]; dup && other.id != id {
			clash = fmt.Sprintf("nodes %s and %s share prefix %q", other.id, id, mb.prefix)
		}
		m.byPrefix[mb.prefix] = mb
		m.all = append(m.all, mb)
		if mb.routable() {
			m.routable = append(m.routable, mb)
		}
		if mb.state == gossip.NodeAlive {
			m.alive++
		}
	}
	if m.self == nil {
		old := n.selfOnly()
		m.self = old.self
		m.all, m.routable = append(m.all, old.self), append(m.routable, old.self)
		m.byPrefix[n.prefix] = old.self
		m.alive++
	}
	// A stable order lets every node pick the same successor.
	sortMembers(m.routable)
	if clash != "" {
		if n.collision.Load() == nil {
			n.log.Error("ephemeral id prefix collision between cluster members; change a node_id", "detail", clash)
		}
		n.collision.Store(&clash)
	} else {
		n.collision.Store(nil)
	}
	// A node whose cluster.size fewer than a majority of that size share (itself included) while another size is in
	// view is the one configured apart (a reload that reached it alone, a node started with an old configuration): it
	// refuses to serve. The nodes of the majority carry on and log the stranger: the partition protocol ignores a node
	// of another size whatever this check says.
	switch {
	case sizes == "":
		if n.sizeOff.Swap(nil) != nil {
			n.log.Info("every node agrees on cluster.size again")
		}
	case sameSize < n.Quorum():
		why := sizes + ", and fewer than a majority of this node's size share it: every node must be configured with " +
			"the same cluster.size (a change of size is made in every node's configuration, then reloaded on every node " +
			"at once; see docs/REPLICATION.md)"
		if n.sizeOff.Swap(&why) == nil {
			n.log.Error("refusing to serve", "reason", why)
		}
	default:
		if old := n.sizeOff.Swap(nil); old != nil {
			n.log.Info("a majority of the nodes agrees on this node's cluster.size again")
		}
		if n.sizeSeen.Swap(&sizes) == nil {
			n.log.Warn("a node with another cluster.size is in view: the partition protocol ignores it until it is "+
				"configured as the others", "detail", sizes)
		}
	}
	if sizes == "" {
		n.sizeSeen.Store(nil)
	}
	if compats != "" {
		if n.compatOff.Swap(&compats) == nil {
			n.log.Error("refusing to serve", "reason", compats)
		}
	} else if n.compatOff.Swap(nil) != nil {
		n.log.Info("every node runs a compatible build again")
	}
	n.mem.Store(m)
}

// publishReady tells the other nodes whether this node serves (metaReady): only nodes that do own hash-routed
// short-lived state (counters, single-use ids).
func (n *Node) publishReady() {
	if n.gc == nil {
		return
	}
	ok, _ := n.Ready()
	if md := n.gc.LocalMetadata(); md.GetBool(metaReady) != ok {
		md.SetBool(metaReady, ok)
	}
}

func sortMembers(ms []*member) {
	for i := 1; i < len(ms); i++ {
		for j := i; j > 0 && ms[j].id < ms[j-1].id; j-- {
			ms[j], ms[j-1] = ms[j-1], ms[j]
		}
	}
}

func (n *Node) onNodeState(nd *gossip.Node, prev gossip.NodeState) { n.rebuild() }

// otherPeers lists alive peers (not this node).
func (n *Node) otherPeers() []*member {
	m := n.mem.Load()
	out := make([]*member, 0, len(m.routable))
	for _, mb := range m.routable {
		if mb.id != n.id && mb.state == gossip.NodeAlive {
			out = append(out, mb)
		}
	}
	return out
}

// ---- leadership, readiness ----

// IsLeader reports whether this node runs housekeeping: always when standalone, the node holding the lease when nodes
// share a database, and in a gossip cluster the owner of partition 0 (the global data) while it serves it and is
// writable. A node that cannot see a quorum, or that is resynchronising, is never the leader.
func (n *Node) IsLeader() bool {
	if n.gc == nil {
		return n.lease == nil || n.lease.held()
	}
	pm := n.manager()
	return pm != nil && pm.IsOwner(globalPartition) && pm.CanRead(globalPartition) && n.Writable()
}

// quorumOK reports whether this node sees at least a majority of the configured cluster size (itself included).
func (n *Node) quorumOK() bool {
	return n.mem.Load().alive >= n.Quorum()
}

// Quorum is the number of nodes (this one included) that make a majority: cluster.size/2+1 (0 without gossip).
func (n *Node) Quorum() int {
	if s := n.Size(); s > 0 {
		return s/2 + 1
	}
	return 0
}

// Size returns the number of nodes the cluster is made of: cluster.size at start, then as changed by Resize.
func (n *Node) Size() int { return int(n.nodes.Load()) }

// Writable reports whether admin writes and new sign-ins are allowed: standalone, or the partition protocol is ready
// (caught up, not resynchronising), a majority of the cluster is in view and the node is not misconfigured.
func (n *Node) Writable() bool {
	if n.refusal() != "" {
		return false
	}
	if n.gc == nil {
		return true
	}
	pm := n.manager()
	return pm != nil && pm.Ready() && !pm.Resyncing() && n.quorumOK()
}

// refusal says why this node accepts no write at all ("" when it may write something): it is misconfigured or its
// database cannot be served.
func (n *Node) refusal() string {
	for _, p := range []*atomic.Pointer[string]{&n.unfit, &n.otherCluster, &n.mixed, &n.foreign, &n.collision, &n.sizeOff,
		&n.compatOff, &n.clockOff} {
		if m := p.Load(); m != nil {
			return *m
		}
	}
	return ""
}

// allowWrite decides whether a local write may be made now. In a gossip cluster only a node that is ready and sees a
// majority writes (Writable): catching up after a start, resynchronising or cut off from the majority it writes
// nothing that replicates — not even sign-outs. Short-lived state, and in a gossip cluster audit events and queued items
// (localOnly), are node-local and always allowed. A refused write has no effect anywhere (store.ErrUnavailable).
func (n *Node) allowWrite(ctx context.Context, rec *store.Record) error {
	if rec.Kind == model.KindEphemeral || (n.gc != nil && localOnly(rec.Kind)) {
		return nil // node-local: a node records its own audit events and queues its own items whatever its state
	}
	if err := n.fenced(ctx); err != nil {
		return err
	}
	if n.gc == nil {
		return nil
	}
	if why := n.refusal(); why != "" {
		return fmt.Errorf("%w: %s", store.ErrUnavailable, why)
	}
	if n.Writable() {
		return nil
	}
	_, why := n.Ready()
	if why == "" {
		why = "no quorum"
	}
	return fmt.Errorf("%w: %s", store.ErrUnavailable, why)
}

// maxSkew is how far ahead of this node's clock a version from a peer may be: versions come from the writers'
// clocks (hybrid logical clocks), so a peer whose clock is ahead wins concurrent updates and its tombstones are kept
// longer. Further ahead, it is counted and reported, and this node's clock does not follow it (store.Witness; see
// docs/REPLICATION.md, "Clocks").
const maxSkew = store.MaxSkew

// checkSkew counts and logs (at most hourly per origin) a replicated record whose version is well ahead of this
// node's clock.
func (n *Node) checkSkew(rec *store.Record) {
	d := store.Ahead(rec.Version)
	if d < maxSkew {
		return
	}
	n.skewed.Add(1)
	now := time.Now().UnixNano()
	if last, ok := n.skewWarned.Load(rec.Origin); ok && now-last.(int64) < int64(time.Hour) {
		return
	}
	n.skewWarned.Store(rec.Origin, now)
	n.log.Warn("a record from another node is versioned ahead of this node's clock: keep every node's clock in sync "+
		"(NTP)", "origin", rec.Origin, "ahead", d.Round(time.Second).String())
}

// allowRead decides whether a read through the owners may be made now: not before the node is ready, and not while it
// resynchronises (its own copy is then not trustworthy either). store.ErrUnavailable, as a refused write.
func (n *Node) allowRead() error {
	if why := n.refusal(); why != "" {
		return fmt.Errorf("%w: %s", store.ErrUnavailable, why)
	}
	if pm := n.manager(); pm == nil || !pm.Ready() || pm.Resyncing() {
		_, why := n.Ready()
		return fmt.Errorf("%w: %s", store.ErrUnavailable, why)
	}
	return nil
}

// Ready implements web.Health: it is false while this node sees fewer than a majority of the configured cluster
// size, while it resynchronises or catches up after starting, or while it is misconfigured.
func (n *Node) Ready() (bool, string) {
	if m := n.mixed.Load(); m != nil {
		return false, *m
	}
	if m := n.foreign.Load(); m != nil {
		return false, *m
	}
	if m := n.sizeOff.Load(); m != nil {
		return false, *m
	}
	if m := n.compatOff.Load(); m != nil {
		return false, *m
	}
	if m := n.clockOff.Load(); m != nil {
		return false, *m
	}
	if n.gc == nil {
		if n.lease != nil && !n.lease.reachable() {
			return false, "the database is not answering"
		}
		return true, ""
	}
	if c := n.collision.Load(); c != nil {
		return false, "node id prefix collision: " + *c
	}
	if m := n.unfit.Load(); m != nil {
		return false, *m
	}
	if m := n.otherCluster.Load(); m != nil {
		return false, *m
	}
	pm := n.manager()
	switch {
	case pm == nil:
		if w := n.dataSetWait.Load(); w != nil {
			return false, *w
		}
		return false, "starting"
	case pm.Resyncing():
		return false, "resynchronising: this node's data was lost or restored, so it copies it from the other nodes before it takes part"
	case !pm.Ready():
		return false, "catching up with the other nodes after starting"
	case !n.quorumOK():
		return false, fmt.Sprintf("no quorum: %d of the %d nodes visible, %d needed", n.mem.Load().alive, n.Size(), n.Quorum())
	}
	if m := n.partOff.Load(); m != nil {
		return false, *m
	}
	// The global partition (organizations, signing keys) is needed by nearly every request: a node that cannot vouch
	// for it (it has not heard its owner yet after starting, or trails it) serves no sign-in or token, so it takes no
	// traffic. One partition only: another partition's trouble refuses its own records, not the node.
	if err := n.readableWithin(context.Background(), globalPartition, 0); err != nil {
		return false, "the global partition cannot be read here yet: " + strings.TrimPrefix(err.Error(), store.ErrUnavailable.Error()+": ")
	}
	return true, ""
}

// Status is a diagnostic snapshot.
type Status struct {
	NodeID      string `json:"node_id"`
	Prefix      string `json:"-"`
	Standalone  bool   `json:"standalone"`
	Replicating bool   `json:"replicating"`
	Size        int    `json:"size"`   // cluster.size
	Quorum      int    `json:"quorum"` // size/2+1
	Members     int    `json:"members"`
	Alive       int    `json:"alive"`
	Leader      bool   `json:"leader"`
	Ready       bool   `json:"ready"`
	Reason      string `json:"reason,omitempty"` // why it is not ready
	Writable    bool   `json:"writable"`
	// CatchingUp: not ready to take part yet because the node is catching up with (or, Resyncing, copying everything
	// from) the other nodes.
	CatchingUp  bool   `json:"catching_up"`
	Resyncing   bool   `json:"resyncing"`
	ForcedStart string `json:"forced_start,omitempty"` // why this start was forced with "quisora force-start"
	// Refused counts changes the owners refused (a version had moved, a unique value was in use, ...) and Unconfirmed
	// those whose outcome this node does not know (the owner was lost mid-write: the next owner settles them).
	Refused     int64 `json:"refused"`
	Unconfirmed int64 `json:"unconfirmed"`
	// Writes, WritesUnavailable, Reads, ReadsFailed and Takeovers count this node's use of the partition protocol since
	// it started: changes committed, changes that found no owner or no majority, fresh reads asked of owners and those
	// that failed, partitions this node became the owner of.
	Writes            int64 `json:"writes"`
	WritesUnavailable int64 `json:"writes_unavailable"`
	Reads             int64 `json:"reads"`
	ReadsFailed       int64 `json:"reads_failed"`
	Takeovers         int64 `json:"takeovers"`
	// PartitionsOwned is how many partitions this node owns; Partitions has every partition's owner as this node
	// believes it, the owner's epoch and this node's committed sequence number (gossip clusters only).
	PartitionsOwned int               `json:"partitions_owned"`
	Partitions      []PartitionStatus `json:"partitions,omitempty"`
	// PartitionsUnreadable and PartitionsDiverged count the partitions this node cannot serve from its copy now, and
	// those of them found diverged here; Divergences counts the divergences found since the partition protocol started.
	// PartitionsImporting counts those being copied whole to this node (PartitionStatus.Importing).
	PartitionsUnreadable int   `json:"partitions_unreadable"`
	PartitionsDiverged   int   `json:"partitions_diverged"`
	PartitionsImporting  int   `json:"partitions_importing"`
	Divergences          int64 `json:"divergences"`
	// ClockSkewed counts records received with a version more than maxSkew ahead of this node's clock (checkSkew);
	// SkewRefused counts versions this node's clock refused to follow (store.Witness).
	ClockSkewed int64 `json:"clock_skewed"`
	SkewRefused int64 `json:"skew_refused"`
	// ClockOffsetMs is how far the other nodes' clocks are ahead of this one's (the median of their latest readings,
	// milliseconds; negative: behind); on a shared database, the database server's clock. Omitted until a peer or the
	// server has answered.
	ClockOffsetMs *int64 `json:"clock_offset_ms,omitempty"`
	// ClusterKeys are this node's gossip keys (ids), the one that encrypts first (a rotation shows more than one).
	ClusterKeys []string `json:"cluster_keys,omitempty"`
	// Nodes is every cluster member this node knows of, as it sees them (replicated clusters only).
	Nodes []MemberStatus `json:"nodes,omitempty"`
	// DataSet names the data set this node holds (its genesis; "" while it holds none and waits for one).
	DataSet string `json:"data_set,omitempty"`
}

// PartitionStatus is one partition as this node sees it.
type PartitionStatus struct {
	Partition int    `json:"partition"`
	Owner     string `json:"owner,omitempty"` // the node this one last heard take the partition ("": none yet)
	Epoch     uint64 `json:"epoch"`           // the owner's epoch counter
	Committed uint64 `json:"committed"`       // the sequence number of the last write this node applied
	Owned     bool   `json:"owned"`           // this node owns it now
	Promised  uint64 `json:"promised"`        // the highest epoch counter this node has promised
	// Readable: this node serves reads of it from its copy (partition.Manager.CanRead). LagMs is how long it has been
	// behind a committed position the owner reported (milliseconds, 0: not behind), CatchingUp whether a catch-up is
	// running, and Diverged whether its copy was found to hold writes the owner does not have. Importing: a copy of it
	// as a whole has begun here and not finished (its reset emptied it): it is not readable until it finishes.
	Readable   bool  `json:"readable"`
	LagMs      int64 `json:"lag_ms"`
	CatchingUp bool  `json:"catching_up"`
	Diverged   bool  `json:"diverged"`
	Importing  bool  `json:"importing"`
}

// MemberStatus is one cluster member as this node sees it.
type MemberStatus struct {
	ID      string `json:"id"`
	Address string `json:"address,omitempty"` // its advertised gossip address
	State   string `json:"state"`             // alive, suspect, dead or leaving (gossip's view)
	Ready   bool   `json:"ready"`             // serves requests (its published readiness; this node: Ready)
	Leader  bool   `json:"leader"`            // the node that runs housekeeping (owns partition 0)
	Self    bool   `json:"self"`              // the node that answered
	Version string `json:"version,omitempty"` // the Quisora version it runs
	// DataSet is the data set it holds, as it publishes it (nodes of different data sets ignore each other).
	DataSet string `json:"data_set,omitempty"`
}

// members lists the cluster members in id order (gossip clusters only); ready is this node's own readiness.
func (n *Node) members(ready bool) []MemberStatus {
	m := n.mem.Load()
	leader := ""
	if pm := n.manager(); pm != nil {
		if id, ok := pm.Owner(globalPartition); ok {
			leader = id.String()
		}
	}
	out := make([]MemberStatus, 0, len(m.all))
	for _, mb := range m.all {
		ms := MemberStatus{ID: mb.id, State: strings.ToLower(mb.state.String()), Ready: mb.ready, Leader: mb.id == leader,
			Self: mb == m.self}
		nd := mb.node
		if ms.Self {
			ms.Ready = ready
			if nd == nil {
				nd = n.gc.LocalNode()
			}
		}
		if nd != nil {
			ms.Address, ms.Version = nd.AdvertisedAddr(), nd.ApplicationVersion
			if nd.Metadata != nil {
				ms.DataSet = nd.Metadata.GetString(metaGenesis)
			}
			if ms.Address == "" {
				if a := nd.GetAddress(); !a.IsEmpty() {
					ms.Address = a.String()
				}
			}
		}
		out = append(out, ms)
	}
	slices.SortFunc(out, func(a, b MemberStatus) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func (n *Node) Status() Status {
	ready, why := n.Ready()
	pm := n.manager()
	s := Status{NodeID: n.id, Prefix: n.prefix, Standalone: n.gc == nil, Replicating: n.gc != nil, Leader: n.IsLeader(),
		Members: 1, Alive: 1, Ready: ready, Reason: why, Writable: n.Writable(), ForcedStart: n.ForcedStart(),
		Refused: n.stats.refused.Load(), Unconfirmed: n.stats.unknown.Load(), Writes: n.stats.writes.Load(),
		WritesUnavailable: n.stats.unavailable.Load(), Reads: n.stats.reads.Load(), ReadsFailed: n.stats.readFailed.Load(),
		Takeovers: n.stats.takeovers.Load(), ClockSkewed: n.skewed.Load(), SkewRefused: store.SkewRefused()}
	if pm != nil {
		s.CatchingUp, s.Resyncing = !pm.Ready(), pm.Resyncing()
	}
	if n.gc != nil {
		s.ClusterKeys = n.ClusterKeyIDs()
	}
	if off, ok := n.clockOffset(); ok {
		ms := off.Milliseconds()
		s.ClockOffsetMs = &ms
	}
	if g := n.genesis.Load(); g != nil {
		s.DataSet = *g
	}
	if n.gc != nil {
		m := n.mem.Load()
		s.Members, s.Alive, s.Quorum, s.Size = len(m.all), m.alive, n.Quorum(), n.Size()
		s.Nodes = n.members(ready)
		s.Partitions = make([]PartitionStatus, partitions)
		var ms partition.Status
		if pm != nil {
			ms = pm.Status()
			s.Divergences = ms.Divergences
		}
		for p := range partitions {
			ps := PartitionStatus{Partition: p}
			if o := n.owners[p].Load(); o != nil {
				ps.Owner, ps.Epoch = o.node, o.epoch
			}
			if st, err := n.pst.State(p); err == nil {
				ps.Committed, ps.Promised = st.Committed.Seq, st.Promised.Counter
			}
			if p < len(ms.Partitions) {
				mp := ms.Partitions[p]
				ps.Owned, ps.Readable, ps.LagMs, ps.CatchingUp, ps.Diverged = mp.Leading, mp.CanRead, mp.Lag.Milliseconds(),
					mp.CatchingUp, mp.Diverged
			}
			if ps.Owned {
				s.PartitionsOwned++
				ps.Owner = n.id
			}
			if n.pst.isImporting(p) {
				ps.Importing, ps.Readable = true, false
				s.PartitionsImporting++
			}
			if !ps.Readable {
				s.PartitionsUnreadable++
			}
			if ps.Diverged {
				s.PartitionsDiverged++
			}
			s.Partitions[p] = ps
		}
	}
	return s
}

// RunHousekeeping calls fn every interval while this node is the leader, and at once when it becomes the leader,
// until ctx is done. Run it in a goroutine. fn gets a context carrying the tenure (fence): its writes are refused once
// this node no longer leads under it, so a housekeeper that was deposed mid-pass (a hand-back, a takeover) writes
// nothing more; the new leader runs the pass again (every task is idempotent).
func (n *Node) RunHousekeeping(ctx context.Context, interval time.Duration, fn func(context.Context)) {
	poll := min(interval, time.Second) // (a node that becomes the housekeeper starts within a second)
	t := time.NewTicker(poll)
	defer t.Stop()
	var last time.Time
	led := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			leader := n.IsLeader()
			if leader && (!led || time.Since(last) >= interval) {
				last = time.Now()
				fn(n.fence(ctx))
			}
			led = leader
		}
	}
}

// Tenure reports whether this node still holds the tenure ctx (from RunHousekeeping) started under: nil, or an error
// once housekeeping has passed to another node. Work that is not a store write (a request to another system) asks it
// first, as only writes are fenced.
func (n *Node) Tenure(ctx context.Context) error { return n.fenced(ctx) }

// RunPurge purges tombstones and expired records every interval until ctx is done (purgeOnce). Run it in a goroutine.
func (n *Node) RunPurge(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.purgeOnce(ctx, time.Now())
		}
	}
}

// purgeOnce purges what is due. With a node-local store (a gossip node) that is the records that expired, which every
// node removes from its own copy, and the tombstones of the partitions this node owns (purgeTombstones); with a shared
// database only the leader purges, and tombstones are kept an hour.
func (n *Node) purgeOnce(ctx context.Context, now time.Time) {
	if n.gc != nil {
		if _, err := n.st.inner.Purge(ctx, time.Time{}, now); err != nil {
			n.log.WithError(err).Warn("purge failed")
		}
		n.purgeTombstones(ctx, now)
		return
	}
	if !n.IsLeader() {
		return
	}
	if n.lease != nil && n.fenced(n.fence(ctx)) != nil {
		return // the lease passed to another node since: it purges
	}
	// No peer ever needs a tombstone (a shared database is the only copy): keep them an hour, enough for any reader in
	// flight, so used codes and finished sign-ins do not pile up.
	c, err := n.st.inner.Purge(ctx, now.Add(-time.Hour), now)
	if err != nil {
		n.log.WithError(err).Warn("purge failed")
	} else if c > 0 {
		n.log.Debug("purged records", "count", c)
	}
}

func decodeClusterKeys(key string, previous []string) ([]byte, [][]byte, error) {
	k, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(k) != 32 {
		return nil, nil, errors.New("cluster: cluster.key must be 32 bytes, base64 encoded")
	}
	var prev [][]byte
	for i, v := range previous {
		p, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(p) != 32 {
			return nil, nil, fmt.Errorf("cluster: cluster.previous_keys[%d] must be 32 bytes, base64 encoded", i)
		}
		prev = append(prev, p)
	}
	return k, prev, nil
}

// ClusterKeyIDs are the ids (secure.KeyID) of the cluster keys in use, the one that encrypts first; nil standalone.
func (n *Node) ClusterKeyIDs() []string {
	n.keyMu.Lock()
	defer n.keyMu.Unlock()
	var ids []string
	for _, v := range n.clusterKs {
		k, _ := base64.StdEncoding.DecodeString(v)
		ids = append(ids, secure.KeyID(k))
	}
	return ids
}

// SetClusterKeys switches gossip to the cluster keys key (encrypts) and previous (still decrypt) while it runs: a
// cluster key rotation without restarts (docs/RUNNING.md). It refuses keys that do not include the key encrypting now:
// each step of a rotation keeps it (as a previous key until every node encrypts with the new one), and a mistyped key
// would cut this node off from the others. It reports whether anything changed.
func (n *Node) SetClusterKeys(key string, previous []string) (bool, error) {
	if n.gc == nil {
		return false, errors.New("cluster: not clustering (cluster.bind is empty)")
	}
	k, prev, err := decodeClusterKeys(key, previous)
	if err != nil {
		return false, err
	}
	n.keyMu.Lock()
	defer n.keyMu.Unlock()
	next := append([]string{key}, previous...)
	if slices.Equal(next, n.clusterKs) {
		return false, nil
	}
	if !slices.Contains(next, n.clusterKs[0]) {
		cur, _ := base64.StdEncoding.DecodeString(n.clusterKs[0])
		return false, fmt.Errorf("cluster: the new keys do not include the key in use (%s); during a rotation it stays "+
			"in cluster.previous_keys until every node encrypts with the new one", secure.KeyID(cur))
	}
	if err := n.gc.SetEncryptionKeys(k, prev...); err != nil {
		return false, fmt.Errorf("cluster: %w", err)
	}
	n.clusterKs = next
	return true, nil
}

func scopeKey(rec *store.Record) string { return string(rec.Kind) + "\x00" + rec.ID }

// noteScope notes the scope of the record a deletion is about to remove, for the change hooks (see fire). It does
// nothing for other writes, or when the record is not there (nothing to tell anyone about).
func (n *Node) noteScope(ctx context.Context, rec *store.Record) {
	if !rec.Deleted || rec.Scope != "" {
		return
	}
	if cur, err := n.st.inner.Get(ctx, rec.Kind, rec.ID); err == nil && cur.Scope != "" {
		n.delScopes.Store(scopeKey(rec), cur.Scope)
	}
}

// forgetScope drops a noted scope whose deletion was not applied.
func (n *Node) forgetScope(rec *store.Record) {
	if rec.Deleted {
		n.delScopes.Delete(scopeKey(rec))
	}
}
