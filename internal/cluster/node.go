// Package cluster runs one of the two cluster modes and reports readiness.
//
// With cluster.bind (mode 2) the node joins a gossip cluster: every node has its own database and replicates its
// writes to the others, ephemeral state is routed to the node that owns it, and a leader is elected for housekeeping.
//
// Without it (mode 1) there is no gossip. On a database server that several nodes share (PostgreSQL, MySQL, MariaDB,
// Valkey) ephemeral state lives in that database and a lease there picks the housekeeping node; on badger or sqlite
// the node is alone, keeps ephemeral state in memory and always leads.
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
	"github.com/paularlott/gossip/leader"
	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/build"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

var (
	// ErrNotReplicated: a durable write a majority did not acknowledge in time (ackPeers). The write itself was
	// applied locally and still reaches the peers through the broadcast and anti-entropy; Store.Put reports success
	// (counted in Status.Unconfirmed), or store.ErrUnconfirmed with cluster.strict_durability.
	ErrNotReplicated = store.ErrNotReplicated
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

// Compatibility of what nodes exchange (records, change feeds, quorum messages). A build speaks compat and still
// understands peers down to minCompat; two nodes work together only when each one's compat is at least the other's
// minimum. A rolling upgrade from the previous release works when the new build keeps minCompat at the previous
// compat (docs/RUNNING.md, "Upgrading"). Raise compat when what nodes send each other changes; raise minCompat when
// this build no longer understands what the previous compat sent. Builds from before this check publish neither
// (0) and are refused. A node that sees an incompatible peer drops its messages and refuses to serve (Ready) until
// the peer is upgraded or gone, as for a cluster.size mismatch.
const (
	compat    = 1
	minCompat = 1
)

// compatible reports whether a peer speaking peerCompat, which understands down to peerMin, works with this build.
func compatible(peerCompat, peerMin int) bool { return peerCompat >= minCompat && compat >= peerMin }

// peerCompatible reports whether messages from sender may be handled: its published compatibility fits, or it has
// published no metadata yet (a peer still joining).
func peerCompatible(sender *gossip.Node) bool {
	if sender == nil || sender.Metadata == nil {
		return true
	}
	return compatible(sender.Metadata.GetInt(metaCompat), sender.Metadata.GetInt(metaMinCompat))
}

// errIncompatible answers a request from a peer of an incompatible build.
var errIncompatible = errors.New("cluster: the peer runs an incompatible build")

func compatOnly(f gossip.Handler) gossip.Handler {
	return func(sender *gossip.Node, p *gossip.Packet) error {
		if !peerCompatible(sender) {
			return nil
		}
		return f(sender, p)
	}
}

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
	// TombstoneRetention is how long tombstones are kept before they are purged. A node that has not synced for
	// nearly that long (maxDowntime) stops serving, as it may hold records whose deletion is gone. Default 7 days.
	TombstoneRetention time.Duration
	// SyncInterval is how often each peer's change feed is pulled. Default 5 seconds.
	SyncInterval time.Duration
	// PageSize is the number of changes requested per anti-entropy page. Default 500.
	PageSize int
	// JoinWait is how long Start waits for the first peer to appear before carrying on. Default 2 seconds.
	JoinWait time.Duration
	// ForceStart starts a node whose data may be out of date (not synced for longer than the tombstone retention
	// allows, or of unknown age), like the ForceStartMarker file "quisora force-start" leaves (tests set it directly).
	ForceStart bool
	// Gossip and Leader adjust the library configuration before use (tests shorten the failure-detection timings).
	Gossip func(*gossip.Config)
	Leader func(*leader.Config)

	prefix    func(id string) string                  // tests: override PrefixOf to force collisions
	transport func(gossip.Transport) gossip.Transport // tests: wrap the transport (network partitions)
}

func (o *Options) defaults() {
	if o.Log == nil {
		o.Log = logger.NewNullLogger()
	}
	if o.TombstoneRetention <= 0 {
		o.TombstoneRetention = 7 * 24 * time.Hour
	}
	if o.SyncInterval <= 0 {
		o.SyncInterval = 5 * time.Second
	}
	if o.PageSize <= 0 {
		o.PageSize = 1000
	}
	if o.JoinWait <= 0 {
		o.JoinWait = 2 * time.Second
	}
}

// Node is this process's membership of the cluster.
type Node struct {
	cfg    *config.Config
	opt    Options
	log    logger.Logger
	id     string
	prefix string
	dir    string

	gc *gossip.Cluster // nil when standalone
	le *leader.LeaderElection

	keyMu     sync.Mutex
	clusterKs []string // cluster.key, then cluster.previous_keys, as in use (SetClusterKeys)

	replicate bool // data replication on: gossip always replicates (each node has its own database)
	size      int  // cluster.size: the number of nodes the cluster is made of
	quorum    int  // size/2+1: fixed for the life of the process
	seedOnce  sync.Once
	seeds     []string // the configured peers other than this node (seedPeers)

	st  *Store
	eph *Ephemeral

	// Nodes sharing one database without gossip: short-lived state lives in the database and leadership is a lease
	// there (both nil otherwise).
	shared *ephemeral.Shared
	// ngc is the notice gossip of a node sharing its database (cluster.notify; nil otherwise): change notices only.
	ngc         *gossip.Cluster
	notifyPeers []string
	// delScopes holds the scope of a record being deleted (kind/id -> scope) from just before the deletion is
	// applied until the change hooks run: a tombstone carries none, and the hooks need it (which organization's
	// administrators, which user's pages, the notices).
	delScopes sync.Map
	lease     *lease

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mem       atomic.Pointer[membership]
	memMu     sync.Mutex
	prefixes  sync.Map // node id -> prefix
	collision atomic.Pointer[string]
	misconfig atomic.Pointer[string] // gossip peers on one database: not while it lasts (sameDatabase)
	sizeOff   atomic.Pointer[string] // a member advertises another cluster.size: not while it lasts (checkSizes)
	compatOff atomic.Pointer[string] // a member runs an incompatible build: not while it lasts
	sameAs    string                 // the peer that caused misconfig (guarded by peersMu)
	mixed     atomic.Pointer[string] // gossip and non-gossip nodes on one database: not while it lasts (mixedDatabase)
	foreign   atomic.Pointer[string] // the database belongs to another node id: not while it lasts (checkOwner)
	// restored: started on a database restored from a backup (RestoredMarker), until a cluster formed around it;
	// restoredInto: it met peers that already hold data (never merged).
	restored     atomic.Bool
	restoredInto atomic.Pointer[string]
	seeded       sync.Map     // peers that copied this restored node's data as new members
	cutOff       atomic.Int64 // unix nanos since this node stopped being writable (0: writable)

	hooks      atomic.Pointer[[]func(*store.Record, bool)]
	hookMu     sync.Mutex
	onConflict atomic.Pointer[func(*store.Record)]

	// anti-entropy
	peersMu        sync.Mutex
	peers          map[string]*peerState
	trigger        chan struct{}
	lastSync       atomic.Int64           // this node's sync point (persisted.LastSync)
	copiedAt       atomic.Int64           // age of data copied without a sync point (persisted.CopiedAt)
	forced         atomic.Pointer[string] // this start was forced (quisora force-start): why it was needed
	forceAudit     atomic.Pointer[forceRecord]
	preForce       int64    // forced while out of date: the sync point it had (0: not forced out of date)
	skewWarned     sync.Map // origin -> unix nanos of the last clock-skew warning
	skewed         atomic.Int64
	behind         atomic.Pointer[string] // too long without a sync (or a separate bootstrap): not served (setBehind)
	joined         atomic.Bool            // has copied from a peer holding data (persisted.Joined)
	bootstrap      atomic.Bool            // fresh node: has not completed its first full sync
	holdsData      atomic.Bool            // the store holds (or has been sent) a record: it is not empty
	catchingUp     atomic.Bool            // started, and not yet caught up with a majority (peers in caughtUp)
	caughtUp       map[string]bool
	startedEmpty   bool        // the store was empty at start: catching up needs a full quorum of peers
	formed         atomic.Bool // its cluster has formed: never an origin again (persisted.Formed, origin)
	dirty          atomic.Bool
	blindReadiness atomic.Bool  // tests only: readyInView sees no ready node (gossip readiness metadata unavailable)
	refused        atomic.Int64 // records refused from peers (another cluster's bootstrap) and writes peers refused
	superseded     atomic.Int64 // durable pushes a peer did not apply because it held something newer
	unconfirmed    atomic.Int64 // durable writes a majority did not acknowledge in time
	voter          *voter       // quorum compare-and-swap state (gossip only)
	bootRR         atomic.Int64
	stateFile      string
	saveMu         sync.Mutex // one saveState at a time
	startedOnce    sync.Once
	closeOnce      sync.Once
	hadStateFile   bool
}

// New builds the node around st. Nothing runs until Start. dataDir persistence (node id, cursors) is skipped when
// cfg.Server.DataDir is empty.
func New(cfg *config.Config, st store.Store, opt Options) (*Node, error) {
	if hlc.BeforeEpoch(wallNow()) {
		return nil, ErrClockBeforeEpoch
	}
	opt.defaults()
	n := &Node{cfg: cfg, opt: opt, log: opt.Log.WithGroup("cluster"), dir: cfg.Server.DataDir,
		peers: map[string]*peerState{}, caughtUp: map[string]bool{},
		trigger: make(chan struct{}, 1)}
	n.ctx, n.cancel = context.WithCancel(context.Background())
	if n.dir != "" {
		if err := os.MkdirAll(n.dir, 0o700); err != nil {
			return nil, fmt.Errorf("cluster: data dir: %w", err)
		}
		n.stateFile = filepath.Join(n.dir, "cluster-state.json")
	}
	id, err := loadNodeID(n.dir, cfg.Cluster.NodeID)
	if err != nil {
		return nil, err
	}
	n.id = id
	n.prefix = n.prefixOf(id)
	if n.dir != "" && cfg.Cluster.Bind != "" {
		if _, err := os.Stat(filepath.Join(n.dir, RestoredMarker)); err == nil {
			n.restored.Store(true)
		}
	}
	n.replicate = cfg.Replicate()
	n.st = &Store{n: n, inner: st}
	n.eph = &Ephemeral{n: n, local: ephemeral.NewLocal(n.prefix)}
	n.mem.Store(n.selfOnly())

	if cfg.Cluster.Bind == "" {
		if cfg.SharedStorage() {
			n.shared = ephemeral.NewShared(st)
			n.lease = &lease{st: store.NewTable[model.Ephemeral](st), self: n.id}
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
	if err := n.buildGossip(); err != nil {
		n.eph.local.Close()
		return nil, err
	}
	n.loadState()
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
	// and until then it is in the duplicate history. Far above the clock skew the nodes may have (store.MaxSkew).
	gcfg.MaxPacketAge = 2 * time.Minute
	gcfg.Cipher = aes.New()
	gcfg.MsgCodec = shamaton.New()
	gcfg.Compressor = snappy.New()
	gcfg.Logger = n.opt.Log
	gcfg.TCPDeadline = 2 * time.Second
	gcfg.ApplicationVersion = build.Version // shown per node on the cluster page (compatibility: metaCompat)
	if n.opt.Gossip != nil {
		n.opt.Gossip(gcfg)
	}
	gcfg.Transport = gossip.NewSocketTransport(gcfg)
	if n.opt.transport != nil {
		gcfg.Transport = n.opt.transport(gcfg.Transport)
	}
	others := n.seedPeers()
	n.size = cfg.Cluster.Size
	if n.size < 2 {
		return errors.New("cluster: cluster.size is required with cluster.bind (the number of nodes, at least 2)")
	}
	if len(others)+1 != n.size {
		return fmt.Errorf("cluster: cluster.size is %d but cluster.peers names %d other nodes (and this one): every "+
			"node lists every other node, and cluster.size counts them all", n.size, len(others))
	}
	n.quorum = n.size/2 + 1
	gc, err := gossip.NewCluster(gcfg)
	if err != nil {
		return fmt.Errorf("cluster: %w", err)
	}
	n.gc = gc
	md := gc.LocalMetadata()
	md.SetInt(metaSize, n.size)
	md.SetInt(metaCompat, compat)
	md.SetInt(metaMinCompat, minCompat)
	md.SetBool(metaReady, false)

	// The quorum is pinned to the configured size: it never shrinks when nodes leave, stop or restart, so a minority
	// can never reach "quorum" on its own (see docs/REPLICATION.md, "Cluster size and quorum").
	lc := leader.DefaultConfig()
	lc.MinClusterSize = n.quorum
	lc.ExpectedClusterSize = n.size
	lc.AutoShrinkDisabled = true
	if n.opt.Leader != nil {
		n.opt.Leader(lc)
	}
	n.le = leader.NewLeaderElection(gc, lc)
	n.voter = newVoter(n)

	for _, h := range []struct {
		t gossip.MessageType
		f gossip.Handler
	}{{msgRecord, n.handleRecord}, {msgAbort, n.handleAbort}} {
		if err := gc.HandleFunc(h.t, compatOnly(h.f)); err != nil {
			return err
		}
	}
	for _, h := range []struct {
		t gossip.MessageType
		f gossip.ReplyHandler
	}{{msgPush, n.handlePush}, {msgFeed, n.handleFeed}, {msgEph, n.handleEph}, {msgPrepare, n.handlePrepare},
		{msgCommit, n.handleCommit}, {msgRead, n.handleRead}, {msgAudit, n.handleAudit}} {
		if err := gc.HandleFuncWithReply(h.t, compatOnlyReply(h.f)); err != nil {
			return err
		}
	}
	gc.HandleNodeStateChangeFunc(n.onNodeState)
	gc.HandleNodeMetadataChangeFunc(func(nd *gossip.Node) {
		if nd.ID.String() != n.id { // (this node's own changes are made by rebuild itself)
			n.rebuild()
		}
	})
	return nil
}

// seedPeers returns the configured peers other than this node itself. The same peers list is usually given to
// every node, so it names this node too — perhaps by host name while the node advertises an IP address (or the
// reverse). Counting it as another node would make the expected cluster one larger than it is, and a three-node
// cluster could not lose a node. An entry is this node when it has the same port and its host is the advertised
// one, resolves to the same address, or is an address of this machine.
func (n *Node) seedPeers() []string {
	n.seedOnce.Do(func() {
		adv := n.cfg.Cluster.Advertise
		if adv == "" {
			adv = n.cfg.Cluster.Bind
		}
		for _, p := range n.cfg.Cluster.Peers {
			if p != "" && !isSelfAddr(p, adv) {
				n.seeds = append(n.seeds, p)
			}
		}
	})
	return n.seeds
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

// Start starts the gossip cluster, joins the configured peers and begins anti-entropy. It fails when another member
// uses the same ephemeral prefix.
func (n *Node) Start(ctx context.Context) error {
	if n.gc == nil {
		if n.lease != nil {
			n.startedOnce.Do(func() {
				if err := n.lease.tick(ctx); err != nil {
					n.log.WithError(err).Warn("housekeeping lease")
				}
				n.checkNoGossip(ctx)
				n.wg.Add(1)
				go n.runLease()
				if n.ngc != nil {
					n.startNotify()
				}
			})
		}
		return nil
	}
	var err error
	n.startedOnce.Do(func() { err = n.start(ctx) })
	return err
}

func (n *Node) start(ctx context.Context) error {
	if len(n.seedPeers()) == 0 {
		// The peers list names only this node (by another name): alone it would be ready and writable after every
		// restart while the others carry on without it.
		return errors.New("cluster: cluster.peers names no other node: every node lists the others")
	}
	// Every start catches up with a majority before serving: restarts too, not only a fresh node.
	n.catchingUp.Store(n.peersExpected())
	n.startedEmpty = n.bootstrap.Load()
	n.checkOwner(ctx) // a database that belongs to another node is refused before it is served to anyone
	n.markGossip(ctx) // before joining: a mixed set-up is refused from the start
	n.wg.Add(1)
	go n.runGossipMarker()
	n.gc.Start()
	n.le.Start()
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
	n.wg.Add(3)
	go n.syncLoop()
	go n.saveLoop()
	go n.voter.pruneLoop()
	return nil
}

// Close stops gossip and the background loops and saves the cursors. It does not close the store.
func (n *Node) Close() error {
	n.closeOnce.Do(func() {
		n.cancel()
		if n.le != nil {
			n.le.Stop()
		}
		if n.gc != nil {
			n.gc.Stop()
		}
		if n.ngc != nil {
			n.ngc.Stop()
		}
		n.wg.Wait()
		n.saveState()
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

// Replicating reports whether data replication is on (otherwise only invalidations are broadcast).
func (n *Node) Replicating() bool { return n.replicate }

// Store returns the replicated store; it implements store.Store.
func (n *Node) Store() *Store { return n.st }

// Ephemeral returns the owner-routing ephemeral store.
func (n *Node) Ephemeral() *Ephemeral { return n.eph }

// SharedDatabase reports whether this node shares its database with other nodes without gossip (it is not told
// about their writes: caches must stay short).
func (n *Node) SharedDatabase() bool { return n.shared != nil }

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

// OnConflict registers fn to be told about each record that lost a unique-key clash during replication, just before
// it is tombstoned. Every node that resolves the clash calls it, so an audit writer should tolerate duplicates.
func (n *Node) OnConflict(fn func(loser *store.Record)) { n.onConflict.Store(&fn) }

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

// rebuild refreshes the membership snapshot from gossip, re-checks prefix uniqueness and the agreement on
// cluster.size, and publishes this node's readiness.
func (n *Node) rebuild() {
	if n.gc == nil {
		return
	}
	n.rebuildMembers()
	n.publishReady() // (outside memMu: publishing runs the metadata handlers synchronously)
}

func (n *Node) rebuildMembers() {
	n.memMu.Lock()
	defer n.memMu.Unlock()
	m := &membership{byPrefix: map[string]*member{}}
	var clash, sizes, compats string
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
			if c, cm := nd.Metadata.GetInt(metaCompat), nd.Metadata.GetInt(metaMinCompat); !compatible(c, cm) && st == gossip.NodeAlive {
				compats = fmt.Sprintf("node %s runs %s, which this build cannot work with (it speaks %d and needs at "+
					"least %d; this build speaks %d and needs at least %d): upgrade one release at a time, every node "+
					"before the next release (see docs/RUNNING.md, \"Upgrading\")", id, nd.ApplicationVersion, c, cm,
					compat, minCompat)
			}
			if sz := nd.Metadata.GetInt(metaSize); sz != 0 && sz != n.size && st == gossip.NodeAlive {
				sizes = fmt.Sprintf("node %s has cluster.size %d, this node %d: every node must be configured with "+
					"the same cluster.size (a change of size is made on every node, with the whole cluster stopped; "+
					"see docs/REPLICATION.md)", id, sz, n.size)
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
	if sizes != "" {
		if n.sizeOff.Swap(&sizes) == nil {
			n.log.Error("refusing to serve", "reason", sizes)
		}
	} else if n.sizeOff.Swap(nil) != nil {
		n.log.Info("every node agrees on cluster.size again")
	}
	if compats != "" {
		if n.compatOff.Swap(&compats) == nil {
			n.log.Error("refusing to serve", "reason", compats)
		}
	} else if n.compatOff.Swap(nil) != nil {
		n.log.Info("every node runs a compatible build again")
	}
	n.mem.Store(m)
	n.trackWritable()
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
	n.sawQuorumReady()
}

// trackWritable records when this node stopped being writable (rebuild runs on every membership change and every
// sync interval, so the time is accurate to a few seconds).
func (n *Node) trackWritable() {
	if n.Writable() {
		n.cutOff.Store(0)
		return
	}
	n.cutOff.CompareAndSwap(0, time.Now().UnixNano())
}

// ServesTokens reports whether the token, userinfo and introspection endpoints may answer. They keep working on a
// node that cannot accept writes (cut off from the majority) for cluster.minority_grace, so
// applications ride out a short partition; after that they refuse too, because changes made on the majority side
// (a user or client disabled, access removed) cannot reach this node and it would keep honouring what was revoked.
func (n *Node) ServesTokens() bool {
	if n.misconfig.Load() != nil || n.mixed.Load() != nil || n.foreign.Load() != nil || n.restoredInto.Load() != nil ||
		n.behind.Load() != nil || n.sizeOff.Load() != nil || n.compatOff.Load() != nil {
		return false
	}
	if n.gc == nil {
		return true
	}
	if n.catchingUp.Load() || n.bootstrap.Load() {
		// Not yet caught up since it started: its data may predate changes (a user disabled, access removed) made
		// while it was down. The grace below is for a node that was serving and then got cut off.
		return false
	}
	n.trackWritable()
	since := n.cutOff.Load()
	return since == 0 || time.Since(time.Unix(0, since)) < time.Duration(n.cfg.Cluster.MinorityGrace)*time.Second
}

func sortMembers(ms []*member) {
	for i := 1; i < len(ms); i++ {
		for j := i; j > 0 && ms[j].id < ms[j-1].id; j-- {
			ms[j], ms[j-1] = ms[j-1], ms[j]
		}
	}
}

func (n *Node) onNodeState(nd *gossip.Node, prev gossip.NodeState) {
	n.rebuild()
	if nd.GetObservedState() == gossip.NodeAlive && nd.ID.String() != n.id {
		select {
		case n.trigger <- struct{}{}:
		default:
		}
	}
}

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

// peersExpected reports whether this node is configured to be one of several (so it must not act alone).
func (n *Node) peersExpected() bool {
	if n.gc == nil {
		return false
	}
	return len(n.seedPeers()) > 0 || len(n.mem.Load().all) > 1
}

// ---- leadership, readiness ----

// IsLeader reports whether this node is the elected leader (always true when standalone). A node that cannot see a
// quorum, or that is resynchronising, is never the leader.
func (n *Node) IsLeader() bool {
	if n.gc == nil {
		return n.lease == nil || n.lease.held()
	}
	return n.le.IsLeader() && n.Writable()
}

// quorumOK reports whether this node sees at least a majority of the configured cluster size (itself included).
func (n *Node) quorumOK() bool {
	return n.mem.Load().alive >= n.quorum
}

// Quorum is the number of nodes (this one included) that make a majority: cluster.size/2+1 (0 without gossip).
func (n *Node) Quorum() int { return n.quorum }

// Writable reports whether admin writes and new sign-ins are allowed: standalone, or a quorum is visible and the
// node is neither catching up, out of date nor misconfigured.
func (n *Node) Writable() bool {
	if n.misconfig.Load() != nil || n.mixed.Load() != nil || n.foreign.Load() != nil || n.restoredInto.Load() != nil ||
		n.sizeOff.Load() != nil || n.compatOff.Load() != nil {
		return false
	}
	if n.gc == nil {
		return true
	}
	return n.collision.Load() == nil && n.behind.Load() == nil && !n.catchingUp.Load() && !n.bootstrap.Load() &&
		n.quorumOK()
}

// refusal says why this node accepts no write at all ("" when it may write something): its data is out of date
// or it is misconfigured.
func (n *Node) refusal() string {
	for _, p := range []*atomic.Pointer[string]{&n.behind, &n.misconfig, &n.mixed, &n.foreign, &n.restoredInto,
		&n.collision, &n.sizeOff, &n.compatOff} {
		if m := p.Load(); m != nil {
			return *m
		}
	}
	return ""
}

// allowWrite decides whether a local write may be made, and so replicated, now. In a gossip cluster only a node
// that knows its data is current and sees a quorum writes (Writable): catching up after a start, copying for the
// first time, or cut off from the majority, it writes nothing that replicates — not even sign-outs or audit
// entries that replicate. Node-local records (localOnly: short-lived state, audit events) are never replicated and
// always allowed. A refused write has no effect
// anywhere (store.ErrNotWritable).
func (n *Node) allowWrite(ctx context.Context, rec *store.Record) error {
	if rec.Kind == model.KindEphemeral || (n.gc != nil && localOnly(rec.Kind)) {
		return nil
	}
	if n.gc == nil {
		return n.fenced(ctx)
	}
	if why := n.refusal(); why != "" {
		return fmt.Errorf("%w: %s", store.ErrNotWritable, why)
	}
	if n.Writable() {
		return nil
	}
	_, why := n.Ready()
	if why == "" {
		why = "no quorum"
	}
	return fmt.Errorf("%w: %s", store.ErrNotWritable, why)
}

// strict reports whether a write fails unless a majority confirms it (cluster.strict_durability, durable writes).
func (n *Node) strict(ctx context.Context, rec *store.Record) bool {
	return n.gc != nil && n.cfg.Cluster.StrictDurability && store.IsDurable(ctx) && !localOnly(rec.Kind)
}

// canConfirm reports whether enough peers are in view for a majority to confirm a write (ackPeers).
func (n *Node) canConfirm() error {
	need := max(n.quorum-1, 1)
	if got := len(n.otherPeers()); got < need {
		return fmt.Errorf("%d peers reachable, %d must confirm", got, need)
	}
	return nil
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

// Ready implements web.Health: it is false while this node sees fewer than a majority of the last stable cluster
// size, while it resynchronises after a prolonged isolation, or while a fresh node has not finished its first sync.
func (n *Node) Ready() (bool, string) {
	if m := n.misconfig.Load(); m != nil {
		return false, *m
	}
	if m := n.mixed.Load(); m != nil {
		return false, *m
	}
	if m := n.foreign.Load(); m != nil {
		return false, *m
	}
	if m := n.restoredInto.Load(); m != nil {
		return false, *m
	}
	if m := n.sizeOff.Load(); m != nil {
		return false, *m
	}
	if m := n.compatOff.Load(); m != nil {
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
	if m := n.behind.Load(); m != nil {
		return false, *m
	}
	if n.catchingUp.Load() {
		return false, "catching up with the other nodes after starting"
	}
	if !n.quorumOK() {
		return false, fmt.Sprintf("no quorum: %d of the %d nodes visible, %d needed", n.mem.Load().alive, n.size,
			n.quorum)
	}
	if n.bootstrap.Load() && n.peersExpected() {
		return false, "initial synchronisation pending"
	}
	return true, ""
}

// Status is a diagnostic snapshot.
type Status struct {
	NodeID      string    `json:"node_id"`
	Prefix      string    `json:"-"`
	Standalone  bool      `json:"standalone"`
	Replicating bool      `json:"replicating"`
	Size        int       `json:"size"`   // cluster.size
	Quorum      int       `json:"quorum"` // size/2+1
	Members     int       `json:"members"`
	Alive       int       `json:"alive"`
	Leader      bool      `json:"leader"`
	Ready       bool      `json:"ready"`
	Writable    bool      `json:"writable"`
	Behind      bool      `json:"behind"` // refused: the others purged deletions this node never saw
	CatchingUp  bool      `json:"catching_up"`
	LastSync    time.Time `json:"last_sync,omitzero"`
	// SyncPoint is LastSync, or the age of the data this node copied before it had one (zero: unknown).
	SyncPoint   time.Time `json:"sync_point,omitzero"`
	ForcedStart string    `json:"forced_start,omitempty"` // why this start was forced with "quisora force-start"
	// Refused counts records refused from peers and writes peers refused (a quorum write's stale or deleted
	// answers, a durable push a peer did not apply because it held something newer).
	Refused     int64 `json:"refused"`
	Unconfirmed int64 `json:"unconfirmed"` // writes a majority did not confirm in time
	// ClockSkewed counts records received with a version more than maxSkew ahead of this node's clock (checkSkew);
	// SkewRefused counts versions this node's clock refused to follow (store.Witness).
	ClockSkewed int64 `json:"clock_skewed"`
	SkewRefused int64 `json:"skew_refused"`
	// ClusterKeys are this node's gossip keys (ids), the one that encrypts first (a rotation shows more than one).
	ClusterKeys []string `json:"cluster_keys,omitempty"`
	// Nodes is every cluster member this node knows of, as it sees them (replicated clusters only).
	Nodes []MemberStatus `json:"nodes,omitempty"`
}

// MemberStatus is one cluster member as this node sees it.
type MemberStatus struct {
	ID      string `json:"id"`
	Address string `json:"address,omitempty"` // its advertised gossip address
	State   string `json:"state"`             // alive, suspect, dead or leaving (gossip's view)
	Ready   bool   `json:"ready"`             // serves requests (its published readiness; this node: Ready)
	Leader  bool   `json:"leader"`            // the elected housekeeping leader
	Self    bool   `json:"self"`              // the node that answered
	Version string `json:"version,omitempty"` // the Quisora version it runs
}

// members lists the cluster members in id order (gossip clusters only); ready is this node's own readiness.
func (n *Node) members(ready bool) []MemberStatus {
	m := n.mem.Load()
	leader := ""
	if n.le != nil && n.le.HasLeader() {
		leader = n.le.GetLeaderID().String()
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
	ready, _ := n.Ready()
	s := Status{NodeID: n.id, Prefix: n.prefix, Standalone: n.gc == nil, Replicating: n.replicate, Leader: n.IsLeader(),
		Members: 1, Alive: 1, Behind: n.behind.Load() != nil, CatchingUp: n.catchingUp.Load() || n.bootstrap.Load(),
		Refused: n.refused.Load() + n.superseded.Load(), Unconfirmed: n.unconfirmed.Load(), Ready: ready,
		Writable: n.Writable(), ForcedStart: n.ForcedStart(), ClockSkewed: n.skewed.Load(),
		SkewRefused: store.SkewRefused()}
	if n.gc != nil {
		s.ClusterKeys = n.ClusterKeyIDs()
	}
	if t := n.lastSync.Load(); t != 0 {
		s.LastSync = time.Unix(0, t)
	}
	if t := n.syncPoint(); t != 0 {
		s.SyncPoint = time.Unix(0, t)
	}
	if n.gc != nil {
		m := n.mem.Load()
		s.Members, s.Alive, s.Quorum, s.Size = len(m.all), m.alive, n.quorum, n.size
		s.Nodes = n.members(ready)
	}
	return s
}

// RunHousekeeping calls fn every interval while this node is the leader, and at once when it becomes the leader,
// until ctx is done. Run it in a goroutine.
func (n *Node) RunHousekeeping(ctx context.Context, interval time.Duration, fn func(context.Context)) {
	poll := min(interval, 5*time.Second)
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

// purgeOnce purges tombstones and expired records. With a node-local store every node purges its own copy; with a
// shared database only the leader does.
func (n *Node) purgeOnce(ctx context.Context, now time.Time) {
	if n.gc == nil && !n.IsLeader() {
		return
	}
	if n.lease != nil && n.fenced(n.fence(ctx)) != nil {
		return // the lease passed to another node since: it purges
	}
	// Without gossip no peer ever needs a tombstone (a shared database is the only copy): keep them an hour, enough
	// for any reader in flight, so used codes and finished sign-ins do not pile up.
	before := now.Add(-time.Hour)
	if n.gc != nil {
		if n.bootstrap.Load() || n.catchingUp.Load() || n.behind.Load() != nil {
			return // not before this node holds what its peers hold
		}
		// With gossip tombstones are kept for the retention: every node that serves has synced within less than that
		// (maxDowntime), so none can miss a deletion and hand the record back.
		before = now.Add(-n.opt.TombstoneRetention)
	}
	c, err := n.st.inner.Purge(ctx, before, now)
	if err != nil {
		n.log.WithError(err).Warn("purge failed")
	} else if c > 0 {
		n.log.Debug("purged records", "count", c)
	}
}

// RestoredMarker is the file a restore leaves in the data directory: the node starts as one restored from a backup
// (see Node.restored).
const RestoredMarker = "restored-from-backup"

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
