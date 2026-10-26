package cluster

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/cluster/clustertest"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/kvstore"
	"github.com/paularlott/quisora/internal/store/memstore"
	"github.com/paularlott/quisora/internal/store/sqlstore"
)

var bg = context.Background()

func testKey() string {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return base64.StdEncoding.EncodeToString(k)
}

// fastOptions are the options of a test node: short timings (clustertest).
func fastOptions() Options {
	return Options{ClockInterval: 300 * time.Millisecond, JoinWait: 3 * time.Second, Gossip: clustertest.Gossip,
		Partition: clustertest.Partition}
}

type tnode struct {
	n    *Node
	dir  string
	addr string
	cfg  *config.Config
	idx  int
}

func (tn *tnode) st() *Store { return tn.n.Store() }

// A backend opens the database of one node, kept in dir: a second call with the same dir opens the same database again
// (the node restarted).
type backend struct {
	name string
	open func(t testing.TB, dir string) store.Store
}

func memBackend() backend {
	return backend{"memory", func(testing.TB, string) store.Store { return memstore.New() }}
}

func badgerBackend() backend {
	return backend{"badgerdb", func(t testing.TB, dir string) store.Store {
		s, err := kvstore.OpenBadger(bg, filepath.Join(dir, "badger"), kvstore.BadgerOptions{NoSync: true})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}}
}

func sqliteBackend() backend {
	return backend{"sqlite", func(t testing.TB, dir string) store.Store {
		s, err := sqlstore.Open(bg, sqlstore.Config{Driver: "sqlite", DSN: filepath.Join(dir, "quisora.db")})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}}
}

var dbCounter atomic.Int64

// serverBackend is a database server (the DSN variable names its admin connection): every node directory gets a
// database of its own, whose DSN is kept in the directory so that a restarted node finds it again.
func serverBackend(driver, env string) backend {
	return backend{driver, func(t testing.TB, dir string) store.Store {
		file := filepath.Join(dir, "dsn")
		b, err := os.ReadFile(file)
		dsn := string(b)
		if err != nil {
			dsn = createDatabase(t, driver, os.Getenv(env), fmt.Sprintf("qsr_c_%s_%d", strings.ReplaceAll(uuid.NewString()[:8], "-", ""),
				dbCounter.Add(1)))
			if err := os.WriteFile(file, []byte(dsn), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		s, err := sqlstore.Open(bg, sqlstore.Config{Driver: driver, DSN: dsn, MaxOpenConns: 8})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}}
}

// createDatabase creates database db through the admin DSN, registers its removal and returns a DSN for it.
func createDatabase(t testing.TB, driver, admin, db string) string {
	t.Helper()
	var sdb *sql.DB
	var err error
	var dsn string
	if driver == "postgres" {
		sdb, err = sql.Open("pgx", admin)
		u, _ := url.Parse(admin)
		u.Path = "/" + db
		dsn = u.String()
	} else {
		cfg, perr := mysql.ParseDSN(admin)
		if perr != nil {
			t.Fatal(perr)
		}
		sdb, err = sql.Open("mysql", cfg.FormatDSN())
		cfg.DBName = db
		dsn = cfg.FormatDSN()
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sdb.Exec("CREATE DATABASE " + db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		defer sdb.Close()
		q := "DROP DATABASE " + db
		if driver == "postgres" {
			q += " WITH (FORCE)"
		}
		if _, err := sdb.Exec(q); err != nil {
			t.Logf("drop %s: %v", db, err)
		}
	})
	return dsn
}

// allBackends are the databases the cluster tests run on: BadgerDB and SQLite always, the servers when their test DSNs
// are set (scripts/test-dbs.sh).
func allBackends() []backend {
	out := []backend{badgerBackend(), sqliteBackend()}
	for _, s := range []struct{ driver, env string }{{"postgres", "QUISORA_TEST_POSTGRES_DSN"},
		{"mysql", "QUISORA_TEST_MYSQL_DSN"}, {"mariadb", "QUISORA_TEST_MARIADB_DSN"}} {
		if os.Getenv(s.env) != "" {
			out = append(out, serverBackend(s.driver, s.env))
		}
	}
	return out
}

// eachBackend runs fn once per database of allBackends.
func eachBackend(t *testing.T, fn func(t *testing.T, b backend)) {
	for _, b := range allBackends() {
		t.Run(b.name, func(t *testing.T) { fn(t, b) })
	}
}

// localBackends are BadgerDB and SQLite only, for the tests that do not depend on the database.
func localBackends() []backend { return []backend{badgerBackend(), sqliteBackend()} }

func eachLocalBackend(t *testing.T, fn func(t *testing.T, b backend)) {
	for _, b := range localBackends() {
		t.Run(b.name, func(t *testing.T) { fn(t, b) })
	}
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
// partition, with both sides cut off from each other), and can drop single message types.
type netsim struct {
	mu     sync.RWMutex
	inner  gossip.Transport
	cut    map[string]bool
	dropTo map[string]map[gossip.MessageType]bool
	holdTo map[string]map[gossip.MessageType]bool // requests sent to a node that never answers (until the caller's context ends)
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

// errUnreachable is a send that never left: a failed dial, which the partition protocol treats as "not sent" (a write
// that gets it is refused as unavailable, not left unconfirmed).
var errUnreachable = &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("netsim: unreachable")}

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

// held reports whether requests of type mt to nd hang (c.hold).
func (ns *netsim) held(nd *gossip.Node, mt gossip.MessageType) bool {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	if nd == nil {
		return false
	}
	a := nd.GetAddress()
	return ns.holdTo[nd.AdvertisedAddr()][mt] || ns.holdTo[a.String()][mt]
}

func (ns *netsim) Send(tt gossip.TransportType, nd *gossip.Node, p *gossip.Packet) error {
	if ns.blocked(nd, p.MessageType) {
		return errUnreachable
	}
	return ns.tr().Send(tt, nd, p)
}

func (ns *netsim) SendWithReply(nd *gossip.Node, p *gossip.Packet) (*gossip.Packet, error) {
	return ns.SendWithReplyContext(context.Background(), nd, p)
}

// OpenStream and SetStreamHandler pass streams (catch-up) through: refused, as packets are, to a node this one is cut
// off from.
func (ns *netsim) OpenStream(ctx context.Context, nd *gossip.Node, p *gossip.Packet) (io.ReadCloser, error) {
	if ns.blocked(nd, p.MessageType) {
		return nil, errUnreachable
	}
	st, ok := ns.tr().(interface {
		OpenStream(context.Context, *gossip.Node, *gossip.Packet) (io.ReadCloser, error)
	})
	if !ok {
		return nil, gossip.ErrStreamsUnsupported
	}
	return st.OpenStream(ctx, nd, p)
}

func (ns *netsim) SetStreamHandler(h func(*gossip.Packet, io.Writer) error) {
	if st, ok := ns.tr().(interface {
		SetStreamHandler(func(*gossip.Packet, io.Writer) error)
	}); ok {
		st.SetStreamHandler(h)
	}
}

// SendWithReplyContext passes the caller's context through (gossip.ContextTransport), as SendWithReply does.
func (ns *netsim) SendWithReplyContext(ctx context.Context, nd *gossip.Node, p *gossip.Packet) (*gossip.Packet, error) {
	if ns.blocked(nd, p.MessageType) {
		return nil, errUnreachable
	}
	if ns.held(nd, p.MessageType) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if ct, ok := ns.tr().(gossip.ContextTransport); ok {
		return ct.SendWithReplyContext(ctx, nd, p)
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

// heal ends every partition and message drop.
func (c *tcluster) heal() {
	for i := range c.addrs {
		ns := c.net(i)
		ns.mu.Lock()
		ns.cut, ns.dropTo, ns.holdTo = map[string]bool{}, map[string]map[gossip.MessageType]bool{}, nil
		ns.mu.Unlock()
	}
}

// drop stops (or restarts) the given message types from node i to node j (one direction).
func (c *tcluster) drop(i, j int, on bool, types ...gossip.MessageType) {
	ns := c.net(i)
	ns.mu.Lock()
	defer ns.mu.Unlock()
	to := c.addrs[j]
	if ns.dropTo[to] == nil {
		ns.dropTo[to] = map[gossip.MessageType]bool{}
	}
	for _, mt := range types {
		ns.dropTo[to][mt] = on
	}
}

// hold makes requests of the given types from node i to node j hang until the caller's context ends (a node that is
// slow, not down), or answer again.
func (c *tcluster) hold(i, j int, on bool, types ...gossip.MessageType) {
	ns := c.net(i)
	ns.mu.Lock()
	defer ns.mu.Unlock()
	to := c.addrs[j]
	if ns.holdTo == nil {
		ns.holdTo = map[string]map[gossip.MessageType]bool{}
	}
	if ns.holdTo[to] == nil {
		ns.holdTo[to] = map[gossip.MessageType]bool{}
	}
	for _, mt := range types {
		ns.holdTo[to][mt] = on
	}
}

// lagBehind makes node i miss what the others write (no write, commit notice or catch-up reaches it) while it stays in
// view, can still send its changes and reads, and hears every heartbeat.
func (c *tcluster) lagBehind(i int, on bool) {
	for j := range c.addrs {
		if j != i {
			c.drop(j, i, on, gossip.PartWriteMsg, gossip.PartCommitMsg, gossip.PartCatchUpMsg)
			c.drop(i, j, on, gossip.PartCatchUpMsg)
		}
	}
}

// partitionMsgs are the partition protocol's message types (a catch-up stream included).
var partitionMsgs = []gossip.MessageType{gossip.PartHeartbeatMsg, gossip.PartPromiseMsg, gossip.PartWriteMsg,
	gossip.PartChangeMsg, gossip.PartStateMsg, gossip.PartCatchUpMsg, gossip.PartRelinquishMsg, gossip.PartCommitMsg,
	gossip.PartClaimMsg, gossip.PartReadMsg}

// seedNewCluster makes an empty store the first node of a new cluster, as "quisora bootstrap" does on a gossip node:
// one record, written as the first write of its partition, and the node state saying that its data is the cluster's.
// Without such a node empty nodes wait (a cluster never forms from empty nodes alone).
func seedNewCluster(t testing.TB, st store.Store, dir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, "cluster-state.json")); err == nil {
		return
	}
	for _, k := range model.Kinds() {
		if n, _ := st.Count(bg, k, ""); n > 0 && k != model.KindEphemeral {
			return // holds data already
		}
	}
	rec := &store.Record{Kind: model.KindLink, ID: "seed", Version: store.Clock.Now(), Scope: "seed", Partition: "seed",
		Data: []byte("{}")}
	if err := st.Put(bg, rec); err != nil {
		t.Fatal(err)
	}
	if err := StartNewCluster(bg, dir, st); err != nil {
		t.Fatal(err)
	}
}

func newTCluster(t testing.TB, size int, mk backend) *tcluster {
	c := &tcluster{t: t, key: testKey(), mk: mk}
	for range size {
		c.addrs = append(c.addrs, clustertest.FreeAddr(t))
	}
	return c
}

// started is a started, ready three-node cluster on b.
func started(t *testing.T, b backend) *tcluster {
	t.Helper()
	c := newTCluster(t, 3, b)
	c.startAll()
	c.waitReady()
	return c
}

// A scenario is a subtest of a suite that shares one cluster (runOn).
type scenario struct {
	name string
	run  func(t *testing.T, c *tcluster)
}

// runOn runs the scenarios as subtests of t, one after another, on the one cluster c, so that they start one cluster
// between them. A scenario leaves the cluster as it found it: healthy (a scenario that stops a node comes last) and its
// variables restored; it writes records, names and values no other scenario uses, and the network is healed after
// each (sub).
func runOn(t *testing.T, c *tcluster, scenarios ...scenario) {
	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) { s.run(t, c.sub(t)) })
	}
}

// sub hands the cluster to subtest t until t ends: its helpers fail t, and at the end the network is healed and the
// cluster handed back. It waits until the cluster is ready.
func (c *tcluster) sub(t *testing.T) *tcluster {
	parent := c.t
	c.t = t
	t.Cleanup(func() { c.heal(); c.t = parent })
	c.waitReady()
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

// build creates node i (not started) on the database in dir ("": a new one).
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
	if m, ok := c.mks[i]; ok {
		mk = m
	}
	st := mk.open(c.t, dir)
	if i == 0 && !c.noSeed {
		seedNewCluster(c.t, st, dir)
	}
	n, err := New(cfg, st, opt)
	if err != nil {
		c.t.Fatal(err)
	}
	return &tnode{n: n, dir: dir, addr: c.addrs[i], cfg: cfg, idx: i}
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

// replace stops node i and starts a new node in its place: a new data directory and database, as after losing the disk.
func (c *tcluster) replace(i int) *tnode {
	c.t.Helper()
	stop(c.nodes[i])
	tn := c.build(i, "", nil)
	c.nodes[i] = tn
	c.start(tn)
	return tn
}

// restart stops node i and starts it again on the same database and data directory.
func (c *tcluster) restart(i int) *tnode {
	c.t.Helper()
	old := c.nodes[i]
	stop(old)
	tn := c.build(i, old.dir, nil)
	c.nodes[i] = tn
	c.start(tn)
	return tn
}

// restartAll stops every node and starts them again on the same data directories, all at once.
func (c *tcluster) restartAll(between func()) {
	c.t.Helper()
	dirs := make([]string, len(c.nodes))
	for i, tn := range c.nodes {
		dirs[i] = tn.dir
		stop(tn)
	}
	if between != nil {
		between()
	}
	for i := range c.nodes {
		c.nodes[i] = c.build(i, dirs[i], nil)
	}
	c.start(c.nodes...)
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

// asked runs op, again while the node refuses it for not being able to vouch for its copy now (store.ErrNotWritable),
// as a client told to retry (503) would: a node starved of CPU (a loaded test run) can go longer than the test timings'
// StaleAfter (300 ms) without hearing a partition's owner, and refuses until it does. Any other answer, or the refusal
// after 10 s, is op's.
func asked(op func() error) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := op()
		if !errors.Is(err, store.ErrNotWritable) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// consistently fails the test unless cond holds at every look over d: for a check that something does not happen,
// where a single look after a sleep would pass whether or not the thing could have happened yet.
func consistently(t testing.TB, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if !cond() {
			t.Fatalf("%s: stopped holding", what)
		}
		if !time.Now().Before(deadline) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// waitReady waits until every node given (default: all) reports Ready.
func (c *tcluster) waitReady(nodes ...*tnode) {
	c.t.Helper()
	if len(nodes) == 0 {
		nodes = c.nodes
	}
	waitFor(c.t, 30*time.Second, "cluster ready", func() bool {
		for _, tn := range nodes {
			if ok, _ := tn.n.Ready(); !ok {
				return false
			}
		}
		return true
	})
}

// waitOwners waits until every node in view of the others knows an owner for every partition it can write.
func (c *tcluster) waitOwners(nodes ...*tnode) {
	c.t.Helper()
	if len(nodes) == 0 {
		nodes = c.nodes
	}
	waitFor(c.t, 30*time.Second, "partition owners", func() bool {
		for _, tn := range nodes {
			pm := tn.n.manager()
			for p := range partitions {
				if _, ok := pm.Owner(p); !ok {
					return false
				}
			}
		}
		return true
	})
}

// waitSettled waits until the partitions are spread over the nodes (each owns some) and their owners have not changed
// for half a second: right after the nodes become ready, the first one ready can own them all for a moment, until the
// others take theirs.
func (c *tcluster) waitSettled() {
	c.t.Helper()
	owners := func() (out [partitions]int, spread bool) {
		owns := make([]int, len(c.nodes))
		for p := range partitions {
			out[p] = -1
			for i, tn := range c.nodes {
				if pm := tn.n.manager(); pm != nil && pm.IsOwner(p) {
					out[p] = i
					owns[i]++
				}
			}
		}
		for _, n := range owns {
			if n == 0 {
				return out, false
			}
		}
		return out, true
	}
	var last [partitions]int
	var since time.Time
	waitFor(c.t, 30*time.Second, "the partitions spread over the nodes, and stable", func() bool {
		cur, spread := owners()
		if !spread || cur != last {
			last, since = cur, time.Now()
			return false
		}
		return time.Since(since) >= 500*time.Millisecond
	})
}

// ownerOf returns the index of the node that owns partition p (as every node agrees), waiting for one.
func (c *tcluster) ownerOf(p int) int {
	c.t.Helper()
	idx := -1
	waitFor(c.t, 20*time.Second, "an owner of partition "+fmt.Sprint(p), func() bool {
		idx = -1
		for i, tn := range c.nodes {
			if pm := tn.n.manager(); pm != nil && pm.IsOwner(p) {
				idx = i
			}
		}
		return idx >= 0
	})
	return idx
}

// orgOwnedBy returns an organization whose partition node i owns, once the ownership has settled.
func (c *tcluster) orgOwnedBy(i int) string {
	c.t.Helper()
	c.waitSettled()
	for k := range 1000 {
		org := fmt.Sprintf("org-%d", k)
		if partitionNum(org) != 0 && c.ownerOf(partitionNum(org)) == i {
			return org
		}
	}
	c.t.Fatal("no organization whose partition the node owns")
	return ""
}

// orgOwnedBy returns an organization id whose partition node i does not own and the index of the node that does, once
// the ownership has settled.
func (c *tcluster) orgNotOwnedBy(i int) (org string, owner int) {
	c.t.Helper()
	c.waitSettled()
	for k := range 1000 {
		org = fmt.Sprintf("org-%d", k)
		if owner = c.ownerOf(partitionNum(org)); owner != i {
			return org, owner
		}
	}
	c.t.Fatal("no organization whose partition another node owns")
	return "", 0
}

func (c *tcluster) member(from, to int) *member {
	return c.nodes[from].n.mem.Load().byPrefix[c.nodes[to].n.Prefix()]
}

// dataKind is the kind of the plain data records the tests write (newRec): organization data, so its partition is
// that of the organization "org1".
const dataKind = model.KindIdentity

func newRec(id, uniq string) *store.Record {
	r := &store.Record{Kind: dataKind, ID: id, Version: store.Clock.Now(), Scope: "org1", Partition: "org1",
		Fields: map[string]any{"display_name": "group " + id, "created": time.Now().UTC().Truncate(time.Microsecond), "n": int64(7), "b": true},
		Data:   []byte("data-" + id)}
	if uniq != "" {
		r.Unique = []string{uniq}
	}
	return r
}

// newOrgRec is a new record of dataKind in the partition of the organization org.
func newOrgRec(org string) *store.Record {
	r := newRec(newID(), "")
	r.Scope, r.Partition = org, org
	return r
}

func newID() string { return uuid.Must(uuid.NewV7()).String() }

// has reports whether the database behind s holds the live record id: what the node holds, whether or not it can vouch
// for it now (a node's cluster store refuses the reads of a partition it cannot read: the staleness gate).
func has(s store.Store, id string) bool {
	if cs, ok := s.(*Store); ok {
		s = cs.inner
	}
	_, err := s.Get(bg, dataKind, id)
	return err == nil
}

// waitHas waits until every node's copy holds the record id.
func (c *tcluster) waitHas(id string, nodes ...*tnode) {
	c.t.Helper()
	if len(nodes) == 0 {
		nodes = c.nodes
	}
	waitFor(c.t, 20*time.Second, "record "+id+" on every node", func() bool {
		for _, tn := range nodes {
			if !has(tn.st(), id) {
				return false
			}
		}
		return true
	})
}

// waitUser waits until every node holds the user and ok accepts it.
func (c *tcluster) waitUser(t *testing.T, id string, ok func(u *model.User) bool) {
	t.Helper()
	waitFor(t, 15*time.Second, "user "+id+" everywhere", func() bool {
		for _, tn := range c.nodes {
			u, err := users(tn).Get(bg, id)
			if err != nil || !ok(u) {
				return false
			}
		}
		return true
	})
}

// waitVersion waits until every node holds the record kind/id at version v.
func (c *tcluster) waitVersion(t *testing.T, kind model.Kind, id string, v hlc.Timestamp) {
	t.Helper()
	waitFor(t, 15*time.Second, "version of "+id+" everywhere", func() bool {
		for _, tn := range c.nodes {
			if r, err := tn.st().Get(bg, kind, id); err != nil || r.Version != v {
				return false
			}
		}
		return true
	})
}

// writeN writes n records of org with ids newID() through tn and returns the ids.
func writeN(t testing.TB, tn *tnode, org string, n int) []string {
	t.Helper()
	ids := make([]string, n)
	for i := range ids {
		r := newOrgRec(org)
		if err := tn.st().Put(bg, r); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		ids[i] = r.ID
	}
	return ids
}

// putRetrying writes rec through tn and returns its id, trying again for as long as the node refuses it with nothing
// written (store.ErrNotWritable: a partition that has no owner yet, a node still catching up, a takeover under way) or
// the outcome is not known (store.ErrUnconfirmed: settled once or never, and written whole again), up to a generous
// deadline.
func putRetrying(t testing.TB, tn *tnode, rec *store.Record) string {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		err := tn.st().Put(bg, rec)
		if err == nil {
			return rec.ID
		}
		if !errors.Is(err, store.ErrNotWritable) && !errors.Is(err, store.ErrUnconfirmed) || time.Now().After(deadline) {
			t.Fatalf("put on node %d: %v", tn.idx, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func allHold(nodes []*tnode, ids []string) bool {
	for _, tn := range nodes {
		for _, id := range ids {
			if !has(tn.st(), id) {
				return false
			}
		}
	}
	return true
}

// committedEqual reports whether every node has committed the same writes of every partition.
func committedEqual(nodes []*tnode) bool {
	for p := range partitions {
		var seq uint64
		for i, tn := range nodes {
			st, _ := tn.n.pst.State(p)
			if i == 0 {
				seq = st.Committed.Seq
			} else if st.Committed.Seq != seq {
				return false
			}
		}
	}
	return true
}

// Every node holds the same records of dataKind in the same versions.
func sameData(nodes []*tnode) bool {
	var ref map[string]*store.Record
	for i, tn := range nodes {
		res, err := tn.st().List(bg, dataKind, store.ListQuery{})
		if err != nil {
			return false
		}
		m := map[string]*store.Record{}
		for _, r := range res.Records {
			m[r.ID] = r
		}
		if i == 0 {
			ref = m
			continue
		}
		if len(m) != len(ref) {
			return false
		}
		for id, r := range ref {
			if o := m[id]; o == nil || o.Version != r.Version || string(o.Data) != string(r.Data) {
				return false
			}
		}
	}
	return true
}

// copyTree copies a file or a directory tree.
func copyTree(from, to string) error {
	info, err := os.Stat(from)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		b, err := os.ReadFile(from)
		if err != nil {
			return err
		}
		return os.WriteFile(to, b, info.Mode())
	}
	if err := os.MkdirAll(to, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(from)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := copyTree(filepath.Join(from, e.Name()), filepath.Join(to, e.Name())); err != nil {
			return err
		}
	}
	return nil
}
