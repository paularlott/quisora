// Package app wires the configuration, storage, cluster, service and HTTP modules into a running server.
package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/admin"
	"github.com/paularlott/quisora/internal/build"
	"github.com/paularlott/quisora/internal/cluster"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/mail"
	"github.com/paularlott/quisora/internal/metrics"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/oidc"
	"github.com/paularlott/quisora/internal/queue"
	"github.com/paularlott/quisora/internal/secrets"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// App is a running server.
type App struct {
	Cfg    *config.Config
	Log    logger.Logger
	Store  store.Store
	Svc    *service.Service
	Server *web.Server
	Eph    ephemeral.Store
	Node   *cluster.Node
	OIDC   *oidc.Provider
	Admin  *admin.Module

	onChange []func(*store.Record) // cache eviction hooks of modules

	closers []func()
	mailer  *mail.Mailer // nil without an SMTP server
	// logoutQueue holds the back-channel logouts to retry (nil without the OIDC provider).
	// Opened after the background work starts (it needs the OIDC provider), so read atomically.
	logoutQueue atomic.Pointer[queue.Queue[oidc.LogoutRetry]]

	// passes counts the housekeeping passes this node has run as the leader (tests wait for them).
	passes atomic.Int64
	// keyReported is when this node's master key report was last stored (unix nanos; 0: never): the node serves only
	// while it counts (keyReportCurrent).
	keyReported atomic.Int64

	// bg tracks the node's background loops (purging, the start-up audit records, indexing older audit events): Close
	// cancels their context and waits for them before it closes anything they use.
	bg sync.WaitGroup
}

// background runs f on its own goroutine until Close.
func (a *App) background(f func()) {
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		f()
	}()
}

// masterKey returns the configured master key (server.master_key, from the config file, QUISORA_MASTER_KEY or
// --master-key). It is never generated or kept in the data directory: a key on the same volume as the data it seals
// protects nothing from whoever copies that volume.
func masterKey(c *config.Config) ([]byte, error) {
	if c.Server.MasterKey != "" {
		return base64.StdEncoding.DecodeString(c.Server.MasterKey)
	}
	return nil, errors.New("server.master_key is not set: make one with \"quisora genkey\" and set it in the config " +
		"file, QUISORA_MASTER_KEY or --master-key (keep it safe, apart from the data and the backups)")
}

// Start opens everything and starts serving. Stop with Close (or cancel ctx and then Close): it stops the background
// work and waits for it before closing the store.
func Start(ctx context.Context, c *config.Config, log logger.Logger) (*App, error) {
	a := &App{Cfg: c, Log: log}
	for _, setting := range secrets.PlainHTTP(c.Secrets) {
		log.Warn("a secret store is reached over plain http: the keys read from it cross the network unencrypted; "+
			"use https unless the store is on this host", "setting", setting)
	}
	if err := os.MkdirAll(c.Server.DataDir, 0o700); err != nil {
		return nil, err
	}
	key, err := masterKey(c)
	if err != nil {
		return nil, err
	}
	for _, w := range transportWarnings(c) {
		log.Warn("connection without verified TLS: " + w)
	}
	sealer, err := newSealer(c, key)
	if err != nil {
		return nil, err
	}
	if err := checkRestoreIncomplete(c); err != nil {
		return nil, err
	}
	inner, err := OpenStore(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	if err := restoreAtStart(ctx, c, inner, sealer, log); err != nil {
		_ = inner.Close()
		return nil, err
	}
	// The store must have been sealed with this master key (or a previous one of its ring): nodes sharing a database
	// must share the key, and a node's own store (standalone, or each node of a gossip cluster) refuses a key it was
	// not sealed with, instead of serving with every sealed secret unopenable.
	if err := checkSharedKey(ctx, inner, sealer, log, !c.Replicate() && c.SharedStorage()); err != nil {
		_ = inner.Close()
		return nil, err
	}
	node, err := cluster.New(c, inner, cluster.Options{Log: log})
	if err != nil {
		_ = inner.Close()
		return nil, fmt.Errorf("cluster: %w", err)
	}
	a.Node = node
	store.SetOrigin(node.ID())
	a.Store = node.Store()
	a.closers = append(a.closers, func() { _ = a.Store.Close() }, func() { _ = node.Close() })
	a.Eph = node.EphemeralStore()
	if err := node.Start(ctx); err != nil {
		a.Close()
		return nil, fmt.Errorf("cluster: %w", err)
	}

	a.Svc = service.New(c, a.Store, sealer)
	a.Svc.Log = log
	a.closers = append(a.closers, a.Svc.WaitBackground) // closed before the store (closers run in reverse)
	if err := a.setupAudit(c, node, log); err != nil {
		a.Close()
		return nil, err
	}
	// Serving never creates the primary organization ("quisora bootstrap" does): a node that starts without one waits
	// to receive it (a new member of a gossip cluster) or reports that it has not been set up.
	switch _, err := a.Svc.PrimaryOrg(ctx); {
	case errors.Is(err, service.ErrNotFound) && !!node.Standalone():
		log.Warn("this server has not been set up: run \"quisora bootstrap\" to create the primary organization and its first administrator")
	}

	srv, err := web.New(c, a.Svc, a.Eph, log)
	if err != nil {
		a.Close()
		return nil, err
	}
	a.Server = srv
	srv.Bearer = bearer(a.Svc)
	srv.Health = &health{node: node, svc: a.Svc, keyReported: a.keyReportCurrent}
	// The master key this node seals with is reported before anything it seals can be stored (the signing keys made at
	// start-up, below): a rotation's re-sealing waits for every node whose report counts (service.MasterKeyAgreed). A
	// store that refuses now leaves it to the reporting loop, and the node unready until then.
	rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
	if err := a.reportKey(rctx); err != nil {
		log.Warn("master key: this node's key is not reported yet (retried; the node serves once it is)", "error", err)
	}
	rcancel()
	srv.Status = func() any { return readyzStatus(node.Status()) }
	srv.Site.Clustered = !node.Status().Standalone
	a.registerMetrics()
	if c.Mail.Enabled() { // its queue is on disk: messages left by the last run go out now
		if a.mailer, err = mail.New(c, log, sealer, &mail.SMTP{Cfg: c.Mail}); err != nil {
			a.Close()
			return nil, err
		}
		a.closers = append(a.closers, a.mailer.Close)
	}
	// Background work (housekeeping, purges, reports) runs until Close, which cancels it and waits for it: after the
	// server stops taking requests, before the mailer, the audit writer and the store close.
	bg, stop := context.WithCancel(ctx)
	a.closers = append(a.closers, func() { stop(); a.bg.Wait() })
	// Every master key report says how many queued items still need a previous key (re-sealing them first).
	a.Svc.QueuesStale = a.resealQueues
	srv.Use(modules(bg, a)...)
	// Replication is already applying records (node.Start): the hook goes in once what it calls (the modules'
	// caches and their onChange hooks) is built. Until the server starts nothing is cached, so nothing is missed.
	node.OnChange(func(rec *store.Record, local bool) { a.evict(rec) })
	if a.OIDC != nil {
		// Back-channel logouts a relying party did not take are retried from disk, also across restarts.
		q, err := a.OIDC.OpenLogoutQueue(c.DataPath(config.DirLogoutQueue))
		if err != nil {
			a.Close()
			return nil, err
		}
		a.logoutQueue.Store(q)
		metrics.Default.Gauge("quisora_backchannel_logout_queued", "Back-channel logouts waiting to be retried.",
			nil, metrics.Value(func() float64 { return float64(q.Queued()) }))
		// Back-channel logouts still being delivered finish (or go to the retry queue) before the queue, the audit
		// writer, the mailer and the store close (closers run in reverse: after the server has stopped taking requests).
		a.closers = append(a.closers, q.Close, a.OIDC.Wait)
	}
	if err := srv.Start(ctx); err != nil {
		a.Close()
		return nil, err
	}
	a.background(func() { node.RunPurge(bg, 10*time.Minute) })
	a.background(func() { a.auditForcedStart(bg) })
	a.background(func() { a.auditRestore(bg) })
	a.background(func() { a.purgeLostDaily(bg) })
	a.closers = append(a.closers, srv.Stop) // the very first: stop taking requests (draining) before anything else
	return a, nil
}

// auditForcedStart writes a start forced with "quisora force-start" (logged when it happened) to the audit log of the
// primary organization once this node may write: the operator's override is on record in the cluster, not only in
// one node's log. It stays pending in the node's cluster state until the event is stored, across restarts.
func (a *App) auditForcedStart(ctx context.Context) {
	auditForcedStart(ctx, a.Node, a.Svc, time.Second)
}

// forceStartNode is what auditForcedStart needs of the node (cluster.Node).
type forceStartNode interface {
	ID() string
	Writable() bool
	PendingForceStart() (at time.Time, reason string, ok bool)
	ForceStartAudited()
}

func auditForcedStart(ctx context.Context, node forceStartNode, svc *service.Service, poll time.Duration) {
	at, reason, ok := node.PendingForceStart()
	if !ok {
		return
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		if node.Writable() {
			org := model.PrimaryOrgID
			if o, err := svc.PrimaryOrg(ctx); err == nil {
				org = o.ID
			}
			err := svc.AuditStored(service.WithCommand(ctx, "force-start", "access to this node's data directory"),
				service.System, org, "cluster.force_start", node.ID(),
				map[string]string{"reason": reason, "at": at.UTC().Format(time.RFC3339)})
			if err == nil {
				node.ForceStartAudited() // only now: until the event is stored, the record stays (the next start tries again)
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// sharedKeyCheckID names the record in a shared database that holds a check value of the master key.
const sharedKeyCheckID = "master-key-check"

// checkSharedKey refuses to serve from a store sealed with another master key: the first start leaves a check value
// of its key in the store (never the key; node-local short-lived state, so with gossip every node keeps its own), and
// a node with another key stops with an error instead of sealing secrets the others cannot open (and failing to open
// theirs, or its own store's). shared says the store is a database other nodes share.
func checkSharedKey(ctx context.Context, st store.Store, sealer *secure.Sealer, log logger.Logger, shared bool) error {
	var checks [][]byte // one per key of the ring, the active one first
	for _, m := range sealer.MACs("quisora shared master key check") {
		checks = append(checks, []byte(base64.RawURLEncoding.EncodeToString(m[:12])))
	}
	t := store.NewTable[model.Ephemeral](st)
	var e *model.Ephemeral
	for attempt := 0; e == nil; attempt++ {
		got, err := t.Get(ctx, sharedKeyCheckID)
		switch {
		case err == nil:
			e = got
		case !errors.Is(err, store.ErrNotFound):
			return fmt.Errorf("master key check: %w", err)
		case attempt == 3:
			return errors.New("master key check: the check record could not be created or read")
		default: // created here, or concurrently by another node: read it again
			err := t.Create(ctx, &model.Ephemeral{Meta: model.Meta{ID: sharedKeyCheckID}, Value: checks[0]})
			if err != nil && !errors.Is(err, store.ErrStale) {
				return fmt.Errorf("master key check: %w", err)
			}
		}
	}
	i := slices.IndexFunc(checks, func(c []byte) bool { return string(c) == string(e.Value) })
	switch {
	case i < 0 && shared:
		return errors.New("this node's master key differs from the one the other nodes of this shared database use: " +
			"set server.master_key to the same value on every node (and, during a rotation, the same " +
			"server.previous_master_keys)")
	case i < 0:
		return errors.New("server.master_key is not the key this node's data was sealed with: give it that key. To " +
			"change keys, rotate: the old one in server.previous_master_keys (docs/RUNNING.md)")
	case i > 0:
		// A rotation: the database names a previous key of this node's ring. From here on it names the new one, so a
		// node that is still given only the old key refuses to start instead of sealing with it.
		e.Value = checks[0]
		if err := t.Update(ctx, e); err != nil && !errors.Is(err, store.ErrStale) {
			return fmt.Errorf("master key check: %w", err)
		}
		log.Info("master key rotation: this store now expects the new master key", "key", sealer.ActiveKeyID())
	}
	return nil
}

// evict drops per-node caches when a record changes here or on another node.
func (a *App) evict(rec *store.Record) {
	switch rec.Kind {
	case model.KindSession:
		a.Server.Sessions.Evict(rec.ID, "")
	case model.KindUser:
		a.Server.Sessions.Evict("", rec.ID)
	case model.KindOrg:
		a.Server.InvalidateOrgs()
		a.Server.Svc.InvalidateSignOut() // its emergency sign-out counters may have moved
	}
	for _, fn := range a.onChange {
		fn(rec)
	}
}

// Close releases everything in reverse order.
func (a *App) Close() {
	for i := len(a.closers) - 1; i >= 0; i-- {
		a.closers[i]()
	}
	a.closers = nil
}

// readyzCluster is the cluster summary /readyz reports: counts only (it is unauthenticated); the full status is
// GET /api/cluster (super admins).
type readyzCluster struct {
	Size        int   `json:"size,omitempty"`
	Quorum      int   `json:"quorum,omitempty"`
	Alive       int   `json:"alive"`
	Partitions  int   `json:"partitions_owned"`
	Unconfirmed int64 `json:"unconfirmed"`
	Refused     int64 `json:"refused"`
	ClockSkewed int64 `json:"clock_skewed"`
	SkewRefused int64 `json:"skew_refused"`
	// ClockOffsetMs: the other nodes' clocks against this one's (cluster.Status.ClockOffsetMs).
	ClockOffsetMs *int64 `json:"clock_offset_ms,omitempty"`
	// Unreadable and Diverged count the partitions this node cannot serve from its copy, and those of them that
	// diverged here (cluster.Status.PartitionsUnreadable, PartitionsDiverged): which ones, and why, is in GET /api/cluster.
	Unreadable int `json:"partitions_unreadable"`
	Diverged   int `json:"partitions_diverged"`
	Importing  int `json:"partitions_importing"`
}

func readyzStatus(st cluster.Status) readyzCluster {
	return readyzCluster{Size: st.Size, Quorum: st.Quorum, Alive: st.Alive, Partitions: st.PartitionsOwned, Unconfirmed: st.Unconfirmed,
		Refused: st.Refused, ClockSkewed: st.ClockSkewed, SkewRefused: st.SkewRefused, ClockOffsetMs: st.ClockOffsetMs,
		Unreadable: st.PartitionsUnreadable, Diverged: st.PartitionsDiverged, Importing: st.PartitionsImporting}
}

// health is the node's readiness plus one thing only the application knows: that the server has been set up (the
// primary organization exists, made by "quisora bootstrap" or received from the cluster).
type health struct {
	node        *cluster.Node
	svc         *service.Service
	keyReported func() bool // this node's master key report counts (App.keyReportCurrent)
	setUp       atomic.Bool // a primary organization was found: once set up, always (readiness checks it on every request)
}

func (h *health) Ready() (bool, string) {
	if ok, why := h.node.Ready(); !ok {
		return ok, why
	}
	if !h.keyReported() {
		return false, "this node's master key report is not stored (it is retried)"
	}
	if h.setUp.Load() {
		return true, ""
	}
	// Until found, a store read, bounded: a database that hangs makes the node unready, not the probe.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := h.svc.PrimaryOrg(ctx); err != nil {
		if ctx.Err() != nil {
			return false, "the database did not answer"
		}
		return false, "not set up: run \"quisora bootstrap\""
	}
	h.setUp.Store(true)
	return true, ""
}

// newSealer builds the master keyring: key seals; server.previous_master_keys (a rotation in progress) only open
// what they sealed and verify what they MACed.
func newSealer(c *config.Config, key []byte) (*secure.Sealer, error) {
	var prev [][]byte
	for _, v := range c.Server.PreviousMasterKeys {
		k, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("server.previous_master_keys: %w", err)
		}
		prev = append(prev, k)
	}
	return secure.NewKeyring(key, prev...)
}

// registerMetrics adds the gauges read from this node when Prometheus scrapes (metrics.token).
func (a *App) registerMetrics() {
	m := metrics.Default
	m.Gauge("quisora_build_info", "The build: 1, labelled with its version.", []string{"version"},
		func() []metrics.Sample { return []metrics.Sample{{Labels: []string{build.Version}, Value: 1}} })
	st := func(f func(cluster.Status) float64) func() []metrics.Sample {
		return metrics.Value(func() float64 { return f(a.Node.Status()) })
	}
	m.Gauge("quisora_ready", "1 when this node serves (the /readyz answer).", nil, st(func(s cluster.Status) float64 { return metrics.Bool(s.Ready) }))
	m.Gauge("quisora_writable", "1 when this node accepts changes (a quorum is reachable, or standalone).", nil,
		st(func(s cluster.Status) float64 { return metrics.Bool(s.Writable) }))
	m.Gauge("quisora_leader", "1 on the node that runs housekeeping (signing keys, end dates, re-sealing).", nil,
		st(func(s cluster.Status) float64 { return metrics.Bool(s.Leader) }))
	m.Gauge("quisora_cluster_alive_nodes", "Cluster nodes this node sees alive, itself included (1 standalone).", nil,
		st(func(s cluster.Status) float64 { return float64(max(s.Alive, 1)) }))
	m.Gauge("quisora_cluster_size", "cluster.size (0 standalone).", nil, st(func(s cluster.Status) float64 { return float64(s.Size) }))
	m.Gauge("quisora_cluster_quorum", "Nodes needed for a write (0 standalone).", nil, st(func(s cluster.Status) float64 { return float64(s.Quorum) }))
	m.Gauge("quisora_partitions_owned", "Partitions this node owns: it orders their writes and commits each on a majority (0 standalone).", nil,
		st(func(s cluster.Status) float64 { return float64(s.PartitionsOwned) }))
	// Counters since this node started (a gauge each: the figures come from the node, not from a counter this registry owns).
	for _, c := range []struct {
		name, help string
		v          func(cluster.Status) int64
	}{
		{"quisora_partition_writes_total", "Changes this node made that were committed on a majority.", func(s cluster.Status) int64 { return s.Writes }},
		{"quisora_partition_writes_refused_total", "Changes an owner refused: a version had moved, a unique value was in use.", func(s cluster.Status) int64 { return s.Refused }},
		{"quisora_partition_writes_unknown_total", "Changes whose outcome this node does not know (the owner was lost mid-write).", func(s cluster.Status) int64 { return s.Unconfirmed }},
		{"quisora_partition_writes_unavailable_total", "Changes that found no owner or no majority.", func(s cluster.Status) int64 { return s.WritesUnavailable }},
		{"quisora_partition_reads_total", "Fresh reads this node asked the owner of a partition for.", func(s cluster.Status) int64 { return s.Reads }},
		{"quisora_partition_reads_failed_total", "Of those, reads that failed.", func(s cluster.Status) int64 { return s.ReadsFailed }},
		{"quisora_partition_takeovers_total", "Partitions this node became the owner of.", func(s cluster.Status) int64 { return s.Takeovers }},
	} {
		m.Gauge(c.name, c.help, nil, st(func(s cluster.Status) float64 { return float64(c.v(s)) }))
	}
	m.Gauge("quisora_partitions_unreadable", "Partitions this node cannot serve from its copy now (no owner heard, trailing it, diverged).", nil,
		st(func(s cluster.Status) float64 { return float64(s.PartitionsUnreadable) }))
	m.Gauge("quisora_partitions_importing", "Partitions being copied whole to this node (served by none of it until the copy finishes).", nil,
		st(func(s cluster.Status) float64 { return float64(s.PartitionsImporting) }))
	m.Gauge("quisora_partitions_diverged", "Partitions whose copy on this node holds writes their owner does not have (resync the node).", nil,
		st(func(s cluster.Status) float64 { return float64(s.PartitionsDiverged) }))
	m.Gauge("quisora_partition_divergences_total", "Divergences found on this node since its partition protocol started.", nil,
		st(func(s cluster.Status) float64 { return float64(s.Divergences) }))
	// Per partition (gossip clusters only): how far behind its owner this node is, whether it is catching up, diverged.
	perPartition := func(f func(cluster.PartitionStatus) float64) func() []metrics.Sample {
		return func() []metrics.Sample {
			ps := a.Node.Status().Partitions
			out := make([]metrics.Sample, len(ps))
			for i, p := range ps {
				out[i] = metrics.Sample{Labels: []string{strconv.Itoa(p.Partition)}, Value: f(p)}
			}
			return out
		}
	}
	m.Gauge("quisora_partition_lag_seconds", "How long this node has been behind a position the partition's owner reported committed (0: not behind).",
		[]string{"partition"}, perPartition(func(p cluster.PartitionStatus) float64 { return float64(p.LagMs) / 1000 }))
	m.Gauge("quisora_partition_catching_up", "1 while this node is catching the partition up.", []string{"partition"},
		perPartition(func(p cluster.PartitionStatus) float64 { return metrics.Bool(p.CatchingUp) }))
	m.Gauge("quisora_partition_diverged", "1 when the partition diverged on this node.", []string{"partition"},
		perPartition(func(p cluster.PartitionStatus) float64 { return metrics.Bool(p.Diverged) }))
	m.Gauge("quisora_master_key_rotation", "1 while previous master keys are configured (a rotation in progress).", nil,
		metrics.Value(func() float64 { return metrics.Bool(a.Svc.Sealer.Previous()) }))
}
