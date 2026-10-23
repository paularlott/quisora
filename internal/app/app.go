// Package app wires the configuration, storage, cluster, service and HTTP modules into a running server.
package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
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
	a.Svc.Writable = node.Writable
	if node.Replicating() {
		a.Svc.MinSuperAdmins = 2 // see service.Service.MinSuperAdmins
	}
	a.closers = append(a.closers, a.Svc.WaitBackground) // closed before the store (closers run in reverse)
	if err := a.setupAudit(c, node, log); err != nil {
		a.Close()
		return nil, err
	}
	// Serving never creates the primary organization ("quisora bootstrap" does): a node that starts without one waits
	// to receive it (a new member of a gossip cluster) or reports that it has not been set up.
	if _, err := a.Svc.PrimaryOrg(ctx); errors.Is(err, service.ErrNotFound) && !node.Replicating() {
		log.Warn("this server has not been set up: run \"quisora bootstrap\" to create the primary organization and its first administrator")
	}

	srv, err := web.New(c, a.Svc, a.Eph, log)
	if err != nil {
		a.Close()
		return nil, err
	}
	a.Server = srv
	srv.Bearer = bearer(a.Svc)
	srv.Health = &health{node: node, svc: a.Svc}
	srv.Writable = node.Writable
	srv.ServesTokens = node.ServesTokens
	srv.Status = func() any { return readyzStatus(node.Status()) }
	srv.Site.Clustered = !node.Status().Standalone
	a.registerMetrics()
	// A record that lost a unique value to another created before it (two nodes accepted the same email address,
	// name...) is kept: the value is removed from it, it is flagged and the change audited (nothing is deleted).
	node.OnConflict(func(loser *store.Record) {
		a.Svc.Background(ctx, func(ctx context.Context) { a.Svc.ResolveUniqueClash(ctx, loser.Kind, loser.ID) })
	})
	if node.SharedDatabase() {
		// No gossip, so no eviction messages from the other nodes: cached sessions are trusted for 5 seconds.
		srv.Sessions.CacheTTL = 5 * time.Second
	}
	node.OnChange(func(rec *store.Record, local bool) { a.evict(rec) })
	if c.Mail.Enabled() { // its queue is on disk: messages left by the last run go out now
		if a.mailer, err = mail.New(c, log, sealer); err != nil {
			a.Close()
			return nil, err
		}
		a.closers = append(a.closers, a.mailer.Close)
	}
	srv.Use(modules(ctx, a)...)
	if err := srv.Start(ctx); err != nil {
		a.Close()
		return nil, err
	}
	bg, stop := context.WithCancel(ctx)
	a.closers = append(a.closers, func() { stop(); a.bg.Wait() }) // the first to run (closers run in reverse)
	a.background(func() { node.RunPurge(bg, 10*time.Minute) })
	a.background(func() { a.auditForcedStart(bg) })
	a.background(func() { a.auditRestore(bg) })
	a.background(func() { refreshAuditIndex(bg, inner, log) })
	a.closers = append(a.closers, srv.Stop) // the very first: stop taking requests (draining) before anything else
	return a, nil
}

// auditForcedStart writes a start forced with "quisora force-start" (logged when it happened) to the audit log of the
// primary organization once this node may write: the operator's override is on record in the cluster, not only in
// one node's log. It stays pending in the node's cluster state until then, across restarts.
func (a *App) auditForcedStart(ctx context.Context) {
	at, reason, ok := a.Node.PendingForceStart()
	if !ok {
		return
	}
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		if a.Node.Writable() {
			org := model.PrimaryOrgID
			if o, err := a.Svc.PrimaryOrg(ctx); err == nil {
				org = o.ID
			}
			a.Svc.Audit(ctx, service.System, org, "cluster.force_start", a.Node.ID(), map[string]string{
				"reason": reason, "at": at.UTC().Format(time.RFC3339)})
			a.Node.ForceStartAudited()
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
	e, err := t.Get(ctx, sharedKeyCheckID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if err := t.Create(ctx, &model.Ephemeral{Meta: model.Meta{ID: sharedKeyCheckID}, Value: checks[0]}); err != nil &&
			!errors.Is(err, store.ErrStale) {
			return fmt.Errorf("master key check: %w", err)
		}
		return checkSharedKey(ctx, st, sealer, logger.NewNullLogger(), shared) // created here or concurrently elsewhere
	case err != nil:
		return fmt.Errorf("master key check: %w", err)
	}
	i := slices.IndexFunc(checks, func(c []byte) bool { return string(c) == string(e.Value) })
	switch {
	case i < 0 && shared:
		return errors.New("this node's master key differs from the one the other nodes of this shared database use: " +
			"set server.master_key to the same value on every node (and, during a rotation, the same " +
			"server.previous_master_keys)")
	case i < 0:
		return errors.New("server.master_key is not the key this node's data was sealed with: give it that key (a " +
			"server that used a generated data_dir/master.key: that file's content). To change keys, rotate: the old " +
			"one in server.previous_master_keys (docs/RUNNING.md)")
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
	Unconfirmed int64 `json:"unconfirmed"`
	Refused     int64 `json:"refused"`
	ClockSkewed int64 `json:"clock_skewed"`
	SkewRefused int64 `json:"skew_refused"`
}

func readyzStatus(st cluster.Status) readyzCluster {
	return readyzCluster{Size: st.Size, Quorum: st.Quorum, Alive: st.Alive, Unconfirmed: st.Unconfirmed,
		Refused: st.Refused, ClockSkewed: st.ClockSkewed, SkewRefused: st.SkewRefused}
}

// health is the node's readiness plus one thing only the application knows: that the server has been set up (the
// primary organization exists, made by "quisora bootstrap" or received from the cluster).
type health struct {
	node *cluster.Node
	svc  *service.Service
}

func (h *health) Ready() (bool, string) {
	if ok, why := h.node.Ready(); !ok {
		return ok, why
	}
	if _, err := h.svc.PrimaryOrg(context.Background()); err != nil { // cached once found
		return false, "not set up: run \"quisora bootstrap\""
	}
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
	m.Gauge("quisora_master_key_rotation", "1 while previous master keys are configured (a rotation in progress).", nil,
		metrics.Value(func() float64 { return metrics.Bool(a.Svc.Sealer.Previous()) }))
}
