// Package app wires the configuration, storage, cluster, service and HTTP modules into a running server.
package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/admin"
	"github.com/paularlott/quisora/internal/cluster"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
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
}

// masterKey returns the configured master key, or (standalone only) one generated and kept in the data directory.
func masterKey(c *config.Config) ([]byte, error) {
	if c.Server.MasterKey != "" {
		return base64.StdEncoding.DecodeString(c.Server.MasterKey)
	}
	path := filepath.Join(c.Server.DataDir, "master.key")
	if b, err := os.ReadFile(path); err == nil {
		return base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	}
	if err := os.MkdirAll(c.Server.DataDir, 0o700); err != nil {
		return nil, err
	}
	k := secure.RandomBytes(32)
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(k)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

// Start opens everything and starts serving. Stop with Close (or cancel ctx and then Close).
func Start(ctx context.Context, c *config.Config, log logger.Logger) (*App, error) {
	a := &App{Cfg: c, Log: log}
	if err := os.MkdirAll(c.Server.DataDir, 0o700); err != nil {
		return nil, err
	}
	getKey := masterKey
	if c.Server.RestoreFrom != "" {
		getKey = existingMasterKey // a restore needs the backup's key: a freshly generated one cannot open it
	}
	key, err := getKey(c)
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
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
	if !c.Replicate() && c.SharedStorage() {
		// Nodes sharing a database must share the master key too, or each seals secrets the others cannot open.
		if err := checkSharedKey(ctx, inner, sealer, c.Server.MasterKey != "", log); err != nil {
			_ = inner.Close()
			return nil, err
		}
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
	// A record that lost a unique value to another created before it (two nodes accepted the same email address,
	// name...) is kept: the value is removed from it, it is flagged and the change audited (nothing is deleted).
	node.OnConflict(func(loser *store.Record) {
		go a.Svc.ResolveUniqueClash(context.WithoutCancel(ctx), loser.Kind, loser.ID)
	})
	if node.SharedDatabase() {
		// No gossip, so no eviction messages from the other nodes: cached sessions are trusted for 5 seconds.
		srv.Sessions.CacheTTL = 5 * time.Second
	}
	node.OnChange(func(rec *store.Record, local bool) { a.evict(rec) })
	srv.Use(modules(ctx, a)...)
	if err := srv.Start(ctx); err != nil {
		a.Close()
		return nil, err
	}
	go node.RunPurge(ctx, 10*time.Minute)
	go a.auditForcedStart(ctx)
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

// checkSharedKey refuses to serve from a shared database whose nodes use different master keys: the first node to
// start leaves a check value of its key in the database (never the key), and a node with another key stops with an
// error instead of sealing secrets the others cannot open (and failing to open theirs).
func checkSharedKey(ctx context.Context, st store.Store, sealer *secure.Sealer, configured bool, log logger.Logger) error {
	if !configured {
		log.Warn("server.master_key is not set: with a shared database every node must be given the same key " +
			"(quisora genkey); this node uses the one generated in its data directory")
	}
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
		return checkSharedKey(ctx, st, sealer, true, logger.NewNullLogger()) // created here or concurrently elsewhere
	case err != nil:
		return fmt.Errorf("master key check: %w", err)
	}
	i := slices.IndexFunc(checks, func(c []byte) bool { return string(c) == string(e.Value) })
	switch {
	case i < 0:
		return errors.New("this node's master key differs from the one the other nodes of this shared database use: " +
			"set server.master_key to the same value on every node (and, during a rotation, the same " +
			"server.previous_master_keys)")
	case i > 0:
		// A rotation: the database names a previous key of this node's ring. From here on it names the new one, so a
		// node that is still given only the old key refuses to start instead of sealing with it.
		e.Value = checks[0]
		if err := t.Update(ctx, e); err != nil && !errors.Is(err, store.ErrStale) {
			return fmt.Errorf("master key check: %w", err)
		}
		log.Info("master key rotation: this shared database now expects the new master key", "key", sealer.ActiveKeyID())
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
// GET /api/v1/cluster (super admins).
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
