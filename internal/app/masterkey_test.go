package app

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/cluster/clustertest"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/mail"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// rotNode is one server of the rotation test, restartable with other keys on the same data directory.
type rotNode struct {
	cfg    *config.Config
	app    *App
	cancel context.CancelFunc
}

func (n *rotNode) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	a, err := Start(ctx, n.cfg, logger.NewNullLogger())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	n.app, n.cancel = a, cancel
	t.Cleanup(func() { cancel(); a.Close() })
}

func (n *rotNode) restart(t *testing.T, master string, previous ...string) {
	t.Helper()
	n.cancel()
	n.app.Close()
	n.cfg.Server.MasterKey, n.cfg.Server.PreviousMasterKeys = master, previous
	n.start(t)
}

// reload switches the running node to the keys, as SIGHUP does.
func (n *rotNode) reload(t *testing.T, master string, previous ...string) {
	t.Helper()
	if err := n.app.ReloadMasterKeys(context.Background(), master, previous); err != nil {
		t.Fatal(err)
	}
}

// A master key rotation on a three-node gossip cluster of complete servers, done as documented (docs/RUNNING.md,
// "Rotating the master key"), each node switched to the next step's keys in place as SIGHUP does (and node 0
// restarted instead, once, mid-rotation), with the housekeeping leader doing the re-seal by itself; the status
// (RotationStatus, GET /api/master-key) says where the rotation stands at each step. Halfway through step 3 the leader
// waits, whichever node it is; once every node seals with the new key it re-seals every secret, on every node; and with
// the old key then removed everywhere, every secret still opens, on every node, none opens with the old key, and a
// re-seal pass on another node finds nothing left.
func TestGossipMasterKeyRotation(t *testing.T) {
	saved := housekeepingEvery
	housekeepingEvery = time.Second
	t.Cleanup(func() { housekeepingEvery = saved })

	k0, k1 := secure.RandomBytes(32), secure.RandomBytes(32)
	b64 := base64.StdEncoding.EncodeToString
	addrs := []string{clustertest.FreeAddr(t), clustertest.FreeAddr(t), clustertest.FreeAddr(t)}
	ckey := b64(secure.RandomBytes(32))
	var nodes []*rotNode
	var publicURL string
	for i := range addrs {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listen := ln.Addr().String()
		ln.Close()
		c := config.Default()
		c.Server.Listen, c.Server.DataDir, c.Storage.Backend = listen, t.TempDir(), "badgerdb"
		if publicURL == "" {
			publicURL = "https://" + listen
		}
		c.Server.PublicURL, c.Server.MasterKey = publicURL, b64(k0)
		c.Limits.PasswordWorkers = 2
		c.Cluster.Bind, c.Cluster.Advertise, c.Cluster.Key, c.Cluster.Peers = addrs[i], addrs[i], ckey, addrs
		c.Cluster.Size = len(addrs)
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if _, _, err := Bootstrap(context.Background(), c, logger.NewNullLogger()); err != nil {
				t.Fatal(err)
			}
		}
		n := &rotNode{cfg: c}
		n.start(t)
		nodes = append(nodes, n)
	}
	ctx := context.Background()
	waitAll := func(what string, d time.Duration, cond func(n *rotNode) bool) {
		t.Helper()
		deadline := time.Now().Add(d)
		for _, n := range nodes {
			for !cond(n) {
				if time.Now().After(deadline) {
					t.Fatalf("timed out waiting for %s", what)
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
	waitAll("the cluster to be ready", 60*time.Second, func(n *rotNode) bool { ok, _ := n.app.Server.Health.Ready(); return ok })

	// Secrets sealed with the old key: a user's authenticator secret, a provider's client secret, a refresh grant.
	write := func(n *rotNode, fn func() error) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for err := fn(); err != nil; err = fn() {
			if time.Now().After(deadline) {
				t.Fatal(err)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	svc0 := nodes[0].app.Svc // until node 0 restarts
	primary, err := svc0.PrimaryOrg(ctx)
	if err != nil {
		t.Fatal(err)
	}
	totp := map[string]string{}
	addTOTP := func(n *rotNode, name string) {
		t.Helper()
		var u *model.User
		write(n, func() (err error) {
			u, err = n.app.Svc.CreateUser(ctx, service.System, primary.ID, service.UserInput{Username: &name,
				Email: ptr(name + "@example.com"), GivenName: &name})
			return err
		})
		write(n, func() error {
			cur, err := n.app.Svc.Users.Get(ctx, u.ID)
			if err != nil {
				return err
			}
			cur.TOTPSecret = n.app.Svc.Sealer.SealFor(service.TOTPBinding(u.ID), []byte("totp-"+name))
			return n.app.Svc.Users.Update(ctx, cur)
		})
		totp[u.ID] = "totp-" + name
	}
	addTOTP(nodes[0], "before")
	var p *model.Provider
	write(nodes[0], func() (err error) {
		p, err = svc0.CreateProvider(ctx, service.System, primary.ID, service.ProviderInput{Type: ptr(model.ProviderOIDC),
			Name: ptr("SSO"), Issuer: ptr("https://sso.example.com"), ClientID: ptr("cid"), ClientSecret: ptr("provider-secret")})
		return err
	})
	g := &model.Grant{ClientID: "c", UserID: "u", OrgID: primary.ID, SessionID: "s", Expires: time.Now().Add(time.Hour)}
	g.ID = model.NewID()
	svc0.NewGrantKey(g)
	write(nodes[0], func() error { return svc0.Grants.Create(ctx, g) })
	grantKey, _ := svc0.Sealer.OpenFor(service.GrantKeyBinding(g.ID), g.Key)

	// every reports whether, on node n, every secret opens with its keyring (and, with sealedWith, is sealed with
	// the key it names).
	every := func(n *rotNode, sealedWith string) bool {
		s := n.app.Svc
		stale := func(v string) bool { return sealedWith != "" && s.Sealer.Stale(v) }
		for id, plain := range totp {
			u, err := s.Users.Get(ctx, id)
			if err != nil {
				return false
			}
			if v, err := s.Sealer.OpenFor(service.TOTPBinding(id), u.TOTPSecret); err != nil || string(v) != plain || stale(u.TOTPSecret) {
				return false
			}
		}
		pp, err := s.Providers.Get(ctx, p.ID)
		if err != nil {
			return false
		}
		if v, err := s.Sealer.OpenFor(service.ProviderSecretBinding(p.ID), pp.ClientSecret); err != nil ||
			string(v) != "provider-secret" || stale(pp.ClientSecret) {
			return false
		}
		gg, err := s.Grants.Get(ctx, g.ID)
		if err != nil {
			return false
		}
		key, err := s.GrantRefreshKey(gg)
		return err == nil && string(key) == string(grantKey) && !stale(gg.Key)
	}
	ready := func(n *rotNode) bool { ok, _ := n.app.Server.Health.Ready(); return ok }
	state := func(n *rotNode, want string, removable bool) func(*rotNode) bool {
		return func(*rotNode) bool {
			st, err := n.app.Svc.RotationStatus(ctx)
			return err == nil && st.State == want && st.Removable == removable
		}
	}
	waitAll("the old secrets on every node", 30*time.Second, func(n *rotNode) bool { return every(n, "") })

	// Step 2, node by node: the new key added as a previous one.
	for _, n := range nodes {
		n.reload(t, b64(k0), b64(k1))
	}
	waitAll("step 2", 60*time.Second, ready)

	// Step 3, node by node; halfway, node 2 still seals with the old key, and no node re-seals anything.
	nodes[0].restart(t, b64(k1), b64(k0)) // (a restart mid-rotation: the start-up check of a node with a ring)
	nodes[1].reload(t, b64(k1), b64(k0))
	waitAll("half of step 3", 60*time.Second, ready)
	waitAll("the status to show the nodes disagreeing", 20*time.Second, state(nodes[0], "waiting_for_nodes", false))
	addTOTP(nodes[2], "step3old")
	addTOTP(nodes[1], "step3new")
	waitAll("both kinds of secret on every node", 30*time.Second, func(n *rotNode) bool { return every(n, "") })
	passes := func() (sum int64) {
		for _, n := range nodes {
			sum += n.app.passes.Load()
		}
		return sum
	}
	from := passes()
	waitAll("three more passes of the housekeeping leader", 30*time.Second, func(*rotNode) bool { return passes() >= from+3 })
	for i, n := range nodes { // nothing was re-sealed while the nodes disagreed: the grant's key still names the old key
		gg, err := n.app.Svc.Grants.Get(ctx, g.ID)
		if err != nil || !strings.HasPrefix(gg.Key, "v3:"+secure.KeyID(k0)+":") {
			t.Fatalf("node %d: re-sealed while the nodes did not agree on the key (%v)", i, err)
		}
	}
	nodes[2].reload(t, b64(k1), b64(k0))
	waitAll("step 3", 60*time.Second, ready)
	waitAll("the leader to re-seal every secret, on every node", 60*time.Second, func(n *rotNode) bool { return every(n, secure.KeyID(k1)) })
	waitAll("every node's status to say the old key can go", 20*time.Second, func(n *rotNode) bool { return state(n, "complete", true)(n) })

	// Step 4: the old key removed everywhere.
	for _, n := range nodes {
		n.reload(t, b64(k1))
	}
	waitAll("step 4", 60*time.Second, ready)
	waitAll("no rotation in progress", 20*time.Second, func(n *rotNode) bool { return state(n, "none", false)(n) })
	waitAll("every secret opening with the new key alone", 30*time.Second, func(n *rotNode) bool { return every(n, secure.KeyID(k1)) })
	old, _ := secure.NewSealer(k0)
	for i, n := range nodes {
		for id := range totp {
			u, _ := n.app.Svc.Users.Get(ctx, id)
			if _, err := old.OpenFor(service.TOTPBinding(id), u.TOTPSecret); err == nil {
				t.Fatalf("node %d: a secret still opens with the old key", i)
			}
		}
	}
	// a re-seal pass on any node now has nothing left to do
	if r, err := nodes[1].app.Svc.ResealSecrets(ctx, time.Minute); err != nil || !r.Done() || r.Resealed != 0 {
		t.Fatalf("a pass after the rotation, on another node: %+v %v", r, err)
	}
}

// A reload is refused, and the keys in use stay, when the new keys leave out the key in use (a typo, a wrong file),
// or are not valid; the same keys again change nothing; a valid next step switches the running keyring in place.
func TestReloadMasterKeysRefusals(t *testing.T) {
	k0 := base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	k1 := base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	a, _, _ := startAppWith(t, "badgerdb", func(c *config.Config) { c.Server.MasterKey = k0 })
	ctx := context.Background()
	sealer := a.Svc.Sealer
	active := sealer.ActiveKeyID()
	if err := a.ReloadMasterKeys(ctx, k1, nil); err == nil || sealer.ActiveKeyID() != active {
		t.Fatalf("a key that leaves out the one in use: %v", err)
	}
	if err := a.ReloadMasterKeys(ctx, "not base64!", nil); err == nil || sealer.ActiveKeyID() != active {
		t.Fatalf("an invalid key: %v", err)
	}
	if err := a.ReloadMasterKeys(ctx, k0, nil); err != nil || sealer.Previous() {
		t.Fatalf("the same key: %v", err)
	}
	if err := a.ReloadMasterKeys(ctx, k1, []string{k0}); err != nil || sealer.ActiveKeyID() == active || !sealer.Previous() {
		t.Fatalf("the next step: %v", err)
	}
	if a.Svc.Sealer != sealer {
		t.Fatal("the keyring was replaced rather than switched in place")
	}
}

// A reload that drops a key while a queued item (an email waiting to be sent) is still sealed with it, because it
// could not be re-sealed (here the store refuses the rewrite), is refused: the item keeps opening. Adding the next key
// meanwhile is fine.
func TestReloadKeepsAKeyAQueuedItemNeeds(t *testing.T) {
	ctx := context.Background()
	b64 := base64.StdEncoding.EncodeToString
	oldKey, newKey := b64(secure.RandomBytes(32)), b64(secure.RandomBytes(32))
	a, _, _ := startAppWith(t, "badgerdb", func(c *config.Config) { c.Server.MasterKey = oldKey })
	st := &refusingQueueWrites{Store: a.Store}
	m := mail.New(a.Cfg, logger.NewNullLogger(), st, a.Node.ID(), a.Svc.Sealer,
		mail.TransportFunc(func(context.Context, mail.Message) error { return errors.New("SMTP offline") }))
	a.mailer = m
	if err := m.Send(ctx, mail.Message{To: "user@example.test", Subject: "invitation", Text: "single-use link"}); err != nil {
		m.Close()
		t.Fatal(err)
	}
	m.Close() // the accepted message stays queued, without a racing delivery worker
	st.refuse.Store(true)
	if err := a.ReloadMasterKeys(ctx, newKey, []string{oldKey}); err != nil {
		t.Fatalf("adding the next key: %v", err)
	}
	if _, err := a.Svc.ResealSecrets(ctx, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := a.ReloadMasterKeys(ctx, newKey, nil); err == nil || !strings.Contains(err.Error(), "still need") {
		t.Fatalf("dropping the key a queued item still needs: %v", err)
	}
	items, _, err := store.NewTable[model.QueueItem](a.Store).List(ctx, store.ListQuery{
		Scope: model.QueueScope("mail", a.Node.ID())})
	if err != nil || len(items) != 1 {
		t.Fatalf("queued items %d: %v", len(items), err)
	}
	if _, err := a.Svc.Sealer.OpenFor("mail/queue", items[0].Sealed); err != nil {
		t.Fatalf("the queued item no longer opens: %v", err)
	}
}

// A reload that drops a key is refused until the leader has been through every stored record since the keys changed
// (what it found is published, and a status read costs no scan), and while a node still seals with another key; once
// both hold, it goes through. A key still needed is never dropped on a guess: before, the check scanned every stored secret
// itself, and no node answered for the leader's walk.
func TestReloadDropsAKeyOnlyAfterTheWalk(t *testing.T) {
	ctx := context.Background()
	b64 := base64.StdEncoding.EncodeToString
	oldKey, newKey := b64(secure.RandomBytes(32)), b64(secure.RandomBytes(32))
	a, _, _ := startAppWith(t, "badgerdb", func(c *config.Config) { c.Server.MasterKey = oldKey })
	// the leader's first pass (under the old key) has run: its next is a minute away, after this test
	deadline := time.Now().Add(20 * time.Second)
	for st, err := a.Svc.RotationStatus(ctx); err != nil || st.Checked == nil; st, err = a.Svc.RotationStatus(ctx) {
		if time.Now().After(deadline) {
			t.Fatalf("the leader's first pass did not finish: %+v %v", st, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := a.ReloadMasterKeys(ctx, newKey, []string{oldKey}); err != nil {
		t.Fatalf("adding the next key: %v", err)
	}
	// no walk has been made with the new key: nothing says the old one is not needed
	if err := a.ReloadMasterKeys(ctx, newKey, nil); err == nil || !strings.Contains(err.Error(), "may still need") {
		t.Fatalf("dropping the key before the walk: %v", err)
	}
	// a node that still seals with the old key
	raw, _ := base64.StdEncoding.DecodeString(oldKey)
	oldSealer, _ := secure.NewSealer(raw)
	laggard := service.New(a.Svc.Cfg, a.Svc.Store, oldSealer)
	if err := laggard.ReportMasterKey(ctx, "laggard"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Svc.ResealSecrets(ctx, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := a.ReloadMasterKeys(ctx, newKey, nil); err == nil || !strings.Contains(err.Error(), "waiting_for_nodes") {
		t.Fatalf("dropping the key while a node seals with it: %v", err)
	}
	l, err := a.Svc.Locks.Get(ctx, "master-key/laggard")
	if err != nil {
		t.Fatal(err)
	}
	l.Until = time.Now().Add(-time.Minute)
	if err := a.Svc.Locks.Update(ctx, l); err != nil {
		t.Fatal(err)
	}
	if err := a.ReloadMasterKeys(ctx, newKey, nil); err != nil {
		t.Fatalf("dropping the key after the walk, every node on the new one: %v", err)
	}
}

// refusingQueueWrites is a store that refuses the rewrites of queued items once refuse is set (a store that fails).
type refusingQueueWrites struct {
	store.Store
	refuse atomic.Bool
}

func (s *refusingQueueWrites) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	if rec.Kind == model.KindQueue && s.refuse.Load() {
		return store.ErrUnavailable
	}
	return s.Store.CompareAndPut(ctx, rec, expect)
}

// A node refuses a master key its database was not sealed with: nodes sharing a database must share the key, and a
// node's own store (standalone or gossip) keeps the key it was sealed with.
func TestMasterKeyCheck(t *testing.T) {
	for _, tc := range []struct {
		name   string
		shared bool
		want   string
	}{{"shared database", true, "master key"}, {"own store", false, "sealed with"}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st := memstore.New()
			a, _ := secure.NewSealer(secure.RandomBytes(32))
			b, _ := secure.NewSealer(secure.RandomBytes(32))
			log := logger.NewNullLogger()
			if err := checkSharedKey(ctx, st, a, log, tc.shared); err != nil {
				t.Fatal(err)
			}
			if err := checkSharedKey(ctx, st, a, log, tc.shared); err != nil {
				t.Fatalf("the same key again: %v", err)
			}
			if err := checkSharedKey(ctx, st, b, log, tc.shared); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("another key: %v", err)
			}
		})
	}
}

// A master key rotation on a shared database: a node whose ring holds the database's key as a previous one starts
// and moves the database to its active key; from then on a node given only the old key refuses, and one given only the
// new key starts.
func TestSharedDatabaseMasterKeyRotation(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	k1, k2 := secure.RandomBytes(32), secure.RandomBytes(32)
	old, _ := secure.NewSealer(k1)
	ring, _ := secure.NewKeyring(k2, k1)
	only2, _ := secure.NewSealer(k2)
	log := logger.NewNullLogger()
	if err := checkSharedKey(ctx, st, old, log, true); err != nil {
		t.Fatal(err)
	}
	if err := checkSharedKey(ctx, st, ring, log, true); err != nil {
		t.Fatalf("the rotating node: %v", err)
	}
	if err := checkSharedKey(ctx, st, old, log, true); err == nil {
		t.Fatal("a node with only the old key started after the rotation")
	}
	if err := checkSharedKey(ctx, st, only2, log, true); err != nil {
		t.Fatalf("a node with only the new key: %v", err)
	}
}
