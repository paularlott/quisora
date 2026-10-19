package app

import (
	"context"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
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
// "Rotating the master key"): every node restarted one at a time for each step, with the housekeeping leader doing
// the re-seal by itself. Halfway through step 3 the leader waits, whichever node it is; once every node seals with
// the new key it re-seals every secret, on every node; and with the old key then removed everywhere, every secret
// still opens, on every node, and none opens with the old key.
func TestGossipMasterKeyRotation(t *testing.T) {
	t.Run("restart", func(t *testing.T) { testGossipMasterKeyRotation(t, false) })
	t.Run("reload", func(t *testing.T) { testGossipMasterKeyRotation(t, true) })
}

// testGossipMasterKeyRotation changes the nodes' keys by restarting them, or (reload) by reloading them in place as
// SIGHUP does; the status (RotationStatus, GET /api/v1/master-key) says where the rotation stands at each step.
func testGossipMasterKeyRotation(t *testing.T, reload bool) {
	saved := housekeepingEvery
	housekeepingEvery = time.Second
	t.Cleanup(func() { housekeepingEvery = saved })

	k0, k1 := secure.RandomBytes(32), secure.RandomBytes(32)
	b64 := base64.StdEncoding.EncodeToString
	addrs := []string{gossipAddr(t), gossipAddr(t), gossipAddr(t)}
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
	waitAll("the cluster to be ready", 60*time.Second, func(n *rotNode) bool { ok, _ := n.app.Node.Ready(); return ok })

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
		keys, legacy, err := s.GrantRefreshKeys(gg)
		return err == nil && !legacy && string(keys[0]) == string(grantKey) && !stale(gg.Key)
	}
	ready := func(n *rotNode) bool { ok, _ := n.app.Node.Ready(); return ok }
	setKeys := func(n *rotNode, master string, previous ...string) {
		t.Helper()
		if reload {
			n.reload(t, master, previous...)
		} else {
			n.restart(t, master, previous...)
		}
	}
	state := func(n *rotNode, want string, removable bool) func(*rotNode) bool {
		return func(*rotNode) bool {
			st, err := n.app.Svc.RotationStatus(ctx)
			return err == nil && st.State == want && st.Removable == removable
		}
	}
	waitAll("the old secrets on every node", 30*time.Second, func(n *rotNode) bool { return every(n, "") })

	// Step 2, node by node: the new key added as a previous one.
	for _, n := range nodes {
		setKeys(n, b64(k0), b64(k1))
	}
	waitAll("step 2", 60*time.Second, ready)

	// Step 3, node by node; halfway, node 2 still seals with the old key, and no node re-seals anything.
	nodes[0].restart(t, b64(k1), b64(k0)) // (the first one restarted, reloaded or not: a restart mid-rotation)
	setKeys(nodes[1], b64(k1), b64(k0))
	waitAll("half of step 3", 60*time.Second, ready)
	waitAll("the status to show the nodes disagreeing", 20*time.Second, state(nodes[0], "waiting_for_nodes", false))
	addTOTP(nodes[2], "step3old")
	addTOTP(nodes[1], "step3new")
	waitAll("both kinds of secret on every node", 30*time.Second, func(n *rotNode) bool { return every(n, "") })
	time.Sleep(5 * housekeepingEvery) // several leader passes
	for i, n := range nodes {         // nothing was re-sealed while the nodes disagreed: the grant's key still names the old key
		gg, err := n.app.Svc.Grants.Get(ctx, g.ID)
		if err != nil || !strings.HasPrefix(gg.Key, "v3:"+secure.KeyID(k0)+":") {
			t.Fatalf("node %d: re-sealed while the nodes did not agree on the key (%v)", i, err)
		}
	}
	setKeys(nodes[2], b64(k1), b64(k0))
	waitAll("step 3", 60*time.Second, ready)
	waitAll("the leader to re-seal every secret, on every node", 60*time.Second, func(n *rotNode) bool { return every(n, secure.KeyID(k1)) })
	waitAll("every node's status to say the old key can go", 20*time.Second, func(n *rotNode) bool { return state(n, "complete", true)(n) })

	// Step 4: the old key removed everywhere.
	for _, n := range nodes {
		setKeys(n, b64(k1))
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
