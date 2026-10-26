package loadtest_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/app"
	"github.com/paularlott/quisora/internal/cluster"
	"github.com/paularlott/quisora/internal/cluster/clustertest"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/loadtest"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// Seeding a gossip node's store makes its records writes of their partitions: three nodes started afterwards, the others
// with empty databases, all end up with the seeded data.
func TestSeedIntoAGossipNodeIsCopiedByTheOthers(t *testing.T) {
	ctx := context.Background()
	clusterKey := base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	master := secure.RandomBytes(32)
	masterKey := base64.StdEncoding.EncodeToString(master)
	addrs := []string{clustertest.FreeAddr(t), clustertest.FreeAddr(t), clustertest.FreeAddr(t)}
	cfgs := make([]*config.Config, 3)
	for i := range cfgs {
		c := config.Default()
		c.Server.DataDir = t.TempDir()
		c.Server.MasterKey = masterKey
		c.Server.PublicURL = "https://id.example.test"
		c.Limits.PasswordWorkers = 4
		c.Storage.Backend = "badgerdb"
		c.Cluster.Bind, c.Cluster.Key, c.Cluster.Peers, c.Cluster.Size = addrs[i], clusterKey, addrs, 3
		cfgs[i] = c
	}

	// seed node 0's own store, as "loadtest seed" does
	st, err := app.OpenStore(ctx, cfgs[0])
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := secure.NewSealer(master)
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(cfgs[0], st, sealer)
	o := loadtest.DefaultSeedOptions()
	o.Orgs, o.Users, o.Grants, o.Sample, o.Workers = 3, 15, 6, 3, 4
	sum, err := loadtest.Seed(ctx, svc, o, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if sum.OrgsCreated != 3 {
		t.Fatalf("seeded %+v", sum)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// the three nodes
	opt := cluster.Options{ClockInterval: 300 * time.Millisecond, JoinWait: 3 * time.Second, Gossip: clustertest.Gossip,
		Partition: clustertest.Partition}
	stores := make([]store.Store, 3)
	nodes := make([]*cluster.Node, 3)
	for i := range nodes {
		if stores[i], err = app.OpenStore(ctx, cfgs[i]); err != nil {
			t.Fatal(err)
		}
		if nodes[i], err = cluster.New(cfgs[i], stores[i], opt); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for i := range nodes {
			nodes[i].Close()
			stores[i].Close()
		}
	})
	errs := make(chan error, 3)
	for _, n := range nodes {
		go func() { errs <- n.Start(ctx) }()
	}
	for range nodes {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}

	counts := func(n *cluster.Node) map[model.Kind]int {
		out := map[model.Kind]int{}
		for _, k := range model.Kinds() {
			if k == model.KindEphemeral || k == model.KindAudit {
				continue // audit events stay on the node that recorded them (checked below)
			}
			c, err := n.Store().Count(ctx, k, "")
			if err != nil {
				t.Fatal(err)
			}
			out[k] = c
		}
		return out
	}
	want := counts(nodes[0])
	if want[model.KindUser] < 3*15 || want[model.KindOrg] < 3 || want[model.KindGrant] < 6 {
		t.Fatalf("the seeded node holds %v", want)
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		same := true
		for _, n := range nodes[1:] {
			if got := counts(n); fmt.Sprint(got) != fmt.Sprint(want) {
				same = false
			}
		}
		ready := true
		for _, n := range nodes {
			if ok, _ := n.Ready(); !ok {
				ready = false
			}
		}
		if same && ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the nodes did not converge:\n node 0: %v\n node 1: %v\n node 2: %v", want, counts(nodes[1]), counts(nodes[2]))
		}
		time.Sleep(100 * time.Millisecond)
	}
	// the seeding's audit events stay on the node that recorded them: the audit log is not replicated
	if c, err := nodes[0].Store().Count(ctx, model.KindAudit, ""); err != nil || c == 0 {
		t.Fatalf("node 0 holds no audit events of the seeding: %d %v", c, err)
	}
	for i, n := range nodes[1:] {
		if c, err := n.Store().Count(ctx, model.KindAudit, ""); err != nil || c != 0 {
			t.Fatalf("node %d holds %d of another node's audit events (%v)", i+1, c, err)
		}
	}
	// and the copies are the seeded records, not counts alone
	for i, n := range nodes[1:] {
		if org, err := n.Store().GetByUnique(ctx, model.KindOrg, model.OrgNameKey(loadtest.OrgName(1))); err != nil || org == nil {
			t.Fatalf("node %d: the seeded organization: %v", i+1, err)
		}
	}
}
