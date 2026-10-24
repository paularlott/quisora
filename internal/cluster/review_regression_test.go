package cluster

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// A single-use value (a client assertion or DPoP proof jti) is a model.Replay record written with a quorum
// compare-and-swap, not hash-routed state in one node's memory: once accepted it stays refused on every node,
// whichever node stops serving.
func TestReviewReplayAfterOwnerReadinessChange(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	replays := func(i int) *store.Table[model.Replay, *model.Replay] {
		return store.NewTable[model.Replay](c.nodes[i].st())
	}
	use := func(i int) error {
		return replays(i).Create(bg, &model.Replay{Meta: model.Meta{ID: "review-jti"}, Expires: time.Now().Add(time.Minute)})
	}
	if err := use(0); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := use(0); !errors.Is(err, store.ErrStale) {
		t.Fatalf("normal replay: %v", err)
	}
	for _, stopped := range []int{0, 1} {
		why := "review: node stopped serving"
		c.nodes[stopped].n.misconfig.Store(&why)
		c.nodes[stopped].n.rebuild()
		for i := range c.nodes {
			if i == stopped {
				continue
			}
			if err := use(i); err == nil {
				t.Fatalf("SECURITY: same jti accepted again on node %d after node %d stopped serving", i, stopped)
			}
		}
		c.nodes[stopped].n.misconfig.Store(nil)
		c.nodes[stopped].n.rebuild()
	}
}

func TestReviewRefreshCounterReplayedFromLaggingNode(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	tables := []*store.Table[model.Grant, *model.Grant]{store.NewTable[model.Grant](c.nodes[0].st()), store.NewTable[model.Grant](c.nodes[1].st())}
	g := &model.Grant{ClientID: "client", UserID: "user", OrgID: "org", Expires: time.Now().Add(time.Hour)}
	if err := tables[0].Create(store.WithDurable(bg), g); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "grant replicated", func() bool { x, err := tables[1].Get(bg, g.ID); return err == nil && x.Version == g.Version })
	stale, _ := tables[1].Get(bg, g.ID)
	c.lagBehind(1, true)
	g.Counter++
	if err := tables[0].Update(store.WithDurable(bg), g); err != nil {
		t.Fatal(err)
	}
	stale.Counter++
	if err := tables[1].Update(store.WithDurable(bg), stale); err == nil {
		t.Fatal("SECURITY: second use of refresh counter0 accepted from lagging node after quorum confirmed counter1")
	}
}

// A replacement needs size-quorum+1 source peers, because those sources intersect
// every prior write quorum. In a two-node cluster that means its sole survivor.
func TestReviewTwoNodeReplacementBecomesReady(t *testing.T) {
	c := newTCluster(t, 2, memBackend)
	c.startAll()
	c.waitReady()
	u := newUser("org1", "review-two-node")
	if err := users(c.nodes[0]).Create(bg, u); err != nil {
		t.Fatal(err)
	}
	c.waitUser(t, u.ID, func(x *model.User) bool { return x.Version == u.Version })
	c.replace(t, 1)
	replacement := c.nodes[1]
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ok, _ := replacement.n.Ready(); ok {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	replacement.n.peersMu.Lock()
	got := len(replacement.n.caughtUp)
	replacement.n.peersMu.Unlock()
	_, copyErr := users(replacement).Get(bg, u.ID)
	t.Fatalf("replacement cannot become ready: %s; source ready=%v; copied user=%v; caught-up peers=%d required=%d", readyWhy(replacement), c.nodes[0].n.Status().Ready, copyErr == nil, got, replacement.n.Quorum())
}

// BenchmarkReviewQuorumUserCreate measures both quorum phases and production
// Badger fsync, which the group-record durable-push benchmark does not cover.
func BenchmarkReviewQuorumUserCreate(b *testing.B) {
	for name, mk := range map[string]backend{"memstore": memBackend, "badger-sync": badgerSyncBackend} {
		b.Run(name, func(b *testing.B) {
			c := newTCluster(b, 3, mk)
			c.startAll()
			c.waitReady()
			table := users(c.nodes[0])
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				if err := table.Create(bg, newUser("org1", fmt.Sprintf("bench-%d", i))); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
