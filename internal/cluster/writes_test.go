package cluster

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/partition"
	"github.com/paularlott/quisora/internal/cluster/clustertest"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// A write on any node is committed by the owner of its partition and applied on every node; the writer reads its own
// write at once, the others when the commit reaches them.
func TestWriteReplicates(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		c := started(t, b)
		c.waitOwners() // (ready does not mean every partition has its owner yet: a write waits for one, and gives up after 5s)
		var got [3]atomic.Int32
		var local [3]atomic.Int32
		for i, tn := range c.nodes {
			tn.n.OnChange(func(rec *store.Record, isLocal bool) {
				if rec.Kind == dataKind {
					got[i].Add(1)
					if isLocal {
						local[i].Add(1)
					}
				}
			})
		}
		for i := range c.nodes {
			rec := newRec(model.NewID(), "")
			putRetrying(t, c.nodes[i], rec)
			// Put returns once this node has applied the write, within a bound (applyWait: the write is committed
			// whether or not this node has seen it in time, which a loaded machine can delay): a node that is slower
			// than that still gets there.
			waitFor(t, 60*time.Second, fmt.Sprintf("node %d to read its own write", i), func() bool { return has(c.nodes[i].st(), rec.ID) })
			c.waitHas(rec.ID)
			var r *store.Record
			err := asked(func() (err error) { r, err = c.nodes[(i+1)%3].st().Get(bg, dataKind, rec.ID); return err })
			if err != nil || r.Version != rec.Version || r.Partition != "org1" || string(r.Data) != string(rec.Data) {
				t.Fatalf("replica %+v (%v), written %+v", r, err, rec)
			}
		}
		waitFor(t, 60*time.Second, "the change hooks on every node", func() bool {
			return got[0].Load() == 3 && got[1].Load() == 3 && got[2].Load() == 3
		})
		for i := range local {
			if local[i].Load() != 1 {
				t.Errorf("node %d: %d of its hooks were for its own writes, want 1", i, local[i].Load())
			}
		}
	})
}

// The owner's refusals come back as the store's own errors.
func TestWritesReturnTheStoresErrors(t *testing.T) {
	eachBackend(t, func(t *testing.T, b backend) {
		c := started(t, b)
		s0, s1 := c.nodes[0].st(), c.nodes[1].st()
		rec := newRec(model.NewID(), "ident-1")
		if err := s0.CompareAndPut(bg, rec, 0); err != nil {
			t.Fatal(err)
		}
		c.waitHas(rec.ID)
		again := newRec(rec.ID, "")
		if err := s1.CompareAndPut(bg, again, 0); !errors.Is(err, store.ErrStale) {
			t.Fatalf("a create over a live record: %v", err)
		}
		if err := s1.CompareAndPut(bg, again, rec.Version+12345); !errors.Is(err, store.ErrStale) {
			t.Fatalf("an update of another version: %v", err)
		}
		if err := s1.CompareAndPut(bg, newRec(model.NewID(), ""), 5); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("an update of nothing: %v", err)
		}
		if err := s1.CompareAndPut(bg, newRec(model.NewID(), "ident-1"), 0); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("a unique value in use: %v", err)
		}
		before := rec.Version
		upd := newRec(rec.ID, "ident-1")
		if err := s1.CompareAndPut(bg, upd, rec.Version); err != nil {
			t.Fatalf("an update of the version held: %v", err)
		}
		if upd.Version <= before {
			t.Fatalf("the stored version %d is not above the one it replaced (%d)", upd.Version, before)
		}
		put := newRec(rec.ID, "ident-1")
		if err := s0.Put(bg, put); err != nil || put.Version <= upd.Version {
			t.Fatalf("a put over a live record: %v (version %d, after %d)", err, put.Version, upd.Version)
		}

		// A deletion is a tombstone that keeps the partition key and scope of the record, on every node.
		if err := s1.Put(bg, store.Tombstone(dataKind, rec.ID)); err != nil {
			t.Fatal(err)
		}
		waitFor(t, 10*time.Second, "the tombstone everywhere", func() bool {
			for _, tn := range c.nodes {
				r, err := tn.st().Lookup(bg, dataKind, rec.ID)
				if err != nil || !r.Deleted || r.Partition != "org1" {
					return false
				}
			}
			return true
		})
		if _, err := s0.Get(bg, dataKind, rec.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a deleted record: %v", err)
		}
		if err := s0.Put(bg, newRec(rec.ID, "")); !errors.Is(err, store.ErrDeleted) || !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a put over a tombstone: %v", err)
		}
		if err := s0.CompareAndPut(bg, newRec(rec.ID, ""), rec.Version); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("an update over a tombstone: %v", err)
		}
		// Its unique value is free again, and the id can be created anew.
		if err := s1.CompareAndPut(bg, newRec(model.NewID(), "ident-1"), 0); err != nil {
			t.Fatalf("the unique value of a deleted record: %v", err)
		}
		if err := s0.CompareAndPut(bg, newRec(rec.ID, ""), 0); err != nil {
			t.Fatalf("a create over a tombstone: %v", err)
		}
		// Deleting what is not there changes nothing; a conditional deletion of another version is stale.
		if err := s0.Put(bg, store.Tombstone(dataKind, model.NewID())); err != nil {
			t.Fatalf("a deletion of nothing: %v", err)
		}
		cur, _ := s0.Get(bg, dataKind, rec.ID)
		if err := s0.CompareAndPut(bg, store.Tombstone(dataKind, rec.ID), cur.Version+1); !errors.Is(err, store.ErrStale) {
			t.Fatalf("a conditional deletion of another version: %v", err)
		}
		if err := s0.CompareAndPut(bg, store.Tombstone(dataKind, rec.ID), cur.Version); err != nil {
			t.Fatalf("a conditional deletion of the version held: %v", err)
		}
		if st := c.nodes[1].n.Status(); st.Refused == 0 || st.Writes == 0 {
			t.Fatalf("the counters: %+v", st)
		}
	})
}

// Writes on one healthy cluster (SQLite): the owner's checks of what it commits.
func TestWritesOnOneCluster(t *testing.T) {
	runOn(t, started(t, sqliteBackend()),
		scenario{"stale copy update is refused", testStaleCopyUpdateIsRefused},
		scenario{"concurrent updates from all nodes", testConcurrentUpdatesFromAllNodes},
		scenario{"concurrent unique claims", testConcurrentUniqueClaims},
		scenario{"tombstone hooks carry the scope", testTombstoneHooksCarryTheScope},
		scenario{"replay refused whichever node stops serving", testReplayRefusedWhicheverNodeStopsServing})
}

// A write made from a copy that has fallen behind is refused by the owner, which compares against its committed data:
// an administrator's change is never erased by an update made from an older copy. A node that cannot catch up with the
// owner's refusal within the staleness bound fails closed (store.ErrUnavailable, retry) instead of answering stale.
func testStaleCopyUpdateIsRefused(t *testing.T, c *tcluster) {
	org, _ := c.orgNotOwnedBy(1)
	u := newUser(org, "alice")
	if err := users(c.nodes[0]).Create(bg, u); err != nil {
		t.Fatal(err)
	}
	c.waitUser(t, u.ID, func(x *model.User) bool { return x.Version == u.Version })
	stale, err := users(c.nodes[1]).Get(bg, u.ID)
	if err != nil {
		t.Fatalf("node 1's copy: %v", err)
	}

	c.lagBehind(1, true)
	admin, err := users(c.nodes[0]).Get(bg, u.ID)
	if err != nil {
		t.Fatalf("node 0's copy: %v", err)
	}
	admin.Active = false
	if err := users(c.nodes[0]).Update(bg, admin); err != nil {
		t.Fatalf("the administrator's change: %v", err)
	}
	// node 1's own copy: through the cluster store its read may already be refused (store.ErrUnavailable), once a
	// heartbeat has told it of the commit it cannot apply, which is the gate doing its job
	if r, err := localUsers(c.nodes[1]).Get(bg, u.ID); err != nil || !r.Active {
		t.Fatalf("test set-up: node 1 must not have the change yet: %+v, %v", r, err)
	}
	stale.GivenName = "signed in"
	begin := time.Now()
	if err := users(c.nodes[1]).Update(bg, stale); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a write from an outdated copy on a node that cannot catch up: %v, want store.ErrUnavailable", err)
	}
	if d := time.Since(begin); d < 250*time.Millisecond {
		t.Fatalf("the node did not wait to catch up with the refusal: %s", d)
	}
	c.lagBehind(1, false)
	c.waitUser(t, u.ID, func(x *model.User) bool { return !x.Active && x.Version == admin.Version })
	// caught up, the same write is refused as stale
	if err := users(c.nodes[1]).Update(bg, stale); !errors.Is(err, store.ErrStale) {
		t.Fatalf("a write from an outdated copy: %v, want store.ErrStale", err)
	}
	c.waitUser(t, u.ID, func(x *model.User) bool { return !x.Active && x.GivenName == "" && x.Version == admin.Version })
}

// Concurrent updates of one record from the same copy: exactly one of each round succeeds, the others are refused as
// stale, and every node ends with the successful one.
func testConcurrentUpdatesFromAllNodes(t *testing.T, c *tcluster) {
	u := newUser("org-updates", "bob")
	if err := users(c.nodes[0]).Create(bg, u); err != nil {
		t.Fatal(err)
	}
	won := 0
	for round := range 15 {
		c.waitUser(t, u.ID, func(x *model.User) bool { return x.Version == u.Version })
		var wg sync.WaitGroup
		errs := make([]error, 3)
		wrote := make([]*model.User, 3)
		for i := range 3 {
			x, err := users(c.nodes[i]).Get(bg, u.ID)
			if err != nil {
				t.Fatalf("round %d, node %d's copy: %v", round, i, err)
			}
			x.GivenName = fmt.Sprintf("round %d node %d", round, i)
			wrote[i] = x
			wg.Add(1)
			go func() { defer wg.Done(); errs[i] = users(c.nodes[i]).Update(bg, x) }()
		}
		wg.Wait()
		ok := 0
		for i, err := range errs {
			switch {
			case err == nil:
				ok++
				u = wrote[i]
			case errors.Is(err, store.ErrStale):
			default:
				t.Fatalf("round %d node %d: %v", round, i, err)
			}
		}
		if ok != 1 {
			t.Fatalf("round %d: %d of three concurrent updates from one copy succeeded", round, ok)
		}
		won++
		want := u.GivenName
		c.waitUser(t, u.ID, func(x *model.User) bool { return x.GivenName == want })
	}
	if won != 15 {
		t.Fatalf("%d rounds", won)
	}
}

// Users claiming one email address at once on every node: exactly one is created, the others get store.ErrConflict.
func testConcurrentUniqueClaims(t *testing.T, c *tcluster) {
	for round := range 5 {
		email := fmt.Sprintf("claimed-%d@example.com", round)
		var wg sync.WaitGroup
		var mu sync.Mutex
		var winners []string
		for i := range 12 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				u := newUser("org-claims", fmt.Sprintf("claim-%d-%d", round, i))
				u.Email = email
				switch err := users(c.nodes[i%3]).Create(bg, u); {
				case err == nil:
					mu.Lock()
					winners = append(winners, u.ID)
					mu.Unlock()
				case errors.Is(err, store.ErrConflict):
				default:
					t.Errorf("round %d claim %d: %v", round, i, err)
				}
			}()
		}
		wg.Wait()
		if len(winners) != 1 {
			t.Fatalf("round %d: %d users hold one email address", round, len(winners))
		}
		waitFor(t, 10*time.Second, "the winner on every node", func() bool {
			for _, tn := range c.nodes {
				h, err := tn.st().GetByUnique(bg, model.KindUser, model.UserEmailKey("org-claims", email))
				if err != nil || h.ID != winners[0] {
					return false
				}
			}
			return true
		})
	}
}

// The change hooks of a deletion get the scope and partition key of the record it deleted, on every node (a tombstone
// stores neither, and the hooks say which organization's administrators and which user's pages to tell).
func testTombstoneHooksCarryTheScope(t *testing.T, c *tcluster) {
	rec := newRec(model.NewID(), "")
	rec.Scope = "user-1"
	got := make(chan *store.Record, 3)
	for _, tn := range c.nodes {
		tn.n.OnChange(func(r *store.Record, local bool) { // (the hooks stay, and the cluster serves other scenarios)
			if r.Deleted && r.ID == rec.ID {
				got <- r
			}
		})
	}
	if err := c.nodes[0].st().Put(bg, rec); err != nil {
		t.Fatal(err)
	}
	c.waitHas(rec.ID)
	if err := c.nodes[1].st().Put(bg, store.Tombstone(dataKind, rec.ID)); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		select {
		case r := <-got:
			if r.ID != rec.ID || r.Scope != "user-1" || r.Partition != "org1" {
				t.Fatalf("the hook of the deletion: %+v", r)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a node did not run the hook of the deletion")
		}
	}
}

// A single-use value (a client assertion or DPoP proof jti) is a model.Replay record, created through the owner of its
// partition (a compare-and-swap), not hash-routed state in one node's memory: once accepted it stays refused on every
// node, whichever node stops serving.
func testReplayRefusedWhicheverNodeStopsServing(t *testing.T, c *tcluster) {
	replays := func(i int) *store.Table[model.Replay, *model.Replay] {
		return store.NewTable[model.Replay](c.nodes[i].st())
	}
	use := func(i int) error {
		return replays(i).Create(bg, &model.Replay{Meta: model.Meta{ID: "replayed-jti"}, Expires: time.Now().Add(time.Minute)})
	}
	if err := use(0); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := use(0); !errors.Is(err, store.ErrStale) {
		t.Fatalf("normal replay: %v", err)
	}
	for _, stopped := range []int{0, 1} {
		why := "test: not serving"
		c.nodes[stopped].n.mixed.Store(&why)
		c.nodes[stopped].n.rebuild()
		if err := use(stopped); !errors.Is(err, store.ErrUnavailable) || !strings.Contains(err.Error(), why) {
			t.Fatalf("a write on node %d, which does not serve: %v", stopped, err)
		}
		for i := range c.nodes {
			if i == stopped {
				continue
			}
			if err := use(i); err == nil {
				t.Fatalf("the same jti accepted again on node %d after node %d stopped serving", i, stopped)
			}
		}
		c.nodes[stopped].n.mixed.Store(nil)
		c.nodes[stopped].n.rebuild()
	}
}

// A write or a fresh read on a node that does not serve is refused with store.ErrUnavailable. A gossip node takes no
// record from outside its partitions (PutReplicated): what it holds arrives through partition writes alone.
func TestWriteFromANodeThatIsNotReady(t *testing.T) {
	n, _ := gnode(t) // built, not started: not ready
	err := n.Store().Put(bg, newRec(model.NewID(), ""))
	if !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	if _, err := n.Store().Fresh(bg, dataKind, []string{"x"}); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a fresh read on a node that is not ready: %v", err)
	}
	rec := newRec(model.NewID(), "")
	if applied, err := n.Store().PutReplicated(bg, rec); applied || err == nil || !strings.Contains(err.Error(), "partitions") {
		t.Fatalf("a record applied on a gossip node outside its partitions: %v %v", applied, err)
	}
	if has(n.Store(), rec.ID) {
		t.Fatal("the refused record is stored")
	}
}

// A change forwarded to the owner of its partition that takes longer than gossip's default transport deadline (2s; here
// a slow disk on the owner) is confirmed, not reported unknown while it commits. A transport deadline shorter than the
// partition protocol needs is refused when the node is built.
func TestForwardedSlowWriteIsConfirmed(t *testing.T) {
	var fs faults
	c := newTCluster(t, 3, fs.over(sqliteBackend()))
	c.startAll()
	c.waitReady()
	org, owner := c.orgNotOwnedBy(0)
	slow := fs.of(c.nodes[owner])
	slow.pendingDelay.Store(int64(3 * time.Second))
	rec := newOrgRec(org)
	start := time.Now()
	err := c.nodes[0].st().Put(bg, rec)
	took := time.Since(start)
	slow.pendingDelay.Store(0)
	if err != nil {
		t.Fatalf("a forwarded write the owner took %s over: %v", took.Round(time.Millisecond), err)
	}
	if took < 2*time.Second {
		t.Fatalf("test set-up: the write took %s, not longer than the old transport deadline", took)
	}
	if n := c.nodes[0].n.Status().Unconfirmed; n != 0 {
		t.Fatalf("%d writes unconfirmed", n)
	}
	c.waitHas(rec.ID)

	opt := fastOptions()
	opt.Gossip = func(g *gossip.Config) { clustertest.Gossip(g); g.TCPDeadline = 2 * time.Second }
	if _, err := New(c.config(0, t.TempDir()), memstore.New(), opt); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("a transport deadline below the write timeout: %v", err)
	}
	opt.Gossip = clustertest.Gossip
	opt.Partition = func(pc *partition.Config) { clustertest.Partition(pc); pc.WriteTimeout = 20 * time.Second }
	n, err := New(c.config(0, t.TempDir()), memstore.New(), opt)
	if err != nil {
		t.Fatalf("the transport deadline does not follow a longer write timeout: %v", err)
	}
	n.Close()
}

// A write whose owner does not answer in time after the write reached the followers (its disk stalls longer than the
// write timeout) is counted as unconfirmed and settled inside the store (submitted again with its request id until it
// is answered): its caller gets the definite answer, and the record is stored once. (How the next owner settles a
// write whose owner is lost is gossip/partition's TestClusterUnknownWriteIsSettledByTakeover.)
func TestUnconfirmedWriteIsSettledEndToEnd(t *testing.T) {
	var fs faults
	c := newTCluster(t, 3, fs.over(sqliteBackend()))
	c.opts = func(o *Options) {
		o.Partition = func(pc *partition.Config) { clustertest.Partition(pc); pc.WriteTimeout = 2 * time.Second }
	}
	c.startAll()
	c.waitReady()
	org, owner := c.orgNotOwnedBy(0)
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svc := service.New(config.Default(), c.nodes[0].st(), sealer)
	slow := fs.of(c.nodes[owner])
	slow.pendingDelay.Store(int64(3 * time.Second)) // longer than the write timeout
	go func() { time.Sleep(4 * time.Second); slow.pendingDelay.Store(0) }()
	g, err := svc.CreateGroup(bg, service.System, org, service.GroupInput{DisplayName: ptrTo("unconfirmed")})
	if err != nil {
		t.Fatalf("a write its owner did not answer in time is settled by the store: %v", err)
	}
	groups, _, err := svc.Groups.List(bg, store.ListQuery{Scope: org})
	if err != nil || len(groups) != 1 || groups[0].ID != g.ID {
		t.Fatalf("the settled write is stored once: %d groups, %v", len(groups), err)
	}
	if n := c.nodes[0].n.Status().Unconfirmed; n < 1 {
		t.Fatalf("unconfirmed count %d: the write was not left unanswered by its owner", n)
	}
}
