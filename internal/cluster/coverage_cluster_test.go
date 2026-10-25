package cluster

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

func covStarted(t *testing.T) *tcluster {
	t.Helper()
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	return c
}

func (c *tcluster) member(from, to int) *member {
	return c.nodes[from].n.mem.Load().byPrefix[c.nodes[to].n.Prefix()]
}

// Ephemeral state is forwarded to the node that owns it; a node that is gone owns nothing any more.
func TestEphemeralForwardedToOwner(t *testing.T) {
	c := covStarted(t)
	a, b, d := c.nodes[0].n, c.nodes[1].n, c.nodes[2].n
	id, err := b.Ephemeral().New(bg, "ns", []byte("v0"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if owner, local, dead := a.OwnerOf("ns", id); owner != b.ID() || local || dead {
		t.Fatalf("owner %q local %v dead %v", owner, local, dead)
	}
	ea := a.Ephemeral()
	if v, err := ea.Get(bg, "ns", id); err != nil || string(v) != "v0" {
		t.Fatalf("remote get: %q %v", v, err)
	}
	if err := ea.Set(bg, "ns", id, []byte("v1"), time.Minute); err != nil {
		t.Fatalf("remote set: %v", err)
	}
	if v, err := ea.Take(bg, "ns", id); err != nil || string(v) != "v1" {
		t.Fatalf("remote take: %q %v", v, err)
	}
	if _, err := ea.Take(bg, "ns", id); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("take again: %v", err)
	}
	if _, err := ea.Get(bg, "ns", id); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("get after take: %v", err)
	}
	if err := ea.Set(bg, "ns", id, []byte("v2"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := ea.Delete(bg, "ns", id); err != nil {
		t.Fatalf("remote delete: %v", err)
	}
	if _, err := ea.Get(bg, "ns", id); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("get after delete: %v", err)
	}

	// The owner's refusal comes back as an error, not as "not found".
	b.eph.local.Budget = 1
	err = ea.Set(bg, "ns", id, make([]byte, 4096), time.Minute)
	if err == nil || errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("a refused remote set: %v", err)
	}
	b.eph.local.Budget = 1 << 20

	// An operation the owner does not know.
	var resp ephResp
	if err := a.gc.SendToWithResponseContext(bg, c.member(0, 1).node, msgEph, &ephReq{Op: 99, NS: "ns", ID: id}, &resp); err != nil ||
		resp.Code != codeError || !strings.Contains(resp.Err, "unknown ephemeral op") {
		t.Fatalf("%+v %v", resp, err)
	}
	// An owner that cannot be reached fails closed.
	c.drop(0, 1, true, msgEph)
	if _, err := ea.Get(bg, "ns", id); err == nil || errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("an unreachable owner: %v", err)
	}
	c.drop(0, 1, false, msgEph)

	// An id of a node that is dead (stopped, and gossip has marked it so) is gone with it.
	gone, err := d.Ephemeral().New(bg, "ns", []byte("v"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	stop(c.nodes[2])
	waitFor(t, 30*time.Second, "the stopped node to be seen dead", func() bool {
		_, _, dead := a.OwnerOf("ns", gone)
		return dead
	})
	if err := ea.Set(bg, "ns", gone, []byte("x"), time.Minute); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Errorf("set on a dead owner: %v", err)
	}
	if _, err := ea.Get(bg, "ns", gone); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Errorf("get on a dead owner: %v", err)
	}
	if _, err := ea.Take(bg, "ns", gone); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Errorf("take on a dead owner: %v", err)
	}
	if err := ea.Delete(bg, "ns", gone); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Errorf("delete on a dead owner: %v", err)
	}
}

func covAudit(t *testing.T, tn *tnode, action string, at time.Time) {
	t.Helper()
	r := &store.Record{Kind: model.KindAudit, ID: newID(), Version: store.Clock.Now(), Scope: "org1", Data: []byte("x"),
		Fields: map[string]any{"action": action, "created": at.UTC().Truncate(time.Microsecond), "actor": "a"}}
	if err := tn.st().Put(bg, r); err != nil {
		t.Fatal(err)
	}
}

// An audit page asks every node for its events and merges them; a node that does not answer is missing from it.
func TestAuditQueryAcrossNodes(t *testing.T) {
	c := covStarted(t)
	base := time.Now().Add(-time.Hour)
	covAudit(t, c.nodes[0], "user.create", base)
	covAudit(t, c.nodes[1], "user.update", base.Add(time.Minute))
	covAudit(t, c.nodes[2], "audit.read", base.Add(2*time.Minute))
	a := c.nodes[0].n

	recs, total, nodes, answered, err := a.AuditQuery(bg, store.ListQuery{Scope: "org1", Limit: 10, Sort: "action"})
	if err != nil || len(recs) != 3 || total != 3 || nodes != 3 || answered != 3 {
		t.Fatalf("%d %d %d %d %v", len(recs), total, nodes, answered, err)
	}
	if recs[0].Fields["action"] != "audit.read" || recs[2].Fields["action"] != "user.update" {
		t.Fatalf("not merged by action: %v %v", recs[0].Fields["action"], recs[2].Fields["action"])
	}
	filtered, total, _, answered, err := a.AuditQuery(bg, store.ListQuery{Scope: "org1", Limit: 10, Desc: true,
		Filters: []store.Filter{{Field: "created", Op: store.OpGTE, Value: base.Add(30 * time.Second)}}})
	if err != nil || len(filtered) != 2 || total != 2 || answered != 3 {
		t.Fatalf("time filter: %d %d %d %v", len(filtered), total, answered, err)
	}
	if filtered[0].Fields["action"] != "audit.read" {
		t.Fatalf("newest first: %v", filtered[0].Fields["action"])
	}

	// A node that cannot answer is left out (after the wait), not an error.
	c.drop(0, 1, true, msgAudit)
	defer c.drop(0, 1, false, msgAudit)
	recs, _, nodes, answered, err = a.AuditQuery(bg, store.ListQuery{Scope: "org1", Limit: 10})
	if err != nil || len(recs) != 2 || nodes != 3 || answered != 2 {
		t.Fatalf("a silent node: %d records, %d of %d answered, %v", len(recs), answered, nodes, err)
	}
	// The caller going away ends the query.
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if _, _, _, _, err := a.AuditQuery(ctx, store.ListQuery{Scope: "org1", Limit: 10}); err == nil {
		t.Fatal("a cancelled query succeeded")
	}
}

// A configuration reload reaches every node in two phases and applies nothing unless every node can.
func TestReloadClusterPhases(t *testing.T) {
	c := covStarted(t)
	type behaviour struct {
		mu        sync.Mutex
		size      int
		checkErr  string
		applyErr  string
		block     chan struct{}
		applied   int
		lastWant  int
		checkRuns int
	}
	bs := make([]*behaviour, 3)
	for i := range bs {
		b := &behaviour{size: 3}
		bs[i] = b
		c.nodes[i].n.SetReloader(func(ctx context.Context, apply bool, want int) ReloadReport {
			b.mu.Lock()
			size, checkErr, applyErr, block := b.size, b.checkErr, b.applyErr, b.block
			b.mu.Unlock()
			if block != nil {
				select {
				case <-block:
				case <-ctx.Done():
				}
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			if !apply {
				b.checkRuns++
				return ReloadReport{Size: size, Error: checkErr}
			}
			b.applied++
			b.lastWant = want
			return ReloadReport{Size: size, Error: applyErr, Changes: []string{"keys"}}
		})
	}
	set := func(i int, f func(*behaviour)) { bs[i].mu.Lock(); f(bs[i]); bs[i].mu.Unlock() }
	a := c.nodes[0].n

	reps, err := a.ReloadCluster(bg)
	if err != nil || len(reps) != 3 {
		t.Fatalf("all agree: %v %v", reps, err)
	}
	for i, b := range bs {
		if b.applied != 1 || b.lastWant != 3 {
			t.Errorf("node %d applied %d times, want size %d", i, b.applied, b.lastWant)
		}
	}
	// Different sizes: nothing is applied.
	set(1, func(b *behaviour) { b.size = 4 })
	if _, err := a.ReloadCluster(bg); err == nil || !strings.Contains(err.Error(), "different sizes") {
		t.Fatalf("%v", err)
	}
	set(1, func(b *behaviour) { b.size = 3; b.checkErr = "unreadable file" })
	if reps, err := a.ReloadCluster(bg); err == nil || !strings.Contains(err.Error(), "nothing was reloaded") ||
		!strings.Contains(err.Error(), "unreadable file") || len(reps) != 3 {
		t.Fatalf("a node that cannot read its configuration: %v", err)
	}
	if bs[2].applied != 1 {
		t.Fatalf("applied despite a failing check: %d", bs[2].applied)
	}
	// A node that fails to apply is reported, and the others have applied.
	set(1, func(b *behaviour) { b.checkErr = ""; b.applyErr = "no space left" })
	if reps, err := a.ReloadCluster(bg); err == nil || !strings.Contains(err.Error(), "not every node reloaded") || len(reps) != 3 {
		t.Fatalf("a node that fails to apply: %v %v", reps, err)
	}
	set(1, func(b *behaviour) { b.applyErr = "" })
	// A node that cannot be reached does not answer.
	c.drop(0, 2, true, msgReload)
	reps, err = a.ReloadCluster(bg)
	if err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("an unreachable node: %v %v", reps, err)
	}
	c.drop(0, 2, false, msgReload)
	// A node that is too slow for the caller's patience.
	release := make(chan struct{})
	set(2, func(b *behaviour) { b.block = release })
	ctx, cancel := context.WithTimeout(bg, 400*time.Millisecond)
	defer cancel()
	reps, err = a.ReloadCluster(ctx)
	close(release)
	if err == nil || !strings.Contains(err.Error(), "nothing was reloaded") {
		t.Fatalf("a slow node: %v %v", reps, err)
	}
	var slow bool
	for _, r := range reps {
		slow = slow || strings.Contains(r.Error, "did not answer")
	}
	if !slow {
		t.Fatalf("the slow node is not reported: %+v", reps)
	}
}

func TestCheckResizeInCluster(t *testing.T) {
	c := covStarted(t)
	a := c.nodes[0].n
	all := c.addrs
	if err := a.CheckResize(3, all); err != nil {
		t.Errorf("the same size: %v", err)
	}
	if err := a.CheckResize(4, all); err == nil || !strings.Contains(err.Error(), "names 2 other nodes") {
		t.Errorf("a size that does not match the peers: %v", err)
	}
	if err := a.CheckResize(1, all[:1]); err == nil || !strings.Contains(err.Error(), "at least 2") {
		t.Errorf("one node: %v", err)
	}
	five := append(append([]string{}, all...), "127.0.0.1:1", "127.0.0.1:2")
	if err := a.CheckResize(5, five); err == nil || !strings.Contains(err.Error(), "one node at a time") {
		t.Errorf("two at once: %v", err)
	}
	if err := a.CheckResize(2, all[:2]); err == nil || !strings.Contains(err.Error(), "shrinking") {
		t.Errorf("shrinking with every node in view: %v", err)
	}
	if err := a.CheckResize(4, append(append([]string{}, all...), "127.0.0.1:1")); err != nil {
		t.Errorf("growing by one with a majority in view: %v", err)
	}
	if changed, err := a.Resize(3, all); err != nil || changed {
		t.Errorf("resize to the same size: %v %v", changed, err)
	}
	if changed, err := a.Resize(5, five); err == nil || changed {
		t.Errorf("an invalid resize: %v %v", changed, err)
	}
}

// A node without a quorum to grow into cannot grow the cluster.
func TestCheckResizeGrowNeedsMajorityInView(t *testing.T) {
	n, _ := gnode(t)
	peers := append(append([]string{}, n.cfg.Cluster.Peers...), "127.0.0.1:1")
	if err := n.CheckResize(4, peers); err == nil || !strings.Contains(err.Error(), "needs 3 of them in view") {
		t.Fatalf("%v", err)
	}
}

// Writes of a quorum kind that the others do not take part in, or take part in late, or only half commit.
func TestQuorumWriteOutcomes(t *testing.T) {
	c := covStarted(t)
	tn := c.nodes[0]
	write := func(name string) error { return users(tn).Create(bg, newUser("org1", name)) }

	// No peer answers the prepare: one grant of the two needed.
	c.drop(0, 1, true, msgPrepare)
	c.drop(0, 2, true, msgPrepare)
	if err := write("no-voters"); !errors.Is(err, store.ErrUnconfirmed) {
		t.Fatalf("no voter answered: %v", err)
	}
	c.drop(0, 1, false, msgPrepare)
	c.drop(0, 2, false, msgPrepare)

	// A record that cannot be put on the wire fails the write before anything is asked of anyone.
	bad := &store.Record{Kind: model.KindUser, ID: newID(), Version: store.Clock.Now(), Scope: "org1", Data: []byte("x"),
		Fields: map[string]any{"f": 1.5}}
	if err := tn.st().Put(bg, bad); err == nil {
		t.Fatal("an unencodable record was written")
	}

	// A duplicate of a unique value is refused (ErrConflict) before the vote.
	if err := write("taken"); err != nil {
		t.Fatal(err)
	}
	if err := write("taken"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a taken username: %v", err)
	}
	// A compare-and-swap of what is not there, and an upsert of what was deleted.
	ghost := mustEncode(t, newUser("org1", "ghost"))
	if err := tn.st().CompareAndPut(bg, ghost, store.Clock.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update of a missing record: %v", err)
	}
	made := newUser("org1", "deleted-then-put")
	if err := users(tn).Create(bg, made); err != nil {
		t.Fatal(err)
	}
	if err := tn.st().Put(bg, &store.Record{Kind: model.KindUser, ID: made.ID, Deleted: true, Version: store.Clock.Now()}); err != nil {
		t.Fatal(err)
	}
	again := mustEncode(t, newUser("org1", "deleted-then-put"))
	again.ID = made.ID
	if err := tn.st().Put(bg, again); !errors.Is(err, store.ErrDeleted) {
		t.Fatalf("an upsert over a deletion: %v", err)
	}

	// The commit reaches no peer: this node applied it, a majority did not.
	c.drop(0, 1, true, msgCommit)
	c.drop(0, 2, true, msgCommit)
	if err := write("half-commit"); !errors.Is(err, store.ErrUnconfirmed) {
		t.Fatalf("a commit no peer applied: %v", err)
	}
	c.drop(0, 1, false, msgCommit)
	c.drop(0, 2, false, msgCommit)

	// Voters whose floor is above the writer's version answer "low": the writer follows the floor and retries.
	floor := hlc.FromTime(time.Now().Add(1500 * time.Millisecond))
	for _, i := range []int{1, 2} {
		v := c.nodes[i].n.voter
		v.mu.Lock()
		v.floor = floor
		v.mu.Unlock()
	}
	if err := write("after-the-floor"); err != nil {
		t.Fatalf("a write below the voters' floor: %v", err)
	}
}

// A record another write holds an intent on stays busy until the writer gives up.
func TestQuorumWriteBusyGivesUp(t *testing.T) {
	c := covStarted(t)
	tn := c.nodes[0]
	u := newUser("org1", "busy-user")
	u.ID = newID()
	for _, i := range []int{1, 2} {
		v := c.nodes[i].n.voter
		v.mu.Lock()
		v.intents[recKey(model.KindUser, u.ID)] = &intent{op: "someone else", version: store.Clock.Now(), exp: time.Now().Add(time.Minute)}
		v.mu.Unlock()
	}
	start := time.Now()
	if err := users(tn).Create(bg, u); !errors.Is(err, store.ErrUnconfirmed) || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("%v", err)
	}
	if time.Since(start) < intentTTL {
		t.Fatalf("gave up after %v", time.Since(start))
	}
	for _, i := range []int{1, 2} {
		v := c.nodes[i].n.voter
		v.mu.Lock()
		delete(v.intents, recKey(model.KindUser, u.ID))
		v.mu.Unlock()
	}
	if err := users(tn).Create(bg, u); err != nil {
		t.Fatalf("once the intents are gone: %v", err)
	}
}

// A deletion a majority did not confirm cannot be undone: it stands, and the caller is told it is unconfirmed.
func TestStrictDurabilityDeletionStands(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	for i := range c.addrs {
		c.nodes = append(c.nodes, c.build(i, "", func(cfg *config.Config) { cfg.Cluster.StrictDurability = true }))
	}
	t.Cleanup(c.closeAll)
	c.start(c.nodes...)
	c.waitReady()
	durable := store.WithDurable(bg)
	rec := newRec(newID(), "")
	if err := c.nodes[0].st().Put(durable, rec); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 15*time.Second, "replicated", func() bool { return allHold(c.nodes, []string{rec.ID}) })
	c.dropPushes(0)
	del := &store.Record{Kind: dataKind, ID: rec.ID, Version: store.Clock.Now(), Deleted: true}
	if err := c.nodes[0].st().Put(durable, del); !errors.Is(err, store.ErrUnconfirmed) {
		t.Fatalf("an unconfirmed deletion: %v", err)
	}
	if has(c.nodes[0].st(), rec.ID) {
		t.Fatal("the deletion was undone")
	}
}

// A node that is slow to answer is missing from the page, not an error: the documented way an audit page treats a
// node that is down or slow (AuditQuery).
func TestAuditQuerySlowNodeIsLeftOut(t *testing.T) {
	c := covStarted(t)
	covAudit(t, c.nodes[0], "user.create", time.Now())
	covAudit(t, c.nodes[1], "user.update", time.Now())
	ns := c.net(0)
	ns.mu.Lock()
	ns.slowMsg, ns.slowBy = msgAudit, time.Minute
	ns.mu.Unlock()
	defer func() { ns.mu.Lock(); ns.slowBy = 0; ns.mu.Unlock() }()
	recs, _, nodes, answered, err := c.nodes[0].n.AuditQuery(bg, store.ListQuery{Scope: "org1", Limit: 10})
	if err != nil {
		t.Fatalf("a slow node failed the page: %v", err)
	}
	if len(recs) != 1 || nodes != 3 || answered != 1 {
		t.Fatalf("%d records, %d of %d answered", len(recs), answered, nodes)
	}
}
