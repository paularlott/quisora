package cluster

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
)

// Hash-routed and node-owned ephemeral state on one healthy cluster (BadgerDB). The last scenario stops a node.
func TestEphemeralOnOneCluster(t *testing.T) {
	runOn(t, started(t, badgerBackend()),
		scenario{"counters fail closed", testCountersFailClosed},
		scenario{"counter reads use the owner's last answer", testCounterReadsUseTheOwnersLastAnswer},
		scenario{"forwarded to the owner", testEphemeralForwardedToOwner})
}

// Ephemeral state is forwarded to the node that owns it; a node that is gone owns nothing any more.
func testEphemeralForwardedToOwner(t *testing.T, c *tcluster) {
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
	budget := b.eph.local.Budget
	b.eph.local.Budget = 1
	err = ea.Set(bg, "ns", id, make([]byte, 4096), time.Minute)
	if err == nil || errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("a refused remote set: %v", err)
	}
	b.eph.local.Budget = budget

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

// Hash-routed counters (rate limits, lockouts) and single-use ids fail closed: when the owner cannot be reached
// the operation fails instead of counting on this node alone; and a node that does not serve owns nothing.
func testCountersFailClosed(t *testing.T, c *tcluster) {
	waitFor(t, 10*time.Second, "everyone sees everyone ready", func() bool {
		for _, tn := range c.nodes {
			for _, mb := range tn.n.mem.Load().routable {
				if !mb.ready {
					return false
				}
			}
		}
		return true
	})
	var key string
	for i := range 1000 {
		k := fmt.Sprintf("login|ip-%d", i)
		if owner, _, _ := c.nodes[0].n.OwnerOf("rate", k); owner == c.nodes[1].n.ID() {
			key = k
			break
		}
	}
	if key == "" {
		t.Fatal("no key owned by node 1")
	}
	eph := c.nodes[0].n.Ephemeral()
	if n, err := eph.Incr(bg, "rate", key, 1, time.Minute); err != nil || n != 1 {
		t.Fatalf("counter on its owner: %d %v", n, err)
	}
	var jti string
	for i := range 1000 {
		k := fmt.Sprintf("client|jti-%d", i)
		if owner, _, _ := c.nodes[0].n.OwnerOf("jti", k); owner == c.nodes[1].n.ID() {
			jti = k
			break
		}
	}
	c.drop(0, 1, true, msgEph)
	if _, err := eph.Incr(bg, "rate", key, 1, time.Minute); err == nil {
		t.Fatal("a counter whose owner is unreachable counted locally (fails open)")
	}
	if _, err := eph.Incr(bg, "jti", jti, 1, time.Minute); err == nil {
		t.Fatal("a single-use id whose owner is unreachable was accepted")
	}
	c.drop(0, 1, false, msgEph)
	// node 1 stops serving (here: misconfigured): it owns nothing any more
	why := "test: not serving"
	c.nodes[1].n.mixed.Store(&why)
	c.nodes[1].n.rebuild()
	waitFor(t, 10*time.Second, "node 0 sees node 1 not serving", func() bool {
		owner, _, _ := c.nodes[0].n.OwnerOf("rate", key)
		return owner != c.nodes[1].n.ID()
	})
	if _, err := eph.Incr(bg, "rate", key, 1, time.Minute); err != nil {
		t.Fatalf("counter on the new owner: %v", err)
	}
	c.nodes[1].n.mixed.Store(nil)
	c.nodes[1].n.rebuild()
}

// A counter read on a node that does not own the counter is answered from the owner's last answer for up to
// counterReadTTL (no round trip on the requests that pass a limit), and every attempt that counts goes to the owner
// and refreshes it: a node lets at most one attempt past a limit reached through other nodes before it refuses too.
// (A counter starts again when its owner changes, as when gossip suspects a node under load: the scenario is then
// run again on a fresh key.)
func testCounterReadsUseTheOwnersLastAnswer(t *testing.T, c *tcluster) {
	reader := c.nodes[0].n
	er := reader.Ephemeral()
	ownerOf := func(key string) *Node {
		mb := reader.hrw("rl", key)
		if mb == nil || mb.id == reader.ID() {
			return nil
		}
		for _, tn := range c.nodes {
			if tn.n.ID() == mb.id {
				return tn.n
			}
		}
		return nil
	}
	scenario := func(key string, owner *Node) (string, bool) {
		if n, err := er.Incr(bg, "rl", key, 0, time.Minute); err != nil || n != 0 {
			return "first read: " + strconv.FormatInt(n, 10), true
		}
		// attempts counted through other nodes: the reader's remembered answer does not see them yet...
		if _, err := owner.eph.local.Incr(bg, "rl", key, 5, time.Minute); err != nil {
			return err.Error(), true
		}
		if n, _ := er.Incr(bg, "rl", key, 0, time.Minute); n != 0 {
			return "a read within the TTL went to the owner: " + strconv.FormatInt(n, 10), true
		}
		// ...until the reader's own attempt, which the owner counts and answers with the true value
		if n, err := er.Incr(bg, "rl", key, 1, time.Minute); err != nil || n != 6 {
			return "counted attempt: " + strconv.FormatInt(n, 10), true
		}
		if n, _ := er.Incr(bg, "rl", key, 0, time.Minute); n != 6 {
			return "a read after the attempt: " + strconv.FormatInt(n, 10), true
		}
		// and past the TTL a read asks the owner again
		if _, err := owner.eph.local.Incr(bg, "rl", key, 1, time.Minute); err != nil {
			return err.Error(), true
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if n, _ := er.Incr(bg, "rl", key, 0, time.Minute); n == 7 {
				return "", false
			}
			time.Sleep(50 * time.Millisecond)
		}
		return "the remembered answer did not expire", true
	}
	for i, tries := 0, 0; tries < 5; i++ {
		key := "k" + strconv.Itoa(i)
		owner := ownerOf(key)
		if owner == nil {
			continue
		}
		tries++
		failure, failed := scenario(key, owner)
		if !failed {
			return
		}
		if ownerOf(key) == owner {
			t.Fatal(failure) // the owner did not change: the failure is real
		}
		t.Logf("the counter's owner changed mid-way (%s): again on a fresh key", failure)
	}
	t.Fatal("the counters' owners kept changing")
}

func TestGossipNodeEphemeralWithoutOwner(t *testing.T) {
	n, _ := gnode(t)
	e := n.Ephemeral()
	// Nothing serves yet (this node has no quorum), so hash-routed state has no owner and everything fails closed.
	if _, err := e.Incr(bg, "rl", "k", 1, time.Minute); !errors.Is(err, errNoOwner) {
		t.Errorf("Incr: %v", err)
	}
	if err := e.Set(bg, "ns", "plain-id", []byte("v"), time.Minute); !errors.Is(err, errNoOwner) {
		t.Errorf("Set: %v", err)
	}
	if _, err := e.Get(bg, "ns", "plain-id"); !errors.Is(err, errNoOwner) {
		t.Errorf("Get: %v", err)
	}
	if _, err := e.Take(bg, "ns", "plain-id"); !errors.Is(err, errNoOwner) {
		t.Errorf("Take: %v", err)
	}
	if err := e.Delete(bg, "ns", "plain-id"); !errors.Is(err, errNoOwner) {
		t.Errorf("Delete: %v", err)
	}
	if id, local, dead := n.OwnerOf("ns", "plain-id"); id != "" || local || !dead {
		t.Errorf("OwnerOf: %q %v %v", id, local, dead)
	}
	// An id this node minted is owned by it, whatever the cluster looks like.
	id, err := e.New(bg, "ns", []byte("v1"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if owner, local, dead := n.OwnerOf("ns", id); owner != n.ID() || !local || dead {
		t.Errorf("OwnerOf own id: %q %v %v", owner, local, dead)
	}
	if err := e.Set(bg, "ns", id, []byte("v2"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if v, err := e.Get(bg, "ns", id); err != nil || string(v) != "v2" {
		t.Fatalf("%q %v", v, err)
	}
	if v, err := e.Take(bg, "ns", id); err != nil || string(v) != "v2" {
		t.Fatalf("%q %v", v, err)
	}
	if err := e.Delete(bg, "ns", id); err != nil {
		t.Fatal(err)
	}
}

func TestStandaloneEphemeralDirect(t *testing.T) {
	n, _ := hnode(t)
	e := n.Ephemeral()
	id, err := e.New(bg, "ns", []byte("a"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Set(bg, "ns", id, []byte("b"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if v, err := e.Get(bg, "ns", id); err != nil || string(v) != "b" {
		t.Fatalf("%q %v", v, err)
	}
	if err := e.Delete(bg, "ns", id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Get(bg, "ns", id); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("%v", err)
	}
	if ok, why := n.Ready(); !ok {
		t.Fatalf("a standalone node is ready: %s", why)
	}
	n.rebuild() // nothing to rebuild without gossip
	n.publishReady()
}

func TestHandleEphOperations(t *testing.T) {
	n, _ := hnode(t)
	call := func(req ephReq) *ephResp {
		t.Helper()
		r, err := n.handleEph(nil, packetOf(t, &req))
		if err != nil {
			t.Fatal(err)
		}
		return r.(*ephResp)
	}
	id, err := n.eph.local.New(bg, "ns", []byte("v0"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if r := call(ephReq{Op: opSet, NS: "ns", ID: id, Val: []byte("v1"), TTL: 60000}); r.Code != codeOK {
		t.Fatalf("set: %+v", r)
	}
	if r := call(ephReq{Op: opGet, NS: "ns", ID: id}); r.Code != codeOK || string(r.Val) != "v1" {
		t.Fatalf("get: %+v", r)
	}
	if r := call(ephReq{Op: opIncr, NS: "rl", ID: "k", Delta: 3, TTL: 60000}); r.Code != codeOK || r.N != 3 {
		t.Fatalf("incr: %+v", r)
	}
	if r := call(ephReq{Op: opTake, NS: "ns", ID: id}); r.Code != codeOK || string(r.Val) != "v1" {
		t.Fatalf("take: %+v", r)
	}
	if r := call(ephReq{Op: opTake, NS: "ns", ID: id}); r.Code != codeNotFound {
		t.Fatalf("take again: %+v", r)
	}
	if r := call(ephReq{Op: opGet, NS: "ns", ID: "missing"}); r.Code != codeNotFound {
		t.Fatalf("get missing: %+v", r)
	}
	if r := call(ephReq{Op: opSet, NS: "ns", ID: id, Val: []byte("again"), TTL: 60000}); r.Code != codeOK {
		t.Fatalf("set: %+v", r)
	}
	if r := call(ephReq{Op: opDelete, NS: "ns", ID: id}); r.Code != codeOK {
		t.Fatalf("delete: %+v", r)
	}
	if r := call(ephReq{Op: 99, NS: "ns", ID: id}); r.Code != codeError || !strings.Contains(r.Err, "unknown ephemeral op") {
		t.Fatalf("unknown op: %+v", r)
	}
	// the namespace is the caller's, an empty one too: the owner keeps it apart from the others
	if r := call(ephReq{Op: opSet, NS: "", ID: id, Val: []byte("x"), TTL: 60000}); r.Code != codeOK {
		t.Fatalf("set without a namespace: %+v", r)
	}
	if r := call(ephReq{Op: opGet, NS: "", ID: id}); r.Code != codeOK || string(r.Val) != "x" {
		t.Fatalf("get without a namespace: %+v", r)
	}
	if r := call(ephReq{Op: opGet, NS: "ns", ID: id}); r.Code != codeNotFound {
		t.Fatalf("the namespaces kept apart: %+v", r)
	}
	if _, err := n.handleEph(nil, badPacket(t)); err == nil {
		t.Error("a bad payload was accepted")
	}
	// A node that does not serve answers for no hash-routed state (a counter, an id without an owner prefix).
	why := "misconfigured"
	n.mixed.Store(&why)
	if r := call(ephReq{Op: opIncr, NS: "rl", ID: "k", Delta: 1, TTL: 60000}); r.Code != codeError || !strings.Contains(r.Err, "does not serve") {
		t.Fatalf("incr on a node that does not serve: %+v", r)
	}
	if r := call(ephReq{Op: opGet, NS: "ns", ID: "no-owner-prefix"}); r.Code != codeError {
		t.Fatalf("get of a hash-routed id on a node that does not serve: %+v", r)
	}
	if r := call(ephReq{Op: opGet, NS: "ns", ID: ephemeral.Owner(id) + "." + "zzz"}); r.Code == codeError && strings.Contains(r.Err, "does not serve") {
		t.Fatalf("an id this node owns is answered whatever its readiness: %+v", r)
	}
}
