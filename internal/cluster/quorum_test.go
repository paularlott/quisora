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
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// drop stops (or restarts) the given message types from node i to node j (one direction).
func (c *tcluster) drop(i, j int, on bool, types ...gossip.MessageType) {
	ns := c.net(i)
	ns.mu.Lock()
	defer ns.mu.Unlock()
	to := c.addrs[j]
	if ns.dropTo[to] == nil {
		ns.dropTo[to] = map[gossip.MessageType]bool{}
	}
	for _, mt := range types {
		ns.dropTo[to][mt] = on
	}
}

// lagBehind makes node i miss every change the others make (no broadcast, push, prepare or commit reaches it, and it
// cannot pull their feeds), while it stays in view and can still send its own prepares and read their answers.
func (c *tcluster) lagBehind(i int, on bool) {
	for j := range c.addrs {
		if j == i {
			continue
		}
		c.drop(j, i, on, msgRecord, msgPush, msgPrepare, msgCommit)
		c.drop(i, j, on, msgFeed)
	}
}

func users(tn *tnode) *store.Table[model.User, *model.User] {
	return store.NewTable[model.User](tn.st())
}

func newUser(org, name string) *model.User {
	return &model.User{OrgID: org, Username: name, Email: name + "@example.com", Role: model.RoleUser, Active: true}
}

// waitUser waits until every node holds the user at version v.
func (c *tcluster) waitUser(t *testing.T, id string, ok func(u *model.User) bool) {
	t.Helper()
	waitFor(t, 15*time.Second, "user "+id+" everywhere", func() bool {
		for _, tn := range c.nodes {
			u, err := users(tn).Get(bg, id)
			if err != nil || !ok(u) {
				return false
			}
		}
		return true
	})
}

// A1 (lost update): an administrator disables a user on node 0, confirmed by a majority, while node 1 — which has
// not received that change yet — rewrites the whole user record from its older copy (a sign-in stamp, before those
// left the user record). Under last-writer-wins node 1's newer write erased the disabling everywhere. With the quorum
// compare-and-swap node 1's write is refused (stale) by the voters that hold the change, its copy is repaired, and the
// user stays disabled on every node.
func TestQuorumCASPreventsLostUpdate(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	u := newUser("org1", "alice")
	if err := users(c.nodes[0]).Create(bg, u); err != nil {
		t.Fatal(err)
	}
	c.waitUser(t, u.ID, func(x *model.User) bool { return x.Version == u.Version })
	stale, _ := users(c.nodes[1]).Get(bg, u.ID)

	c.lagBehind(1, true)
	admin, _ := users(c.nodes[0]).Get(bg, u.ID)
	admin.Active = false
	if err := users(c.nodes[0]).Update(store.WithDurable(bg), admin); err != nil {
		t.Fatalf("the administrator's change: %v", err)
	}
	if r, _ := users(c.nodes[1]).Get(bg, u.ID); !r.Active {
		t.Fatal("test set-up: node 1 must not have the change yet")
	}
	stale.GivenName = "signed in"
	err := users(c.nodes[1]).Update(bg, stale)
	if !errors.Is(err, store.ErrStale) {
		t.Fatalf("a write from an outdated copy: %v, want store.ErrStale", err)
	}
	if r, _ := users(c.nodes[1]).Get(bg, u.ID); r.Active || r.Version != admin.Version {
		t.Fatal("the refused writer's copy was not repaired")
	}
	c.lagBehind(1, false)
	time.Sleep(time.Second) // a few sync rounds
	c.waitUser(t, u.ID, func(x *model.User) bool { return !x.Active && x.GivenName == "" && x.Version == admin.Version })
	if c.nodes[1].n.Status().Refused == 0 {
		t.Fatal("the refusal was not counted")
	}
}

// A1: two nodes update one record concurrently from the same copy, many times over: exactly one of each pair
// succeeds, the other is refused as stale, and every node ends with the successful one.
func TestQuorumCASConcurrentUpdates(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	u := newUser("org1", "bob")
	if err := users(c.nodes[0]).Create(bg, u); err != nil {
		t.Fatal(err)
	}
	for round := range 15 {
		c.waitUser(t, u.ID, func(x *model.User) bool { return x.Version == u.Version })
		var wg sync.WaitGroup
		errs := make([]error, 2)
		wrote := make([]*model.User, 2)
		for i := range 2 {
			x, _ := users(c.nodes[i]).Get(bg, u.ID)
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
			case errors.Is(err, store.ErrStale), errors.Is(err, store.ErrUnconfirmed):
			default:
				t.Fatalf("round %d node %d: %v", round, i, err)
			}
		}
		if ok > 1 {
			t.Fatalf("round %d: both concurrent updates from one copy succeeded", round)
		}
		if ok == 0 {
			x, _ := users(c.nodes[0]).Get(bg, u.ID)
			u = x
			continue
		}
		want := u.GivenName
		c.waitUser(t, u.ID, func(x *model.User) bool { return x.GivenName == want })
	}
}

// A1: the TOTP step is a cluster-wide create-once / compare-and-swap. The same code presented on two nodes at once is
// accepted once; presented again on a node that has not received the first use yet, it is refused.
func TestTOTPStepReplayAcrossNodes(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 1
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svcs := []*service.Service{service.New(cfg, c.nodes[0].st(), sealer), service.New(cfg, c.nodes[1].st(), sealer)}
	u := newUser("org1", "carol")
	if err := users(c.nodes[0]).Create(bg, u); err != nil {
		t.Fatal(err)
	}
	c.waitUser(t, u.ID, func(*model.User) bool { return true })
	secret := secure.NewTOTPSecret()
	for round := range 3 {
		now := time.Now().Add(time.Duration(round*90) * time.Second)
		code := secure.TOTPCode(secret, now)
		var accepted atomic.Int64
		var wg sync.WaitGroup
		for _, s := range svcs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if s.ConsumeTOTPAt(bg, u, secret, code, now) {
					accepted.Add(1)
				}
			}()
		}
		wg.Wait()
		if accepted.Load() != 1 {
			t.Fatalf("round %d: a code presented on two nodes at once was accepted %d times", round, accepted.Load())
		}
	}
	// node 1 lags: it has not received the use of the next code on node 0, and is presented the same code
	waitFor(t, 10*time.Second, "sign-in record everywhere", func() bool {
		_, err := c.nodes[2].st().Get(bg, model.KindSignIn, u.ID)
		return err == nil
	})
	c.lagBehind(1, true)
	now := time.Now().Add(5 * 90 * time.Second)
	code := secure.TOTPCode(secret, now)
	if !svcs[0].ConsumeTOTPAt(bg, u, secret, code, now) {
		t.Fatal("a fresh code was refused")
	}
	if svcs[1].ConsumeTOTPAt(bg, u, secret, code, now) {
		t.Fatal("a code already used on node 0 was accepted again on node 1 (cross-node replay)")
	}
	c.lagBehind(1, false)
}

// A2: a long-standing user and a user created later elsewhere (a provisioning push on a node that had not received
// the first one's address) claim one email address. The user created first keeps it — however recently it was
// changed or signed in; the other is kept (never deleted), the address is removed from it, it is flagged and the
// change is audited.
func TestUniqueClashKeepsFirstClaim(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 1
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	var svcs []*service.Service
	for _, tn := range c.nodes {
		s := service.New(cfg, tn.st(), sealer)
		s.Writable = tn.n.Writable
		tn.n.OnConflict(func(loser *store.Record) { go s.ResolveUniqueClash(bg, loser.Kind, loser.ID) })
		svcs = append(svcs, s)
	}
	c.lagBehind(1, true)
	old := newUser("org1", "dave")
	if err := users(c.nodes[0]).Create(bg, old); err != nil {
		t.Fatal(err)
	}
	svcs[0].TouchLogin(bg, old) // signs in: the user record is not rewritten
	old.GivenName = "updated since"
	if err := users(c.nodes[0]).Update(bg, old); err != nil { // and an edit: a newer version than the clash
		t.Fatal(err)
	}
	if _, err := users(c.nodes[1]).Get(bg, old.ID); err == nil {
		t.Fatal("test set-up: node 1 must not have the first user")
	}
	scim := newUser("org1", "dave-scim")
	scim.Email = old.Email
	if err := users(c.nodes[1]).Create(bg, scim); err != nil {
		t.Fatalf("the later create on node 1: %v", err)
	}
	c.lagBehind(1, false)
	waitFor(t, 20*time.Second, "the clash resolved everywhere", func() bool {
		for _, tn := range c.nodes {
			holder, err := tn.st().GetByUnique(bg, model.KindUser, model.UserEmailKey("org1", old.Email))
			if err != nil || holder.ID != old.ID {
				return false
			}
			s, err := users(tn).Get(bg, scim.ID)
			if err != nil || s.Email != "" || s.Conflict == "" {
				return false
			}
			if o, err := users(tn).Get(bg, old.ID); err != nil || o.Email != old.Email || o.Conflict != "" {
				return false
			}
		}
		return true
	})
	// Audit events stay on the node that records them: the clash is audited by a node that resolved it.
	audited := false
	for _, s := range svcs {
		audits, _, _ := s.Audits.List(bg, store.ListQuery{Scope: "org1", Filters: []store.Filter{{Field: "action", Value: "unique.conflict"}}})
		audited = audited || len(audits) > 0
	}
	if !audited {
		t.Fatal("the clash was not audited")
	}
}

// A3: a membership is revoked on node 0 (durable) at a later real time than it was re-added on node 2, but node 2's
// clock is fast so its re-addition carries the newer version. The re-addition's generation is the deletion it had
// seen (the earlier one): the revocation it had not seen wins on every node, whatever the versions say. (The nodes of
// this test share one process clock, so node 2's skew is made larger than MaxSkew — 40 s rather than the 5 s
// reported — to keep the shared clock from following it; the rule does not depend on the size of the skew.)
func TestRevocationBeatsReAddFromFastNode(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	members := func(tn *tnode) *store.Table[model.Member, *model.Member] {
		return store.NewTable[model.Member](tn.st())
	}
	m := &model.Member{Meta: model.Meta{ID: model.MemberID("g1", "u1")}, GroupID: "g1", UserID: "u1", OrgID: "org1"}
	if err := members(c.nodes[0]).Create(bg, m); err != nil {
		t.Fatal(err)
	}
	if err := members(c.nodes[0]).Delete(bg, m.ID); err != nil {
		t.Fatal(err)
	}
	var first *store.Record
	waitFor(t, 10*time.Second, "first removal everywhere", func() bool {
		for _, tn := range c.nodes {
			r, err := tn.st().Lookup(bg, model.KindMember, m.ID)
			if err != nil || !r.Deleted {
				return false
			}
			first = r
		}
		return true
	})
	// Node 2, its clock fast, adds the member again: a re-creation of the deletion it saw.
	c.dropData(2, true)
	readd := *m
	readd.Version = hlc.FromTime(time.Now().Add(40 * time.Second))
	rec, _ := store.EncodeAsIs(&readd)
	rec.Origin, rec.Epoch, rec.Created = c.nodes[2].n.ID(), first.Version, readd.Version
	if _, err := c.nodes[2].st().applyReplica(bg, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := members(c.nodes[2]).Get(bg, m.ID); err != nil {
		t.Fatal("test set-up: node 2 holds the re-added member")
	}
	time.Sleep(50 * time.Millisecond)
	// Later in real time, node 0 (which has not seen the re-addition) revokes it.
	if err := members(c.nodes[0]).Delete(store.WithDurable(bg), m.ID); err != nil {
		t.Fatal(err)
	}
	revoke, _ := c.nodes[0].st().Lookup(bg, model.KindMember, m.ID)
	if revoke.Version >= rec.Version {
		t.Fatal("test set-up: the revocation must carry the older version")
	}
	c.dropData(2, false)
	time.Sleep(time.Second)
	waitFor(t, 15*time.Second, "revocation everywhere", func() bool {
		for _, tn := range c.nodes {
			if _, err := members(tn).Get(bg, m.ID); err == nil {
				return false
			}
		}
		return true
	})
}

// A4: a durable write is acknowledged only by peers that applied exactly that version. Peers holding a newer version
// do not apply it and say so: the write is counted as unconfirmed and the refusals are surfaced.
func TestDurablePushAckOnlyWhenApplied(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	id := newID()
	newer := newRec(id, "")
	newer.Version = store.Clock.Now()
	for _, tn := range c.nodes[1:] {
		if _, _, err := tn.st().Inner().PutReplicated(bg, newer); err != nil {
			t.Fatal(err)
		}
	}
	older := newRec(id, "")
	older.Version = newer.Version - 1000
	if err := c.nodes[0].st().Put(store.WithDurable(bg), older); err != nil {
		t.Fatal(err)
	}
	st := c.nodes[0].n.Status()
	if st.Unconfirmed != 1 || st.Refused < 2 {
		t.Fatalf("a push the peers did not apply was counted as confirmed: unconfirmed %d, refused %d", st.Unconfirmed,
			st.Refused)
	}
	if c.nodes[1].n.applyPush(older) != pushSuperseded {
		t.Fatal("a superseded push must say so")
	}
	if c.nodes[1].n.applyPush(newer) != pushApplied {
		t.Fatal("a push of the version held is an acknowledgement")
	}
}

// A5: an empty replacement node holds no write of its own, so it must catch up with enough complete peers to share
// one with every majority (two of a three-node cluster), not count itself. Here it can first reach only the one node
// that missed a write the other two confirmed: it must not serve until it also reached the other.
func TestEmptyReplacementNeedsCompletePeers(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	c.dropData(2, true) // node 2 misses the next write
	w := newRec(newID(), "")
	if err := c.nodes[0].st().Put(store.WithDurable(bg), w); err != nil {
		t.Fatal(err)
	}
	if !has(c.nodes[1].st(), w.ID) || has(c.nodes[2].st(), w.ID) {
		t.Fatal("test set-up: nodes 0 and 1 confirm the write, node 2 lacks it")
	}
	stop(c.nodes[1]) // node 1's disk is lost
	c.dropData(2, false)
	c.dropDataBetween(0, 2, true) // node 2 still lacks the write
	c.dropDataBetween(0, 1, true) // and the replacement reaches only node 2
	c.nodes[1] = c.build(1, "", nil)
	c.start(c.nodes[1])
	e := c.nodes[1]
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if ok, _ := e.n.Ready(); ok {
			t.Fatalf("the replacement serves after copying from one node (holds the confirmed write: %v)", has(e.st(), w.ID))
		}
		time.Sleep(50 * time.Millisecond)
	}
	c.heal()
	waitFor(t, 20*time.Second, "replacement ready with the write", func() bool {
		ok, _ := e.n.Ready()
		return ok && has(e.st(), w.ID)
	})
}

// A7: hash-routed counters (rate limits, lockouts) and single-use ids fail closed: when the owner cannot be reached
// the operation fails instead of counting on this node alone; and a node that does not serve owns nothing.
func TestCountersFailClosed(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
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
	c.nodes[1].n.misconfig.Store(&why)
	c.nodes[1].n.rebuild()
	waitFor(t, 10*time.Second, "node 0 sees node 1 not serving", func() bool {
		owner, _, _ := c.nodes[0].n.OwnerOf("rate", key)
		return owner != c.nodes[1].n.ID()
	})
	if _, err := eph.Incr(bg, "rate", key, 1, time.Minute); err != nil {
		t.Fatalf("counter on the new owner: %v", err)
	}
	c.nodes[1].n.misconfig.Store(nil)
	c.nodes[1].n.rebuild()
}

// A8: nodes sharing one database without gossip elect a housekeeper with a lease. A node that lost the lease (it
// stalled past its expiry and another node took over) has its housekeeping writes refused: the lease generation it
// started under is no longer the current one.
func TestHousekeepingFencedAfterLeaseLoss(t *testing.T) {
	saved := [3]time.Duration{leaseTTL, leaseRenew, leaseMargin}
	leaseTTL, leaseRenew, leaseMargin = 600*time.Millisecond, time.Hour, 100*time.Millisecond
	t.Cleanup(func() { leaseTTL, leaseRenew, leaseMargin = saved[0], saved[1], saved[2] })
	shared := memstore.New()
	mk := func() *Node {
		cfg := config.Default()
		cfg.Server.DataDir = t.TempDir()
		cfg.Storage.Backend = "postgres" // a database server the nodes share (not opened: the store is given)
		n, err := New(cfg, shared, Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		return n
	}
	a, b := mk(), mk()
	if err := a.lease.tick(bg); err != nil || !a.IsLeader() {
		t.Fatalf("a takes the lease: %v", err)
	}
	ctx := a.fence(bg)
	if err := a.Store().Put(ctx, newRec(newID(), "")); err != nil {
		t.Fatalf("the holder's housekeeping write: %v", err)
	}
	time.Sleep(700 * time.Millisecond) // a stalls past its lease
	if err := b.lease.tick(bg); err != nil || !b.IsLeader() {
		t.Fatalf("b takes over: %v", err)
	}
	a.lease.until.Store(time.Now().Add(time.Hour).UnixNano()) // a's clock (or pause) makes it believe it still leads
	if err := a.Store().Put(ctx, newRec(newID(), "")); !errors.Is(err, store.ErrNotWritable) {
		t.Fatalf("a housekeeping write after the lease passed on: %v", err)
	}
	if err := b.Store().Put(b.fence(bg), newRec(newID(), "")); err != nil {
		t.Fatalf("the new holder's housekeeping write: %v", err)
	}
	if err := a.Store().Put(bg, newRec(newID(), "")); err != nil {
		t.Fatalf("an ordinary (unfenced) write: %v", err)
	}
}

// A9: two administrators of an organization are demoted at once on two different nodes. The last-admin guard is a
// cluster-wide lock plus a count from a quorum's copies: at most one demotion succeeds, and the organization always
// keeps an active administrator.
func TestLastAdminGuardIsClusterWide(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 1
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svcs := []*service.Service{service.New(cfg, c.nodes[0].st(), sealer), service.New(cfg, c.nodes[1].st(), sealer)}
	admin, user := model.RoleAdmin, model.RoleUser
	for round := range 4 {
		name := fmt.Sprintf("org-%d", round)
		org, err := svcs[0].CreateOrg(bg, service.System, service.OrgInput{Name: &name})
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for i := range 2 {
			un, em := fmt.Sprintf("admin%d", i), fmt.Sprintf("admin%d@example.com", i)
			u, err := svcs[0].CreateUser(bg, service.System, org.ID, service.UserInput{Username: &un, Email: &em,
				GivenName: &un, Role: &admin})
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, u.ID)
		}
		for _, id := range ids {
			c.waitUser(t, id, func(u *model.User) bool { return u.Role == model.RoleAdmin && u.Active })
		}
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = svcs[i].UpdateUser(bg, service.System, ids[i], service.UserInput{Role: &user})
			}()
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			} else if !errors.Is(err, service.ErrLastAdmin) && !errors.Is(err, service.ErrUnavailable) &&
				!errors.Is(err, service.ErrStale) {
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if ok > 1 {
			t.Fatalf("round %d: both administrators were demoted", round)
		}
		time.Sleep(500 * time.Millisecond)
		for i, tn := range c.nodes {
			n := 0
			for _, id := range ids {
				if u, err := users(tn).Get(bg, id); err == nil && u.Role == model.RoleAdmin && u.Active {
					n++
				}
			}
			if n == 0 {
				t.Fatalf("round %d: node %d sees the organization without an administrator", round, i)
			}
		}
	}
}

// A9b: as A9, with two administrators deleting each other at once on two nodes: at most one deletion succeeds, and
// the organization always keeps an active administrator.
func TestLastAdminDeleteIsClusterWide(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 1
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svcs := []*service.Service{service.New(cfg, c.nodes[0].st(), sealer), service.New(cfg, c.nodes[1].st(), sealer)}
	admin := model.RoleAdmin
	for round := range 3 {
		name := fmt.Sprintf("org-%d", round)
		org, err := svcs[0].CreateOrg(bg, service.System, service.OrgInput{Name: &name})
		if err != nil {
			t.Fatal(err)
		}
		var us []*model.User
		for i := range 2 {
			un, em := fmt.Sprintf("admin%d", i), fmt.Sprintf("admin%d@example.com", i)
			u, err := svcs[0].CreateUser(bg, service.System, org.ID, service.UserInput{Username: &un, Email: &em,
				GivenName: &un, Role: &admin})
			if err != nil {
				t.Fatal(err)
			}
			us = append(us, u)
		}
		for _, u := range us {
			c.waitUser(t, u.ID, func(u *model.User) bool { return u.Role == model.RoleAdmin && u.Active })
		}
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// each administrator deletes the other, on their own node
				errs[i] = svcs[i].DeleteUser(bg, service.ActorForUser(us[i], ""), us[1-i].ID)
			}()
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			} else if !errors.Is(err, service.ErrLastAdmin) && !errors.Is(err, service.ErrUnavailable) &&
				!errors.Is(err, service.ErrStale) {
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if ok > 1 {
			t.Fatalf("round %d: both administrators were deleted", round)
		}
		time.Sleep(500 * time.Millisecond)
		for i, tn := range c.nodes {
			n := 0
			for _, u := range us {
				if cur, err := users(tn).Get(bg, u.ID); err == nil && cur.Role == model.RoleAdmin && cur.Active {
					n++
				}
			}
			if n == 0 {
				t.Fatalf("round %d: node %d sees the organization without an administrator", round, i)
			}
		}
	}
}

// A10: a node refuses to start on a clock set before the version clock's epoch; a version far ahead of this node's
// clock is applied but not followed (counted), so this node's own versions do not inherit the skew.
func TestClockGuards(t *testing.T) {
	saved := wallNow
	wallNow = func() time.Time { return time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC) }
	if _, err := New(tempConfig(t), memstore.New(), Options{}); !errors.Is(err, ErrClockBeforeEpoch) {
		t.Fatalf("a clock before the epoch: %v", err)
	}
	wallNow = saved
	n, err := New(tempConfig(t), memstore.New(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	before := store.SkewRefused()
	far := newRec(newID(), "")
	far.Version = hlc.FromTime(time.Now().Add(time.Hour))
	if applied, err := n.st.applyReplica(bg, far); err != nil || !applied {
		t.Fatalf("a far-ahead record: %v %v", applied, err)
	}
	if store.SkewRefused() <= before || n.Status().ClockSkewed == 0 || n.Status().SkewRefused == 0 {
		t.Fatal("the skew was not counted")
	}
	if v := store.Clock.Now(); v >= far.Version {
		t.Fatal("the clock followed a version an hour ahead")
	}
}

// Every node must be configured with the same cluster.size: a node that sees a member advertising another size
// refuses to serve until they agree. A configuration whose size does not match its peers list is refused at once.
func TestClusterSizeMustAgree(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	cfg := c.config(0, t.TempDir())
	cfg.Cluster.Size = 4
	if _, err := New(cfg, memstore.New(), fastOptions()); err == nil {
		t.Fatal("cluster.size that does not match the peers list was accepted")
	}
	for i := range c.addrs {
		c.nodes = append(c.nodes, c.build(i, "", nil))
	}
	t.Cleanup(c.closeAll)
	c.start(c.nodes...)
	c.waitReady()
	if st := c.nodes[0].n.Status(); st.Size != 3 || st.Quorum != 2 {
		t.Fatalf("status: size %d quorum %d", st.Size, st.Quorum)
	}
	c.nodes[2].n.gc.LocalMetadata().SetInt(metaSize, 5) // node 2 configured with another size
	waitFor(t, 10*time.Second, "mismatch refused", func() bool {
		ok, why := c.nodes[0].n.Ready()
		return !ok && !c.nodes[0].n.Writable() && len(why) > 0
	})
	c.nodes[2].n.gc.LocalMetadata().SetInt(metaSize, 3)
	c.waitReady()
}

// A node of an incompatible build (here: one from before compatibility was published, or too new) makes the others
// refuse to serve and drop its messages until it is gone or upgraded.
func TestIncompatiblePeerRefused(t *testing.T) {
	for _, tc := range []struct{ c, min int }{{0, 0}, {compat + 2, compat + 1}} {
		if compatible(tc.c, tc.min) {
			t.Fatalf("compat %d/%d accepted", tc.c, tc.min)
		}
	}
	if !compatible(compat, minCompat) || !compatible(compat+1, compat) {
		t.Fatal("this build, or the next one keeping this as its minimum, refused")
	}
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	md := c.nodes[2].n.gc.LocalMetadata()
	md.SetInt(metaCompat, 0) // an older build
	md.SetInt(metaMinCompat, 0)
	waitFor(t, 10*time.Second, "incompatible peer refused", func() bool {
		ok, why := c.nodes[0].n.Ready()
		return !ok && !c.nodes[0].n.Writable() && strings.Contains(why, "cannot work with")
	})
	md.SetInt(metaCompat, compat)
	md.SetInt(metaMinCompat, minCompat)
	c.waitReady()
}

// The quorum is the configured size's majority and never shrinks: with two of three nodes stopped (they left), the
// survivor is not writable, whatever it observed before.
func TestQuorumNeverShrinks(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	stop(c.nodes[1])
	waitFor(t, 15*time.Second, "one down", func() bool { return c.nodes[0].n.Status().Alive == 2 })
	if !c.nodes[0].n.Writable() {
		t.Fatal("two of three must be writable")
	}
	stop(c.nodes[2])
	time.Sleep(6 * time.Second) // well past failure detection and the leader's stability period
	if c.nodes[0].n.Writable() || c.nodes[0].n.IsLeader() || c.nodes[0].n.Quorum() != 2 {
		t.Fatal("the quorum shrank after nodes left")
	}
	if err := c.nodes[0].st().Put(bg, newRec(newID(), "")); !errors.Is(err, store.ErrNotWritable) {
		t.Fatalf("a write without a quorum: %v", err)
	}
}

// A5 (formation only): a node is an origin for new nodes only while its cluster is forming. Once it has seen a
// quorum of nodes ready it records that the cluster has formed (cluster-state.json, kept across restarts) and is
// never an origin again — not after losing the quorum, not after a restart — so an empty node joining a formed
// cluster always catches up with size-quorum+1 caught-up peers.
func TestOriginOnlyWhileForming(t *testing.T) {
	c := newTCluster(t, 3, badgerBackend)
	c.startAll()
	c.waitReady()
	waitFor(t, 10*time.Second, "formed everywhere", func() bool {
		for _, tn := range c.nodes {
			if !tn.n.formed.Load() || tn.n.origin() {
				return false
			}
		}
		return true
	})
	c.partition([]int{0, 1}, []int{2})
	waitFor(t, 30*time.Second, "minority", func() bool { return !c.nodes[2].n.Writable() })
	if c.nodes[2].n.origin() {
		t.Fatal("a node cut off from a formed cluster is an origin")
	}
	c.heal()
	c.waitReady()
	dir := c.nodes[2].dir
	stop(c.nodes[2])
	c.nodes[2] = c.build(2, dir, nil)
	if !c.nodes[2].n.formed.Load() {
		t.Fatal("the formed cluster was forgotten across a restart")
	}
	c.start(c.nodes[2])
	c.waitReady()
	if c.nodes[2].n.origin() {
		t.Fatal("a restarted node of a formed cluster is an origin")
	}
}

// A5 (formation): a confirmed quorum write proves the cluster has formed, even when the readiness the nodes gossip
// never lets a node see a ready quorum (it can lag under load). Without such a view no node is formed after the
// cluster starts; once each node has completed one durable write that a quorum applied, every node is formed and
// none is an origin, so a node cut off from the majority seeds nobody.
func TestConfirmedWriteFormsCluster(t *testing.T) {
	c := newTCluster(t, 5, memBackend)
	for i := range 3 {
		tn := c.build(i, "", nil)
		tn.n.blindReadiness.Store(true)
		c.nodes = append(c.nodes, tn)
	}
	t.Cleanup(c.closeAll)
	c.start(c.nodes...)
	c.waitReady()
	time.Sleep(time.Second) // several rebuild rounds
	for i, tn := range c.nodes {
		if tn.n.formed.Load() {
			t.Fatalf("test set-up: node %d formed without seeing a ready quorum or a confirmed write", i)
		}
	}
	for i, tn := range c.nodes {
		if err := users(tn).Create(bg, newUser("org1", fmt.Sprintf("former%d", i))); err != nil {
			t.Fatalf("durable write on node %d: %v", i, err)
		}
		if !tn.n.formed.Load() {
			t.Fatalf("node %d completed a confirmed quorum write but the cluster has not formed", i)
		}
	}
	for i, tn := range c.nodes {
		if !tn.n.formed.Load() || tn.n.origin() {
			t.Fatalf("node %d: formed=%v origin=%v, want formed and not an origin", i, tn.n.formed.Load(), tn.n.origin())
		}
	}

	c.partition([]int{0, 1}, []int{2, 3})
	waitFor(t, 30*time.Second, "minority", func() bool { return !c.nodes[2].n.Writable() })
	fresh := c.build(3, "", nil)
	c.nodes = append(c.nodes, fresh)
	c.start(fresh)
	time.Sleep(3 * time.Second)
	if countAll(fresh.st()) != 0 || !fresh.n.bootstrap.Load() || fresh.n.ServesTokens() {
		t.Fatal("a node cut off from the majority seeded a new node")
	}
	if c.nodes[2].n.origin() {
		t.Fatal("the cut-off node is an origin")
	}
}
