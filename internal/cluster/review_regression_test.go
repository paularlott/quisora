package cluster

// Regression tests from the external code reviews, one per finding: each states the failure it guards against.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/codec/shamaton"
	"github.com/paularlott/gossip/compression/snappy"
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

type deepDesignDeleteFailure struct {
	store.Store
	fail atomic.Bool
}

func (s *deepDesignDeleteFailure) PutReplicated(ctx context.Context, rec *store.Record) (bool, []string, error) {
	if rec.Deleted && s.fail.Load() {
		return false, nil, errors.New("review: deletion commit storage failure")
	}
	return s.Store.PutReplicated(ctx, rec)
}

// A deletion prepares A/B but only commits A. A subsequent update succeeds at
// B/C with a higher Version. B retained its high-water mark throughout, without
// restarting. The documented partial-write recovery guarantee requires that the
// confirmed update rank above the earlier partial deletion when A reconnects.
func TestDeepDesignPartialDeletionCannotEraseLaterConfirmedUpdate(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	failing := &deepDesignDeleteFailure{Store: memstore.New()}
	c.mks = map[int]backend{1: func(testing.TB, string) store.Store { return failing }}
	c.startAll()
	c.waitReady()
	u := newUser("org1", "partial-deletion")
	if err := users(c.nodes[0]).Create(bg, u); err != nil {
		t.Fatal(err)
	}
	c.waitUser(t, u.ID, func(x *model.User) bool { return x.Version == u.Version })
	later, err := users(c.nodes[2]).Get(bg, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Only B may join A's prepare quorum; broadcasts and anti-entropy must not
	// deliver A's partial deletion to B/C before the subsequent update.
	c.drop(0, 2, true, msgPrepare)
	for _, i := range []int{1, 2} {
		c.drop(0, i, true, msgRecord, msgPush)
		c.drop(i, 0, true, msgFeed)
	}
	failing.fail.Store(true)
	err = users(c.nodes[0]).Delete(bg, u.ID)
	failing.fail.Store(false)
	if !errors.Is(err, store.ErrUnconfirmed) {
		t.Fatalf("partial deletion: %v, want ErrUnconfirmed", err)
	}
	partial, err := c.nodes[0].st().Lookup(bg, model.KindUser, u.ID)
	if err != nil || !partial.Deleted {
		t.Fatalf("A must hold the partial tombstone: %v, %#v", err, partial)
	}
	// The later caller starts after the deletion already returned failure.
	// Only B may join C's quorum; B holds the old base and the deletion's hw.
	c.drop(2, 0, true, msgPrepare)
	later.GivenName = "confirmed after partial deletion"
	if err := users(c.nodes[2]).Update(bg, later); err != nil {
		t.Fatalf("later update should be confirmed at B/C: %v", err)
	}
	if later.Version <= partial.Version {
		t.Fatalf("later version %d did not exceed partial deletion %d", later.Version, partial.Version)
	}
	for _, i := range []int{1, 2} {
		got, err := users(c.nodes[i]).Get(bg, u.ID)
		if err != nil || got.Version != later.Version {
			t.Fatalf("node %d must hold confirmed update: %v, %#v", i, err, got)
		}
	}
	// Deliver precisely the record A's normal anti-entropy would send upon heal.
	for _, i := range []int{1, 2} {
		if _, err := c.nodes[i].st().applyReplica(bg, partial); err != nil {
			t.Fatal(err)
		}
		if _, err := users(c.nodes[i]).Get(bg, u.ID); errors.Is(err, store.ErrNotFound) {
			t.Fatalf("old partial deletion erased later quorum-confirmed update on node %d despite retained high-water mark and higher update version", i)
		} else if err != nil {
			t.Fatal(err)
		}
	}
}

func TestDeepReviewConditionalDeleteChecksExpectedVersion(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	table := users(c.nodes[0])
	u := newUser("org1", "conditional-delete")
	if err := table.Create(bg, u); err != nil {
		t.Fatal(err)
	}
	expected := u.Version
	u.GivenName = "Changed after decision"
	if err := table.Update(bg, u); err != nil {
		t.Fatal(err)
	}
	if err := table.DeleteIf(bg, u.ID, expected); !errors.Is(err, store.ErrStale) {
		t.Fatalf("conditional deletion ignored stale expected version: got %v, want ErrStale", err)
	}
}

type deepPromotionDeleteGate struct {
	store.Store
	id           string
	fired        atomic.Bool
	beforeDelete func()
}

func (g *deepPromotionDeleteGate) CompareAndPut(ctx context.Context, r *store.Record, expected hlc.Timestamp) error {
	if r.Deleted && r.Kind == model.KindUser && r.ID == g.id && g.fired.CompareAndSwap(false, true) {
		g.beforeDelete()
	}
	return g.Store.CompareAndPut(ctx, r, expected)
}
func TestDeepReviewDeleteUserRechecksConcurrentPromotion(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svc := service.New(config.Default(), c.nodes[0].st(), sealer)
	if _, _, err := svc.Bootstrap(bg, "root@example.test"); err != nil {
		t.Fatal(err)
	}
	org, err := svc.PrimaryOrg(bg)
	if err != nil {
		t.Fatal(err)
	}
	makeUser := func(name string, role model.Role) *model.User {
		email := name + "@example.test"
		u, err := svc.CreateUser(bg, service.System, org.ID, service.UserInput{Username: &name, GivenName: &name, Email: &email, Role: &role})
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	admin := makeUser("admin", model.RoleAdmin)
	target := makeUser("target", model.RoleUser)
	svc.MinSuperAdmins = 2
	gate := &deepPromotionDeleteGate{Store: svc.Users.S, id: target.ID}
	gate.beforeDelete = func() {
		role := model.RoleSuperAdmin
		if _, err := svc.UpdateUser(bg, service.System, target.ID, service.UserInput{Role: &role}); err != nil {
			t.Error(err)
		}
	}
	svc.Users.S = gate
	if err := svc.DeleteUser(bg, service.ActorForUser(admin, ""), target.ID); err == nil {
		t.Fatal("ordinary admin deleted concurrently promoted super admin without rechecking permissions or last-admin guard")
	}
}

type deepReviewReadFailure struct {
	store.Store
	fail atomic.Bool
}

func (s *deepReviewReadFailure) Lookup(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == model.KindUser && s.fail.Load() {
		return nil, errors.New("review: backend I/O failure")
	}
	return s.Store.Lookup(ctx, kind, id)
}

// A responder with an unreadable record is not a successful quorum read. In
// particular, its missing response must not certify a lagging caller's old user.
func TestDeepReviewQuorumReadFailsClosedOnPeerStorageError(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	failing := &deepReviewReadFailure{Store: memstore.New()}
	c.mks = map[int]backend{2: func(testing.TB, string) store.Store { return failing }}
	c.startAll()
	c.waitReady()
	u := newUser("org1", "deep-read")
	if err := users(c.nodes[0]).Create(bg, u); err != nil {
		t.Fatal(err)
	}
	c.waitUser(t, u.ID, func(x *model.User) bool { return x.Version == u.Version })
	c.lagBehind(1, true)
	u.Active = false
	if err := users(c.nodes[0]).Update(bg, u); err != nil {
		t.Fatal(err)
	}
	failing.fail.Store(true)
	defer failing.fail.Store(false)
	c.drop(1, 0, true, msgRead)
	// Node 0 cannot be reached and node 2 cannot read the record: only node 1 itself answers, short of a quorum.
	recs, err := c.nodes[1].st().Fresh(bg, model.KindUser, []string{u.ID})
	if errors.Is(err, store.ErrUnconfirmed) {
		return
	}
	if err != nil {
		t.Fatalf("quorum read: %v, want ErrUnconfirmed", err)
	}
	got := &model.User{}
	if err := store.Decode(recs[u.ID], got); err != nil {
		t.Fatal(err)
	}
	t.Fatalf("quorum read succeeded without a quorum of answers (active=%v): a voter that could not read its copy "+
		"was counted", got.Active)
}

// quorumWrite keeps one operation id across retries. An abort emitted while
// settling an older attempt can arrive after the voter granted the next stamp.
// Such an abort must not cancel the newer attempt's valid commit intent.
func TestDeepReviewDelayedAbortDoesNotReleaseRetryIntent(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	v := c.nodes[2].n.voter
	u := newUser("org1", "deep-retry")
	first, err := store.Encode(u)
	if err != nil {
		t.Fatal(err)
	}
	base := store.Rank{}
	if err := store.StampLocal(first, nil, true); err != nil {
		t.Fatal(err)
	}
	if r := v.prepare(bg, "same-write", first, modeMatch, base); r.St != stGrant {
		t.Fatalf("first prepare: %d", r.St)
	}
	second := *first
	second.Version = store.Clock.Now()
	second.Created = second.Version
	if r := v.prepare(bg, "same-write", &second, modeMatch, base); r.St != stGrant {
		t.Fatalf("retry prepare: %d", r.St)
	}
	v.release("same-write", first.Version) // delayed abort for the first stamp
	if st := v.commit(bg, "same-write", &second, false); st != stGrant {
		t.Fatalf("delayed abort of previous attempt canceled newer granted retry; commit status %d", st)
	}
}

// A failed quorum member must not let a second administrator removal pass on
// a node that missed the first confirmed removal.
func TestDeepReviewLastAdminGuardFailsClosedOnPeerStorageError(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	failing := &deepReviewReadFailure{Store: memstore.New()}
	c.mks = map[int]backend{2: func(testing.TB, string) store.Store { return failing }}
	c.startAll()
	c.waitReady()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svcs := []*service.Service{service.New(config.Default(), c.nodes[0].st(), sealer), service.New(config.Default(), c.nodes[1].st(), sealer)}
	for _, s := range svcs {
		s.MinSuperAdmins = 2
	}
	root, _, err := svcs[0].Bootstrap(bg, "deep-root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	primary, err := svcs[0].PrimaryOrg(bg)
	if err != nil {
		t.Fatal(err)
	}
	all := []*model.User{root}
	role := model.RoleSuperAdmin
	for _, name := range []string{"deep-super-one", "deep-super-two"} {
		email := name + "@example.com"
		u, err := svcs[0].CreateUser(bg, service.System, primary.ID, service.UserInput{Username: &name, Email: &email, GivenName: &name, Role: &role})
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, u)
	}
	for _, u := range all {
		c.waitUser(t, u.ID, func(x *model.User) bool { return x.Active && x.Role == role })
	}
	c.lagBehind(1, true)
	active := false
	if _, err := svcs[0].UpdateUser(bg, service.System, all[1].ID, service.UserInput{Active: &active}); err != nil {
		t.Fatal(err)
	}
	failing.fail.Store(true)
	defer failing.fail.Store(false)
	c.drop(1, 0, true, msgRead)
	_, err = svcs[1].UpdateUser(bg, service.System, all[2].ID, service.UserInput{Active: &active})
	if err == nil {
		t.Fatal("second super-admin disable succeeded despite only two usable super admins remaining; guard counted a failed read as quorum evidence")
	}
}

// Nodes in these tests normally share the process HLC. This test supplies the independent clocks of a restarted
// process and a third writer, while the first writer's clock runs ahead (as far as a voter allows, voteAhead). The
// voter that granted the fast partial write restarts with nothing on disk: its restart pause (restartPause, at least
// voteAhead) must keep it out until its clock is past the partial version, so the later confirmed write outranks it.
// Timings are scaled down from seconds to milliseconds.
func TestDeepReviewRestartCannotLoseGrantedVersionFloor(t *testing.T) {
	defer func(a, p time.Duration) { voteAhead, restartPause = a, p }(voteAhead, restartPause)
	voteAhead, restartPause = 300*time.Millisecond, 0
	var ns []*Node
	for range 3 {
		n, err := New(tempConfig(t), memstore.New(), Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		n.voter = newVoter(n)
		n.voter.floor = hlc.NewClock().Now()
		ns = append(ns, n)
	}
	u := newUser("org1", "deep-crash")
	initial, err := store.Encode(u)
	if err != nil {
		t.Fatal(err)
	}
	// From the wall clock, not the process clock other tests may have moved ahead: the bounds below are wall-clock.
	initial.Version = hlc.FromTime(time.Now())
	initial.Created = initial.Version
	for _, n := range ns {
		if _, _, err := n.st.inner.PutReplicated(bg, initial); err != nil {
			t.Fatal(err)
		}
	}
	base := initial.Rank()
	// A version further ahead than voteAhead is granted nowhere.
	tooFast := *initial
	tooFast.Version = hlc.FromTime(time.Now().Add(2 * voteAhead))
	if r := ns[1].voter.prepare(bg, "too-fast", &tooFast, modeMatch, base); r.St == stGrant {
		t.Fatal("granted a version further ahead than voteAhead")
	}
	// A fast writer within the bound prepares at A and B, and only A commits before it fails.
	old := *initial
	old.Version = max(hlc.FromTime(time.Now().Add(voteAhead*9/10)), initial.Version+2)
	for _, i := range []int{0, 1} {
		if r := ns[i].voter.prepare(bg, "partial", &old, modeMatch, base); r.St != stGrant {
			t.Fatalf("old prepare %d: %d", i, r.St)
		}
	}
	if st := ns[0].voter.commit(bg, "partial", &old, true); st != stGrant {
		t.Fatalf("partial commit: %d", st)
	}
	// B restarts: its high-water marks and its clock's memory are gone, and nothing about the grant is on disk.
	restartPause = voteAhead
	ns[1].voter = newVoter(ns[1])
	ns[1].voter.floor = hlc.NewClock().Now()
	disabled := *u
	disabled.Active = false
	newer, err := store.EncodeAsIs(&disabled)
	if err != nil {
		t.Fatal(err)
	}
	newer.Created = initial.Created
	newer.Version = max(initial.Version+1, hlc.NewClock().Now())
	if r := ns[1].voter.prepare(bg, "confirmed", newer, modeMatch, base); r.St != stNotReady {
		t.Fatalf("a voter in its restart pause answered %d, want not ready", r.St)
	}
	time.Sleep(restartPause)
	// A writer's fresh clock now mints a version past the partial one; B and C confirm it.
	newer.Version = max(initial.Version+1, hlc.NewClock().Now())
	if newer.Version <= old.Version {
		t.Fatalf("after the restart pause a fresh clock (%d) is still behind the partial version (%d)", newer.Version, old.Version)
	}
	for _, i := range []int{1, 2} {
		if r := ns[i].voter.prepare(bg, "confirmed", newer, modeMatch, base); r.St != stGrant {
			t.Fatalf("new prepare %d: %d", i, r.St)
		}
	}
	for _, i := range []int{1, 2} {
		if st := ns[i].voter.commit(bg, "confirmed", newer, true); st != stGrant {
			t.Fatalf("new quorum commit %d: %d", i, st)
		}
	}
	// A's old partial write is disseminated later by anti-entropy.
	if _, err := ns[1].st.applyReplica(bg, &old); err != nil {
		t.Fatal(err)
	}
	got, err := users(&tnode{n: ns[1]}).Get(bg, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Active {
		t.Fatal("old fast-clock partial write overwrote quorum-confirmed disable after intersecting voter restarted")
	}
}

// In a three-node cluster, the local healthy clock and the other healthy node
// outvote a single skewed node. The skewed node must not disable both healthy voters.
func TestFreshTwoHealthyClocksOutvoteOneSkewedPeer(t *testing.T) {
	n := voterNode(t)
	now := time.Now()
	n.clockReading("healthy-peer", now, now, now.UnixNano())
	n.clockReading("skewed-peer", now, now, now.Add(time.Minute).UnixNano())
	if why := n.clockOff.Load(); why != nil {
		t.Fatalf("healthy majority refused to serve: %s", *why)
	}
}

func TestFreshReviewQuorumBatchFitsDefaultTransport(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	randomText := func(n int) string {
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)[:n]
	}
	const n = 6000 // below the production orphan sweep's 20,000-record batch
	ids := make([]string, 0, n)
	resp := &struct{ Recs [][]byte }{} // the size the reply would have as one packet
	for i := range n {
		u := &model.User{Meta: model.Meta{ID: model.NewID()}, OrgID: "org", Username: fmt.Sprintf("user-%06d", i), Email: fmt.Sprintf("user-%06d@example.test", i), GivenName: randomText(100), FamilyName: randomText(100), ExternalID: randomText(255), Active: true}
		u.Work.Title = randomText(255)
		u.Work.Department = randomText(255)
		u.Work.Organization = randomText(255)
		u.Work.Division = randomText(255)
		u.Work.CostCenter = randomText(255)
		u.Work.EmployeeNumber = randomText(255)
		rec, err := store.Encode(u)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, u.ID)
		b, err := encodeRecord(rec)
		if err != nil {
			t.Fatal(err)
		}
		resp.Recs = append(resp.Recs, b)
		for _, tn := range c.nodes {
			if err := tn.st().inner.Put(bg, rec); err != nil {
				t.Fatal(err)
			}
		}
	}
	encoded, err := shamaton.New().Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := snappy.New().Compress(encoded)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("users=%d raw response=%d compressed response=%d default TCPMaxPacketSize=%d", n, len(encoded), len(compressed), gossip.DefaultConfig().TCPMaxPacketSize)
	if _, err := c.nodes[0].st().Fresh(bg, model.KindUser, ids[:100]); err != nil {
		t.Fatalf("small read failed: %v", err)
	}
	if got, err := c.nodes[0].st().Fresh(bg, model.KindUser, ids); err != nil {
		t.Fatalf("supported sweep-sized batch failed (received %d users): %v", len(got), err)
	}
}

type fresh6PartialReadFailure struct {
	store.Store
	fail atomic.Bool
}

// A stream dial uses the transport's dial timeout, not the request's context.
// Fresh must still stop awaiting replies when its caller's deadline expires.
func TestFresh6QuorumReadHonorsDeadlineDuringStreamDial(t *testing.T) {
	var slow atomic.Bool
	c := newTCluster(t, 3, memBackend)
	c.opts = func(o *Options) {
		o.Gossip = func(cfg *gossip.Config) {
			fastGossip(cfg)
			cfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
				if !slow.Load() {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(250 * time.Millisecond):
					return nil, errors.New("review: dial timed out")
				}
			}
		}
	}
	c.startAll()
	c.waitReady()
	slow.Store(true)
	defer slow.Store(false)
	ctx, cancel := context.WithTimeout(bg, 25*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.nodes[0].st().Fresh(ctx, model.KindUser, []string{"deadline-user"})
	if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
		t.Fatalf("quorum read ignored 25ms deadline for %s: %v", elapsed, err)
	}
}

func (s *fresh6PartialReadFailure) Lookup(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == model.KindUser && id == "stream-fault" && s.fail.Load() {
		return nil, errors.New("review: fault after earlier streamed records")
	}
	return s.Store.Lookup(ctx, kind, id)
}

// The first record is big enough to flush transport frames before the second
// lookup fails. A complete-looking first record must not count as a peer answer.
func TestFresh6PartialStreamDoesNotCountAsQuorumAnswer(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	fault := &fresh6PartialReadFailure{Store: memstore.New()}
	c.mks = map[int]backend{2: func(testing.TB, string) store.Store { return fault }}
	c.startAll()
	c.waitReady()
	ids := []string{"stream-first", "stream-fault"}
	for _, id := range ids {
		u := &model.User{Meta: model.Meta{ID: id}, OrgID: "org", Username: id, Active: true, GivenName: strings.Repeat("a", 100_000)}
		r, err := store.Encode(u)
		if err != nil {
			t.Fatal(err)
		}
		for _, tn := range c.nodes {
			if err := tn.st().inner.Put(bg, r); err != nil {
				t.Fatal(err)
			}
		}
	}
	fault.fail.Store(true)
	defer fault.fail.Store(false)
	c.drop(0, 1, true, msgRead)
	if _, err := c.nodes[0].st().Fresh(bg, model.KindUser, ids); !errors.Is(err, store.ErrUnconfirmed) {
		t.Fatalf("partial stream certified a read: %v", err)
	}
	c.drop(0, 1, false, msgRead)
	got, err := c.nodes[0].st().Fresh(bg, model.KindUser, ids)
	if err != nil || len(got) != len(ids) {
		t.Fatalf("healthy peer could not supply quorum after partial-stream failure: records=%d err=%v", len(got), err)
	}
}

// A blind deletion of a record absent on the writer carries its own Version as
// Epoch. The scalar quorum high-water mark cannot make a later create outrank it.
func TestFreshPartialBlindDeletionCannotEraseConfirmedCreate(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	failing := &deepDesignDeleteFailure{Store: memstore.New()}
	c.mks = map[int]backend{1: func(testing.TB, string) store.Store { return failing }}
	c.startAll()
	c.waitReady()
	u := newUser("org1", "create-after-partial-blind-delete")
	u.ID = model.NewID()
	c.drop(0, 2, true, msgPrepare)
	for _, i := range []int{1, 2} {
		c.drop(0, i, true, msgRecord, msgPush)
		c.drop(i, 0, true, msgFeed)
	}
	failing.fail.Store(true)
	err := users(c.nodes[0]).Delete(bg, u.ID) // absent everywhere
	failing.fail.Store(false)
	if !errors.Is(err, store.ErrUnconfirmed) {
		t.Fatalf("partial blind deletion: %v", err)
	}
	partial, err := c.nodes[0].st().Lookup(bg, model.KindUser, u.ID)
	if err != nil || !partial.Deleted {
		t.Fatalf("partial deletion missing: %v %+v", err, partial)
	}
	c.drop(2, 0, true, msgPrepare)
	if err := users(c.nodes[2]).Create(bg, u); err != nil {
		t.Fatalf("later quorum create failed: %v", err)
	}
	if u.Version <= partial.Version {
		t.Fatal("create version did not advance past deletion")
	}
	for _, i := range []int{1, 2} {
		if _, err := users(c.nodes[i]).Get(bg, u.ID); err != nil {
			t.Fatalf("confirmed create absent before healing: %v", err)
		}
	}
	for _, i := range []int{1, 2} {
		if _, err := c.nodes[i].st().applyReplica(bg, partial); err != nil {
			t.Fatal(err)
		}
		if _, err := users(c.nodes[i]).Get(bg, u.ID); err != nil {
			t.Fatalf("older partial blind deletion erased later quorum-confirmed create on node%d: %v", i, err)
		}
	}
}

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

// A crash can occur before the ten-second prune loop saves an unapplied deletion.
// Waiting out a restart pause raises versions, but cannot recover its lost epoch.
func TestRound3PartialDeletionMarkSurvivesImmediateVoterRestart(t *testing.T) {
	var nodes []*Node
	for range 3 {
		n, err := New(tempConfig(t), memstore.New(), Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { n.Close() })
		n.voter = newVoter(n)
		nodes = append(nodes, n)
	}
	u := newUser("org1", "immediate-voter-restart")
	initial, err := store.Encode(u)
	if err != nil {
		t.Fatal(err)
	}
	initial.Created = initial.Version
	for _, n := range nodes {
		if _, _, err := n.st.inner.PutReplicated(bg, initial); err != nil {
			t.Fatal(err)
		}
	}
	deletion := store.Tombstone(model.KindUser, u.ID)
	for _, i := range []int{0, 1} {
		if r := nodes[i].voter.prepare(bg, "partial-delete", deletion, modeBlind, initial.Rank()); r.St != stGrant {
			t.Fatalf("prepare deletion node%d: %+v", i, r)
		}
	}
	if st := nodes[0].voter.commit(bg, "partial-delete", deletion, true); st != stGrant {
		t.Fatalf("partial commit: %d", st)
	}
	// Restart before intentTTL; the store and directory survive, RAM does not.
	previousPause := restartPause
	restartPause = 25 * time.Millisecond
	nodes[1].voter = newVoter(nodes[1])
	restartPause = previousPause
	time.Sleep(30 * time.Millisecond)
	changed := *u
	changed.GivenName = "Later confirmed profile"
	encoded, err := store.Encode(&changed)
	if err != nil {
		t.Fatal(err)
	}
	later := *encoded
	later.Created = initial.Created
	// A voter may answer low (its floor is past every version it granted before its restart); the writer then
	// stamps past the floor and prepares again, as quorumWrite does.
	for attempt := 0; ; attempt++ {
		var floor uint64
		for _, i := range []int{1, 2} {
			switch r := nodes[i].voter.prepare(bg, "later-confirmed", &later, modeMatch, initial.Rank()); r.St {
			case stGrant:
			case stLow:
				floor = max(floor, r.Floor)
			default:
				t.Fatalf("later prepare node%d: %+v", i, r)
			}
		}
		if floor == 0 {
			break
		}
		if attempt > 0 {
			t.Fatalf("later prepare still low after re-stamping past floor %d", floor)
		}
		later.Version = hlc.Timestamp(floor) + 1
	}
	for _, i := range []int{1, 2} {
		if st := nodes[i].voter.commit(bg, "later-confirmed", &later, true); st != stGrant {
			t.Fatalf("later commit node%d: %d", i, st)
		}
	}
	if _, err := nodes[1].st.applyReplica(bg, deletion); err != nil {
		t.Fatal(err)
	}
	if _, err := nodes[1].st.Get(bg, model.KindUser, u.ID); err != nil {
		t.Fatalf("unsaved deletion mark vanished on restart; old partial deletion erased later quorum-confirmed write: %v", err)
	}
}
