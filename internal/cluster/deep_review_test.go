package cluster

import (
	"context"
	"errors"
	"github.com/paularlott/gossip/hlc"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

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
	recs, err := c.nodes[1].st().Fresh(bg, model.KindUser, []string{u.ID})
	if err != nil {
		return
	}
	got := &model.User{}
	if err := store.Decode(recs[u.ID], got); err != nil {
		t.Fatal(err)
	}
	if got.Active {
		t.Fatal("quorum read certified stale active user after intersecting voter could not read its disabled copy")
	}
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

// Nodes in these tests normally share the process HLC. This test supplies the
// independent normal-clock stamps a restarted process and a third writer would
// use, while the first writer is 20 seconds fast (inside store.MaxSkew).
func TestDeepReviewRestartCannotLoseGrantedVersionFloor(t *testing.T) {
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
	initial.Created = initial.Version
	for _, n := range ns {
		if _, _, err := n.st.inner.PutReplicated(bg, initial); err != nil {
			t.Fatal(err)
		}
	}
	base := initial.Rank()
	old := *initial
	old.Version = max(hlc.FromTime(time.Now().Add(20*time.Second)), initial.Version+2)
	// First operation prepares a majority but only A commits before failure.
	for _, i := range []int{0, 1} {
		if r := ns[i].voter.prepare(bg, "partial", &old, modeMatch, base); r.St != stGrant {
			t.Fatalf("old prepare %d: %d", i, r.St)
		}
	}
	if st := ns[0].voter.commit(bg, "partial", &old, true); st != stGrant {
		t.Fatalf("partial commit: %d", st)
	}
	// B restarts; its durable store still has the base. It can catch up from C,
	// which also has the base. A process restart loses the witnessed HLC and hw map.
	ns[1].voter = newVoter(ns[1])
	ns[1].voter.floor = hlc.NewClock().Now()
	disabled := *u
	disabled.Active = false
	newer, err := store.EncodeAsIs(&disabled)
	if err != nil {
		t.Fatal(err)
	}
	newer.Version = max(initial.Version+1, hlc.NewClock().Now())
	newer.Created = initial.Created
	if newer.Version >= old.Version {
		t.Fatal("test requires fast partial version above normal new version")
	}
	// The restarted voter may refuse the stamp as low (its persisted ceiling covers the version it granted before
	// the restart); the writer then stamps past the floor and prepares again, as quorumWrite does.
	for attempt := 0; ; attempt++ {
		var floor uint64
		for _, i := range []int{1, 2} {
			switch r := ns[i].voter.prepare(bg, "confirmed", newer, modeMatch, base); r.St {
			case stGrant:
			case stLow:
				floor = max(floor, r.Floor)
			default:
				t.Fatalf("new prepare %d: %d", i, r.St)
			}
		}
		if floor == 0 {
			break
		}
		if attempt > 0 {
			t.Fatalf("new prepare still low after re-stamping past floor %d", floor)
		}
		newer.Version = hlc.Timestamp(floor) + 1
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
		t.Fatal("old fast-clock partial write overwrote quorum-confirmed disable after intersecting voter restarted and lost its granted version floor")
	}
}
