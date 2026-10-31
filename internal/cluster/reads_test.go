package cluster

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/partition"
	"github.com/paularlott/quisora/internal/cluster/clustertest"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Fresh reads on one healthy cluster (BadgerDB).
func TestReadsOnOneCluster(t *testing.T) {
	runOn(t, started(t, badgerBackend()),
		scenario{"fresh reads see what this node lacks", testFreshReadsSeeWhatThisNodeLacks},
		scenario{"fresh read of a large batch", testFreshReadOfALargeBatch},
		scenario{"fresh read honours the caller's deadline", testFreshReadHonoursTheCallersDeadline})
}

// A fresh read goes through the owner: a node that has not applied a write yet, or has never heard of the record, still
// sees it, and sees a deletion.
func testFreshReadsSeeWhatThisNodeLacks(t *testing.T, c *tcluster) {
	org, _ := c.orgNotOwnedBy(1)
	first := newUser(org, "first")
	if err := users(c.nodes[0]).Create(bg, first); err != nil {
		t.Fatal(err)
	}
	c.waitUser(t, first.ID, func(*model.User) bool { return true })

	c.lagBehind(1, true)
	defer c.lagBehind(1, false)
	n1 := c.nodes[1].st()
	second := newUser(org, "second")
	if err := users(c.nodes[0]).Create(bg, second); err != nil {
		t.Fatal(err)
	}
	changed, err := users(c.nodes[0]).Get(bg, first.ID)
	if err != nil {
		t.Fatalf("node 0's copy: %v", err)
	}
	changed.GivenName = "changed"
	if err := users(c.nodes[0]).Update(bg, changed); err != nil {
		t.Fatal(err)
	}
	if _, err := n1.Get(bg, model.KindUser, second.ID); err == nil {
		t.Fatal("test set-up: node 1 must not have the new user")
	}
	got, err := n1.Fresh(bg, model.KindUser, []string{first.ID, second.ID, "missing"})
	if err != nil || len(got) != 2 || got[first.ID].Version != changed.Version || got[second.ID] == nil {
		t.Fatalf("fresh read on a node that lags: %v %v", got, err)
	}
	if err := users(c.nodes[0]).Delete(bg, second.ID); err != nil {
		t.Fatal(err)
	}
	got, err = n1.Fresh(bg, model.KindUser, []string{second.ID})
	if err != nil || got[second.ID] == nil || !got[second.ID].Deleted {
		t.Fatalf("a deletion is seen as a tombstone: %v %v", got[second.ID], err)
	}
	// A kind known to live in one partition is asked of its owner only: organizations are global.
	if _, err := n1.Fresh(bg, model.KindOrg, []string{"nope"}); err != nil {
		t.Fatal(err)
	}
	if got, err := n1.Fresh(bg, model.KindUser, nil); err != nil || len(got) != 0 {
		t.Fatalf("no ids: %v %v", got, err)
	}
}

// A fresh read of more records than one reply holds (maxReadReply: a sweep's batch of users, say) is answered whole:
// the owner refuses a reply that does not fit, and the reader asks for halves until each does.
func testFreshReadOfALargeBatch(t *testing.T, c *tcluster) {
	saved := maxReadReply
	maxReadReply = 64 << 10
	t.Cleanup(func() { maxReadReply = saved })
	ids := make([]string, 300)
	size := 0
	for i := range ids {
		u := newUser("org-batch", fmt.Sprintf("user-%03d", i))
		u.ID = model.NewID()
		u.Work.Title = strings.Repeat("x", 1000)
		rec, err := store.Encode(u)
		if err != nil {
			t.Fatal(err)
		}
		b, err := encodeRecord(rec)
		if err != nil {
			t.Fatal(err)
		}
		size += len(b)
		for _, tn := range c.nodes { // (as the owner holds them: a read asks the owner)
			if _, err := tn.st().inner.PutReplicated(bg, rec); err != nil {
				t.Fatal(err)
			}
		}
		ids[i] = u.ID
	}
	if size < 4*maxReadReply {
		t.Fatalf("test set-up: the batch (%d bytes) needs fewer than four replies", size)
	}
	got, err := c.nodes[0].st().Fresh(bg, model.KindUser, ids)
	if err != nil || len(got) != len(ids) {
		t.Fatalf("a batch larger than a reply: %d of %d records, %v", len(got), len(ids), err)
	}
}

// A fresh read that is not answered in time gives up with its caller's deadline instead of waiting for the write
// timeout.
func testFreshReadHonoursTheCallersDeadline(t *testing.T, c *tcluster) {
	org, _ := c.orgNotOwnedBy(2)
	u := newUser(org, "slow-read")
	if err := users(c.nodes[0]).Create(bg, u); err != nil {
		t.Fatal(err)
	}
	c.waitUser(t, u.ID, func(*model.User) bool { return true })
	c.partition([]int{0, 1}, []int{2})
	ctx, cancel := context.WithTimeout(bg, 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.nodes[2].st().Fresh(ctx, model.KindUser, []string{u.ID})
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("a fresh read cut off from the owner: %v after %s", err, time.Since(start))
	}
}

// An id this node does not hold is asked of every partition's owner; told the partition (FreshIn), the caller asks one,
// and gets the same answer, whether the node holds the record yet or not. A wrong hint never makes a record look
// absent: an id the hinted partition does not hold, but that this node holds in another, is read from that partition's
// owner (a caller that finds a record absent may delete what depends on it). (The read counts are exact: this test
// has a cluster of its own.)
func TestFreshInAsksOnlyThePartitionOwner(t *testing.T) {
	c := started(t, badgerBackend())
	c.waitOwners()
	reads := func(tn *tnode) int64 { return tn.n.stats.reads.Load() }
	node := c.nodes[0]

	unknown := model.NewID()
	before := reads(node)
	got, err := node.st().Fresh(bg, dataKind, []string{unknown})
	if err != nil || len(got) != 0 {
		t.Fatalf("an id nobody holds: %v %v", got, err)
	}
	if n := reads(node) - before; n != partitions {
		t.Fatalf("an unknown id was asked of %d owners, want all %d", n, partitions)
	}
	before = reads(node)
	got, err = node.st().FreshIn(bg, dataKind, "org1", []string{unknown})
	if err != nil || len(got) != 0 {
		t.Fatalf("an id nobody holds, in its partition: %v %v", got, err)
	}
	if n := reads(node) - before; n != 1 {
		t.Fatalf("an id with its partition was asked of %d owners, want 1", n)
	}

	// a record written elsewhere is found through its partition without waiting for it to arrive here
	rec := newRec(model.NewID(), "")
	if err := c.nodes[1].st().Put(bg, rec); err != nil {
		t.Fatal(err)
	}
	for i, tn := range c.nodes {
		got, err := tn.st().FreshIn(bg, dataKind, "org1", []string{rec.ID})
		if err != nil || got[rec.ID] == nil || got[rec.ID].Version != rec.Version {
			t.Fatalf("node %d: %v %v", i, got, err)
		}
	}
	// without a key (the caller does not know it) the fan-out is the fallback, and a global kind needs none
	before = reads(node)
	if got, err := node.st().FreshIn(bg, dataKind, "", []string{unknown}); err != nil || len(got) != 0 {
		t.Fatalf("no key: %v %v", got, err)
	}
	if n := reads(node) - before; n != partitions {
		t.Fatalf("without a key %d owners were asked, want %d", n, partitions)
	}

	// hinted at the wrong partition
	c.waitHas(rec.ID)
	wrong := "org-other"
	for i := 0; partitionNum(wrong) == recPartition(rec); i++ {
		wrong = "org-other-" + string(rune('a'+i))
	}
	for i, tn := range c.nodes {
		got, err := tn.st().FreshIn(bg, dataKind, wrong, []string{rec.ID})
		if err != nil || got[rec.ID] == nil || got[rec.ID].Version != rec.Version {
			t.Fatalf("node %d, hinted at the wrong partition: %v %v", i, got, err)
		}
	}
	// an id nobody holds stays absent, asked of the hinted partition only
	before = reads(node)
	if got, err := node.st().FreshIn(bg, dataKind, wrong, []string{unknown}); err != nil || len(got) != 0 {
		t.Fatalf("an id nobody holds: %v %v", got, err)
	}
	if n := reads(node) - before; n != 1 {
		t.Fatalf("an unknown id with a wrong hint was asked of %d owners, want 1", n)
	}
}

// A follower that keeps failing to catch one partition up stops serving that partition's records (sessions here) while
// it still serves the others and the other nodes serve it; it stays ready (an unreadable partition is counted, not a
// reason to leave the load balancer); once it catches up it serves again.
func TestLaggingFollowerStopsServingThePartition(t *testing.T) {
	var fs faults
	c := newTCluster(t, 3, fs.over(badgerBackend()))
	c.startAll()
	c.waitReady()
	org, _ := c.orgNotOwnedBy(1)
	p := partitionNum(org)
	elsewhere := ""
	for k := 0; elsewhere == ""; k++ {
		if o := fmt.Sprintf("other-%d", k); partitionNum(o) != p && partitionNum(o) != 0 {
			elsewhere = o
		}
	}
	sess, other := newSession(org), newSession(elsewhere)
	for _, s := range []*model.Session{sess, other} {
		if err := sessions(c.nodes[0]).Create(bg, s); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, 10*time.Second, "the sessions everywhere", func() bool {
		for _, tn := range c.nodes {
			for _, s := range []*model.Session{sess, other} {
				if _, err := sessions(tn).Get(bg, s.ID); err != nil {
					return false
				}
			}
		}
		return true
	})

	// node 1 misses the next write of the partition, and every catch-up of it fails
	fs.of(c.nodes[1]).failImport.Store(int64(p) + 1)
	for _, j := range []int{0, 2} {
		c.drop(j, 1, true, gossip.PartWriteMsg, gossip.PartCommitMsg)
	}
	later := newSession(org)
	if err := sessions(c.nodes[0]).Create(bg, later); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "node 1 to refuse the partition it trails", func() bool {
		_, err := sessions(c.nodes[1]).Get(bg, sess.ID)
		return errors.Is(err, store.ErrUnavailable)
	})
	if _, err := c.nodes[1].st().Lookup(bg, model.KindSession, sess.ID); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a lookup on the trailing node: %v", err)
	}
	if _, err := sessions(c.nodes[1]).Get(bg, other.ID); err != nil {
		t.Fatalf("a partition the node follows is refused too: %v", err)
	}
	for _, i := range []int{0, 2} {
		if _, err := sessions(c.nodes[i]).Get(bg, later.ID); err != nil {
			t.Fatalf("node %d: %v", i, err)
		}
	}
	st := c.nodes[1].n.Status()
	if st.PartitionsUnreadable == 0 || st.Partitions[p].Readable || st.Partitions[p].LagMs == 0 || !st.Ready {
		t.Fatalf("status of the trailing node: unreadable %d, partition %+v, ready %v (%s)", st.PartitionsUnreadable,
			st.Partitions[p], st.Ready, st.Reason)
	}
	for _, i := range []int{0, 2} {
		if ok, why := c.nodes[i].n.Ready(); !ok {
			t.Fatalf("node %d: %s", i, why)
		}
	}

	fs.of(c.nodes[1]).failImport.Store(0)
	for _, j := range []int{0, 2} {
		c.drop(j, 1, false, gossip.PartWriteMsg, gossip.PartCommitMsg)
	}
	c.waitReady()
	waitFor(t, 10*time.Second, "node 1 to serve the partition again", func() bool {
		_, err := sessions(c.nodes[1]).Get(bg, later.ID)
		return err == nil
	})
}

// A read that finds nothing is answered from the copy of the partition the record would be in, when its key names one:
// while a node cannot read one partition (a catch-up that keeps failing), a username, organization name or id missing
// from any other partition is not found there (an unknown user signing in elsewhere is told so, not 503), and so is an
// id asked of an organization of another partition (a stale session cookie, an unknown refresh token: store.GetIn); only
// a miss in that partition, or one whose key names no partition, is refused.
func TestMissIsGatedOnItsOwnPartition(t *testing.T) {
	var fs faults
	c := newTCluster(t, 3, fs.over(badgerBackend()))
	c.startAll()
	c.waitReady()
	c.waitSettled()
	// Two organizations (by id, as a unique value names its organization): one in a partition node 1 does not own and
	// will trail, one in another partition.
	var trailed, other string
	for trailed == "" || other == "" {
		org := model.NewID()
		switch q := partitionNum(org); {
		case q == globalPartition:
		case trailed == "":
			if c.ownerOf(q) != 1 {
				trailed = org
			}
		case q != partitionNum(trailed):
			other = org
		}
	}
	p := partitionNum(trailed)
	replayID := func(in bool) string { // a replay record's partition is its id's (partitionHint)
		for {
			if id := model.NewID(); (partitionNum(id) == p) == in {
				return id
			}
		}
	}
	missIn, missOut := replayID(true), replayID(false)
	// a session of the other organization, which node 1 holds
	held := newSession(other)
	if err := sessions(c.nodes[0]).Create(bg, held); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "node 1 to hold the session", func() bool {
		_, err := sessions(c.nodes[1]).Get(bg, held.ID)
		return err == nil
	})

	// node 1 misses the next write of the partition, and every catch-up of it fails
	fs.of(c.nodes[1]).failImport.Store(int64(p) + 1)
	for _, j := range []int{0, 2} {
		c.drop(j, 1, true, gossip.PartWriteMsg, gossip.PartCommitMsg)
	}
	trailedSession := newSession(trailed)
	if err := sessions(c.nodes[0]).Create(bg, trailedSession); err != nil {
		t.Fatal(err)
	}
	st := c.nodes[1].st()
	waitFor(t, 10*time.Second, "node 1 to refuse the partition it trails", func() bool {
		_, err := st.Get(bg, model.KindReplay, missIn)
		return errors.Is(err, store.ErrUnavailable)
	})

	for what, op := range map[string]func() error{
		"a username of another organization": func() error {
			_, err := st.GetByUnique(bg, model.KindUser, model.UserUsernameKey(other, "nobody"))
			return err
		},
		"an organization's name": func() error {
			_, err := st.GetByUnique(bg, model.KindOrg, model.OrgNameKey("nobody"))
			return err
		},
		"an id of another partition": func() error {
			_, err := st.Get(bg, model.KindReplay, missOut)
			return err
		},
		"ids of another partition": func() error {
			if recs, err := st.GetMany(bg, model.KindReplay, []string{missOut}); err != nil || len(recs) > 0 {
				return fmt.Errorf("%d records, %w", len(recs), err)
			}
			return store.ErrNotFound
		},
		// (a session cookie, a refresh token: ids that name no partition, asked of the organization they are presented to)
		"an unknown session id asked of another organization": func() error {
			_, err := store.GetIn(bg, st, model.KindSession, other, model.NewID())
			return err
		},
		"an unknown grant id asked of another organization": func() error {
			_, err := store.GetIn(bg, st, model.KindGrant, other, model.NewID())
			return err
		},
		"a session of the trailed organization asked of another": func() error {
			_, err := store.GetIn(bg, st, model.KindSession, other, trailedSession.ID)
			return err
		},
	} {
		if err := asked(op); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s, on the node trailing partition %d: want not found, got %v", what, p, err)
		}
	}
	if _, err := sessions(c.nodes[1]).GetIn(bg, other, held.ID); err != nil {
		t.Errorf("a session of another organization, asked of its own, on the node trailing partition %d: %v", p, err)
	}
	for what, op := range map[string]func() error{
		"a username of the trailed organization": func() error {
			_, err := st.GetByUnique(bg, model.KindUser, model.UserUsernameKey(trailed, "nobody"))
			return err
		},
		"an id of the trailed partition": func() error {
			_, err := st.Get(bg, model.KindReplay, missIn)
			return err
		},
		"ids, one of the trailed partition": func() error {
			_, err := st.GetMany(bg, model.KindReplay, []string{missOut, missIn})
			return err
		},
		"a unique value that names no partition": func() error {
			_, err := st.GetByUnique(bg, model.KindLink, model.LinkTokenKey("nothing"))
			return err
		},
		"an id that names no partition": func() error {
			_, err := st.Get(bg, model.KindSession, model.NewID())
			return err
		},
		"an unknown session id asked of the trailed organization": func() error {
			_, err := store.GetIn(bg, st, model.KindSession, trailed, model.NewID())
			return err
		},
		"an unknown grant id asked of the trailed organization": func() error {
			_, err := store.GetIn(bg, st, model.KindGrant, trailed, model.NewID())
			return err
		},
	} {
		if err := op(); !errors.Is(err, store.ErrUnavailable) {
			t.Errorf("%s, on the node trailing partition %d: want unavailable, got %v", what, p, err)
		}
	}
}

// A partition that diverged on a node (its copy holds a write the owner does not have: a disk restored wrongly) makes
// the node not ready, saying so; it serves nothing of that partition, and the other nodes are unaffected.
func TestDivergedPartitionMakesTheNodeNotReady(t *testing.T) {
	b := sqliteBackend()
	c := started(t, b)
	org := c.orgOwnedBy(0)
	p := partitionNum(org)
	ids := writeN(t, c.nodes[0], org, 3)
	c.waitHas(ids[2])
	// node 2 has recorded everything the owner committed: the data of a write arrives before its commit, and a write
	// made at a position the owner has committed would be taken for the owner's own (one owner writes each position of
	// its epoch), not for a divergence
	owner := c.nodes[0].n.Status().Partitions[p].Committed
	waitFor(t, 15*time.Second, "node 2 to commit what the owner committed", func() bool {
		return c.nodes[2].n.Status().Partitions[p].Committed >= owner
	})

	// node 2's database gets a write of the partition nobody else has
	dir := c.nodes[2].dir
	stop(c.nodes[2])
	st := b.open(t, dir)
	pst := st.(store.PartitionStore)
	ps, err := pst.PartitionState(bg, p)
	if err != nil {
		t.Fatal(err)
	}
	if ps.Committed.Seq < owner {
		t.Fatalf("test set-up: node 2 stopped with position %d committed, the owner had %d", ps.Committed.Seq, owner)
	}
	rogue := newOrgRec(org)
	if err := pst.ApplyPartition(bg, p, []*store.Record{rogue}, store.PartitionPos{Epoch: ps.Committed.Epoch,
		Seq: ps.Committed.Seq + 1}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	// Until node 2 has found its copy diverged it takes no part in a promise round, either way: a round (one runs as it
	// rejoins, by the owner or by node 2 itself) takes the highest committed position it hears as the majority's, so the
	// rogue write would pass for a commit the others missed and be adopted (or node 2 would lead with it) before node 2
	// saw it was ahead. A real divergence is a write no majority acknowledged, which a promise round does not hear of;
	// once found, nothing takes it (asked again below, with the network whole).
	isolate := func(on bool) {
		for j := range 2 {
			c.drop(j, 2, on, gossip.PartPromiseMsg, gossip.PartClaimMsg, gossip.PartCatchUpMsg)
			c.drop(2, j, on, gossip.PartPromiseMsg, gossip.PartClaimMsg)
		}
	}
	isolate(true)
	c.nodes[2] = c.build(2, dir, nil)
	c.start(c.nodes[2])

	waitFor(t, 30*time.Second, "node 2 to find the partition diverged", func() bool {
		st := c.nodes[2].n.Status()
		return st.PartitionsDiverged == 1 && st.Partitions[p].Diverged && st.Divergences >= 1
	})
	isolate(false)
	waitFor(t, 5*time.Second, "node 2 not ready", func() bool {
		ok, why := c.nodes[2].n.Ready()
		return !ok && strings.Contains(why, "diverged")
	})
	if _, err := c.nodes[2].st().Get(bg, dataKind, ids[0]); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a record of the diverged partition served: %v", err)
	}
	// the others are ready (once they hear owners again: node 2 took part in no promise round meanwhile), and with the
	// network whole none takes the diverged write
	readyWithin(t, 15*time.Second, c.nodes[:2]...)
	for _, tn := range c.nodes[:2] {
		if _, err := tn.n.st.inner.Get(bg, dataKind, rogue.ID); err == nil {
			t.Fatalf("node %d holds the diverged write", tn.idx)
		}
	}
	if st := c.nodes[2].n.Status(); !st.Partitions[p].Diverged {
		t.Fatal("node 2's partition stopped being diverged")
	}
}

// Signing keys are listed through the gate of the global partition: a node that trails it (a key revoked meanwhile, a
// catch-up that keeps failing) refuses the listing, so it never publishes a key set the majority has changed.
func TestTrailingNodeRefusesToListSigningKeys(t *testing.T) {
	var fs faults
	c := newTCluster(t, 3, fs.over(badgerBackend()))
	c.startAll()
	c.waitReady()
	c.waitSettled()
	owner := c.ownerOf(globalPartition)
	trail := (owner + 1) % 3 // a follower of the global partition
	other := 3 - owner - trail
	keys := func(tn *tnode) *store.Table[model.SigningKey, *model.SigningKey] {
		return store.NewTable[model.SigningKey](tn.st())
	}
	k1 := &model.SigningKey{Meta: model.Meta{ID: "k1"}, Alg: "ES256"}
	if err := keys(c.nodes[owner]).Create(bg, k1); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "the key listed everywhere", func() bool {
		for _, tn := range c.nodes {
			if ks, _, err := keys(tn).List(bg, store.ListQuery{}); err != nil || len(ks) != 1 {
				return false
			}
		}
		return true
	})
	// the follower misses the key's removal, and every catch-up of the global partition fails
	fs.of(c.nodes[trail]).failImport.Store(int64(globalPartition) + 1)
	for _, j := range []int{owner, other} {
		c.drop(j, trail, true, gossip.PartWriteMsg, gossip.PartCommitMsg)
	}
	if err := keys(c.nodes[owner]).Delete(bg, k1.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "the trailing node to refuse listing the keys", func() bool {
		_, _, err := keys(c.nodes[trail]).List(bg, store.ListQuery{})
		return errors.Is(err, store.ErrUnavailable)
	})
	if ks, _, err := keys(c.nodes[owner]).List(bg, store.ListQuery{}); err != nil || len(ks) != 0 {
		t.Fatalf("the majority's listing: %d keys, %v", len(ks), err)
	}
}

// A full import that is cut short after its reset has emptied the partition must not leave a node that serves the
// emptied partition, or takes it over, from the old committed position it still holds: until an import completes the
// node refuses to read the partition, reports it Incomplete to the protocol with the position it had (which a promise
// it gives must still report; the library catches it up with a full copy, and a retry is a full import whatever the
// library asked), and never acknowledges a write on top of what it lost. The acknowledged
// records must all be on every node afterwards, the node that was cut short included, as an owner too.
func TestInterruptedFullImportIsRepeatedWhole(t *testing.T) {
	var fs faults
	c := newTCluster(t, 3, fs.over(badgerBackend()))
	c.startAll()
	c.waitReady()
	org := c.orgOwnedBy(0)
	p := partitionNum(org)
	first := writeN(t, c.nodes[0], org, 5)
	c.waitHas(first[4])

	// node 1 misses the next writes and cannot catch up
	victim, f := c.nodes[1], fs.of(c.nodes[1])
	f.failImport.Store(int64(p) + 1)
	for _, j := range []int{0, 2} {
		c.drop(j, 1, true, gossip.PartWriteMsg, gossip.PartCommitMsg)
	}
	later := writeN(t, c.nodes[0], org, 3)
	c.waitHas(later[2], c.nodes[2])
	all := append(append([]string{}, first...), later...)

	// a full copy of the partition starts on node 1 and is cut short after the reset
	before, err := victim.n.pst.State(p)
	if err != nil {
		t.Fatal(err)
	}
	upTo, rc, err := c.nodes[0].n.pst.Export(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.cutAfterReset.Store(int64(p) + 1)
	err = victim.n.pst.Import(p, rc, upTo, true)
	f.cutAfterReset.Store(0)
	rc.Close()
	if !errors.Is(err, errTestImport) {
		t.Fatalf("the cut import: %v", err)
	}
	if ps, err := f.PartitionState(bg, p); err != nil || !ps.Importing || ps.Committed.Seq == 0 {
		t.Fatalf("the backend after the cut import: %+v %v", ps, err)
	}
	if has(victim.st(), first[0]) {
		t.Fatal("the reset left a record behind: the scenario is not what it should be")
	}
	if st, err := victim.n.pst.State(p); err != nil || !st.Incomplete || st.Committed != before.Committed ||
		(st.Pending == nil) != (before.Pending == nil) {
		t.Fatalf("the library is told %+v (%v), want Incomplete at the position it had, %+v", st, err, before)
	}
	if err := victim.n.readable(bg, p); !errors.Is(err, store.ErrUnavailable) || !strings.Contains(err.Error(), "importing") {
		t.Fatalf("a read of the partition while its import is unfinished: %v", err)
	}
	if _, err := victim.st().Get(bg, dataKind, first[0]); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a read in the emptied partition: %v", err)
	}
	if err := victim.n.pst.Commit(&partition.Write{Partition: p, Pos: partition.Pos{Seq: upTo.Seq + 1}}); err == nil {
		t.Fatal("a write was applied on top of the hole")
	}

	// the owner goes away, the cut node can catch up again: whoever owns the partition then holds every record
	stop(c.nodes[0])
	f.failImport.Store(0)
	c.drop(2, 1, false, gossip.PartWriteMsg, gossip.PartCommitMsg)
	waitFor(t, 30*time.Second, "node 1 to hold every record of the partition again", func() bool {
		ps, err := f.PartitionState(bg, p)
		return err == nil && !ps.Importing && allHold([]*tnode{victim}, all)
	})
	extra := newOrgRec(org)
	putRetrying(t, c.nodes[2], extra)
	all = append(all, extra.ID)
	waitFor(t, 20*time.Second, "every record readable on both nodes", func() bool {
		for _, tn := range c.nodes[1:] {
			for _, id := range all {
				if r, err := tn.st().Get(bg, dataKind, id); err != nil || r == nil || r.Deleted {
					return false
				}
			}
		}
		return true
	})
	if _, rc, err := victim.n.pst.Export(p, 0); err != nil {
		t.Fatalf("the completed import still blocks exports: %v", err)
	} else {
		rc.Close()
	}
	c.restart(0)
	c.waitReady()
	c.waitHas(extra.ID)
}

// A read on a node that is behind its owner waits for the copy to catch up, and then answers from the caught-up copy,
// never with what it read before waiting (a user disabled meanwhile served as enabled).
func TestReadWaitingForCatchUpAnswersTheCaughtUpCopy(t *testing.T) {
	var fs faults
	c := newTCluster(t, 3, fs.over(badgerBackend()))
	c.opts = func(o *Options) {
		o.Partition = func(pc *partition.Config) { clustertest.Partition(pc); pc.StaleAfter = 5 * time.Second }
	}
	c.startAll()
	c.waitReady()
	org := c.orgOwnedBy(0)
	p := partitionNum(org)
	follower := c.nodes[1]
	tn := newTenant(org, "before")
	if err := tenants(c.nodes[0]).Create(bg, tn); err != nil {
		t.Fatal(err)
	}
	c.waitVersion(t, model.KindTenant, tn.ID, tn.Version)
	// the follower is cut off and misses a change
	c.partition([]int{0, 2}, []int{1})
	tn.Description = "after"
	if err := tenants(c.nodes[0]).Update(bg, tn); err != nil {
		t.Fatal(err)
	}
	// contact is regained while its catch-up fails: it hears the owner's position and is behind it
	fs.of(follower).failImport.Store(int64(p) + 1)
	c.heal()
	waitFor(t, 10*time.Second, "the follower to hear it is behind", func() bool {
		st, err := follower.n.manager().PartitionStatus(p)
		return err == nil && st.CanRead && st.Committed.Seq < st.OwnerCommitted.Seq
	})
	type answer struct {
		t   *model.Tenant
		err error
	}
	got := make(chan answer, 1)
	go func() {
		r, err := tenants(follower).Get(bg, tn.ID)
		got <- answer{r, err}
	}()
	time.Sleep(200 * time.Millisecond) // the read is waiting for the copy
	fs.of(follower).failImport.Store(0)
	a := <-got
	if a.err != nil {
		t.Fatalf("the read after catching up: %v", a.err)
	}
	if a.t.Description != "after" {
		t.Fatalf("the read answered the copy it had before catching up: %q", a.t.Description)
	}
}

// A backup is refused while a partition is being copied whole to the node (its reset emptied it): the snapshot may hold
// the partition empty, and still verify. (One that begins as the snapshot is taken is the backend's to refuse: its view
// holds the import's marker, storetest.s SnapshotRefusedWhileAnImportIsUnfinished.)
func TestBackupSnapshotRefusedDuringAFullImport(t *testing.T) {
	c := started(t, badgerBackend())
	n := c.nodes[0].n
	n.pst.importing[5].Store(true)
	_, err := n.st.Snapshot(bg)
	n.pst.importing[5].Store(false)
	if !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("snapshot while a partition is importing: %v", err)
	}
	r, err := n.st.Snapshot(bg)
	if err != nil {
		t.Fatalf("snapshot with no import: %v", err)
	}
	r.Close()
}

// A read whose copy was behind when it read and caught up before the gate looked (the gate then finds the partition
// current) answers the caught-up copy, never what it read before: a change applied in between makes it read again.
func TestReadCaughtUpBetweenReadAndGateAnswersTheCaughtUpCopy(t *testing.T) {
	var fs faults
	c := newTCluster(t, 3, fs.over(badgerBackend()))
	c.opts = func(o *Options) {
		o.Partition = func(pc *partition.Config) { clustertest.Partition(pc); pc.StaleAfter = 5 * time.Second }
	}
	c.startAll()
	c.waitReady()
	org := c.orgOwnedBy(0)
	p := partitionNum(org)
	follower := c.nodes[1]
	tn := newTenant(org, "before")
	if err := tenants(c.nodes[0]).Create(bg, tn); err != nil {
		t.Fatal(err)
	}
	c.waitVersion(t, model.KindTenant, tn.ID, tn.Version)
	c.partition([]int{0, 2}, []int{1})
	tn.Description = "after"
	if err := tenants(c.nodes[0]).Update(bg, tn); err != nil {
		t.Fatal(err)
	}
	fs.of(follower).failImport.Store(int64(p) + 1)
	c.heal()
	waitFor(t, 10*time.Second, "the follower to hear it is behind", func() bool {
		st, err := follower.n.manager().PartitionStatus(p)
		return err == nil && st.CanRead && st.Committed.Seq < st.OwnerCommitted.Seq
	})
	// The read takes the old copy; the follower then catches up before the gate looks.
	caughtUp := func() {
		fs.of(follower).failImport.Store(0)
		waitFor(t, 10*time.Second, "the follower to catch up", func() bool {
			st, err := follower.n.manager().PartitionStatus(p)
			return err == nil && st.Committed.Seq >= st.OwnerCommitted.Seq
		})
	}
	fs.of(follower).afterGet.Store(&caughtUp)
	got, err := tenants(follower).Get(bg, tn.ID)
	if fs.of(follower).afterGet.Load() != nil {
		t.Fatal("test set-up: the read did not reach the store")
	}
	if err != nil {
		t.Fatalf("the read: %v", err)
	}
	if got.Description != "after" {
		t.Fatalf("the read answered the copy it had before catching up: %q", got.Description)
	}
}
