package kvstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// gate holds the single commit worker of a Badger store inside a write, so that the writes submitted meanwhile are
// queued and then committed as one batch, in submission order.
type gate struct {
	t       *testing.T
	s       *Store
	e       *badgerEngine
	release chan struct{}
	done    chan error
	queued  int
}

func openGated(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := OpenBadger(bg, dir, BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if s.eng.(*badgerEngine).gc == nil || len(s.eng.(*badgerEngine).gc.queues) != 1 {
		t.Fatal("group commit with one worker expected by default")
	}
	return s
}

// hold blocks the worker in a no-op write and returns once it is held.
func hold(t *testing.T, s *Store) *gate {
	t.Helper()
	g := &gate{t: t, s: s, e: s.eng.(*badgerEngine), release: make(chan struct{}), done: make(chan error, 1)}
	started := make(chan struct{})
	go func() {
		g.done <- g.e.Group(bg, "test", "gate", func(tx txn) error {
			close(started)
			<-g.release
			return nil
		})
	}()
	<-started
	return g
}

// submit runs fn in a goroutine and waits until its write is queued behind the gate; the result arrives on the
// returned channel.
func (g *gate) submit(fn func() error) <-chan error {
	g.t.Helper()
	out := make(chan error, 1)
	go func() { out <- fn() }()
	g.queued++
	deadline := time.Now().Add(5 * time.Second)
	for len(g.e.gc.queues[0]) < g.queued {
		if time.Now().After(deadline) {
			g.t.Fatalf("write %d never queued", g.queued)
		}
		time.Sleep(50 * time.Microsecond)
	}
	return out
}

// open lets the held write finish; the queued writes then commit as one batch.
func (g *gate) open() {
	close(g.release)
	if err := <-g.done; err != nil {
		g.t.Fatal(err)
	}
}

func commits(s *Store) uint64 { return s.eng.(*badgerEngine).gc.commits.Load() }

func wait(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("write did not return")
		return nil
	}
}

func userRec(t *testing.T, u *model.User) *store.Record {
	t.Helper()
	r, err := store.Encode(u)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A failing write inside a batch (stale CompareAndPut, unique conflict, create over a live record) fails alone: the
// writes around it, including later writes of the same record, commit, and it leaves no trace.
func TestGroupConflictIsolation(t *testing.T) {
	s := openGated(t, t.TempDir())
	defer s.Close()
	tb := store.NewTable[model.User](s)
	base := &model.User{OrgID: "o", Username: "base", Email: "base@x", Role: model.RoleUser}
	if err := tb.Put(bg, base); err != nil {
		t.Fatal(err)
	}
	v0 := base.Version

	g := hold(t, s)
	before := commits(s)
	upd1 := *base
	upd1.GivenName = "first"
	r1 := userRec(t, &upd1)
	ok1 := g.submit(func() error { return s.CompareAndPut(bg, r1, v0) })
	upd2 := *base
	upd2.GivenName = "second"
	r2 := userRec(t, &upd2)
	stale := g.submit(func() error { return s.CompareAndPut(bg, r2, v0) }) // v0 is gone once r1 applied
	x := &model.User{OrgID: "o", Username: "x", Email: "claim@x", Role: model.RoleUser}
	okX := g.submit(func() error { return tb.Create(bg, x) })
	y := &model.User{OrgID: "o", Username: "y", Email: "claim@x", Role: model.RoleUser}
	conflict := g.submit(func() error { return tb.Create(bg, y) })
	again := *base
	again.ID = base.ID
	recreate := g.submit(func() error { return s.CompareAndPut(bg, userRec(t, &again), 0) }) // live: create refused
	z := &model.User{OrgID: "o", Username: "z", Email: "z@x", Role: model.RoleUser}
	okZ := g.submit(func() error { return tb.Put(bg, z) })
	// Fails after writing its unique index and scope entries (the record cannot be encoded): none of it may stay,
	// and a later write of the batch claims the same value.
	broken := &store.Record{Kind: model.KindGroup, ID: "broken", Origin: "n1", Scope: "o", Version: store.Clock.Now(),
		Unique: []string{"o|half"}, Fields: map[string]any{"display_name": struct{}{}}}
	failed := g.submit(func() error { return s.Put(bg, broken) })
	claim := &store.Record{Kind: model.KindGroup, ID: "claims", Origin: "n1", Scope: "o", Version: store.Clock.Now(),
		Unique: []string{"o|half"}, Fields: map[string]any{"display_name": "c"}}
	okClaim := g.submit(func() error { return s.CompareAndPut(bg, claim, 0) })
	r3 := func() *store.Record { u := upd1; u.GivenName = "third"; return userRec(t, &u) }()
	follow := g.submit(func() error { return s.CompareAndPut(bg, r3, r1.Version) }) // builds on r1, same batch
	g.open()

	for name, c := range map[string]struct {
		ch   <-chan error
		want error
	}{
		"cas": {ok1, nil}, "stale": {stale, store.ErrStale}, "createX": {okX, nil}, "conflictY": {conflict, store.ErrConflict},
		"recreate": {recreate, store.ErrStale}, "putZ": {okZ, nil}, "follow": {follow, nil}, "claim": {okClaim, nil},
	} {
		if err := wait(t, c.ch); !errors.Is(err, c.want) || (c.want == nil && err != nil) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	if err := wait(t, failed); err == nil || errors.Is(err, store.ErrConflict) {
		t.Errorf("unencodable record: %v", err)
	}
	if n := commits(s) - before; n != 1 {
		t.Errorf("the queued writes took %d commits, want 1", n)
	}
	if h, err := s.GetByUnique(bg, model.KindGroup, "o|half"); err != nil || h.ID != "claims" {
		t.Fatalf("unique value of the failed write: %v %v", h, err)
	}
	if n, _ := s.Count(bg, model.KindGroup, "o"); n != 1 {
		t.Fatalf("group count %d, want 1", n)
	}
	got, err := tb.Get(bg, base.ID)
	if err != nil || got.GivenName != "third" || got.Version != r3.Version {
		t.Fatalf("base: %+v %v", got, err)
	}
	h, err := tb.GetByUnique(bg, model.UserEmailKey("o", "claim@x"))
	if err != nil || h.ID != x.ID {
		t.Fatalf("unique holder %v %v", h, err)
	}
	if _, err := s.Lookup(bg, model.KindUser, y.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the conflicting create left a record: %v", err)
	}
	if n, _ := tb.Count(bg, "o"); n != 3 {
		t.Fatalf("count %d, want 3 (base, x, z)", n)
	}
	ch, _, err := s.Changes(bg, 0, 0)
	if err != nil || len(ch) != 4 {
		t.Fatalf("feed %d entries, %v", len(ch), err)
	}
}

// Writes of one record queued together apply in arrival order: each CompareAndPut expects the version the previous
// one wrote, a deletion follows them and a create starts the next generation. The feed keeps one entry for the
// record, under the last sequence number, and no entry of the intermediate writes.
func TestGroupSameKeyOrder(t *testing.T) {
	s := openGated(t, t.TempDir())
	defer s.Close()
	tb := store.NewTable[model.User](s)
	u := &model.User{OrgID: "o", Username: "a", Email: "a@x", Role: model.RoleUser}
	first := userRec(t, u)

	g := hold(t, s)
	before := commits(s)
	var chans []<-chan error
	chans = append(chans, g.submit(func() error { return s.CompareAndPut(bg, first, 0) }))
	prev := first
	for i := range 5 {
		c := *u
		c.GivenName = fmt.Sprint(i)
		r := userRec(t, &c)
		expect := prev.Version
		chans = append(chans, g.submit(func() error { return s.CompareAndPut(bg, r, expect) }))
		prev = r
	}
	tomb := store.Tombstone(model.KindUser, u.ID)
	chans = append(chans, g.submit(func() error { return s.Put(bg, tomb) }))
	re := *u
	re.GivenName = "reborn"
	again := userRec(t, &re)
	chans = append(chans, g.submit(func() error { return s.CompareAndPut(bg, again, 0) }))
	g.open()
	for i, ch := range chans {
		if err := wait(t, ch); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if n := commits(s) - before; n != 1 {
		t.Errorf("the queued writes took %d commits, want 1", n)
	}
	got, err := tb.Get(bg, u.ID)
	if err != nil || got.GivenName != "reborn" {
		t.Fatalf("got %+v %v", got, err)
	}
	r, _ := s.Lookup(bg, model.KindUser, u.ID)
	if r.Epoch != tomb.Version || r.Created != again.Version {
		t.Fatalf("epoch %d created %d, want %d %d", r.Epoch, r.Created, tomb.Version, again.Version)
	}
	members, err := s.eng.Range(bg, feedBkt, "", "", 0)
	if err != nil || len(members) != 1 {
		t.Fatalf("feed index %v %v", members, err)
	}
	ch, _, _ := s.Changes(bg, 0, 0)
	if len(ch) != 1 || ch[0].Record.Version != again.Version {
		t.Fatalf("changes %+v", ch)
	}
	if want := seqMember(ch[0].Seq, entryOf(model.KindUser, u.ID)); members[0] != want {
		t.Fatalf("feed member %s, want %s", members[0], want)
	}
	// Eight writes consumed eight sequence numbers (the deletion's tombstone is a write too).
	if ch[0].Seq != 8 {
		t.Fatalf("seq %d, want 8", ch[0].Seq)
	}
}

// Replicated writes are grouped too and keep PutReplicated semantics: a stale copy is not applied, a unique clash
// is resolved by creation order.
func TestGroupReplicated(t *testing.T) {
	s := openGated(t, t.TempDir())
	defer s.Close()
	mk := func(id, uniq string) *store.Record {
		return &store.Record{Kind: model.KindGroup, ID: id, Origin: "n2", Scope: "o", Version: store.Clock.Now(),
			Unique: []string{uniq}, Data: []byte(id), Fields: map[string]any{"display_name": id, "created": time.Now().UTC()}}
	}
	older, newer := mk("g1", "o|same"), mk("g2", "o|same")
	older.Created, newer.Created = older.Version, newer.Version
	stale := *older
	stale.Version, stale.Data = older.Version-1, []byte("stale")

	g := hold(t, s)
	type res struct {
		applied bool
		losers  []string
		err     error
	}
	out := make([]res, 3)
	var chans []<-chan error
	for i, r := range []*store.Record{newer, older, &stale} {
		chans = append(chans, g.submit(func() error {
			a, l, err := s.PutReplicated(bg, r)
			out[i] = res{a, l, err}
			return err
		}))
	}
	g.open()
	for _, ch := range chans {
		if err := wait(t, ch); err != nil {
			t.Fatal(err)
		}
	}
	if !out[0].applied || !out[1].applied || out[2].applied {
		t.Fatalf("applied %+v", out)
	}
	if len(out[1].losers) != 1 || out[1].losers[0] != "g2" {
		t.Fatalf("losers %+v", out[1].losers)
	}
	h, err := s.GetByUnique(bg, model.KindGroup, "o|same")
	if err != nil || h.ID != "g1" || string(h.Data) != "g1" {
		t.Fatalf("holder %+v %v", h, err)
	}
}

// Many writers on overlapping records: sequence numbers are strictly increasing in commit order, every committed
// write is reflected (the last write of each record is what is stored), and the stored counter is the highest seq.
func TestGroupFeedMonotonicUnderConcurrency(t *testing.T) {
	s := openGated(t, t.TempDir())
	defer s.Close()
	tb := store.NewTable[model.User](s)
	ids := make([]*model.User, 20)
	for i := range ids {
		ids[i] = &model.User{OrgID: "o", Username: fmt.Sprintf("u%d", i), Email: fmt.Sprintf("u%d@x", i), Role: model.RoleUser}
		if err := tb.Put(bg, ids[i]); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	var ok atomic.Int64
	stop := make(chan struct{})
	var followErr error
	var followed sync.WaitGroup
	followed.Add(1)
	go func() { // follow the feed while writes commit: seqs never go back, the cursor never skips
		defer followed.Done()
		var cursor, prev uint64
		for {
			ch, next, err := s.Changes(bg, cursor, 16)
			if err != nil {
				followErr = err
				return
			}
			for _, c := range ch {
				if c.Seq <= prev {
					followErr = fmt.Errorf("seq %d after %d", c.Seq, prev)
					return
				}
				prev = c.Seq
			}
			cursor = next
			select {
			case <-stop:
				if len(ch) == 0 {
					return
				}
			default:
			}
		}
	}()
	for w := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 60 {
				u := *ids[(w*7+i)%len(ids)]
				u.GivenName = fmt.Sprintf("%d-%d", w, i)
				if err := tb.Put(bg, &u); err == nil {
					ok.Add(1)
				} else if !errors.Is(err, store.ErrStale) {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	followed.Wait()
	if followErr != nil {
		t.Fatal(followErr)
	}
	ch, _, err := s.Changes(bg, 0, 0)
	if err != nil || len(ch) != len(ids) {
		t.Fatalf("feed %d %v", len(ch), err)
	}
	var maxSeq uint64
	for i, c := range ch {
		if i > 0 && c.Seq <= ch[i-1].Seq {
			t.Fatal("feed out of order")
		}
		maxSeq = max(maxSeq, c.Seq)
		r, _ := s.Lookup(bg, model.KindUser, c.Record.ID)
		if r.Version != c.Record.Version {
			t.Fatalf("feed holds %d, store %d", c.Record.Version, r.Version)
		}
	}
	stored, _ := s.eng.Get(bg, metaSeq)
	if seqOf(stored) != maxSeq || maxSeq != uint64(len(ids))+uint64(ok.Load()) {
		t.Fatalf("counter %d, max seq %d, writes %d", seqOf(stored), maxSeq, uint64(len(ids))+uint64(ok.Load()))
	}
	if commits(s) >= uint64(ok.Load()) {
		t.Logf("no batching observed: %d commits for %d writes", commits(s), ok.Load())
	}
}

// Concurrent writes are durable once acknowledged: after a clean close and reopen every acknowledged write is
// there, and the feed counter continues from where it stopped.
func TestGroupDurableReopen(t *testing.T) {
	dir := t.TempDir()
	s := openGated(t, dir)
	tb := store.NewTable[model.User](s)
	var mu sync.Mutex
	acked := map[string]hlc.Timestamp{}
	var wg sync.WaitGroup
	for w := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 40 {
				u := &model.User{OrgID: "o", Username: fmt.Sprintf("w%d-%d", w, i), Email: fmt.Sprintf("w%d-%d@x", w, i), Role: model.RoleUser}
				if err := tb.Put(bg, u); err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				acked[u.ID] = u.Version
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	_, last, _ := s.Changes(bg, 0, 0)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openGated(t, dir)
	defer s.Close()
	tb = store.NewTable[model.User](s)
	for id, v := range acked {
		u, err := tb.Get(bg, id)
		if err != nil || u.Version != v {
			t.Fatalf("%s after reopen: %v %v", id, u, err)
		}
	}
	if n, _ := tb.Count(bg, "o"); n != len(acked) {
		t.Fatalf("count %d, want %d", n, len(acked))
	}
	u := &model.User{OrgID: "o", Username: "after", Email: "after@x", Role: model.RoleUser}
	if err := tb.Put(bg, u); err != nil {
		t.Fatal(err)
	}
	ch, _, _ := s.Changes(bg, last, 0)
	if len(ch) != 1 || ch[0].Seq != last+1 {
		t.Fatalf("after reopen: %+v (last %d)", ch, last)
	}
}

// Close commits every queued write before the database closes; a write submitted after Close fails at once.
func TestGroupShutdownDrains(t *testing.T) {
	dir := t.TempDir()
	s := openGated(t, dir)
	tb := store.NewTable[model.User](s)
	g := hold(t, s)
	var chans []<-chan error
	var users []*model.User
	for i := range 50 {
		u := &model.User{OrgID: "o", Username: fmt.Sprintf("d%d", i), Email: fmt.Sprintf("d%d@x", i), Role: model.RoleUser}
		users = append(users, u)
		chans = append(chans, g.submit(func() error { return tb.Put(bg, u) }))
	}
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	// Close waits for the queues: let the held write go only once Close has stopped new submissions.
	deadline := time.Now().Add(5 * time.Second)
	for {
		g.e.gc.mu.RLock()
		c := g.e.gc.closed
		g.e.gc.mu.RUnlock()
		if c {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Close did not start")
		}
		time.Sleep(100 * time.Microsecond)
	}
	if err := tb.Put(bg, &model.User{OrgID: "o", Username: "late", Email: "late@x"}); err == nil {
		t.Fatal("a write after Close succeeded")
	}
	g.open()
	for i, ch := range chans {
		if err := wait(t, ch); err != nil {
			t.Fatalf("queued write %d: %v", i, err)
		}
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	s = openGated(t, dir)
	defer s.Close()
	tb = store.NewTable[model.User](s)
	for _, u := range users {
		if _, err := tb.Get(bg, u.ID); err != nil {
			t.Fatalf("drained write %s lost: %v", u.Username, err)
		}
	}
}

// A caller whose context ends while its write is queued gets the context error and the write never applies; a
// panic in a write reaches its own caller, and the other writes of the batch commit.
func TestGroupCancelAndPanic(t *testing.T) {
	s := openGated(t, t.TempDir())
	defer s.Close()
	tb := store.NewTable[model.User](s)
	g := hold(t, s)
	cctx, cancel := context.WithCancel(bg)
	gone := &model.User{OrgID: "o", Username: "gone", Email: "gone@x", Role: model.RoleUser}
	canceled := g.submit(func() error { return tb.Put(cctx, gone) })
	panicked := g.submit(func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("recovered: %v", r)
			}
		}()
		return g.e.Group(bg, "user", "p", func(tx txn) error { panic("boom") })
	})
	kept := &model.User{OrgID: "o", Username: "kept", Email: "kept@x", Role: model.RoleUser}
	okc := g.submit(func() error { return tb.Put(bg, kept) })
	cancel()
	if err := wait(t, canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled write: %v", err)
	}
	g.open()
	if err := wait(t, panicked); err == nil || err.Error() != "recovered: boom" {
		t.Fatalf("panic: %v", err)
	}
	if err := wait(t, okc); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup(bg, model.KindUser, gone.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("canceled write applied: %v", err)
	}
	if _, err := tb.Get(bg, kept.ID); err != nil {
		t.Fatal(err)
	}
}

// Writes larger than one Badger transaction in total are split into several commits, in order.
func TestGroupSplitsTooBig(t *testing.T) {
	s, err := OpenBadger(bg, t.TempDir(), BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	g := hold(t, s)
	big := make([]byte, 600<<10) // 600 KiB: ~16 of these exceed Badger's 9.6 MB transaction limit (64 MB memtable)
	var chans []<-chan error
	for i := range 40 {
		r := &store.Record{Kind: model.KindGroup, ID: fmt.Sprintf("big%02d", i), Origin: "n1", Scope: "o",
			Version: store.Clock.Now(), Data: big, Fields: map[string]any{"display_name": "x", "created": time.Now().UTC()}}
		chans = append(chans, g.submit(func() error { return s.Put(bg, r) }))
	}
	before := commits(s)
	g.open()
	for i, ch := range chans {
		if err := wait(t, ch); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if n := commits(s) - before; n < 2 {
		t.Fatalf("expected the batch to be split, got %d commits", n)
	}
	ch, _, _ := s.Changes(bg, 0, 0)
	if len(ch) != 40 {
		t.Fatalf("feed %d", len(ch))
	}
	for i := range ch {
		if want := fmt.Sprintf("big%02d", i); ch[i].Record.ID != want {
			t.Fatalf("feed position %d holds %s, want %s (arrival order)", i, ch[i].Record.ID, want)
		}
	}
}
