package kvstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
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
	follow := g.submit(func() error { return s.Put(bg, r3) }) // over r1, same batch: the store stamps it newer
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
}

// Writes of one record queued together apply in arrival order: each Put is stamped newer than the previous one's, a
// deletion follows them and a create starts the next generation.
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
	var puts []*store.Record
	for i := range 5 {
		c := *u
		c.GivenName = fmt.Sprint(i)
		r := userRec(t, &c)
		chans = append(chans, g.submit(func() error { return s.Put(bg, r) }))
		puts = append(puts, r)
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
	prev := first
	for i, r := range puts {
		if r.Version <= prev.Version {
			t.Fatalf("put %d stamped %d, not newer than the write before it (%d)", i, r.Version, prev.Version)
		}
		prev = r
	}
	got, err := tb.Get(bg, u.ID)
	if err != nil || got.GivenName != "reborn" {
		t.Fatalf("got %+v %v", got, err)
	}
	r, _ := s.Lookup(bg, model.KindUser, u.ID)
	if r.Epoch != tomb.Version || r.Created != again.Version {
		t.Fatalf("epoch %d created %d, want %d %d", r.Epoch, r.Created, tomb.Version, again.Version)
	}
	if r.Version != again.Version {
		t.Fatalf("stored version %d, want the last write's %d", r.Version, again.Version)
	}
	// The scope index holds the record once (every write of the group replaced the earlier one's entries).
	if n, err := tb.Count(bg, "o"); err != nil || n != 1 {
		t.Fatalf("count %d %v", n, err)
	}
}

// Replicated writes are grouped too and keep PutReplicated semantics: a stale copy is not applied, a unique clash
// is refused.
func TestGroupReplicated(t *testing.T) {
	s := openGated(t, t.TempDir())
	defer s.Close()
	mk := func(id, uniq string) *store.Record {
		return &store.Record{Kind: model.KindGroup, ID: id, Origin: "n2", Scope: "o", Version: store.Clock.Now(),
			Unique: []string{uniq}, Data: []byte(id), Fields: map[string]any{"display_name": id, "created": time.Now().UTC()}}
	}
	first, clash := mk("g1", "o|same"), mk("g2", "o|same")
	stale := *first
	stale.Version, stale.Data = first.Version-1, []byte("stale")

	g := hold(t, s)
	type res struct {
		applied bool
		err     error
	}
	out := make([]res, 3)
	var chans []<-chan error
	for i, r := range []*store.Record{first, clash, &stale} {
		chans = append(chans, g.submit(func() error {
			a, err := s.PutReplicated(bg, r)
			out[i] = res{a, err}
			return nil
		}))
	}
	g.open()
	for _, ch := range chans {
		if err := wait(t, ch); err != nil {
			t.Fatal(err)
		}
	}
	if !out[0].applied || out[0].err != nil || out[1].applied || !errors.Is(out[1].err, store.ErrConflict) || out[2].applied || out[2].err != nil {
		t.Fatalf("results %+v", out)
	}
	h, err := s.GetByUnique(bg, model.KindGroup, "o|same")
	if err != nil || h.ID != "g1" || string(h.Data) != "g1" {
		t.Fatalf("holder %+v %v", h, err)
	}
	if _, err := s.Get(bg, model.KindGroup, "g2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refused record was stored: %v", err)
	}
}

// Concurrent writes are durable once acknowledged: after a clean close and reopen every acknowledged write is
// there.
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
	if _, err := tb.Get(bg, u.ID); err != nil {
		t.Fatalf("a write after the reopen: %v", err)
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
	for i := range 40 {
		if _, err := s.Get(bg, model.KindGroup, fmt.Sprintf("big%02d", i)); err != nil {
			t.Fatalf("write %d lost: %v", i, err)
		}
	}
}

// An aborted transaction writes nothing; retry retries conflicts up to maxRetries, stops at a canceled context and passes
// other errors through.
func TestUpdateRetriesConflictsThenGivesUp(t *testing.T) {
	ctx := context.Background()
	s := openBadger(t, BadgerOptions{Group: GroupOptions{Disabled: true}})
	// An error from the transaction body is returned unchanged and nothing is written.
	boom := errors.New("boom")
	err := s.eng.Update(ctx, func(tx txn) error { tx.Set("k", []byte("v")); return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("Update: %v", err)
	}
	if b, _ := s.eng.Get(ctx, "k"); b != nil {
		t.Fatal("an aborted transaction wrote")
	}
	// retry gives up after maxRetries conflicts, reports a canceled context, and passes other errors through.
	calls := 0
	err = retry(ctx, func() error { calls++; return errConflict })
	if !errors.Is(err, store.ErrUnavailable) || calls != maxRetries {
		t.Fatalf("retry exhaustion: %v after %d calls", err, calls)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	calls = 0
	if err := retry(cctx, func() error { calls++; return errConflict }); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("retry canceled: %v after %d calls", err, calls)
	}
	if err := retry(ctx, func() error { return boom }); !errors.Is(err, boom) {
		t.Fatal("retry swallowed an error")
	}
	n := 0
	if err := retry(ctx, func() error {
		if n++; n < 3 {
			return errConflict
		}
		return nil
	}); err != nil || n != 3 {
		t.Fatalf("retry success: %v %d", err, n)
	}
}

// With group commit disabled, Group runs the transaction on its own, returning its error.
func TestGroupRunsInlineWhenGroupCommitDisabled(t *testing.T) {
	ctx := context.Background()
	s := openBadger(t, BadgerOptions{Group: GroupOptions{Disabled: true}})
	e := s.eng.(*badgerEngine)
	boom := errors.New("boom")
	if err := e.Group(ctx, "k", "i", func(tx txn) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("ungrouped Group: %v", err)
	}
	if err := e.Group(ctx, "k", "i", func(tx txn) error { tx.Set("x", []byte("1")); return nil }); err != nil {
		t.Fatal(err)
	}
	if b, _ := e.Get(ctx, "x"); string(b) != "1" {
		t.Fatal("write lost")
	}
}

// A transaction is one write of a batch: a refused one leaves nothing of its earlier ops, and the writes around it
// commit.
func TestGroupTxIsolation(t *testing.T) {
	s := openGated(t, t.TempDir())
	defer s.Close()
	a := &model.User{OrgID: "o", Username: "a", Email: "a@x", Role: model.RoleUser}
	b := &model.User{OrgID: "o", Username: "b", Email: "b@x", Role: model.RoleUser}
	c := &model.User{OrgID: "o", Username: "c", Email: "c@x", Role: model.RoleUser}
	d := &model.User{OrgID: "o", Username: "d", Email: "d@x", Role: model.RoleUser}
	for _, u := range []*model.User{a, b, c, d} {
		u.ID = u.Username
	}
	g := hold(t, s)
	okTx := g.submit(func() error {
		return s.Tx(bg, []store.Op{{Rec: userRec(t, a), Match: true}, {Rec: userRec(t, b), Match: true}})
	})
	badTx := g.submit(func() error { // c is written, then d claims a's email: refused, c must not stay
		d.Email = a.Email
		return s.Tx(bg, []store.Op{{Rec: userRec(t, c), Match: true}, {Rec: userRec(t, d), Match: true}})
	})
	g.open()
	if err := wait(t, okTx); err != nil {
		t.Fatalf("first transaction: %v", err)
	}
	if err := wait(t, badTx); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second transaction: want ErrConflict, got %v", err)
	}
	for id, want := range map[string]bool{"a": true, "b": true, "c": false, "d": false} {
		if _, err := s.Lookup(bg, model.KindUser, id); (err == nil) != want {
			t.Errorf("user %s stored: %v, want %v", id, err == nil, want)
		}
	}
	if n, _ := s.Count(bg, model.KindUser, "o"); n != 2 {
		t.Fatalf("count %d, want 2", n)
	}
}
