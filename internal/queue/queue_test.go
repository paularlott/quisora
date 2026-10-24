package queue

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/secure"
)

// sink records delivered items; fail makes the next deliveries fail.
type sink struct {
	mu   sync.Mutex
	got  []string
	fail atomic.Int32
	n    atomic.Int32
}

func (s *sink) deliver(_ context.Context, it string) error {
	s.n.Add(1)
	if s.fail.Load() > 0 {
		s.fail.Add(-1)
		return errors.New("down")
	}
	s.mu.Lock()
	s.got = append(s.got, it)
	s.mu.Unlock()
	return nil
}

func (s *sink) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.got) }

func open(t *testing.T, dir string, sealer *secure.Sealer, s *sink, backoff ...time.Duration) *Queue[string] {
	t.Helper()
	q, err := Open(dir, Options[string]{Name: "test queue", Log: logger.NewNullLogger(), Sealer: sealer,
		Binding: "test/queue", Backoff: backoff, Max: 1000, Deliver: s.deliver})
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func sealer(t *testing.T, keys ...[]byte) *secure.Sealer {
	t.Helper()
	s, err := secure.NewKeyring(keys[0], keys[1:]...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// An item that fails is retried after each delay of the backoff, and given up on after the last.
func TestRetryThenGiveUp(t *testing.T) {
	s := &sink{}
	s.fail.Store(2)
	q := open(t, t.TempDir(), sealer(t, secure.RandomBytes(32)), s, 10*time.Millisecond, 10*time.Millisecond)
	defer q.Close()
	if err := q.Add("a", 0, 0); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return s.count() == 1 })
	if s.n.Load() != 3 {
		t.Fatalf("attempts %d", s.n.Load())
	}

	s.n.Store(0)
	s.fail.Store(100)
	_ = q.Add("b", 0, 0)
	waitFor(t, func() bool { return q.Queued() == 0 })
	if s.n.Load() != 3 {
		t.Fatalf("expected 3 attempts then give up, got %d", s.n.Load())
	}
}

// Add with attempts already made starts further down the backoff (a first attempt made elsewhere).
func TestAddAfterAttempts(t *testing.T) {
	s := &sink{}
	s.fail.Store(100)
	q := open(t, t.TempDir(), sealer(t, secure.RandomBytes(32)), s, time.Hour, 10*time.Millisecond)
	defer q.Close()
	if err := q.Add("a", 10*time.Millisecond, 1); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return q.Queued() == 0 })
	if s.n.Load() != 2 { // the attempts left after the first: the one 10ms on, then give up after the last delay
		t.Fatalf("attempts %d", s.n.Load())
	}
}

// The queue is on disk and sealed: an item not yet delivered when the queue stops goes out from the next one on the
// same directory, and nothing of it is readable in the file.
func TestSurvivesRestart(t *testing.T) {
	dir, sl := t.TempDir(), sealer(t, secure.RandomBytes(32))
	down := &sink{}
	down.fail.Store(100)
	q := open(t, dir, sl, down, time.Hour)
	if err := q.Add("ann@example.com s3cr3t", 0, 0); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return down.n.Load() == 1 })
	q.Close()
	names, _ := q.files()
	if len(names) != 1 {
		t.Fatalf("queue holds %d files", len(names))
	}
	raw, _ := os.ReadFile(filepath.Join(dir, names[0]))
	if strings.Contains(string(raw), "ann@example.com") || strings.Contains(string(raw), "s3cr3t") {
		t.Fatal("queued item readable on disk")
	}
	it, _ := q.read(names[0])
	it.Next = time.Time{} // due now
	if err := q.write(names[0], it); err != nil {
		t.Fatal(err)
	}
	up := &sink{}
	q2 := open(t, dir, sl, up, time.Hour)
	defer q2.Close()
	waitFor(t, func() bool { return up.count() == 1 && q2.Queued() == 0 })
}

// A master key rotation re-seals the queue, so the previous key can go without losing an item; an item sealed with a
// key that is not configured is kept, not dropped.
func TestSurvivesKeyRotation(t *testing.T) {
	dir := t.TempDir()
	oldKey, newKey := secure.RandomBytes(32), secure.RandomBytes(32)
	down := &sink{}
	down.fail.Store(100)
	q := open(t, dir, sealer(t, oldKey), down, time.Hour)
	_ = q.Add("invite", 0, 0)
	waitFor(t, func() bool { return down.n.Load() == 1 })
	q.Close()

	q2 := open(t, dir, sealer(t, newKey), down, time.Hour) // the old key removed too early
	if n := q2.Reseal(); n != 1 || q2.Queued() != 1 {
		t.Fatalf("unopenable %d, queued %d", n, q2.Queued())
	}
	q2.Close()

	q3 := open(t, dir, sealer(t, newKey, oldKey), down, time.Hour) // the rotation's keys: Open re-seals
	q3.Close()
	names, _ := q3.files()
	newOnly := &Queue[string]{o: Options[string]{Sealer: sealer(t, newKey), Binding: "test/queue"}, dir: dir}
	if it, err := newOnly.read(names[0]); err != nil || it.Item != "invite" {
		t.Fatalf("after the re-seal: %v %+v", err, it)
	}
}

func TestFull(t *testing.T) {
	q := open(t, t.TempDir(), sealer(t, secure.RandomBytes(32)), &sink{})
	defer q.Close()
	q.queued.Store(int64(q.o.Max))
	if err := q.Add("a", 0, 0); !errors.Is(err, ErrFull) {
		t.Fatalf("full queue: %v", err)
	}
}

// Items added while the worker reads the queue are never lost to it, and a temporary file a crash left behind is
// cleared at the next start.
func TestConcurrentAdds(t *testing.T) {
	dir, sl, s := t.TempDir(), sealer(t, secure.RandomBytes(32)), &sink{}
	q := open(t, dir, sl, s)
	_ = os.WriteFile(filepath.Join(dir, ".leftover"+ext+".tmp"), []byte("x"), 0o600)
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Go(func() {
			if err := q.Add(strconv.Itoa(i), 0, 0); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	waitFor(t, func() bool { return s.count() == 100 })
	q.Close()
	open(t, dir, sl, s).Close()
	if _, err := os.Stat(filepath.Join(dir, ".leftover"+ext+".tmp")); !os.IsNotExist(err) {
		t.Fatal("a crash's temporary file was not cleared at start")
	}
}
