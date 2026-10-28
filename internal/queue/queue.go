// Package queue is a small retry queue on disk: emails waiting for SMTP, back-channel logouts waiting for an
// application. An item is one file in the queue's directory, sealed with the master key (items carry single-use links
// and user identifiers) and written durably before Add returns, so it survives a restart or a crash and is delivered
// by the node once it is back. The queue delivers what is due, oldest first, one item at a time or by a bounded pool
// of workers (Options.Workers) that keeps one key's items (say, one organization's) from taking them all
// (Options.PerKey). A delivery starts as soon as a worker is free and an item is due (just added, retried, or its
// wait over), so a slow delivery holds its worker and nothing else. An item that fails waits for the next delay of
// Backoff, and after the last one it is given up on (Failed). A file is removed once its item is delivered or given
// up on.
//
// After a master key change the queue is re-sealed with the active key (Reseal) before the node reports that key, so
// a rotation the cluster reports complete leaves no queued item needing a previous key. An item sealed with a key
// that is not configured is kept, and delivered once that key is configured again.
package queue

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/durable"
	"github.com/paularlott/quisora/internal/secure"
)

// ErrFull is returned by Add when the queue holds Max items.
var ErrFull = errors.New("queue: full")

// Options configure a queue. Deliver is required.
type Options[T any] struct {
	Name    string // in log messages ("mail queue")
	Log     logger.Logger
	Sealer  *secure.Sealer
	Binding string // binds the sealed files to this queue (secure.Sealer.SealFor)
	// Backoff are the delays after each failed delivery; after the last, the item is given up on.
	Backoff []time.Duration
	Max     int // most items held; Add refuses more (ErrFull)
	Deliver func(ctx context.Context, item T) error
	// Failed is told of each failed delivery (attempt counts them): retry is the delay before the next attempt, or 0
	// when the item is given up on. Optional (the queue logs nothing of its own about failures).
	// It is called from the delivering worker, so from several goroutines at once when Workers is more than one.
	Failed func(item T, attempt int, retry time.Duration, err error)
	// Workers is the most deliveries at once (0 or 1: one at a time). A slow delivery (at most 30 s) then holds one
	// worker, not the queue: any other item is delivered as soon as a worker is free, so Deliver must be safe to call
	// from several goroutines.
	Workers int
	// Key and PerKey share the workers fairly: no more than PerKey deliveries of items with the same Key at once
	// (PerKey 0 or no Key: no limit), the rest of that key's due items waiting for one of its deliveries to end while
	// the workers serve the other keys, so a key whose deliveries are slow (an application that never answers) cannot
	// hold every worker and delay the other keys.
	Key    func(item T) string
	PerKey int
}

// Queue is a retry queue on disk (see the package comment).
type Queue[T any] struct {
	o   Options[T]
	dir string
	// fileMu is held for one change to an item's file at a time (a delivery's end, Reseal's rewrite, a purge), never
	// across a delivery: that takes as long as an application takes to answer.
	fileMu sync.Mutex
	// waiting is when the items the workers have read (or retried) are next due, by file, with the file's modification
	// time then (under fileMu): an item that is not due is not read and opened again each time the scheduler looks at
	// the queue (which would make each Add cost the whole backlog) unless its file changed since.
	waiting map[string]waitingItem
	queued  atomic.Int64
	addMu   sync.RWMutex // adds hold it shared from taking their place to writing their file; PurgeLost exclusively
	// running is the files being delivered now, with their keys (under runMu). Only the scheduler adds to it, so an
	// item is never delivered twice at once; a delivery leaves it after recording its outcome.
	runMu      sync.Mutex
	running    map[string]string
	deliveries sync.WaitGroup
	kick       chan struct{} // the scheduler has something new to look at (a buffer of one: a kick is never lost)
	stop       chan struct{}
	wg         sync.WaitGroup
	once       sync.Once
}

// item is a queued item as its file holds it (sealed).
type item[T any] struct {
	Item    T         `json:"m"`
	Attempt int       `json:"a"` // failed deliveries so far
	Next    time.Time `json:"n"` // not before
}

const ext = ".item"

func newQueue[T any](dir string, o Options[T]) *Queue[T] {
	return &Queue[T]{o: o, dir: dir, running: map[string]string{}, kick: make(chan struct{}, 1), stop: make(chan struct{})}
}

// Open opens (creating) the queue in dir and starts its scheduler, which first delivers whatever a previous run left;
// call Close to stop it.
func Open[T any](dir string, o Options[T]) (*Queue[T], error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("%s: %w", o.Name, err)
	}
	q := newQueue(dir, o)
	q.removeTemp()
	q.Reseal()
	names, err := q.files()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", o.Name, err)
	}
	q.queued.Store(int64(len(names)))
	if len(names) > 0 {
		o.Log.Info(o.Name+": delivering items left from before", "items", len(names))
	}
	q.wg.Add(1)
	go q.run()
	return q, nil
}

// Close stops the scheduler, cancelling the deliveries in flight (their attempts do not count) and waiting for them;
// items not yet delivered stay queued for the next start.
func (q *Queue[T]) Close() {
	q.once.Do(func() { close(q.stop) })
	q.wg.Wait()
}

// Queued returns how many items are waiting.
func (q *Queue[T]) Queued() int { return int(q.queued.Load()) }

// Add queues it, to be delivered once after (now: at once) having failed attempts deliveries already, and returns
// once it is on disk.
func (q *Queue[T]) Add(it T, after time.Duration, attempts int) error {
	// The place is taken before the write (given back if it fails), so adds at once never pass Max between them.
	q.addMu.RLock()
	defer q.addMu.RUnlock()
	if q.queued.Add(1) > int64(q.o.Max) {
		q.queued.Add(-1)
		return ErrFull
	}
	var r [6]byte
	_, _ = rand.Read(r[:])
	name := fmt.Sprintf("%020d-%s%s", time.Now().UnixNano(), hex.EncodeToString(r[:]), ext) // oldest first when listed
	if err := q.write(name, &item[T]{Item: it, Attempt: attempts, Next: time.Now().Add(after)}); err != nil {
		q.queued.Add(-1)
		return err
	}
	q.wake()
	return nil
}

// wake tells the scheduler to look at the queue again.
func (q *Queue[T]) wake() {
	select {
	case q.kick <- struct{}{}:
	default:
	}
}

// Reseal re-seals every queued item with the active master key, and returns how many are still not sealed with it:
// stale, those whose rewrite failed (a full or failing disk), which still need the configured previous key they are
// sealed with: while any is left no previous key may be removed (app.ReloadMasterKeys refuses, and this node reports
// the rotation unfinished); and lost, those no configured key opens, which need no configured key, so they hold
// nothing back: they wait for their key to be configured again, and are given up once their links have expired
// (PurgeLost, the node's daily sweep). Call it after the master keys change, before the node reports its new key
// (service.ReportMasterKey). An unreadable queue counts as one stale item.
func (q *Queue[T]) Reseal() (stale, lost int) {
	q.fileMu.Lock()
	q.waiting = nil // the keys changed: every item is read afresh (one that needs a key no longer configured waits)
	q.fileMu.Unlock()
	names, err := q.files()
	if err != nil {
		q.o.Log.Error(q.o.Name+": cannot be read", "error", err)
		return 1, 0
	}
	for _, name := range names {
		switch err := q.reseal(name); {
		case errors.Is(err, secure.ErrUnknownKey):
			lost++
		case err != nil:
			stale++
		}
	}
	if stale > 0 {
		q.o.Log.Error(q.o.Name+": items not re-sealed with the active master key (a write that failed: it is tried "+
			"again); their previous key stays needed", "items", stale)
	}
	if lost > 0 {
		q.o.Log.Warn(q.o.Name+": items sealed with a master key that is not configured: put it back in "+
			"server.previous_master_keys, or they are given up once they are 8 days old", "items", lost)
	}
	return stale, lost
}

func (q *Queue[T]) reseal(name string) error {
	q.fileMu.Lock()
	defer q.fileMu.Unlock()
	b, err := os.ReadFile(filepath.Join(q.dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil // delivered meanwhile
	} else if err != nil {
		return err
	}
	sealed, err := q.o.Sealer.Reseal(q.o.Binding, string(b))
	if err != nil || sealed == string(b) {
		return err
	}
	return q.writeSealed(name, sealed)
}

// write stores it as name, atomically and durably: a crash or a power loss leaves the old file or the new one, never
// part of one, and an item accepted is on disk.
func (q *Queue[T]) write(name string, it *item[T]) error {
	b, err := json.Marshal(it)
	if err != nil {
		return err
	}
	return q.writeSealed(name, q.o.Sealer.SealFor(q.o.Binding, b))
}

func (q *Queue[T]) writeSealed(name, sealed string) error {
	// Durable before Add returns: "accepted means on disk". The temporary name is hidden, so a listing never takes
	// it for an item.
	return durable.WriteFile(filepath.Join(q.dir, "."+name+".tmp"), filepath.Join(q.dir, name), []byte(sealed))
}

func (q *Queue[T]) read(name string) (*item[T], error) {
	b, err := os.ReadFile(filepath.Join(q.dir, name))
	if err != nil {
		return nil, err
	}
	plain, err := q.o.Sealer.OpenFor(q.o.Binding, string(b))
	if err != nil {
		return nil, err
	}
	var it item[T]
	return &it, json.Unmarshal(plain, &it)
}

func (q *Queue[T]) remove(name string) {
	delete(q.waiting, name)
	if err := os.Remove(filepath.Join(q.dir, name)); err == nil {
		q.queued.Add(-1)
	}
}

// files lists the queued items, oldest first. Temporary files are an Add writing one (or, at start, a write a crash
// cut short: removeTemp).
func (q *Queue[T]) files() ([]string, error) {
	ents, err := os.ReadDir(q.dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if n := e.Name(); strings.HasSuffix(n, ext) && !strings.HasPrefix(n, ".") && e.Type().IsRegular() {
			out = append(out, n)
		}
	}
	return out, nil // (os.ReadDir lists by name: oldest first)
}

// removeTemp removes the temporary files of writes a crash cut short (their Add reported the failure). Only at
// start, before anything can be writing one.
func (q *Queue[T]) removeTemp() {
	ents, _ := os.ReadDir(q.dir)
	for _, e := range ents {
		if n := e.Name(); strings.HasPrefix(n, ".") && strings.HasSuffix(n, ".tmp") {
			_ = os.Remove(filepath.Join(q.dir, n))
		}
	}
}

// PurgeLost removes the items no configured master key opens that were queued before before (see the package
// PurgeLost), one file at a time as the worker changes them, so it runs while the queue does.
func (q *Queue[T]) PurgeLost(before time.Time) (int, error) {
	q.fileMu.Lock()
	defer q.fileMu.Unlock()
	// Counted again from disk with no add in flight (each holds addMu from taking its place to writing its file), so
	// every place taken has its file.
	q.addMu.Lock()
	defer q.addMu.Unlock()
	n, err := PurgeLost(q.dir, q.o.Sealer, before)
	if names, ferr := q.files(); ferr == nil {
		q.queued.Store(int64(len(names)))
	}
	return n, err
}

// PurgeLost removes from the queue in dir the items no key of sealer opens (sealed with a master key that is not in
// server.master_key nor server.previous_master_keys) that were queued before before: the time is in the file's name,
// which retries and re-seals keep. Such items are kept otherwise, to be delivered once their key is configured again;
// purging them gives them up for good. It returns how many it removed. A queue that is open is purged through it
// (Queue.PurgeLost); this is for one no worker runs on.
func PurgeLost(dir string, sealer *secure.Sealer, before time.Time) (int, error) {
	q := &Queue[struct{}]{dir: dir}
	names, err := q.files()
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	for _, name := range names {
		if !queuedBefore(name, before) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return n, err
		}
		if _, err := sealer.OpenFor("", string(b)); !errors.Is(err, secure.ErrUnknownKey) {
			continue // opened (or not this queue's binding, which is not judged here): not lost
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// queuedBefore reports whether the item in file name (Add: "<unix nanoseconds>-<random>.item") was queued before t.
// A name that is not one of those is not judged old.
func queuedBefore(name string, t time.Time) bool {
	at, _, ok := strings.Cut(name, "-")
	ns, err := strconv.ParseInt(at, 10, 64)
	return ok && err == nil && time.Unix(0, ns).Before(t)
}

// idleCheck bounds how long the scheduler sleeps: it notices files put there by hand, which nothing else wakes it for.
const idleCheck = time.Minute

// run is the scheduler. It looks at the queue whenever something may have changed: an item was added, a delivery ended
// (a worker and a share of its key are free, and a retry is waiting), or the next item waiting came due. It never
// waits for a delivery, so a slow one holds its worker and nothing else.
func (q *Queue[T]) run() {
	defer q.wg.Done()
	ctx, cancel := context.WithCancel(context.Background())
	defer q.deliveries.Wait() // after the cancel: the deliveries in flight end, then the queue is closed
	defer cancel()
	go func() { <-q.stop; cancel() }()
	for {
		wait := idleCheck
		if next := q.dispatch(ctx); !next.IsZero() {
			wait = min(max(time.Until(next), 0), idleCheck)
		}
		t := time.NewTimer(wait)
		select {
		case <-q.stop:
			t.Stop()
			return
		case <-q.kick:
		case <-t.C:
		}
		t.Stop()
	}
}

// dispatch starts a delivery for each due item the limits allow, oldest first, and returns when the next item waiting
// is due (zero: none known). It does not wait for the deliveries: each ends by waking the scheduler, which then fills
// the worker and key shares it freed. Once the workers are all busy it stops looking (so the next due time is only
// what it saw), for the end of a delivery makes it look again.
func (q *Queue[T]) dispatch(ctx context.Context) time.Time {
	names, err := q.files()
	if err != nil {
		q.o.Log.Error(q.o.Name+": cannot be read", "error", err)
		return time.Time{}
	}
	var next time.Time
	for _, name := range names {
		if ctx.Err() != nil {
			break
		}
		due, full := q.consider(ctx, name)
		if full {
			break
		}
		if !due.IsZero() && (next.IsZero() || due.Before(next)) {
			next = due
		}
	}
	return next
}

// consider starts the delivery of the item in file name if it is due, not being delivered, and there is room for it in
// the workers and in its key's share; if it is not due it returns when it will be. full reports that every worker is
// busy.
//
// The running check comes before the item is read, and both are under runMu: a delivery leaves running only after
// recording its outcome, so an item found not running is read as that outcome left it, never delivered again from a
// stale read. (runMu is held across the read, which is quick; Deliver never runs under it.)
func (q *Queue[T]) consider(ctx context.Context, name string) (due time.Time, full bool) {
	q.runMu.Lock()
	defer q.runMu.Unlock()
	if len(q.running) >= max(q.o.Workers, 1) {
		return time.Time{}, true
	}
	if _, ok := q.running[name]; ok {
		return time.Time{}, false
	}
	it, due := q.due(name)
	if it == nil {
		return due, false
	}
	var key string
	if q.o.Key != nil {
		key = q.o.Key(it.Item)
		if q.o.PerKey > 0 && q.perKey(key) >= q.o.PerKey {
			return time.Time{}, false // tried again when one of the key's deliveries ends
		}
	}
	q.running[name] = key
	q.deliveries.Add(1)
	go func() {
		defer q.deliveries.Done()
		q.deliver(ctx, name, it)
		q.runMu.Lock()
		delete(q.running, name)
		q.runMu.Unlock()
		q.wake()
	}()
	return time.Time{}, false
}

// perKey counts the deliveries running for key (under runMu).
func (q *Queue[T]) perKey(key string) (n int) {
	for _, k := range q.running {
		if k == key {
			n++
		}
	}
	return n
}

// due reads the queued item in file name and returns it if it is due; if not, it returns when it is next due (zero:
// no longer queued, or cannot be opened yet).
func (q *Queue[T]) due(name string) (*item[T], time.Time) {
	q.fileMu.Lock()
	defer q.fileMu.Unlock()
	if w, ok := q.waiting[name]; ok && w.next.After(time.Now()) {
		if fi, err := os.Stat(filepath.Join(q.dir, name)); err == nil && fi.ModTime().Equal(w.mod) {
			return nil, w.next
		}
	}
	delete(q.waiting, name)
	it, err := q.read(name)
	switch {
	case errors.Is(err, os.ErrNotExist), errors.Is(err, secure.ErrUnknownKey):
		// Gone, or sealed with a key not configured now: kept for when it is (Reseal logs it). Load-bearing: Reseal
		// counts such items, and that count is what keeps a previous master key from being retired while an item
		// still needs it (service QueuesStale); dropping them would lose the items and hide the dependency.
		return nil, time.Time{}
	case err != nil:
		q.o.Log.Error(q.o.Name+": item cannot be read, dropping it", "file", name, "error", err)
		q.remove(name)
		return nil, time.Time{}
	}
	if it.Next.After(time.Now()) {
		q.wait(name, it.Next)
		return nil, it.Next
	}
	return it, time.Time{}
}

// deliver tries the item read from file name and records the outcome.
//
// No lock is held while Deliver runs, so Reseal (and the other workers) go on meanwhile. That is safe because what
// Reseal changes is only how the file is sealed, never the item: the outcome is then recorded under fileMu, against
// whatever file is there. A delivered item's file is removed, whether Reseal rewrote it meanwhile or not (a Reseal
// that finds it gone counts it delivered); a failed one is written again, sealed here with the key active at that
// moment and under the lock, so a Reseal for a newer key (which runs after the keys changed) either follows this
// write and rewrites it, or finds it already sealed with the new key. Nothing is lost and nothing delivered twice:
// only the scheduler starts a delivery, and never of an item still running, which leaves running only after this has
// recorded its outcome.
func (q *Queue[T]) deliver(ctx context.Context, name string, it *item[T]) {
	dctx, dcancel := context.WithTimeout(ctx, 30*time.Second)
	err := q.o.Deliver(dctx, it.Item)
	dcancel()
	if err == nil {
		q.fileMu.Lock()
		q.remove(name)
		q.fileMu.Unlock()
		return
	}
	if ctx.Err() != nil { // stopping: the attempt does not count
		return
	}
	giveUp := it.Attempt >= len(q.o.Backoff)
	var delay time.Duration
	if !giveUp {
		delay = q.o.Backoff[it.Attempt]
	}
	it.Attempt++
	if q.o.Failed != nil {
		q.o.Failed(it.Item, it.Attempt, delay, err)
	}
	q.fileMu.Lock()
	defer q.fileMu.Unlock()
	if giveUp {
		q.remove(name)
		return
	}
	it.Next = time.Now().Add(delay)
	if err := q.write(name, it); err != nil {
		q.o.Log.Error(q.o.Name+": retry not recorded", "error", err)
	}
	q.wait(name, it.Next) // so the scheduler, woken when this delivery ends, finds when the retry is due
}

type waitingItem struct{ next, mod time.Time }

// wait records when the item in file name is next due, as the file is now (under fileMu).
func (q *Queue[T]) wait(name string, next time.Time) {
	fi, err := os.Stat(filepath.Join(q.dir, name))
	if err != nil {
		return
	}
	if q.waiting == nil {
		q.waiting = map[string]waitingItem{}
	}
	q.waiting[name] = waitingItem{next: next, mod: fi.ModTime()}
}
