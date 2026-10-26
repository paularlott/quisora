// Package queue is a small retry queue on disk: emails waiting for SMTP, back-channel logouts waiting for an
// application. An item is one file in the queue's directory, sealed with the master key (items carry single-use links
// and user identifiers) and written durably before Add returns, so it survives a restart or a crash and is delivered
// by the node once it is back. A worker delivers what is due, oldest first; an item that fails waits for the next
// delay of Backoff, and after the last one it is given up on (GiveUp). A file is removed once its item is delivered
// or given up on.
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
	Failed func(item T, attempt int, retry time.Duration, err error)
}

// Queue is a retry queue on disk (see the package comment).
type Queue[T any] struct {
	o      Options[T]
	dir    string
	fileMu sync.Mutex // one change to an item's file at a time: the worker's, or Reseal's
	// waiting is when the items this worker has read (or retried) are next due, by file, with the file's modification
	// time then (under fileMu): an item that is not due is not read and opened again on every pass (which would make
	// each Add cost the whole backlog) unless its file changed since.
	waiting map[string]waitingItem
	queued  atomic.Int64
	addMu   sync.RWMutex // adds hold it shared from taking their place to writing their file; PurgeLost exclusively
	kick    chan struct{}
	stop    chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
}

// item is a queued item as its file holds it (sealed).
type item[T any] struct {
	Item    T         `json:"m"`
	Attempt int       `json:"a"` // failed deliveries so far
	Next    time.Time `json:"n"` // not before
}

const ext = ".item"

// Open opens (creating) the queue in dir and starts its worker, which first delivers whatever a previous run left;
// call Close to stop it.
func Open[T any](dir string, o Options[T]) (*Queue[T], error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("%s: %w", o.Name, err)
	}
	q := &Queue[T]{o: o, dir: dir, kick: make(chan struct{}, 1), stop: make(chan struct{})}
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

// Close stops the worker; items not yet delivered stay queued for the next start.
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
	select {
	case q.kick <- struct{}{}:
	default:
	}
	return nil
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

// idleCheck bounds how long the worker sleeps: it notices a retry that is due, or files put there by hand.
const idleCheck = time.Minute

func (q *Queue[T]) run() {
	defer q.wg.Done()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-q.stop; cancel() }()
	for {
		wait := idleCheck
		if next := q.deliverDue(ctx); !next.IsZero() {
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

// deliverDue tries every item that is due, and returns when the next waiting one is (zero: none waiting).
func (q *Queue[T]) deliverDue(ctx context.Context) time.Time {
	names, err := q.files()
	if err != nil {
		q.o.Log.Error(q.o.Name+": cannot be read", "error", err)
		return time.Time{}
	}
	var next time.Time
	for _, name := range names {
		if ctx.Err() != nil {
			return time.Time{}
		}
		if due := q.deliverOne(ctx, name); !due.IsZero() && (next.IsZero() || due.Before(next)) {
			next = due
		}
	}
	return next
}

// deliverOne tries one queued item if it is due, and returns when it is next due (zero: no longer queued, cannot be
// opened yet, or the worker is stopping).
func (q *Queue[T]) deliverOne(ctx context.Context, name string) time.Time {
	q.fileMu.Lock()
	defer q.fileMu.Unlock()
	if w, ok := q.waiting[name]; ok && w.next.After(time.Now()) {
		if fi, err := os.Stat(filepath.Join(q.dir, name)); err == nil && fi.ModTime().Equal(w.mod) {
			return w.next
		}
	}
	delete(q.waiting, name)
	it, err := q.read(name)
	switch {
	case errors.Is(err, os.ErrNotExist), errors.Is(err, secure.ErrUnknownKey):
		// Gone, or sealed with a key not configured now: kept for when it is (Reseal logs it). Load-bearing: Reseal
		// counts such items, and that count is what keeps a previous master key from being retired while an item
		// still needs it (service QueuesStale); dropping them would lose the items and hide the dependency.
		return time.Time{}
	case err != nil:
		q.o.Log.Error(q.o.Name+": item cannot be read, dropping it", "file", name, "error", err)
		q.remove(name)
		return time.Time{}
	}
	if it.Next.After(time.Now()) {
		q.wait(name, it.Next)
		return it.Next
	}
	dctx, dcancel := context.WithTimeout(ctx, 30*time.Second)
	err = q.o.Deliver(dctx, it.Item)
	dcancel()
	if err == nil {
		q.remove(name)
		return time.Time{}
	}
	if ctx.Err() != nil { // stopping: the attempt does not count
		return time.Time{}
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
	if giveUp {
		q.remove(name)
		return time.Time{}
	}
	it.Next = time.Now().Add(delay)
	if err := q.write(name, it); err != nil {
		q.o.Log.Error(q.o.Name+": retry not recorded", "error", err)
	}
	q.wait(name, it.Next)
	return it.Next
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
