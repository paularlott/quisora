// Package queue is a node's durable retry queue: emails waiting for SMTP, back-channel logouts waiting for an
// application. An item is a record of the store (model.QueueItem), sealed with the master key (items carry single-use
// links and user identifiers) and written before Add returns, so it survives a restart or a crash and is delivered by
// the node once it is back.
//
// An item belongs to the node that queued it: its scope names the node (Options.Node), and only that node lists,
// counts or delivers it. The kind is node-local (never replicated, never backed up); on a database several nodes
// share, each sees the others' items and never touches them, so nothing is claimed or locked and no item is delivered
// by two nodes. A node that is gone for good leaves its items behind: each expires at the queue's discard horizon (set
// by Add: past the point it would have been given up anyway), and the store's purge removes it.
//
// The queue delivers what is due, earliest due first (the order items were added, for items not yet retried), by a
// bounded pool of workers (Options.Workers) that keeps one key's items (say, one organization's) from taking them all
// (Options.PerKey). A delivery starts as soon as a worker is free and an item is due (just added, retried, or its wait
// over), so a slow delivery holds its worker and nothing else. An item that fails waits for the next delay of
// Backoff, and after the last one it is given up on (Failed). A delivered or given-up item is ended by expiring it at
// once: the store's purge removes it, on every node and backend alike (a tombstone of a node-local kind would wait for
// a gossip partition's purge, which never covers it).
//
// After a master key change the queue is re-sealed with the active key (Reseal) before the node reports that key, so
// a rotation the cluster reports complete leaves no queued item needing a previous key. An item sealed with a key
// that is not configured is kept, and delivered once that key is configured again (or discarded at its horizon).
package queue

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

// ErrFull is returned by Add when this node's items of the queue number Max, or MaxPerKey of the item's key.
var ErrFull = errors.New("queue: full")

// Options configure a queue. Store, Node, Sealer and Deliver are required.
type Options[T any] struct {
	Name  string // the queue's name: its items' (model.QueueItem.Queue), and in log messages ("mail")
	Log   logger.Logger
	Store store.Store
	// Node is this node's id (cluster.Node.ID): the queue's items are this node's, and only them it counts and delivers.
	Node    string
	Sealer  *secure.Sealer
	Binding string // binds the sealed items to this queue (secure.Sealer.SealFor)
	// Backoff are the delays after each failed delivery; after the last, the item is given up on.
	Backoff []time.Duration
	Max     int // most items of this node held; Add refuses more (ErrFull)
	// MaxPerKey is the most items of this node held of one Key (0: no limit besides Max; with no Key, all items have
	// one key). It keeps one key, an organization whose application never answers, from filling the queue with its
	// items so that Add refuses (ErrFull) the others'.
	MaxPerKey int
	Deliver   func(ctx context.Context, item T) error
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

const (
	// deliveryTimeout bounds one delivery.
	deliveryTimeout = 30 * time.Second
	// discardMargin is how long past its last retry (Add: the discard horizon) an item is kept: for the attempts
	// themselves and a backlog behind them, and for a master key put back. Past it the item is worth nothing (its
	// retries are over) and expires, so the items of a node that is gone, or that no key opens, do not linger.
	discardMargin = 24 * time.Hour
	// idleCheck is how often the scheduler reads the whole queue afresh, whatever it has learned to skip (dispatch).
	idleCheck = time.Minute
	// scanPage is how many items the scheduler reads at a time.
	scanPage = 100
	// writeWait bounds the recording of a delivery's outcome, which goes on when the queue is closing.
	writeWait = 10 * time.Second
)

// Queue is a node's retry queue in the store (see the package comment).
type Queue[T any] struct {
	o     Options[T]
	items *store.Table[model.QueueItem, *model.QueueItem]
	scope string // this node's items of the queue (model.QueueScope)
	// addMu is held by an Add from its counts to its write, so this node's adds never pass a cap between them, and taken
	// by Reseal before it reads the queue, so every Add that sealed its item before the keys changed has written it.
	addMu sync.Mutex
	// itemMu is held for one change to a stored item at a time (a delivery's outcome, a re-seal), never across a
	// delivery: that takes as long as an application takes to answer.
	itemMu sync.Mutex
	// mu guards the scheduler's state below. It is held by a pass of the scheduler (dispatch) while it reads the queue,
	// by a delivery's end (its outcome written, and its item leaving running, as one step: a pass never reads an item a
	// delivery has changed and not yet left, whose place in the queue a store that loads what it lists later than it
	// lists it would not show consistently), and briefly by an Add.
	mu sync.Mutex
	// running is the items being delivered now, by id, with their keys, and perKey how many of each key. Only the
	// scheduler adds to them, and never an item already running, so an item is never delivered twice at once; a
	// delivery leaves them as it records its outcome.
	running map[string]string
	perKey  map[string]int
	// floor and behind spare the scheduler what it cannot deliver: every due item before floor that is not running is
	// one no key opens, one whose outcome was not recorded (unrecorded), or of a key in behind (it was at its PerKey
	// when the scheduler read past its item, or its item was written due behind the floor). A pass reads the due items
	// from floor on (atFloor are those due exactly at floor it has read already, by id), and of each key in behind only
	// its first ones (its range of the slot index), so the backlog of a key at its limit is not read again each time the
	// scheduler looks at the queue. Reset each idleCheck.
	floor   time.Time
	atFloor map[string]bool
	behind  map[string]bool
	// unrecorded are the items whose last delivery's outcome the store did not take (deliver): due as they were, they
	// are not delivered again before the next full read of the queue, rather than at once and again while the store
	// fails.
	unrecorded map[string]bool
	// queued is the last count of this node's items (what Queued reports while the store cannot answer).
	queued     atomic.Int64
	deliveries sync.WaitGroup
	kick       chan struct{} // the scheduler has something new to look at (a buffer of one: a kick is never lost)
	stop       chan struct{}
	wg         sync.WaitGroup
	once       sync.Once
}

func newQueue[T any](o Options[T]) *Queue[T] {
	return &Queue[T]{o: o, items: store.NewTable[model.QueueItem](o.Store), scope: model.QueueScope(o.Name, o.Node),
		running: map[string]string{}, perKey: map[string]int{}, behind: map[string]bool{}, unrecorded: map[string]bool{},
		kick: make(chan struct{}, 1), stop: make(chan struct{})}
}

// Open opens this node's queue and starts its scheduler, which first delivers whatever a previous run left (re-sealed
// with the active master key); call Close to stop it.
func Open[T any](o Options[T]) *Queue[T] {
	q := newQueue(o)
	q.Reseal()
	if n := q.Queued(); n > 0 {
		o.Log.Info(o.Name+" queue: delivering items left from before", "items", n)
	}
	q.wg.Add(1)
	go q.run()
	return q
}

// Close stops the scheduler, cancelling the deliveries in flight (their attempts do not count) and waiting for them;
// items not yet delivered stay queued for the next start.
func (q *Queue[T]) Close() {
	q.once.Do(func() { close(q.stop) })
	q.wg.Wait()
}

// Queued returns how many items of this node are waiting (the last count, when the store cannot answer now).
func (q *Queue[T]) Queued() int {
	if n, err := q.items.Count(context.Background(), q.scope); err == nil {
		q.queued.Store(int64(n))
	}
	return int(q.queued.Load())
}

// Add queues it, to be delivered once after (now: at once) having failed attempts deliveries already, and returns
// once it is stored. The caps count this node's items in the store (on a shared database, the others' items are
// theirs: each node holds up to Max of its own).
func (q *Queue[T]) Add(it T, after time.Duration, attempts int) error {
	ctx := context.Background()
	plain, err := json.Marshal(it)
	if err != nil {
		return err
	}
	key := q.keyOf(it)
	q.addMu.Lock()
	defer q.addMu.Unlock()
	n, err := q.items.Count(ctx, q.scope)
	if err != nil {
		return err
	}
	if n >= q.o.Max {
		return ErrFull
	}
	if q.o.MaxPerKey > 0 {
		_, held, err := q.items.List(ctx, q.keyQuery(key, 1))
		if err != nil {
			return err
		}
		if held >= q.o.MaxPerKey {
			return ErrFull
		}
	}
	now := time.Now()
	item := &model.QueueItem{Meta: model.Meta{ID: model.NewID()}, Queue: q.o.Name, Node: q.o.Node, Key: key,
		Attempt: attempts, Next: now.Add(after), Sealed: q.o.Sealer.SealFor(q.o.Binding, plain),
		Expires: now.Add(after + q.horizon(attempts))}
	if err := q.items.Create(ctx, item); err != nil {
		return err
	}
	q.queued.Store(int64(n + 1))
	q.written(item)
	q.wake()
	return nil
}

// horizon is how long after its first attempt an item that has failed attempts deliveries is kept at most: the
// delays of its retries, then discardMargin.
func (q *Queue[T]) horizon(attempts int) time.Duration {
	d := discardMargin
	for _, b := range q.o.Backoff[min(attempts, len(q.o.Backoff)):] {
		d += b
	}
	return d
}

// keyQuery lists the items of key in the order they come due (their range of the slot index), limit at a time.
func (q *Queue[T]) keyQuery(key string, limit int) store.ListQuery {
	return store.ListQuery{Scope: q.scope, Sort: "slot", Limit: limit,
		Filters: []store.Filter{{Field: "slot", Op: store.OpPrefix, Value: model.QueueKeySlots(key)}}}
}

// keyOf is the key of it: its share of the queue and of the workers (Options.Key; none: all items have the same).
func (q *Queue[T]) keyOf(it T) string {
	if q.o.Key == nil {
		return ""
	}
	return q.o.Key(it)
}

// written tells the scheduler of an item just written due when it is: one due already (a pass may have read past where
// it now is) puts its key behind the floor, so the next pass reads that key's first items.
func (q *Queue[T]) written(it *model.QueueItem) {
	if it.Next.After(time.Now()) {
		return // due after every pass so far has read: a pass reads it once it is due
	}
	q.mu.Lock()
	q.behind[it.Key] = true
	q.mu.Unlock()
}

// wake tells the scheduler to look at the queue again.
func (q *Queue[T]) wake() {
	select {
	case q.kick <- struct{}{}:
	default:
	}
}

// rescan makes the next pass read the whole queue again.
func (q *Queue[T]) rescan() {
	q.mu.Lock()
	q.floor, q.atFloor, q.behind, q.unrecorded = time.Time{}, nil, map[string]bool{}, map[string]bool{}
	q.mu.Unlock()
}

// Reseal re-seals every item of this node with the active master key, and returns how many are still not sealed with
// it: stale, those whose rewrite failed (a store that refused it), which still need the configured previous key they
// are sealed with: while any is left no previous key may be removed (app.ReloadMasterKeys refuses, and this node
// reports the rotation unfinished); and lost, those no configured key opens, which need no configured key, so they hold
// nothing back: they wait for their key to be configured again, and are discarded at their horizon (Add). Call it
// after the master keys change, before the node reports its new key (service.ReportMasterKey). A queue that cannot be
// read counts one stale item more.
func (q *Queue[T]) Reseal() (stale, lost int) {
	q.addMu.Lock() // (every Add sealing with the keys before the change has written its item, and is read below)
	q.addMu.Unlock()
	ctx := context.Background()
	for after := ""; ; {
		page, _, err := q.items.List(ctx, store.ListQuery{Scope: q.scope, After: after, Limit: scanPage})
		if err != nil {
			q.o.Log.Error(q.o.Name+" queue: cannot be read", "error", err)
			stale++
			break
		}
		for _, it := range page {
			switch err := q.reseal(ctx, it); {
			case errors.Is(err, secure.ErrUnknownKey):
				lost++
			case err != nil:
				stale++
			}
		}
		if len(page) < scanPage {
			break
		}
		after = page[len(page)-1].ID
	}
	if stale > 0 {
		q.o.Log.Error(q.o.Name+" queue: items not re-sealed with the active master key (tried again at the node's "+
			"next key report); their previous key stays needed", "items", stale)
	}
	if lost > 0 {
		q.o.Log.Warn(q.o.Name+" queue: items sealed with a master key that is not configured: put it back in "+
			"server.previous_master_keys, or they are discarded once their retries are a day over", "items", lost)
	}
	// The keys changed: an item no key opened before may open now, wherever the scheduler last skipped it.
	q.rescan()
	q.wake()
	return stale, lost
}

// reseal re-seals item it with the active master key, as it is stored now: a delivery's outcome recorded since it was
// read is re-sealed in turn (it changes the item's state, never what is sealed). An item gone meanwhile (delivered) is
// no failure.
func (q *Queue[T]) reseal(ctx context.Context, it *model.QueueItem) error {
	q.itemMu.Lock()
	defer q.itemMu.Unlock()
	for {
		sealed, err := q.o.Sealer.Reseal(q.o.Binding, it.Sealed)
		if err != nil || sealed == it.Sealed {
			return err
		}
		it.Sealed = sealed
		switch err := q.items.Update(ctx, it); {
		case errors.Is(err, store.ErrNotFound):
			return nil
		case !errors.Is(err, store.ErrStale):
			return err
		}
		// Changed since it was read (and not since: itemMu is held): re-seal what it is now.
		if it, err = q.items.Get(ctx, it.ID); errors.Is(err, store.ErrNotFound) {
			return nil
		} else if err != nil {
			return err
		}
	}
}

// run is the scheduler. It looks at the queue whenever something may have changed: an item was added, a delivery ended
// (a worker and a share of its key are free, and a retry is waiting), or the next item waiting came due. It never
// waits for a delivery, so a slow one holds its worker and nothing else.
func (q *Queue[T]) run() {
	defer q.wg.Done()
	ctx, cancel := context.WithCancel(context.Background())
	defer q.deliveries.Wait() // after the cancel: the deliveries in flight end, then the queue is closed
	defer cancel()
	go func() { <-q.stop; cancel() }()
	read := time.Now()
	for {
		if time.Since(read) >= idleCheck {
			// What the scheduler skips is read again now and then: an item whose outcome could not be recorded (a
			// store that failed), or one a clock that went back left behind the floor.
			q.rescan()
			read = time.Now()
		}
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

// dispatch starts a delivery for each due item the limits allow, earliest due first, and returns when the next item
// waiting is due (zero: none). It does not wait for the deliveries: each ends by waking the scheduler, which then fills
// the worker and key shares it freed. It reads first the keys behind the floor that have room now (one whose delivery
// just ended), only as far as their room, then the due items from the floor on, until the workers are all busy.
func (q *Queue[T]) dispatch(ctx context.Context) time.Time {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now()
	for key := range q.behind {
		if ctx.Err() != nil || q.free() == 0 {
			break
		}
		if q.room(key) > 0 && q.serveKey(ctx, key, now) {
			delete(q.behind, key)
		}
	}
	q.scan(ctx, now)
	if ctx.Err() != nil {
		return time.Time{}
	}
	next, _, err := q.items.List(ctx, store.ListQuery{Scope: q.scope, Sort: "due", Limit: 1,
		Filters: []store.Filter{{Field: "due", Op: store.OpGTE, Value: now}}})
	if err != nil || len(next) == 0 {
		return time.Time{}
	}
	return next[0].Next
}

// serveKey starts the deliveries of key's due items its room allows, from its first (under mu), and reports whether
// it read all of them: key then has nothing due behind the floor. It reads as many as the key's deliveries running
// (likely its first) and its room, and twice as many again while that is not enough (items no key opens, or whose
// outcome was not recorded, are in the way).
func (q *Queue[T]) serveKey(ctx context.Context, key string, now time.Time) bool {
	for limit := q.perKey[key] + q.room(key); ; limit *= 2 {
		page, total, err := q.items.List(ctx, q.keyQuery(key, limit))
		if err != nil {
			q.o.Log.Error(q.o.Name+" queue: cannot be read", "error", err)
			return false
		}
		for _, it := range page {
			if it.Next.After(now) {
				return true // and the rest of the key's items: they come due after this pass read
			}
			if _, ok := q.running[it.ID]; ok { // (or started by the page before)
				continue
			}
			if q.room(key) == 0 {
				return false
			}
			q.consider(ctx, it)
		}
		if total <= limit { // (not len(page): a store may list an item and find it gone, past its horizon, as it loads it)
			return true
		}
	}
}

// scan starts the deliveries of the due items from the floor on that the limits allow, in the order they came due,
// and moves the floor past each item it has read (under mu). An item of a key at its PerKey puts its key behind the
// floor. Once the workers are all busy it stops, the floor at the last item it read; once it has read every due item,
// the floor is now, to the millisecond below (a store keeps due times to the millisecond or finer: an item written due
// after now, which this pass may have missed, is stored due at or after that floor).
func (q *Queue[T]) scan(ctx context.Context, now time.Time) {
	for ctx.Err() == nil && q.free() > 0 {
		filters := []store.Filter{{Field: "due", Op: store.OpLT, Value: now}}
		if !q.floor.IsZero() {
			filters = append(filters, store.Filter{Field: "due", Op: store.OpGTE, Value: q.floor})
		}
		// The items due at floor that were read are read again, not skipped by an offset: one may have left since (its
		// delivery ended), and an offset would then skip another.
		limit := scanPage + len(q.atFloor)
		page, total, err := q.items.List(ctx, store.ListQuery{Scope: q.scope, Sort: "due", Filters: filters, Limit: limit})
		if err != nil {
			q.o.Log.Error(q.o.Name+" queue: cannot be read", "error", err)
			return
		}
		for _, it := range page {
			if it.Next.Equal(q.floor) && q.atFloor[it.ID] {
				continue
			}
			if q.free() == 0 {
				return
			}
			if !it.Next.Equal(q.floor) {
				q.floor, q.atFloor = it.Next, nil
			}
			if q.atFloor == nil {
				q.atFloor = map[string]bool{}
			}
			q.atFloor[it.ID] = true
			if _, ok := q.running[it.ID]; ok {
				continue
			}
			if q.room(it.Key) == 0 { // its key's to read again once it has room (serveKey)
				q.behind[it.Key] = true
				continue
			}
			q.consider(ctx, it)
		}
		if f := now.Truncate(time.Millisecond); total <= limit { // (as in serveKey)
			if f.After(q.floor) {
				q.floor, q.atFloor = f, nil
			}
			return
		}
	}
}

// free is how many workers are free (under mu).
func (q *Queue[T]) free() int { return max(q.o.Workers, 1) - len(q.running) }

// room is how many more deliveries of key may start now: the free workers, and no more than its PerKey allows (under
// mu).
func (q *Queue[T]) room(key string) int {
	n := q.free()
	if q.o.Key != nil && q.o.PerKey > 0 {
		n = min(n, q.o.PerKey-q.perKey[key])
	}
	return max(n, 0)
}

// consider starts the delivery of due item it, which is not running (under mu). An item no configured key opens is
// left as it is, for when its key is configured again; one that cannot be read at all is dropped; one whose last
// outcome could not be recorded waits for the next full read of the queue.
func (q *Queue[T]) consider(ctx context.Context, it *model.QueueItem) {
	if q.unrecorded[it.ID] {
		return
	}
	var v T
	plain, err := q.o.Sealer.OpenFor(q.o.Binding, it.Sealed)
	if err == nil {
		err = json.Unmarshal(plain, &v)
	}
	switch {
	case errors.Is(err, secure.ErrUnknownKey):
		// Load-bearing: Reseal counts such items, and that count is what keeps a previous master key from being
		// retired while an item still needs it (service QueuesStale); dropping them would lose the items and hide the
		// dependency.
		return
	case err != nil:
		q.o.Log.Error(q.o.Name+" queue: item cannot be read, dropping it", "item", it.ID, "error", err)
		q.itemMu.Lock()
		if err := q.end(ctx, it); err != nil {
			q.o.Log.Error(q.o.Name+" queue: item not dropped", "item", it.ID, "error", err)
		}
		q.itemMu.Unlock()
		return
	}
	q.running[it.ID] = it.Key
	q.perKey[it.Key]++
	q.deliveries.Add(1)
	go func() {
		defer q.deliveries.Done()
		q.deliver(ctx, it, v)
		q.wake()
	}()
}

// deliver tries item it (holding v), then records the outcome and leaves running, as one step under mu.
//
// No lock is held while Deliver runs, so Reseal (and the other workers) go on meanwhile. The outcome is then recorded
// under itemMu on the item as it is stored now: Reseal changes only how it is sealed, so a failed item written back
// keeps the sealing Reseal gave it, and a Reseal for a newer key (which runs after the keys changed) re-seals it after.
// A delivery whose outcome cannot be recorded (the store failed) leaves the item as it was, due: it is delivered again
// once the scheduler reads the whole queue again (idleCheck), not at once (unrecorded).
func (q *Queue[T]) deliver(ctx context.Context, it *model.QueueItem, v T) {
	dctx, dcancel := context.WithTimeout(ctx, deliveryTimeout)
	err := q.o.Deliver(dctx, v)
	dcancel()
	stopping := err != nil && ctx.Err() != nil // the attempt does not count
	giveUp := err != nil && it.Attempt >= len(q.o.Backoff)
	var delay time.Duration
	if err != nil && !giveUp {
		delay = q.o.Backoff[it.Attempt]
	}
	if err != nil && !stopping && q.o.Failed != nil {
		q.o.Failed(v, it.Attempt+1, delay, err)
	}
	wctx, wcancel := context.WithTimeout(context.WithoutCancel(ctx), writeWait)
	defer wcancel()
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.running, it.ID)
	if q.perKey[it.Key]--; q.perKey[it.Key] <= 0 {
		delete(q.perKey, it.Key)
	}
	if stopping {
		return
	}
	retry, err := q.record(wctx, it, err == nil || giveUp, delay)
	switch {
	case err != nil:
		q.o.Log.Error(q.o.Name+" queue: outcome not recorded (the item is delivered again once the queue is read "+
			"afresh)", "item", it.ID, "error", err)
		q.unrecorded[it.ID] = true
	case retry != nil && !retry.Next.After(time.Now()):
		q.behind[it.Key] = true // due already: a pass may have read past where it now is (written)
	}
}

// record records the outcome of a delivery of item it (holding itemMu): ended, or failed once more and due again
// after delay, which it returns.
func (q *Queue[T]) record(ctx context.Context, it *model.QueueItem, ended bool, delay time.Duration) (*model.QueueItem, error) {
	q.itemMu.Lock()
	defer q.itemMu.Unlock()
	cur, err := q.items.Get(ctx, it.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, nil // past its horizon meanwhile
	case err != nil:
		return nil, err
	case ended:
		return nil, q.end(ctx, cur)
	}
	cur.Attempt, cur.Next = it.Attempt+1, time.Now().Add(delay)
	if err := q.items.Update(ctx, cur); err != nil {
		return nil, err
	}
	return cur, nil
}

// end removes item it from the queue (under itemMu): expired at once, it is no longer read, and the store's purge
// removes it (see the package comment). The expiry is a second ago, not now: a store keeps it rounded up to its
// precision, and the item must not read as live meanwhile. One gone meanwhile (past its horizon) is no failure.
func (q *Queue[T]) end(ctx context.Context, it *model.QueueItem) error {
	it.Expires = time.Now().Add(-time.Second)
	if err := q.items.Update(ctx, it); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}
