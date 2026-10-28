// Package queue is a node's durable retry queue: emails waiting for SMTP, back-channel logouts waiting for an
// application. An item is a record of the store (model.QueueItem), sealed with the master key (items carry single-use
// links and user identifiers) and written before Add returns, so it survives a restart or a crash and is delivered by
// the node once it is back.
//
// An item belongs to the node that queued it: its scope names the node (Options.Node), and only that node reads,
// writes or delivers it. The kind is node-local (never replicated, never backed up); on a database several nodes
// share, each sees the others' items and never touches them, so nothing is claimed or locked and no item is delivered
// by two nodes. A node that is gone for good leaves its items behind: each expires at the queue's discard horizon (set
// by Add: past the point it would have been given up anyway), and the store's purge removes it.
//
// The store is only the durable copy. Being the only writer of its items, the node keeps an index of them in memory
// (what is due when, of which key, after how many attempts), listed from the store once (Open) and kept by its own
// writes from then on: the scheduler and the caps read the index alone, never the store, so what they cost does not
// grow with the items the store still holds expired, and a request's Add never waits for the scheduler's reads.
// Nothing else changes an item: a re-seal (Reseal) rewrites only how it is sealed, which the index does not hold, and an
// item's expiry is in the index too. The index and the store can part only where a write's outcome is unknown (a store
// that fails as it commits an Add, which then reports an error): such an item is not in the index, so it is sent after
// the node's next start, or discarded at its horizon.
//
// The queue delivers what is due, earliest due first (the order items were added, for items not yet retried), by a
// bounded pool of workers (Options.Workers) that keeps one key's items (say, one organization's) from taking them all
// (Options.PerKey). A delivery starts as soon as a worker is free and an item is due (just added, retried, or its wait
// over), so a slow delivery holds its worker and nothing else. A delivery reads its item from the store first (to open
// it, and to drop one past its horizon). An item that fails waits for the next delay of Backoff, and after the last one
// it is given up on (Failed). A delivered or given-up item is ended by expiring it at once: the store's purge removes
// it, on every node and backend alike (a tombstone of a node-local kind would wait for a gossip partition's purge, which
// never covers it). An item whose end the store does not take is never delivered again: its end is written again until
// the store takes it, or its horizon passes.
//
// After a master key change the queue is re-sealed with the active key (Reseal) before the node reports that key, so
// a rotation the cluster reports complete leaves no queued item needing a previous key. An item sealed with a key
// that is not configured is kept, and delivered once that key is configured again (or discarded at its horizon).
package queue

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"slices"
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
	// storeWait is how long an item waits after the store failed it (the read before its delivery, or the write of its
	// outcome), and how often the queue is listed again while it could not be (Open).
	storeWait = time.Minute
	// listPage is how many items the listing of the queue (Open) reads at a time.
	listPage = 500
	// writeWait bounds each read and write of an item by a delivery, which goes on when the queue is closing.
	writeWait = 10 * time.Second
)

// entry is what the index holds of an item: all the scheduler and the caps need, so neither reads the store.
type entry struct {
	id, key string
	seq     uint64    // the order of the items due at the same time: the order they were added (or listed)
	attempt int       // failed deliveries so far
	next    time.Time // not to be tried before
	expires time.Time // its discard horizon (model.QueueItem.Expires)
	// ended is an item delivered or given up on whose end the store has not taken: it is due only to write that end
	// again, and is never delivered again.
	ended bool
	// locked is an item no configured master key opens: it waits for the keys to change (Reseal), due at its horizon.
	locked bool
}

// before orders the entries as they come due, the earlier added first among those due at once. It compares wall
// clock times only, so an order made of times read from the store and of this process's clock stays consistent.
func (e *entry) before(o *entry) int {
	if c := cmp.Compare(e.next.UnixNano(), o.next.UnixNano()); c != 0 {
		return c
	}
	return cmp.Compare(e.seq, o.seq)
}

// Queue is a node's retry queue in the store (see the package comment).
type Queue[T any] struct {
	o     Options[T]
	items *store.Table[model.QueueItem, *model.QueueItem]
	scope string // this node's items of the queue (model.QueueScope)
	// sealing is held (shared) by each Add from sealing its item to entering it in the index, and taken by Reseal before
	// it reads the index, so every item sealed with the keys before a change is re-sealed.
	sealing sync.RWMutex
	// mu guards the index and the scheduler's state below. It is held for work in memory only, never across a call to
	// the store or a delivery, so an Add waits for no read or write of another.
	mu sync.Mutex
	// index is this node's items: waiting, being delivered, or ended and their end not yet written; waiting is those not
	// being delivered, in the order they come due (entry.before).
	index   map[string]*entry
	waiting []*entry
	// held is how many items of each key the index holds and Adds are writing; adding is how many Adds are writing (the
	// caps count them: an Add reserves its place before it writes, so Adds at once never pass a cap between them).
	held   map[string]int
	adding int
	// running is how many deliveries are running, and busy how many of each key. An item being delivered is out of
	// waiting until its delivery ends, so it is never delivered twice at once.
	running int
	busy    map[string]int
	seq     uint64
	// listed is set once the store's items of this node are in the index; nothing is delivered before (dispatch), and
	// until then the caps count only the items added since the start.
	listed     atomic.Bool
	deliveries sync.WaitGroup
	kick       chan struct{} // the scheduler has something new to look at (a buffer of one: a kick is never lost)
	stop       chan struct{}
	wg         sync.WaitGroup
	once       sync.Once
}

func newQueue[T any](o Options[T]) *Queue[T] {
	return &Queue[T]{o: o, items: store.NewTable[model.QueueItem](o.Store), scope: model.QueueScope(o.Name, o.Node),
		index: map[string]*entry{}, held: map[string]int{}, busy: map[string]int{},
		kick: make(chan struct{}, 1), stop: make(chan struct{})}
}

// Open opens this node's queue and starts its scheduler, which first delivers whatever a previous run left (re-sealed
// with the active master key); call Close to stop it.
func Open[T any](o Options[T]) *Queue[T] {
	q := newQueue(o)
	if err := q.list(context.Background()); err != nil {
		o.Log.Error(o.Name+" queue: cannot be read (read again every minute; nothing is delivered until it is)", "error", err)
	}
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

// Queued returns how many items of this node the store holds.
func (q *Queue[T]) Queued() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.index)
}

// list enters this node's items in the store into the index, once: from then on the index follows the node's own
// writes. Items Add entered meanwhile are entered once. Nothing is delivered before it, so no item ends while it reads
// and every item it lists is still queued.
func (q *Queue[T]) list(ctx context.Context) error {
	var items []*model.QueueItem
	for after := ""; ; {
		page, _, err := q.items.List(ctx, store.ListQuery{Scope: q.scope, After: after, Limit: listPage})
		if err != nil {
			return err
		}
		items = append(items, page...)
		if len(page) < listPage {
			break
		}
		after = page[len(page)-1].ID
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, it := range items {
		q.enter(&entry{id: it.ID, key: it.Key, attempt: it.Attempt, next: it.Next, expires: it.Expires})
	}
	q.listed.Store(true)
	return nil
}

// Add queues it, to be delivered once after (now: at once) having failed attempts deliveries already, and returns
// once it is stored. The caps count this node's items (on a shared database, the others' items are theirs: each node
// holds up to Max of its own).
func (q *Queue[T]) Add(it T, after time.Duration, attempts int) error {
	plain, err := json.Marshal(it)
	if err != nil {
		return err
	}
	key := q.keyOf(it)
	q.sealing.RLock()
	defer q.sealing.RUnlock()
	q.mu.Lock()
	if len(q.index)+q.adding >= q.o.Max || q.o.MaxPerKey > 0 && q.held[key] >= q.o.MaxPerKey {
		q.mu.Unlock()
		return ErrFull
	}
	q.adding++
	q.held[key]++
	q.mu.Unlock()

	now := time.Now()
	item := &model.QueueItem{Meta: model.Meta{ID: model.NewID()}, Queue: q.o.Name, Node: q.o.Node, Key: key,
		Attempt: attempts, Next: now.Add(after), Sealed: q.o.Sealer.SealFor(q.o.Binding, plain),
		Expires: now.Add(after + q.horizon(attempts))}
	err = q.items.Create(context.Background(), item)

	q.mu.Lock()
	q.adding--
	q.release(key)
	if err == nil {
		q.enter(&entry{id: item.ID, key: key, attempt: attempts, next: item.Next, expires: item.Expires})
	}
	q.mu.Unlock()
	if err != nil {
		return err
	}
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

// keyOf is the key of it: its share of the queue and of the workers (Options.Key; none: all items have the same).
func (q *Queue[T]) keyOf(it T) string {
	if q.o.Key == nil {
		return ""
	}
	return q.o.Key(it)
}

// enter puts e in the index, waiting, unless its item is there already (under mu).
func (q *Queue[T]) enter(e *entry) {
	if q.index[e.id] != nil {
		return
	}
	q.seq++
	e.seq = q.seq
	q.index[e.id] = e
	q.held[e.key]++
	q.wait(e)
}

// release gives back a place of key (under mu).
func (q *Queue[T]) release(key string) {
	if q.held[key]--; q.held[key] <= 0 {
		delete(q.held, key)
	}
}

// wait puts e, which is not being delivered, in waiting at its place (under mu).
func (q *Queue[T]) wait(e *entry) {
	i, _ := slices.BinarySearchFunc(q.waiting, e, (*entry).before)
	q.waiting = slices.Insert(q.waiting, i, e)
}

// wake tells the scheduler to look at the queue again.
func (q *Queue[T]) wake() {
	select {
	case q.kick <- struct{}{}:
	default:
	}
}

// Reseal re-seals every item of this node with the active master key, and returns how many are still not sealed with
// it: stale, those whose rewrite failed (a store that refused it), which still need the configured previous key they
// are sealed with: while any is left no previous key may be removed (app.ReloadMasterKeys refuses, and this node
// reports the rotation unfinished); and lost, those no configured key opens, which need no configured key, so they hold
// nothing back: they wait for their key to be configured again, and are discarded at their horizon (Add). Call it
// after the master keys change, before the node reports its new key (service.ReportMasterKey). A queue the store could
// not list yet (Open) counts one stale item more: what it holds is not known.
func (q *Queue[T]) Reseal() (stale, lost int) {
	q.sealing.Lock() // (every Add sealing with the keys before the change has entered its item, and is read below)
	q.sealing.Unlock()
	if !q.listed.Load() {
		stale++
	}
	q.mu.Lock()
	ids := make([]string, 0, len(q.index))
	for id := range q.index {
		ids = append(ids, id)
	}
	q.mu.Unlock()
	ctx := context.Background()
	for _, id := range ids {
		switch err := q.reseal(ctx, id); {
		case errors.Is(err, secure.ErrUnknownKey):
			lost++
		case err != nil:
			stale++
		}
	}
	if stale > 0 {
		q.o.Log.Error(q.o.Name+" queue: items not re-sealed with the active master key (tried again at the node's "+
			"next key report); their previous key stays needed", "items", stale)
	}
	if lost > 0 {
		q.o.Log.Warn(q.o.Name+" queue: items sealed with a master key that is not configured: put it back in "+
			"server.previous_master_keys, or they are discarded once their retries are a day over", "items", lost)
	}
	// The keys changed: an item no key opened may open now.
	q.mu.Lock()
	now := time.Now()
	for _, e := range q.index {
		if e.locked {
			if i, ok := slices.BinarySearchFunc(q.waiting, e, (*entry).before); ok {
				q.waiting = slices.Delete(q.waiting, i, i+1)
			}
			e.locked, e.next = false, now
			q.wait(e)
		}
	}
	q.mu.Unlock()
	q.wake()
	return stale, lost
}

// reseal re-seals item id with the active master key, as it is stored now. An item gone meanwhile (past its horizon,
// or ended) is no failure.
func (q *Queue[T]) reseal(ctx context.Context, id string) error {
	return q.rewrite(ctx, id, nil, func(it *model.QueueItem) (bool, error) {
		sealed, err := q.o.Sealer.Reseal(q.o.Binding, it.Sealed)
		if err != nil || sealed == it.Sealed {
			return false, err
		}
		it.Sealed = sealed
		return true, nil
	})
}

// rewrite applies change to item id as stored (it: as read already; nil: read now) and writes it, unless change says
// there is nothing to write. A re-seal and a delivery's outcome may rewrite one item at once: the one that finds the
// item changed since it read it applies its change again to what is stored now, so each keeps the other's. An item gone
// (past its horizon) is no failure.
func (q *Queue[T]) rewrite(ctx context.Context, id string, it *model.QueueItem, change func(*model.QueueItem) (bool, error)) error {
	for {
		if it == nil {
			var err error
			if it, err = q.items.Get(ctx, id); errors.Is(err, store.ErrNotFound) {
				return nil
			} else if err != nil {
				return err
			}
		}
		if write, err := change(it); err != nil || !write {
			return err
		}
		switch err := q.items.Update(ctx, it); {
		case errors.Is(err, store.ErrStale):
			it = nil
		case errors.Is(err, store.ErrNotFound):
			return nil
		default:
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
	for {
		var due <-chan time.Time
		if next := q.dispatch(ctx); !next.IsZero() {
			due = time.After(time.Until(next))
		}
		select {
		case <-q.stop:
			return
		case <-q.kick:
		case <-due:
		}
	}
}

// dispatch starts a delivery for each due item the limits allow, earliest due first, and returns when the next item
// waiting is due (zero: none, or every worker is busy: a delivery's end wakes the scheduler). It reads the index only:
// what it passes over is the due items of the keys at their PerKey, then it stops at the first item not due. A queue
// not yet listed (Open) is listed first: until it is, nothing is delivered, and it is tried again after storeWait.
func (q *Queue[T]) dispatch(ctx context.Context) time.Time {
	if !q.listed.Load() {
		if err := q.list(ctx); err != nil {
			if ctx.Err() == nil {
				q.o.Log.Error(q.o.Name+" queue: cannot be read", "error", err)
			}
			return time.Now().Add(storeWait)
		}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now()
	for i := 0; i < len(q.waiting) && q.running < max(q.o.Workers, 1) && ctx.Err() == nil; {
		e := q.waiting[i]
		if e.next.After(now) {
			return e.next
		}
		if q.o.Key != nil && q.o.PerKey > 0 && q.busy[e.key] >= q.o.PerKey {
			i++ // its key's to deliver once one of its deliveries ends
			continue
		}
		q.waiting = slices.Delete(q.waiting, i, i+1)
		e.locked = false // (Reseal puts only a waiting item back)
		q.running++
		q.busy[e.key]++
		q.deliveries.Add(1)
		go func() {
			defer q.deliveries.Done()
			q.settle(e, q.attempt(ctx, e))
			q.wake()
		}()
	}
	return time.Time{}
}

// attempt makes one attempt at item e, which is being delivered (nothing else changes its entry meanwhile), and records
// its outcome in the store; it returns e as it is now (nil: gone from the queue).
//
// No lock is held meanwhile, so Reseal and the other workers go on. An item past its horizon is gone (the store has
// expired it), as is one the store no longer holds. One the store cannot read now waits for storeWait, as it was. A
// delivery cut short by the queue closing leaves the item as it was. Otherwise the item is ended (delivered, given up
// on, or unreadable), or due again after its next delay; an ended item whose end the store does not take stays ended,
// its end written again after storeWait and never delivered again.
func (q *Queue[T]) attempt(ctx context.Context, e *entry) *entry {
	to := *e
	if !time.Now().Before(e.expires) {
		return nil
	}
	wctx, wcancel := context.WithTimeout(context.WithoutCancel(ctx), writeWait)
	defer wcancel()
	it, err := q.items.Get(wctx, e.id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		q.o.Log.Error(q.o.Name+" queue: item cannot be read (tried again in a minute)", "item", e.id, "error", err)
		to.next = time.Now().Add(storeWait)
		return &to
	}
	if !to.ended {
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
			to.locked, to.next = true, e.expires
			return &to
		case err != nil:
			q.o.Log.Error(q.o.Name+" queue: item cannot be read, dropping it", "item", e.id, "error", err)
			to.ended = true
		default:
			dctx, dcancel := context.WithTimeout(ctx, deliveryTimeout)
			err = q.o.Deliver(dctx, v)
			dcancel()
			if err != nil && ctx.Err() != nil {
				return &to // the queue is closing: the attempt does not count
			}
			giveUp := err != nil && e.attempt >= len(q.o.Backoff)
			var delay time.Duration
			if err != nil && !giveUp {
				delay = q.o.Backoff[e.attempt]
			}
			if err != nil && q.o.Failed != nil {
				q.o.Failed(v, e.attempt+1, delay, err)
			}
			to.ended = err == nil || giveUp
			to.attempt, to.next = e.attempt+1, time.Now().Add(delay)
		}
	}
	err = q.rewrite(wctx, e.id, it, func(it *model.QueueItem) (bool, error) {
		if to.ended {
			// Expired a second ago, not now: a store keeps the expiry rounded up to its precision, and the item must not
			// read as live meanwhile.
			it.Expires = time.Now().Add(-time.Second)
		} else {
			it.Attempt, it.Next = to.attempt, to.next
		}
		return true, nil
	})
	switch {
	case err == nil && to.ended:
		return nil
	case err != nil && to.ended:
		q.o.Log.Error(q.o.Name+" queue: item's end not recorded (written again in a minute; it is not delivered again)",
			"item", e.id, "error", err)
		to.next = time.Now().Add(storeWait)
	case err != nil:
		// Its retry is kept here, as is: the store's copy, due sooner, matters only after a restart.
		q.o.Log.Error(q.o.Name+" queue: item's retry not recorded", "item", e.id, "error", err)
	}
	return &to
}

// settle ends the delivery of e: its worker and its key's share are free again, and e is back waiting as to, or gone
// from the queue (to nil).
func (q *Queue[T]) settle(e, to *entry) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.running--
	if q.busy[e.key]--; q.busy[e.key] <= 0 {
		delete(q.busy, e.key)
	}
	if to == nil {
		delete(q.index, e.id)
		q.release(e.key)
		return
	}
	*e = *to
	q.wait(e)
}
