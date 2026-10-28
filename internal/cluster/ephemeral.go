package cluster

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/quisora/internal/ephemeral"
)

// Ephemeral operation codes.
const (
	opSet uint8 = iota + 1
	opGet
	opTake
	opDelete
	opIncr
)

const (
	codeOK uint8 = iota
	codeNotFound
	codeError
)

type ephReq struct {
	Op    uint8
	NS    string
	ID    string
	Val   []byte
	TTL   int64 // milliseconds (the window for Incr)
	Delta int64
}

type ephResp struct {
	Code uint8
	Val  []byte
	N    int64
	Err  string
}

// Ephemeral implements ephemeral.Store over a node-local ephemeral.Local. New always creates locally (the id carries
// this node's prefix). Operations on an id owned by another node are forwarded to it; when that node is dead per
// gossip the state is gone and ErrNotFound is returned. Ids without an owner prefix (hash-routed keys) and counters
// (Incr: rate limits, lockouts) go to the rendezvous-hash owner among the live nodes that serve (Ready, published in
// gossip metadata): a node that is catching up or cut off owns nothing. Everything fails closed: when the owner
// cannot be reached the operation returns an error (a rate limit or lockout then refuses) rather than counting on
// this node alone. Hash-routed state lives in its owner's memory only, so when the owner changes (a node stops
// serving, starts again, or goes) the new owner starts from nothing: a rate limit's window starts again. Nothing that
// must hold across that, such as a single-use value, is kept here (service.UseOnce keeps those).
//
// A counter read (Incr with delta 0: a limit checked before anything else, on every token and API request) is
// answered from the value this node last had from the owner when that is under counterReadTTL old, so the requests
// that pass a limit cost no round trip. It may miss attempts counted through other nodes for that long, but never
// this node's own: every attempt that counts (delta > 0) goes to the owner and its answer replaces the remembered
// value, so a node lets at most one attempt past a limit reached elsewhere before it refuses too.
type Ephemeral struct {
	n     *Node
	local *ephemeral.Local

	seenMu sync.Mutex
	seen   map[string]seenCount // ns + "/" + key: the owner's last answer
}

// seenCount is a counter's value as its owner last answered it.
type seenCount struct {
	n  int64
	at time.Time
}

// counterReadTTL is how long a counter value from its owner answers this node's reads; seenMax bounds how many are
// remembered (past it the old ones go, then all: a read then asks the owner).
const (
	counterReadTTL = time.Second
	seenMax        = 100_000
)

func (e *Ephemeral) remembered(k string) (int64, bool) {
	e.seenMu.Lock()
	defer e.seenMu.Unlock()
	v, ok := e.seen[k]
	if !ok || time.Since(v.at) >= counterReadTTL {
		return 0, false
	}
	return v.n, true
}

func (e *Ephemeral) remember(k string, n int64) {
	e.seenMu.Lock()
	defer e.seenMu.Unlock()
	if e.seen == nil {
		e.seen = map[string]seenCount{}
	}
	if len(e.seen) >= seenMax {
		for key, v := range e.seen {
			if time.Since(v.at) >= counterReadTTL {
				delete(e.seen, key)
			}
		}
		if len(e.seen) >= seenMax {
			clear(e.seen)
		}
	}
	e.seen[k] = seenCount{n: n, at: time.Now()}
}

var _ ephemeral.Store = (*Ephemeral)(nil)

// Local returns the node-local store (for tests and metrics).
func (e *Ephemeral) Local() *ephemeral.Local { return e.local }

func (e *Ephemeral) New(ctx context.Context, ns string, value []byte, ttl time.Duration) (string, error) {
	return e.local.New(ctx, ns, value, ttl)
}

func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

// keyHash is FNV-1a over ns, '/', key without allocating.
func keyHash(ns, key string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(ns); i++ {
		h = (h ^ uint64(ns[i])) * 1099511628211
	}
	h = (h ^ '/') * 1099511628211
	for i := 0; i < len(key); i++ {
		h = (h ^ uint64(key[i])) * 1099511628211
	}
	return h
}

// errNoOwner: no node that serves is in view to own hash-routed state.
var errNoOwner = errors.New("cluster: no node that serves can own this state now")

// hrw returns the live, serving member with the highest rendezvous weight for (ns, key), or nil when there is none.
// A member gossip suspects owns nothing hash-routed: its counters go to the next member at once, rather than every
// request whose counter it held waiting for an answer that does not come until gossip declares it dead (a counter
// starts again when its owner changes, as it does when a node stops serving).
func (n *Node) hrw(ns, key string) *member {
	m := n.mem.Load()
	kh := keyHash(ns, key)
	selfReady, _ := n.Ready()
	var best *member
	var bs uint64
	for _, mb := range m.routable {
		if mb == m.self && !selfReady || mb != m.self && (!mb.ready || mb.state != gossip.NodeAlive) {
			continue // not serving, or suspected: owns nothing
		}
		s := mix64(mb.seed ^ kh)
		if best == nil || s > bs || (s == bs && mb.id > best.id) {
			best, bs = mb, s
		}
	}
	return best
}

func (n *Node) route(ns, id string) (mb *member, dead bool) {
	m := n.mem.Load()
	if owner := ephemeral.Owner(id); owner != "" {
		if owner == n.prefix {
			return m.self, false
		}
		if mb := m.byPrefix[owner]; mb != nil {
			return mb, !mb.routable()
		}
	}
	return n.hrw(ns, id), false
}

// ephWait bounds one ephemeral operation forwarded to its owner: the gossip transport waits longer for a reply (as long
// as a partition write may take), and a sign-in step must not wait that long for a node that hangs.
const ephWait = 2 * time.Second

func (e *Ephemeral) call(ctx context.Context, mb *member, req *ephReq) (*ephResp, error) {
	ctx, cancel := context.WithTimeout(ctx, ephWait)
	defer cancel()
	var resp ephResp
	if err := e.n.gc.SendToWithResponseContext(ctx, mb.node, msgEph, req, &resp); err != nil {
		return nil, fmt.Errorf("cluster: ephemeral forward to %s: %w", mb.id, err)
	}
	switch resp.Code {
	case codeNotFound:
		return nil, ephemeral.ErrNotFound
	case codeError:
		return nil, errors.New(resp.Err)
	}
	return &resp, nil
}

func (e *Ephemeral) Set(ctx context.Context, ns, id string, value []byte, ttl time.Duration) error {
	if e.n.gc == nil {
		return e.local.Set(ctx, ns, id, value, ttl)
	}
	mb, dead := e.n.route(ns, id)
	if dead {
		return ephemeral.ErrNotFound
	}
	if mb == nil {
		return errNoOwner
	}
	if mb.id == e.n.id {
		return e.local.Set(ctx, ns, id, value, ttl)
	}
	_, err := e.call(ctx, mb, &ephReq{Op: opSet, NS: ns, ID: id, Val: value, TTL: ttl.Milliseconds()})
	return err
}

func (e *Ephemeral) Get(ctx context.Context, ns, id string) ([]byte, error) {
	if e.n.gc == nil {
		return e.local.Get(ctx, ns, id)
	}
	mb, dead := e.n.route(ns, id)
	if dead {
		return nil, ephemeral.ErrNotFound
	}
	if mb == nil {
		return nil, errNoOwner
	}
	if mb.id == e.n.id {
		return e.local.Get(ctx, ns, id)
	}
	r, err := e.call(ctx, mb, &ephReq{Op: opGet, NS: ns, ID: id})
	if err != nil {
		return nil, err
	}
	return r.Val, nil
}

func (e *Ephemeral) Take(ctx context.Context, ns, id string) ([]byte, error) {
	if e.n.gc == nil {
		return e.local.Take(ctx, ns, id)
	}
	mb, dead := e.n.route(ns, id)
	if dead {
		return nil, ephemeral.ErrNotFound
	}
	if mb == nil {
		return nil, errNoOwner
	}
	if mb.id == e.n.id {
		return e.local.Take(ctx, ns, id)
	}
	r, err := e.call(ctx, mb, &ephReq{Op: opTake, NS: ns, ID: id})
	if err != nil {
		return nil, err
	}
	return r.Val, nil
}

func (e *Ephemeral) Delete(ctx context.Context, ns, id string) error {
	if e.n.gc == nil {
		return e.local.Delete(ctx, ns, id)
	}
	mb, dead := e.n.route(ns, id)
	if dead {
		return ephemeral.ErrNotFound
	}
	if mb == nil {
		return errNoOwner
	}
	if mb.id == e.n.id {
		return e.local.Delete(ctx, ns, id)
	}
	_, err := e.call(ctx, mb, &ephReq{Op: opDelete, NS: ns, ID: id})
	return err
}

// Incr routes to the rendezvous-hash owner of key among the live nodes that serve. It fails closed: when no such
// node is in view, or the owner cannot be reached, it returns an error (rate limits and lockouts then refuse)
// instead of counting on this node alone, which would let a client multiply its attempts by the number of nodes.
func (e *Ephemeral) Incr(ctx context.Context, ns, key string, delta int64, window time.Duration) (int64, error) {
	if e.n.gc == nil {
		return e.local.Incr(ctx, ns, key, delta, window)
	}
	mb := e.n.hrw(ns, key)
	if mb == nil {
		return 0, errNoOwner
	}
	if mb.id == e.n.id {
		return e.local.Incr(ctx, ns, key, delta, window)
	}
	k := ns + "/" + key
	if delta == 0 {
		if n, ok := e.remembered(k); ok {
			return n, nil
		}
	}
	r, err := e.call(ctx, mb, &ephReq{Op: opIncr, NS: ns, ID: key, Delta: delta, TTL: window.Milliseconds()})
	if err != nil {
		e.n.log.WithError(err).Debug("counter owner unreachable: refusing")
		return 0, err
	}
	e.remember(k, r.N)
	return r.N, nil
}

// handleEph executes a forwarded operation on this node's local store.
func (n *Node) handleEph(_ *gossip.Node, pkt *gossip.Packet) (any, error) {
	var req ephReq
	if err := pkt.Unmarshal(&req); err != nil {
		return nil, err
	}
	l := n.eph.local
	ttl := time.Duration(req.TTL) * time.Millisecond
	var resp ephResp
	var err error
	if ok, _ := n.Ready(); !ok && (req.Op == opIncr || ephemeral.Owner(req.ID) == "") {
		// Hash-routed state belongs to nodes that serve; the sender's view of this node is out of date.
		return &ephResp{Code: codeError, Err: "cluster: this node does not serve now"}, nil
	}
	switch req.Op {
	case opSet:
		err = l.Set(n.ctx, req.NS, req.ID, req.Val, ttl)
	case opGet:
		resp.Val, err = l.Get(n.ctx, req.NS, req.ID)
	case opTake:
		resp.Val, err = l.Take(n.ctx, req.NS, req.ID)
	case opDelete:
		err = l.Delete(n.ctx, req.NS, req.ID)
	case opIncr:
		resp.N, err = l.Incr(n.ctx, req.NS, req.ID, req.Delta, ttl)
	default:
		err = fmt.Errorf("cluster: unknown ephemeral op %d", req.Op)
	}
	switch {
	case errors.Is(err, ephemeral.ErrNotFound):
		resp = ephResp{Code: codeNotFound}
	case err != nil:
		resp = ephResp{Code: codeError, Err: err.Error()}
	}
	return &resp, nil
}
