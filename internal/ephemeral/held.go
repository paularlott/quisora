package ephemeral

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/paularlott/quisora/internal/metrics"
)

// Held budgets. A rate limit bounds how fast a requester may write short-lived state, not how much of it the node
// then holds: ten minutes of writes at a few hundred a minute, each a dozen kilobytes of the requester's own
// parameters, is tens of megabytes an address, and a few dozen addresses fill the node (ErrFull: every sign-in of
// every tenant refused). So whatever is kept for a requester nobody has admitted yet (an address), or one with no
// more standing than an account (a signed-in user), is first charged, in bytes, to what that requester may hold
// (Budget.Charge), and refused past it (ErrHeld: 429), whatever its request rate.
//
// The accounting is a counter per requester and window of time (Hold), aligned to the clock: the window a charge
// falls in is named in the counter's key and stamped on the charge (Held). An entry lives no longer than a window, so
// everything a requester holds was charged in the current window or the one before, and each is held to the limit:
// a requester holds at most twice its budget, across the turn of a window, and nothing more whatever it does. What
// ends early gives its charge back (Held.Refund) into the window it was charged in and no other, so that a counter
// that has started again is never credited for what an earlier one counted, and a counter never goes below zero
// (Store.Incr): giving back cannot buy room. An entry that is saved again keeps its first expiry (its callers see to
// that), so a charge never outlives the window it was made for.
//
// The counters are the store's own (Incr), so the budget is the cluster's, not each node's: a counter lives on the
// node that owns its key, whichever node the request reached, and in a shared database when that keeps the state.
// With gossip a counter's owner changes when nodes stop serving or start, and the new owner counts from nothing
// (cluster.Ephemeral): what was charged before the change is no longer counted, and what it gives back afterwards is
// taken off the charges made since, in the same window. So each change of a key's owner within a window lets its
// requester hold up to one more limit until that window's entries have expired, and no more: a bound that depends
// on the cluster's membership, which no requester chooses, and that a window's turn ends. A charge is not stamped
// with the node that counted it, because a node that restarts owns the same keys again with nothing counted, and
// the stamp would say nothing of that.
//
// Three budgets are kept apart, each a counter of its own. Budget.Charge counts what lives up to HeldWindow (flows,
// provider states, challenges, tickets, device sign-ins) in windows of HeldWindow. Budget.ChargeFor counts what
// lives a shorter time of its own (authorization codes) in windows of that time, so that it comes back as soon as
// the entries expire, not twenty minutes later. Budget.ChargeGuard counts the records protections rest on (guard
// namespaces) against a small share of the limit (GuardShare), because their room is one every tenant's
// redemptions need (GuardPrefix).

// ErrHeld is returned when a requester already holds its budget of short-lived state (Budget.Charge): the request
// that wanted to keep more is refused (429 with Retry-After), counted as
// quisora_ephemeral_refused_total{reason="held_bytes"}. Nobody else is refused anything.
var ErrHeld = errors.New("ephemeral: this requester holds its budget of short-lived state")

const (
	// HeldNS is the namespace of the budgets' counters.
	HeldNS = "held"
	// HeldWindow is the window charges are counted in: at least the longest life of anything charged (a sign-in flow's
	// 20 minutes). A charge for something that lives longer is counted in a window of that length (Budget.Charge).
	HeldWindow = 20 * time.Minute
	// WideFactor is how many times a requester's budget its wider key may hold (Holder.Wide), and WidestFactor its
	// widest (Holder.Widest).
	WideFactor   = 16
	WidestFactor = 64
	// GuardShare is the part of a requester's budget it may hold in guard records (Budget.ChargeGuard): a sixteenth,
	// but at least MinGuardHeld, so that the smallest limits.held_kb still redeems a few dozen codes in a window.
	// The guard namespaces' room is a quarter of the node's (Local.GuardBudget) and config.Validate keeps
	// limits.held_kb to a small part of the node's too, so filling that room takes hundreds of requesters at the
	// least, and about a thousand as both are set by default.
	GuardShare   = 16
	MinGuardHeld = 32 << 10
	// heldSlack is added to every charge for what the entry costs beyond its value: its id, the stamp of the charge
	// kept in it, and the few fields its later steps add (a flow's decision, say).
	heldSlack = 256
)

// Holder names who short-lived state is kept for. Key is the requester: a client address as rate limits count it (an
// IPv4 address, an IPv6 /64), or a signed-in user. Wide and Widest, when set, are coarser keys the charge counts
// against as well, with WideFactor and WidestFactor times the budget: the /48 and the /32 of an IPv6 address, so that
// one allocation's 65,536 /64s do not each bring a budget of their own, nor a provider's 65,536 /48s.
type Holder struct {
	Key    string
	Wide   string
	Widest string
}

// tiers are the keys of h a charge counts against, with how many times the limit each may hold.
func (h Holder) tiers() [3]struct {
	key    string
	factor int64
} {
	return [3]struct {
		key    string
		factor int64
	}{{h.Key, 1}, {h.Wide, WideFactor}, {h.Widest, WidestFactor}}
}

// Held is a charge as it was made: kept with the entry it paid for (in its JSON), and given back when the entry ends
// before its time (Refund).
type Held struct {
	Key    string `json:"k"`
	Wide   string `json:"w,omitempty"`
	Widest string `json:"x,omitempty"`
	Epoch  int64  `json:"e"` // the window it was charged in, for every key: the only one it is given back into
	N      int64  `json:"n"`
	Win    int64  `json:"s"` // the window's length, seconds
}

// now is the clock windows are told by (tests move it).
var now = time.Now

// Holding is what key holds in namespace ns by the count of the current window of length window (Hold): for tests
// and diagnostics.
func Holding(ctx context.Context, st Store, ns, key string, window time.Duration) (int64, error) {
	return st.Incr(ctx, ns, counterKey(key, window, now().UnixNano()/int64(window)), 0, 2*window)
}

// counterKey is the counter of key in window epoch of length window.
func counterKey(key string, window time.Duration, epoch int64) string {
	return key + "|" + strconv.FormatInt(int64(window/time.Second), 10) + "|" + strconv.FormatInt(epoch, 10)
}

// Hold counts n more of something (bytes, entries) held for key in namespace ns, and reports whether that is within
// limit: when it is not, nothing stays counted. The count is of the current window (see above), so with everything
// counted living at most window, key holds at most twice limit. The counter is incremented before it is compared, so
// requests arriving together cannot pass the limit between them. A counter that cannot be used is an error, and one
// too contended or past the store's caps is over any limit: both refuse.
func Hold(ctx context.Context, st Store, ns, key string, n, limit int64, window time.Duration) (Held, bool, error) {
	return HoldFor(ctx, st, ns, Holder{Key: key}, n, limit, window)
}

// HoldFor is Hold for every key of h: its own within limit, its wider ones within WideFactor and WidestFactor times
// limit. All are counted in one window, told once before the first is counted: a charge whose keys were counted
// either side of a window's turn would be given back into one window only (Held.Epoch), and what the other counted
// would stay until it expired. When any key is past its limit, or cannot be counted, none stays counted.
func HoldFor(ctx context.Context, st Store, ns string, h Holder, n, limit int64, window time.Duration) (Held, bool, error) {
	epoch := now().UnixNano() / int64(window)
	held := Held{Epoch: epoch, N: n, Win: int64(window / time.Second)}
	for i, t := range h.tiers() {
		if t.key == "" {
			continue
		}
		ck := counterKey(t.key, window, epoch)
		// The counter outlives its window by another: what was charged in it may be given back until then.
		got, err := st.Incr(ctx, ns, ck, n, 2*window)
		if err == nil && got <= limit*t.factor {
			switch i {
			case 0:
				held.Key = t.key
			case 1:
				held.Wide = t.key
			default:
				held.Widest = t.key
			}
			continue
		}
		if err == nil && got < Contended { // counted, so given back; a counter that could not be updated counted nothing
			_, _ = st.Incr(context.WithoutCancel(ctx), ns, ck, -n, 2*window)
		}
		Release(ctx, st, ns, held) // what the narrower keys counted
		return Held{}, false, err
	}
	return held, true, nil
}

// Release gives a charge made by Hold in namespace ns back, into the window it was made in: once that window's
// counter has gone, nothing is given back (and nothing needs to be).
func Release(ctx context.Context, st Store, ns string, h Held) {
	if h.N <= 0 || h.Win <= 0 {
		return
	}
	ctx = context.WithoutCancel(ctx)
	window := time.Duration(h.Win) * time.Second
	for _, key := range [3]string{h.Key, h.Wide, h.Widest} {
		if key != "" {
			_, _ = st.Incr(ctx, ns, counterKey(key, window, h.Epoch), -h.N, 2*window)
		}
	}
}

// Budget charges short-lived state to whoever it is kept for. Limit is the bytes one requester may hold (read at
// each charge, so a change counts at once; 0 or less: no budget). A nil Budget charges nothing.
type Budget struct {
	Store Store
	Limit func() int64
}

// Charge counts an entry of namespace ns with a value of size bytes, kept for ttl, against what h may hold. It
// answers ErrHeld when h (or one of its wider keys) is at its budget, another error when the count could not be made
// (the caller refuses, as for any counter that fails), and otherwise the charge, to keep in the entry and give back
// when it ends early (Held.Refund); nil when nothing was charged (no budget, or nobody to charge).
func (b *Budget) Charge(ctx context.Context, h Holder, ns string, size int, ttl time.Duration) (*Held, error) {
	return b.charge(ctx, h, ns, size, max(HeldWindow, ttl), 1)
}

// ChargeFor is Charge for an entry that lives a short time of its own (an authorization code's minute), counted in
// windows of that time instead of HeldWindow: a budget apart from Charge's, as large, that an entry which is never
// taken gives back when it expires (within two of its lifetimes) instead of twenty minutes later. What can be made
// on a requester's behalf by someone else (a code, by any page that sends a signed-in browser to an application it
// already allowed) is charged this way, so that making it cannot keep the requester's own sign-ins refused for long.
func (b *Budget) ChargeFor(ctx context.Context, h Holder, ns string, size int, ttl time.Duration) (*Held, error) {
	return b.charge(ctx, h, ns, size, max(ttl, time.Second), 1)
}

// ChargeGuard is Charge for a record of a guard namespace (GuardPrefix), against a budget of its own: a GuardShare
// of the limit (at least MinGuardHeld), counted apart from everything else h holds. The guard namespaces' room is
// what every redemption and device poll on the node needs, so one requester's part of it is far smaller than its
// part of the sign-in state's.
func (b *Budget) ChargeGuard(ctx context.Context, h Holder, ns string, size int, ttl time.Duration) (*Held, error) {
	for _, k := range []*string{&h.Key, &h.Wide, &h.Widest} {
		if *k != "" {
			*k = "guard|" + *k
		}
	}
	return b.charge(ctx, h, ns, size, max(HeldWindow, ttl), GuardShare)
}

// GuardLimit is what one requester may hold in guard records under a budget of limit bytes (ChargeGuard).
func GuardLimit(limit int64) int64 { return max(limit/GuardShare, MinGuardHeld) }

// charge counts the entry against h's keys in windows of window, each within its factor of the limit (a share'th of
// it, for guard records).
func (b *Budget) charge(ctx context.Context, h Holder, ns string, size int, window time.Duration, share int64) (*Held, error) {
	if b == nil || b.Store == nil || b.Limit == nil || h.Key == "" {
		return nil, nil
	}
	limit := b.Limit()
	if limit <= 0 {
		return nil, nil
	}
	if share > 1 {
		limit = GuardLimit(limit)
	}
	n := int64(len(ns)+size) + itemOverhead + heldSlack
	held, ok, err := HoldFor(ctx, b.Store, HeldNS, h, n, limit, window)
	if err != nil {
		return nil, err
	}
	if !ok {
		metrics.EphemeralRefused.Inc("held_bytes")
		return nil, ErrHeld
	}
	return &held, nil
}

// Refund gives the charge back: for an entry that ended before its time (a flow finished, a challenge answered), or
// one that could not be stored after all. A nil charge is nothing to give back. Only the request that ended the
// entry (the one whose Take had it) may call it, once.
func (h *Held) Refund(ctx context.Context, st Store) {
	if h == nil || st == nil {
		return
	}
	Release(ctx, st, HeldNS, *h)
}

type holderKey struct{}

type charged struct {
	b *Budget
	h Holder
}

// With returns ctx naming h as the requester that what the request stores is kept for: the packages that store it
// (a provider's sign-in state, a passkey challenge) charge it with Charge. A nil Budget returns ctx as it is.
func (b *Budget) With(ctx context.Context, h Holder) context.Context {
	if b == nil {
		return ctx
	}
	return context.WithValue(ctx, holderKey{}, charged{b, h})
}

// Charge is Budget.Charge for the budget and requester ctx names (Budget.With); a ctx that names none charges
// nothing (nil).
func Charge(ctx context.Context, ns string, size int, ttl time.Duration) (*Held, error) {
	c, ok := ctx.Value(holderKey{}).(charged)
	if !ok {
		return nil, nil
	}
	return c.b.Charge(ctx, c.h, ns, size, ttl)
}

// JSON encodes v as encoding/json does, but without escaping <, > and & (each six bytes escaped): the values kept
// here are never written into HTML, and they carry what requesters sent (a state, a path to return to), which must
// not cost six times its length to hold. It returns nil for a value that cannot be encoded.
func JSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) != nil {
		return nil
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})
}
