package cluster

// TestChaosSoak: an application-level chaos soak of a three-node gossip cluster. A workload of concurrent writers (users
// through the service layer, sessions, signing keys and organizations through the cluster store) and readers (every
// node) runs while faults come and go at random, from a seed: a node killed (cut off first, so its peers get no goodbye)
// and restarted with its data or with its disk lost, links cut (both ways, one way, a node isolated), a node made to
// miss writes (lagBehind), requests that hang, catch-ups that fail (failImport) or are cut after their reset
// (cutAfterReset), a slow disk, and writes that land and then report store.ErrUnconfirmed. Every write's outcome is
// kept in a ledger (acknowledged, refused, unknown). The checks:
//
//  1. no acknowledged write is lost: after the quiet period every node holds the latest acknowledged version of every
//     record or a later one an unknown outcome may explain, an acknowledged delete stays deleted, and a refused write
//     never appears;
//  2. bounded staleness: a read a node answers (a record found, a listing of signing keys or organizations) never
//     returns a version superseded by an acknowledged write more than StaleAfter plus a slack ago;
//  3. convergence: after the quiet period every node holds the same committed data of every partition;
//  4. audit completeness: every service-level change that was acknowledged (or whose outcome was reported unknown) has
//     an audit event on the node that served it.
//
// It runs only with QUISORA_CHAOS=1 or when TestChaosSoak is named with -run. QUISORA_CHAOS_SEED replays the fault
// schedule (message timing is not reproducible), QUISORA_CHAOS_DURATION sets the length of the run (default 60s),
// QUISORA_CHAOS_BACKEND is badger (default) or sqlite, QUISORA_CHAOS_SLACK is the staleness slack on top of StaleAfter
// (default 2s). QUISORA_CHAOS_STRICT=1 makes two known findings failures (they are counted and reported otherwise): a stale
// answer within StaleAfter of a node regaining contact with an owner (TestChaosNoStaleServingAfterContactRegained), and
// tombstones held by some nodes only (TestChaosPurgeReachesANodeThatMissedIt).
//
// What it cannot do: a node is "killed" by cutting it off, closing its protocol (nothing it says reaches its peers) and
// closing its database whole, never by abandoning the database (BadgerDB runs with NoSync here: a real kill -9 loses what
// the disk had not got); the disk is lost only for one node at a time, with the others up and the previous one copied back
// (with a majority of disks lost nothing is promised); one clock serves every node (versions come from one process);
// the workload goes through the service layer (users: the only audited writes) and the cluster store, never through HTTP;
// a read of an id the node cannot place in a partition (a user or session it does not hold) is answered ungated, as
// designed, so a missing record is not judged except in the listings of the global partition.

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func chaosWanted() bool {
	if os.Getenv("QUISORA_CHAOS") == "1" {
		return true
	}
	f := flag.Lookup("test.run")
	return f != nil && strings.Contains(f.Value.String(), "ChaosSoak")
}

func chaosEnvInt(t testing.TB, name string, def int64) int64 {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		t.Fatalf("%s=%q: %v", name, v, err)
	}
	return n
}

func chaosEnvDur(t testing.TB, name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		t.Fatalf("%s=%q: %v", name, v, err)
	}
	return d
}

// ---- the store that lies about outcomes ----

// chaosStore is a node's cluster store whose replicated writes can be made to report store.ErrUnconfirmed: after they
// landed (the usual unknown outcome: the node deciding it was lost before it answered) or without having been made.
type chaosStore struct {
	*Store
	landP    atomic.Int64 // per mille of the successful writes reported unknown
	skipP    atomic.Int64 // per mille of the writes reported unknown without being made
	mu       sync.Mutex
	rng      *rand.Rand
	landed   atomic.Int64
	notMade  atomic.Int64
	reported atomic.Int64
}

func (c *chaosStore) roll(p *atomic.Int64) bool {
	n := p.Load()
	if n <= 0 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rng.Int63n(1000) < n
}

var errChaosUnknown = fmt.Errorf("%w: chaos: the outcome is not known", store.ErrUnconfirmed)

func (c *chaosStore) Put(ctx context.Context, rec *store.Record) error {
	if localOnly(rec.Kind) {
		return c.Store.Put(ctx, rec)
	}
	if c.roll(&c.skipP) {
		c.notMade.Add(1)
		return errChaosUnknown
	}
	err := c.Store.Put(ctx, rec)
	if err == nil && c.roll(&c.landP) {
		c.landed.Add(1)
		return errChaosUnknown
	}
	return err
}

func (c *chaosStore) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	if localOnly(rec.Kind) {
		return c.Store.CompareAndPut(ctx, rec, expect)
	}
	if c.roll(&c.skipP) {
		c.notMade.Add(1)
		return errChaosUnknown
	}
	err := c.Store.CompareAndPut(ctx, rec, expect)
	if err == nil && c.roll(&c.landP) {
		c.landed.Add(1)
		return errChaosUnknown
	}
	return err
}

// ---- the ledger ----

// chaosDeleted is the state a deletion writes; states of a record's writes otherwise count up from 1 (0: never written).
const chaosDeleted = 1 << 30

type chaosOutcome int

const (
	outPending chaosOutcome = iota
	outAck
	outRefused
	outUnknown
)

func (o chaosOutcome) String() string { return [...]string{"pending", "ack", "refused", "unknown"}[o] }

type chaosOp struct {
	state      int // what it writes (chaosDeleted: a deletion)
	del        bool
	action     string // the audit action of a service-level change ("": none)
	node       int    // the node that served it
	start, end time.Time
	out        chaosOutcome
	version    hlc.Timestamp // of an acknowledged write
	err        error
	killed     bool // the node was killed while the operation ran
}

// chaosEpoch is the start of the run (the traces show times from it).
var chaosEpoch = time.Now()

func (o chaosOp) String() string {
	s := fmt.Sprintf("%d:%s", o.state, o.out)
	if o.del {
		s = "del:" + o.out.String()
	}
	if o.node >= 0 && o.out != outPending {
		s += fmt.Sprintf("@n%d[%.2f-%.2f]", o.node, o.start.Sub(chaosEpoch).Seconds(), o.end.Sub(chaosEpoch).Seconds())
	}
	if o.killed {
		s += "(killed)"
	}
	if o.out == outRefused && o.err != nil { // what refused it (a refusal is a claim that nothing changed)
		e := o.err.Error()
		if len(e) > 120 {
			e = e[:120]
		}
		s += "(" + e + ")"
	}
	return s
}

type chaosRec struct {
	kind    model.Kind
	org     string // partition key (users, sessions)
	name    string // the record's name: a user's username (its identity in the ledger), a key's or organization's id
	expires time.Time
	dead    atomic.Bool // a deletion of it was acknowledged or left unknown (the readers look at live records more)
	// owned by the writer goroutine
	counter int
	// under the ledger's lock
	id  string
	ops []*chaosOp
}

type chaosLedger struct {
	mu    sync.Mutex
	order []*chaosRec
}

func (l *chaosLedger) add(r *chaosRec) {
	l.mu.Lock()
	l.order = append(l.order, r)
	l.mu.Unlock()
}

func (l *chaosLedger) all() []*chaosRec {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.order)
}

func (l *chaosLedger) ofKind(k model.Kind) []*chaosRec {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []*chaosRec
	for _, r := range l.order {
		if r.kind == k {
			out = append(out, r)
		}
	}
	return out
}

func (l *chaosLedger) idOf(r *chaosRec) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return r.id
}

func (l *chaosLedger) setID(r *chaosRec, id string) {
	l.mu.Lock()
	r.id = id
	l.mu.Unlock()
}

func (l *chaosLedger) begin(r *chaosRec, op *chaosOp) {
	l.mu.Lock()
	r.ops = append(r.ops, op)
	l.mu.Unlock()
}

func (l *chaosLedger) drop(r *chaosRec, op *chaosOp) {
	l.mu.Lock()
	r.ops = slices.DeleteFunc(r.ops, func(o *chaosOp) bool { return o == op })
	l.mu.Unlock()
}

func (l *chaosLedger) finish(op *chaosOp, out chaosOutcome, v hlc.Timestamp, err error, node int, killed bool, end time.Time) {
	l.mu.Lock()
	op.out, op.version, op.err, op.node, op.killed, op.end = out, v, err, node, killed, end
	l.mu.Unlock()
}

// opsOf returns a copy of the operations of r.
func (l *chaosLedger) opsOf(r *chaosRec) []chaosOp {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]chaosOp, len(r.ops))
	for i, o := range r.ops {
		out[i] = *o
	}
	return out
}

func (r *chaosRec) String() string { return fmt.Sprintf("%s %s", r.kind, r.name) }

func chaosTrace(ops []chaosOp) string {
	parts := make([]string, len(ops))
	for i, o := range ops {
		parts[i] = o.String()
	}
	return strings.Join(parts, " ")
}

// chaosObs is what a read (or the final look) found of a record.
type chaosObs struct {
	absent  bool
	state   int
	torn    bool // the record's fields do not agree with its state
	version hlc.Timestamp
}

func (o chaosObs) String() string {
	switch {
	case o.absent:
		return "absent"
	case o.torn:
		return fmt.Sprintf("state %d (torn)", o.state)
	}
	return fmt.Sprintf("state %d", o.state)
}

// noopDelete reports whether op is a deletion of a record that had expired by the time it was acknowledged: an expired record is hidden from
// every read (it is not there to delete: the store reports nothing to delete and the purge removes it later), so the
// deletion is acknowledged and changes nothing.
func noopDelete(op chaosOp, expires time.Time) bool {
	return op.del && !expires.IsZero() && op.end.After(expires)
}

// judgeRead says what is wrong with a read of r that found o, started at t0 and ended at t1 ("" nothing). A version
// superseded by an acknowledged write more than bound before the read began is stale; a state no write of the record
// ever made, or only a refused one, never existed; a record found after an acknowledged deletion is back from the dead.
// Absence is judged only when strict (the read of a record whose partition is known: an absent record the node cannot
// place is answered from its own copy ungated, which fails safe), and then only if the record was acknowledged live
// before that and no deletion of it was ever started.
func judgeRead(ops []chaosOp, expires time.Time, o chaosObs, t0, t1 time.Time, bound time.Duration, strict bool) (msg string, stale bool) {
	floor := 0
	var floorOp chaosOp
	deleteStarted := false
	valid := map[int]bool{}
	for _, op := range ops {
		if op.start.Before(t1) && op.out != outRefused {
			valid[op.state] = true
			if op.del {
				deleteStarted = true
			}
		}
		if op.out == outAck && op.end.Before(t0.Add(-bound)) && !noopDelete(op, expires) {
			floor, floorOp = op.state, op
		}
	}
	if o.absent {
		if strict && floor != 0 && floor != chaosDeleted && !deleteStarted && (expires.IsZero() || expires.After(t1)) {
			return fmt.Sprintf("a record acknowledged live (state %d, %s ago) is missing", floor, t0.Sub(floorOp.end).Round(time.Millisecond)), true
		}
		return "", false
	}
	switch {
	case o.torn:
		return fmt.Sprintf("a torn record (fields disagree with state %d)", o.state), false
	case !valid[o.state]:
		return fmt.Sprintf("state %d was never written (or only by a refused write)", o.state), false
	case o.state < floor && floor == chaosDeleted:
		return fmt.Sprintf("a record deleted (acknowledged %s ago) is served: state %d", t0.Sub(floorOp.end).Round(time.Millisecond), o.state), true
	case o.state < floor:
		return fmt.Sprintf("state %d served, superseded by acknowledged state %d %s ago", o.state, floor, t0.Sub(floorOp.end).Round(time.Millisecond)), true
	}
	return "", false
}

// staleAge is how long before t0 the acknowledged write that supersedes what a read found (o) was acknowledged: how stale
// the answer was (0: it was not stale).
func staleAge(ops []chaosOp, expires time.Time, o chaosObs, t0 time.Time, strict bool) time.Duration {
	var first, latest *chaosOp // the first acknowledged write before t0, and the latest
	deleteStarted := false
	for i, op := range ops {
		if op.del && op.out != outRefused {
			deleteStarted = true
		}
		if op.out == outAck && !noopDelete(op, expires) && op.end.Before(t0) {
			latest = &ops[i]
			if !o.absent && op.state > o.state && first == nil {
				first = &ops[i]
			}
		}
	}
	switch {
	case o.absent:
		if strict && latest != nil && !latest.del && !deleteStarted {
			for i, op := range ops {
				if op.out == outAck && op.end.Before(t0) {
					return t0.Sub(ops[i].end)
				}
			}
		}
		return 0
	case first != nil:
		return t0.Sub(first.end)
	}
	return 0
}

func (h *chaosHarness) stalest() time.Duration {
	h.smu.Lock()
	defer h.smu.Unlock()
	return h.maxStale
}

// noteStale keeps the stalest answer served.
func (h *chaosHarness) noteStale(age time.Duration, what string) {
	h.smu.Lock()
	defer h.smu.Unlock()
	if age > h.maxStale {
		h.maxStale, h.maxStaleWhat = age, what
	}
}

// judgeFinal says what is wrong with the final state o of a record whose operations are all over: it must be the
// latest acknowledged state, or a state of an unknown outcome made after that; absent when that was a deletion.
func judgeFinal(ops []chaosOp, expires time.Time, o chaosObs, now time.Time) string {
	last := -1
	for i, op := range ops {
		if op.out == outAck && !noopDelete(op, expires) {
			last = i
		}
	}
	allowed := map[int]bool{}
	absentOK := last < 0
	var lastVersion hlc.Timestamp
	if last >= 0 {
		allowed[ops[last].state] = true
		lastVersion = ops[last].version
		if ops[last].del {
			absentOK = true
		}
	}
	for _, op := range ops[max(last, 0):] {
		if op.out == outUnknown && (last < 0 || op.start.After(ops[last].start)) {
			allowed[op.state] = true
			if op.del {
				absentOK = true
			}
		}
	}
	if !expires.IsZero() && expires.Before(now) {
		absentOK = true
	}
	switch {
	case o.absent && !absentOK:
		return fmt.Sprintf("an acknowledged write is lost: the record is absent, the latest acknowledged state is %d", ops[last].state)
	case o.absent:
		return ""
	case o.torn:
		return fmt.Sprintf("a torn record (fields disagree with state %d)", o.state)
	case !allowed[o.state]:
		if last >= 0 && ops[last].del {
			return fmt.Sprintf("a record deleted by an acknowledged write is back (state %d)", o.state)
		}
		return fmt.Sprintf("state %d is neither the latest acknowledged state nor an unknown outcome after it (allowed %v)",
			o.state, sortedStates(allowed))
	case last >= 0 && o.state == ops[last].state && o.version < lastVersion:
		return fmt.Sprintf("version %d is older than the acknowledged %d", o.version, lastVersion)
	}
	return ""
}

func sortedStates(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Ints(out)
	return out
}

// ---- observations of each kind ----

var chaosRoles = []model.Role{model.RoleUser, model.RoleManager, model.RoleAdmin}

func chaosState(prefix, s string) (int, bool) {
	if !strings.HasPrefix(s, prefix) {
		return 0, false
	}
	n, err := strconv.Atoi(s[len(prefix):])
	return n, err == nil
}

func obsUser(u *model.User) chaosObs {
	n, ok := chaosState("g", u.GivenName)
	return chaosObs{state: n, version: u.Version,
		torn: !ok || u.Role != chaosRoles[n%3] || u.Active != (n%4 != 0)}
}

func obsSession(s *model.Session) chaosObs {
	n, ok := chaosState("n", s.IP)
	return chaosObs{state: n, version: s.Version, torn: !ok || s.UserAgent != fmt.Sprintf("ua-%s-%d", s.ID, n)}
}

func obsKey(k *model.SigningKey) chaosObs {
	n, ok := chaosState("n", string(k.PublicJWK))
	return chaosObs{state: n, version: k.Version, torn: !ok}
}

func obsOrg(o *model.Org) chaosObs {
	n, ok := chaosState("n", o.DisplayName)
	return chaosObs{state: n, version: o.Version, torn: !ok || o.Name != o.ID}
}

// obsRecord decodes a stored record of rec's kind.
func obsRecord(kind model.Kind, r *store.Record) (chaosObs, error) {
	switch kind {
	case model.KindUser:
		var u model.User
		if err := store.Decode(r, &u); err != nil {
			return chaosObs{}, err
		}
		return obsUser(&u), nil
	case model.KindSession:
		var s model.Session
		if err := store.Decode(r, &s); err != nil {
			return chaosObs{}, err
		}
		return obsSession(&s), nil
	case model.KindKey:
		var k model.SigningKey
		if err := store.Decode(r, &k); err != nil {
			return chaosObs{}, err
		}
		return obsKey(&k), nil
	case model.KindOrg:
		var o model.Org
		if err := store.Decode(r, &o); err != nil {
			return chaosObs{}, err
		}
		return obsOrg(&o), nil
	}
	return chaosObs{}, fmt.Errorf("no observation of kind %s", kind)
}

// ---- the cluster under test ----

// chaosNode is one node as the workload sees it: workers and readers hold its lock for reading during an operation, a
// kill waits for them (so no operation runs on a closed database) and replaces the node under the write lock.
type chaosNode struct {
	idx int
	mu  sync.RWMutex
	up  atomic.Bool
	tn  *tnode
	cs  *chaosStore
	svc *service.Service
	// lastRefused is when a read of each partition was last refused on this node (unix nanoseconds), upSince when the
	// node (re)started: a node serves its stale copy for up to StaleAfter after it regains contact with the owner of a
	// partition (the lag is counted from the first report it hears, not from the commit), which the soak sets apart
	// (the grace window).
	lastRefused [partitions]atomic.Int64
	upSince     atomic.Int64
}

type chaosHarness struct {
	t     *testing.T
	c     *tcluster
	fs    *faults
	seed  int64
	bound time.Duration
	// grace is the window after a node regained contact with a partition's owner (or restarted) in which a stale answer is
	// counted apart, not a violation (strictGrace: a violation)
	grace       time.Duration
	strictGrace bool
	start       time.Time
	nodes       []*chaosNode
	led         chaosLedger
	cfg         *config.Config
	seal        *secure.Sealer

	stop atomic.Bool
	wg   sync.WaitGroup
	seq  atomic.Int64

	vmu  sync.Mutex
	viol []string
	seen map[string]bool

	smu           sync.Mutex
	stats         map[string]int
	maxStale      time.Duration
	graceCount    int
	graceExamples []string
	maxStaleWhat  string

	userOrgs, sessOrgs []string

	// the controller's (the test goroutine's) alone
	hist     []string
	cut      [3][3]bool
	dead     [3]bool
	down     [3]bool
	wipes    [3][]time.Time
	lost     int // the node whose lost disk is still being copied back (-1: none)
	chaosGen int64
}

func (h *chaosHarness) stopping() bool { return h.stop.Load() }

func (h *chaosHarness) count(format string, args ...any) {
	k := fmt.Sprintf(format, args...)
	h.smu.Lock()
	h.stats[k]++
	h.smu.Unlock()
}

func (h *chaosHarness) violate(format string, args ...any) {
	msg := fmt.Sprintf("%6.2fs ", time.Since(h.start).Seconds()) + fmt.Sprintf(format, args...)
	h.vmu.Lock()
	defer h.vmu.Unlock()
	if len(h.viol) < 60 {
		h.viol = append(h.viol, msg)
	}
}

func (h *chaosHarness) note(format string, args ...any) {
	h.hist = append(h.hist, fmt.Sprintf("%6.2fs ", time.Since(h.start).Seconds())+fmt.Sprintf(format, args...))
}

// onNode runs fn on a node that is up, preferring node prefer (-1: none), holding its lock for reading. killed is true
// when the node went down while fn ran; ran is false when no node was up.
func (h *chaosHarness) onNode(rng *rand.Rand, prefer int, fn func(nd *chaosNode)) (idx int, killed, ran bool) {
	order := rng.Perm(len(h.nodes))
	if prefer >= 0 && rng.Intn(10) < 7 {
		order = append([]int{prefer}, slices.DeleteFunc(order, func(i int) bool { return i == prefer })...)
	}
	for _, i := range order {
		nd := h.nodes[i]
		if !nd.up.Load() {
			continue
		}
		nd.mu.RLock()
		if !nd.up.Load() {
			nd.mu.RUnlock()
			continue
		}
		fn(nd)
		killed = !nd.up.Load()
		nd.mu.RUnlock()
		return i, killed, true
	}
	return -1, false, false
}

func (h *chaosHarness) newService(tn *tnode, cs *chaosStore) *service.Service {
	return service.New(h.cfg, cs, h.seal)
}

func (h *chaosHarness) newChaosStore(tn *tnode, idx int) *chaosStore {
	h.chaosGen++
	return &chaosStore{Store: tn.st(), rng: rand.New(rand.NewSource(h.seed + 7919*h.chaosGen + int64(idx)))}
}

// ---- writers ----

type chaosWorker struct {
	h   *chaosHarness
	id  int
	rng *rand.Rand
}

func (w *chaosWorker) nap() {
	time.Sleep(time.Duration(3+w.rng.Intn(25)) * time.Millisecond)
}

// write runs one write of rec on a node (preferring prefer) and records its outcome. It returns the outcome (outPending:
// no node was up, nothing was tried).
func (w *chaosWorker) write(rec *chaosRec, op *chaosOp, prefer int, fn func(nd *chaosNode) (hlc.Timestamp, error)) chaosOutcome {
	h := w.h
	op.start = time.Now()
	h.led.begin(rec, op)
	var ver hlc.Timestamp
	var err error
	idx, killed, ran := h.onNode(w.rng, prefer, func(nd *chaosNode) { ver, err = fn(nd) })
	end := time.Now()
	if !ran {
		h.led.drop(rec, op)
		return outPending
	}
	out := outAck
	switch {
	case err == nil:
	case killed, errors.Is(err, store.ErrUnconfirmed), errors.Is(err, service.ErrOutcomeUnknown), errors.Is(err, errUnsettled):
		// (a write the store could not settle before its deadline is store.ErrUnavailable: it may have been applied)
		out = outUnknown
	default:
		out = outRefused
	}
	h.led.finish(op, out, ver, err, idx, killed, end)
	if op.del && out != outRefused {
		rec.dead.Store(true)
	}
	kind := "write"
	switch {
	case op.del:
		kind = "delete"
	case op.state == 1:
		kind = "create"
	}
	h.count("%s %s: %s", rec.kind, kind, out)
	if err != nil {
		h.count("  error of %s %s (%s): %.70s", rec.kind, kind, out, strings.Join(strings.Fields(err.Error()), " "))
	}
	return out
}

func (r *chaosRec) next() int {
	r.counter++
	return r.counter
}

// userWorker creates, updates (name, role, active) and deletes users through the service layer.
func (w *chaosWorker) userWorker() {
	h := w.h
	var slots []*chaosRec
	for !h.stopping() {
		w.nap()
		if len(slots) < 6 && (len(slots) == 0 || w.rng.Intn(5) == 0) {
			org := h.userOrgs[w.rng.Intn(len(h.userOrgs))]
			name := fmt.Sprintf("u%d-%d", w.id, h.seq.Add(1))
			rec := &chaosRec{kind: model.KindUser, org: org, name: name}
			h.led.add(rec)
			op := &chaosOp{state: rec.next(), action: "user.create"}
			var u *model.User
			out := w.write(rec, op, -1, func(nd *chaosNode) (hlc.Timestamp, error) {
				role, gn, email := chaosRoles[1], "g1", name+"@chaos.test"
				var err error
				u, err = nd.svc.CreateUser(bg, service.System, org, service.UserInput{Username: &name, Email: &email,
					GivenName: &gn, Role: &role})
				if err != nil {
					return 0, err
				}
				return u.Version, nil
			})
			if out == outAck {
				h.led.setID(rec, u.ID)
			}
			if out == outAck || out == outUnknown {
				slots = append(slots, rec)
			}
			continue
		}
		if len(slots) == 0 {
			continue
		}
		i := w.rng.Intn(len(slots))
		rec := slots[i]
		id := h.led.idOf(rec)
		if id == "" { // the creation's outcome was not known: is there such a user?
			id = w.resolve(rec)
			if id == "" {
				if w.rng.Intn(6) == 0 {
					slots = slices.Delete(slots, i, i+1)
				}
				continue
			}
		}
		last := h.lastNode(rec)
		if w.rng.Intn(8) == 0 {
			op := &chaosOp{state: chaosDeleted, del: true, action: "user.delete"}
			out := w.write(rec, op, last, func(nd *chaosNode) (hlc.Timestamp, error) {
				return 0, nd.svc.DeleteUser(bg, service.System, id)
			})
			if out == outAck || out == outUnknown {
				slots = slices.Delete(slots, i, i+1)
			}
			continue
		}
		s := rec.next()
		op := &chaosOp{state: s, action: "user.update"}
		w.write(rec, op, last, func(nd *chaosNode) (hlc.Timestamp, error) {
			gn, role, active := "g"+strconv.Itoa(s), chaosRoles[s%3], s%4 != 0
			u, err := nd.svc.UpdateUser(bg, service.System, id, service.UserInput{GivenName: &gn, Role: &role, Active: &active})
			if err != nil {
				return 0, err
			}
			return u.Version, nil
		})
	}
}

// resolve finds the id of a user whose creation's outcome was not known, "" if no node holds it.
func (w *chaosWorker) resolve(rec *chaosRec) string {
	var id string
	w.h.onNode(w.rng, -1, func(nd *chaosNode) {
		r, err := nd.cs.GetByUnique(bg, model.KindUser, model.UserUsernameKey(rec.org, rec.name))
		if err == nil {
			id = r.ID
		}
	})
	if id != "" {
		w.h.led.setID(rec, id)
	}
	return id
}

// lastNode is the node that served the last operation of rec (-1: none).
func (h *chaosHarness) lastNode(rec *chaosRec) int {
	ops := h.led.opsOf(rec)
	for i := len(ops) - 1; i >= 0; i-- {
		if ops[i].out != outPending {
			return ops[i].node
		}
	}
	return -1
}

// sessionWorker creates, replaces and deletes sessions, some with a short life.
func (w *chaosWorker) sessionWorker() {
	h := w.h
	var slots []*chaosRec
	for !h.stopping() {
		w.nap()
		if len(slots) < 8 && (len(slots) == 0 || w.rng.Intn(4) == 0) {
			org := h.sessOrgs[w.rng.Intn(len(h.sessOrgs))]
			exp := time.Now().Add(time.Hour)
			if w.rng.Intn(3) == 0 {
				exp = time.Now().Add(time.Duration(1+w.rng.Intn(5)) * time.Second)
			}
			rec := &chaosRec{kind: model.KindSession, org: org, name: model.NewID(), expires: exp}
			rec.id = rec.name
			h.led.add(rec)
			op := &chaosOp{state: rec.next()}
			out := w.write(rec, op, -1, func(nd *chaosNode) (hlc.Timestamp, error) {
				s := chaosSession(rec, op.state)
				err := store.NewTable[model.Session](nd.cs).Create(bg, s)
				return s.Version, err
			})
			if out == outAck || out == outUnknown {
				slots = append(slots, rec)
			}
			continue
		}
		if len(slots) == 0 {
			continue
		}
		i := w.rng.Intn(len(slots))
		rec := slots[i]
		last := h.lastNode(rec)
		if w.rng.Intn(6) == 0 {
			op := &chaosOp{state: chaosDeleted, del: true}
			out := w.write(rec, op, last, func(nd *chaosNode) (hlc.Timestamp, error) {
				return 0, store.NewTable[model.Session](nd.cs).Delete(bg, rec.id)
			})
			if out == outAck || out == outUnknown {
				slots = slices.Delete(slots, i, i+1)
			}
			continue
		}
		op := &chaosOp{state: rec.next()}
		w.write(rec, op, last, func(nd *chaosNode) (hlc.Timestamp, error) {
			s := chaosSession(rec, op.state)
			err := store.NewTable[model.Session](nd.cs).Put(bg, s)
			return s.Version, err
		})
	}
}

func chaosSession(rec *chaosRec, state int) *model.Session {
	return &model.Session{Meta: model.Meta{ID: rec.id}, UserID: "user-" + rec.org, OrgID: rec.org, Expires: rec.expires,
		IP: "n" + strconv.Itoa(state), UserAgent: fmt.Sprintf("ua-%s-%d", rec.id, state)}
}

// keyWorker creates, replaces and deletes signing keys (the global partition).
func (w *chaosWorker) keyWorker() {
	h := w.h
	var slots []*chaosRec
	for !h.stopping() {
		time.Sleep(time.Duration(40+w.rng.Intn(120)) * time.Millisecond)
		if len(slots) < 4 && (len(slots) == 0 || w.rng.Intn(3) == 0) {
			rec := &chaosRec{kind: model.KindKey, name: fmt.Sprintf("k%d-%d", w.id, h.seq.Add(1))}
			rec.id = rec.name
			h.led.add(rec)
			op := &chaosOp{state: rec.next()}
			out := w.write(rec, op, -1, func(nd *chaosNode) (hlc.Timestamp, error) {
				k := chaosKey(rec, op.state)
				err := store.NewTable[model.SigningKey](nd.cs).Create(bg, k)
				return k.Version, err
			})
			if out == outAck || out == outUnknown {
				slots = append(slots, rec)
			}
			continue
		}
		if len(slots) == 0 {
			continue
		}
		i := w.rng.Intn(len(slots))
		rec := slots[i]
		last := h.lastNode(rec)
		if w.rng.Intn(3) != 0 {
			op := &chaosOp{state: chaosDeleted, del: true}
			out := w.write(rec, op, last, func(nd *chaosNode) (hlc.Timestamp, error) {
				return 0, store.NewTable[model.SigningKey](nd.cs).Delete(bg, rec.id)
			})
			if out == outAck || out == outUnknown {
				slots = slices.Delete(slots, i, i+1)
			}
			continue
		}
		op := &chaosOp{state: rec.next()}
		w.write(rec, op, last, func(nd *chaosNode) (hlc.Timestamp, error) {
			k := chaosKey(rec, op.state)
			err := store.NewTable[model.SigningKey](nd.cs).Put(bg, k)
			return k.Version, err
		})
	}
}

func chaosKey(rec *chaosRec, state int) *model.SigningKey {
	return &model.SigningKey{Meta: model.Meta{ID: rec.id}, Alg: "ES256", PrivateKey: "x", PublicJWK: []byte("n" + strconv.Itoa(state)),
		Expires: time.Now().Add(24 * time.Hour)}
}

// orgWorker renames the base organizations and creates, renames and deletes extra ones (the global partition).
func (w *chaosWorker) orgWorker() {
	h := w.h
	base := h.led.ofKind(model.KindOrg)
	var extra []*chaosRec
	for !h.stopping() {
		time.Sleep(time.Duration(40+w.rng.Intn(120)) * time.Millisecond)
		var rec *chaosRec
		create := false
		switch r := w.rng.Intn(10); {
		case r < 3 && len(extra) < 4:
			rec = &chaosRec{kind: model.KindOrg, name: fmt.Sprintf("chaos-x%d-%d", w.id, h.seq.Add(1))}
			rec.id = rec.name
			h.led.add(rec)
			create = true
		case r < 6 && len(extra) > 0:
			rec = extra[w.rng.Intn(len(extra))]
		default:
			rec = base[w.rng.Intn(len(base))]
		}
		last := h.lastNode(rec)
		if !create && slices.Contains(extra, rec) && w.rng.Intn(4) == 0 {
			op := &chaosOp{state: chaosDeleted, del: true}
			out := w.write(rec, op, last, func(nd *chaosNode) (hlc.Timestamp, error) {
				return 0, store.NewTable[model.Org](nd.cs).Delete(bg, rec.id)
			})
			if out == outAck || out == outUnknown {
				extra = slices.DeleteFunc(extra, func(r *chaosRec) bool { return r == rec })
			}
			continue
		}
		op := &chaosOp{state: rec.next()}
		out := w.write(rec, op, last, func(nd *chaosNode) (hlc.Timestamp, error) {
			o := chaosOrg(rec, op.state)
			tbl := store.NewTable[model.Org](nd.cs)
			if create {
				err := tbl.Create(bg, o)
				return o.Version, err
			}
			err := tbl.Put(bg, o)
			return o.Version, err
		})
		if create && (out == outAck || out == outUnknown) {
			extra = append(extra, rec)
		}
	}
}

func chaosOrg(rec *chaosRec, state int) *model.Org {
	return &model.Org{Meta: model.Meta{ID: rec.id}, Name: rec.id, DisplayName: "n" + strconv.Itoa(state)}
}

// ---- readers ----

// reader reads through node i, over and over, and judges every answer.
func (h *chaosHarness) reader(i int, seed int64) {
	rng := rand.New(rand.NewSource(seed))
	for !h.stopping() {
		time.Sleep(time.Duration(2+rng.Intn(15)) * time.Millisecond)
		nd := h.nodes[i]
		if !nd.up.Load() {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		nd.mu.RLock()
		if nd.up.Load() {
			switch r := rng.Intn(100); {
			case r < 40:
				h.readUser(nd, rng)
			case r < 65:
				h.readSession(nd, rng)
			case r < 83:
				h.readKeys(nd)
			default:
				h.readOrgs(nd)
			}
		}
		nd.mu.RUnlock()
	}
}

// pick chooses a record to read, preferring one not deleted yet.
func pick(rng *rand.Rand, recs []*chaosRec) *chaosRec {
	if len(recs) == 0 {
		return nil
	}
	r := recs[rng.Intn(len(recs))]
	for range 6 {
		if !r.dead.Load() {
			break
		}
		r = recs[rng.Intn(len(recs))]
	}
	return r
}

// answer classifies the error of a read: found (nil), absent, or refused.
func (h *chaosHarness) answer(nd *chaosNode, what string, part int, err error) (found, absent, refused bool) {
	switch {
	case err == nil:
		h.count("read %s: answered", what)
		return true, false, false
	case errors.Is(err, store.ErrNotFound):
		h.count("read %s: not found", what)
		return false, true, false
	case errors.Is(err, store.ErrUnavailable):
		h.count("read %s: refused (not writable)", what)
		nd.lastRefused[part].Store(time.Now().UnixNano())
		return false, false, true
	}
	h.count("read %s: other error %.60s", what, err.Error())
	return false, false, true
}

func (h *chaosHarness) judge(nd *chaosNode, rec *chaosRec, o chaosObs, t0, t1 time.Time, ready bool, strict bool, via string) {
	ops := h.led.opsOf(rec)
	p := h.partOf(rec)
	since := "never"
	sinceRefused := time.Duration(1 << 40)
	if lr := nd.lastRefused[p].Load(); lr != 0 {
		sinceRefused = t0.Sub(time.Unix(0, lr))
		since = sinceRefused.Round(time.Millisecond).String()
	}
	sinceUp := t0.Sub(time.Unix(0, nd.upSince.Load()))
	grace := sinceRefused < h.grace || sinceUp < h.grace
	if age := staleAge(ops, rec.expires, o, t0, strict); age > h.stalest()/2 {
		h.noteStale(age, fmt.Sprintf("node %d (last refused read of the partition %s before, up for %v) %s of %s [%s] %s", nd.idx, since,
			sinceUp.Round(time.Millisecond), via, rec, chaosTrace(ops), h.partStatus(nd, rec)))
	}
	msg, stale := judgeRead(ops, rec.expires, o, t0, t1, h.bound, strict)
	if msg == "" {
		return
	}
	report := fmt.Sprintf("node %d (ready %v, last refused read of the partition %s before, up for %v) %s of %s: %s [%s] %s", nd.idx, ready,
		since, sinceUp.Round(time.Millisecond), via, rec, msg, chaosTrace(ops), h.partStatus(nd, rec))
	if stale && grace && !h.strictGrace {
		h.noteGrace(report)
		return
	}
	h.violate("STALE/BAD READ %s", report)
}

// noteGrace counts a stale answer served within the grace window after the node regained contact with the owner.
func (h *chaosHarness) noteGrace(report string) {
	h.smu.Lock()
	defer h.smu.Unlock()
	h.graceCount++
	if len(h.graceExamples) < 3 {
		h.graceExamples = append(h.graceExamples, report)
	}
}

// partOf is the partition of rec.
func (h *chaosHarness) partOf(rec *chaosRec) int {
	if rec.kind == model.KindUser || rec.kind == model.KindSession {
		return partitionNum(rec.org)
	}
	return globalPartition
}

// partStatus describes the node's view of the partition of rec (for a violation's report).
func (h *chaosHarness) partStatus(nd *chaosNode, rec *chaosRec) string {
	p := h.partOf(rec)
	pm := nd.tn.n.manager()
	if pm == nil {
		return "(no manager)"
	}
	st, err := pm.PartitionStatus(p)
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("{partition %d on node %d now: leading %v, canRead %v, committed %s, ownerCommitted %s, lag %v, catchingUp %v, diverged %v}",
		p, nd.idx, st.Leading, st.CanRead, st.Committed.String(), st.OwnerCommitted.String(), st.Lag.Round(time.Millisecond), st.CatchingUp, st.Diverged)
}

func (h *chaosHarness) readUser(nd *chaosNode, rng *rand.Rand) {
	rec := pick(rng, h.led.ofKind(model.KindUser))
	if rec == nil {
		return
	}
	ready, _ := nd.tn.n.Ready()
	tbl := store.NewTable[model.User](nd.cs)
	t0 := time.Now()
	var u *model.User
	var err error
	via := "get by username"
	if id := h.led.idOf(rec); id != "" && rng.Intn(2) == 0 {
		via = "get by id"
		u, err = tbl.Get(bg, id)
	} else {
		u, err = tbl.GetByUnique(bg, model.UserUsernameKey(rec.org, rec.name))
	}
	t1 := time.Now()
	found, absent, _ := h.answer(nd, "user", partitionNum(rec.org), err)
	switch {
	case found:
		h.judge(nd, rec, obsUser(u), t0, t1, ready, false, via)
	case absent:
		h.judge(nd, rec, chaosObs{absent: true}, t0, t1, ready, false, via)
	}
}

func (h *chaosHarness) readSession(nd *chaosNode, rng *rand.Rand) {
	rec := pick(rng, h.led.ofKind(model.KindSession))
	if rec == nil {
		return
	}
	ready, _ := nd.tn.n.Ready()
	t0 := time.Now()
	s, err := store.NewTable[model.Session](nd.cs).Get(bg, rec.id)
	t1 := time.Now()
	found, absent, _ := h.answer(nd, "session", partitionNum(rec.org), err)
	switch {
	case found:
		h.judge(nd, rec, obsSession(s), t0, t1, ready, false, "get")
	case absent:
		h.judge(nd, rec, chaosObs{absent: true}, t0, t1, ready, false, "get")
	}
}

// judgeListing judges a listing of one global kind: every record of the ledger of that kind is either in it or not, and
// nothing outside the ledger may be in it.
func (h *chaosHarness) judgeListing(nd *chaosNode, kind model.Kind, t0, t1 time.Time, ready bool, listed map[string]chaosObs) {
	recs := h.led.ofKind(kind)
	known := map[string]bool{}
	for _, rec := range recs {
		known[rec.id] = true
		o, ok := listed[rec.id]
		if !ok {
			o = chaosObs{absent: true}
		}
		h.judge(nd, rec, o, t0, t1, ready, true, "list")
	}
	for id := range listed {
		if !known[id] {
			h.violate("BAD READ node %d (ready %v) list of %s: %s is listed and was never written", nd.idx, ready, kind, id)
		}
	}
}

func (h *chaosHarness) readKeys(nd *chaosNode) {
	ready, _ := nd.tn.n.Ready()
	t0 := time.Now()
	keys, _, err := store.NewTable[model.SigningKey](nd.cs).List(bg, store.ListQuery{Limit: 10000})
	t1 := time.Now()
	if found, _, _ := h.answer(nd, "keys list", globalPartition, err); !found {
		return
	}
	listed := map[string]chaosObs{}
	for _, k := range keys {
		listed[k.ID] = obsKey(k)
	}
	h.judgeListing(nd, model.KindKey, t0, t1, ready, listed)
}

func (h *chaosHarness) readOrgs(nd *chaosNode) {
	ready, _ := nd.tn.n.Ready()
	t0 := time.Now()
	orgs, _, err := store.NewTable[model.Org](nd.cs).List(bg, store.ListQuery{Limit: 10000})
	t1 := time.Now()
	if found, _, _ := h.answer(nd, "orgs list", globalPartition, err); !found {
		return
	}
	listed := map[string]chaosObs{}
	for _, o := range orgs {
		listed[o.ID] = obsOrg(o)
	}
	h.judgeListing(nd, model.KindOrg, t0, t1, ready, listed)
}

// ---- faults ----

// applyNet makes the simulated network what the controller's link state says.
func (h *chaosHarness) applyNet() {
	for i := range h.c.addrs {
		ns := h.c.net(i)
		ns.mu.Lock()
		ns.cut = map[string]bool{}
		for j, a := range h.c.addrs {
			if j != i && (h.cut[i][j] || h.dead[i] || h.dead[j]) {
				ns.cut[a] = true
			}
		}
		ns.mu.Unlock()
	}
}

// kill stops node i the way a crash looks from outside: nothing it says reaches its peers (it is cut off first, so the
// hand-over it announces when it closes is never heard), operations in flight on it end unknown, and its database is
// closed whole afterwards (a real kill -9 is out of reach: the store is closed, never abandoned).
func (h *chaosHarness) kill(i int) {
	nd := h.nodes[i]
	h.note("kill %d", i)
	nd.up.Store(false)
	h.dead[i] = true
	h.applyNet()
	_ = nd.tn.n.Close()
	nd.mu.Lock()
	nd.svc.WaitBackground()
	_ = nd.tn.n.Store().Close()
	nd.mu.Unlock()
	h.down[i] = true
}

// restart starts node i again on its data, or on a new empty disk (lose).
func (h *chaosHarness) restart(i int, lose bool) {
	nd := h.nodes[i]
	dir := nd.tn.dir
	if lose {
		dir = ""
		h.wipes[i] = append(h.wipes[i], time.Now())
		h.lost = i
		h.note("restart %d with its disk lost", i)
	} else {
		h.note("restart %d with its data", i)
	}
	tn := h.c.build(i, dir, nil)
	h.c.nodes[i] = tn
	h.dead[i] = false
	h.applyNet()
	h.c.start(tn)
	cs := h.newChaosStore(tn, i)
	svc := h.newService(tn, cs)
	nd.mu.Lock()
	nd.tn, nd.cs, nd.svc = tn, cs, svc
	nd.upSince.Store(time.Now().UnixNano())
	nd.up.Store(true)
	nd.mu.Unlock()
	h.down[i] = false
}

func (h *chaosHarness) canLoseDisk(i int) bool {
	if h.lost >= 0 {
		if ok, _ := h.c.nodes[h.lost].n.Ready(); !ok || h.down[h.lost] {
			return false
		}
		h.lost = -1
	}
	for j := range h.nodes {
		if j != i && h.down[j] {
			return false
		}
	}
	return true
}

type chaosUndo struct {
	at   time.Time
	what string
	fn   func()
}

// faultParts are the partitions the faults on catch-ups aim at: the global one and those of the organizations.
func (h *chaosHarness) faultPart(rng *rand.Rand) int {
	all := append(append([]string{""}, h.userOrgs...), h.sessOrgs...)
	return partitionNum(all[rng.Intn(len(all))])
}

// runFaults injects random faults for dur (from the seed), undoing each after a while.
func (h *chaosHarness) runFaults(rng *rand.Rand, dur time.Duration) {
	var undos []chaosUndo
	later := func(min, max time.Duration, what string, fn func()) {
		undos = append(undos, chaosUndo{at: time.Now().Add(min + time.Duration(rng.Int63n(int64(max-min)))), what: what, fn: fn})
	}
	n := len(h.nodes)
	pair := func() (int, int) {
		i := rng.Intn(n)
		return i, (i + 1 + rng.Intn(n-1)) % n
	}
	nDown := func() int {
		c := 0
		for _, d := range h.down {
			if d {
				c++
			}
		}
		return c
	}
	deadline := time.Now().Add(dur)
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	lastPurge := time.Now()
	for time.Now().Before(deadline) {
		<-tick.C
		if time.Since(lastPurge) >= 1500*time.Millisecond { // owners purge the tombstones past the retention: nodes away longer copy whole partitions
			lastPurge = time.Now()
			h.purgeRound()
		}
		sort.Slice(undos, func(a, b int) bool { return undos[a].at.Before(undos[b].at) })
		for len(undos) > 0 && !undos[0].at.After(time.Now()) {
			u := undos[0]
			undos = undos[1:]
			h.note("undo: %s", u.what)
			u.fn()
		}
		if rng.Intn(100) >= 35 {
			continue
		}
		switch r := rng.Intn(100); {
		case r < 14: // kill a node, restart it later with its data, or with its disk lost
			i := rng.Intn(n)
			if h.down[i] || nDown() >= 1 && rng.Intn(5) != 0 {
				continue
			}
			lose := rng.Intn(3) == 0
			h.kill(i)
			later(300*time.Millisecond, 4*time.Second, fmt.Sprintf("restart %d", i), func() {
				if lose && h.canLoseDisk(i) {
					h.restart(i, true)
				} else {
					h.restart(i, false)
				}
			})
		case r < 26: // cut a pair of nodes, both ways
			i, j := pair()
			h.note("cut %d <-> %d", i, j)
			h.cut[i][j], h.cut[j][i] = true, true
			h.applyNet()
			later(300*time.Millisecond, 3*time.Second, fmt.Sprintf("heal %d <-> %d", i, j), func() {
				h.cut[i][j], h.cut[j][i] = false, false
				h.applyNet()
			})
		case r < 38: // cut one direction
			i, j := pair()
			h.note("cut %d -> %d", i, j)
			h.cut[i][j] = true
			h.applyNet()
			later(300*time.Millisecond, 3*time.Second, fmt.Sprintf("heal %d -> %d", i, j), func() {
				h.cut[i][j] = false
				h.applyNet()
			})
		case r < 45: // a node cut off from both others
			i := rng.Intn(n)
			h.note("isolate %d", i)
			for j := range h.nodes {
				if j != i {
					h.cut[i][j], h.cut[j][i] = true, true
				}
			}
			h.applyNet()
			later(500*time.Millisecond, 3*time.Second, fmt.Sprintf("unisolate %d", i), func() {
				for j := range h.nodes {
					if j != i {
						h.cut[i][j], h.cut[j][i] = false, false
					}
				}
				h.applyNet()
			})
		case r < 53: // a node misses what the others write, and (often) its catch-ups fail
			i := rng.Intn(n)
			if h.down[i] {
				continue
			}
			h.note("lag %d", i)
			h.c.lagBehind(i, true)
			var f *faultStore
			if rng.Intn(2) == 0 {
				f = h.fs.of(h.c.nodes[i])
				p := h.faultPart(rng)
				h.note("  and its catch-ups of partition %d fail", p)
				f.failImport.Store(int64(p) + 1)
			}
			later(500*time.Millisecond, 3*time.Second, fmt.Sprintf("unlag %d", i), func() {
				h.c.lagBehind(i, false)
				if f != nil {
					f.failImport.Store(0)
				}
			})
		case r < 60: // catch-ups of a partition fail on a node
			i := rng.Intn(n)
			if h.down[i] {
				continue
			}
			p := h.faultPart(rng)
			f := h.fs.of(h.c.nodes[i])
			h.note("failImport %d partition %d", i, p)
			f.failImport.Store(int64(p) + 1)
			later(time.Second, 5*time.Second, fmt.Sprintf("failImport %d off", i), func() { f.failImport.Store(0) })
		case r < 66: // a full import is cut after its reset
			i := rng.Intn(n)
			if h.down[i] {
				continue
			}
			p := h.faultPart(rng)
			f := h.fs.of(h.c.nodes[i])
			h.note("cutAfterReset %d partition %d", i, p)
			f.cutAfterReset.Store(int64(p) + 1)
			later(2*time.Second, 6*time.Second, fmt.Sprintf("cutAfterReset %d off", i), func() { f.cutAfterReset.Store(0) })
		case r < 72: // a slow disk
			i := rng.Intn(n)
			if h.down[i] {
				continue
			}
			f := h.fs.of(h.c.nodes[i])
			d := time.Duration(50+rng.Intn(300)) * time.Millisecond
			h.note("slow disk %d (%v)", i, d)
			f.pendingDelay.Store(int64(d))
			later(time.Second, 4*time.Second, fmt.Sprintf("slow disk %d off", i), func() { f.pendingDelay.Store(0) })
		case r < 86: // writes that report an unknown outcome
			i := rng.Intn(n)
			if h.down[i] {
				continue
			}
			cs := h.nodes[i].cs
			land, skip := int64(100+rng.Intn(500)), int64(rng.Intn(150))
			h.note("unconfirmed writes on %d (landed %d‰, not made %d‰)", i, land, skip)
			cs.landP.Store(land)
			cs.skipP.Store(skip)
			later(time.Second, 4*time.Second, fmt.Sprintf("unconfirmed writes on %d off", i), func() {
				cs.landP.Store(0)
				cs.skipP.Store(0)
			})
		case r < 94: // requests that hang
			i, j := pair()
			h.note("hold %d -> %d", i, j)
			h.c.hold(i, j, true, gossip.PartWriteMsg, gossip.PartReadMsg, gossip.PartCommitMsg)
			later(500*time.Millisecond, 3*time.Second, fmt.Sprintf("unhold %d -> %d", i, j), func() {
				h.c.hold(i, j, false, gossip.PartWriteMsg, gossip.PartReadMsg, gossip.PartCommitMsg)
			})
		default: // every link repaired
			h.note("heal the network")
			h.cut = [3][3]bool{}
			h.applyNet()
			h.c.heal()
			for i := range h.dead {
				h.dead[i] = h.down[i]
			}
			h.applyNet()
		}
	}
	h.note("end of faults: %d undo(s) pending", len(undos))
	for _, u := range undos {
		if strings.HasPrefix(u.what, "restart") { // a node still down comes back with its data (quiesce does it)
			continue
		}
		u.fn()
	}
}

// purgeRound runs the purge of every node that is up (the application does it every few minutes): expired records go
// from each node's own copy, and the owner of a partition writes the purge of its tombstones past the retention.
func (h *chaosHarness) purgeRound() {
	for i, nd := range h.nodes {
		if !h.down[i] {
			nd.tn.n.purgeOnce(bg, time.Now())
		}
	}
	h.count("purge rounds: %d", 1)
}

// ---- the quiet period and the final checks ----

func (h *chaosHarness) poll(d time.Duration, what string, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	h.violate("LIVENESS: timed out after %v waiting for %s", d, what)
	return false
}

// quiesce ends every fault and waits until the cluster is ready and has settled.
func (h *chaosHarness) quiesce() {
	h.stop.Store(true)
	h.wg.Wait()
	h.note("workload stopped; healing everything")
	h.cut = [3][3]bool{}
	h.c.heal()
	for i := range h.nodes {
		h.dead[i] = h.down[i]
		if !h.down[i] {
			h.nodes[i].cs.landP.Store(0)
			h.nodes[i].cs.skipP.Store(0)
			if f := h.fs.of(h.c.nodes[i]); f != nil {
				f.failImport.Store(0)
				f.cutAfterReset.Store(0)
				f.pendingDelay.Store(0)
			}
		}
	}
	h.applyNet()
	for i := range h.nodes {
		if h.down[i] {
			h.restart(i, false)
		}
	}
	h.c.heal()
	h.applyNet()
	if !h.poll(90*time.Second, "every node ready", func() bool {
		for _, tn := range h.c.nodes {
			if ok, _ := tn.n.Ready(); !ok {
				return false
			}
		}
		return true
	}) {
		for i, tn := range h.c.nodes {
			ok, why := tn.n.Ready()
			h.violate("  node %d ready %v: %s", i, ok, why)
		}
		return
	}
	// one purge as at the same time everywhere: expired records go from every copy, whatever each node did meanwhile
	time.Sleep(1100 * time.Millisecond)
	h.purgeRound()
	h.poll(90*time.Second, "every node to hold the same committed data", func() bool {
		if !committedEqual(h.c.nodes) {
			return false
		}
		diff, _, err := h.compareExports()
		return err == nil && len(diff) == 0
	})
	// let unknown outcomes settle and the staleness window pass, then look
	time.Sleep(h.bound)
	h.poll(30*time.Second, "committed positions to agree", func() bool { return committedEqual(h.c.nodes) })
}

// compareExports compares what every node's database holds of every partition, tombstones included, to node 0's.
func (h *chaosHarness) compareExports() (diffs, tombstones []string, err error) {
	sums := make([][partitions]map[string]string, len(h.c.nodes))
	pos := make([][partitions]uint64, len(h.c.nodes))
	purged := make([][partitions]uint64, len(h.c.nodes)) // each node's purge point: a tombstone held by some only is told by it
	for i, tn := range h.c.nodes {
		ps, ok := tn.st().Inner().(store.PartitionStore)
		if !ok {
			return nil, nil, errors.New("not a partition store")
		}
		for p := range partitions {
			if st, err := ps.PartitionState(bg, p); err == nil {
				purged[i][p] = st.Purged
			}
			m := map[string]string{}
			err := ps.ExportPartition(bg, p, 0, func(at store.PartitionPos) error { pos[i][p] = at.Seq; return nil },
				func(r store.PartitionRecord) error {
					sum := sha256.Sum256(r.Data)
					m[string(r.Kind)+"/"+r.ID] = fmt.Sprintf("v%d del=%v data=%x seq=%d", r.Version, r.Deleted, sum[:6], r.Seq)
					return nil
				})
			if err != nil {
				return nil, nil, fmt.Errorf("node %d partition %d: %w", i, p, err)
			}
			sums[i][p] = m
		}
	}
	for p := range partitions {
		for i := 1; i < len(h.c.nodes); i++ {
			if pos[i][p] != pos[0][p] {
				diffs = append(diffs, fmt.Sprintf("partition %d: node %d is at sequence %d, node 0 at %d", p, i, pos[i][p], pos[0][p]))
			}
			add := func(tombstone bool, format string, args ...any) {
				if tombstone {
					tombstones = append(tombstones, fmt.Sprintf(format, args...)+
						fmt.Sprintf(" (purged below: node 0 %d, node %d %d)", purged[0][p]+1, i, purged[i][p]+1))
				} else {
					diffs = append(diffs, fmt.Sprintf(format, args...))
				}
			}
			for k, v := range sums[0][p] {
				if o, ok := sums[i][p][k]; !ok {
					add(strings.Contains(v, "del=true"), "partition %d: %s is on node 0 (%s) and not on node %d", p, k, v, i)
				} else if o != v {
					add(false, "partition %d: %s differs: node 0 %s, node %d %s", p, k, v, i, o)
				}
			}
			for k, v := range sums[i][p] {
				if _, ok := sums[0][p][k]; !ok {
					add(strings.Contains(v, "del=true"), "partition %d: %s is on node %d (%s) and not on node 0", p, k, i, v)
				}
			}
		}
	}
	sort.Strings(diffs)
	sort.Strings(tombstones)
	return diffs, tombstones, nil
}

// finalObs is what node tn's database holds of rec.
func (h *chaosHarness) finalObs(tn *tnode, rec *chaosRec) (chaosObs, error) {
	inner := tn.st().Inner()
	var r *store.Record
	var err error
	if rec.kind == model.KindUser {
		r, err = inner.GetByUnique(bg, model.KindUser, model.UserUsernameKey(rec.org, rec.name))
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return chaosObs{}, err
		}
		if id := h.led.idOf(rec); id != "" {
			byID, err2 := inner.Lookup(bg, model.KindUser, id)
			switch {
			case err2 != nil && !errors.Is(err2, store.ErrNotFound):
				return chaosObs{}, err2
			case err2 == nil && !byID.Deleted && r == nil:
				return chaosObs{}, errors.New("the user is held under its id and not found by its username (the unique index lost it)")
			case err2 == nil && byID.Deleted && r != nil:
				return chaosObs{}, errors.New("the user's tombstone is held and its username still finds a user")
			}
		}
	} else {
		r, err = inner.Lookup(bg, rec.kind, rec.id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return chaosObs{}, err
		}
	}
	if err != nil || r == nil || r.Deleted {
		return chaosObs{absent: true}, nil
	}
	return obsRecord(rec.kind, r)
}

func (h *chaosHarness) verify() {
	now := time.Now()
	// 1. no acknowledged write lost, no refused write seen
	acked, unknown, refused := 0, 0, 0
	for _, rec := range h.led.all() {
		ops := h.led.opsOf(rec)
		for _, o := range ops {
			switch o.out {
			case outAck:
				acked++
			case outUnknown:
				unknown++
			case outRefused:
				refused++
			case outPending:
				h.violate("a write never ended: %s %s", rec, o)
			}
		}
		for i, tn := range h.c.nodes {
			o, err := h.finalObs(tn, rec)
			if err != nil {
				h.violate("FINAL node %d: %s: %v", i, rec, err)
				continue
			}
			if msg := judgeFinal(ops, rec.expires, o, now); msg != "" {
				h.violate("FINAL node %d: %s: %s; holds %s [%s]", i, rec, msg, o, chaosTrace(ops))
			}
		}
	}
	h.t.Logf("ledger: %d acknowledged, %d unknown, %d refused writes of %d records", acked, unknown, refused, len(h.led.all()))
	// a node that is ready answers reads of everything it holds
	for i, tn := range h.c.nodes {
		for _, rec := range h.led.all() {
			var err error
			switch rec.kind {
			case model.KindUser:
				_, err = tn.st().GetByUnique(bg, model.KindUser, model.UserUsernameKey(rec.org, rec.name))
			default:
				_, err = tn.st().Get(bg, rec.kind, rec.id)
			}
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				h.violate("FINAL node %d is ready and refuses to read %s: %v", i, rec, err)
				break
			}
		}
		for _, kind := range []model.Kind{model.KindKey, model.KindOrg} {
			if _, err := tn.st().List(bg, kind, store.ListQuery{Limit: 10000}); err != nil {
				h.violate("FINAL node %d is ready and refuses to list %s: %v", i, kind, err)
			}
		}
	}
	// 3. convergence
	if diffs, tombs, err := h.compareExports(); err != nil {
		h.violate("CONVERGENCE: %v", err)
	} else {
		if len(tombs) > 0 {
			// the nodes hold the same live data and positions but not the same tombstones: see
			// TestChaosPurgeReachesANodeThatMissedIt
			msg := fmt.Sprintf("%d tombstone(s) held by some nodes only, e.g. %s", len(tombs), tombs[0])
			if h.strictGrace {
				h.violate("CONVERGENCE (tombstones): %s", msg)
			} else {
				h.t.Logf("KNOWN, not a failure unless QUISORA_CHAOS_STRICT=1: %s", msg)
			}
		}
		for i, d := range diffs {
			if i == 10 {
				h.violate("CONVERGENCE: ... and %d more differences", len(diffs)-10)
				break
			}
			h.violate("CONVERGENCE: %s", d)
		}
	}
	// 4. audit completeness
	h.verifyAudit()
}

// verifyAudit checks that every service-level change acknowledged (or reported unknown) on a node left an audit event
// there, unless the node's disk was lost afterwards or the node was killed while serving it.
func (h *chaosHarness) verifyAudit() {
	type key struct {
		node           int
		action, target string
	}
	want := map[key]int{}
	for _, rec := range h.led.all() {
		if rec.kind != model.KindUser {
			continue
		}
		for _, o := range h.led.opsOf(rec) {
			if o.action == "" || o.killed || (o.out != outAck && o.out != outUnknown) {
				continue
			}
			lost := false
			for _, w := range h.wipes[o.node] {
				if w.After(o.start) {
					lost = true
				}
			}
			if !lost {
				want[key{o.node, o.action, rec.name}]++
			}
		}
	}
	have := map[key]int{}
	for i, tn := range h.c.nodes {
		after := ""
		for {
			res, err := tn.st().Inner().List(bg, model.KindAudit, store.ListQuery{Limit: 500, After: after})
			if err != nil {
				h.violate("AUDIT: node %d: %v", i, err)
				break
			}
			for _, r := range res.Records {
				var a model.Audit
				if err := store.Decode(r, &a); err == nil {
					have[key{i, a.Action, a.Target}]++
				}
				after = r.ID
			}
			if len(res.Records) < 500 {
				break
			}
		}
	}
	missing := 0
	for k, n := range want {
		if have[k] < n {
			missing++
			if missing <= 10 {
				h.violate("AUDIT: node %d has %d audit event(s) %q for %s, %d change(s) landed or were reported unknown there",
					k.node, have[k], k.action, k.target, n)
			}
		}
	}
	if missing > 10 {
		h.violate("AUDIT: ... and %d more changes without an audit event", missing-10)
	}
	h.t.Logf("audit: %d changes checked on %d (node, action, user) keys", func() int {
		t := 0
		for _, n := range want {
			t += n
		}
		return t
	}(), len(want))
}

// ---- the test ----

func TestChaosSoak(t *testing.T) {
	if testing.Short() {
		t.Skip("chaos soak skipped in -short mode")
	}
	if !chaosWanted() {
		t.Skip("chaos soak: set QUISORA_CHAOS=1 or run it with -run TestChaosSoak")
	}
	seed := chaosEnvInt(t, "QUISORA_CHAOS_SEED", time.Now().UnixNano()%1_000_000_007)
	dur := chaosEnvDur(t, "QUISORA_CHAOS_DURATION", 60*time.Second)
	slack := chaosEnvDur(t, "QUISORA_CHAOS_SLACK", 2*time.Second)
	var b backend
	switch bn := os.Getenv("QUISORA_CHAOS_BACKEND"); bn {
	case "", "badger", "badgerdb":
		b = badgerBackend()
	case "sqlite":
		b = sqliteBackend()
	default:
		t.Fatalf("QUISORA_CHAOS_BACKEND=%q: badger or sqlite", bn)
	}
	t.Logf("chaos soak seed %d (QUISORA_CHAOS_SEED=%d), %v, backend %s", seed, seed, dur, b.name)

	// tombstones are purged after 3 s, and every second at most per partition (the soak runs the purge itself): a node that
	// was away a while copies whole partitions, which cutAfterReset can then interrupt
	scan := purgeScanEvery
	purgeScanEvery = time.Second
	t.Cleanup(func() { purgeScanEvery = scan })
	fs := &faults{}
	c := newTCluster(t, 3, fs.over(b))
	c.opts = shortRetention
	c.startAll()
	c.waitReady()
	c.waitSettled()
	c.noSeed = true // a node whose disk is lost joins the cluster; it never forms a new one

	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 1
	sealer, err := secure.NewSealer(secure.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	h := &chaosHarness{t: t, c: c, fs: fs, seed: seed, start: time.Now(), cfg: cfg, seal: sealer, stats: map[string]int{},
		seen: map[string]bool{}, lost: -1}
	h.bound = time.Duration(c.nodes[0].n.staleAfter.Load()) + slack
	h.grace = time.Duration(c.nodes[0].n.staleAfter.Load()) + 700*time.Millisecond
	h.strictGrace = os.Getenv("QUISORA_CHAOS_STRICT") == "1"
	for k := range 4 {
		h.userOrgs = append(h.userOrgs, fmt.Sprintf("chaos-org-%d", k))
	}
	for k := range 6 {
		h.sessOrgs = append(h.sessOrgs, fmt.Sprintf("chaos-s-%d", k))
	}
	for i, tn := range c.nodes {
		nd := &chaosNode{idx: i, tn: tn}
		nd.cs = h.newChaosStore(tn, i)
		nd.svc = h.newService(tn, nd.cs)
		nd.up.Store(true)
		nd.upSince.Store(time.Now().UnixNano())
		h.nodes = append(h.nodes, nd)
	}
	// the organizations the users live in are created, acknowledged, and held everywhere before the run
	for _, name := range h.userOrgs {
		rec := &chaosRec{kind: model.KindOrg, name: name, id: name, counter: 1}
		h.led.add(rec)
		op := &chaosOp{state: 1, node: 0, start: time.Now()}
		h.led.begin(rec, op)
		deadline := time.Now().Add(60 * time.Second)
		for {
			o := chaosOrg(rec, 1)
			err := store.NewTable[model.Org](c.nodes[0].st()).Create(bg, o)
			if err == nil {
				h.led.finish(op, outAck, o.Version, nil, 0, false, time.Now())
				break
			}
			if !errors.Is(err, store.ErrUnavailable) && !errors.Is(err, store.ErrUnconfirmed) || time.Now().After(deadline) {
				t.Fatalf("setup: organization %s: %v", name, err)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	waitFor(t, 30*time.Second, "the organizations on every node", func() bool {
		for _, tn := range c.nodes {
			for _, name := range h.userOrgs {
				if _, err := store.NewTable[model.Org](tn.st()).Get(bg, name); err != nil {
					return false
				}
			}
		}
		return true
	})

	h.start = time.Now()
	chaosEpoch = h.start
	spawn := func(fn func()) {
		h.wg.Add(1)
		go func() { defer h.wg.Done(); fn() }()
	}
	worker := func(id int) *chaosWorker {
		return &chaosWorker{h: h, id: id, rng: rand.New(rand.NewSource(seed*131 + int64(id)))}
	}
	for id := range 3 {
		w := worker(id)
		spawn(w.userWorker)
	}
	for id := 3; id < 5; id++ {
		w := worker(id)
		spawn(w.sessionWorker)
	}
	w := worker(5)
	spawn(w.keyWorker)
	w = worker(6)
	spawn(w.orgWorker)
	for i := range h.nodes {
		for k := range 2 {
			spawn(func() { h.reader(i, seed*977+int64(i*10+k)) })
		}
	}

	h.runFaults(rand.New(rand.NewSource(seed)), dur)
	h.quiesce()
	h.verify()

	h.smu.Lock()
	lines := make([]string, 0, len(h.stats))
	for k, v := range h.stats {
		lines = append(lines, fmt.Sprintf("  %-62s %d", k, v))
	}
	h.smu.Unlock()
	sort.Strings(lines)
	h.smu.Lock()
	t.Logf("stale answers served within the grace window after contact with an owner was regained: %d (strict: %v)", h.graceCount, h.strictGrace)
	for _, ex := range h.graceExamples {
		t.Logf("  e.g. %s", ex)
	}
	t.Logf("stalest answer served: %v (the bound is %v): %s", h.maxStale.Round(time.Millisecond), h.bound, h.maxStaleWhat)
	h.smu.Unlock()
	for _, nd := range h.nodes {
		lines = append(lines, fmt.Sprintf("  node %d unconfirmed injection: %d landed, %d not made", nd.idx, nd.cs.landed.Load(), nd.cs.notMade.Load()))
	}
	counts := map[string]int{}
	for _, line := range h.hist {
		f := strings.Fields(line)
		if len(f) < 2 || f[1] == "undo:" || f[0] == "" {
			continue
		}
		k := f[1]
		if k == "restart" && strings.Contains(line, "disk lost") {
			k = "restart (disk lost)"
		}
		counts[k]++
	}
	var fl []string
	for k, v := range counts {
		fl = append(fl, fmt.Sprintf("%s %d", k, v))
	}
	sort.Strings(fl)
	var full, failed, cutImp int64
	fs.mu.Lock()
	for _, f := range fs.byDir {
		full, failed, cutImp = full+f.fullImports.Load(), failed+f.failedImports.Load(), cutImp+f.cutImports.Load()
	}
	fs.mu.Unlock()
	t.Logf("faults: %s; full imports started %d, imports failed by failImport %d, full imports cut after their reset %d",
		strings.Join(fl, ", "), full, failed, cutImp)
	t.Logf("workload and read outcomes:\n%s", strings.Join(lines, "\n"))
	for _, tn := range h.c.nodes {
		h.nodeStatus(tn)
	}
	h.vmu.Lock()
	defer h.vmu.Unlock()
	if len(h.viol) > 0 {
		t.Logf("fault history (seed %d):\n%s", seed, strings.Join(h.hist, "\n"))
		for _, v := range h.viol {
			t.Errorf("VIOLATION (seed %d, backend %s): %s", seed, b.name, v)
		}
	}
	for _, nd := range h.nodes {
		nd.svc.WaitBackground()
	}
}

func (h *chaosHarness) nodeStatus(tn *tnode) {
	st := tn.n.Status()
	h.t.Logf("node %d: ready %v, partitions unreadable %d, diverged %d, divergences %d", tn.idx, st.Ready, st.PartitionsUnreadable,
		st.PartitionsDiverged, st.Divergences)
}

// The soak's judges, on hand-made histories: they accept what the protocol allows and name what it must never do.
func TestChaosJudges(t *testing.T) {
	base := time.Now().Add(-time.Minute)
	at := func(s float64) time.Time { return base.Add(time.Duration(s * float64(time.Second))) }
	ack := func(state int, from, to float64) chaosOp {
		return chaosOp{state: state, out: outAck, start: at(from), end: at(to)}
	}
	unk := func(state int, from, to float64) chaosOp {
		return chaosOp{state: state, out: outUnknown, start: at(from), end: at(to)}
	}
	ref := func(state int, from, to float64) chaosOp {
		return chaosOp{state: state, out: outRefused, start: at(from), end: at(to)}
	}
	del := func(o chaosOp) chaosOp { o.state, o.del = chaosDeleted, true; return o }
	live := func(s int) chaosObs { return chaosObs{state: s} }
	gone := chaosObs{absent: true}
	bound := time.Second

	reads := []struct {
		name   string
		ops    []chaosOp
		obs    chaosObs
		t0     float64
		strict bool
		bad    bool
	}{
		{"current", []chaosOp{ack(1, 0, 1), ack(2, 2, 3)}, live(2), 10, false, false},
		{"stale within the bound", []chaosOp{ack(1, 0, 1), ack(2, 2, 3)}, live(1), 3.5, false, false},
		{"stale past the bound", []chaosOp{ack(1, 0, 1), ack(2, 2, 3)}, live(1), 4.5, false, true},
		{"a later state in flight", []chaosOp{ack(1, 0, 1), {state: 2, start: at(2)}}, live(2), 10, false, false},
		{"state of a refused write", []chaosOp{ack(1, 0, 1), ref(2, 2, 3)}, live(2), 10, false, true},
		{"state of an unknown write", []chaosOp{ack(1, 0, 1), unk(2, 2, 3)}, live(2), 10, false, false},
		{"deleted and served", []chaosOp{ack(1, 0, 1), del(ack(0, 2, 3))}, live(1), 10, false, true},
		{"deleted and served within the bound", []chaosOp{ack(1, 0, 1), del(ack(0, 2, 3))}, live(1), 3.5, false, false},
		{"deleted and absent", []chaosOp{ack(1, 0, 1), del(ack(0, 2, 3))}, gone, 10, true, false},
		{"missing in a listing", []chaosOp{ack(1, 0, 1)}, gone, 10, true, true},
		{"missing in a listing within the bound", []chaosOp{ack(1, 0, 1)}, gone, 1.5, true, false},
		{"missing, not strict", []chaosOp{ack(1, 0, 1)}, gone, 10, false, false},
		{"missing while a deletion is unknown", []chaosOp{ack(1, 0, 1), del(unk(0, 2, 3))}, gone, 10, true, false},
		{"missing though the deletion was refused", []chaosOp{ack(1, 0, 1), del(ref(0, 2, 3))}, gone, 10, true, true},
		{"torn", []chaosOp{ack(1, 0, 1)}, chaosObs{state: 1, torn: true}, 10, false, true},
		{"a state never written", []chaosOp{ack(1, 0, 1)}, live(7), 10, false, true},
	}
	for _, c := range reads {
		if msg, _ := judgeRead(c.ops, time.Time{}, c.obs, at(c.t0), at(c.t0), bound, c.strict); (msg != "") != c.bad {
			t.Errorf("read %q: %q, want bad=%v", c.name, msg, c.bad)
		}
	}
	finals := []struct {
		name string
		ops  []chaosOp
		obs  chaosObs
		bad  bool
	}{
		{"latest acknowledged", []chaosOp{ack(1, 0, 1), ack(2, 2, 3)}, live(2), false},
		{"an acknowledged write lost", []chaosOp{ack(1, 0, 1), ack(2, 2, 3)}, live(1), true},
		{"absent though acknowledged", []chaosOp{ack(1, 0, 1)}, gone, true},
		{"an unknown write after it landed", []chaosOp{ack(1, 0, 1), unk(2, 2, 3)}, live(2), false},
		{"an unknown write after it did not land", []chaosOp{ack(1, 0, 1), unk(2, 2, 3)}, live(1), false},
		{"an unknown write before the acknowledged one", []chaosOp{unk(1, 0, 1), ack(2, 2, 3)}, live(1), true},
		{"a refused write appeared", []chaosOp{ack(1, 0, 1), ref(2, 2, 3)}, live(2), true},
		{"deleted", []chaosOp{ack(1, 0, 1), del(ack(0, 2, 3))}, gone, false},
		{"deleted and back", []chaosOp{ack(1, 0, 1), del(ack(0, 2, 3))}, live(1), true},
		{"an unknown deletion landed", []chaosOp{ack(1, 0, 1), del(unk(0, 2, 3))}, gone, false},
		{"an unknown deletion did not", []chaosOp{ack(1, 0, 1), del(unk(0, 2, 3))}, live(1), false},
		{"nothing acknowledged, an unknown creation landed", []chaosOp{unk(1, 0, 1)}, live(1), false},
		{"nothing acknowledged, nothing held", []chaosOp{unk(1, 0, 1)}, gone, false},
		{"nothing acknowledged, a refused creation held", []chaosOp{ref(1, 0, 1)}, live(1), true},
		{"older version of the acknowledged state", []chaosOp{{state: 1, out: outAck, version: 50, start: at(0), end: at(1)}},
			chaosObs{state: 1, version: 40}, true},
	}
	for _, c := range finals {
		if msg := judgeFinal(c.ops, time.Time{}, c.obs, time.Now()); (msg != "") != c.bad {
			t.Errorf("final %q: %q, want bad=%v", c.name, msg, c.bad)
		}
	}
	// an expired record may be hidden from a deletion, and absent
	exp := at(2.5)
	if msg := judgeFinal([]chaosOp{ack(1, 0, 1), del(ack(0, 2, 3))}, exp, live(1), time.Now()); msg != "" {
		t.Errorf("a deletion acknowledged after the record's expiry changed nothing: %q", msg)
	}
	if msg := judgeFinal([]chaosOp{ack(1, 0, 1)}, exp, gone, time.Now()); msg != "" {
		t.Errorf("an expired record may be absent: %q", msg)
	}
}

// ---- regressions of what the soak found ----

// A node that regains contact with its owner while behind (cut off, or restarted far behind) must not serve its old copy
// for a fresh StaleAfter window: the library counts the lag from when it hears the owner's position, not from when the
// owner committed it, so Node.readable refuses a copy that is behind the owner's reported position (found by
// TestChaosSoak: a signing key deleted seconds before was listed again).
func TestChaosNoStaleServingAfterContactRegained(t *testing.T) {
	var fs faults
	c := newTCluster(t, 3, fs.over(badgerBackend()))
	c.startAll()
	c.waitReady()
	c.waitSettled()
	owner := c.ownerOf(globalPartition)
	follower := (owner + 1) % 3
	other := 3 - owner - follower
	keys := func(tn *tnode) *store.Table[model.SigningKey, *model.SigningKey] {
		return store.NewTable[model.SigningKey](tn.st())
	}
	k := &model.SigningKey{Meta: model.Meta{ID: "k-" + model.NewID()}, Alg: "ES256", PublicJWK: []byte("n1")}
	if err := keys(c.nodes[owner]).Create(bg, k); err != nil {
		t.Fatal(err)
	}
	listed := func(tn *tnode) (bool, error) {
		ks, _, err := keys(tn).List(bg, store.ListQuery{Limit: 100})
		for _, x := range ks {
			if x.ID == k.ID {
				return true, err
			}
		}
		return false, err
	}
	waitFor(t, 10*time.Second, "the key listed everywhere", func() bool {
		for _, tn := range c.nodes {
			if ok, err := listed(tn); err != nil || !ok {
				return false
			}
		}
		return true
	})
	// the follower is cut off, and refuses to list (it has not heard its owner for StaleAfter)
	c.partition([]int{owner, other}, []int{follower})
	waitFor(t, 10*time.Second, "the cut-off follower to refuse listing", func() bool {
		_, err := listed(c.nodes[follower])
		return errors.Is(err, store.ErrUnavailable)
	})
	if err := keys(c.nodes[owner]).Delete(bg, k.ID); err != nil {
		t.Fatal(err)
	}
	acked := time.Now()
	staleAfter := time.Duration(c.nodes[follower].n.staleAfter.Load())
	time.Sleep(3 * staleAfter) // the deletion is long past the bound
	// contact is regained while the follower cannot catch up at once (a large partition, a slow disk: here a catch-up
	// that fails)
	fs.of(c.nodes[follower]).failImport.Store(int64(globalPartition) + 1)
	defer fs.of(c.nodes[follower]).failImport.Store(0)
	c.heal()
	var servedAt time.Duration
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ok, err := listed(c.nodes[follower])
		if err == nil && ok && servedAt == 0 {
			servedAt = time.Since(acked)
		}
		if servedAt > 0 && err != nil {
			break // refused again: the window ended
		}
		time.Sleep(time.Millisecond)
	}
	if servedAt > 0 {
		t.Fatalf("the follower listed a key deleted %v before (StaleAfter %v): its first answers after regaining contact were its old copy",
			servedAt.Round(time.Millisecond), staleAfter)
	}
}

// A node that misses the write that purges a partition's old tombstones, and catches up incrementally (it is not below the
// purge point), must purge them too: the catch-up stream carries the source's purge point and Import applies it (found by
// TestChaosSoak: the node kept the tombstones the others removed, for good).
func TestChaosPurgeReachesANodeThatMissedIt(t *testing.T) {
	var fs faults
	c := newTCluster(t, 3, fs.over(badgerBackend()))
	c.opts = shortRetention
	c.startAll()
	c.waitReady()
	org := c.orgOwnedBy(0)
	p := partitionNum(org)
	ids := writeN(t, c.nodes[0], org, 6)
	c.waitHas(ids[5])
	tombstone := func(id string) {
		t.Helper()
		if err := c.nodes[0].st().Put(bg, store.Tombstone(dataKind, id)); err != nil {
			t.Fatal(err)
		}
		waitFor(t, 15*time.Second, "the tombstone everywhere", func() bool {
			for _, tn := range c.nodes {
				if !tombstoned(tn, id) {
					return false
				}
			}
			return true
		})
	}
	tombstone(ids[0])
	past := time.Now().Add(tombstoneKeep(testRetention)) // at which time the first tombstone is past the retention
	tombstone(ids[1])                                    // and this one is not: the purge point is its sequence, which node 1 has reached
	waitFor(t, 15*time.Second, "every node at the same position", func() bool { return committedEqual(c.nodes) })

	// node 1 misses the purge write itself
	c.lagBehind(1, true)
	purgeAll(c, past)
	waitFor(t, 15*time.Second, "the old tombstone purged on the nodes that saw the purge", func() bool {
		return gone(c.nodes[0], ids[0]) && gone(c.nodes[2], ids[0])
	})
	if !tombstoned(c.nodes[1], ids[0]) {
		t.Fatal("test set-up: node 1 must have missed the purge")
	}
	c.lagBehind(1, false)
	waitFor(t, 20*time.Second, "node 1 at the position of the others", func() bool { return committedEqual(c.nodes) })
	time.Sleep(time.Second)
	if !gone(c.nodes[1], ids[0]) {
		st, _ := c.nodes[1].n.pst.pst.PartitionState(bg, p)
		t.Fatalf("node 1 caught up past the purge (position %d, purge point %d) and still holds the tombstone the others purged",
			st.Committed.Seq, st.Purged)
	}
}

// A node that copies a partition whole (it was behind the purge point) takes the purge point of the nodes that applied
// the purge, never its copy's position: at the same position every node holds the same tombstones. Found by
// TestChaosSoak: a full copy raised its purge point to the position it copied, keeping its source's tombstones below
// it; the node then purged them at its next start (which finishes a purge a crash cut short), and a node that caught up
// from it purged to that position too, while the third kept them, for good.
func TestChaosFullCopyTakesThePurgePoint(t *testing.T) {
	eachLocalBackend(t, func(t *testing.T, b backend) {
		var fs faults
		c := newTCluster(t, 3, fs.over(b))
		c.opts = shortRetention
		c.startAll()
		c.waitReady()
		org := c.orgOwnedBy(0)
		p := partitionNum(org)
		ids := writeN(t, c.nodes[0], org, 6)
		c.waitHas(ids[5])

		// node 1 misses the deletions and the purge, so it falls below the purge point and copies the partition whole
		c.lagBehind(1, true)
		tombstone := func(id string) {
			t.Helper()
			if err := c.nodes[0].st().Put(bg, store.Tombstone(dataKind, id)); err != nil {
				t.Fatal(err)
			}
			waitFor(t, 15*time.Second, "the tombstone on nodes 0 and 2", func() bool {
				return tombstoned(c.nodes[0], id) && tombstoned(c.nodes[2], id)
			})
		}
		tombstone(ids[0])
		past := time.Now().Add(tombstoneKeep(testRetention)) // at which time the first tombstone is past the retention
		tombstone(ids[1])                                    // and this one is not: the copy brings it, and every node keeps it
		purgeAll(c, past)
		waitFor(t, 15*time.Second, "the old tombstone purged on nodes 0 and 2", func() bool {
			return gone(c.nodes[0], ids[0]) && gone(c.nodes[2], ids[0])
		})
		c.lagBehind(1, false)
		waitFor(t, 20*time.Second, "node 1 at the position of the others", func() bool { return committedEqual(c.nodes) })
		if fs.of(c.nodes[1]).fullImports.Load() == 0 {
			t.Fatal("test set-up: node 1 must have copied the partition whole")
		}

		same := func(when string) {
			t.Helper()
			want, _ := c.nodes[0].n.pst.pst.PartitionState(bg, p)
			for i, tn := range c.nodes {
				st, _ := tn.n.pst.pst.PartitionState(bg, p)
				if st.Purged != want.Purged {
					t.Fatalf("%s: node %d's purge point is %d, node 0's %d (position %d)", when, i, st.Purged, want.Purged,
						st.Committed.Seq)
				}
				if !gone(tn, ids[0]) || !tombstoned(tn, ids[1]) {
					t.Fatalf("%s: node %d holds the purged tombstone (%v) or lacks the young one (%v)", when, i,
						!gone(tn, ids[0]), !tombstoned(tn, ids[1]))
				}
			}
		}
		same("after the copy")
		c.restart(1) // its start finishes any purge a crash cut short: there is none
		c.waitReady()
		same("after node 1 restarted")
	})
}
