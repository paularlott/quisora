package cluster

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/codec/shamaton"
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// covPacket is a packet carrying v, as a peer's request would arrive at a handler.
func covPacket(t testing.TB, v any) *gossip.Packet {
	t.Helper()
	c := shamaton.New()
	b, err := c.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	p := gossip.NewPacket()
	p.SetCodec(c)
	p.SetPayload(b)
	t.Cleanup(p.Release)
	return p
}

// covBad is a packet whose payload cannot be read as the struct a handler expects.
func covBad(t testing.TB) *gossip.Packet { return covPacket(t, "not a struct") }

// covStore fails the calls its fields name.
type covStore struct {
	store.Store
	lookup, put, list, purge, putRepl, get, cas, changes error
	gets                                                 atomic.Int64
	getHook                                              func(*store.Record, error) (*store.Record, error)
}

func (s *covStore) Get(ctx context.Context, k model.Kind, id string) (*store.Record, error) {
	s.gets.Add(1)
	if s.get != nil {
		return nil, s.get
	}
	r, err := s.Store.Get(ctx, k, id)
	if s.getHook != nil {
		return s.getHook(r, err)
	}
	return r, err
}

func (s *covStore) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if s.cas != nil {
		return s.cas
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

func (s *covStore) Lookup(ctx context.Context, k model.Kind, id string) (*store.Record, error) {
	if s.lookup != nil {
		return nil, s.lookup
	}
	return s.Store.Lookup(ctx, k, id)
}

func (s *covStore) Put(ctx context.Context, r *store.Record) error {
	if s.put != nil {
		return s.put
	}
	return s.Store.Put(ctx, r)
}

func (s *covStore) List(ctx context.Context, k model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if s.list != nil {
		return nil, s.list
	}
	return s.Store.List(ctx, k, q)
}

func (s *covStore) Purge(ctx context.Context, a, b time.Time) (int, error) {
	if s.purge != nil {
		return 0, s.purge
	}
	return s.Store.Purge(ctx, a, b)
}

func (s *covStore) PutReplicated(ctx context.Context, r *store.Record) (bool, []string, error) {
	if s.putRepl != nil {
		return false, nil, s.putRepl
	}
	return s.Store.PutReplicated(ctx, r)
}

// hnode is a standalone node over a failing store, with the quorum voter a gossip node has, so the handlers can be
// called directly.
func hnode(t *testing.T) (*Node, *covStore) {
	t.Helper()
	cs := &covStore{Store: memstore.New()}
	n, err := New(tempConfig(t), cs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	n.voter = newVoter(n)
	return n, cs
}

func covRec(kind model.Kind, id string, version hlc.Timestamp) *store.Record {
	return &store.Record{Kind: kind, ID: id, Version: version, Epoch: 0, Created: version, Scope: "org1", Data: []byte("d")}
}

func covEncode(t testing.TB, r *store.Record) []byte {
	t.Helper()
	b, err := encodeRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVoterPrepareAnswers(t *testing.T) {
	n, cs := hnode(t)
	v := n.voter
	now := store.Clock.Now()
	next := func() hlc.Timestamp { return store.Clock.Now() }

	// Busy: another write holds an intent on the record.
	r1 := covRec(model.KindUser, "busy", next())
	if got := v.prepare(bg, "op1", r1, modeMatch, store.Rank{}); got.St != stGrant {
		t.Fatalf("first: %d", got.St)
	}
	r2 := covRec(model.KindUser, "busy", next())
	if got := v.prepare(bg, "op2", r2, modeMatch, store.Rank{}); got.St != stBusy {
		t.Fatalf("second writer: %d", got.St)
	}
	// ...but its own retry supersedes its own intent.
	r1b := covRec(model.KindUser, "busy", next())
	if got := v.prepare(bg, "op1", r1b, modeMatch, store.Rank{}); got.St != stGrant {
		t.Fatalf("a retry: %d", got.St)
	}

	// Low: a version at or below the floor.
	low := covRec(model.KindUser, "low", 5)
	if got := v.prepare(bg, "op", low, modeMatch, store.Rank{}); got.St != stLow || got.Floor == 0 {
		t.Fatalf("low: %+v", got)
	}

	// Deleted: a live write onto a deletion of a later generation than the writer saw.
	tomb := store.Tombstone(model.KindUser, "gone")
	tomb.Version = next()
	if _, _, err := cs.Store.PutReplicated(bg, tomb); err != nil {
		t.Fatal(err)
	}
	live := covRec(model.KindUser, "gone", next())
	got := v.prepare(bg, "op", live, modeMatch, store.Rank{})
	if got.St != stDeleted || len(got.Cur) == 0 {
		t.Fatalf("deleted: %+v", got)
	}
	// A blind (deleting) write onto it is not refused for that.
	del := store.Tombstone(model.KindUser, "gone")
	del.Version = next()
	if got := v.prepare(bg, "op3", del, modeBlind, store.Rank{}); got.St != stGrant {
		t.Fatalf("a deletion over a deletion: %d", got.St)
	}

	// Stale: an older generation than the one held, and a base older than the copy held.
	held := covRec(model.KindUser, "held", next())
	held.Epoch = held.Version - 1
	if _, _, err := cs.Store.PutReplicated(bg, held); err != nil {
		t.Fatal(err)
	}
	older := covRec(model.KindUser, "held", next())
	older.Epoch = held.Epoch - 5
	if got := v.prepare(bg, "op", older, modeMatch, store.Rank{}); got.St != stStale || len(got.Cur) == 0 {
		t.Fatalf("older generation: %+v", got)
	}
	based := covRec(model.KindUser, "held", next())
	based.Epoch = held.Epoch
	if got := v.prepare(bg, "op", based, modeMatch, store.Rank{Version: held.Version - 1}); got.St != stStale {
		t.Fatalf("older base: %d", got.St)
	}
	if got := v.prepare(bg, "opB", based, modeBlind, store.Rank{Version: 1}); got.St != stGrant {
		t.Fatalf("a blind write has no base: %d", got.St)
	}

	// An expired intent no longer blocks.
	v.mu.Lock()
	v.intents[recKey(model.KindUser, "busy")].exp = time.Now().Add(-time.Second)
	v.mu.Unlock()
	if got := v.prepare(bg, "op2", covRec(model.KindUser, "busy", next()), modeMatch, store.Rank{}); got.St != stGrant {
		t.Fatalf("after the intent expired: %d", got.St)
	}

	// A store that cannot be read fails the vote; a version far ahead of the clock is refused.
	cs.lookup = errors.New("disk")
	if got := v.prepare(bg, "op", covRec(model.KindUser, "x", next()), modeMatch, store.Rank{}); got.St != stFailed {
		t.Fatalf("lookup error: %d", got.St)
	}
	cs.lookup = nil
	if got := v.prepare(bg, "op", covRec(model.KindUser, "x", hlc.FromTime(time.Now().Add(time.Hour))), modeMatch, store.Rank{}); got.St != stFailed {
		t.Fatalf("far ahead: %d", got.St)
	}
	_ = now
}

func TestVoterCommit(t *testing.T) {
	n, cs := hnode(t)
	v := n.voter
	rec := covRec(model.KindUser, "c1", store.Clock.Now())
	if st := v.commit(bg, "op", rec, true); st != stFailed {
		t.Fatalf("commit without an intent: %d", st)
	}
	if got := v.prepare(bg, "op", rec, modeMatch, store.Rank{}); got.St != stGrant {
		t.Fatal("prepare")
	}
	if st := v.commit(bg, "other-op", rec, true); st != stFailed {
		t.Fatalf("commit of another write: %d", st)
	}
	if st := v.commit(bg, "op", rec, true); st != stGrant {
		t.Fatalf("commit: %d", st)
	}
	if st := v.commit(bg, "op", rec, true); st != stFailed {
		t.Fatalf("the intent is released: %d", st)
	}

	// An intent that expired before the commit is not honoured.
	r2 := covRec(model.KindUser, "c2", store.Clock.Now())
	v.prepare(bg, "op", r2, modeMatch, store.Rank{})
	v.mu.Lock()
	v.intents[recKey(model.KindUser, "c2")].exp = time.Now().Add(-time.Second)
	v.mu.Unlock()
	if st := v.commit(bg, "op", r2, true); st != stFailed {
		t.Fatalf("expired: %d", st)
	}

	// The store fails the apply.
	r3 := covRec(model.KindUser, "c3", store.Clock.Now())
	v.prepare(bg, "op", r3, modeMatch, store.Rank{})
	cs.putRepl = errors.New("disk full")
	if st := v.commit(bg, "op", r3, false); st != stFailed {
		t.Fatalf("apply error: %d", st)
	}
	cs.putRepl = nil

	// The store holds something newer: not applied, and not what the writer meant to write.
	newer := covRec(model.KindUser, "c4", store.Clock.Now())
	if _, _, err := cs.Store.PutReplicated(bg, newer); err != nil {
		t.Fatal(err)
	}
	old := covRec(model.KindUser, "c4", newer.Version-1000)
	v.mu.Lock()
	v.intents[recKey(model.KindUser, "c4")] = &intent{op: "op", version: old.Version, exp: time.Now().Add(time.Minute)}
	v.mu.Unlock()
	if st := v.commit(bg, "op", old, false); st != stFailed {
		t.Fatalf("a commit under a newer copy: %d", st)
	}
}

func TestVoterRelease(t *testing.T) {
	n, _ := hnode(t)
	v := n.voter
	rec := covRec(model.KindUser, "r1", store.Clock.Now())
	v.prepare(bg, "op", rec, modeMatch, store.Rank{})
	v.release("op", rec.Version+1) // an earlier attempt's abort arriving late: the intent of this one stays
	if len(v.intents) != 1 {
		t.Fatal("a release of another stamp dropped the intent")
	}
	v.release("op", rec.Version)
	if len(v.intents) != 0 {
		t.Fatal("the abort did not release the intent")
	}
}

func TestPrepareCommitAbortHandlers(t *testing.T) {
	n, _ := hnode(t)
	if _, err := n.handlePrepare(nil, covBad(t)); err == nil {
		t.Error("prepare: a bad payload was accepted")
	}
	if r, err := n.handlePrepare(nil, covPacket(t, &prepareReq{Op: "o", Rec: []byte("junk")})); err != nil || r.(*prepareResp).St != stFailed {
		t.Errorf("prepare: undecodable record: %v %v", r, err)
	}
	notQuorum := covRec(dataKind, "x", store.Clock.Now())
	if model.QuorumCAS(dataKind) {
		t.Fatal("test set-up: dataKind is a quorum kind")
	}
	if r, _ := n.handlePrepare(nil, covPacket(t, &prepareReq{Op: "o", Rec: covEncode(t, notQuorum), Mode: modeMatch})); r.(*prepareResp).St != stFailed {
		t.Errorf("prepare: a kind that is not written by quorum: %v", r)
	}
	rec := covRec(model.KindUser, "h1", store.Clock.Now())
	r, err := n.handlePrepare(nil, covPacket(t, &prepareReq{Op: "o", Rec: covEncode(t, rec), Mode: modeMatch}))
	if err != nil || r.(*prepareResp).St != stGrant {
		t.Fatalf("prepare: %v %v", r, err)
	}

	if _, err := n.handleCommit(nil, covBad(t)); err == nil {
		t.Error("commit: a bad payload was accepted")
	}
	if r, _ := n.handleCommit(nil, covPacket(t, &commitReq{Op: "o", Rec: []byte("junk")})); r.(*commitResp).St != stFailed {
		t.Errorf("commit: undecodable record: %v", r)
	}
	if r, _ := n.handleCommit(nil, covPacket(t, &commitReq{Op: "o", Rec: covEncode(t, rec)})); r.(*commitResp).St != stGrant {
		t.Errorf("commit: %v", r)
	}

	if err := n.handleAbort(nil, covBad(t)); err == nil {
		t.Error("abort: a bad payload was accepted")
	}
	if err := n.handleAbort(nil, covPacket(t, &abortReq{Op: "o", Version: uint64(rec.Version)})); err != nil {
		t.Error(err)
	}
}

func TestHandleReadStream(t *testing.T) {
	n, cs := hnode(t)
	a := covRec(model.KindUser, "a", store.Clock.Now())
	tomb := store.Tombstone(model.KindUser, "b")
	other := covRec(model.KindGroup, "g", store.Clock.Now())
	for _, r := range []*store.Record{a, tomb, other} {
		if _, _, err := cs.Store.PutReplicated(bg, r); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	req := &readReq{Kind: string(model.KindUser), IDs: []string{"a", "missing", "b", "g"}}
	if err := n.handleRead(covPacket(t, req), &buf); err != nil {
		t.Fatal(err)
	}
	var got []*store.Record
	for {
		b, err := readFrame(&buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		r, err := decodeRecord(b)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	// The record, and the tombstone (a deletion is an answer); not the missing id, not another kind's record.
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "b" || !got[1].Deleted {
		t.Fatalf("answered %+v", got)
	}

	if err := n.handleRead(covBad(t), io.Discard); err == nil {
		t.Error("a bad payload was accepted")
	}
	tooMany := make([]string, readBatch+1)
	if err := n.handleRead(covPacket(t, &readReq{Kind: "user", IDs: tooMany}), io.Discard); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("over the batch size: %v", err)
	}
	cs.lookup = errors.New("disk")
	if err := n.handleRead(covPacket(t, req), io.Discard); err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Errorf("unreadable copy: %v", err)
	}
	cs.lookup = nil
	if err := n.handleRead(covPacket(t, req), &covFailWriter{failAt: 1}); err == nil {
		t.Error("a failing stream was not reported")
	}
	n.catchingUp.Store(true)
	if err := n.handleRead(covPacket(t, req), io.Discard); !errors.Is(err, errNotVoting) {
		t.Errorf("a node that does not vote: %v", err)
	}
}

func TestHandleEphOperations(t *testing.T) {
	n, _ := hnode(t)
	call := func(req ephReq) *ephResp {
		t.Helper()
		r, err := n.handleEph(nil, covPacket(t, &req))
		if err != nil {
			t.Fatal(err)
		}
		return r.(*ephResp)
	}
	id, err := n.eph.local.New(bg, "ns", []byte("v0"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if r := call(ephReq{Op: opSet, NS: "ns", ID: id, Val: []byte("v1"), TTL: 60000}); r.Code != codeOK {
		t.Fatalf("set: %+v", r)
	}
	if r := call(ephReq{Op: opGet, NS: "ns", ID: id}); r.Code != codeOK || string(r.Val) != "v1" {
		t.Fatalf("get: %+v", r)
	}
	if r := call(ephReq{Op: opIncr, NS: "rl", ID: "k", Delta: 3, TTL: 60000}); r.Code != codeOK || r.N != 3 {
		t.Fatalf("incr: %+v", r)
	}
	if r := call(ephReq{Op: opTake, NS: "ns", ID: id}); r.Code != codeOK || string(r.Val) != "v1" {
		t.Fatalf("take: %+v", r)
	}
	if r := call(ephReq{Op: opTake, NS: "ns", ID: id}); r.Code != codeNotFound {
		t.Fatalf("take again: %+v", r)
	}
	if r := call(ephReq{Op: opGet, NS: "ns", ID: "missing"}); r.Code != codeNotFound {
		t.Fatalf("get missing: %+v", r)
	}
	if r := call(ephReq{Op: opSet, NS: "ns", ID: id, Val: []byte("again"), TTL: 60000}); r.Code != codeOK {
		t.Fatalf("set: %+v", r)
	}
	if r := call(ephReq{Op: opDelete, NS: "ns", ID: id}); r.Code != codeOK {
		t.Fatalf("delete: %+v", r)
	}
	if r := call(ephReq{Op: 99, NS: "ns", ID: id}); r.Code != codeError || !strings.Contains(r.Err, "unknown ephemeral op") {
		t.Fatalf("unknown op: %+v", r)
	}
	if r := call(ephReq{Op: opSet, NS: "", ID: id, Val: []byte("x"), TTL: 1}); r.Code == codeOK {
		t.Logf("set without a namespace is accepted: %+v", r)
	}
	if _, err := n.handleEph(nil, covBad(t)); err == nil {
		t.Error("a bad payload was accepted")
	}
	// A node that does not serve answers for no hash-routed state (a counter, an id without an owner prefix).
	why := "misconfigured"
	n.mixed.Store(&why)
	if r := call(ephReq{Op: opIncr, NS: "rl", ID: "k", Delta: 1, TTL: 60000}); r.Code != codeError || !strings.Contains(r.Err, "does not serve") {
		t.Fatalf("incr on a node that does not serve: %+v", r)
	}
	if r := call(ephReq{Op: opGet, NS: "ns", ID: "no-owner-prefix"}); r.Code != codeError {
		t.Fatalf("get of a hash-routed id on a node that does not serve: %+v", r)
	}
	if r := call(ephReq{Op: opGet, NS: "ns", ID: ephemeral.Owner(id) + "." + "zzz"}); r.Code == codeError && strings.Contains(r.Err, "does not serve") {
		t.Fatalf("an id this node owns is answered whatever its readiness: %+v", r)
	}
}

func TestHandleAuditAndAuditQueryStandalone(t *testing.T) {
	n, cs := hnode(t)
	for i, act := range []string{"user.create", "user.update"} {
		r := covRec(model.KindAudit, newID(), store.Clock.Now())
		r.Fields = map[string]any{"action": act, "created": time.Now().UTC().Add(time.Duration(i) * time.Second).Truncate(time.Microsecond),
			"actor": "a"}
		if err := cs.Store.Put(bg, r); err != nil {
			t.Fatal(err)
		}
	}
	r, err := n.handleAudit(nil, covPacket(t, &auditReq{Limit: 10}))
	if err != nil {
		t.Fatal(err)
	}
	resp := r.(*auditResp)
	if !resp.Filtered || resp.Total != 2 || len(resp.Recs) != 2 {
		t.Fatalf("%+v", resp)
	}
	if _, err := n.handleAudit(nil, covBad(t)); err == nil {
		t.Error("a bad payload was accepted")
	}
	recs, total, nodes, answered, err := n.AuditQuery(bg, store.ListQuery{Limit: 10})
	if err != nil || len(recs) != 2 || total != 2 || nodes != 1 || answered != 1 {
		t.Fatalf("standalone query: %d %d %d %d %v", len(recs), total, nodes, answered, err)
	}
	cs.list = errors.New("disk")
	if _, err := n.handleAudit(nil, covPacket(t, &auditReq{Limit: 10})); err == nil {
		t.Error("a store error was not reported")
	}
	if _, _, _, _, err := n.AuditQuery(bg, store.ListQuery{Limit: 10}); err == nil {
		t.Error("a store error was not reported by the query")
	}
}

func TestHandleNotice(t *testing.T) {
	n, _ := hnode(t)
	var got []*store.Record
	n.OnChange(func(r *store.Record, local bool) {
		if local {
			t.Error("a notice is not a local change")
		}
		got = append(got, r)
	})
	n.OnChange(func(*store.Record, bool) {}) // a second hook: both are kept
	if err := n.handleNotice(nil, covBad(t)); err == nil {
		t.Error("a bad payload was accepted")
	}
	for _, m := range []noticeMsg{{}, {K: "user"}, {I: "x"}} {
		if err := n.handleNotice(nil, covPacket(t, &m)); err != nil {
			t.Error(err)
		}
	}
	if len(got) != 0 {
		t.Fatalf("an incomplete notice ran the hooks: %v", got)
	}
	if err := n.handleNotice(nil, covPacket(t, &noticeMsg{K: "user", I: "u1", S: "org", D: true})); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kind != model.KindUser || got[0].ID != "u1" || got[0].Scope != "org" || !got[0].Deleted {
		t.Fatalf("%+v", got)
	}
	n.notice(got[0]) // no notice gossip: nothing to send
	if noticeWorthy(model.KindEphemeral) || noticeWorthy(model.KindLock) || !noticeWorthy(model.KindUser) {
		t.Error("noticeWorthy")
	}
}

func TestHandleReloadAndReloadStandalone(t *testing.T) {
	n, _ := hnode(t)
	if r := n.Reload(bg); r.Error == "" || r.Node != n.ID() {
		t.Fatalf("without a reloader: %+v", r)
	}
	if _, err := n.handleReload(nil, covBad(t)); err == nil {
		t.Error("a bad payload was accepted")
	}
	var calls atomic.Int32
	var lastApply atomic.Bool
	fail := ""
	n.SetReloader(func(_ context.Context, apply bool, want int) ReloadReport {
		calls.Add(1)
		lastApply.Store(apply)
		return ReloadReport{Size: want, Error: fail, Changes: []string{"x"}}
	})
	r, err := n.handleReload(nil, covPacket(t, &reloadReq{Apply: true, Want: 3}))
	if err != nil {
		t.Fatal(err)
	}
	if rep := r.(*ReloadReport); rep.Size != 3 || rep.Node != n.ID() || !lastApply.Load() {
		t.Fatalf("%+v", rep)
	}
	if reps, err := n.ReloadCluster(bg); err != nil || len(reps) != 1 || reps[0].Node != n.ID() {
		t.Fatalf("standalone reload: %v %v", reps, err)
	}
	fail = "bad config"
	if reps, err := n.ReloadCluster(bg); err == nil || !strings.Contains(err.Error(), "bad config") || len(reps) != 1 {
		t.Fatalf("a failing reload: %v %v", reps, err)
	}
}

func TestReloadClusterSharedDatabaseWithoutNotify(t *testing.T) {
	cfg := tempConfig(t)
	cfg.Storage.Backend = "postgres" // shared, not opened: the store is given
	n, err := New(cfg, memstore.New(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	n.SetReloader(func(context.Context, bool, int) ReloadReport { return ReloadReport{} })
	if reps, err := n.ReloadCluster(bg); err == nil || !strings.Contains(err.Error(), "this node only") || len(reps) != 1 {
		t.Fatalf("%v %v", reps, err)
	}
	if n.EphemeralStore() == ephemeral.Store(n.Ephemeral()) {
		t.Error("a node sharing a database keeps ephemeral state in it")
	}
}

func TestCheckResizeAndResizeStandalone(t *testing.T) {
	n, _ := hnode(t)
	if err := n.CheckResize(0, nil); err != nil {
		t.Error(err)
	}
	if err := n.CheckResize(3, nil); err == nil || !strings.Contains(err.Error(), "applies only with cluster.bind") {
		t.Errorf("%v", err)
	}
	if changed, err := n.Resize(0, nil); err != nil || changed {
		t.Errorf("%v %v", changed, err)
	}
	if changed, err := n.Resize(3, nil); err == nil || changed {
		t.Errorf("%v %v", changed, err)
	}
	if sign(-3) != -1 || sign(4) != 1 || sign(0) != 1 {
		t.Error("sign")
	}
	if _, err := n.SetClusterKeys(testKey(), nil); err == nil || !strings.Contains(err.Error(), "not clustering") {
		t.Errorf("%v", err)
	}
	if n.ClusterKeyIDs() != nil {
		t.Error("a standalone node has no cluster keys")
	}
}

func TestNodeAccessors(t *testing.T) {
	n, _ := hnode(t)
	if !n.Standalone() || n.Replicating() != n.cfg.Replicate() {
		t.Error("standalone or replicating")
	}
	if n.Prefix() == "" || n.Prefix() != PrefixOf(n.ID()) {
		t.Errorf("prefix %q", n.Prefix())
	}
	if n.EphemeralStore() != ephemeral.Store(n.Ephemeral()) || n.Ephemeral().Local() == nil {
		t.Error("ephemeral store")
	}
}

func (s *covStore) Changes(ctx context.Context, since uint64, limit int) ([]store.Change, uint64, error) {
	if s.changes != nil {
		return nil, 0, s.changes
	}
	return s.Store.Changes(ctx, since, limit)
}

// covBatchStore is a store that applies a feed page in one go, as the SQL and key-value backends do.
type covBatchStore struct {
	*covStore
	batchErr error
}

func (s *covBatchStore) PutReplicatedBatch(ctx context.Context, recs []*store.Record) ([]bool, [][]string, error) {
	if s.batchErr != nil {
		return nil, nil, s.batchErr
	}
	return s.Store.(store.BatchReplicator).PutReplicatedBatch(ctx, recs)
}
