package kvstore

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// countingWrites counts the keys a write transaction sets, by kind of write: the record and unique keys (Set), the
// ordered-set memberships (SetAdd) and the counters (Add).
type countingWrites struct {
	engine
	sets, members, counters int
}

func (e *countingWrites) Update(ctx context.Context, fn func(tx txn) error) error {
	return e.engine.Update(ctx, func(tx txn) error {
		e.sets, e.members, e.counters = 0, 0, 0 // the transaction may run again: count its last run
		return fn(&countingTxn{txn: tx, e: e})
	})
}

type countingTxn struct {
	txn
	e *countingWrites
}

func (t *countingTxn) Set(key string, val []byte) { t.e.sets++; t.txn.Set(key, val) }
func (t *countingTxn) SetAdd(bucket, member string, expMs int64) {
	t.e.members++
	t.txn.SetAdd(bucket, member, expMs)
}
func (t *countingTxn) Add(key string, delta int64) { t.e.counters++; t.txn.Add(key, delta) }

// A kind whose records always expire (audit events, sessions, grants, links) keeps no counters: a counter of a range
// with an expiring member never answers a total (the engine counts the live members), so each would cost
// read-modify-write keys on every write for nothing. Its totals stay exact, and a kind that may not expire (users)
// keeps its counters.
func TestAlwaysExpiringKindsKeepNoCounters(t *testing.T) {
	ctx := context.Background()
	s := openBadger(t, BadgerOptions{InMemory: true})
	w := &countingWrites{engine: s.eng}
	s.eng = w
	exp := time.Now().Add(time.Hour)
	audits, sessions := store.NewTable[model.Audit](s), store.NewTable[model.Session](s)
	for i := range 5 {
		if err := audits.Put(ctx, &model.Audit{OrgID: "org", Action: "user.create", Actor: "a", Outcome: "success", Expires: exp}); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			t.Logf("audit event: %d keys, %d index members, %d counters", w.sets, w.members, w.counters)
			if w.counters != 0 {
				t.Errorf("an audit event writes %d counters", w.counters)
			}
		}
		if err := sessions.Put(ctx, &model.Session{UserID: "u", OrgID: "org", Expires: exp}); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			t.Logf("session: %d keys, %d index members, %d counters", w.sets, w.members, w.counters)
			if w.counters != 0 {
				t.Errorf("a session writes %d counters", w.counters)
			}
		}
	}
	if n, err := s.Count(ctx, model.KindAudit, "org"); err != nil || n != 5 {
		t.Errorf("audit count %d %v", n, err)
	}
	res, err := s.List(ctx, model.KindAudit, store.ListQuery{Scope: "org", Sort: "created", Desc: true, Limit: 2})
	if err != nil || res.Total != 5 || len(res.Records) != 2 {
		t.Errorf("audit page: %+v %v", res, err)
	}
	if res, err = s.List(ctx, model.KindSession, store.ListQuery{Scope: "u", Limit: 2}); err != nil || res.Total != 5 || len(res.Records) != 2 {
		t.Errorf("session page: %+v %v", res, err)
	}
	if err := store.NewTable[model.User](s).Put(ctx, &model.User{OrgID: "org", Username: "u", Role: model.RoleUser}); err != nil {
		t.Fatal(err)
	}
	if w.counters == 0 {
		t.Error("a user keeps no counters")
	}
	if n, _ := s.Count(ctx, model.KindUser, "org"); n != 1 {
		t.Errorf("user count %d", n)
	}
}

// A tombstone is in the age index (which Purge reads) unless a partition write stamped it: those are removed by
// sequence as their partition moves past them, and kept out of the age index so a gossip node does not write an
// entry for every deletion that nothing reads.
func TestPartitionTombstonesAreNotInTheAgeIndex(t *testing.T) {
	ctx := context.Background()
	s := openBadger(t, BadgerOptions{InMemory: true})
	users := store.NewTable[model.User](s)
	plain := &model.User{OrgID: "org", Username: "plain", Role: model.RoleUser}
	if err := users.Put(ctx, plain); err != nil {
		t.Fatal(err)
	}
	if err := users.Delete(ctx, plain.ID); err != nil {
		t.Fatal(err)
	}
	stamped := &model.User{OrgID: "org", Username: "stamped", Role: model.RoleUser}
	rec, err := store.Encode(stamped)
	if err != nil {
		t.Fatal(err)
	}
	tomb := store.Tombstone(rec.Kind, rec.ID)
	tomb.Partition = rec.Partition
	if err := s.ApplyPartition(ctx, 7, []*store.Record{rec}, store.PartitionPos{Seq: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyPartition(ctx, 7, []*store.Record{tomb}, store.PartitionPos{Seq: 2}); err != nil {
		t.Fatal(err)
	}
	if m, _ := s.eng.Range(ctx, "tomb", "", "", 0); len(m) != 1 || !strings.HasSuffix(m[0], "/"+plain.ID) {
		t.Errorf("the age index holds %v, want the unstamped tombstone only", m)
	}
	if m, _ := s.eng.Range(ctx, ptBucket(7), "", "", 0); len(m) != 1 || !strings.HasSuffix(m[0], "/"+rec.ID) {
		t.Errorf("the partition's tombstone index holds %v", m)
	}
	if n, err := s.Purge(ctx, time.Now().Add(time.Hour), time.Time{}); err != nil || n != 1 {
		t.Errorf("Purge by age removed %d (%v), want the unstamped tombstone", n, err)
	}
	if _, err := s.Lookup(ctx, model.KindUser, rec.ID); err != nil {
		t.Errorf("a partition's tombstone is left to its partition: %v", err)
	}
}
