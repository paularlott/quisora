package cluster

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

func auditRec(t *testing.T, org, action string, at time.Time) *store.Record {
	t.Helper()
	e := &model.Audit{Meta: model.Meta{ID: model.NewID(), Created: at}, OrgID: org, Action: action, Actor: "ada", Target: "pat"}
	rec, err := store.EncodeAsIs(e)
	if err != nil {
		t.Fatal(err)
	}
	rec.Version = store.Clock.Now()
	return rec
}

// bigAuditRec is an audit event of about 2 KB.
func bigAuditRec(t *testing.T, org, action string, at time.Time) *store.Record {
	t.Helper()
	e := &model.Audit{Meta: model.Meta{ID: model.NewID(), Created: at}, OrgID: org, Action: action, Actor: "ada", Target: "pat",
		Detail: map[string]string{"note": strings.Repeat("x", 2000)}}
	rec, err := store.EncodeAsIs(e)
	if err != nil {
		t.Fatal(err)
	}
	rec.Version = store.Clock.Now()
	return rec
}

// Audit events stay on the node that wrote them: no node's database holds another node's events, and a query on any node
// asks every node and merges their events in order, pages with offsets (and pages the nodes' replies, when they hold
// more than one reply carries), applies filters on every node, and reports a node that did not answer.
func TestAuditIsNodeLocalAndMerged(t *testing.T) {
	c := started(t, badgerBackend())
	base := time.Now().Add(-time.Hour)
	written := make([]map[string]bool, 3)
	for i := range written {
		written[i] = map[string]bool{}
	}
	for i := range 9 { // events interleaved in time across the three nodes; two organizations
		org := "org-a"
		if i%3 == 2 {
			org = "org-b"
		}
		rec := auditRec(t, org, fmt.Sprintf("action.%d", i), base.Add(time.Duration(i)*time.Minute))
		if err := c.nodes[i%3].st().Put(bg, rec); err != nil {
			t.Fatal(err)
		}
		written[i%3][rec.ID] = true
	}
	consistently(t, 300*time.Millisecond, "each node holding its own 3 audit events alone (they must not replicate)", func() bool {
		for _, tn := range c.nodes {
			if res, err := tn.st().Inner().List(bg, model.KindAudit, store.ListQuery{Limit: 100}); err != nil || len(res.Records) != 3 {
				return false
			}
		}
		return true
	})
	for i, tn := range c.nodes {
		res, err := tn.st().Inner().List(bg, model.KindAudit, store.ListQuery{Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range res.Records {
			if !written[i][r.ID] {
				t.Fatalf("node %d holds another node's audit event %s", i, r.ID)
			}
			if r.Partition != "" && tn.n.pst != nil {
				if st, _ := tn.n.pst.State(recPartition(r)); st.Pending != nil {
					t.Fatalf("node %d: an audit event is pending in a partition", i)
				}
			}
		}
	}
	recs, total, nodes, answered, err := c.nodes[1].n.AuditQuery(bg, store.ListQuery{Sort: "created", Desc: true, Limit: 100})
	if err != nil || total != 9 || nodes != 3 || answered != 3 || len(recs) != 9 {
		t.Fatalf("merged: %d records, total %d, %d/%d nodes, %v", len(recs), total, answered, nodes, err)
	}
	for i := 1; i < len(recs); i++ {
		a, _ := recs[i-1].Fields["created"].(time.Time)
		b, _ := recs[i].Fields["created"].(time.Time)
		if a.Before(b) {
			t.Fatal("merged events are not newest first")
		}
	}
	// one organization, first page of two
	recs, total, _, _, _ = c.nodes[0].n.AuditQuery(bg, store.ListQuery{Scope: "org-a", Sort: "created", Desc: true, Limit: 2})
	if total != 6 || len(recs) != 2 || recs[0].Fields["action"] != "action.7" || recs[1].Fields["action"] != "action.6" {
		t.Fatalf("org-a page: total %d %v", total, recs)
	}
	// filters reach every node: a family of actions and a time range, each event on its own node
	recs, total, _, answered, err = c.nodes[0].n.AuditQuery(bg, store.ListQuery{Sort: "created", Desc: true, Limit: 100,
		Filters: []store.Filter{{Field: "action", Op: store.OpPrefix, Value: "ACTION.1"},
			{Field: "created", Op: store.OpGTE, Value: base.Add(time.Minute)}}})
	if err != nil || answered != 3 || total != 1 || len(recs) != 1 || recs[0].Fields["action"] != "action.1" {
		t.Fatalf("filtered: %d records, total %d, %d answered, %v", len(recs), total, answered, err)
	}
	recs, total, _, _, _ = c.nodes[2].n.AuditQuery(bg, store.ListQuery{Sort: "created", Limit: 100,
		Filters: []store.Filter{{Field: "created", Op: store.OpGTE, Value: base.Add(3 * time.Minute)},
			{Field: "created", Op: store.OpLT, Value: base.Add(6 * time.Minute)}}})
	if total != 3 || len(recs) != 3 || recs[0].Fields["action"] != "action.3" || recs[2].Fields["action"] != "action.5" {
		t.Fatalf("time range across nodes: total %d, %d records", total, len(recs))
	}
	// a node that does not answer is left out (after the wait), not an error
	c.drop(0, 1, true, msgAudit)
	recs, _, nodes, answered, err = c.nodes[0].n.AuditQuery(bg, store.ListQuery{Limit: 100})
	if err != nil || len(recs) != 6 || nodes != 3 || answered != 2 {
		t.Fatalf("a silent node: %d records, %d of %d answered, %v", len(recs), answered, nodes, err)
	}
	c.drop(0, 1, false, msgAudit)
	// a node that is slow, not down, is left out too once the wait is over: the answer comes at the deadline, not as an
	// error
	c.hold(0, 1, true, msgAudit)
	start := time.Now()
	recs, _, nodes, answered, err = c.nodes[0].n.AuditQuery(bg, store.ListQuery{Limit: 100})
	if err != nil || len(recs) != 6 || nodes != 3 || answered != 2 {
		t.Fatalf("a slow node: %d records, %d of %d answered, %v", len(recs), answered, nodes, err)
	}
	if d := time.Since(start); d < auditWait-100*time.Millisecond {
		t.Fatalf("the query did not wait for the slow node: %s", d)
	}
	c.hold(0, 1, false, msgAudit)
	// the caller going away ends the query
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if _, _, _, _, err := c.nodes[0].n.AuditQuery(ctx, store.ListQuery{Limit: 10}); err == nil {
		t.Fatal("a cancelled query succeeded")
	}

	// nodes holding more than fits one reply (auditReplyBytes): the page is still complete and in order, as the nodes'
	// replies are paged
	saved := auditReplyBytes
	auditReplyBytes = 10 << 10
	t.Cleanup(func() { auditReplyBytes = saved })
	pageBase := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Microsecond)
	var all []string
	for i := range 45 {
		r := bigAuditRec(t, "org-p", fmt.Sprintf("p.%d", i), pageBase.Add(time.Duration(i)*time.Second))
		if err := c.nodes[i%3].st().Put(bg, r); err != nil {
			t.Fatal(err)
		}
		all = append(all, r.ID)
	}
	recs, total, nodes, answered, err = c.nodes[0].n.AuditQuery(bg, store.ListQuery{Scope: "org-p", Sort: "created", Limit: 100})
	if err != nil || len(recs) != 45 || total != 45 || nodes != 3 || answered != 3 {
		t.Fatalf("%d large events (total %d, %d of %d nodes), want 45 from 3: %v", len(recs), total, answered, nodes, err)
	}
	for i, r := range recs {
		if r.ID != all[i] {
			t.Fatalf("large event %d out of order", i)
		}
	}
	// a page smaller than a node's holding asks for less
	recs, _, _, _, err = c.nodes[1].n.AuditQuery(bg, store.ListQuery{Scope: "org-p", Sort: "created", Desc: true, Limit: 7})
	if err != nil || len(recs) != 7 || recs[0].ID != all[44] || recs[6].ID != all[38] {
		t.Fatalf("newest 7: %d events, %v", len(recs), err)
	}

	// a node down: its events are missing and the answer says so
	stop(c.nodes[2])
	waitFor(t, 10*time.Second, "node 2 seen down", func() bool { return len(c.nodes[0].n.otherPeers()) == 1 })
	recs, total, nodes, answered, err = c.nodes[0].n.AuditQuery(bg, store.ListQuery{Sort: "created", Desc: true, Limit: 100,
		Filters: []store.Filter{{Field: "action", Op: store.OpPrefix, Value: "action."}}})
	if err != nil || nodes != 3 || answered != 2 || total != 6 || len(recs) != 6 {
		t.Fatalf("with a node down: %d records, total %d, %d/%d nodes, %v", len(recs), total, answered, nodes, err)
	}
}

// An audit page is answered only to a node of the same data set: a node set up apart is not part of the cluster's log.
func TestAuditAnsweredOnlyWithinTheDataSet(t *testing.T) {
	n := newTestNode(t)
	asker := func(genesis string) *gossip.Node {
		md := gossip.NewMetadata()
		if genesis != "" {
			md.SetString(metaGenesis, genesis)
		}
		return &gossip.Node{Metadata: md}
	}
	if _, err := n.handleAudit(asker("another"), packetOf(t, &auditReq{Limit: 10})); !errors.Is(err, errOtherDataSet) {
		t.Fatalf("a node of another data set was answered: %v", err)
	}
	if _, err := n.handleAudit(asker(""), packetOf(t, &auditReq{Limit: 10})); !errors.Is(err, errOtherDataSet) {
		t.Fatalf("a node of no data set was answered: %v", err)
	}
	if _, err := n.handleAudit(asker(*n.genesis.Load()), packetOf(t, &auditReq{Limit: 10})); err != nil {
		t.Fatalf("a node of the same data set: %v", err)
	}
}

func TestHandleAuditAndAuditQueryStandalone(t *testing.T) {
	n, cs := hnode(t)
	for i, act := range []string{"user.create", "user.update"} {
		v := store.Clock.Now()
		r := &store.Record{Kind: model.KindAudit, ID: newID(), Version: v, Created: v, Scope: "org1", Data: []byte("d")}
		r.Fields = map[string]any{"action": act, "created": time.Now().UTC().Add(time.Duration(i) * time.Second).Truncate(time.Microsecond),
			"actor": "a"}
		if err := cs.Store.Put(bg, r); err != nil {
			t.Fatal(err)
		}
	}
	r, err := n.handleAudit(nil, packetOf(t, &auditReq{Limit: 10}))
	if err != nil {
		t.Fatal(err)
	}
	resp := r.(*auditResp)
	if !resp.Filtered || resp.Total != 2 || len(resp.Recs) != 2 {
		t.Fatalf("%+v", resp)
	}
	if _, err := n.handleAudit(nil, badPacket(t)); err == nil {
		t.Error("a bad payload was accepted")
	}
	recs, total, nodes, answered, err := n.AuditQuery(bg, store.ListQuery{Limit: 10})
	if err != nil || len(recs) != 2 || total != 2 || nodes != 1 || answered != 1 {
		t.Fatalf("standalone query: %d %d %d %d %v", len(recs), total, nodes, answered, err)
	}
	cs.list = errors.New("disk")
	if _, err := n.handleAudit(nil, packetOf(t, &auditReq{Limit: 10})); err == nil {
		t.Error("a store error was not reported")
	}
	if _, _, _, _, err := n.AuditQuery(bg, store.ListQuery{Limit: 10}); err == nil {
		t.Error("a store error was not reported by the query")
	}
}

// A node's reply holds events up to auditReplyBytes (at least one) and says there are more; the asker's next request
// starts where the reply ended, and the pages add up to every event once.
func TestAuditReplyIsCutBySize(t *testing.T) {
	saved := auditReplyBytes
	auditReplyBytes = 10 << 10
	defer func() { auditReplyBytes = saved }()
	n, cs := hnode(t)
	base := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	want := map[string]bool{}
	for i := range 30 {
		r := bigAuditRec(t, "org-a", fmt.Sprintf("a.%d", i), base.Add(time.Duration(i)*time.Second))
		if err := cs.Store.Put(bg, r); err != nil {
			t.Fatal(err)
		}
		want[r.ID] = true
	}
	got := map[string]bool{}
	pages := 0
	for offset := 0; ; pages++ {
		r, err := n.handleAudit(nil, packetOf(t, &auditReq{Limit: 100, Sort: "created", Offset: offset}))
		if err != nil {
			t.Fatal(err)
		}
		resp := r.(*auditResp)
		size := 0
		for _, b := range resp.Recs {
			size += len(b)
			rec, err := decodeRecord(b)
			if err != nil || got[rec.ID] {
				t.Fatalf("event %v twice or unreadable: %v", rec, err)
			}
			got[rec.ID] = true
		}
		if size > auditReplyBytes+2500 || len(resp.Recs) == 0 {
			t.Fatalf("a reply of %d events, %d bytes (limit %d)", len(resp.Recs), size, auditReplyBytes)
		}
		if resp.Total != 30 {
			t.Fatalf("total %d", resp.Total)
		}
		offset += len(resp.Recs)
		if !resp.More {
			break
		}
	}
	if pages < 3 || len(got) != 30 {
		t.Fatalf("%d events in %d pages, want 30 in several", len(got), pages)
	}
	// one event bigger than the limit is still sent (the reply holds at least one)
	auditReplyBytes = 100
	r, _ := n.handleAudit(nil, packetOf(t, &auditReq{Limit: 100, Sort: "created"}))
	if resp := r.(*auditResp); len(resp.Recs) != 1 || !resp.More {
		t.Fatalf("an event over the limit: %d events, more %v", len(resp.Recs), resp.More)
	}
}

func TestMergeAuditOrders(t *testing.T) {
	at := func(s int) time.Time { return time.Unix(int64(s), 0).UTC() }
	rec := func(id, action string, sec int) *store.Record {
		return &store.Record{ID: id, Fields: map[string]any{"action": action, "created": at(sec)}}
	}
	mk := func() []*store.Record {
		return []*store.Record{rec("c", "User.Update", 3), rec("a", "user.create", 1), rec("b", "user.create", 1),
			rec("d", "audit.read", 2)}
	}
	ids := func(rs []*store.Record) string {
		var s []string
		for _, r := range rs {
			s = append(s, r.ID)
		}
		return strings.Join(s, "")
	}
	if got := ids(mergeAudit(mk(), store.ListQuery{})); got != "abdc" { // time, then id
		t.Errorf("by time: %s", got)
	}
	if got := ids(mergeAudit(mk(), store.ListQuery{Desc: true})); got != "cdba" {
		t.Errorf("by time, newest first: %s", got)
	}
	if got := ids(mergeAudit(mk(), store.ListQuery{Sort: "action"})); got != "dabc" { // case-insensitive action
		t.Errorf("by action: %s", got)
	}
	if got := ids(mergeAudit(mk(), store.ListQuery{Sort: "action", Desc: true, Limit: 2})); got != "cb" {
		t.Errorf("by action, descending, limited: %s", got)
	}
}

func TestAuditFiltersWireRoundTrip(t *testing.T) {
	when := time.Date(2026, 1, 2, 3, 4, 5, 6000, time.UTC)
	in := []store.Filter{{Field: "action", Op: "=", Value: "a"}, {Field: "created", Op: ">=", Value: when}, {Field: "n", Op: "=", Value: 5}}
	out := fromAuditFilters(toAuditFilters(in))
	if len(out) != 3 || out[0].Value != "a" || !out[1].Value.(time.Time).Equal(when) || out[2].Value != "" {
		t.Fatalf("%+v", out)
	}
}
