package cluster

import (
	"fmt"
	"testing"
	"time"

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

// Audit events stay on the node that wrote them; a query asks every node and merges their events in order, pages
// with offsets, and reports a node that did not answer.
func TestAuditIsNodeLocalAndMerged(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	base := time.Now().Add(-time.Hour)
	for i := range 9 { // events interleaved in time across the three nodes; two organizations
		org := "org-a"
		if i%3 == 2 {
			org = "org-b"
		}
		if err := c.nodes[i%3].st().Put(bg, auditRec(t, org, fmt.Sprintf("action.%d", i), base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(time.Second) // several sync rounds
	for i, tn := range c.nodes {
		if n, _ := tn.st().Inner().Count(bg, model.KindAudit, ""); n != 3 {
			t.Fatalf("node %d holds %d audit events, want its own 3 (they must not replicate)", i, n)
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
		t.Fatalf("org-a page: total %d %v %v", total, recs[0].Fields["action"], recs[1].Fields["action"])
	}
	// a node down: its events are missing and the answer says so
	stop(c.nodes[2])
	waitFor(t, 10*time.Second, "node 2 seen down", func() bool { return len(c.nodes[0].n.otherPeers()) == 1 })
	recs, total, nodes, answered, err = c.nodes[0].n.AuditQuery(bg, store.ListQuery{Sort: "created", Desc: true, Limit: 100})
	if err != nil || nodes != 3 || answered != 2 || total != 6 || len(recs) != 6 {
		t.Fatalf("with a node down: %d records, total %d, %d/%d nodes, %v", len(recs), total, answered, nodes, err)
	}
}

// A node that cannot write replicated data (no quorum) still records audit events: they are its own.
func TestAuditWritableWithoutQuorum(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	c.startAll()
	c.waitReady()
	stop(c.nodes[1])
	stop(c.nodes[2])
	waitFor(t, 10*time.Second, "no quorum", func() bool { return !c.nodes[0].n.Writable() })
	if err := c.nodes[0].st().Put(bg, auditRec(t, "org-a", "login.failure", time.Now())); err != nil {
		t.Fatalf("an audit event refused without quorum: %v", err)
	}
}
