package vlogs

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// These tests run against a real VictoriaLogs (QUISORA_TEST_VICTORIALOGS=http://127.0.0.1:9428) and are skipped
// without one.

func liveAddr(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("QUISORA_TEST_VICTORIALOGS")
	if addr == "" {
		t.Skip("QUISORA_TEST_VICTORIALOGS not set")
	}
	return addr
}

// Events written by the client are read back per organization, newest first, searched, paged and counted.
func TestVictoriaLogsRoundTrip(t *testing.T) {
	c, err := New(liveAddr(t), "node-1", logger.NewNullLogger())
	if err != nil {
		t.Fatal(err)
	}
	c.Start()
	orgA, orgB, mark := model.NewID(), model.NewID(), "mark"+model.NewID()[24:]
	base := time.Now().Add(-time.Minute).UTC()
	for i := range 5 {
		c.WriteAudit(&model.Audit{Meta: model.Meta{ID: model.NewID(), Created: base.Add(time.Duration(i) * time.Second)},
			OrgID: orgA, Action: "user.update", Actor: "ada", Target: mark + "-" + string(rune('a'+i)), IP: "192.0.2.1",
			Detail: map[string]string{"tags": "x y"}})
	}
	c.WriteAudit(&model.Audit{Meta: model.Meta{ID: model.NewID(), Created: base}, OrgID: orgB, Action: "user.delete", Actor: "bob", Target: mark})
	c.Close() // flushes
	ctx := context.Background()
	var pg service.AuditPage
	// VictoriaLogs makes new rows searchable within a second or so
	waitFor(t, "the events to be searchable", func() bool {
		pg, err = c.ReadAudit(ctx, service.AuditQuery{Org: orgA, Sort: "created", Desc: true, Limit: 2})
		return err == nil && pg.Total == 5 && len(pg.Items) == 2
	})
	if pg.Source != "victorialogs" {
		t.Fatalf("org a: %+v", pg)
	}
	if pg.Items[0].Target != mark+"-e" || pg.Items[1].Target != mark+"-d" || pg.Items[0].Detail["tags"] != "x y" ||
		pg.Items[0].IP != "192.0.2.1" || pg.Items[0].OrgID != orgA || pg.Items[0].ID == "" {
		t.Fatalf("org a newest first: %+v %+v", pg.Items[0], pg.Items[1])
	}
	page2, _ := c.ReadAudit(ctx, service.AuditQuery{Org: orgA, Sort: "created", Desc: true, Offset: 2, Limit: 2})
	if len(page2.Items) != 2 || page2.Items[0].Target != mark+"-c" {
		t.Fatalf("second page: %+v", page2.Items)
	}
	other, _ := c.ReadAudit(ctx, service.AuditQuery{Org: orgB, Sort: "created", Desc: true, Limit: 10})
	if other.Total != 1 || other.Items[0].Action != "user.delete" {
		t.Fatalf("org b: %+v", other)
	}
	// every organization, by search (case-insensitive substring)
	all, _ := c.ReadAudit(ctx, service.AuditQuery{Search: strings.ToUpper(mark), Sort: "created", Desc: true, Limit: 50})
	if all.Total != 6 {
		t.Fatalf("search across organizations: %d", all.Total)
	}
}

// VictoriaLogs holding every event twice (at-least-once delivery) still pages through each distinct event once: the
// duplicates take no place on a page (TestReadAuditPagesSeeEveryDistinctEventDespiteDuplicates without the fake).
func TestVictoriaLogsLivePaginationWithDuplicates(t *testing.T) {
	c := newReader(t, liveAddr(t))
	defer c.cancel()
	org := model.NewID()
	var body strings.Builder
	now := time.Now().Add(-time.Minute).UTC()
	for i, id := range []string{"a", "b", "c"} {
		row := map[string]string{"app": "quisora", "org": org, "id": org + id, "_time": now.Add(-time.Duration(i) * time.Second).Format(time.RFC3339Nano), "action": "user.update", "actor": "dup", "_msg": "duplicate paging"}
		b, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			body.Write(b)
			body.WriteByte('\n')
		}
	}
	if err := c.post(c.insertURL(), []byte(body.String())); err != nil {
		t.Fatal(err)
	}
	q := service.AuditQuery{Org: org, Desc: true, Limit: 2}
	var first service.AuditPage
	var err error
	// The count sees new rows a moment before row queries do: wait for both.
	waitFor(t, "the events to be searchable", func() bool {
		first, err = c.ReadAudit(context.Background(), q)
		return err == nil && first.Total == 3 && len(first.Items) == q.Limit
	})
	seen := map[string]bool{}
	for offset := 0; offset < first.Total; offset += q.Limit {
		q.Offset = offset
		page, err := c.ReadAudit(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page.Items {
			seen[e.ID] = true
		}
	}
	if len(seen) != 3 {
		t.Fatalf("real VictoriaLogs pagination exposes %d of 3 distinct events over advertised pages: %v", len(seen), seen)
	}
}
