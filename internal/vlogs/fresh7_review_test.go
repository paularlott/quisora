package vlogs

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/paularlott/quisora/internal/model"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/service"
)

func TestFreshReviewDuplicateEventsDoNotConsumeAuditPage(t *testing.T) {
	// Simulate the rows VictoriaLogs stores after normal at-least-once retries.
	rows := []map[string]string{{"id": "a"}, {"id": "a"}, {"id": "b"}, {"id": "b"}, {"id": "c"}, {"id": "c"}}
	bounds := regexp.MustCompile(`\| offset (\d+) \| limit (\d+)`)
	f := newFakeSelect(t, func(q string, w http.ResponseWriter) {
		if strings.HasSuffix(q, countSuffix) {
			fmt.Fprintln(w, `{"n":"3"}`)
			return
		}
		selected := rows
		// A query that deduplicates before pagination follows distinct-row offsets.
		if strings.Contains(q, "uniq") || strings.Contains(q, "stats by (id)") {
			selected = []map[string]string{rows[0], rows[2], rows[4]}
		}
		m := bounds.FindStringSubmatch(q)
		if m == nil {
			t.Errorf("missing page bounds in %q", q)
			return
		}
		offset, _ := strconv.Atoi(m[1])
		limit, _ := strconv.Atoi(m[2])
		for _, row := range selected[min(offset, len(selected)):min(offset+limit, len(selected))] {
			_ = json.NewEncoder(w).Encode(row)
		}
	})
	c := newReader(t, f.srv.URL)
	seen := map[string]bool{}
	for offset := 0; offset < 3; offset += 2 {
		page, err := c.ReadAudit(context.Background(), service.AuditQuery{Limit: 2, Offset: offset})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page.Items {
			seen[e.ID] = true
		}
	}
	if len(seen) != 3 {
		t.Fatalf("pagination exposes only %d of 3 distinct audit events: %v", len(seen), seen)
	}
}

func TestFreshReviewLiveDuplicateEventsDoNotConsumeAuditPage(t *testing.T) {
	addr := os.Getenv("QUISORA_TEST_VICTORIALOGS")
	if addr == "" {
		t.Skip("QUISORA_TEST_VICTORIALOGS not set")
	}
	c := newReader(t, addr)
	defer c.cancel()
	org := model.NewID()
	var body strings.Builder
	now := time.Now().Add(-time.Minute).UTC()
	for i, id := range []string{"a", "b", "c"} {
		row := map[string]string{"app": "quisora", "org": org, "id": org + id, "_time": now.Add(-time.Duration(i) * time.Second).Format(time.RFC3339Nano), "action": "user.update", "actor": "review", "_msg": "duplicate paging review"}
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
	deadline := time.Now().Add(5 * time.Second)
	var first service.AuditPage
	for {
		var err error
		first, err = c.ReadAudit(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		if first.Total == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("events did not arrive: %+v", first)
		}
		time.Sleep(100 * time.Millisecond)
	}
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
