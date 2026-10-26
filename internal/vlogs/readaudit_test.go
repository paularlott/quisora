package vlogs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/service"
)

// A page is two LogsQL queries, the filter with the sort, offset and limit and the filter with a count; the rows come
// back as audit events with their time, every named field and the detail.* fields, and the count is the total.
// Delivery is at least once, so the page query keeps one row per id before it cuts the page (dedup).
func TestReadAuditQueriesAndParsesRows(t *testing.T) {
	rows := `{"_time":"2026-10-24T10:00:01.5Z","id":"e1","org":"o1","actor":"ada","actor_id":"u1","action":"user.update","target":"bob","ip":"192.0.2.1","outcome":"success","request_id":"r1","user_agent":"curl","session_id":"s1","detail.tags":"x y","detail.reason":"policy"}` + "\n\n" +
		`{"_time":"2026-10-24T09:59:59Z","id":"e2","org":"o1","actor":"bob","action":"login.failure","outcome":"failure"}` + "\n"
	vl := newFakeSelect(t, answer(rows, `{"n":"7"}`+"\n"))
	c := newReader(t, vl.srv.URL)
	q := service.AuditQuery{Org: "o1", Sort: "created", Desc: true, Offset: 3, Limit: 2}
	page, err := c.ReadAudit(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	seen := vl.seen()
	if len(seen) != 2 || seen[0] != Filter(q)+dedup+" | sort by (_time desc) | offset 3 | limit 2" || seen[1] != Filter(q)+countSuffix {
		t.Fatalf("queries %q", seen)
	}
	if page.Total != 7 || page.Source != "victorialogs" || page.Nodes != 1 || page.Answered != 1 || len(page.Items) != 2 {
		t.Fatalf("page %+v", page)
	}
	e := page.Items[0]
	want := time.Date(2026, 10, 24, 10, 0, 1, 500_000_000, time.UTC)
	if e.ID != "e1" || !e.Created.Equal(want) || e.OrgID != "o1" || e.Actor != "ada" || e.ActorID != "u1" || e.Action != "user.update" ||
		e.Target != "bob" || e.IP != "192.0.2.1" || e.Outcome != "success" || e.RequestID != "r1" || e.UserAgent != "curl" || e.SessionID != "s1" {
		t.Fatalf("first row %+v", e)
	}
	if len(e.Detail) != 2 || e.Detail["tags"] != "x y" || e.Detail["reason"] != "policy" {
		t.Fatalf("detail %v", e.Detail)
	}
	if page.Items[1].ID != "e2" || page.Items[1].Detail != nil || page.Items[1].Action != "login.failure" {
		t.Fatalf("second row %+v", page.Items[1])
	}
}

// The sort clause follows the query: by time either way, by action then time, and an offset below zero or a limit
// below one are not sent to VictoriaLogs.
func TestReadAuditSortOrders(t *testing.T) {
	vl := newFakeSelect(t, answer("", `{"n":"0"}`+"\n"))
	c := newReader(t, vl.srv.URL)
	cases := []struct {
		q    service.AuditQuery
		tail string
	}{
		{service.AuditQuery{Sort: "created", Desc: false, Limit: 10}, " | sort by (_time) | offset 0 | limit 10"},
		{service.AuditQuery{Sort: "action", Desc: true, Limit: 10}, " | sort by (action desc, _time desc) | offset 0 | limit 10"},
		{service.AuditQuery{Sort: "action", Desc: false, Offset: 5, Limit: 10}, " | sort by (action, _time) | offset 5 | limit 10"},
		{service.AuditQuery{Desc: true, Offset: -4, Limit: 0}, " | sort by (_time desc) | offset 0 | limit 1"},
	}
	for i, tc := range cases {
		page, err := c.ReadAudit(context.Background(), tc.q)
		if err != nil || page.Total != 0 || len(page.Items) != 0 {
			t.Fatalf("case %d: %+v %v", i, page, err)
		}
		seen := vl.seen()
		if got := seen[2*i]; got != Filter(tc.q)+dedup+tc.tail {
			t.Errorf("case %d: query %q, want tail %q", i, got, tc.tail)
		}
	}
}

// Every way VictoriaLogs can fail a page is an error: refusing the query (with its message, cut short), an unreadable
// row, a row longer than the reader takes (not a truncated page), a failing count, and not answering at all. A count
// that is not one row leaves the total at zero.
func TestReadAuditErrors(t *testing.T) {
	ctx := context.Background()
	t.Run("status", func(t *testing.T) {
		vl := newFakeSelect(t, func(_ string, w http.ResponseWriter) {
			http.Error(w, strings.Repeat("x", 600), http.StatusInternalServerError)
		})
		_, err := newReader(t, vl.srv.URL).ReadAudit(ctx, service.AuditQuery{Limit: 1})
		if err == nil || !strings.Contains(err.Error(), "answered 500") || len(err.Error()) > 600 {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("malformed row", func(t *testing.T) {
		vl := newFakeSelect(t, answer("{not json\n", `{"n":"1"}`))
		if _, err := newReader(t, vl.srv.URL).ReadAudit(ctx, service.AuditQuery{Limit: 1}); err == nil {
			t.Fatal("malformed row accepted")
		}
	})
	t.Run("line too long", func(t *testing.T) {
		vl := newFakeSelect(t, answer(string(bytes.Repeat([]byte("a"), 5<<20)), `{"n":"1"}`))
		if _, err := newReader(t, vl.srv.URL).ReadAudit(ctx, service.AuditQuery{Limit: 1}); err == nil {
			t.Fatal("a 5 MB line was accepted")
		}
	})
	t.Run("count fails", func(t *testing.T) {
		vl := newFakeSelect(t, func(q string, w http.ResponseWriter) {
			if strings.HasSuffix(q, countSuffix) {
				http.Error(w, "down", http.StatusServiceUnavailable)
			}
		})
		if _, err := newReader(t, vl.srv.URL).ReadAudit(ctx, service.AuditQuery{Limit: 1}); err == nil || !strings.Contains(err.Error(), "503") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		_, err := newReader(t, "http://127.0.0.1:1").ReadAudit(ctx, service.AuditQuery{Limit: 1})
		if err == nil || !strings.Contains(err.Error(), "VictoriaLogs") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("odd count", func(t *testing.T) {
		vl := newFakeSelect(t, answer("", `{"n":"3"}`+"\n"+`{"n":"4"}`+"\n"))
		page, err := newReader(t, vl.srv.URL).ReadAudit(ctx, service.AuditQuery{Limit: 1})
		if err != nil || page.Total != 0 {
			t.Fatalf("page %+v %v", page, err)
		}
	})
}

// A row with an unreadable time is still an event (without a time), and detail fields exist only when there are some.
func TestFromRow(t *testing.T) {
	e := fromRow(map[string]string{"_time": "yesterday", "id": "e9", "action": "x"})
	if e.ID != "e9" || !e.Created.IsZero() || e.Detail != nil || e.Action != "x" {
		t.Fatalf("%+v", e)
	}
	e = fromRow(map[string]string{"detail.a": "1", "detail.": "empty", "other": "no"})
	if len(e.Detail) != 2 || e.Detail["a"] != "1" || e.Detail[""] != "empty" {
		t.Fatalf("detail %v", e.Detail)
	}
}

// VictoriaLogs holds every event twice (at-least-once delivery): paging through the events still shows each distinct
// event, because the duplicates are removed before the offset and limit apply. The fake answers distinct rows only
// to a query carrying the de-duplication; TestVictoriaLogsLivePaginationWithDuplicates runs it on VictoriaLogs.
func TestReadAuditPagesSeeEveryDistinctEventDespiteDuplicates(t *testing.T) {
	rows := []map[string]string{{"id": "a"}, {"id": "a"}, {"id": "b"}, {"id": "b"}, {"id": "c"}, {"id": "c"}}
	bounds := regexp.MustCompile(`\| offset (\d+) \| limit (\d+)`)
	f := newFakeSelect(t, func(q string, w http.ResponseWriter) {
		if strings.HasSuffix(q, countSuffix) {
			fmt.Fprintln(w, `{"n":"3"}`)
			return
		}
		selected := rows
		if strings.Contains(q, dedup) {
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
