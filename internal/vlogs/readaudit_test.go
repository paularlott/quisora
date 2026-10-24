package vlogs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/service"
)

// fakeSelect is a VictoriaLogs query endpoint: it records every LogsQL query it is sent and answers from respond.
type fakeSelect struct {
	mu      sync.Mutex
	queries []string
	respond func(q string, w http.ResponseWriter)
	srv     *httptest.Server
}

func newFakeSelect(t *testing.T, respond func(q string, w http.ResponseWriter)) *fakeSelect {
	f := &fakeSelect{respond: respond}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/select/logsql/query" {
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		q := r.PostForm.Get("query")
		f.mu.Lock()
		f.queries = append(f.queries, q)
		f.mu.Unlock()
		f.respond(q, w)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSelect) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

const countSuffix = " | stats count() n"

// answer serves rows to the page query and count to the count query.
func answer(rows, count string) func(string, http.ResponseWriter) {
	return func(q string, w http.ResponseWriter) {
		if strings.HasSuffix(q, countSuffix) {
			_, _ = w.Write([]byte(count))
			return
		}
		_, _ = w.Write([]byte(rows))
	}
}

func newReader(t *testing.T, base string) *Client {
	t.Helper()
	c, err := New(base, "n1", logger.NewNullLogger())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A page is two LogsQL queries, the filter with the sort, offset and limit and the filter with a count; the rows come
// back as audit events with their time, every named field and the detail.* fields, and the count is the total.
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
	if len(seen) != 2 || seen[0] != Filter(q)+" | sort by (_time desc) | offset 3 | limit 2" || seen[1] != Filter(q)+countSuffix {
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
		if got := seen[2*i]; got != Filter(tc.q)+tc.tail {
			t.Errorf("case %d: query %q, want tail %q", i, got, tc.tail)
		}
	}
}

// Every way VictoriaLogs can fail a page is an error: refusing the query (with its message, cut short), an unreadable
// row, a failing count, and not answering at all. A count that is not one row leaves the total at zero.
func TestReadAuditErrors(t *testing.T) {
	ctx := context.Background()
	t.Run("status", func(t *testing.T) {
		vl := newFakeSelect(t, func(string, http.ResponseWriter) {}) // set below
		vl.respond = func(_ string, w http.ResponseWriter) {
			http.Error(w, strings.Repeat("x", 600), http.StatusInternalServerError)
		}
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

// The spool size is zero without a spool, and the bytes on disk with one.
func TestSpoolBytes(t *testing.T) {
	c := newReader(t, "http://127.0.0.1:1")
	if c.SpoolBytes() != 0 {
		t.Fatal("size without a spool")
	}
	if err := c.Spool(t.TempDir(), 0); err != nil {
		t.Fatal(err)
	}
	if c.SpoolBytes() != 0 {
		t.Fatal("size of an empty spool")
	}
	line := []byte(`{"id":"a"}` + "\n")
	if _, err := c.spool.store(line); err != nil {
		t.Fatal(err)
	}
	if got := c.SpoolBytes(); got != int64(len(line)) {
		t.Fatalf("spool holds %d bytes, want %d", got, len(line))
	}
}

// An event the queue has no room for, and one written after Close, go to the structured log in full.
func TestWriteAuditWithoutRoomOrWriterIsLogged(t *testing.T) {
	log := newCapture()
	c, err := New("http://127.0.0.1:1", "n1", log)
	if err != nil {
		t.Fatal(err)
	}
	c.queue = make(chan []byte, 1) // no writer running: the second event finds no room
	c.WriteAudit(event(0))
	c.WriteAudit(event(1))
	if ids := log.undeliveredIDs(); ids["ev-00000"] || !ids["ev-00001"] {
		t.Fatalf("logged %v", ids)
	}
	c.mu.Lock()
	dropped := c.dropped
	c.mu.Unlock()
	if dropped != 1 {
		t.Fatalf("dropped %d", dropped)
	}

	log2 := newCapture()
	c2, _ := New("http://127.0.0.1:1", "n1", log2)
	c2.Start()
	c2.Close()
	c2.WriteAudit(event(5))
	if ids := log2.undeliveredIDs(); !ids["ev-00005"] {
		t.Fatalf("after close: logged %v", ids)
	}
}

// A spool that stops being writable after startup does not lose the batch silently: it is logged in full.
func TestToSpoolWriteFailureIsLogged(t *testing.T) {
	log := newCapture()
	dir := filepath.Join(t.TempDir(), "spool")
	c, _ := New("http://127.0.0.1:1", "n1", log)
	if err := c.Spool(dir, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, nil, 0o600); err != nil { // a file where the directory was
		t.Fatal(err)
	}
	c.toSpool([]byte(`{"id":"ev-00042"}` + "\n"))
	if ids := log.undeliveredIDs(); !ids["ev-00042"] {
		t.Fatalf("logged %v", ids)
	}
}

// Only http and https URLs with a host are VictoriaLogs addresses.
func TestNewRejectsBadURLs(t *testing.T) {
	for _, bad := range []string{"", "ftp://logs:9428", "http://", "://x", "victorialogs:9428"} {
		if _, err := New(bad, "n1", logger.NewNullLogger()); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := New("https://user:pw@logs.example:9428/", "n1", logger.NewNullLogger()); err != nil {
		t.Fatal(err)
	}
}

// A row carries the request id, user agent and session id only when the event has them, and every detail field.
func TestRowOptionalFields(t *testing.T) {
	c := newReader(t, "http://127.0.0.1:1")
	e := event(1)
	r := c.row(e)
	for _, k := range []string{"request_id", "user_agent", "session_id"} {
		if _, ok := r[k]; ok {
			t.Errorf("%s present on a bare event", k)
		}
	}
	if r["node"] != "n1" || r["app"] != app || r["id"] != "ev-00001" || r["_msg"] != "audit user.update" {
		t.Fatalf("row %v", r)
	}
	e.RequestID, e.UserAgent, e.SessionID, e.Detail = "r", "ua", "s", map[string]string{"k": "v"}
	r = c.row(e)
	if r["request_id"] != "r" || r["user_agent"] != "ua" || r["session_id"] != "s" || r["detail.k"] != "v" {
		t.Fatalf("row %v", r)
	}
}

// Every event a process accepts is numbered in turn within its boot, delivered or not, so a gap in VictoriaLogs is an
// event it does not hold.
func TestRowSequence(t *testing.T) {
	c := newReader(t, "http://127.0.0.1:1")
	a, b := c.row(event(1)), c.row(event(2))
	if a["boot"] != c.boot || a["boot"] == "" || a["seq"] != uint64(1) || b["seq"] != uint64(2) {
		t.Fatalf("rows %v %v", a, b)
	}
	if d, _ := New("http://127.0.0.1:1", "n1", logger.NewNullLogger()); d.boot == c.boot {
		t.Fatal("two starts share a boot id")
	}
}
