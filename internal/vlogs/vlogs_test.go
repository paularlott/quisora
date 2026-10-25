package vlogs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Values from a request never become LogsQL syntax: quotes, pipes and regular-expression characters are escaped.
func TestFilterEscapes(t *testing.T) {
	f := Filter(service.AuditQuery{Org: `x" | delete`, Search: `a.*") or app:*`})
	for _, bad := range []string{`org:="x" |`, `.*")`, `or app:*`} {
		if strings.Contains(f, bad) {
			t.Fatalf("unescaped request text in %s", f)
		}
	}
	if !strings.HasPrefix(f, `app:="quisora" org:="x\" | delete"`) || !strings.Contains(f, `actor:~"(?i)a\\.\\*\"\\) or app:\\*"`) {
		t.Fatalf("filter %s", f)
	}
	if Filter(service.AuditQuery{}) != `app:="quisora"` {
		t.Fatal("empty query")
	}
}

// The filters become LogsQL conditions: a time range, an action family (escaped, case-insensitive), one action, an
// outcome; the search covers actor, target and IP address, not the action.
func TestFilterConditions(t *testing.T) {
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	f := Filter(service.AuditQuery{From: from, To: to, ActionPrefix: "user.", Action: "user.update", Outcome: "failure", Search: "10.0"})
	for _, want := range []string{`_time:>=2026-10-01T00:00:00Z`, `_time:<2026-10-02T00:00:00Z`, `action:~"(?i)^user\\."`,
		`action:="user.update"`, `outcome:="failure"`, `(actor:~"(?i)10\\.0" or target:~"(?i)10\\.0" or ip:~"(?i)10\\.0")`} {
		if !strings.Contains(f, want) {
			t.Errorf("filter %s lacks %s", f, want)
		}
	}
}

// Against a real VictoriaLogs (QUISORA_TEST_VICTORIALOGS=http://127.0.0.1:9428): events written by the client are
// read back per organization, newest first, searched, paged and counted.
func TestVictoriaLogsRoundTrip(t *testing.T) {
	addr := os.Getenv("QUISORA_TEST_VICTORIALOGS")
	if addr == "" {
		t.Skip("QUISORA_TEST_VICTORIALOGS not set")
	}
	c, err := New(addr, "node-1", logger.NewNullLogger())
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
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) { // VictoriaLogs makes new rows searchable within a second or so
		pg, err = c.ReadAudit(ctx, service.AuditQuery{Org: orgA, Sort: "created", Desc: true, Limit: 2})
		if err == nil && pg.Total == 5 && len(pg.Items) == 2 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil || pg.Total != 5 || len(pg.Items) != 2 || pg.Source != "victorialogs" {
		t.Fatalf("org a: %+v %v", pg, err)
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

// fakeVL is a VictoriaLogs insert endpoint that can be switched off, and counts the events it took.
type fakeVL struct {
	mu  sync.Mutex
	up  bool
	ids map[string]int
	srv *httptest.Server
}

func newFakeVL(t *testing.T) *fakeVL {
	f := &fakeVL{ids: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if !f.up {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		sc := bufio.NewScanner(r.Body)
		for sc.Scan() {
			var row map[string]any
			if json.Unmarshal(sc.Bytes(), &row) == nil {
				f.ids[row["id"].(string)]++
			}
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeVL) set(up bool) { f.mu.Lock(); f.up = up; f.mu.Unlock() }

func (f *fakeVL) count() (distinct, total int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.ids {
		distinct++
		total += n
	}
	return
}

func event(i int) *model.Audit {
	return &model.Audit{Meta: model.Meta{ID: fmt.Sprintf("ev-%05d", i), Created: time.Now()}, OrgID: "o", Action: "user.update"}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// With a spool, events written while VictoriaLogs is down are kept on disk and sent once it is back, also after a
// restart of the writer; nothing is left in the spool afterwards.
func TestSpoolKeepsEventsThroughAnOutage(t *testing.T) {
	vl := newFakeVL(t)
	dir := t.TempDir()
	c, err := New(vl.srv.URL, "n1", logger.NewNullLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Spool(dir, 0); err != nil {
		t.Fatal(err)
	}
	c.Start()
	for i := range 100 {
		c.WriteAudit(event(i))
	}
	waitFor(t, "the spool to fill", func() bool { return !c.spool.empty() })
	c.Close() // shuts down with events still spooled

	vl.set(true)
	c2, _ := New(vl.srv.URL, "n1", logger.NewNullLogger())
	if err := c2.Spool(dir, 0); err != nil {
		t.Fatal(err)
	}
	c2.Start()
	defer c2.Close()
	for i := 100; i < 110; i++ {
		c2.WriteAudit(event(i))
	}
	waitFor(t, "every event to arrive", func() bool { d, _ := vl.count(); return d == 110 })
	waitFor(t, "the spool to drain", func() bool {
		segs, _ := c2.spool.segments()
		return len(segs) == 0
	})
}

// The spool stays within its size: past it the oldest events go (and are counted as dropped), the newest stay.
func TestSpoolIsBounded(t *testing.T) {
	s, err := newSpool(t.TempDir(), 1) // 1 MB
	if err != nil {
		t.Fatal(err)
	}
	line := []byte(`{"id":"x","pad":"` + strings.Repeat("a", 1000) + `"}` + "\n")
	batch := bytes.Repeat(line, 100) // ~100 KB
	evicted := 0
	for range 40 {
		ev, err := s.store(batch)
		if err != nil {
			t.Fatal(err)
		}
		evicted += len(ev)
	}
	segs, total := s.segments()
	if total > 1<<20+int64(segmentMax) || len(segs) == 0 {
		t.Fatalf("spool holds %d bytes in %d segments", total, len(segs))
	}
	if evicted == 0 || evicted%100 != 0 {
		t.Fatalf("evicted %d events", evicted)
	}
}

// A line torn by a crash while it was written is skipped on replay; the complete ones are sent.
func TestSpoolSkipsTornLines(t *testing.T) {
	s, err := newSpool(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store([]byte("{\"id\":\"a\"}\n{\"id\":\"b\"}\n{\"id\":")); err != nil {
		t.Fatal(err)
	}
	name, body, _, _ := s.oldest()
	if name == "" || string(body) != "{\"id\":\"a\"}\n{\"id\":\"b\"}\n" {
		t.Fatalf("replayed %q", body)
	}
}

// A spool directory that cannot be written is refused at startup.
func TestSpoolDirMustBeWritable(t *testing.T) {
	f := t.TempDir() + "/file"
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := New("http://127.0.0.1:1", "n1", logger.NewNullLogger())
	if err := c.Spool(f+"/spool", 0); err == nil {
		t.Fatal("a spool under a file was accepted")
	}
}

// capture is a logger that records Error lines (through With and WithGroup too).
type capture struct {
	mu     *sync.Mutex
	errors *[][]any // message, then key-value pairs
}

func newCapture() capture { return capture{mu: &sync.Mutex{}, errors: &[][]any{}} }

func (c capture) Trace(string, ...any) {}
func (c capture) Debug(string, ...any) {}
func (c capture) Info(string, ...any)  {}
func (c capture) Warn(string, ...any)  {}
func (c capture) Fatal(string, ...any) {}
func (c capture) Error(msg string, kv ...any) {
	c.mu.Lock()
	*c.errors = append(*c.errors, append([]any{msg}, kv...))
	c.mu.Unlock()
}
func (c capture) With(string, any) logger.Logger { return c }
func (c capture) WithError(error) logger.Logger  { return c }
func (c capture) WithGroup(string) logger.Logger { return c }

// undeliveredIDs returns the event ids logged as audit.undelivered.
func (c capture) undeliveredIDs() map[string]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]bool{}
	for _, e := range *c.errors {
		if e[0] != "audit.undelivered" {
			continue
		}
		for i := 1; i+1 < len(e); i += 2 {
			if e[i] == "event" {
				if ev, ok := e[i+1].(map[string]any); ok {
					out[fmt.Sprint(ev["id"])] = true
				}
			}
		}
	}
	return out
}

// Events VictoriaLogs will never get go to the structured log in full, as audit.undelivered: without a spool once
// the retries are spent, with one when the spool has to make room.
func TestUndeliveredEventsAreLoggedInFull(t *testing.T) {
	vl := newFakeVL(t) // down
	log := newCapture()
	c, _ := New(vl.srv.URL, "n1", log)
	c.Start()
	for i := range 3 {
		c.WriteAudit(event(i))
	}
	waitFor(t, "the events to be logged as undelivered", func() bool { return len(log.undeliveredIDs()) == 3 })
	c.Close()
	if ids := log.undeliveredIDs(); !ids["ev-00000"] || !ids["ev-00002"] {
		t.Fatalf("logged %v", ids)
	}

	s, err := newSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	log2 := newCapture()
	c2, _ := New(vl.srv.URL, "n1", log2)
	c2.spool = s
	pad := strings.Repeat("a", 1000)
	for i := range 2000 { // ~2 MB through a 1 MB spool
		b, _ := json.Marshal(map[string]any{"id": fmt.Sprintf("ev-%05d", i), "pad": pad})
		c2.toSpool(append(b, '\n'))
	}
	ids := log2.undeliveredIDs()
	if len(ids) == 0 || !ids["ev-00000"] || ids["ev-01999"] {
		t.Fatalf("evicted and logged: %d (oldest %v, newest %v)", len(ids), ids["ev-00000"], ids["ev-01999"])
	}
}

// A spool disk that does not answer must not stall the request writing the event: after spoolWait the event is
// logged in full instead, and WriteAudit returns.
func TestWriteAuditWaitIsBounded(t *testing.T) {
	defer func(d time.Duration) { spoolWait = d }(spoolWait)
	spoolWait = 50 * time.Millisecond
	log := newCapture()
	c, err := New("http://example.invalid", "n1", log)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Spool(t.TempDir(), 1); err != nil {
		t.Fatal(err)
	}
	// Not started: nothing takes the event to disk, as with a hung disk.
	start := time.Now()
	c.WriteAudit(event(7))
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("WriteAudit waited %s", d)
	}
	if !log.undeliveredIDs()[event(7).ID] {
		t.Fatal("the event was neither spooled nor logged")
	}
}
