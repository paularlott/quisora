package vlogs

import (
	"bufio"
	"encoding/json"
	"errors"
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
)

// fastTimers shortens the writer's flush tick and its first retry wait for one test, so delivery and retries happen
// in milliseconds instead of seconds.
func fastTimers(t *testing.T) {
	t.Helper()
	flush, retry := flushEvery, firstRetryWait
	flushEvery, firstRetryWait = 10*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { flushEvery, firstRetryWait = flush, retry })
}

// fakeVL is a VictoriaLogs insert endpoint. It can be switched off (it then answers downStatus, 503 unless set), and
// refuses a request holding the event id reject with rejectStatus, as VictoriaLogs refuses content it will never
// take. It counts the requests and the events it took.
type fakeVL struct {
	mu           sync.Mutex
	up           bool
	downStatus   int
	reject       string
	rejectStatus int
	requests     int
	ids          map[string]int
	srv          *httptest.Server
}

func newFakeVL(t *testing.T) *fakeVL {
	f := &fakeVL{ids: map[string]int{}, downStatus: http.StatusServiceUnavailable}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests++
		if !f.up {
			http.Error(w, "down", f.downStatus)
			return
		}
		var got []string
		sc := bufio.NewScanner(r.Body)
		for sc.Scan() {
			var row map[string]any
			if json.Unmarshal(sc.Bytes(), &row) == nil {
				got = append(got, row["id"].(string))
			}
		}
		for _, id := range got {
			if f.reject != "" && id == f.reject {
				http.Error(w, "rejected: "+strings.Repeat("x", 400), f.rejectStatus) // longer than a log line takes
				return
			}
		}
		for _, id := range got {
			f.ids[id]++
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeVL) set(up bool) { f.mu.Lock(); f.up = up; f.mu.Unlock() }

func (f *fakeVL) setDownStatus(status int) { f.mu.Lock(); f.downStatus = status; f.mu.Unlock() }

func (f *fakeVL) setReject(id string, status int) {
	f.mu.Lock()
	f.reject, f.rejectStatus = id, status
	f.mu.Unlock()
}

func (f *fakeVL) count() (distinct, total int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.ids {
		distinct++
		total += n
	}
	return
}

func (f *fakeVL) took(id string) bool { f.mu.Lock(); defer f.mu.Unlock(); return f.ids[id] > 0 }

func (f *fakeVL) requestCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.requests }

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

// The LogsQL ReadAudit appends to the filter: the count of a page, and the de-duplication by id before the page is cut.
const (
	countSuffix = " | stats count_uniq(id) n"
	dedup       = " | sort by (_time desc) partition by (id) limit 1"
)

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

// spooled is a client with a spool in a temporary directory, not started: the tests call replay, spooler and the
// like themselves, so nothing else touches the spool or the delivery state.
func spooled(t *testing.T, base string, log logger.Logger) *Client {
	t.Helper()
	c, err := New(base, "n1", log)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Spool(t.TempDir(), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.cancel)
	return c
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

// undeliveredEvent is one audit.undelivered line: why the event was not delivered, and the event as logged.
type undeliveredEvent struct {
	reason string
	event  map[string]any
}

// undelivered returns the audit.undelivered lines, in order.
func (c capture) undelivered() []undeliveredEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []undeliveredEvent
	for _, e := range *c.errors {
		if e[0] != "audit.undelivered" {
			continue
		}
		var u undeliveredEvent
		for i := 1; i+1 < len(e); i += 2 {
			switch e[i] {
			case "reason":
				u.reason, _ = e[i+1].(string)
			case "event":
				u.event, _ = e[i+1].(map[string]any)
			}
		}
		out = append(out, u)
	}
	return out
}

// undeliveredIDs returns the event ids logged as audit.undelivered.
func (c capture) undeliveredIDs() map[string]bool {
	out := map[string]bool{}
	for _, u := range c.undelivered() {
		out[fmt.Sprint(u.event["id"])] = true
	}
	return out
}

func event(i int) *model.Audit {
	return &model.Audit{Meta: model.Meta{ID: fmt.Sprintf("ev-%05d", i), Created: time.Now()}, OrgID: "o", Action: "user.update"}
}

func line(id string) []byte { return []byte(fmt.Sprintf("{\"id\":%q}\n", id)) }

// ids returns the ids of the events in a replay body, in order.
func ids(body []byte) []string {
	var out []string
	for _, l := range jsonLines(body) {
		var ev struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(l, &ev)
		out = append(out, ev.ID)
	}
	return out
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func chmodFor(t *testing.T, path string, mode os.FileMode, restore os.FileMode) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not bind root")
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, restore) })
}

// faultFile is a segment whose disk fails on demand: a write that stores only the first short bytes before failing,
// an fsync that fails after the write, or a file that disappears as it is written (as if the disk or an operator
// removed it), so the failed append cannot be cut back.
type faultFile struct {
	segmentFile
	path     string
	short    int  // write only this many bytes, then fail (-1: write everything)
	syncFail bool // fsync fails
	vanish   bool // the file is removed before the write
}

func (f *faultFile) Write(b []byte) (int, error) {
	if f.vanish {
		_ = os.Remove(f.path)
	}
	if f.short < 0 {
		return f.segmentFile.Write(b)
	}
	n, _ := f.segmentFile.Write(b[:f.short])
	return n, errors.New("injected: disk full")
}

func (f *faultFile) Sync() error {
	if f.syncFail {
		return errors.New("injected: fsync failed")
	}
	return f.segmentFile.Sync()
}

// faults makes the next segment appends fail as told (one entry per append; nil: that append works), restoring the
// real disk afterwards.
func faults(t *testing.T, plan ...*faultFile) {
	t.Helper()
	real := openSegment
	t.Cleanup(func() { openSegment = real })
	i := 0
	openSegment = func(path string) (segmentFile, error) {
		f, err := real(path)
		if err != nil || i >= len(plan) || plan[i] == nil {
			i++
			return f, err
		}
		ff := plan[i]
		i++
		ff.segmentFile, ff.path = f, path
		return ff, nil
	}
}
