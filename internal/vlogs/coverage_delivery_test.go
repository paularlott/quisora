package vlogs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/logger"
)

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

// counting is an insert endpoint answering status and counting its requests.
func counting(t *testing.T, status *atomic.Int32, requests *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(int(status.Load()))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestReplayWithoutSpoolDoesNothing(t *testing.T) {
	c, _ := New("http://127.0.0.1:1", "n1", logger.NewNullLogger())
	c.replay()
	if c.spooling || !c.retryAt.IsZero() {
		t.Fatal("state changed")
	}
}

// A failed replay holds VictoriaLogs off, doubling the wait up to maxBackoff, until a delivery resets it.
func TestReplayBackoffAndRecovery(t *testing.T) {
	var status, requests atomic.Int32
	status.Store(http.StatusServiceUnavailable)
	srv := counting(t, &status, &requests)
	c := spooled(t, srv.URL, logger.NewNullLogger())
	if _, err := c.spool.store(line("a")); err != nil {
		t.Fatal(err)
	}

	c.replay()
	if !c.spooling || c.backoff != minBackoff || time.Until(c.retryAt) <= 0 || requests.Load() != 1 {
		t.Fatalf("after one failure: spooling %v backoff %v requests %d", c.spooling, c.backoff, requests.Load())
	}
	c.replay() // inside the hold-off: no request
	if requests.Load() != 1 {
		t.Fatalf("replayed during the back-off: %d requests", requests.Load())
	}
	want := minBackoff
	for range 8 {
		c.retryAt = time.Time{}
		c.replay()
		want = min(want*2, maxBackoff)
		if c.backoff != want {
			t.Fatalf("backoff %v, want %v", c.backoff, want)
		}
	}
	if c.backoff != maxBackoff {
		t.Fatalf("backoff did not cap: %v", c.backoff)
	}
	if c.spool.empty() {
		t.Fatal("a failed segment was removed")
	}

	status.Store(http.StatusOK)
	c.retryAt = time.Time{}
	c.replay()
	if !c.spool.empty() || c.spooling || c.backoff != 0 || !c.retryAt.IsZero() {
		t.Fatalf("after recovery: empty %v spooling %v backoff %v", c.spool.empty(), c.spooling, c.backoff)
	}
}

// A tick replays at most replayPerTick segments, so a backlog does not starve new events.
func TestReplayPerTickLimit(t *testing.T) {
	var status, requests atomic.Int32
	status.Store(http.StatusOK)
	srv := counting(t, &status, &requests)
	c := spooled(t, srv.URL, logger.NewNullLogger())
	const segs = replayPerTick + 4
	for i := range segs {
		if _, err := c.spool.store(line(fmt.Sprint("e", i))); err != nil {
			t.Fatal(err)
		}
		c.spool.seal()
	}
	c.replay()
	if left, _ := c.spool.segments(); len(left) != 4 || requests.Load() != replayPerTick {
		t.Fatalf("%d segments left, %d requests", len(left), requests.Load())
	}
	c.replay()
	if !c.spool.empty() {
		t.Fatal("the backlog did not drain on the next tick")
	}
}

// Close ending a request in flight is not a VictoriaLogs failure: no back-off, nothing logged as an outage.
func TestReplayInterruptedByCloseIsNotAnOutage(t *testing.T) {
	var c *Client
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.cancel()
		<-release
	}))
	defer srv.Close()
	defer close(release)
	c = spooled(t, srv.URL, logger.NewNullLogger())
	if _, err := c.spool.store(line("a")); err != nil {
		t.Fatal(err)
	}
	c.replay()
	if c.spooling || c.backoff != 0 || c.spool.empty() {
		t.Fatalf("spooling %v backoff %v empty %v", c.spooling, c.backoff, c.spool.empty())
	}
	// Once closed, replay does not even try.
	c.replay()
}

func TestReplayWaitsForRetryTime(t *testing.T) {
	var status, requests atomic.Int32
	status.Store(http.StatusOK)
	srv := counting(t, &status, &requests)
	c := spooled(t, srv.URL, logger.NewNullLogger())
	if _, err := c.spool.store(line("a")); err != nil {
		t.Fatal(err)
	}
	c.retryAt = time.Now().Add(time.Hour)
	c.replay()
	if requests.Load() != 0 || c.spool.empty() {
		t.Fatalf("replayed before its time: %d requests", requests.Load())
	}
}

func TestSendAtShutdownAndWhenClosed(t *testing.T) {
	vl := newFakeVL(t)
	log := newCapture()
	c, _ := New(vl.srv.URL, "n1", log)
	defer c.cancel()
	body := func(i int) [][]byte { b, _ := json.Marshal(c.row(event(i))); return [][]byte{b} }

	c.closing = true // Close is waiting: one short try, then the structured log
	vl.set(true)
	c.send(body(1))
	if d, _ := vl.count(); d != 1 || len(log.undeliveredIDs()) != 0 {
		t.Fatalf("delivered %d, logged %v", d, log.undeliveredIDs())
	}
	vl.set(false)
	c.send(body(2))
	if ids := log.undeliveredIDs(); len(ids) != 1 || !ids["ev-00002"] {
		t.Fatalf("shutdown failure logged %v", ids)
	}

	// Without the shutdown flag, a context already cancelled gives up after the first failure instead of retrying.
	c.closing = false
	c.cancel()
	start := time.Now()
	c.send(body(3))
	if ids := log.undeliveredIDs(); !ids["ev-00003"] || time.Since(start) > 5*time.Second {
		t.Fatalf("cancelled send logged %v after %v", ids, time.Since(start))
	}
}

// Events queued before Close are all sent: a full batch is flushed at once, the rest when the queue closes.
func TestRunFlushesFullBatchesAndTheRest(t *testing.T) {
	vl := newFakeVL(t)
	vl.set(true)
	c, _ := New(vl.srv.URL, "n1", logger.NewNullLogger())
	defer c.cancel()
	const n = batchSize + 7
	for i := range n {
		b, _ := json.Marshal(c.row(event(i)))
		c.queue <- b
	}
	close(c.queue)
	c.run() // returns once the queue is closed and flushed
	if d, total := vl.count(); d != n || total != n {
		t.Fatalf("%d distinct, %d total of %d", d, total, n)
	}
	select {
	case <-c.done:
	default:
		t.Fatal("run did not signal done")
	}
}

// The spooler writes everything waiting in one go and releases each writer, also when the queue closes meanwhile.
func TestSpoolerGroupCommitReleasesWriters(t *testing.T) {
	c := spooled(t, "http://127.0.0.1:1", logger.NewNullLogger())
	var dones []chan struct{}
	for i := range 3 {
		cm := commit{line: line(fmt.Sprint("e", i)), done: make(chan struct{})}
		dones = append(dones, cm.done)
		c.commits <- cm
	}
	close(c.commits)
	c.spooler()
	for i, d := range dones {
		select {
		case <-d:
		default:
			t.Fatalf("writer %d not released", i)
		}
	}
	_, body, _, _ := c.spool.oldest()
	if got := strings.Join(ids(body), ","); got != "e0,e1,e2" {
		t.Fatalf("spooled %q", got)
	}
}

// An event written after Close (the queue or the commit channel is closed) is logged in full, not lost or panicking.
func TestWriteAuditAfterClose(t *testing.T) {
	for _, withSpool := range []bool{false, true} {
		t.Run(fmt.Sprint("spool=", withSpool), func(t *testing.T) {
			log := newCapture()
			c, _ := New("http://127.0.0.1:1", "n1", log)
			if withSpool {
				if err := c.Spool(t.TempDir(), 0); err != nil {
					t.Fatal(err)
				}
			}
			c.Close()
			c.Close() // idempotent
			c.WriteAudit(event(5))
			if ids := log.undeliveredIDs(); !ids["ev-00005"] {
				t.Fatalf("logged %v", ids)
			}
		})
	}
}

func TestUndeliveredLogsUnparseableLineRaw(t *testing.T) {
	log := newCapture()
	c, _ := New("http://127.0.0.1:1", "n1", log)
	defer c.cancel()
	c.undelivered("test", nil) // nothing: no log, no count
	c.undelivered("test", [][]byte{[]byte("not json at all")})
	log.mu.Lock()
	defer log.mu.Unlock()
	for _, e := range *log.errors {
		if e[0] != "audit.undelivered" {
			continue
		}
		for i := 1; i+1 < len(e); i += 2 {
			if ev, ok := e[i+1].(map[string]any); e[i] == "event" && ok && ev["raw"] == "not json at all" {
				return
			}
		}
	}
	t.Fatalf("raw line not logged: %v", *log.errors)
}

func TestPostAndQueryRequestErrors(t *testing.T) {
	c, _ := New("http://127.0.0.1:1", "n1", logger.NewNullLogger())
	defer c.cancel()
	if err := c.post("http://127.0.0.1/\x7f", nil); err == nil {
		t.Fatal("a URL with a control character was posted to")
	}
	var nilCtx context.Context
	if _, err := c.query(nilCtx, "x"); err == nil {
		t.Fatal("query without a context succeeded")
	}
}

// A result line longer than the scanner's limit is an error, not a truncated page.
func TestQueryLineTooLong(t *testing.T) {
	f := newFakeSelect(t, func(string, http.ResponseWriter) {})
	f.respond = func(_ string, w http.ResponseWriter) { _, _ = w.Write(bytes.Repeat([]byte("a"), 5<<20)) }
	c := newReader(t, f.srv.URL)
	if _, err := c.query(context.Background(), "x"); err == nil {
		t.Fatal("a 5 MB line was accepted")
	}
}
