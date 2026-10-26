package vlogs

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/logger"
)

// Replay sends nothing when it is not due: without a spool, before the retry time after a failure, and once Close has
// ended the client.
func TestReplayDoesNothingWhenNotDue(t *testing.T) {
	cases := []struct {
		name  string
		setup func(c *Client)
	}{
		{"no spool", func(c *Client) { c.spool = nil }},
		{"before the retry time", func(c *Client) { c.retryAt = time.Now().Add(time.Hour) }},
		{"closed", func(c *Client) { c.cancel() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vl := newFakeVL(t)
			vl.set(true)
			c := spooled(t, vl.srv.URL, logger.NewNullLogger())
			if _, err := c.spool.store(line("a")); err != nil {
				t.Fatal(err)
			}
			tc.setup(c)
			retryAt := c.retryAt
			c.replay()
			if vl.requestCount() != 0 || c.spooling || !c.retryAt.Equal(retryAt) {
				t.Fatalf("replayed: %d requests, spooling %v", vl.requestCount(), c.spooling)
			}
		})
	}
}

// A segment VictoriaLogs does not take for a reason other than its content is an outage: a server error, or wrong
// credentials (every segment would be refused alike). The spool keeps every segment, nothing is logged as
// undelivered, and replay holds off, doubling the wait up to maxBackoff, until a delivery resets it and the backlog
// is sent.
func TestReplayBackoffAndRecovery(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusUnauthorized} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			vl := newFakeVL(t)
			vl.setDownStatus(status)
			log := newCapture()
			c := spooled(t, vl.srv.URL, log)
			for _, id := range []string{"a", "b"} {
				if _, err := c.spool.store(line(id)); err != nil {
					t.Fatal(err)
				}
				c.spool.seal()
			}

			c.replay()
			if !c.spooling || c.backoff != minBackoff || time.Until(c.retryAt) <= 0 || vl.requestCount() != 1 {
				t.Fatalf("after one failure: spooling %v backoff %v requests %d", c.spooling, c.backoff, vl.requestCount())
			}
			c.replay() // inside the hold-off: no request
			if vl.requestCount() != 1 {
				t.Fatalf("replayed during the back-off: %d requests", vl.requestCount())
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
			if segs, _ := c.spool.segments(); len(segs) != 2 || len(log.undelivered()) != 0 {
				t.Fatalf("an outage dropped events: %d segments left, logged %v", len(segs), log.undelivered())
			}

			vl.set(true)
			c.retryAt = time.Time{}
			c.replay()
			if !c.spool.empty() || c.spooling || c.backoff != 0 || !c.retryAt.IsZero() {
				t.Fatalf("after recovery: empty %v spooling %v backoff %v", c.spool.empty(), c.spooling, c.backoff)
			}
			if !vl.took("a") || !vl.took("b") {
				t.Fatal("the backlog was not delivered after recovery")
			}
		})
	}
}

// A tick replays at most replayPerTick segments, so a backlog does not starve new events.
func TestReplayPerTickLimit(t *testing.T) {
	vl := newFakeVL(t)
	vl.set(true)
	c := spooled(t, vl.srv.URL, logger.NewNullLogger())
	const segs = replayPerTick + 4
	for i := range segs {
		if _, err := c.spool.store(line(fmt.Sprint("e", i))); err != nil {
			t.Fatal(err)
		}
		c.spool.seal()
	}
	c.replay()
	if left, _ := c.spool.segments(); len(left) != 4 || vl.requestCount() != replayPerTick {
		t.Fatalf("%d segments left, %d requests", len(left), vl.requestCount())
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
}

// A segment VictoriaLogs rejects for its content (400, 413, 422: it will never take it) must not hold back the
// segments after it: its events are logged in full as audit.undelivered and it leaves the spool. Wrong credentials
// (401) are an outage instead (TestReplayBackoffAndRecovery).
func TestReplayRejectedSegmentDoesNotBlockLaterOnes(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			vl := newFakeVL(t)
			vl.set(true)
			vl.setReject("poison", status)
			log := newCapture()
			c := spooled(t, vl.srv.URL, log)
			for _, id := range []string{"poison", "good-1", "good-2"} {
				if _, err := c.spool.store(line(id)); err != nil {
					t.Fatal(err)
				}
				c.spool.seal()
			}
			c.replay()
			if !vl.took("good-1") || !vl.took("good-2") || vl.took("poison") {
				t.Fatal("later segments not delivered after a rejected one")
			}
			got := log.undelivered()
			if len(got) != 1 || got[0].event["id"] != "poison" || !strings.Contains(got[0].reason, "rejected") {
				t.Fatalf("the rejected event was not logged in full: %v", got)
			}
			if !strings.HasSuffix(got[0].reason, "x…") || len(got[0].reason) > 500 {
				t.Fatalf("VictoriaLogs' answer not cut short in the log: %q", got[0].reason)
			}
			if !c.spool.empty() || c.spooling || c.backoff != 0 {
				t.Fatalf("a rejection was taken for an outage: empty %v spooling %v backoff %v", c.spool.empty(), c.spooling, c.backoff)
			}
		})
	}
}

// A complete line (newline-terminated) that is not JSON is not a crash's torn tail: it can never be delivered, so it
// is logged in full as audit.undelivered, and the valid lines around it are sent.
func TestReplayLogsNonJSONLineAndSendsTheRest(t *testing.T) {
	vl := newFakeVL(t)
	vl.set(true)
	log := newCapture()
	c := spooled(t, vl.srv.URL, log)
	if _, err := c.spool.store([]byte("{\"id\":\"a\"}\nthis is not json\n{\"id\":\"b\"}\n")); err != nil {
		t.Fatal(err)
	}
	c.replay()
	if d, _ := vl.count(); d != 2 || !c.spool.empty() {
		t.Fatalf("valid lines delivered: %d, spool empty %v", d, c.spool.empty())
	}
	got := log.undelivered()
	if len(got) != 1 || got[0].event["raw"] != "this is not json" || !strings.Contains(got[0].reason, "not JSON") {
		t.Fatalf("the invalid line was not logged in full: %v", got)
	}
}

// With a spool, events written while VictoriaLogs is down are kept on disk and sent once it is back, also after a
// restart of the writer; nothing is left in the spool afterwards.
func TestSpoolKeepsEventsThroughAnOutage(t *testing.T) {
	fastTimers(t)
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
