package vlogs

import (
	"encoding/json"
	"fmt"
	"math/bits"
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

// spoolLines stores events id-000 … id-(n-1) as one segment, as the spooler writes a moment's events of every
// organization together, and returns their ids.
func spoolLines(t *testing.T, c *Client, n int) []string {
	t.Helper()
	var body []byte
	var out []string
	for i := range n {
		id := fmt.Sprintf("id-%03d", i)
		body, out = append(body, line(id)...), append(out, id)
	}
	if _, err := c.spool.store(body); err != nil {
		t.Fatal(err)
	}
	c.spool.seal()
	return out
}

// One line VictoriaLogs refuses must not take the rest of its segment with it: the segment is sifted, every other
// line is delivered, and only the refused ones are logged (as audit.undelivered, with VictoriaLogs' answer). The
// sifting is bounded: a couple of bad lines among hundreds cost a few dozen requests, not one per line.
func TestReplayRejectedSegmentKeepsItsGoodLines(t *testing.T) {
	vl := newFakeVL(t)
	vl.set(true)
	vl.setRejects(http.StatusBadRequest, "id-050", "id-151")
	log := newCapture()
	c := spooled(t, vl.srv.URL, log)
	all := spoolLines(t, c, 200)
	c.replay()
	for _, id := range all {
		if bad := id == "id-050" || id == "id-151"; vl.took(id) == bad {
			t.Fatalf("%s: delivered %v", id, vl.took(id))
		}
	}
	got := log.undelivered()
	if len(got) != 2 || got[0].event["id"] != "id-050" || got[1].event["id"] != "id-151" ||
		!strings.Contains(got[0].reason, "rejected") {
		t.Fatalf("logged %v", got)
	}
	if n := vl.requestCount(); n > 1+siftPosts {
		t.Fatalf("%d requests to sift one segment", n)
	}
	if !c.spool.empty() || c.spooling || c.backoff != 0 {
		t.Fatalf("empty %v spooling %v backoff %v", c.spool.empty(), c.spooling, c.backoff)
	}
}

// A segment VictoriaLogs refuses wholesale is not sent line by line: no part of it is taken, so it earns no more
// than the siftPosts requests it starts with; the parts left then get one last request each (at most one per
// halving), and the rest is logged as a rejected segment always was, every line exactly once.
func TestReplaySiftingIsBounded(t *testing.T) {
	vl := newFakeVL(t)
	vl.set(true)
	vl.setReject("*", http.StatusUnprocessableEntity)
	log := newCapture()
	c := spooled(t, vl.srv.URL, log)
	all := spoolLines(t, c, 500)
	c.replay()
	if n := vl.requestCount(); n < 1+siftPosts || n > 1+siftPosts+bits.Len(uint(len(all)))+1 {
		t.Fatalf("%d requests, want %d and a last one for each part left", n, 1+siftPosts)
	}
	got := log.undelivered()
	if ids := log.undeliveredIDs(); len(got) != len(all) || len(ids) != len(all) {
		t.Fatalf("logged %d lines, %d distinct, of %d", len(got), len(ids), len(all))
	}
	if !c.spool.empty() || c.spooling {
		t.Fatal("a refused segment stayed in the spool")
	}
}

// spoolScattered stores n events as one segment, bad of them (spread evenly through it) ones VictoriaLogs refuses,
// and returns how many it refuses.
func spoolScattered(t *testing.T, c *Client, vl *fakeVL, n, bad int) int {
	t.Helper()
	var body []byte
	var refused []string
	for i := range n {
		id := fmt.Sprintf("ev-%05d", i)
		if i%(n/bad) == n/bad/2 && len(refused) < bad {
			refused = append(refused, id)
		}
		body = append(body, line(id)...)
	}
	vl.setRejects(http.StatusBadRequest, refused...)
	if _, err := c.spool.store(body); err != nil {
		t.Fatal(err)
	}
	c.spool.seal()
	return len(refused)
}

// A full segment with a few refused lines scattered through it loses those lines and no others: every part
// VictoriaLogs takes earns the requests that finding the next bad line costs, so the sifting does not run out part
// way and give up hundreds of good events with each bad one (with a fixed 64 requests, 4 bad lines among 3,000 lost
// 374 good events, and 12 lost 2,116). It stays far from a request per line.
func TestReplaySiftsScatteredRefusedLinesToTheEnd(t *testing.T) {
	const lines = 3000 // a full 1 MB segment holds some 2,000 to 3,500 events
	for _, bad := range []int{1, 4, 12, 20} {
		vl := newFakeVL(t)
		vl.set(true)
		log := newCapture()
		c := spooled(t, vl.srv.URL, log)
		refused := spoolScattered(t, c, vl, lines, bad)
		c.replay()
		if lost := len(log.undeliveredIDs()) - refused; lost != 0 {
			t.Fatalf("%d refused lines of %d: %d good events not delivered", refused, lines, lost)
		}
		if got, _ := vl.count(); got != lines-refused {
			t.Fatalf("%d refused lines of %d: %d delivered", refused, lines, got)
		}
		if n := vl.requestCount(); n > 1+siftMaxPosts {
			t.Fatalf("%d refused lines of %d: %d requests", refused, lines, n)
		}
	}
}

// Once the requests are spent, the parts left are posted once each and never halved again, even when one of that
// last pass is taken and earns its credit: the search is over, so it ends within the parts left. (A part taken in
// the last pass once earned requests that halved the next part again, past the bound.) Here, with one request to
// start with, 8 lines with id-000 and id-007 refused: the batch, then 0-3 (rejected, halved), then the last pass:
// 0-1 refused whole, 2-3 taken, 4-7 refused whole, not halved.
func TestReplaySiftingLastPassIsNotHalved(t *testing.T) {
	posts := siftPosts
	t.Cleanup(func() { siftPosts = posts })
	siftPosts = 1
	vl := newFakeVL(t)
	vl.set(true)
	vl.setRejects(http.StatusBadRequest, "id-000", "id-007")
	log := newCapture()
	c := spooled(t, vl.srv.URL, log)
	all := spoolLines(t, c, 8)
	c.replay()
	if n := vl.requestCount(); n != 5 {
		t.Fatalf("%d requests, want 5", n)
	}
	logged := log.undeliveredIDs()
	for i, id := range all {
		if refused := i != 2 && i != 3; logged[id] != refused || vl.took(id) == refused {
			t.Fatalf("%s: logged %v, delivered %v", id, logged[id], vl.took(id))
		}
	}
}

// The sifting is bounded whatever it earns: a segment with more refused lines than it has requests to find (one in
// every four here) runs out, and one whose search reaches siftMaxPosts (lowered here) stops there; either way with
// one last request for each part left. What that last request delivers is kept; only the parts that hold a refused
// line are given up, and every line is delivered or logged, none both.
func TestReplaySiftingRunsOutCleanly(t *testing.T) {
	const lines = 3000
	limit := siftMaxPosts
	t.Cleanup(func() { siftMaxPosts = limit })
	for _, tc := range []struct{ bad, ceiling int }{{lines / 4, limit}, {12, 40}} {
		siftMaxPosts = tc.ceiling
		vl := newFakeVL(t)
		vl.set(true)
		log := newCapture()
		c := spooled(t, vl.srv.URL, log)
		refused := spoolScattered(t, c, vl, lines, tc.bad)
		c.replay()
		if n := vl.requestCount(); n > 1+siftMaxPosts+bits.Len(uint(lines))+1 || (tc.ceiling < limit && n < tc.ceiling) {
			t.Fatalf("%d refused lines: %d requests with a ceiling of %d", refused, n, tc.ceiling)
		}
		logged := log.undeliveredIDs()
		got, total := vl.count()
		if got != total || got+len(logged) != lines || len(logged) <= refused {
			t.Fatalf("%d refused lines: delivered %d (%d sent), logged %d, of %d", refused, got, total, len(logged), lines)
		}
		for id := range logged {
			if vl.took(id) {
				t.Fatalf("%s was delivered and logged as undelivered", id)
			}
		}
		if !c.spool.empty() || c.spooling {
			t.Fatal("the segment stayed in the spool")
		}
	}
}

// VictoriaLogs going down while a segment is sifted is an outage, not a refusal: the sifting stops at once (no more
// requests to a server that is down), nothing is logged, and the segment stays for the back-off; once VictoriaLogs is
// back the segment is sent again (the lines already taken twice: at least once) and only the bad line is logged.
func TestReplayOutageWhileSiftingKeepsTheSegment(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusUnauthorized} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			vl := newFakeVL(t)
			vl.set(true)
			vl.setDownStatus(status)
			vl.setRejects(http.StatusBadRequest, "id-010")
			log := newCapture()
			c := spooled(t, vl.srv.URL, log)
			all := spoolLines(t, c, 100)
			vl.goDownAfter(3) // the whole segment and two halves, then down
			c.replay()
			if n := vl.requestCount(); n != 4 {
				t.Fatalf("%d requests, want 4 (the sifting must stop at the first outage answer)", n)
			}
			if got := log.undelivered(); len(got) != 0 {
				t.Fatalf("an outage logged %v", got)
			}
			if c.spool.empty() || !c.spooling || c.backoff == 0 {
				t.Fatalf("not taken for an outage: empty %v spooling %v backoff %v", c.spool.empty(), c.spooling, c.backoff)
			}
			vl.set(true)
			c.retryAt = time.Time{}
			c.replay()
			for _, id := range all {
				if vl.took(id) == (id == "id-010") {
					t.Fatalf("%s: delivered %v", id, vl.took(id))
				}
			}
			if ids := log.undeliveredIDs(); len(ids) != 1 || !ids["id-010"] || !c.spool.empty() {
				t.Fatalf("logged %v, spool empty %v", ids, c.spool.empty())
			}
		})
	}
}

// Without a spool (commands) a rejected batch is sifted the same way: only the refused line is logged.
func TestSendRejectedBatchKeepsItsGoodLines(t *testing.T) {
	vl := newFakeVL(t)
	vl.set(true)
	vl.setRejects(http.StatusBadRequest, "ev-00003")
	log := newCapture()
	c, _ := New(vl.srv.URL, "n1", log)
	defer c.cancel()
	var batch [][]byte
	for i := range 10 {
		b, _ := json.Marshal(c.row(event(i)))
		batch = append(batch, b)
	}
	c.send(batch)
	if d, _ := vl.count(); d != 9 || vl.took("ev-00003") {
		t.Fatalf("delivered %d", d)
	}
	if ids := log.undeliveredIDs(); len(ids) != 1 || !ids["ev-00003"] {
		t.Fatalf("logged %v", ids)
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
