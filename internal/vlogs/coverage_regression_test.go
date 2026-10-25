package vlogs

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/service"
)

// A segment VictoriaLogs rejects for its content (400, 413, 422: it will never take it) must not hold back the
// segments after it: its events are logged in full as audit.undelivered and it leaves the spool. Wrong credentials
// (401) are an outage instead: every segment would be refused alike, so all of them wait for the fix
// (TestReplayHoldsOnRefusedCredentials).
func TestReplayRejectedSegmentDoesNotBlockLaterOnes(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var mu sync.Mutex
			got := map[string]bool{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sc := bufio.NewScanner(r.Body)
				var lines []string
				for sc.Scan() {
					lines = append(lines, sc.Text())
				}
				all := strings.Join(lines, "\n")
				if strings.Contains(all, `"poison"`) {
					w.WriteHeader(status)
					return
				}
				mu.Lock()
				for _, id := range ids([]byte(all + "\n")) {
					got[id] = true
				}
				mu.Unlock()
			}))
			defer srv.Close()
			log := newCapture()
			c := spooled(t, srv.URL, log)
			for _, id := range []string{"poison", "good-1", "good-2"} {
				if _, err := c.spool.store(line(id)); err != nil {
					t.Fatal(err)
				}
				c.spool.seal()
			}
			for range 5 { // several ticks, past any back-off
				c.retryAt = time.Time{}
				c.replay()
			}
			mu.Lock()
			defer mu.Unlock()
			if !got["good-1"] || !got["good-2"] {
				t.Fatalf("later segments not delivered: %v", got)
			}
			if ids := log.undeliveredIDs(); len(ids) != 1 || !ids["poison"] {
				t.Fatalf("the rejected event was not logged in full: %v", ids)
			}
			if !c.spool.empty() {
				t.Fatal("the spool kept segments")
			}
		})
	}
}

// Wrong credentials refuse every segment alike: an outage, not a rejection. Nothing is dropped from the spool, and
// everything is delivered once the credentials are fixed.
func TestReplayHoldsOnRefusedCredentials(t *testing.T) {
	var mu sync.Mutex
	refuse := true
	got := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if refuse {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		got++
	}))
	defer srv.Close()
	log := newCapture()
	c := spooled(t, srv.URL, log)
	for _, id := range []string{"a", "b"} {
		if _, err := c.spool.store(line(id)); err != nil {
			t.Fatal(err)
		}
		c.spool.seal()
	}
	c.retryAt = time.Time{}
	c.replay()
	if c.spool.empty() || len(log.undeliveredIDs()) != 0 {
		t.Fatal("a credentials refusal dropped events")
	}
	mu.Lock()
	refuse = false
	mu.Unlock()
	c.retryAt = time.Time{}
	c.replay()
	mu.Lock()
	defer mu.Unlock()
	if got != 2 || !c.spool.empty() {
		t.Fatalf("after the fix: %d segments delivered, spool empty=%v", got, c.spool.empty())
	}
}

// VictoriaLogs holds an event twice when it was delivered twice (at-least-once: a crash mid-replay, or an event logged
// and spooled after a slow disk), and docs/RUNNING.md says every event has a unique id "for removing duplicates when
// reading": a page must not show the same event twice.
func TestReadAuditRemovesDuplicatesByID(t *testing.T) {
	row := `{"_time":"2026-01-02T03:04:05Z","id":"dup-1","org":"o","action":"user.update","actor":"a","outcome":"success"}` + "\n"
	other := `{"_time":"2026-01-02T03:04:06Z","id":"other","org":"o","action":"user.update","actor":"a","outcome":"success"}` + "\n"
	f := newFakeSelect(t, answer(row+row+other, `{"n":"3"}`+"\n"))
	c := newReader(t, f.srv.URL)
	page, err := c.ReadAudit(context.Background(), service.AuditQuery{Org: "o", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, it := range page.Items {
		seen[it.ID]++
	}
	if seen["dup-1"] != 1 || seen["other"] != 1 {
		t.Fatalf("events by id: %v (total %d)", seen, page.Total)
	}
}

// A complete line (newline-terminated) that is not valid JSON is not a crash's torn tail: it cannot be delivered, and
// the audit trail's promise is that every event not delivered is logged in full as audit.undelivered. It is dropped
// without a trace instead, and the valid lines around it are sent.
func TestSpoolInvalidCompleteLineIsLoggedNotDroppedSilently(t *testing.T) {
	vl := newFakeVL(t)
	vl.set(true)
	log := newCapture()
	c := spooled(t, vl.srv.URL, log)
	if _, err := c.spool.store([]byte("{\"id\":\"a\"}\nthis is not json\n{\"id\":\"b\"}\n")); err != nil {
		t.Fatal(err)
	}
	c.replay()
	if d, _ := vl.count(); d != 2 {
		t.Fatalf("valid lines delivered: %d", d)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	for _, e := range *log.errors {
		if e[0] == "audit.undelivered" {
			return
		}
	}
	t.Fatalf("the invalid line left no trace: %v", *log.errors)
}
