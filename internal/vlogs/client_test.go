package vlogs

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/logger"
)

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

// A row carries the target's user id, request id, user agent and session id only when the event has them, every
// detail field, and always whether it is a super admin's event (the readers below super admin filter on false).
func TestRowOptionalFields(t *testing.T) {
	c := newReader(t, "http://127.0.0.1:1")
	e := event(1)
	r := c.row(e)
	if r["super_admin"] != "false" {
		t.Errorf("super_admin %v on an event of nobody's", r["super_admin"])
	}
	for _, k := range []string{"target_id", "request_id", "user_agent", "session_id"} {
		if _, ok := r[k]; ok {
			t.Errorf("%s present on a bare event", k)
		}
	}
	if r["node"] != "n1" || r["app"] != app || r["id"] != "ev-00001" || r["_msg"] != "audit user.update" {
		t.Fatalf("row %v", r)
	}
	e.RequestID, e.UserAgent, e.SessionID, e.Detail = "r", "ua", "s", map[string]string{"k": "v"}
	e.TargetID, e.SuperAdmin = "u2", true
	r = c.row(e)
	if r["request_id"] != "r" || r["user_agent"] != "ua" || r["session_id"] != "s" || r["detail.k"] != "v" ||
		r["target_id"] != "u2" || r["super_admin"] != "true" {
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
	l := line("a")
	if _, err := c.spool.store(l); err != nil {
		t.Fatal(err)
	}
	if got := c.SpoolBytes(); got != int64(len(l)) {
		t.Fatalf("spool holds %d bytes, want %d", got, len(l))
	}
}

// An event the queue has no room for goes to the structured log in full, and is counted as dropped.
func TestWriteAuditWithoutRoomIsLogged(t *testing.T) {
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
}

// An event written after Close (the queue or the commit channel is closed) is logged in full, not lost or panicking,
// with or without a spool and whether or not the writer ran.
func TestWriteAuditAfterClose(t *testing.T) {
	for _, withSpool := range []bool{false, true} {
		for _, started := range []bool{false, true} {
			t.Run(fmt.Sprintf("spool=%v started=%v", withSpool, started), func(t *testing.T) {
				log := newCapture()
				c, _ := New("http://127.0.0.1:1", "n1", log)
				if withSpool {
					if err := c.Spool(t.TempDir(), 0); err != nil {
						t.Fatal(err)
					}
				}
				if started {
					c.Start()
				}
				c.Close()
				c.Close() // idempotent
				c.WriteAudit(event(5))
				if ids := log.undeliveredIDs(); len(ids) != 1 || !ids["ev-00005"] {
					t.Fatalf("logged %v", ids)
				}
			})
		}
	}
}

// A spool disk that does not answer must not stall the request writing the event: after spoolWait the event is
// logged in full instead and WriteAudit returns. It is still spooled once the disk answers and reaches VictoriaLogs:
// it is then held twice (log and VictoriaLogs), never nowhere.
func TestWriteAuditTimedOutEventIsStillSpooled(t *testing.T) {
	fastTimers(t)
	defer func(d time.Duration) { spoolWait = d }(spoolWait)
	spoolWait = 50 * time.Millisecond
	vl := newFakeVL(t)
	vl.set(true)
	log := newCapture()
	c, err := New(vl.srv.URL, "n1", log)
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
		t.Fatal("the event was not logged after the wait")
	}
	c.Start() // the disk answers
	defer c.Close()
	waitFor(t, "the event to reach VictoriaLogs", func() bool { return vl.took(event(7).ID) })
}

// hungFile is a segment whose fsync does not return until hang is closed: a hung disk.
type hungFile struct {
	segmentFile
	hang chan struct{}
}

func (f hungFile) Sync() error { <-f.hang; return f.segmentFile.Sync() }

// A hung spool disk costs the first audited request spoolWait, not every one: once an event has waited in vain, the
// events after it are logged at once (and still queued for the spool) until the spooler finishes a write in time
// again; from then on events wait for their fsync again. Every event is logged or spooled, and all reach VictoriaLogs
// once the disk answers.
func TestWriteAuditFailsFastWhileTheSpoolDiskIsHung(t *testing.T) {
	fastTimers(t)
	wait, open := spoolWait, openSegment
	t.Cleanup(func() { spoolWait, openSegment = wait, open })
	spoolWait = 200 * time.Millisecond
	hang := make(chan struct{})
	var first sync.Once
	openSegment = func(path string) (segmentFile, error) {
		f, err := open(path)
		hung := false
		first.Do(func() { hung = true })
		if err != nil || !hung {
			return f, err
		}
		return hungFile{f, hang}, nil
	}
	vl := newFakeVL(t)
	vl.set(true)
	log := newCapture()
	c, err := New(vl.srv.URL, "n1", log)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Spool(t.TempDir(), 1); err != nil {
		t.Fatal(err)
	}
	c.Start()
	defer c.Close()
	var released sync.Once
	release := func() { released.Do(func() { close(hang) }) }
	defer release() // before Close, which waits for the spooler, also when the test fails

	start := time.Now()
	c.WriteAudit(event(1)) // waits spoolWait for the hung fsync
	if d := time.Since(start); d < spoolWait {
		t.Fatalf("the first event waited only %s", d)
	}
	start = time.Now()
	for i := 2; i <= 6; i++ {
		c.WriteAudit(event(i))
	}
	if d := time.Since(start); d >= spoolWait {
		t.Fatalf("five events took %s on a disk known to be hung: each waited again", d)
	}
	if ids := log.undeliveredIDs(); len(ids) != 6 {
		t.Fatalf("logged %v, want all six", ids)
	}

	release() // the disk answers: the hung write ends late, the backlog's write in time
	waitFor(t, "the disk to be taken as answering", func() bool { return !c.diskStuck.Load() })
	c.WriteAudit(event(7))
	if ids := log.undeliveredIDs(); ids[event(7).ID] {
		t.Fatal("an event was logged although the disk answers again")
	}
	waitFor(t, "every event to reach VictoriaLogs", func() bool {
		d, _ := vl.count()
		return d == 7
	})
}

// slowFile is a segment whose fsync takes delay: a disk that answers, slowly.
type slowFile struct {
	segmentFile
	delay time.Duration
}

func (f slowFile) Sync() error { time.Sleep(f.delay); return f.segmentFile.Sync() }

// A disk that is slow but answers must not flap between the fast path and waiting. An event queued while one write
// is under way waits for that write and its own: longer than spoolWait, though each write is shorter. That raises
// the flag, and the write that carried the event, short as it was, must not lower it again (it kept an event
// waiting too long: the next would wait in vain again, and each round would log a warning, an all-clear and a run
// of false audit.undelivered). The fast path ends when an event is on disk within spoolWait of being queued.
func TestSlowSpoolDiskDoesNotFlap(t *testing.T) {
	fastTimers(t)
	wait, open := spoolWait, openSegment
	t.Cleanup(func() { spoolWait, openSegment = wait, open })
	spoolWait = 400 * time.Millisecond
	openSegment = func(path string) (segmentFile, error) {
		f, err := open(path)
		if err != nil {
			return f, err
		}
		return slowFile{f, 300 * time.Millisecond}, nil
	}
	vl := newFakeVL(t)
	vl.set(true)
	log := newCapture()
	c, err := New(vl.srv.URL, "n1", log)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Spool(t.TempDir(), 1); err != nil {
		t.Fatal(err)
	}
	c.Start()
	defer c.Close()

	var first sync.WaitGroup
	defer first.Wait()
	first.Go(func() { c.WriteAudit(event(1)) }) // its write takes 300 ms: in time
	time.Sleep(100 * time.Millisecond)          // queued behind it: 200 ms of that write, then 300 ms of its own
	c.WriteAudit(event(2))
	if !c.diskStuck.Load() || !log.undeliveredIDs()[event(2).ID] {
		t.Fatal("an event that waited longer than spoolWait did not start the fast path")
	}
	time.Sleep(300 * time.Millisecond) // its write has ended by now, within spoolWait of starting
	if !c.diskStuck.Load() {
		t.Fatal("the write that kept an event waiting too long ended the fast path: the disk would flap")
	}
	c.WriteAudit(event(3)) // not waited for; on disk 300 ms after it was queued, which is in time
	waitFor(t, "the disk to be taken as answering", func() bool { return !c.diskStuck.Load() })
	c.WriteAudit(event(4))
	if log.undeliveredIDs()[event(4).ID] {
		t.Fatal("an event was logged although the disk answers in time again")
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

// At shutdown (Close is waiting) a batch is tried once, briefly: taken, or logged in full. Outside shutdown, a
// context already cancelled gives up after the first failure instead of retrying.
func TestSendAtShutdownTriesOnceThenLogs(t *testing.T) {
	vl := newFakeVL(t)
	body := func(c *Client, i int) [][]byte { b, _ := json.Marshal(c.row(event(i))); return [][]byte{b} }
	t.Run("shutdown", func(t *testing.T) {
		log := newCapture()
		c, _ := New(vl.srv.URL, "n1", log)
		defer c.cancel()
		c.closing = true
		vl.set(true)
		c.send(body(c, 1))
		if !vl.took("ev-00001") || len(log.undeliveredIDs()) != 0 {
			t.Fatalf("delivered %v, logged %v", vl.took("ev-00001"), log.undeliveredIDs())
		}
		vl.set(false)
		before := vl.requestCount()
		c.send(body(c, 2))
		if ids := log.undeliveredIDs(); len(ids) != 1 || !ids["ev-00002"] || vl.requestCount() != before+1 {
			t.Fatalf("shutdown failure: logged %v after %d tries", ids, vl.requestCount()-before)
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		vl.set(false)
		log := newCapture()
		c, _ := New(vl.srv.URL, "n1", log)
		c.cancel()
		start := time.Now()
		c.send(body(c, 3))
		if ids := log.undeliveredIDs(); !ids["ev-00003"] || time.Since(start) > 5*time.Second {
			t.Fatalf("cancelled send logged %v after %v", ids, time.Since(start))
		}
	})
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

// Events VictoriaLogs will never get go to the structured log in full, as audit.undelivered: without a spool once
// the retries are spent, with one when the spool has to make room.
func TestUndeliveredEventsAreLoggedInFull(t *testing.T) {
	fastTimers(t)
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
	if n := vl.requestCount(); n == 0 || n%maxRetries != 0 { // each batch is tried maxRetries times
		t.Fatalf("%d tries, want a multiple of %d", n, maxRetries)
	}

	s, err := newSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	log2 := newCapture()
	c2, _ := New(vl.srv.URL, "n1", log2)
	c2.spool = s
	pad := strings.Repeat("a", 1000)
	var batch []byte
	for i := range 2000 { // ~2 MB through a 1 MB spool, in batches of 100 (as the spooler writes them)
		b, _ := json.Marshal(map[string]any{"id": fmt.Sprintf("ev-%05d", i), "pad": pad})
		if batch = append(append(batch, b...), '\n'); (i+1)%100 == 0 {
			c2.toSpool(batch)
			batch = nil
		}
	}
	ids := log2.undeliveredIDs()
	if len(ids) == 0 || !ids["ev-00000"] || ids["ev-01999"] {
		t.Fatalf("evicted and logged: %d (oldest %v, newest %v)", len(ids), ids["ev-00000"], ids["ev-01999"])
	}
}

// A line that is not JSON is logged raw; nothing to log logs nothing.
func TestUndeliveredLogsUnparseableLineRaw(t *testing.T) {
	log := newCapture()
	c, _ := New("http://127.0.0.1:1", "n1", log)
	defer c.cancel()
	c.undelivered("test", nil)
	c.undelivered("test", [][]byte{[]byte("not json at all")})
	if got := log.undelivered(); len(got) != 1 || got[0].event["raw"] != "not json at all" || got[0].reason != "test" {
		t.Fatalf("logged %v", got)
	}
}

// With a disk that fails every write, WriteAudit returns promptly with every event logged in full, and Close returns
// instead of hanging on the disk; nothing half-written is left in the spool.
func TestCloseWithFailingDisk(t *testing.T) {
	plan := make([]*faultFile, 50)
	for i := range plan {
		plan[i] = &faultFile{short: 2}
	}
	faults(t, plan...)
	log := newCapture()
	c, err := New("http://example.invalid", "n1", log)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Spool(t.TempDir(), 1); err != nil {
		t.Fatal(err)
	}
	c.Start()
	start := time.Now()
	for i := range 5 {
		c.WriteAudit(event(i))
	}
	done := make(chan struct{})
	go func() { c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close hung on a failing disk")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("writing and closing took %s", d)
	}
	if got := log.undeliveredIDs(); len(got) != 5 {
		t.Fatalf("logged %d of 5 events: %v", len(got), got)
	}
	if !c.spool.empty() {
		segs, _ := c.spool.segments()
		t.Fatalf("segments left by failed writes: %v", segs)
	}
}

// Close returns while VictoriaLogs holds a delivery open (Close ends the request), and the event being delivered
// stays in the spool for the next start: the process may exit as soon as Close returns.
func TestCloseDoesNotHangOnBlockedDelivery(t *testing.T) {
	fastTimers(t)
	entered, release := make(chan struct{}, 1), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // runs first: the handler must end before the server can close
	dir := t.TempDir()
	c, err := New(srv.URL, "n1", logger.NewNullLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Spool(dir, 1); err != nil {
		t.Fatal(err)
	}
	c.Start()
	c.WriteAudit(event(1))
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the event was never delivered")
	}
	closed := make(chan struct{})
	go func() { c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung on a delivery VictoriaLogs holds open")
	}
	s, err := newSpool(dir, 1) // the next start
	if err != nil {
		t.Fatal(err)
	}
	if _, body, _, _ := s.oldest(); strings.Join(ids(body), ",") != "ev-00001" {
		t.Fatalf("spooled after Close: %q", body)
	}
}
