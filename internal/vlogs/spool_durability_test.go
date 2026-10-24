package vlogs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// faultFile is a segment whose disk fails on demand: a write that stores only the first short bytes before failing,
// or an fsync that fails after the write.
type faultFile struct {
	segmentFile
	short    int  // write only this many bytes, then fail (-1: write everything)
	syncFail bool // fsync fails
}

func (f *faultFile) Write(b []byte) (int, error) {
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
		ff.segmentFile = f
		return ff, nil
	}
}

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

func line(id string) []byte { return []byte(fmt.Sprintf("{\"id\":%q}\n", id)) }

// A write that stores only part of the batch and fails is undone: the segment is back to its last good size, the
// batch is not replayed (its caller logs it), and the next batch lands after a complete line and replays whole.
func TestSpoolShortWriteIsUndone(t *testing.T) {
	s, err := newSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store(line("a")); err != nil {
		t.Fatal(err)
	}
	faults(t, &faultFile{short: 5})
	if _, err := s.store(line("lost-but-logged")); err == nil {
		t.Fatal("a short write was reported stored")
	}
	info, err := os.Stat(filepath.Join(s.dir, s.active))
	if err != nil || info.Size() != int64(len(line("a"))) {
		t.Fatalf("segment after a short write: %v %v (want %d bytes)", info, err, len(line("a")))
	}
	if _, err := s.store(line("b")); err != nil {
		t.Fatal(err)
	}
	if _, body := s.oldest(); strings.Join(ids(body), ",") != "a,b" {
		t.Fatalf("replayed %q", body)
	}
}

// A write that lands but whose fsync fails is not durable: it is cut off too, so the segment holds only what callers
// were told is on disk, and the next batch replays.
func TestSpoolFailedSyncIsUndone(t *testing.T) {
	s, err := newSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store(line("a")); err != nil {
		t.Fatal(err)
	}
	faults(t, &faultFile{short: -1, syncFail: true})
	if _, err := s.store(line("not-durable")); err == nil {
		t.Fatal("a failed fsync was reported stored")
	}
	if _, err := s.store(line("b")); err != nil {
		t.Fatal(err)
	}
	if _, body := s.oldest(); strings.Join(ids(body), ",") != "a,b" {
		t.Fatalf("replayed %q", body)
	}
}

// A new segment whose first append fails (a full disk: ENOSPC on every write) is removed, so failing batches do not
// litter the spool with empty segments, and a name is never reused: once the disk answers the next batch is stored.
func TestSpoolFailedNewSegmentIsRemoved(t *testing.T) {
	s, err := newSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	faults(t, &faultFile{short: 0}, &faultFile{short: 3}, &faultFile{short: -1, syncFail: true})
	for i := range 3 {
		if _, err := s.store(line(fmt.Sprint("full-", i))); err == nil {
			t.Fatal("stored on a full disk")
		}
	}
	if segs, _ := s.segments(); len(segs) != 0 {
		t.Fatalf("%d segments left by failed appends: %v", len(segs), segs)
	}
	if _, err := s.store(line("after")); err != nil {
		t.Fatal(err)
	}
	if _, body := s.oldest(); strings.Join(ids(body), ",") != "after" {
		t.Fatalf("replayed %q", body)
	}
}

// The directory fsync making a new segment's name durable can fail too: the batch is then not reported stored and
// the segment goes, so the caller's log is its only copy (not the log and, after a crash, VictoriaLogs too).
func TestSpoolFailedDirectorySyncIsNotStored(t *testing.T) {
	s, err := newSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	real := syncDir
	t.Cleanup(func() { syncDir = real })
	syncDir = func(string) error { return errors.New("injected: directory fsync failed") }
	if _, err := s.store(line("a")); err == nil {
		t.Fatal("stored without a durable name")
	}
	if !s.empty() {
		t.Fatal("a segment without a durable name was kept")
	}
	syncDir = real
	if _, err := s.store(line("b")); err != nil {
		t.Fatal(err)
	}
	if _, body := s.oldest(); strings.Join(ids(body), ",") != "b" {
		t.Fatalf("replayed %q", body)
	}
}

// The active segment vanishing from outside (an operator's rm, or an eviction of a misnamed file) must not have the
// next append recreate it and pad it: a new segment starts.
func TestSpoolActiveSegmentRemovedOutside(t *testing.T) {
	s, err := newSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store(line("gone")); err != nil {
		t.Fatal(err)
	}
	first := s.active
	if err := os.Remove(filepath.Join(s.dir, first)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store(line("b")); err != nil {
		t.Fatal(err)
	}
	second := s.active
	if second == first {
		t.Fatal("the removed segment was recreated")
	}
	if name, body := s.oldest(); name != second || strings.Join(ids(body), ",") != "b" || bytes.IndexByte(body, 0) >= 0 {
		t.Fatalf("replayed %s %q", name, body)
	}
}

// A segment a crash left on disk, torn at the end (the write was in progress, or written but not yet fsynced), is
// never appended to after a restart: its complete lines replay, its torn tail is left out, and new events start a
// new segment.
func TestSpoolNeverAppendsToSegmentFoundOnDisk(t *testing.T) {
	dir := t.TempDir()
	s, err := newSpool(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store(line("before-crash")); err != nil {
		t.Fatal(err)
	}
	old := s.active
	f, err := os.OpenFile(filepath.Join(dir, old), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"id":"torn-by-cr`) // crash here
	f.Close()

	s2, err := newSpool(dir, 1) // restart
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.store(line("after-restart")); err != nil {
		t.Fatal(err)
	}
	if s2.active == old {
		t.Fatal("appended to a segment found on disk")
	}
	name, body := s2.oldest()
	if name != old || strings.Join(ids(body), ",") != "before-crash" {
		t.Fatalf("old segment replayed as %s %q", name, body)
	}
	s2.remove(name)
	if name, body := s2.oldest(); name != s2.active && name == old || strings.Join(ids(body), ",") != "after-restart" {
		t.Fatalf("new segment replayed as %s %q", name, body)
	}
}

// Replay judges every line by itself: a torn line never swallows the complete line after it, and a line without its
// terminating newline is not complete even if it parses.
func TestJSONLinesFraming(t *testing.T) {
	got := jsonLines([]byte("{\"id\":\"a\"}\n{\"id\":\"torn\n{\"id\":\"b\"}\n\n   \n{\"id\":\"c\"}"))
	if len(got) != 2 || string(got[0]) != `{"id":"a"}` || string(got[1]) != `{"id":"b"}` {
		t.Fatalf("kept %q", got)
	}
	if got := jsonLines(nil); len(got) != 0 {
		t.Fatalf("kept %q from nothing", got)
	}
}

// Segment names stay in age order even when the clock steps back (also across a restart), so eviction always takes
// the oldest and never the segment being written.
func TestSpoolSegmentNamesStayOrdered(t *testing.T) {
	dir := t.TempDir()
	s, err := newSpool(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	s.stamp = time.Now().Add(time.Hour).UnixNano() // as if the clock had been an hour ahead
	if _, err := s.store(line("future")); err != nil {
		t.Fatal(err)
	}
	future := s.active
	if _, err := s.store(bytes.Repeat(line("x"), segmentMax/len(line("x")))); err != nil { // forces a new segment
		t.Fatal(err)
	}
	if s.active <= future {
		t.Fatalf("segment %s sorts before the earlier %s", s.active, future)
	}
	s2, err := newSpool(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.store(line("restarted")); err != nil {
		t.Fatal(err)
	}
	if segs, _ := s2.segments(); segs[len(segs)-1].name != s2.active {
		t.Fatalf("after a restart the new segment %s is not the newest of %v", s2.active, segs)
	}
}

// The deliverer may be posting a segment while the spooler evicts it: the segment's events are then logged as
// undelivered by the spooler (and may also reach VictoriaLogs), never lost without a trace, and the deliverer's
// removal of a segment that is already gone is harmless.
func TestSpoolEvictionDuringDelivery(t *testing.T) {
	s, err := newSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store(line("delivering")); err != nil {
		t.Fatal(err)
	}
	name, body := s.oldest() // the deliverer holds this while posting
	if name == "" || !bytes.Contains(body, []byte("delivering")) {
		t.Fatalf("oldest %s %q", name, body)
	}
	var evicted [][]byte
	batch := bytes.Repeat(line(strings.Repeat("p", 1000)), 100) // ~100 KB
	for range 15 {                                              // ~1.5 MB through a 1 MB spool
		ev, err := s.store(batch)
		if err != nil {
			t.Fatal(err)
		}
		evicted = append(evicted, ev...)
	}
	found := false
	for _, l := range evicted {
		found = found || bytes.Contains(l, []byte("delivering"))
	}
	if !found {
		t.Fatal("the segment being delivered was evicted without its events being returned for logging")
	}
	s.remove(name) // the post succeeded meanwhile: nothing to remove, nothing wrong
	if segs, _ := s.segments(); len(segs) == 0 {
		t.Fatal("the newest segment went")
	}
}

// An event WriteAudit gave up waiting for (logged as audit.undelivered after spoolWait) is still spooled once the
// disk answers and reaches VictoriaLogs: it is then held twice (log and VictoriaLogs), never nowhere.
func TestWriteAuditTimedOutEventIsStillSpooled(t *testing.T) {
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
	c.WriteAudit(event(7)) // not started: the disk does not answer in time
	if !log.undeliveredIDs()[event(7).ID] {
		t.Fatal("the event was not logged after the wait")
	}
	c.Start() // the disk answers
	defer c.Close()
	waitFor(t, "the event to reach VictoriaLogs", func() bool { d, _ := vl.count(); return d == 1 })
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
