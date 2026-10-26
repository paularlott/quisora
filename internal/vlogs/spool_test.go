package vlogs

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/logger"
)

// A spool directory that cannot be written is refused at startup.
func TestSpoolDirMustBeWritable(t *testing.T) {
	t.Run("read-only directory", func(t *testing.T) {
		dir := t.TempDir()
		chmodFor(t, dir, 0o500, 0o700)
		if _, err := newSpool(dir, 1); err == nil || !strings.Contains(err.Error(), "not writable") {
			t.Fatalf("read-only spool directory: %v", err)
		}
	})
	t.Run("path under a file", func(t *testing.T) {
		f := t.TempDir() + "/file"
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		c, _ := New("http://127.0.0.1:1", "n1", logger.NewNullLogger())
		if err := c.Spool(f+"/spool", 0); err == nil {
			t.Fatal("a spool under a file was accepted")
		}
	})
}

// The spool stays within its size: past it the oldest events go (and are counted as dropped), the newest stay.
func TestSpoolIsBounded(t *testing.T) {
	s, err := newSpool(t.TempDir(), 1) // 1 MB
	if err != nil {
		t.Fatal(err)
	}
	l := []byte(`{"id":"x","pad":"` + strings.Repeat("a", 1000) + `"}` + "\n")
	batch := bytes.Repeat(l, 100) // ~100 KB
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

// A segment's name carries its time; any other name has none.
func TestSegmentStamp(t *testing.T) {
	if got := segmentStamp("audit-00000000000000000123-000007.jsonl"); got != 123 {
		t.Fatalf("%d", got)
	}
	for _, n := range []string{"", "junk", "audit-x-1.jsonl", "audit-5.jsonl"} {
		if got := segmentStamp(n); got != 0 {
			t.Fatalf("%q: %d", n, got)
		}
	}
}

// Only files named like segments count: other files and directories in the spool directory are left alone.
func TestSpoolListIgnoresForeignEntries(t *testing.T) {
	s, err := newSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(s.dir, "audit-1-1.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"notes.txt", "audit-2-2.tmp", "other-3-3.jsonl"} {
		if err := os.WriteFile(filepath.Join(s.dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if segs, total := s.segments(); len(segs) != 0 || total != 0 || !s.empty() {
		t.Fatalf("%v %d", segs, total)
	}
	if name, body, _, _ := s.oldest(); name != "" || body != nil {
		t.Fatalf("oldest %q %q", name, body)
	}
	if err := os.RemoveAll(s.dir); err != nil { // the directory itself gone: an empty spool, not a crash
		t.Fatal(err)
	}
	if segs, total := s.segments(); segs != nil || total != 0 {
		t.Fatalf("%v %d", segs, total)
	}
}

// A segment with nothing replayable (only a torn line) is removed and the next one is replayed.
func TestOldestSkipsSegmentWithNothingUsable(t *testing.T) {
	s, err := newSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	torn := filepath.Join(s.dir, "audit-00000000000000000001-000001.jsonl")
	if err := os.WriteFile(torn, []byte(`{"id":"half`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store(line("good")); err != nil {
		t.Fatal(err)
	}
	name, body, _, _ := s.oldest()
	if name == "" || strings.Join(ids(body), ",") != "good" {
		t.Fatalf("replayed %q from %q", body, name)
	}
	if _, err := os.Stat(torn); !os.IsNotExist(err) {
		t.Fatalf("empty segment kept: %v", err)
	}
}

// A segment that cannot be read stops replay: an error, not an empty spool, so it is neither skipped nor removed, and
// the deliverer holds off as for an outage.
func TestOldestUnreadableSegmentStopsReplay(t *testing.T) {
	vl := newFakeVL(t)
	vl.set(true)
	c := spooled(t, vl.srv.URL, logger.NewNullLogger())
	if _, err := c.spool.store(line("a")); err != nil {
		t.Fatal(err)
	}
	chmodFor(t, filepath.Join(c.spool.dir, c.spool.active), 0, 0o600)
	if name, body, _, err := c.spool.oldest(); err == nil || name != "" || body != nil {
		t.Fatalf("unreadable segment replayed: %q %q %v", name, body, err)
	}
	c.replay()
	if vl.requestCount() != 0 || !c.spooling || c.backoff != minBackoff || c.spool.empty() {
		t.Fatalf("after an unreadable segment: %d requests, spooling %v, backoff %v", vl.requestCount(), c.spooling, c.backoff)
	}
}

// truncateSynced cuts a file to its good size; it and syncDir report a missing path instead of succeeding.
func TestTruncateSynced(t *testing.T) {
	if err := truncateSynced(filepath.Join(t.TempDir(), "missing"), 0); err == nil {
		t.Fatal("truncate of a missing file succeeded")
	}
	if err := syncDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("sync of a missing directory succeeded")
	}
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := truncateSynced(p, 3); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "abc" {
		t.Fatalf("%q", b)
	}
}

// A failed append that cannot be cut back seals the segment: the next batch starts a new one instead of landing
// after a torn line.
func TestSpoolSealsWhenFailedAppendCannotBeUndone(t *testing.T) {
	s, err := newSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store(line("a")); err != nil {
		t.Fatal(err)
	}
	first := s.active
	faults(t, &faultFile{short: 0, vanish: true})
	if _, err := s.store(line("b")); err == nil {
		t.Fatal("failed append reported stored")
	}
	if s.active != "" {
		t.Fatalf("segment %q still active", s.active)
	}
	if _, err := s.store(line("c")); err != nil || s.active == first {
		t.Fatalf("next batch: %v, active %q", err, s.active)
	}
}

// Bytes found past the good size are cut off before appending; when they cannot be cut off the segment is sealed and
// a new one is started, so the append never lands after a torn line.
func TestSpoolSealsWhenTornTailCannotBeCut(t *testing.T) {
	s, err := newSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store(line("a")); err != nil {
		t.Fatal(err)
	}
	first := s.active
	path := filepath.Join(s.dir, first)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"id":"torn`)
	f.Close()
	chmodFor(t, path, 0o400, 0o600)
	if _, err := s.store(line("b")); err != nil {
		t.Fatal(err)
	}
	if s.active == first || s.active == "" {
		t.Fatalf("appended to an uncuttable segment: %q", s.active)
	}
	name, body, _, _ := s.oldest() // the sealed one first: its complete line, not the torn one
	if name != first || strings.Join(ids(body), ",") != "a" {
		t.Fatalf("%q %q", name, body)
	}
}

// Bytes found past the active segment's good size (an append that failed in a way this process could not undo) are
// cut off before the next append, so the next event is not joined to a torn line and lost on replay; the segment
// stays active (TestSpoolSealsWhenTornTailCannotBeCut is the case where the cut fails).
func TestSpoolCutsTornTailBeforeAppending(t *testing.T) {
	s, err := newSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store([]byte("{\"id\":\"first\"}\n")); err != nil {
		t.Fatal(err)
	}
	first := s.active
	f, err := os.OpenFile(filepath.Join(s.dir, s.active), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("{\"id\":\"torn")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store([]byte("{\"id\":\"accepted-after-recovery\"}\n")); err != nil {
		t.Fatal(err)
	}
	if s.active != first {
		t.Fatalf("a cuttable segment was sealed: %q, was %q", s.active, first)
	}
	if _, body, _, _ := s.oldest(); strings.Join(ids(body), ",") != "first,accepted-after-recovery" {
		t.Fatalf("replayed %q", body)
	}
}

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
	if _, body, _, _ := s.oldest(); strings.Join(ids(body), ",") != "a,b" {
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
	if _, body, _, _ := s.oldest(); strings.Join(ids(body), ",") != "a,b" {
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
	if _, body, _, _ := s.oldest(); strings.Join(ids(body), ",") != "after" {
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
	if _, body, _, _ := s.oldest(); strings.Join(ids(body), ",") != "b" {
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
	if name, body, _, _ := s.oldest(); name != second || strings.Join(ids(body), ",") != "b" || bytes.IndexByte(body, 0) >= 0 {
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
	name, body, _, _ := s2.oldest()
	if name != old || strings.Join(ids(body), ",") != "before-crash" {
		t.Fatalf("old segment replayed as %s %q", name, body)
	}
	s2.remove(name)
	if name, body, _, _ := s2.oldest(); name != s2.active && name == old || strings.Join(ids(body), ",") != "after-restart" {
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
	name, body, _, _ := s.oldest() // the deliverer holds this while posting
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

// blockedTransport holds every request until it is cancelled, signalling entered when the first one arrives.
type blockedTransport struct{ entered chan struct{} }

func (tr blockedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	select {
	case tr.entered <- struct{}{}:
	default:
	}
	<-r.Context().Done()
	return nil, r.Context().Err()
}

// An event accepted while the deliverer is blocked sending the first segment (which oldest has sealed, so the event
// starts a new segment) is on disk when WriteAudit returns: the process exiting without Close (a crash) keeps it. The
// child process writes the events and exits; the parent reads the spool it left.
func TestAcceptedAuditSurvivesProcessExitWhileDeliveryIsBlocked(t *testing.T) {
	fastTimers(t)
	if dir := os.Getenv("QUISORA_AUDIT_EXIT_CHILD_DIR"); dir != "" {
		c, err := New("http://example.invalid", "n1", logger.NewNullLogger())
		if err != nil {
			t.Fatal(err)
		}
		if err = c.Spool(dir, 1); err != nil {
			t.Fatal(err)
		}
		entered := make(chan struct{}, 1)
		c.http.Transport = blockedTransport{entered: entered}
		c.Start()
		c.WriteAudit(event(1))
		select { // the first segment is on disk and the deliverer is blocked sending it
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatal("the first event was never delivered")
		}
		c.WriteAudit(event(2)) // accepted while the deliverer is busy
		os.Exit(0)             // no Close: as a crash
	}
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestAcceptedAuditSurvivesProcessExitWhileDeliveryIsBlocked$")
	cmd.Env = append(os.Environ(), "QUISORA_AUDIT_EXIT_CHILD_DIR="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v %s", err, out)
	}
	s, err := newSpool(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for {
		name, body, _, err := s.oldest()
		if err != nil {
			t.Fatal(err)
		}
		if name == "" {
			break
		}
		got = append(got, ids(body)...)
		if err := s.remove(name); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(got, ",") != "ev-00001,ev-00002" {
		t.Fatalf("spooled after the process exited: %v", got)
	}
}
