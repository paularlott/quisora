package vlogs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestNewSpoolDirectoryNotWritable(t *testing.T) {
	dir := t.TempDir()
	chmodFor(t, dir, 0o500, 0o700)
	if _, err := newSpool(dir, 1); err == nil || !strings.Contains(err.Error(), "not writable") {
		t.Fatalf("read-only spool directory: %v", err)
	}
}

func TestNewSpoolStartsStampAfterExistingSegments(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "audit-00000000000000000042-000001.jsonl"), line("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := newSpool(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if s.stamp != 42 {
		t.Fatalf("stamp %d", s.stamp)
	}
}

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

func TestOldestUnreadableSegmentStopsReplay(t *testing.T) {
	s, err := newSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store(line("a")); err != nil {
		t.Fatal(err)
	}
	chmodFor(t, filepath.Join(s.dir, s.active), 0, 0o600)
	if name, body, _, _ := s.oldest(); name != "" || body != nil {
		t.Fatalf("unreadable segment replayed: %q %q", name, body)
	}
}

func TestTruncateSyncedAndSyncDirErrors(t *testing.T) {
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

// vanishing is a segment whose file disappears while it is being written, as if the disk or an operator removed it:
// the failed append cannot then be cut back.
type vanishing struct {
	segmentFile
	path string
}

func (v *vanishing) Write([]byte) (int, error) {
	_ = os.Remove(v.path)
	return 0, errors.New("injected: write failed")
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
	real := openSegment
	t.Cleanup(func() { openSegment = real })
	openSegment = func(path string) (segmentFile, error) {
		f, err := real(path)
		return &vanishing{segmentFile: f, path: path}, err
	}
	if _, err := s.store(line("b")); err == nil {
		t.Fatal("failed append reported stored")
	}
	if s.active != "" {
		t.Fatalf("segment %q still active", s.active)
	}
	openSegment = real
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
