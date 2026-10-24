package vlogs

// On-disk spool for audit events VictoriaLogs did not take (adapted from knot's log spool). Batches are appended, as
// the JSON lines they would have been posted as, to segment files of about segmentMax bytes, and replayed oldest
// segment first once VictoriaLogs answers again; a segment is removed only after VictoriaLogs accepted it, so a crash
// mid-replay sends it again (VictoriaLogs then holds the events twice, never not at all). The spool is bounded: past
// maxBytes the oldest segments go, and every event in them is logged in full (audit.undelivered). The spooler
// appends and the deliverer replays concurrently: mu orders them.
//
// Durability rule: a batch store reported written is on disk, complete, and will be replayed. The spool keeps the
// active segment's good size (bytes written and fsynced, all complete lines) in memory and only ever appends at it:
// a failed or partial append is cut back to that size (or, if that fails, the segment is sealed so nothing is ever
// appended after the torn line); bytes past the good size found before an append are cut off the same way; a segment
// found on disk at start is never appended to. So a torn line is always a segment's last line, and replay drops it
// alone, never a complete line after it (jsonLines).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	segmentPrefix  = "audit-"
	segmentExt     = ".jsonl"
	segmentMax     = 1 << 20 // a segment is one replay request: VictoriaLogs takes far larger ones
	replayPerTick  = 16      // segments replayed per flush, so a backlog drains fast without starving new events
	defaultSpoolMB = 256
)

type spool struct {
	mu       sync.Mutex
	dir      string
	maxBytes int64
	active   string // segment being appended to; "" starts a new one
	size     int64  // the active segment's good size: bytes on disk and fsynced, ending with a complete line
	seq      int
	stamp    int64 // the newest segment name's time: names must stay in age order even if the clock steps back
}

// newSpool opens (creating) dir as a spool of at most maxMB megabytes (0 = defaultSpoolMB) and checks it can write
// there, so a bad path fails at startup rather than at the first outage. Segments already there (a previous run's)
// are replayed, never appended to: whatever a crash left torn at the end of one stays its last line.
func newSpool(dir string, maxMB int) (*spool, error) {
	if maxMB <= 0 {
		maxMB = defaultSpoolMB
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("vlogs: spool directory: %w", err)
	}
	f, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return nil, fmt.Errorf("vlogs: spool directory is not writable: %w", err)
	}
	f.Close()
	os.Remove(f.Name())
	s := &spool{dir: dir, maxBytes: int64(maxMB) << 20}
	if segs, _ := s.list(); len(segs) > 0 {
		s.stamp = segmentStamp(segs[len(segs)-1].name)
	}
	return s, nil
}

type segment struct {
	name string
	size int64
}

// segments lists the spool's segments, oldest first, and their total size.
func (s *spool) segments() ([]segment, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.list()
}

func (s *spool) list() ([]segment, int64) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, 0
	}
	var out []segment
	var total int64
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, segmentPrefix) || !strings.HasSuffix(name, segmentExt) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, segment{name, info.Size()})
		total += info.Size()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name }) // names start with the time: age order
	return out, total
}

// segmentStamp is the time in a segment's name (0 if it is not one of ours).
func segmentStamp(name string) int64 {
	var t int64
	var seq int
	if _, err := fmt.Sscanf(name, segmentPrefix+"%d-%d"+segmentExt, &t, &seq); err != nil {
		return 0
	}
	return t
}

// seal stops appending to the active segment: the next store starts a new one.
func (s *spool) seal() { s.active, s.size = "", 0 }

// store appends body (JSON lines, each ending in '\n') to the active segment, starting a new one when it would grow
// past segmentMax, and evicts the oldest segments while the spool is over its size. It returns the events (JSON
// lines) evicted. On an error nothing of body is kept: the segment is cut back to what it held (or sealed), so a
// later store never lands after a torn line, and the caller must log the batch itself.
func (s *spool) store(body []byte) (evicted [][]byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active != "" && s.size+int64(len(body)) > segmentMax {
		s.seal()
	}
	if s.active != "" && !s.reusable() {
		s.seal()
	}
	created := s.active == ""
	if created {
		s.seq++
		now := time.Now().UnixNano()
		if now <= s.stamp {
			now = s.stamp + 1
		}
		s.stamp = now
		s.active, s.size = fmt.Sprintf("%s%020d-%06d%s", segmentPrefix, now, s.seq, segmentExt), 0
	}
	if err := s.append(body, created); err != nil {
		// Nothing of body stays: a partial write, or one not known to be durable, must not become the start of a
		// line the next store completes. A new segment holds nothing promised to anyone and goes; an old one is put
		// back to its good size and stays active, or, if even that fails, is sealed with its torn tail as its last
		// line (replay leaves that line out and keeps the complete ones).
		path := filepath.Join(s.dir, s.active)
		if created {
			os.Remove(path)
			s.seal()
		} else if truncateSynced(path, s.size) != nil {
			s.seal()
		}
		return nil, err
	}
	s.size += int64(len(body))
	segs, total := s.list()
	for len(segs) > 1 && total > s.maxBytes { // the newest segment (just written) always stays
		data, _ := os.ReadFile(filepath.Join(s.dir, segs[0].name))
		if os.Remove(filepath.Join(s.dir, segs[0].name)) == nil {
			evicted = append(evicted, jsonLines(data)...)
			total -= segs[0].size
		}
		segs = segs[1:]
	}
	return evicted, nil
}

// reusable reports whether the active segment can still be appended to: it is there and holds its good size. Bytes
// past the good size are a torn line (an append that failed in a way this process could not undo, or a write from
// outside) and are cut off first; if they cannot be, or the segment is gone or shorter, it is not reused.
func (s *spool) reusable() bool {
	path := filepath.Join(s.dir, s.active)
	info, err := os.Stat(path)
	if err != nil || info.Size() < s.size {
		return false
	}
	if info.Size() > s.size {
		if err := truncateSynced(path, s.size); err != nil {
			return false
		}
	}
	return true
}

// segmentFile is what append needs of an open segment; openSegment and syncDir are variables so tests can make the
// disk fail in every way it can (a short write, a failed fsync, a failed directory fsync).
type segmentFile interface {
	io.WriteCloser
	Sync() error
}

var openSegment = func(path string) (segmentFile, error) {
	return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
}

// append writes body at the end of the active segment, whose first s.size bytes are good, and makes it durable (the
// name too, for a segment just created). The caller undoes a failed append.
func (s *spool) append(body []byte, created bool) error {
	f, err := openSegment(filepath.Join(s.dir, s.active))
	if err != nil {
		return err
	}
	_, err = f.Write(body)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && created {
		// A new segment's name must be on disk too, or a power loss can drop the whole file the caller was told is
		// durable.
		err = syncDir(s.dir)
	}
	return err
}

// truncateSynced cuts path to size and syncs it.
func truncateSynced(path string, size int64) error {
	if err := os.Truncate(path, size); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// oldest returns the oldest segment's name and its events (the complete JSON lines in it: a line torn by a crash
// while it was written is left out), or "" when the spool is empty. The segment is sealed: nothing more is appended
// to it. Remove it once VictoriaLogs has taken it.
func (s *spool) oldest() (string, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		segs, _ := s.list()
		if len(segs) == 0 {
			return "", nil
		}
		name := segs[0].name
		if name == s.active {
			s.seal()
		}
		data, err := os.ReadFile(filepath.Join(s.dir, name))
		if err != nil {
			return "", nil
		}
		var body []byte
		for _, l := range jsonLines(data) {
			body = append(append(body, l...), '\n')
		}
		if len(body) > 0 {
			return name, body
		}
		os.Remove(filepath.Join(s.dir, name)) // nothing usable in it
	}
}

// jsonLines returns the complete JSON lines in data: each ends with '\n' (every line written does, so one without
// is the end of a write that was cut short) and is valid JSON. A torn line is left out on its own: the line after
// it, if any, is judged by itself.
func jsonLines(data []byte) [][]byte {
	var out [][]byte
	for line := range bytes.Lines(data) {
		if line[len(line)-1] != '\n' {
			continue
		}
		if l := bytes.TrimSpace(line); len(l) > 0 && json.Valid(l) {
			out = append(out, l)
		}
	}
	return out
}

// syncDir syncs directory dir, making the names created in it durable.
var syncDir = func(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *spool) remove(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	os.Remove(filepath.Join(s.dir, name))
}

// empty reports whether nothing is spooled.
func (s *spool) empty() bool {
	segs, _ := s.segments()
	return len(segs) == 0
}
