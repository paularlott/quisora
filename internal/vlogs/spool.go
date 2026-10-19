package vlogs

// On-disk spool for audit events VictoriaLogs did not take (adapted from knot's log spool). Batches are appended, as
// the JSON lines they would have been posted as, to segment files of about segmentMax bytes, and replayed oldest
// segment first once VictoriaLogs answers again; a segment is removed only after VictoriaLogs accepted it, so a crash
// mid-replay sends it again (VictoriaLogs then holds the events twice, never not at all). The spool is bounded: past
// maxBytes the oldest segments go, and every event in them is logged in full (audit.undelivered). Only the writer
// goroutine uses it.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	dir      string
	maxBytes int64
	active   string // segment being appended to; "" starts a new one
	seq      int
}

// newSpool opens (creating) dir as a spool of at most maxMB megabytes (0 = defaultSpoolMB) and checks it can write
// there, so a bad path fails at startup rather than at the first outage.
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
	return &spool{dir: dir, maxBytes: int64(maxMB) << 20}, nil
}

type segment struct {
	name string
	size int64
}

// segments lists the spool's segments, oldest first, and their total size.
func (s *spool) segments() ([]segment, int64) {
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

// store appends body (JSON lines) to the active segment, starting a new one when it would grow past segmentMax, and
// evicts the oldest segments while the spool is over its size. It returns the events (JSON lines) evicted.
func (s *spool) store(body []byte) (evicted [][]byte, err error) {
	if s.active != "" {
		if info, err := os.Stat(filepath.Join(s.dir, s.active)); err != nil || info.Size()+int64(len(body)) > segmentMax {
			s.active = ""
		}
	}
	if s.active == "" {
		s.seq++
		s.active = fmt.Sprintf("%s%020d-%06d%s", segmentPrefix, time.Now().UnixNano(), s.seq, segmentExt)
	}
	f, err := os.OpenFile(filepath.Join(s.dir, s.active), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	_, err = f.Write(body)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	segs, total := s.segments()
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

// oldest returns the oldest segment's name and its events (the complete JSON lines in it: a line torn by a crash
// while it was written is left out), or "" when the spool is empty. The segment is sealed: nothing more is appended
// to it. Remove it once VictoriaLogs has taken it.
func (s *spool) oldest() (string, []byte) {
	for {
		segs, _ := s.segments()
		if len(segs) == 0 {
			return "", nil
		}
		name := segs[0].name
		if name == s.active {
			s.active = ""
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

// jsonLines returns the complete JSON lines in data (a line torn by a crash while it was written is left out).
func jsonLines(data []byte) [][]byte {
	var out [][]byte
	for line := range bytes.Lines(data) {
		if l := bytes.TrimSpace(line); len(l) > 0 && json.Valid(l) {
			out = append(out, l)
		}
	}
	return out
}

func (s *spool) remove(name string) { os.Remove(filepath.Join(s.dir, name)) }

// empty reports whether nothing is spooled.
func (s *spool) empty() bool {
	segs, _ := s.segments()
	return len(segs) == 0
}
