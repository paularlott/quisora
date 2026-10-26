package cluster

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/partition"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// commitChange runs a change through Prepare and Commit on n's partition store, as the owner and then every node does,
// at the next sequence number of partition p, and returns what Prepare replied.
func commitChange(t *testing.T, n *Node, p int, c *change) writeReply {
	t.Helper()
	b, err := encodeMsg(c)
	if err != nil {
		t.Fatal(err)
	}
	data, reply, err := n.pst.Prepare(p, b)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	st, _ := n.pst.State(p)
	if err := n.pst.Commit(&partition.Write{Partition: p, Pos: partition.Pos{Seq: st.Committed.Seq + 1}, Prev: st.Committed,
		Data: data}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var rep writeReply
	if err := decodeMsg(reply, &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

// tomb is a deletion of a record of org1, as the cluster store builds it (it carries the partition key and scope).
func tomb(id string) *store.Record {
	r := store.Tombstone(dataKind, id)
	r.Partition, r.Scope = "org1", "org1"
	return r
}

func writeChange(t *testing.T, rec *store.Record, mode uint8, expect uint64) *change {
	t.Helper()
	b, err := encodeRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	return &change{Op: opWrite, Mode: mode, Expect: expect, Rec: b}
}

func refusalCode(err error) string {
	var re *partition.RefusedError
	if errors.As(err, &re) {
		return re.Code
	}
	return ""
}

// prepare asks the owner's check for a change and returns the code it was refused with ("": accepted).
func prepare(t *testing.T, n *Node, p int, c *change) string {
	t.Helper()
	b, err := encodeMsg(c)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = n.pst.Prepare(p, b)
	if err != nil && refusalCode(err) == "" {
		t.Fatalf("a failure, not a refusal: %v", err)
	}
	return refusalCode(err)
}

// The owner's check of a change, against its committed data: every refusal has its code.
func TestPrepareRefusalCodes(t *testing.T) {
	n, _ := gnode(t)
	p := partitionNum("org1")
	rec := newRec("r1", "uniq-1")
	rep := commitChange(t, n, p, writeChange(t, rec, modeMatch, 0))
	cases := []struct {
		name string
		c    *change
		want string
	}{
		{"create over a live record", writeChange(t, newRec("r1", ""), modeMatch, 0), whyStale},
		{"update of another version", writeChange(t, newRec("r1", ""), modeMatch, rep.Version+1), whyStale},
		{"update of nothing", writeChange(t, newRec("nothing", ""), modeMatch, 7), whyNotFound},
		{"a unique value in use", writeChange(t, newRec("r2", "uniq-1"), modeMatch, 0), whyConflict},
		{"the right version", writeChange(t, newRec("r1", "uniq-1"), modeMatch, rep.Version), ""},
		{"an upsert over a live record", writeChange(t, newRec("r1", ""), modeUpsert, 0), ""},
		{"a blind deletion of nothing", writeChange(t, tomb("nothing"), modeBlind, 0), whyNothing},
	}
	for _, tc := range cases {
		if got := prepare(t, n, p, tc.c); got != tc.want {
			t.Errorf("%s: refused with %q, want %q", tc.name, got, tc.want)
		}
	}
	// a record belongs to the partition its key says
	if got := prepare(t, n, (p+1)%partitions, writeChange(t, newRec("r3", ""), modeMatch, 0)); got != whyBad {
		t.Errorf("a record in another partition: %q", got)
	}
	// a record never moves
	moved := newRec("r1", "")
	moved.Partition = "org-other"
	if got := prepare(t, n, partitionNum("org-other"), writeChange(t, moved, modeUpsert, 0)); got != whyBad {
		t.Errorf("a record that changes partition: %q", got)
	}
	// a global value is reserved, never listed by a record
	tn := &model.Tenant{OrgID: "org1", Name: "t", Resources: []string{"https://x.example.com"}}
	trec, _ := store.Encode(tn)
	if got := prepare(t, n, p, writeChange(t, trec, modeMatch, 0)); got != whyBad {
		t.Errorf("a record listing a global value: %q", got)
	}
	// a deletion, then a live write over it
	commitChange(t, n, p, writeChange(t, tomb("r1"), modeBlind, 0))
	if got := prepare(t, n, p, writeChange(t, newRec("r1", ""), modeUpsert, 0)); got != whyDeleted {
		t.Errorf("an upsert over a tombstone: %q", got)
	}
	if got := prepare(t, n, p, writeChange(t, newRec("r1", ""), modeMatch, 0)); got != "" {
		t.Errorf("a create over a tombstone: %q", got)
	}
	// malformed
	if _, _, err := n.pst.Prepare(p, []byte("garbage")); refusalCode(err) != whyBad {
		t.Errorf("garbage: %v", err)
	}
	if got := prepare(t, n, p, &change{Op: 99}); got != whyBad {
		t.Errorf("an unknown change: %q", got)
	}
	// a purge point beyond what is committed
	if got := prepare(t, n, p, &change{Op: opPurge, Before: 1000}); got != whyBad {
		t.Errorf("a purge beyond the committed position: %q", got)
	}
	if got := prepare(t, n, p, &change{Op: opPurge, Before: 1}); got != whyNothing {
		t.Errorf("a purge of nothing: %q", got)
	}
}

// A new version is always above the one it replaces, whatever the clock says, and a tombstone keeps the record's
// partition.
func TestVersionsRiseAndTombstonesKeepTheirPartition(t *testing.T) {
	n, _ := gnode(t)
	p := partitionNum("org1")
	rec := newRec("v1", "")
	first := commitChange(t, n, p, writeChange(t, rec, modeMatch, 0))
	// a record whose stored version is far ahead of this node's clock (a clock that ran ahead on an earlier owner)
	ahead := newRec("v2", "")
	r1 := commitChange(t, n, p, writeChange(t, ahead, modeMatch, 0))
	stored, _ := n.st.inner.Lookup(bg, dataKind, "v2")
	cp := *stored
	cp.Version += 1 << 40
	if _, err := n.st.inner.PutReplicated(bg, &cp); err != nil {
		t.Fatal(err)
	}
	r2 := commitChange(t, n, p, writeChange(t, newRec("v2", ""), modeUpsert, 0))
	if r2.Version <= cp.Version.Uint64() || r1.Version == 0 || first.Version == 0 {
		t.Fatalf("a version %d does not rise above the stored %d", r2.Version, cp.Version)
	}
	commitChange(t, n, p, writeChange(t, tomb("v1"), modeBlind, 0))
	tomb, err := n.st.inner.Lookup(bg, dataKind, "v1")
	if err != nil || !tomb.Deleted || tomb.Partition != "org1" {
		t.Fatalf("tombstone %+v %v", tomb, err)
	}
}

// Export and import: a stream that ends before its marker does not move the position (and, of this size, applies nothing: a
// batch is applied when it is full or the stream ends), a complete one applies everything, and "after" selects by the
// sequence of the write that last changed a record.
func TestExportImport(t *testing.T) {
	src, _ := gnode(t)
	p := partitionNum("org1")
	for i := range 3 {
		commitChange(t, src, p, writeChange(t, newRec(string(rune('a'+i)), ""), modeMatch, 0))
	}
	export := func(after uint64) (partition.Pos, []byte) {
		t.Helper()
		pos, rc, err := src.pst.Export(p, after)
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		b, err := io.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		return pos, b
	}
	pos, all := export(0)
	if pos.Seq != 3 {
		t.Fatalf("exported up to %d", pos.Seq)
	}
	// cut short: the end marker (a zero length frame) is missing
	dst, _ := gnode(t)
	if err := dst.pst.Import(p, bytes.NewReader(all[:len(all)-4]), pos, false); err == nil {
		t.Fatal("a stream without its end marker was applied")
	}
	if err := dst.pst.Import(p, bytes.NewReader(all[:len(all)/2]), pos, false); err == nil {
		t.Fatal("half a stream was applied")
	}
	if n, _ := dst.st.inner.Count(bg, dataKind, ""); n != 0 {
		t.Fatalf("a failed import left %d records", n)
	}
	if st, _ := dst.pst.State(p); st.Committed.Seq != 0 {
		t.Fatal("a failed import moved the committed position")
	}
	var seen []string
	dst.OnChange(func(r *store.Record, local bool) { seen = append(seen, r.ID) })
	if err := dst.pst.Import(p, bytes.NewReader(all), pos, false); err != nil {
		t.Fatal(err)
	}
	if n, _ := dst.st.inner.Count(bg, dataKind, ""); n != 3 || len(seen) != 3 {
		t.Fatalf("%d records, %d hooks", n, len(seen))
	}
	if st, _ := dst.pst.State(p); st.Committed.Seq != 3 {
		t.Fatalf("committed %d", st.Committed.Seq)
	}
	// only what changed after a sequence number
	_, tail := export(2)
	third := newTestNode(t)
	if err := third.pst.Import(p, bytes.NewReader(tail), pos, false); err != nil {
		t.Fatal(err)
	}
	if n, _ := third.st.inner.Count(bg, dataKind, ""); n != 1 {
		t.Fatalf("after 2: %d records", n)
	}
	// history that was purged cannot be exported by sequence
	commitChange(t, src, p, writeChange(t, tomb("a"), modeBlind, 0))
	commitChange(t, src, p, &change{Op: opPurge, Before: 5})
	if _, _, err := src.pst.Export(p, 1); !errors.Is(err, partition.ErrPurged) {
		t.Fatalf("an export of purged history: %v", err)
	}
	if _, rc, err := src.pst.Export(p, 0); err != nil {
		t.Fatalf("a whole export: %v", err)
	} else {
		rc.Close()
	}
}

// countingParts watches a node's partition backend: the records an export has produced, the exports and imports in
// flight, and the batches an import was given.
type countingParts struct {
	store.PartitionStore
	emitted atomic.Int64 // records ExportPartition passed to its callback
	active  atomic.Int64 // ExportPartition calls that have not returned (each holds a snapshot)
	mu      sync.Mutex
	imports []importCall
}

type importCall struct {
	n    int
	step store.ImportStep
}

func (c *countingParts) ExportPartition(ctx context.Context, p int, after uint64, start func(store.PartitionPos) error,
	fn func(store.PartitionRecord) error) error {
	c.active.Add(1)
	defer c.active.Add(-1)
	return c.PartitionStore.ExportPartition(ctx, p, after, start, func(r store.PartitionRecord) error {
		c.emitted.Add(1)
		return fn(r)
	})
}

func (c *countingParts) ImportPartition(ctx context.Context, p int, recs []store.PartitionRecord, upTo store.PartitionPos, step store.ImportStep) error {
	c.mu.Lock()
	c.imports = append(c.imports, importCall{len(recs), step})
	c.mu.Unlock()
	return c.PartitionStore.ImportPartition(ctx, p, recs, upTo, step)
}

func (c *countingParts) importCalls() []importCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]importCall(nil), c.imports...)
}

// watched makes n's partition backend a countingParts.
func watched(n *Node) *countingParts {
	c := &countingParts{PartitionStore: n.pst.pst}
	n.pst.pst = c
	return c
}

// filesBelow lists every file below dir.
func filesBelow(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			out = append(out, path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// An export streams: the backend is read as the reader takes the stream (a reader that has taken a byte has the backend
// a few records ahead, not the whole partition), and no file is made in the data directory at any point.
func TestExportStreamsWithoutSpooling(t *testing.T) {
	n := newTestNode(t)
	n.dir = t.TempDir()
	w := watched(n)
	p := partitionNum("org1")
	big := bytes.Repeat([]byte("x"), 100<<10)
	const records = 300
	for i := range records {
		r := newRec(fmt.Sprintf("r%03d", i), "")
		r.Data = big
		commitChange(t, n, p, writeChange(t, r, modeMatch, 0))
	}
	w.emitted.Store(0)
	before := filesBelow(t, n.dir)
	pos, rc, err := n.pst.Export(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if pos.Seq != records {
		t.Fatalf("position %d", pos.Seq)
	}
	one := make([]byte, 1)
	if _, err := io.ReadFull(rc, one); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // a producer that is not held back by the reader would be done by now
	if got := w.emitted.Load(); got > 5 {
		t.Fatalf("the export read %d of %d records ahead of a reader that took one byte", got, records)
	}
	if now := filesBelow(t, n.dir); !slices.Equal(now, before) {
		t.Fatalf("files in the data directory during an export: %v", now)
	}
	// the whole stream into a second node, which applies it in batches as it arrives
	n2 := newTestNode(t)
	if err := n2.pst.Import(p, io.MultiReader(bytes.NewReader(one), rc), pos, false); err != nil {
		t.Fatal(err)
	}
	rc.Close()
	if c, _ := n2.st.inner.Count(bg, dataKind, ""); c != records {
		t.Fatalf("%d records imported", c)
	}
	if now := filesBelow(t, n.dir); !slices.Equal(now, before) {
		t.Fatalf("files in the data directory after an export: %v", now)
	}
}

// A reader that is closed early releases the snapshot at once and leaves no goroutine behind, whether it took part of the
// stream or none of it; so does one that is read to the end.
func TestExportReleasedWhenTheReaderCloses(t *testing.T) {
	n := newTestNode(t)
	w := watched(n)
	p := partitionNum("org1")
	big := bytes.Repeat([]byte("x"), 100<<10)
	for i := range 40 {
		r := newRec(fmt.Sprintf("r%02d", i), "")
		r.Data = big
		commitChange(t, n, p, writeChange(t, r, modeMatch, 0))
	}
	released := func(what string) {
		t.Helper()
		waitFor(t, 5*time.Second, what+": the snapshot released", func() bool { return w.active.Load() == 0 })
	}
	baseline := runtime.NumGoroutine()
	// closed without a read
	_, rc, err := n.pst.Export(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	rc.Close()
	released("closed unread")
	// closed after a part
	_, rc, err = n.pst.Export(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 150<<10)
	if _, err := io.ReadFull(rc, buf); err != nil {
		t.Fatal(err)
	}
	if w.active.Load() != 1 {
		t.Fatalf("exports in flight while one is half read: %d", w.active.Load())
	}
	rc.Close()
	released("closed half read")
	if _, err := rc.Read(buf); err == nil {
		t.Fatal("a closed export reads on")
	}
	// read to the end
	_, rc, err = n.pst.Export(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, rc); err != nil {
		t.Fatal(err)
	}
	released("read to the end")
	rc.Close()
	waitFor(t, 5*time.Second, "no goroutine left by the exports", func() bool { return runtime.NumGoroutine() <= baseline })
}

// A failure while the export is under way reaches the reader as an error, not as the end of the stream: the importer
// must not take a short stream for a whole one.
func TestExportFailureIsNotAnEndOfStream(t *testing.T) {
	n := newTestNode(t)
	p := partitionNum("org1")
	for i := range 5 {
		commitChange(t, n, p, writeChange(t, newRec(fmt.Sprintf("r%d", i), ""), modeMatch, 0))
	}
	boom := errors.New("disk failed")
	n.pst.pst = &failingExport{PartitionStore: n.pst.pst, after: 2, err: boom}
	_, rc, err := n.pst.Export(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if _, err := io.ReadAll(rc); !errors.Is(err, boom) {
		t.Fatalf("a failed export read to the end: %v", err)
	}
}

// failingExport fails its export after some records.
type failingExport struct {
	store.PartitionStore
	after int
	err   error
}

func (f *failingExport) ExportPartition(ctx context.Context, p int, after uint64, start func(store.PartitionPos) error,
	fn func(store.PartitionRecord) error) error {
	n := 0
	return f.PartitionStore.ExportPartition(ctx, p, after, start, func(r store.PartitionRecord) error {
		if n++; n > f.after {
			return f.err
		}
		return fn(r)
	})
}

// noStartExport is a backend whose export returns without an error and without ever calling start (a bug).
type noStartExport struct{ store.PartitionStore }

func (noStartExport) ExportPartition(context.Context, int, uint64, func(store.PartitionPos) error,
	func(store.PartitionRecord) error) error {
	return nil
}

// A backend that exports nothing, not even its position, fails the export at once: nothing is written into the pipe
// nobody reads (which would hold the export, and its slot, for ever).
func TestExportWithoutAPositionFails(t *testing.T) {
	n := newTestNode(t)
	n.pst.pst = noStartExport{n.pst.pst}
	done := make(chan error, 1)
	go func() {
		_, rc, err := n.pst.Export(partitionNum("org1"), 0)
		if rc != nil {
			rc.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("an export without a position succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an export without a position hangs")
	}
	waitFor(t, 5*time.Second, "its slot released", func() bool { return len(n.pst.exports) == 0 })
}

// At most exportSlots exports run at once (each holds a snapshot, and on SQLite a reader connection, for its whole
// stream): one more is refused with an error the asker's catch-up retries, and a slot is free again once a reader is
// closed or read to the end.
func TestExportsAreBounded(t *testing.T) {
	for _, c := range []struct{ pool, want int }{{1, 1}, {2, 1}, {4, 2}, {8, 4}, {32, 4}} {
		if got := exportSlots(c.pool); got != c.want {
			t.Errorf("a pool of %d readers: %d exports at once, want %d", c.pool, got, c.want)
		}
	}
	dir := t.TempDir()
	sq := sqliteBackend().open(t, dir)
	defer sq.Close()
	if got := sq.(readerPool).Readers(); got < 4 {
		t.Fatalf("the SQLite reader pool: %d", got)
	}

	n := newTestNode(t)
	p := partitionNum("org1")
	commitChange(t, n, p, writeChange(t, newRec("r1", ""), modeMatch, 0))
	limit := cap(n.pst.exports)
	if limit != exportSlots(8) {
		t.Fatalf("a backend without a reader pool: %d exports at once", limit)
	}
	var open []io.ReadCloser
	for range limit {
		_, rc, err := n.pst.Export(p, 0)
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, rc)
	}
	if _, _, err := n.pst.Export(p, 0); !errors.Is(err, errExportsBusy) {
		t.Fatalf("an export over the limit: %v", err)
	}
	open[0].Close()
	if _, err := io.Copy(io.Discard, open[1]); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "two slots free", func() bool { return len(n.pst.exports) == limit-2 })
	for range 2 {
		_, rc, err := n.pst.Export(p, 0)
		if err != nil {
			t.Fatalf("an export once slots are free: %v", err)
		}
		open = append(open, rc)
	}
	for _, rc := range open {
		rc.Close()
	}
	waitFor(t, 5*time.Second, "every slot free", func() bool { return len(n.pst.exports) == 0 })
}

// While an import of a partition has begun and not finished on this node (it failed part way: batches applied, the
// committed position not moved), its exports are refused: they would leave out the records the import replaced. The
// next import that completes lifts it.
func TestExportRefusedDuringAnUnfinishedImport(t *testing.T) {
	src, dst := newTestNode(t), newTestNode(t)
	p := partitionNum("org1")
	const records = importBatch + 300
	for i := range records {
		commitChange(t, src, p, writeChange(t, newRec(fmt.Sprintf("r%04d", i), ""), modeMatch, 0))
	}
	pos, rc, err := src.pst.Export(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	all, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, rc, err := dst.pst.Export(p, 0); err != nil {
		t.Fatalf("an export before any import: %v", err)
	} else {
		rc.Close()
	}
	// a stream that breaks after the first batch was applied
	if err := dst.pst.Import(p, bytes.NewReader(all[:len(all)*9/10]), pos, true); err == nil {
		t.Fatal("a broken stream was imported")
	}
	if st, _ := dst.pst.State(p); st.Committed == pos {
		t.Fatal("test set-up: the broken import completed")
	}
	if _, _, err := dst.pst.Export(p, 0); !errors.Is(err, errImportUnfinished) {
		t.Fatalf("an export during an unfinished import: %v", err)
	}
	// another partition is not affected
	if _, rc, err := dst.pst.Export(partitionNum("org-other"), 0); err != nil {
		t.Fatalf("an export of another partition: %v", err)
	} else {
		rc.Close()
	}
	// the import repeated to the end
	if err := dst.pst.Import(p, bytes.NewReader(all), pos, true); err != nil {
		t.Fatal(err)
	}
	_, rc, err = dst.pst.Export(p, 0)
	if err != nil {
		t.Fatalf("an export after the import completed: %v", err)
	}
	defer rc.Close()
	br := bufio.NewReader(rc)
	frames := 0
	for {
		fb, err := readFrame(br)
		if err != nil {
			t.Fatalf("the export after the import: %v", err)
		}
		if len(fb) == 0 {
			break
		}
		frames++
	}
	if frames != records {
		t.Fatalf("the export after the import has %d records, the source %d", frames, records)
	}
}

// A partition is imported in batches as the stream arrives: no call holds more than importBatch records, the committed
// position is set by the last only, and a stream that breaks leaves the batches already applied (committed data of the
// source) with the position where it was; the same import repeated completes it, and the hooks hear of every record.
func TestImportStreamsInBatches(t *testing.T) {
	src := newTestNode(t)
	p := partitionNum("org1")
	const records = 2*importBatch + 500
	for i := range records {
		commitChange(t, src, p, writeChange(t, newRec(fmt.Sprintf("r%04d", i), ""), modeMatch, 0))
	}
	pos, rc, err := src.pst.Export(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	all, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	dst := newTestNode(t)
	w := watched(dst)
	var seen atomic.Int64
	dst.OnChange(func(*store.Record, bool) { seen.Add(1) })
	// the stream breaks after the second batch
	cut := bytes.NewReader(all[:len(all)*5/6])
	if err := dst.pst.Import(p, cut, pos, false); err == nil {
		t.Fatal("a stream cut short was imported")
	}
	if st, _ := dst.pst.State(p); st.Committed.Seq != 0 {
		t.Fatalf("a stream that broke moved the position to %d", st.Committed.Seq)
	}
	calls := w.importCalls()
	if len(calls) != 2 || calls[0].n != importBatch || !calls[0].step.First || calls[1].step.First || calls[0].step.Final || calls[1].step.Final {
		t.Fatalf("calls of a broken import: %+v", calls)
	}
	if c, _ := dst.st.inner.Count(bg, dataKind, ""); c != 2*importBatch {
		t.Fatalf("%d records stored by the batches before the break, want %d", c, 2*importBatch)
	}
	// the same import again
	if err := dst.pst.Import(p, bytes.NewReader(all), pos, false); err != nil {
		t.Fatal(err)
	}
	calls = w.importCalls()[2:]
	if len(calls) != 3 || calls[0].n != importBatch || calls[1].n != importBatch || calls[2].n != 500 ||
		!calls[0].step.First || !calls[2].step.Final || calls[1].step.Final || calls[0].step.Full {
		t.Fatalf("calls of the import: %+v", calls)
	}
	if c, _ := dst.st.inner.Count(bg, dataKind, ""); c != records {
		t.Fatalf("%d records, want %d", c, records)
	}
	if st, _ := dst.pst.State(p); st.Committed.Seq != records {
		t.Fatalf("committed %d", st.Committed.Seq)
	}
	if got := seen.Load(); got < records {
		t.Fatalf("%d hooks for %d records", got, records)
	}
}

// A full copy in batches removes at its end what the batches did not bring, and says which (the hooks).
func TestFullImportInBatchesReportsRemovedRecords(t *testing.T) {
	src, dst := newTestNode(t), newTestNode(t)
	w := watched(dst)
	p := partitionNum("org1")
	const records = importBatch + 300
	for i := range records {
		commitChange(t, src, p, writeChange(t, newRec(fmt.Sprintf("keep%04d", i), ""), modeMatch, 0))
		if i%100 == 0 {
			commitChange(t, dst, p, writeChange(t, newRec(fmt.Sprintf("keep%04d", i), ""), modeMatch, 0)) // held on both
		}
	}
	for i := range 7 {
		commitChange(t, dst, p, writeChange(t, newRec(fmt.Sprintf("gone%d", i), ""), modeMatch, 0))
	}
	pos, rc, err := src.pst.Export(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	var mu sync.Mutex
	removed := map[string]bool{}
	dst.OnChange(func(r *store.Record, local bool) {
		if r.Deleted {
			mu.Lock()
			removed[r.ID] = true
			mu.Unlock()
		}
	})
	if err := dst.pst.Import(p, rc, pos, true); err != nil {
		t.Fatal(err)
	}
	if len(removed) != 7 {
		t.Fatalf("removals reported: %v", removed)
	}
	for i := range 7 {
		id := fmt.Sprintf("gone%d", i)
		if !removed[id] {
			t.Fatalf("%s not reported", id)
		}
		if _, err := dst.st.inner.Get(bg, dataKind, id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s is still there: %v", id, err)
		}
	}
	if c, _ := dst.st.inner.Count(bg, dataKind, ""); c != records {
		t.Fatalf("%d records, want %d", c, records)
	}
	calls := w.importCalls()
	if len(calls) != 2 || !calls[0].step.Full || !calls[0].step.First || !calls[1].step.Final {
		t.Fatalf("calls: %+v", calls)
	}
}

// A fresh read answers from the committed data of one partition, refuses what does not fit one message, and leaves out
// the records of other partitions.
func TestReadAnswers(t *testing.T) {
	n, _ := gnode(t)
	p := partitionNum("org1")
	commitChange(t, n, p, writeChange(t, newRec("a", ""), modeMatch, 0))
	big := newRec("b", "")
	big.Data = bytes.Repeat([]byte("y"), maxReadReply)
	commitChange(t, n, p, writeChange(t, big, modeMatch, 0))
	read := func(p int, ids ...string) ([][]byte, error) {
		b, err := encodeMsg(&readReq{Kind: string(dataKind), IDs: ids})
		if err != nil {
			t.Fatal(err)
		}
		out, err := n.pst.Read(p, b)
		if err != nil {
			return nil, err
		}
		var recs [][]byte
		return recs, decodeMsg(out, &recs)
	}
	if recs, err := read(p, "a", "missing"); err != nil || len(recs) != 1 {
		t.Fatalf("%d records, %v", len(recs), err)
	}
	if recs, err := read((p+1)%partitions, "a"); err != nil || len(recs) != 0 {
		t.Fatalf("a record of another partition: %d %v", len(recs), err)
	}
	if _, err := read(p, "a", "b"); refusalCode(err) != whyLarge {
		t.Fatalf("a reply too large for one message: %v", err)
	}
	if _, err := n.pst.Read(p, []byte("garbage")); refusalCode(err) != whyBad {
		t.Fatalf("garbage: %v", err)
	}
}

// Audit events are never part of the partition protocol: an owner refuses one as a write, an export leaves it out, an
// import never brings one (another node's), seeding a new cluster leaves them as they are, and a full copy of the
// partition their organization's records are in leaves a node's own events untouched.
func TestAuditNeverInAPartition(t *testing.T) {
	src, dst := newTestNode(t), newTestNode(t)
	org := "org1"
	p := partitionNum(org)
	ev := auditRec(t, org, "user.create", time.Now())
	if code := prepare(t, src, p, writeChange(t, ev, modeMatch, 0)); code != whyBad {
		t.Fatalf("an audit event as a partition write: %q", code)
	}
	// each node records its own, locally
	mine := auditRec(t, org, "user.update", time.Now())
	if err := dst.st.Put(bg, mine); err != nil {
		t.Fatal(err)
	}
	if err := src.st.Put(bg, ev); err != nil {
		t.Fatal(err)
	}
	commitChange(t, src, p, writeChange(t, newRec("kept", ""), modeMatch, 0))
	pos, rc, err := src.pst.Export(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	all, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(all, []byte(ev.ID)) {
		t.Fatal("an export carries an audit event")
	}
	// a full copy of the partition: dst's own event stays, src's never arrives
	if err := dst.pst.Import(p, bytes.NewReader(all), pos, true); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.st.Inner().Get(bg, model.KindAudit, mine.ID); err != nil {
		t.Fatalf("a full copy removed this node's own audit event: %v", err)
	}
	if _, err := dst.st.Inner().Get(bg, model.KindAudit, ev.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another node's audit event arrived: %v", err)
	}
	if !has(dst.st, "kept") {
		t.Fatal("the copy did not bring the partition's record")
	}

	// seeding a new cluster leaves audit events out of the partitions
	dir := t.TempDir()
	st := badgerBackend().open(t, dir)
	defer st.Close()
	seedPlain(t, st, 0, 2)
	if err := st.Put(bg, auditRec(t, "org-000", "server.bootstrap", time.Now())); err != nil {
		t.Fatal(err)
	}
	if err := StartNewCluster(bg, dir, st); err != nil {
		t.Fatal(err)
	}
	if n, _ := exportedCount(t, st); n != 2 {
		t.Fatalf("%d records in the partitions after seeding, want the 2 that are not audit events", n)
	}
	if c, _ := st.Count(bg, model.KindAudit, ""); c != 1 {
		t.Fatalf("the audit event after seeding: %d", c)
	}
}

// A pending write is kept in the database as it is, and is the partition's pending write again when the node starts
// anew on that database (the partition protocol settles it then).
func TestPendingWriteIsKeptAcrossARestart(t *testing.T) {
	st := memstore.New()
	c := newTCluster(t, 3, backend{"one database", func(testing.TB, string) store.Store { return st }})
	dir := t.TempDir()
	tn := c.build(0, dir, nil)
	p := partitionNum("org1")
	w := &partition.Write{Partition: p, Pos: partition.Pos{Epoch: partition.Epoch{Counter: 3}, Seq: 1}, Data: []byte("change")}
	if err := tn.n.pst.SetPending(p, w); err != nil {
		t.Fatal(err)
	}
	tn.n.Close()
	again := c.build(0, dir, nil)
	defer again.n.Close()
	got, err := again.n.pst.State(p)
	if err != nil || got.Pending == nil || got.Pending.Pos != w.Pos || string(got.Pending.Data) != "change" {
		t.Fatalf("the pending write after a restart: %+v %v", got.Pending, err)
	}
}
