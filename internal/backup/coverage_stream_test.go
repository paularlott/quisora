package backup

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

func covSealer(t testing.TB) *secure.Sealer {
	t.Helper()
	s, err := secure.NewSealer(secure.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func covJSON(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func covHeader(s *secure.Sealer) string {
	b, _ := json.Marshal(header{Format: format, Version: version, Created: time.Now().UTC(), KeyCheck: keyCheck(s)})
	return string(b)
}

// covGroup is the line of a valid group record, changed by mod.
func covGroup(t testing.TB, id, name string, mod func(*line)) string {
	t.Helper()
	g := &model.Group{OrgID: "org", DisplayName: name}
	g.ID = id
	rec, err := store.Encode(g)
	if err != nil {
		t.Fatal(err)
	}
	l := line{Kind: model.KindGroup, ID: id, Version: rec.Version, Created: rec.Version, Origin: "n1",
		Data: base64.StdEncoding.EncodeToString(rec.Data)}
	if mod != nil {
		mod(&l)
	}
	return covJSON(t, l)
}

// covStream assembles an encrypted backup from raw lines with a trailer signed over them (unless the caller overwrites
// the MAC through trailer): a damaged line then fails on its own account, not on the integrity check.
func covStream(t testing.TB, s *secure.Sealer, first string, body []string, trailer func(*line)) []byte {
	t.Helper()
	mac := newMAC(s)
	mac.Write([]byte(first + "\n"))
	records := 0
	for _, b := range body {
		mac.Write([]byte(b + "\n"))
		records++
	}
	tr := line{End: true, Records: records}
	macTrailer(mac, tr.Records, tr.Sealed)
	tr.MAC = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if trailer != nil {
		trailer(&tr)
	}
	out, err := Pack([]byte(first+"\n"+strings.Join(append(body, covJSON(t, tr)), "\n")+"\n"), covPassword)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifyRejectsDamagedRecordLines(t *testing.T) {
	s := covSealer(t)
	h := covHeader(s)
	cases := []struct {
		name string
		body []string
		want string
	}{
		{"unknown kind", []string{covGroup(t, "g1", "a", func(l *line) { l.Kind = "bogus" })}, "unknown kind"},
		{"skipped kind", []string{covGroup(t, "g1", "a", func(l *line) { l.Kind = model.KindEphemeral })}, "unknown kind"},
		{"bad base64", []string{covGroup(t, "g1", "a", func(l *line) { l.Data = "***" })}, "bad group record"},
		{"no id", []string{covGroup(t, "g1", "a", func(l *line) { l.ID = "" })}, "bad group record"},
		{"no version", []string{covGroup(t, "g1", "a", func(l *line) { l.Version = 0 })}, "bad group record"},
		{"undecodable data", []string{covGroup(t, "g1", "a", func(l *line) { l.Data = base64.StdEncoding.EncodeToString([]byte("not msgpack")) })}, "group g1"},
		{"id mismatch", []string{covGroup(t, "g1", "a", func(l *line) { l.ID = "other" })}, "id mismatch"},
		{"epoch not before version", []string{covGroup(t, "g1", "a", func(l *line) { l.Epoch = l.Version })}, "bad generation"},
		{"created after version", []string{covGroup(t, "g1", "a", func(l *line) { l.Created = l.Version + 1 })}, "bad generation"},
		{"not json", []string{"this is not json"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(bytes.NewReader(covStream(t, s, h, tc.body, nil)), s, covPassword)
			if !errors.Is(err, ErrFormat) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want ErrFormat containing %q", err, tc.want)
			}
		})
	}
}

func TestVerifyHeaderAndTrailerDamage(t *testing.T) {
	s := covSealer(t)
	good := []string{covGroup(t, "g1", "a", nil)}
	st, err := Verify(bytes.NewReader(covStream(t, s, covHeader(s), good, nil)), s, covPassword)
	if err != nil || st[model.KindGroup] != 1 {
		t.Fatalf("a valid crafted backup: %v %v", st, err)
	}
	for name, first := range map[string]string{
		"header not json":  "nope",
		"wrong format":     covJSON(t, header{Format: "other", Version: version}),
		"empty header obj": "{}",
	} {
		if _, err := Verify(bytes.NewReader(covStream(t, s, first, good, nil)), s, covPassword); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A stream that holds nothing: the first line cannot be read.
	empty, _ := Pack(nil, covPassword)
	if _, err := Verify(bytes.NewReader(empty), s, covPassword); !errors.Is(err, ErrFormat) {
		t.Errorf("empty stream: %v", err)
	}
	if _, err := Verify(bytes.NewReader(covStream(t, s, covHeader(s), good, func(l *line) { l.Records = 5 })), s, covPassword); !errors.Is(err, ErrFormat) ||
		!strings.Contains(err.Error(), "trailer says 5") {
		t.Errorf("wrong count: %v", err)
	}
	if _, err := Verify(bytes.NewReader(covStream(t, s, covHeader(s), good, func(l *line) { l.MAC = "!!!" })), s, covPassword); !errors.Is(err, ErrFormat) {
		t.Errorf("bad mac: %v", err)
	}
	// Without a sealer only the structure is checked: a bad MAC passes, a bad count does not.
	if _, err := Verify(bytes.NewReader(covStream(t, s, covHeader(s), good, func(l *line) { l.MAC = "!!!" })), nil, covPassword); err != nil {
		t.Errorf("structure-only check: %v", err)
	}
}

// A record line longer than the reader's buffer is read whole; one past maxLine is refused rather than buffered.
func TestVerifyLongRecordLines(t *testing.T) {
	s := covSealer(t)
	long := covGroup(t, "g1", strings.Repeat("n", 200<<10), nil)
	st, err := Verify(bytes.NewReader(covStream(t, s, covHeader(s), []string{long}, nil)), s, covPassword)
	if err != nil || st.Total() != 1 {
		t.Fatalf("a 200 KB line: %v %v", st, err)
	}
	huge := covGroup(t, "g1", "x", func(l *line) { l.Data = strings.Repeat("A", maxLine+(64<<10)) })
	if _, err := Verify(bytes.NewReader(covStream(t, s, covHeader(s), []string{huge}, nil)), s, covPassword); !errors.Is(err, ErrFormat) {
		t.Fatalf("a line past maxLine: %v", err)
	}
}

// Two records of a backup claiming one unique value cannot both be restored, forced or not: nothing is merged by
// guessing which keeps it.
func TestRestoreRefusesUniqueClash(t *testing.T) {
	s := covSealer(t)
	data := covStream(t, s, covHeader(s), []string{covGroup(t, "g1", "same", nil), covGroup(t, "g2", "same", nil)}, nil)
	for _, force := range []bool{false, true} {
		if _, err := Restore(context.Background(), memstore.New(), s, bytes.NewReader(data), force, covPassword, t.TempDir()); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("clash (force %v): %v", force, err)
		}
	}
}

// failingStore fails the calls its fields name.
type failingStore struct {
	store.Store
	list, count, put error
	snapshot         func() (store.Reader, error)
}

func (f failingStore) List(ctx context.Context, k model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if f.list != nil {
		return nil, f.list
	}
	return f.Store.List(ctx, k, q)
}

func (f failingStore) Count(ctx context.Context, k model.Kind, scope string) (int, error) {
	if f.count != nil {
		return 0, f.count
	}
	return f.Store.Count(ctx, k, scope)
}

func (f failingStore) PutReplicated(ctx context.Context, r *store.Record) (bool, error) {
	if f.put != nil {
		return false, f.put
	}
	return f.Store.PutReplicated(ctx, r)
}

type snapshottingStore struct {
	failingStore
}

func (s snapshottingStore) Snapshot(context.Context) (store.Reader, error) { return s.snapshot() }

type countingReader struct {
	store.Reader
	lists, closes int
}

func (c *countingReader) List(ctx context.Context, k model.Kind, q store.ListQuery) (*store.ListResult, error) {
	c.lists++
	return c.Reader.List(ctx, k, q)
}
func (c *countingReader) Close() error { c.closes++; return c.Reader.Close() }

func covStoreWithGroups(t testing.TB, n int) store.Store {
	t.Helper()
	st := memstore.New()
	for i := range n {
		g := &model.Group{OrgID: "org", DisplayName: fmt.Sprint("group-", i)}
		rec, err := store.Encode(g)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Put(context.Background(), rec); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

func TestWriteSnapshotChoices(t *testing.T) {
	ctx := context.Background()
	s := covSealer(t)
	base := covStoreWithGroups(t, 3)

	view := &countingReader{Reader: liveReader{base}}
	st := snapshottingStore{failingStore{Store: base, snapshot: func() (store.Reader, error) { return view, nil }}}
	var buf bytes.Buffer
	if stats, err := WriteWith(ctx, st, s, &buf, Options{Password: covPassword}); err != nil || stats[model.KindGroup] != 3 {
		t.Fatalf("with a snapshot: %v %v", stats, err)
	}
	if view.lists == 0 || view.closes != 1 {
		t.Fatalf("snapshot used %d times, closed %d times", view.lists, view.closes)
	}

	// A backend without a snapshot reads the live store.
	st.snapshot = func() (store.Reader, error) { return nil, store.ErrNoSnapshot }
	buf.Reset()
	if stats, err := WriteWith(ctx, st, s, &buf, Options{Password: covPassword}); err != nil || stats[model.KindGroup] != 3 {
		t.Fatalf("no snapshot: %v %v", stats, err)
	}

	// Any other snapshot failure fails the backup: no silent fall back to a live read.
	boom := errors.New("snapshot boom")
	st.snapshot = func() (store.Reader, error) { return nil, boom }
	if _, err := WriteWith(ctx, st, s, io.Discard, Options{Password: covPassword}); !errors.Is(err, boom) || !strings.Contains(err.Error(), "snapshot") {
		t.Fatalf("snapshot failure: %v", err)
	}
}

func TestLiveReaderForwards(t *testing.T) {
	st := covStoreWithGroups(t, 2)
	r := liveReader{st}
	if n, err := r.Count(context.Background(), model.KindGroup, ""); err != nil || n != 2 {
		t.Fatalf("%d %v", n, err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWriteStoreAndContextErrors(t *testing.T) {
	s := covSealer(t)
	boom := errors.New("list boom")
	if _, err := WriteWith(context.Background(), failingStore{Store: memstore.New(), list: boom}, s, io.Discard, Options{Password: covPassword}); !errors.Is(err, boom) {
		t.Fatalf("list error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := WriteWith(ctx, memstore.New(), s, io.Discard, Options{Password: covPassword}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}

func TestEmptyAndRestoreCountError(t *testing.T) {
	s := covSealer(t)
	boom := errors.New("count boom")
	st := failingStore{Store: memstore.New(), count: boom}
	if _, err := Empty(context.Background(), st); !errors.Is(err, boom) {
		t.Fatalf("%v", err)
	}
	data := covStream(t, s, covHeader(s), []string{covGroup(t, "g1", "a", nil)}, nil)
	if _, err := Restore(context.Background(), st, s, bytes.NewReader(data), false, covPassword, t.TempDir()); !errors.Is(err, boom) {
		t.Fatalf("restore: %v", err)
	}
}

type noSeek struct{ io.Reader }

func (noSeek) Seek(int64, int) (int64, error) { return 0, errors.New("seek boom") }

func TestRestoreSeekPutAndContextErrors(t *testing.T) {
	s := covSealer(t)
	data := covStream(t, s, covHeader(s), []string{covGroup(t, "g1", "a", nil)}, nil)
	ctx := context.Background()
	// read once, then restored from the private copy it was verified into: the caller's reader is never rewound
	if _, err := Restore(ctx, memstore.New(), s, noSeek{bytes.NewReader(data)}, false, covPassword, t.TempDir()); err != nil {
		t.Fatalf("a reader that cannot seek: %v", err)
	}
	boom := errors.New("put boom")
	if _, err := Restore(ctx, failingStore{Store: memstore.New(), put: boom}, s, bytes.NewReader(data), false, covPassword, t.TempDir()); !errors.Is(err, boom) ||
		!strings.Contains(err.Error(), "restore group g1") {
		t.Fatalf("put: %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	dst := memstore.New()
	if _, err := Restore(cctx, dst, s, bytes.NewReader(data), false, covPassword, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
	if empty, _ := Empty(ctx, dst); !empty {
		t.Fatal("a cancelled restore wrote records")
	}
}

// A value sealed before values named their key, or a grant with only the legacy secret, may need any key of the ring.
// A backup needs the master key each sealed value names, and only those.
func TestSealedKeysNeedTheKeysNamed(t *testing.T) {
	enc := func(e model.Entity) *store.Record {
		rec, err := store.EncodeAsIs(e)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	need := map[string]bool{}
	sealedKeys(enc(&model.Grant{Key: "v3:k2:AAAA"}), need)
	sealedKeys(enc(&model.User{PasswordHash: "v3:k1:BBBB"}), need)
	if len(need) != 2 || !need["k1"] || !need["k2"] {
		t.Errorf("named keys: %v", need)
	}
	need = map[string]bool{}
	sealedKeys(enc(&model.Group{DisplayName: "x"}), need)
	sealedKeys(&store.Record{Kind: model.KindUser, Data: []byte("garbage")}, need)
	if len(need) != 0 {
		t.Errorf("nothing sealed: %v", need)
	}
}

func TestStatsTotal(t *testing.T) {
	if (Stats{model.KindUser: 2, model.KindGroup: 3}).Total() != 5 || (Stats(nil)).Total() != 0 {
		t.Fatal("Total")
	}
}
