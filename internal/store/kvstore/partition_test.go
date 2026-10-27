package kvstore

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/storetest"
)

func TestBadgerPartition(t *testing.T) {
	storetest.RunPartition(t, func(t testing.TB) store.Store {
		s, err := OpenBadger(context.Background(), t.TempDir(), BadgerOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

func TestBadgerPartitionDurable(t *testing.T) {
	storetest.RunPartitionDurable(t, func(t testing.TB) *storetest.Durable {
		dir := t.TempDir()
		open := func(dir string) store.Store {
			s, err := OpenBadger(context.Background(), dir, BadgerOptions{})
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
		d := &storetest.Durable{Store: open(dir)}
		cur := d.Store
		d.Reopen = func() store.Store {
			cur.Close()
			cur = open(dir)
			return cur
		}
		d.Crash = func() store.Store {
			img := t.TempDir()
			copyTree(t, dir, img)
			return open(img)
		}
		t.Cleanup(func() { cur.Close() })
		return d
	})
}

// copyTree copies a directory as it is on disk, files Badger pre-allocates (sparse) included without writing their
// holes.
func copyTree(t testing.TB, from, to string) {
	t.Helper()
	err := filepath.Walk(from, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, path)
		dst := filepath.Join(to, rel)
		if info.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		defer out.Close()
		buf := make([]byte, 1<<20)
		var off int64
		for {
			n, err := in.Read(buf)
			if n > 0 {
				zero := true
				for _, b := range buf[:n] {
					if b != 0 {
						zero = false
						break
					}
				}
				if !zero {
					if _, werr := out.WriteAt(buf[:n], off); werr != nil {
						return werr
					}
				}
				off += int64(n)
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}
		}
		return out.Truncate(off)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func rec(t testing.TB, org, name string) *store.Record {
	t.Helper()
	r, err := store.Encode(&model.User{OrgID: org, Username: name, Email: name + "@example.com", Role: model.RoleUser, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The partition stamp survives a rewrite by a format migration, and a plain write clears it.
func TestStampKeptByRewriteClearedByPlainWrite(t *testing.T) {
	ctx := context.Background()
	s, err := OpenBadger(ctx, t.TempDir(), BadgerOptions{InMemory: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u := rec(t, "o", "stamp")
	if err := s.ApplyPartition(ctx, 4, []*store.Record{u}, store.PartitionPos{Seq: 7}); err != nil {
		t.Fatal(err)
	}
	n, err := s.rewriteRecords(ctx, model.KindUser, func(r *store.Record) (bool, error) { r.Data = slices.Clone(r.Data); return true, nil })
	if err != nil || n != 1 {
		t.Fatalf("rewrite: %d %v", n, err)
	}
	var got []store.PartitionRecord
	if _, err := exportAfter(s, ctx, 4, 0, func(r store.PartitionRecord) error { got = append(got, r); return nil }); err != nil || len(got) != 1 || got[0].Seq != 7 {
		t.Fatalf("after rewrite: %v %+v", err, got)
	}
	v := *u
	v.Version = store.Clock.Now()
	if err := s.Put(ctx, &v); err != nil {
		t.Fatal(err)
	}
	got = nil
	if _, err := exportAfter(s, ctx, 4, 0, func(r store.PartitionRecord) error { got = append(got, r); return nil }); err != nil || len(got) != 0 {
		t.Fatalf("after a plain put: %v %+v", err, got)
	}
	if ents, _ := s.eng.Range(ctx, psBucket(4), "", "", 0); len(ents) != 0 {
		t.Fatalf("index entries left: %v", ents)
	}
}

// exportAfter runs ExportPartition and returns the position it started with.
func exportAfter(s *Store, ctx context.Context, p int, after uint64, fn func(store.PartitionRecord) error) (store.PartitionPos, error) {
	var pos store.PartitionPos
	err := s.ExportPartition(ctx, p, after, func(at store.PartitionPos) error { pos = at; return nil }, fn)
	return pos, err
}
