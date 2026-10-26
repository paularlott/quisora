package kvstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// A record that no longer decodes (bit rot, a foreign writer) is an error to every reader, never a silent skip
// and never a panic.
func TestCorruptStoredRecordIsAnErrorOnEveryPath(t *testing.T) {
	ctx := context.Background()
	s := openBadger(t, BadgerOptions{})
	good := record(model.KindLink, "good", time.Time{}, "u-good")
	if err := s.Put(ctx, good); err != nil {
		t.Fatal(err)
	}
	// Corrupt the stored bytes in place; the indexes still point at the record.
	err := s.eng.Update(ctx, func(tx txn) error {
		tx.Set(recKey(model.KindLink, "good"), []byte{0xc1, 0xc1, 0xc1})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]func() error{
		"Get":      func() error { _, err := s.Get(ctx, model.KindLink, "good"); return err },
		"Lookup":   func() error { _, err := s.Lookup(ctx, model.KindLink, "good"); return err },
		"ByUnique": func() error { _, err := s.GetByUnique(ctx, model.KindLink, "u-good"); return err },
		"GetMany":  func() error { _, err := s.GetMany(ctx, model.KindLink, []string{"good"}); return err },
		"List":     func() error { _, err := s.List(ctx, model.KindLink, store.ListQuery{Scope: "sc"}); return err },
		"Put":      func() error { return s.Put(ctx, record(model.KindLink, "good", time.Time{})) },
		"Repl": func() error {
			_, err := s.PutReplicated(ctx, record(model.KindLink, "good", time.Time{}))
			return err
		},
		"ReplB": func() error {
			_, err := s.PutReplicatedBatch(ctx, []*store.Record{record(model.KindLink, "good", time.Time{})})
			return err
		},
		"CAS": func() error { return s.CompareAndPut(ctx, record(model.KindLink, "good", time.Time{}), 1) },
	}
	for name, f := range checks {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s panicked on a corrupt record: %v", name, r)
				}
			}()
			if err := f(); err == nil || errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s over a corrupt record: %v", name, err)
			}
		}()
	}
}

// An entry of the tombstone or expiry index that is not kind/id fails Purge, naming the index.
func TestCorruptIndexEntryFailsPurge(t *testing.T) {
	ctx := context.Background()
	now := time.Now().Add(time.Hour)
	// An index entry that is not kind/id.
	for _, bucket := range []string{"tomb", "exp"} {
		s := openBadger(t, BadgerOptions{})
		err := s.eng.Update(ctx, func(tx txn) error { tx.SetAdd(bucket, "0000/notenough", 0); return nil })
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Purge(ctx, now, now); err == nil || !strings.Contains(err.Error(), "corrupt "+bucket+" index entry") {
			t.Fatalf("%s: %v", bucket, err)
		}
	}
}
