package kvstore

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A store at an older format is migrated at open, once, step by step; one from a newer build, or from before
// formatBase, is refused. (There are no real migrations yet: this test adds two.)
func TestFormatMigrations(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	open := func() (*Store, error) { return OpenBadger(ctx, dir, BadgerOptions{}) }
	s, err := open()
	if err != nil {
		t.Fatal(err)
	}
	set := func(v string) {
		t.Helper()
		if err := s.eng.Update(ctx, func(tx txn) error { tx.Set(metaFormat, []byte(v)); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	set("1") // a pre-release format older than formatBase
	s.Close()
	if _, err := open(); err == nil || !strings.Contains(err.Error(), "pre-release") {
		t.Fatalf("an old pre-release store: %v", err)
	}
	s, _ = OpenBadger(ctx, t.TempDir(), BadgerOptions{}) // (the refused one stays refused; carry on with a new one)
	dir = s.eng.(*badgerEngine).db.Opts().Dir

	saved := formatMigrations
	t.Cleanup(func() { formatMigrations = saved })
	var ran []string
	failOnce := true
	formatMigrations = []formatMigration{
		{"first", func(ctx context.Context, s *Store) error { ran = append(ran, "first"); return nil }},
		{"second", func(ctx context.Context, s *Store) error {
			if failOnce {
				failOnce = false
				return errors.New("interrupted")
			}
			ran = append(ran, "second")
			return nil
		}},
	}
	s.Close()
	if _, err := open(); err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("an interrupted migration: %v", err)
	}
	s, err = open() // resumes at the second migration
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ran, ",") != "first,second" {
		t.Fatalf("migrations run: %v", ran)
	}
	if b, _ := s.eng.Get(ctx, metaFormat); string(b) != "4" {
		t.Fatalf("format after migrating: %s", b)
	}
	s.Close()
	if s, err = open(); err != nil || len(ran) != 2 {
		t.Fatalf("reopened: %v (%v)", err, ran)
	}
	s.Close()

	formatMigrations = saved // a build that knows fewer formats: the store is newer than it
	if _, err := open(); err == nil || !strings.Contains(err.Error(), "newer build") {
		t.Fatalf("a store from a newer build: %v", err)
	}
}
