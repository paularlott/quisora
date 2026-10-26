package kvstore

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/shamaton/msgpack/v3"
)

// TestMigrationScale upgrades a Badger store of QUISORA_MIGRATION_USERS users (5,000,000 for the target: 5,000
// organizations of 1,000) through a format migration that rewrites every user: the given name moved from an old
// stored key ("gnm") to the current one ("gn"), which changes the "name" sort index of each. Opt-in: seeding takes
// minutes and gigabytes.
func TestMigrationScale(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("QUISORA_MIGRATION_USERS"))
	if n <= 0 {
		t.Skip("set QUISORA_MIGRATION_USERS (5000000 for the target)")
	}
	const perOrg = 1000
	ctx := context.Background()
	dir := t.TempDir()

	// Seed with the old format: users whose given name is stored under "gnm", as an older build would have left them
	// (index fields as that build computed them).
	s, err := OpenBadger(ctx, dir, BadgerOptions{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	batch := make([]*store.Record, 0, 1000)
	flush := func() {
		if _, err := s.PutReplicatedBatch(ctx, batch); err != nil {
			t.Fatal(err)
		}
		batch = batch[:0]
	}
	for i := range n {
		org := fmt.Sprintf("org-%05d", i/perOrg)
		u := &model.User{Meta: model.Meta{ID: model.NewID(), Version: store.Clock.Now(), Created: time.Now()},
			OrgID: org, Username: fmt.Sprintf("u%07d", i), Email: fmt.Sprintf("u%07d@example.com", i),
			GivenName: fmt.Sprintf("Given %07d", n-i), Role: model.RoleUser, Active: true}
		r, err := store.EncodeAsIs(u)
		if err != nil {
			t.Fatal(err)
		}
		r.Created = r.Version
		if r.Data, err = renameKey(r.Data, "gn", "gnm"); err != nil || r.Data == nil {
			t.Fatalf("seeding the old format: %v", err)
		}
		if batch = append(batch, r); len(batch) == cap(batch) {
			flush()
		}
	}
	flush()
	t.Logf("seeded %d users in %d organizations in %s", n, n/perOrg, time.Since(start).Round(time.Second))
	if err := s.markFormat(ctx, currentFormat()); err != nil {
		t.Fatal(err)
	}
	s.Close()

	saved := formatMigrations
	t.Cleanup(func() { formatMigrations = saved })
	formatMigrations = append(slices.Clone(saved), formatMigration{"given name key", func(ctx context.Context, s *Store) error {
		_, err := s.rewriteRecords(ctx, model.KindUser, func(r *store.Record) (bool, error) {
			data, err := renameKey(r.Data, "gnm", "gn")
			if err != nil || data == nil {
				return false, err // nothing to rename: migrated already
			}
			r.Data = data
			return true, nil
		})
		return err
	}})

	// The upgrade: the next open migrates, with fsync on as in production.
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start = time.Now()
	s, err = OpenBadger(ctx, dir, BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	took := time.Since(start)
	runtime.ReadMemStats(&after)
	t.Logf("migrated %d users in %s (%.0f users/s), allocated %.0f MB, heap in use %.0f MB", n, took.Round(time.Second),
		float64(n)/took.Seconds(), float64(after.TotalAlloc-before.TotalAlloc)/(1<<20), float64(after.HeapInuse)/(1<<20))

	// Every user reads its given name again, and the name index follows: org-00000's first user by name is the
	// one with the lowest number, the last one seeded in it.
	res, err := s.List(ctx, model.KindUser, store.ListQuery{Scope: "org-00000", Sort: "name", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	var u model.User
	if len(res.Records) != 1 || store.Decode(res.Records[0], &u) != nil ||
		u.GivenName != fmt.Sprintf("Given %07d", n-perOrg+1) || res.Total != perOrg {
		t.Fatalf("after the migration: %d records, total %d, first %+v", len(res.Records), res.Total, u.GivenName)
	}
	if b, _ := s.eng.Get(ctx, metaFormat); string(b) != strconv.Itoa(currentFormat()) {
		t.Fatalf("format %s after the migration", b)
	}
}

// renameKey renames the top-level key from to to in a msgpack map; nil when there is no such key.
func renameKey(data []byte, from, to string) ([]byte, error) {
	var m map[string]any
	if err := msgpack.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	v, ok := m[from]
	if !ok {
		return nil, nil
	}
	delete(m, from)
	m[to] = v
	return msgpack.Marshal(m)
}
