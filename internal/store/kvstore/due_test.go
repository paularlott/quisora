package kvstore

import (
	"context"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// The due index lists only the users whose end date has come, earliest first, without reading the others; it follows
// every write.
func TestDueIndex(t *testing.T) {
	ctx := context.Background()
	s, err := OpenBadger(ctx, t.TempDir(), BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC().Truncate(time.Millisecond)
	put := func(name string, until *time.Time, active bool) *model.User {
		t.Helper()
		u := &model.User{Meta: model.Meta{ID: model.NewID(), Created: now}, OrgID: "org1", Username: name,
			Email: name + "@x.example", Role: model.RoleUser, Active: active, ValidUntil: until}
		r, err := store.Encode(u)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, r); err != nil {
			t.Fatal(err)
		}
		return u
	}
	at := func(d time.Duration) *time.Time { t := now.Add(d); return &t }
	put("later", at(time.Hour), true)
	put("second", at(-time.Minute), true)
	first := put("first", at(-time.Hour), true)
	put("never", nil, true)
	put("disabled", at(-2*time.Hour), false)

	names := func() []string {
		t.Helper()
		recs, err := s.ListDue(ctx, model.KindUser, now, 0)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range recs {
			var u model.User
			if err := store.Decode(r, &u); err != nil {
				t.Fatal(err)
			}
			out = append(out, u.Username)
		}
		return out
	}
	if got := names(); len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Fatalf("due: %v, want [first second]", got)
	}
	// Disabled (as the job does): no longer due.
	cur, err := s.Get(ctx, model.KindUser, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	first.Active = false
	r, _ := store.Encode(first)
	if err := s.CompareAndPut(ctx, r, cur.Version); err != nil {
		t.Fatal(err)
	}
	if got := names(); len(got) != 1 || got[0] != "second" {
		t.Fatalf("after disabling first: %v", got)
	}

}

// An equality filter on an indexed field reads that field's index bucket, not the whole kind.
func TestFieldIndex(t *testing.T) {
	ctx := context.Background()
	s, err := OpenBadger(ctx, t.TempDir(), BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := range 30 {
		client := "app-a"
		if i%3 == 0 {
			client = "app-b"
		}
		g := &model.Grant{Meta: model.Meta{ID: model.NewID(), Created: time.Now()}, UserID: "u" + string(rune('a'+i)),
			OrgID: "org1", ClientID: client, Expires: time.Now().Add(time.Hour)}
		r, err := store.Encode(g)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	count := func() int {
		t.Helper()
		res, err := s.List(ctx, model.KindGrant, store.ListQuery{Filters: []store.Filter{{Field: "client_id", Value: "app-b"}}})
		if err != nil {
			t.Fatal(err)
		}
		return res.Total
	}
	if n := count(); n != 10 {
		t.Fatalf("app-b grants: %d, want 10", n)
	}
	// Without the buckets the filter finds nothing: it reads them, not the kind.
	if err := s.eng.Update(ctx, func(tx txn) error {
		for _, c := range []string{"app-a", "app-b"} {
			b := fieldBucket(model.KindGrant, "client_id", c)
			members, err := s.eng.Range(ctx, b, "", "", 0)
			for _, m := range members {
				tx.SetDel(b, m)
			}
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 0 {
		t.Fatalf("with the index dropped the filter still found %d: it is not read from the index", n)
	}
}
