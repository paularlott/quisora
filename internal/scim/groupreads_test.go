package scim_test

import (
	"context"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// readCountingStore counts the read calls made to the store (a GetMany is one call, as on the backends that read
// many records at once).
type readCountingStore struct {
	store.Store
	calls atomic.Int64
}

func (s *readCountingStore) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	s.calls.Add(1)
	return s.Store.Get(ctx, kind, id)
}

func (s *readCountingStore) GetMany(ctx context.Context, kind model.Kind, ids []string) ([]*store.Record, error) {
	s.calls.Add(1)
	return store.GetMany(ctx, s.Store, kind, ids)
}

func (s *readCountingStore) GetByUnique(ctx context.Context, kind model.Kind, v string) (*store.Record, error) {
	s.calls.Add(1)
	return s.Store.GetByUnique(ctx, kind, v)
}

func (s *readCountingStore) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	s.calls.Add(1)
	return s.Store.List(ctx, kind, q)
}

// A page of users renders each user's groups from the memberships of the page, not from the pending changes of the
// organization read again for every user: the store reads a page costs grow by one per user at most (the user's
// membership index read), however many users the page holds.
func TestUserPageReadsGroupsInBulk(t *testing.T) {
	cs := &readCountingStore{Store: memstore.New()}
	e := newEnvStore(t, cs)
	const users = 1000
	byGroup := make([][]string, 5)
	for i := range users {
		name := "u" + strconv.Itoa(i)
		u, err := e.Svc.CreateUser(e.ctx, service.System, e.orgA.ID, service.UserInput{Username: &name, Email: ptr(name + "@acme.test"), GivenName: ptr("G")})
		if err != nil {
			t.Fatal(err)
		}
		byGroup[i%5] = append(byGroup[i%5], u.ID)
	}
	for k, members := range byGroup {
		e.group("g"+strconv.Itoa(k), members...)
	}
	for _, n := range []int{50, 1000} {
		before := cs.calls.Load()
		r := e.do("GET", "/scim/v2/acme/Users?count="+strconv.Itoa(n)+"&attributes=userName,groups", e.admA, nil)
		wantStatus(t, "page", r, 200)
		got := cs.calls.Load() - before
		t.Logf("a page of %d users: %d store reads", n, got)
		if len(r.list("Resources")) < n {
			t.Fatalf("%d users listed, want %d", len(r.list("Resources")), n)
		}
		for _, res := range r.list("Resources") {
			m := res.(map[string]any)
			if strings.HasPrefix(m["userName"].(string), "u") && len(m["groups"].([]any)) != 1 {
				t.Fatalf("groups of %v: %v", m["userName"], m["groups"])
			}
		}
		if got > int64(n)+20 {
			t.Errorf("a page of %d users took %d store reads, want at most %d", n, got, n+20)
		}
	}
}
