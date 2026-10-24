package scim_test

import (
	"context"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

type deepConditionalStore struct {
	store.Store
	userID     string
	gets       int
	interleave func()
}

func (s *deepConditionalStore) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == model.KindUser && id == s.userID {
		s.gets++
		if s.gets == 2 {
			s.interleave()
		}
	}
	return s.Store.Get(ctx, kind, id)
}

func TestDeepReviewSCIMIfMatchProtectsFinalWrite(t *testing.T) {
	e := newEnv(t)
	id := e.mk("conditional", nil)
	path := "/scim/v2/acme/Users/" + id
	before := e.do("GET", path, e.admA, nil)
	tag := before.Header.Get("ETag")
	rawUsers := store.NewTable[model.User](e.Store)
	hook := &deepConditionalStore{Store: e.Store, userID: id}
	hook.interleave = func() {
		u, err := rawUsers.Get(e.ctx, id)
		if err != nil {
			t.Error(err)
			return
		}
		u.GivenName = "Concurrent winner"
		if err := rawUsers.Update(e.ctx, u); err != nil {
			t.Error(err)
		}
	}
	e.Svc.Users.S = hook
	r := e.do("PATCH", path, e.admA, patchBody(op("replace", "name.givenName", "Stale request")), "If-Match", tag)
	if hook.gets < 2 {
		t.Fatalf("did not exercise interleaving: reads=%d", hook.gets)
	}
	if r.Status != 412 {
		t.Fatalf("stale conditional PATCH overwrote concurrent edit: status=%d body=%s", r.Status, r.Raw)
	}
}
