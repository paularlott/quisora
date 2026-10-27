package admin_test

import (
	"context"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// refusingUser is a store that cannot answer reads of one user (a node not current on their partition: the store's
// "unavailable, retry").
type refusingUser struct {
	store.Store
	id string
}

func (s refusingUser) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == model.KindUser && id == s.id {
		return nil, store.ErrUnavailable
	}
	return s.Store.Get(ctx, kind, id)
}

// A user the store cannot read now is answered 503 (try again), never 404: the user is not known to be missing.
func TestUnreadableUserIsUnavailableNotNotFound(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	uid := w.users["user"].ID
	good := w.env.Svc.Users.S
	w.env.Svc.Users.S = refusingUser{good, uid}
	r := ad.get(AU + "/" + uid)
	w.env.Svc.Users.S = good
	want(t, r, 503)
}

// A signed-in administrator whose own record the store cannot read now is answered 503 (try again), never 401
// "session ended": the session is not known to be gone.
func TestUncheckableSessionIsUnavailableNotSignedOut(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	uid := w.users["admin"].ID
	w.env.Server.Sessions.Evict("", uid) // read again, not served from the cache
	good := w.env.Svc.Users.S
	w.env.Svc.Users.S = refusingUser{good, uid}
	r := ad.get(AU)
	w.env.Svc.Users.S = good
	want(t, r, 503)
	want(t, ad.get(AU), 200) // and signed in still once the store answers
}
