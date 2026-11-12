package admin_test

import (
	"context"
	"sync/atomic"
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

// refusingOrgs is a store that cannot answer a lookup of an organization by name.
type refusingOrgs struct{ store.Store }

func (s refusingOrgs) GetByUnique(ctx context.Context, kind model.Kind, v string) (*store.Record, error) {
	if kind == model.KindOrg {
		return nil, store.ErrUnavailable
	}
	return s.Store.GetByUnique(ctx, kind, v)
}

// The super admin's audit filter ?org= answers 503 (try again) when the store cannot look the organization up, as the
// per-organization route does, and 404 only for one that is not there.
func TestAuditOrgFilterUnreadableOrgIsUnavailable(t *testing.T) {
	w := newWorld(t)
	su := w.as("super")
	good := w.env.Svc.Orgs.S
	w.env.Svc.Orgs.S = refusingOrgs{good}
	r := su.get("/api/audit?org=globex")
	w.env.Svc.Orgs.S = good
	want(t, r, 503)
	want(t, su.get("/api/audit?org=nope"), 404)
}

// failingAfter lets the first n reads of a user through and refuses the rest.
type failingAfter struct {
	store.Store
	n     int64
	reads *atomic.Int64
}

func (s failingAfter) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == model.KindUser && s.reads.Add(1) > s.n {
		return nil, store.ErrUnavailable
	}
	return s.Store.Get(ctx, kind, id)
}

// A page of a group's members that cannot be read is answered 503, not as a page without them.
func TestGroupMembersPageReadFailureIsUnavailable(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	gid := ad.post(A+"/groups", map[string]any{"display_name": "Eng"}).str("id")
	want(t, ad.put(A+"/groups/"+gid+"/members/"+w.users["user"].ID, nil), 200)
	good := w.env.Svc.Users.S
	w.env.Svc.Users.S = failingAfter{good, 1, new(atomic.Int64)} // the membership check reads the one member; the page's read fails
	r := ad.get(A + "/groups/" + gid + "/members")
	w.env.Svc.Users.S = good
	want(t, r, 503)
}
