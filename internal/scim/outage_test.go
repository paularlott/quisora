package scim_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// flakyStore is a store that, once armed, cannot read what a test points it at: one user by id, any user or group by
// unique value (an organization's name still resolves), and the listing of the users above a caller's rank.
type flakyStore struct {
	store.Store
	userID    atomic.Value // string: the user whose Get fails
	unique    atomic.Bool  // GetByUnique fails
	adminList atomic.Bool  // the users listing by admin_rank fails
}

func (f *flakyStore) down() error { return fmt.Errorf("read: %w", store.ErrUnavailable) }

func (f *flakyStore) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if want, _ := f.userID.Load().(string); kind == model.KindUser && want != "" && id == want {
		return nil, f.down()
	}
	return f.Store.Get(ctx, kind, id)
}

func (f *flakyStore) GetByUnique(ctx context.Context, kind model.Kind, value string) (*store.Record, error) {
	if f.unique.Load() && (kind == model.KindUser || kind == model.KindGroup) {
		return nil, f.down()
	}
	return f.Store.GetByUnique(ctx, kind, value)
}

func (f *flakyStore) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if f.adminList.Load() && kind == model.KindUser {
		for _, fl := range q.Filters {
			if fl.Field == "admin_rank" {
				return nil, f.down()
			}
		}
	}
	return f.Store.List(ctx, kind, q)
}

// A filter that finds one resource by id or unique value answers an empty list only when there is none: when the store
// cannot be read it is a 503, as a client told "no such user" (or group) creates it again.
func TestFilterLookupOutageIsNotAnEmptyList(t *testing.T) {
	fs := &flakyStore{Store: memstore.New()}
	e := newEnvStore(t, fs)
	u := e.mkUser(e.orgA, "pat", model.RoleUser)
	if _, err := e.Svc.CreateGroup(e.ctx, service.System, e.orgA.ID, service.GroupInput{DisplayName: ptr("Staff")}); err != nil {
		t.Fatal(err)
	}
	list := func(kind, filter string) resp {
		return e.do("GET", "/scim/v2/"+e.orgA.Name+"/"+kind+"?filter="+qs(filter), e.admA, nil)
	}

	// Found and not found, while the store is well.
	if r := list("Users", `userName eq "pat"`); r.Status != 200 || r.total() != 1 {
		t.Fatalf("found: %d %s", r.Status, r.Raw)
	}
	if r := list("Users", `id eq "nobody"`); r.Status != 200 || r.total() != 0 {
		t.Fatalf("missing id: %d %s", r.Status, r.Raw)
	}
	if r := list("Groups", `displayName eq "Nothing"`); r.Status != 200 || r.total() != 0 {
		t.Fatalf("missing group: %d %s", r.Status, r.Raw)
	}

	fs.userID.Store(u.ID)
	fs.unique.Store(true)
	for _, c := range []struct{ kind, filter string }{
		{"Users", `id eq "` + u.ID + `"`},
		{"Users", `userName eq "pat"`},
		{"Users", `emails.value eq "pat@example.com"`},
		{"Groups", `displayName eq "Staff"`},
	} {
		if r := list(c.kind, c.filter); r.Status != http.StatusServiceUnavailable {
			t.Errorf("%s %s: %d %s, want 503", c.kind, c.filter, r.Status, r.Raw)
		}
	}
}

// The users the caller does not see in full are left out of a group's members; when they cannot be worked out the
// request fails rather than listing everyone.
func TestHiddenUsersFailClosedWhenTheirListCannotBeRead(t *testing.T) {
	fs := &flakyStore{Store: memstore.New()}
	e := newEnvStore(t, fs)
	p := e.primary()
	mgr := e.mkUser(p, "pm", model.RoleManager)
	adm := e.mkUser(p, "pa", model.RoleAdmin)
	g, err := e.Svc.CreateGroup(e.ctx, service.System, p.ID, service.GroupInput{DisplayName: ptr("All")})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{adm.ID, e.mkUser(p, "pp", model.RoleUser).ID} {
		if err := e.Svc.SetMembership(e.ctx, service.System, g.ID, id, true); err != nil {
			t.Fatal(err)
		}
	}
	staff := e.mkUser(p, "ps", model.RoleUser)
	if _, err := e.Svc.UpdateUser(e.ctx, service.System, staff.ID, service.UserInput{Work: &service.WorkInput{ManagerID: &mgr.ID}}); err != nil {
		t.Fatal(err)
	}
	tok := e.token(mgr, "scim")
	path := "/scim/v2/" + p.Name + "/Groups/" + g.ID

	if r := e.do("GET", path, tok, nil); r.Status != 200 || strings.Contains(string(r.Raw), adm.ID) {
		t.Fatalf("well: %d %s", r.Status, r.Raw)
	}
	fs.adminList.Store(true)
	for _, url := range []string{path, "/scim/v2/" + p.Name + "/Groups?attributes=members"} {
		r := e.do("GET", url, tok, nil)
		if r.Status != http.StatusServiceUnavailable || strings.Contains(string(r.Raw), adm.ID) {
			t.Errorf("%s: %d %s, want 503 without the administrator", url, r.Status, r.Raw)
		}
	}
	// A user with a manager shows whether the manager is seen: that is not guessed either.
	if r := e.do("GET", "/scim/v2/"+p.Name+"/Users/"+staff.ID, tok, nil); r.Status != http.StatusServiceUnavailable {
		t.Errorf("user with a manager: %d %s, want 503", r.Status, r.Raw)
	}
}
