package service_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// A manager sees an administrator only as a directory entry (no username, email, department...): sorting the
// listing on one of those fields must not place the administrator by the value it hides. Probes the manager created
// either side of the hidden value cannot bracket it, and changing the hidden value does not move the row.
func TestListUsersSortHidesDirectoryValues(t *testing.T) {
	e := newEnv(t)
	acme := e.org("acme")
	mgr := e.user(acme.ID, "mgr", model.RoleManager)
	adm := e.user(acme.ID, "m-admin", model.RoleAdmin)
	if _, err := e.svc.UpdateUser(e.ctx, service.System, adm.ID, service.UserInput{
		Work: &service.WorkInput{Department: ptr("m-dept")}}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"m-admim", "m-admio"} {
		if _, err := e.svc.CreateUser(e.ctx, actor(mgr), acme.ID, service.UserInput{Username: ptr(p), GivenName: ptr(p),
			Email: ptr(p + "@example.com"), Work: &service.WorkInput{Department: ptr(p)}}); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(a *service.Actor, sort string, desc bool) []string {
		t.Helper()
		l, n, err := e.svc.ListUsers(e.ctx, a, acme.ID, store.ListQuery{Sort: sort, Desc: desc})
		if err != nil || n != len(l) {
			t.Fatalf("list by %s: %d of %d, %v", sort, len(l), n, err)
		}
		out := make([]string, len(l))
		for i, u := range l {
			out[i] = u.ID
		}
		return out
	}
	between := func(order []string) bool {
		var lo, hi, at int
		for i, id := range order {
			u, _ := e.svc.Users.Get(e.ctx, id)
			switch {
			case id == adm.ID:
				at = i
			case u.Username == "m-admim":
				lo = i
			case u.Username == "m-admio":
				hi = i
			}
		}
		return min(lo, hi) < at && at < max(lo, hi)
	}
	for _, sort := range []string{"username", "email", "valid_until"} {
		for _, desc := range []bool{false, true} {
			before := ids(actor(mgr), sort, desc)
			if sort != "valid_until" && between(before) {
				t.Errorf("sort %s (desc %v): the administrator sorts between the probes", sort, desc)
			}
			if _, err := e.svc.UpdateUser(e.ctx, service.System, adm.ID, service.UserInput{Username: ptr("zz-" + sort),
				Email: ptr("zz-" + sort + "@example.com"), UserType: ptr("zz"), ValidUntil: ptr("2099-01-01"),
				Work: &service.WorkInput{Department: ptr("zz")}}); err != nil {
				t.Fatal(err)
			}
			if after := ids(actor(mgr), sort, desc); !slices.Equal(before, after) {
				t.Errorf("sort %s (desc %v): changing the hidden value moved the administrator", sort, desc)
			}
			if _, err := e.svc.UpdateUser(e.ctx, service.System, adm.ID, service.UserInput{Username: ptr("m-admin"),
				Email: ptr("m-admin@example.com"), UserType: ptr(""), ValidUntil: ptr(""),
				Work: &service.WorkInput{Department: ptr("m-dept")}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	// someone who sees the administrator in full still gets the stored order
	if !between(ids(actor(e.super), "username", false)) {
		t.Error("super admin: the administrator should sort between the probes by username")
	}
	// paging the in-memory order matches the whole of it
	all := ids(actor(mgr), "username", false)
	l, n, err := e.svc.ListUsers(e.ctx, actor(mgr), acme.ID, store.ListQuery{Sort: "username", Offset: 1, Limit: 2})
	if err != nil || n != len(all) || len(l) != 2 || l[0].ID != all[1] || l[1].ID != all[2] {
		t.Errorf("paged: %d of %d, %v", len(l), n, err)
	}
	if _, _, err := e.svc.ListUsers(e.ctx, actor(mgr), acme.ID, store.ListQuery{Sort: "password"}); err == nil {
		t.Error("an unsortable field is refused")
	}
}

// What a manager can find by searching must not reveal an administrator's address, username or tags: they are
// directory entries to a manager, found only by name.
func TestSearchDoesNotLeakHiddenFields(t *testing.T) {
	c := newCast(t)
	if _, err := c.svc.UpdateUser(c.ctx, service.System, c.aAdmin.ID, service.UserInput{Tags: tags("finance")}); err != nil {
		t.Fatal(err)
	}
	m := actor(c.aManager)
	names := func(q store.ListQuery) map[string]bool {
		l, _, err := c.svc.ListUsers(c.ctx, m, c.a.ID, q)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, u := range l {
			out[u.Username] = true
		}
		return out
	}
	if got := names(store.ListQuery{Search: "aadmin@example"}); len(got) != 0 {
		t.Errorf("search by an admin's address found %v", got)
	}
	if got := names(store.ListQuery{Search: "aadmin"}); got["aadmin"] {
		t.Errorf("search by an admin's username found %v", got)
	}
	if got := names(store.ListQuery{Filters: []store.Filter{{Field: "tags", Value: "finance"}}}); len(got) != 0 {
		t.Errorf("filter by an admin's tag found %v", got)
	}
	// the same search by an admin finds them
	if l, _, err := c.svc.ListUsers(c.ctx, actor(c.aAdmin), c.a.ID, store.ListQuery{Search: "aadmin@example"}); err != nil || len(l) != 1 {
		t.Errorf("admin search: %v %d", err, len(l))
	}
	// the manager reads the administrator as a directory entry, and does not see a super admin at all
	if u, err := c.svc.GetUser(c.ctx, m, c.aAdmin.ID); err != nil || u.Email != "" {
		t.Errorf("manager reading an admin: %+v %v", u, err)
	}
	if _, err := c.svc.GetUser(c.ctx, m, c.super.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("super admin visible to a manager: %v", err)
	}
	if _, err := c.svc.GetUser(c.ctx, actor(c.aUser), c.aManager.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("plain user reading a manager: %v", err)
	}
}

// A provisioning client has no use for directory entries: the users it is given in full are those below its rank (an
// administrator's, for a client), and a manager is given a plain user's but not an administrator's.
func TestFullViewListsOnlyWhatTheViewerSeesInFull(t *testing.T) {
	c := newCast(t)
	client := service.ActorForServiceAccount(&model.Client{Meta: model.Meta{ID: "scim"}, OrgID: c.primary.ID}, nil, "")
	for _, tc := range []struct {
		name   string
		viewer *service.Actor
		want   []string
	}{
		{"manager", actor(c.pManager), []string{"pmanager", "puser"}},
		{"provisioning client", client, []string{"padmin", "pmanager", "puser"}},
		{"super admin", actor(c.super), []string{"padmin", "pmanager", "puser", "root@example.com"}},
	} {
		q := service.FullViewQuery(tc.viewer, store.ListQuery{Scope: c.primary.ID, Sort: "username"})
		l, _, err := c.svc.Users.List(c.ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, u := range l {
			got = append(got, u.Username)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s is given %v in full, want %v", tc.name, got, tc.want)
		}
	}
}

// Looking a user up by address or external id confirms them, as a search would: a manager finds the users they see in
// full, and an administrator (a directory entry to them) is not found by its address or external id.
func TestFindUserDoesNotConfirmHiddenFields(t *testing.T) {
	e := newEnv(t)
	acme := e.org("acme")
	mgr := e.user(acme.ID, "mgr", model.RoleManager)
	adm := e.user(acme.ID, "f-admin", model.RoleAdmin)
	plain := e.user(acme.ID, "f-plain", model.RoleUser)
	if _, err := e.svc.UpdateUser(e.ctx, service.System, adm.ID, service.UserInput{ExternalID: ptr("ext-admin")}); err != nil {
		t.Fatal(err)
	}
	if got, err := e.svc.FindUser(e.ctx, actor(mgr), acme.ID, "", plain.Email); err != nil || got.ID != plain.ID {
		t.Fatalf("a plain user by address: %v %v", got, err)
	}
	for name, find := range map[string][2]string{"address": {"", adm.Email}, "external id": {"ext-admin", ""}} {
		if got, err := e.svc.FindUser(e.ctx, actor(mgr), acme.ID, find[0], find[1]); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("a manager found an administrator by its %s: %v %v", name, got, err)
		}
		if got, err := e.svc.FindUser(e.ctx, actor(e.super), acme.ID, find[0], find[1]); err != nil || got.ID != adm.ID {
			t.Errorf("a super admin did not find the administrator by its %s: %v %v", name, got, err)
		}
	}
}
