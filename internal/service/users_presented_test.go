package service_test

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/kvstore"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// A manager's listing sorted on a field directory entries blank places the administrators among a page of the others
// that the store sorts: every page, at every offset and size, in either order, with or without a search, is that
// page of the whole listing sorted on the values as the manager sees them (directory entries on "", ties by id).
func TestListUsersByPresentedPages(t *testing.T) {
	for _, sto := range []struct {
		name string
		open func(t *testing.T) store.Store
	}{
		{"memory", func(t *testing.T) store.Store { return memstore.New() }},
		{"badger", func(t *testing.T) store.Store {
			st, err := kvstore.OpenBadger(t.Context(), t.TempDir(), kvstore.BadgerOptions{InMemory: true})
			if err != nil {
				t.Fatal(err)
			}
			return st
		}},
	} {
		t.Run(sto.name, func(t *testing.T) {
			st := sto.open(t)
			t.Cleanup(func() { _ = st.Close() })
			e := newEnvOn(t, st)
			org := e.org("acme")
			mgr := e.user(org.ID, "mgr", model.RoleManager)
			for i := range 40 {
				role := model.RoleUser
				if i%8 == 3 {
					role = model.RoleAdmin
				}
				name := fmt.Sprintf("u%02d", (i*17)%40) // usernames out of creation order
				in := service.UserInput{Username: &name, GivenName: ptr("given" + strconv.Itoa(i%5)), Role: &role,
					FamilyName: ptr("fam" + strconv.Itoa(i%3)), Email: ptr(name + "@example.com")}
				if i%3 == 0 { // the others have none, and sort on it as a directory entry does
					in.ValidUntil = ptr(time.Now().AddDate(1, 0, i).Format("2006-01-02"))
				}
				if _, err := e.svc.CreateUser(e.ctx, service.System, org.ID, in); err != nil {
					t.Fatal(err)
				}
			}
			a := actor(mgr)
			for _, search := range []string{"", "u1", "given2"} {
				shown, _, err := e.svc.ListUsers(e.ctx, a, org.ID, store.ListQuery{Search: search})
				if err != nil {
					t.Fatal(err)
				}
				for _, sort := range []string{"username", "email", "family_name", "valid_until"} {
					for _, desc := range []bool{false, true} {
						want := slices.Clone(shown)
						slices.SortStableFunc(want, func(x, y *model.User) int {
							c := store.CompareValues(x.Index().Fields[sort], y.Index().Fields[sort])
							if desc {
								c = -c
							}
							if c == 0 {
								c = strings.Compare(x.ID, y.ID)
							}
							return c
						})
						for _, limit := range []int{0, 1, 3, 10} {
							for offset := 0; offset <= len(want)+1; offset++ {
								q := store.ListQuery{Search: search, Sort: sort, Desc: desc, Offset: offset, Limit: limit}
								got, n, err := e.svc.ListUsers(e.ctx, a, org.ID, q)
								if err != nil {
									t.Fatal(err)
								}
								page := want[min(offset, len(want)):]
								if limit > 0 && len(page) > limit {
									page = page[:limit]
								}
								if n != len(want) || !slices.Equal(userIDs(got), userIDs(page)) {
									t.Fatalf("%+v: total %d, %v\nwant total %d, %v", q, n, userIDs(got), len(want), userIDs(page))
								}
								for _, u := range got {
									if u.Role == model.RoleAdmin && (u.Username != "" || u.Email != "") {
										t.Fatalf("%+v: an administrator in full: %+v", q, u)
									}
								}
							}
						}
					}
				}
			}
		})
	}
}

// GetUsers reads many users in one read and gives each as GetUser would: in full, as a directory entry, or not at all.
func TestGetUsersAsGetUser(t *testing.T) {
	c := newCast(t)
	ids := []string{c.aUser.ID, c.super.ID, c.aAdmin.ID, "nobody", c.bAdmin.ID, c.aManager.ID}
	for _, who := range []*model.User{c.aManager, c.aAdmin, c.super} {
		a := actor(who)
		var want []*model.User
		for _, id := range ids {
			if u, err := c.svc.GetUser(c.ctx, a, id); err == nil {
				want = append(want, u)
			}
		}
		got, err := c.svc.GetUsers(c.ctx, a, ids)
		if err != nil || len(got) != len(want) {
			t.Fatalf("%s: %d users, want %d (%v)", who.Username, len(got), len(want), err)
		}
		for i := range got {
			if got[i].ID != want[i].ID || got[i].Email != want[i].Email || got[i].Username != want[i].Username {
				t.Errorf("%s: %+v, want %+v", who.Username, got[i], want[i])
			}
		}
	}
}

func userIDs(l []*model.User) []string {
	out := make([]string, len(l))
	for i, u := range l {
		out[i] = u.ID
	}
	return out
}
