package scim_test

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// readCounter counts the records the store hands out (listed, or read by id or unique value), which is what a listing
// that renders only its page must keep proportional to the page.
type readCounter struct {
	store.Store
	n atomic.Int64
}

func (c *readCounter) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	r, err := c.Store.Get(ctx, kind, id)
	c.n.Add(1)
	return r, err
}

func (c *readCounter) GetByUnique(ctx context.Context, kind model.Kind, value string) (*store.Record, error) {
	r, err := c.Store.GetByUnique(ctx, kind, value)
	c.n.Add(1)
	return r, err
}

func (c *readCounter) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	res, err := c.Store.List(ctx, kind, q)
	if res != nil {
		c.n.Add(int64(len(res.Records)))
	}
	return res, err
}

// listPages GETs pages of size count of path (which has a query) and returns the names (attr) they hold, the total
// each page reported, and the most records the store read for one page.
func (e *env) listPages(rc *readCounter, path, attr string, count, pages int) (names []string, total, reads int) {
	e.t.Helper()
	for i := range pages {
		before := rc.n.Load()
		r := e.do("GET", path+"&count="+strconv.Itoa(count)+"&startIndex="+strconv.Itoa(1+i*count), e.admA, nil)
		if r.Status != 200 {
			e.t.Fatalf("%s page %d: %d %s", path, i, r.Status, r.Raw)
		}
		if t := r.total(); i > 0 && t != total {
			e.t.Errorf("%s page %d: total %d, page 0 said %d", path, i, t, total)
		}
		total = r.total()
		names = append(names, r.names(attr)...)
		reads = max(reads, int(rc.n.Load()-before))
	}
	return names, total, reads
}

func (e *env) makeGroups(n int, name func(i int) string) {
	e.t.Helper()
	for i := range n {
		if _, err := e.Svc.CreateGroup(e.ctx, service.System, e.orgA.ID, service.GroupInput{DisplayName: ptr(name(i))}); err != nil {
			e.t.Fatal(err)
		}
	}
}

// A page of the group list renders and reads only its page: a full sync of an organization is linear, and the total
// is the store's.
func TestGroupListReadsOnlyItsPage(t *testing.T) {
	rc := &readCounter{Store: memstore.New()}
	e := newEnvStore(t, rc)
	const n, page = 3000, 100
	e.makeGroups(n, func(i int) string { return fmt.Sprintf("g%04d", i) })
	// readsPerPage is generous: the page, the caller's own records and a little housekeeping, far from the 3000.
	const readsPerPage = 2*page + 20

	for _, c := range []struct {
		name, query string
		want        func(i int) string
		total       int
	}{
		{"default order", "?excludedAttributes=members", func(i int) string { return fmt.Sprintf("g%04d", i) }, n},
		{"with members", "?", func(i int) string { return fmt.Sprintf("g%04d", i) }, n},
		{"by name", "?sortBy=displayName&excludedAttributes=members", func(i int) string { return fmt.Sprintf("g%04d", i) }, n},
		{"by name descending", "?sortBy=displayName&sortOrder=descending&excludedAttributes=members",
			func(i int) string { return fmt.Sprintf("g%04d", n-1-i) }, n},
		{"by creation", "?sortBy=meta.created&excludedAttributes=members", func(i int) string { return fmt.Sprintf("g%04d", i) }, n},
		{"name prefix", "?excludedAttributes=members&sortBy=displayName&filter=" + qs(`displayName sw "G1"`),
			func(i int) string { return fmt.Sprintf("g%04d", 1000+i) }, 1000},
	} {
		got, total, reads := e.listPages(rc, "/scim/v2/acme/Groups"+c.query, "displayName", page, 3)
		if total != c.total {
			t.Errorf("%s: total %d, want %d", c.name, total, c.total)
		}
		if reads > readsPerPage {
			t.Errorf("%s: a page read %d records, want about %d", c.name, reads, page)
		}
		want := make([]string, 3*page)
		for i := range want {
			want[i] = c.want(i)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: pages hold %v ... want %v ...", c.name, got[:3], want[:3])
		}
	}

	// A page past the end is empty with the total still told; count=0 asks for the total alone.
	r := e.do("GET", "/scim/v2/acme/Groups?startIndex=5000", e.admA, nil)
	if r.Status != 200 || r.total() != n || len(r.list("Resources")) != 0 {
		t.Errorf("past the end: %d %s", r.Status, r.Raw)
	}
	if r := e.do("GET", "/scim/v2/acme/Groups?count=0", e.admA, nil); r.Status != 200 || r.total() != n || len(r.list("Resources")) != 0 {
		t.Errorf("count 0: %d %s", r.Status, r.Raw)
	}
}

// The members of the listed groups are those of the page only, whole and in order.
func TestGroupListPageMembers(t *testing.T) {
	e := newEnv(t)
	u1, u2 := e.mk("pm1", nil), e.mk("pm2", nil)
	e.group("A1", u1, u2)
	e.group("A2", u2)
	e.group("A3")
	r := e.do("GET", "/scim/v2/acme/Groups?sortBy=displayName&startIndex=2&count=2", e.admA, nil)
	res := r.list("Resources")
	if r.total() != 3 || len(res) != 2 || res[0].(map[string]any)["displayName"] != "A2" ||
		len(res[0].(map[string]any)["members"].([]any)) != 1 || len(res[1].(map[string]any)["members"].([]any)) != 0 {
		t.Errorf("page 2: %s", r.Raw)
	}
}

// An organization with more groups than a scan may evaluate lists, page by page, and says "tooMany" only for a
// filter the store cannot answer.
func TestGroupListBeyondTheScanLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("creates more than 50000 groups")
	}
	rc := &readCounter{Store: memstore.New()}
	e := newEnvStore(t, rc)
	const n = 50_001 + 5
	e.makeGroups(n, func(i int) string { return fmt.Sprintf("big%06d", i) })

	got, total, reads := e.listPages(rc, "/scim/v2/acme/Groups?excludedAttributes=members&sortBy=displayName", "displayName", 100, 2)
	if total != n || reads > 220 || len(got) != 200 || got[0] != "big000000" || got[199] != "big000199" {
		t.Errorf("pages of %d groups: total %d, reads %d, %d names", n, total, reads, len(got))
	}
	if _, total, _ := e.listPages(rc, "/scim/v2/acme/Groups?excludedAttributes=members&filter="+qs(`displayName sw "big0499"`), "displayName", 100, 1); total != 100 {
		t.Errorf("prefix filter total %d, want 100", total)
	}
	if r := e.do("GET", "/scim/v2/acme/Groups?filter="+qs(`displayName co "9"`), e.admA, nil); r.Status != 400 || r.str("scimType") != "tooMany" {
		t.Errorf("unindexed filter: %d %s, want 400 tooMany", r.Status, r.Raw)
	}
	if r := e.do("GET", "/scim/v2/acme/Groups?filter="+qs(`displayName eq "big000007"`), e.admA, nil); r.Status != 200 || r.total() != 1 {
		t.Errorf("name lookup: %d %s", r.Status, r.Raw)
	}
}

// Pages of the user list that the store can filter and order read only their page: the active and role filters, alone
// and together, and with the order the console shows.
func TestUserListIndexedFilterReadsOnlyItsPage(t *testing.T) {
	rc := &readCounter{Store: memstore.New()}
	e := newEnvStore(t, rc)
	const n, page = 2000, 50
	for i := range n {
		name := fmt.Sprintf("u%04d", i)
		in := service.UserInput{Username: &name, GivenName: ptr("T"), Email: ptr(name + "@acme.test")}
		if i%10 == 0 {
			in.Active = ptr(false)
		}
		if i%5 == 1 {
			in.Role = ptr(model.RoleManager)
		}
		if _, err := e.Svc.CreateUser(e.ctx, service.System, e.orgA.ID, in); err != nil {
			t.Fatal(err)
		}
	}
	const readsPerPage = 2*page + 20
	// The organization also holds the administrator and the manager whose tokens the fixture makes.
	for _, c := range []struct {
		name, filter string
		total        int
		first        string
	}{
		{"disabled", `active eq false`, 200, "u0000"},
		{"active", `active eq true`, 1802, "adm-a"},
		{"managers", `urn:paularlott:quisora:scim:schemas:2.0:User:role eq "manager"`, 401, "mgr-a"},
		{"active managers", `active eq true and urn:paularlott:quisora:scim:schemas:2.0:User:role eq "manager"`, 401, "mgr-a"},
	} {
		got, total, reads := e.listPages(rc, "/scim/v2/acme/Users?excludedAttributes=groups&sortBy=userName&filter="+qs(c.filter), "userName", page, 3)
		if total != c.total || len(got) != 3*page || got[0] != c.first || !slices.IsSorted(got) {
			t.Errorf("%s: total %d (want %d), %d names from %v", c.name, total, c.total, len(got), got[:2])
		}
		if reads > readsPerPage {
			t.Errorf("%s: a page read %d records, want about %d", c.name, reads, page)
		}
	}
	// Filters the store cannot express alone still answer, by evaluating the narrowed set.
	if _, total, _ := e.listPages(rc, "/scim/v2/acme/Users?excludedAttributes=groups&filter="+qs(`active eq false and userName ew "0"`), "userName", page, 1); total != 200 {
		t.Errorf("narrowed scan total %d, want 200", total)
	}
}

// A page of users shows each user's groups without reading the organization's groups: the cost follows the page and the
// memberships of its users, however many groups the organization has.
func TestUserListGroupsReadOnlyThePagesMemberships(t *testing.T) {
	rc := &readCounter{Store: memstore.New()}
	e := newEnvStore(t, rc)
	e.makeGroups(3000, func(i int) string { return fmt.Sprintf("g%04d", i) })
	var ids []string
	for i := range 120 {
		ids = append(ids, e.mk(fmt.Sprintf("m%03d", i), nil))
	}
	for i, g := range []string{"g0007", "g1500"} {
		gr, err := e.Svc.Groups.GetByUnique(e.ctx, model.GroupNameKey(e.orgA.ID, g))
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range ids[i*60 : i*60+60] {
			if err := e.Svc.SetMembership(e.ctx, service.System, gr.ID, id, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	before := rc.n.Load()
	r := e.do("GET", "/scim/v2/acme/Users?sortBy=userName&filter="+qs(`userName sw "m"`)+"&count=50&startIndex=51", e.admA, nil)
	if r.Status != 200 || r.total() != 121 || len(r.list("Resources")) != 50 {
		t.Fatalf("page: %d %s", r.Status, r.Raw)
	}
	if reads := rc.n.Load() - before; reads > 400 {
		t.Errorf("a page of 50 users read %d records in an organization of 3000 groups", reads)
	}
	for _, it := range r.list("Resources") {
		u := it.(map[string]any)
		want := "g0007"
		if i, _ := strconv.Atoi(u["userName"].(string)[1:]); i >= 60 {
			want = "g1500"
		}
		if gs, _ := u["groups"].([]any); len(gs) != 1 || gs[0].(map[string]any)["display"] != want {
			t.Errorf("%v: groups %v, want %s", u["userName"], u["groups"], want)
		}
	}
}
