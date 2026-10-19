package scim_test

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func benchEnv(b *testing.B, n int) *env {
	e := newEnv(b)
	for i := range n {
		name := "user" + strconv.Itoa(i)
		mail := name + "@acme.test"
		if _, err := e.Svc.CreateUser(e.ctx, service.System, e.orgA.ID, service.UserInput{Username: &name, Email: &mail,
			GivenName: ptr("Given" + strconv.Itoa(i)), FamilyName: ptr("Family" + strconv.Itoa(i%50))}); err != nil {
			b.Fatal(err)
		}
	}
	return e
}

func benchGet(b *testing.B, e *env, path string, want int) {
	b.ReportAllocs()
	for b.Loop() {
		req, _ := http.NewRequest("GET", e.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+e.admA)
		res, err := e.client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = readAll(res)
		if res.StatusCode != want {
			b.Fatalf("status %d", res.StatusCode)
		}
	}
}

func BenchmarkListUsersFilter1000(b *testing.B) {
	e := benchEnv(b, 1000)
	for name, f := range map[string]string{
		"userName_eq_unique": `userName eq "user500"`,
		"emails_eq_unique":   `emails.value eq "user500@acme.test"`,
		"userName_sw":        `userName sw "user99"`,
		"displayName_co":     `displayName co "Given77"`,
		"name_and_given":     `name.familyName eq "Family7" and name.givenName eq "Given7"`,
		"or_not_scan":        `not (active eq false) and (name.givenName sw "Given1" or name.familyName eq "Family3")`,
		"valuepath_scan":     `emails[type eq "work" and value ew "9@acme.test"]`,
	} {
		b.Run(name, func(b *testing.B) { benchGet(b, e, "/scim/v2/acme/Users?count=100&filter="+qs(f), 200) })
	}
	b.Run("page100_no_filter", func(b *testing.B) { benchGet(b, e, "/scim/v2/acme/Users?count=100&startIndex=300", 200) })
	b.Run("sorted_familyName_page", func(b *testing.B) { benchGet(b, e, "/scim/v2/acme/Users?count=100&sortBy=name.familyName", 200) })
	b.Run("page100_no_groups", func(b *testing.B) {
		benchGet(b, e, "/scim/v2/acme/Users?count=100&excludedAttributes=groups", 200)
	})
}

func BenchmarkGetUser(b *testing.B) {
	e := benchEnv(b, 10)
	r := e.do("GET", "/scim/v2/acme/Users?count=1&filter="+qs(`userName eq "user3"`), e.admA, nil)
	id := r.list("Resources")[0].(map[string]any)["id"].(string)
	benchGet(b, e, "/scim/v2/acme/Users/"+id, 200)
}

func BenchmarkCreateUser(b *testing.B) {
	e := newEnv(b)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		i++
		body := fmt.Sprintf(`{"userName":"bench%d","displayName":"Bench %d","emails":[{"value":"bench%d@acme.test","primary":true}],"name":{"givenName":"B","familyName":"%d"}}`, i, i, i, i)
		r := e.do("POST", "/scim/v2/acme/Users", e.admA, body)
		if r.Status != 201 {
			b.Fatalf("%d %s", r.Status, r.Raw)
		}
	}
}

func BenchmarkPatchUser(b *testing.B) {
	e := benchEnv(b, 10)
	r := e.do("GET", "/scim/v2/acme/Users?count=1&filter="+qs(`userName eq "user3"`), e.admA, nil)
	id := r.list("Resources")[0].(map[string]any)["id"].(string)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		i++
		body := fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"displayName","value":"T%d"},{"op":"Replace","path":"emails[type eq \"work\"].value","value":"p%d@acme.test"}]}`, i, i)
		if r := e.do("PATCH", "/scim/v2/acme/Users/"+id, e.admA, body); r.Status != 200 {
			b.Fatalf("%d %s", r.Status, r.Raw)
		}
	}
}

// BenchmarkListUsersGroups lists a page of 100 in a 1000-user org with 8 groups of 250 members each.
func BenchmarkListUsersGroups(b *testing.B) {
	e := benchEnv(b, 1000)
	users, _, err := e.Svc.ListUsers(e.ctx, service.System, e.orgA.ID, store.ListQuery{})
	if err != nil {
		b.Fatal(err)
	}
	for g := range 8 {
		grp, err := e.Svc.CreateGroup(e.ctx, service.System, e.orgA.ID, service.GroupInput{DisplayName: ptr("group" + strconv.Itoa(g))})
		if err != nil {
			b.Fatal(err)
		}
		for i := g; i < len(users); i += 4 {
			if err := e.Svc.SetMembership(e.ctx, service.System, grp.ID, users[i].ID, true); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.Run("page100_with_groups", func(b *testing.B) { benchGet(b, e, "/scim/v2/acme/Users?count=100&startIndex=300", 200) })
	b.Run("page100_excluded_groups", func(b *testing.B) {
		benchGet(b, e, "/scim/v2/acme/Users?count=100&startIndex=300&excludedAttributes=groups", 200)
	})
	b.Run("page100_attributes_no_groups", func(b *testing.B) {
		benchGet(b, e, "/scim/v2/acme/Users?count=100&startIndex=300&attributes=userName", 200)
	})
	b.Run("filtered_page_with_groups", func(b *testing.B) {
		benchGet(b, e, "/scim/v2/acme/Users?count=100&filter="+qs(`name.familyName eq "Family7"`), 200)
	})
	b.Run("groups_page_with_members", func(b *testing.B) { benchGet(b, e, "/scim/v2/acme/Groups?count=2", 200) })
	b.Run("groups_page_no_members", func(b *testing.B) {
		benchGet(b, e, "/scim/v2/acme/Groups?count=100&excludedAttributes=members", 200)
	})
}
