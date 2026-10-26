package service_test

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestUserUniqueConflictsAreFieldErrors(t *testing.T) {
	c := newCast(t)
	base := c.user(c.a.ID, "alice", model.RoleUser)
	_, err := c.svc.UpdateUser(c.ctx, actor(c.aAdmin), base.ID, service.UserInput{ExternalID: ptr("ext-1")})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		in    service.UserInput
		field string
	}{
		{"username", service.UserInput{Username: ptr("alice"), Email: ptr("alice@example.com")}, "username"},
		{"username case", service.UserInput{Username: ptr("ALICE"), Email: ptr("ALICE@example.com")}, "username"},
		{"email", service.UserInput{Username: ptr("other"), Email: ptr("Alice@Example.com")}, "email"},
		{"external", service.UserInput{Username: ptr("other2"), Email: ptr("other2@example.com"), ExternalID: ptr("ext-1")}, "external_id"},
	}
	for _, tc := range cases {
		tc.in.GivenName = ptr("T")
		_, err := c.svc.CreateUser(c.ctx, actor(c.aAdmin), c.a.ID, tc.in)
		var fe *service.FieldError
		if !errors.As(err, &fe) || fe.Field != tc.field || !errors.Is(err, service.ErrConflict) || !errors.Is(err, service.ErrInvalid) {
			t.Errorf("%s: want conflict field error on %s, got %v", tc.name, tc.field, err)
		}
	}
	// The same values are fine in another org.
	if _, err := c.svc.CreateUser(c.ctx, actor(c.bAdmin), c.b.ID, service.UserInput{GivenName: ptr("T"), Username: ptr("alice"), Email: ptr("alice@example.com"), ExternalID: ptr("ext-1")}); err != nil {
		t.Errorf("same values in other org: %v", err)
	}
	// Updating to a clashing value.
	bob := c.user(c.a.ID, "bob", model.RoleUser)
	_, err = c.svc.UpdateUser(c.ctx, actor(c.aAdmin), bob.ID, service.UserInput{Email: ptr("alice@example.com")})
	var fe *service.FieldError
	if !errors.As(err, &fe) || fe.Field != "email" {
		t.Errorf("update email clash: %v", err)
	}
	_, err = c.svc.UpdateUser(c.ctx, actor(c.aAdmin), bob.ID, service.UserInput{Username: ptr("alice"), Email: ptr("alice@example.com")})
	if !errors.As(err, &fe) || fe.Field != "username" {
		t.Errorf("update username clash: %v", err)
	}
	// Updating a user to its own values is not a clash.
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.aAdmin), base.ID, service.UserInput{Username: ptr("alice"), Email: ptr("alice@example.com"), ExternalID: ptr("ext-1")}); err != nil {
		t.Errorf("self values: %v", err)
	}
	// A deleted user frees its keys.
	if err := c.svc.DeleteUser(c.ctx, actor(c.aAdmin), base.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.CreateUser(c.ctx, actor(c.aAdmin), c.a.ID, service.UserInput{GivenName: ptr("T"), Username: ptr("alice"), Email: ptr("alice@example.com"), ExternalID: ptr("ext-1")}); err != nil {
		t.Errorf("reuse after delete: %v", err)
	}
}

func TestUserValidation(t *testing.T) {
	c := newCast(t)
	long := strings.Repeat("x", 201)
	cases := []struct {
		name  string
		in    service.UserInput
		field string
	}{
		{"nothing", service.UserInput{}, "email"},
		{"username only", service.UserInput{Username: ptr("nomail")}, "email"},
		{"blank email", service.UserInput{Username: ptr("nomail"), Email: ptr("   ")}, "email"},
		{"bad username", service.UserInput{Username: ptr("a b"), Email: ptr("ab@example.com")}, "username"},
		{"long username", service.UserInput{Username: ptr(strings.Repeat("a", 129)), Email: ptr("la@example.com")}, "username"},
		{"bad email", service.UserInput{Username: ptr("u1"), Email: ptr("nope")}, "email"},
		{"display email", service.UserInput{Username: ptr("u2"), Email: ptr("Name <a@b.com>")}, "email"},
		{"bad role", service.UserInput{Username: ptr("u3"), Email: ptr("u3@example.com"), Role: ptr(model.Role("root"))}, "role"},
		{"long name", service.UserInput{Username: ptr("u4"), Email: ptr("u4@example.com"), GivenName: &long}, "given_name"},
		{"short password", service.UserInput{Username: ptr("u5"), Email: ptr("u5@example.com"), Password: ptr("short")}, "password"},
		{"long password", service.UserInput{Username: ptr("u6"), Email: ptr("u6@example.com"), Password: ptr(strings.Repeat("p", 1025))}, "password"},
		{"long locale", service.UserInput{Username: ptr("u7"), Email: ptr("u7@example.com"), Locale: ptr(strings.Repeat("l", 36))}, "locale"},
	}
	for _, tc := range cases {
		if tc.in.GivenName == nil {
			tc.in.GivenName = ptr("T")
		}
		_, err := c.svc.CreateUser(c.ctx, actor(c.aAdmin), c.a.ID, tc.in)
		var fe *service.FieldError
		if !errors.As(err, &fe) || !errors.Is(err, service.ErrInvalid) || fe.Field != tc.field || fe.Msg == "" {
			t.Errorf("%s: want invalid on %s, got %v", tc.name, tc.field, err)
		}
	}
	// Username falls back to the email; display name to the full name then the username.
	u, err := c.svc.CreateUser(c.ctx, actor(c.aAdmin), c.a.ID, service.UserInput{Email: ptr("carol@example.com"),
		GivenName: ptr("Carol"), FamilyName: ptr("Jones")})
	if err != nil || u.Username != "carol@example.com" || u.FullName() != "Carol Jones" || !u.Active || u.Role != model.RoleUser {
		t.Errorf("defaults: %v %+v", err, u)
	}
	u, err = c.svc.CreateUser(c.ctx, actor(c.aAdmin), c.a.ID, service.UserInput{GivenName: ptr("T"), Username: ptr("dave"), Email: ptr("dave@example.com")})
	if err != nil || u.FullName() != "T" {
		t.Errorf("name default: %v %+v", err, u)
	}
	// A blank username also falls back to the email; the username never needs to be given.
	u, err = c.svc.CreateUser(c.ctx, actor(c.aAdmin), c.a.ID, service.UserInput{GivenName: ptr("T"), Username: ptr("  "), Email: ptr("erica@example.com")})
	if err != nil || u.Username != "erica@example.com" {
		t.Errorf("blank username default: %v %+v", err, u)
	}
	// The email cannot be cleared by an update (and a failed update changes nothing).
	for _, blank := range []string{"", "  "} {
		_, err = c.svc.UpdateUser(c.ctx, actor(c.aAdmin), u.ID, service.UserInput{Email: ptr(blank)})
		var fe *service.FieldError
		if !errors.As(err, &fe) || fe.Field != "email" {
			t.Errorf("clearing email %q: %v", blank, err)
		}
	}
	// Unknown org.
	if _, err := c.svc.CreateUser(c.ctx, actor(c.super), "no-such-org", service.UserInput{GivenName: ptr("T"), Username: ptr("x"), Email: ptr("x@example.com")}); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown org: %v", err)
	}
	// Changing the email clears the verified flag.
	v, err := c.svc.CreateUser(c.ctx, actor(c.aAdmin), c.a.ID, service.UserInput{GivenName: ptr("T"), Username: ptr("erin"), Email: ptr("erin@example.com"), Verified: ptr(true)})
	if err != nil || !v.EmailVerified {
		t.Fatalf("verified: %v", err)
	}
	v, err = c.svc.UpdateUser(c.ctx, actor(c.aAdmin), v.ID, service.UserInput{Email: ptr("erin2@example.com")})
	if err != nil || v.EmailVerified {
		t.Errorf("email change should clear verified: %v %+v", err, v)
	}
}

// Deleting a user deletes the user record: what was theirs stops counting at once, and the orphan sweep removes it.
func TestDeleteUserRemovesEverything(t *testing.T) {
	c := newCast(t)
	u := c.aUser
	g, _ := c.svc.CreateGroup(c.ctx, actor(c.aAdmin), c.a.ID, service.GroupInput{DisplayName: ptr("staff")})
	if err := c.svc.SetMembership(c.ctx, actor(c.aAdmin), g.ID, u.ID, true); err != nil {
		t.Fatal(err)
	}
	tok, plain, err := c.svc.CreateAPIToken(c.ctx, actor(u), service.APITokenInput{Name: "t", Scopes: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	sess := &model.Session{Meta: model.Meta{ID: "s-" + u.ID}, UserID: u.ID, OrgID: u.OrgID}
	_ = c.svc.Sessions.Create(c.ctx, sess)
	if err := c.svc.DeleteUser(c.ctx, actor(c.aAdmin), u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.Users.Get(c.ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Error("user remains")
	}
	if _, _, err := c.svc.ValidateAPIToken(c.ctx, plain); err == nil {
		t.Error("token of a deleted user accepted")
	}
	if _, err := c.svc.SweepAll(c.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.APITokens.Get(c.ctx, tok.ID); !errors.Is(err, store.ErrNotFound) {
		t.Error("token remains")
	}
	if _, err := c.svc.Sessions.Get(c.ctx, sess.ID); !errors.Is(err, store.ErrNotFound) {
		t.Error("session remains")
	}
	ids, err := c.svc.GroupMembers(c.ctx, actor(c.aAdmin), g.ID)
	if err != nil || len(ids) != 0 {
		t.Errorf("membership remains: %v %v", ids, err)
	}
	if err := c.svc.DeleteUser(c.ctx, actor(c.aAdmin), u.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

// Concurrent updates of one user end ok or stale and at least one succeeds; an update from a copy read before another
// write is refused as stale, never silently lost.
func TestOptimisticConcurrency(t *testing.T) {
	c := newCast(t)
	u := c.user(c.a.ID, "race", model.RoleUser)
	a := actor(c.aAdmin)
	var wg sync.WaitGroup
	var mu sync.Mutex
	counts := map[string]int{}
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.svc.UpdateUser(c.ctx, a, u.ID, service.UserInput{FamilyName: ptr("t" + strconv.Itoa(i))})
			mu.Lock()
			counts[outcome(err)]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	for k := range counts {
		if k != "ok" && k != "stale" {
			t.Errorf("unexpected outcome %s", k)
		}
	}
	if counts["ok"] == 0 {
		t.Error("no update succeeded")
	}

	// A write by someone else between read and write is reported, never silently lost: simulate with a stale entity.
	stale, _ := c.svc.Users.Get(c.ctx, u.ID)
	fresh, _ := c.svc.Users.Get(c.ctx, u.ID)
	fresh.FamilyName = "fresh"
	if err := c.svc.Users.Update(c.ctx, fresh); err != nil {
		t.Fatal(err)
	}
	stale.FamilyName = "stale"
	err := c.svc.Users.Update(c.ctx, stale)
	if !errors.Is(err, store.ErrStale) {
		t.Fatalf("stale update: %v", err)
	}
	got, _ := c.svc.Users.Get(c.ctx, u.ID)
	if got.FamilyName != "fresh" {
		t.Errorf("lost update: %q", got.FamilyName)
	}
}

// Concurrent writers of one organization, group and client fail only as ErrStale (retryable), and each is written.
func TestConcurrentWritesFailOnlyAsStale(t *testing.T) {
	// Hammer one org, group and client with concurrent writers; every failure must be ErrStale (retryable).
	c := newCast(t)
	g, _ := c.svc.CreateGroup(c.ctx, actor(c.aAdmin), c.a.ID, service.GroupInput{DisplayName: ptr("race-group")})
	cl, _, _ := c.svc.CreateClient(c.ctx, actor(c.aAdmin), c.a.ID, service.ClientInput{Name: ptr("race-client"),
		RedirectURIs: ptr([]string{"https://r.example.com/cb"})})
	var wg sync.WaitGroup
	var mu sync.Mutex
	bad := []string{}
	record := func(err error) {
		if err != nil && !errors.Is(err, service.ErrStale) {
			mu.Lock()
			bad = append(bad, err.Error())
			mu.Unlock()
		}
	}
	for i := range 30 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			_, err := c.svc.UpdateGroup(c.ctx, actor(c.aAdmin), g.ID, service.GroupInput{ExternalID: ptr("e" + strconv.Itoa(i))})
			record(err)
		}()
		go func() {
			defer wg.Done()
			_, err := c.svc.UpdateClient(c.ctx, actor(c.aAdmin), cl.ID, service.ClientInput{Description: ptr("d" + strconv.Itoa(i))})
			record(err)
		}()
		go func() {
			defer wg.Done()
			_, err := c.svc.UpdateOrg(c.ctx, actor(c.super), c.a.ID, service.OrgInput{DisplayName: ptr("n" + strconv.Itoa(i))})
			record(err)
		}()
	}
	wg.Wait()
	if len(bad) > 0 {
		t.Errorf("non-stale failures: %v", bad)
	}
	// at least one writer of each won: every writer failing as stale would pass the check above
	if got, _ := c.svc.Groups.Get(c.ctx, g.ID); got.ExternalID == "" {
		t.Error("no group update succeeded")
	}
	if got, _ := c.svc.Clients.Get(c.ctx, cl.ID); got.Description == "" {
		t.Error("no client update succeeded")
	}
	if got, _ := c.svc.Orgs.Get(c.ctx, c.a.ID); !strings.HasPrefix(got.DisplayName, "n") {
		t.Error("no organization update succeeded")
	}
}

func TestListUsersQuery(t *testing.T) {
	c := newCast(t)
	for i := range 25 {
		c.user(c.a.ID, "list"+strconv.Itoa(100+i), model.RoleUser)
	}
	a := actor(c.aAdmin)
	page, total, err := c.svc.ListUsers(c.ctx, a, c.a.ID, store.ListQuery{Search: "list1", Sort: "username", Limit: 10, Offset: 5})
	if err != nil || total != 25 || len(page) != 10 || page[0].Username != "list105" {
		t.Fatalf("page: %v total=%d len=%d", err, total, len(page))
	}
	_, total, _ = c.svc.ListUsers(c.ctx, a, c.a.ID, store.ListQuery{Filters: []store.Filter{{Field: "role", Value: "admin"}}})
	if total != 1 {
		t.Errorf("admin filter total %d", total)
	}
	if _, _, err := c.svc.ListUsers(c.ctx, a, c.a.ID, store.ListQuery{Sort: "password_hash"}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("bad sort: %v", err)
	}
	if _, _, err := c.svc.ListUsers(c.ctx, a, c.a.ID, store.ListQuery{Filters: []store.Filter{{Field: "nope", Value: "x"}}}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("bad filter: %v", err)
	}
	// Scope cannot be overridden to read another org.
	_, total, err = c.svc.ListUsers(c.ctx, a, c.a.ID, store.ListQuery{Scope: c.b.ID})
	if err != nil || total != 28 {
		t.Errorf("scope override: %v total=%d", err, total)
	}
}

// Sign-in lookup is by email address only, case-insensitively; the username never matches.
func TestFindUserByEmail(t *testing.T) {
	c := newCast(t)
	u, err := c.svc.CreateUser(c.ctx, actor(c.aAdmin), c.a.ID, service.UserInput{GivenName: ptr("T"), Username: ptr("zed"), Email: ptr("Zed@Example.com")})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []string{"Zed@Example.com", "zed@example.com", "  ZED@EXAMPLE.COM "} {
		if got, err := c.svc.FindUserByEmail(c.ctx, c.a.ID, e); err != nil || got.ID != u.ID {
			t.Errorf("%q: %v", e, err)
		}
	}
	if _, err := c.svc.FindUserByEmail(c.ctx, c.a.ID, "zed"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("username must not find the user: %v", err)
	}
	if _, err := c.svc.FindUserByEmail(c.ctx, c.b.ID, "zed@example.com"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("other org: %v", err)
	}
}
