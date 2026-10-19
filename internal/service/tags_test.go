package service_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func tags(s ...string) *[]string { return &s }

func TestTagValidation(t *testing.T) {
	c := newCast(t)
	adm := actor(c.aAdmin)
	for _, ok := range []string{"a", "A1", "dept:finance", "marketplace:seller", "a.b_c-d/e:f", strings.Repeat("x", 64), "9"} {
		if !model.ValidTag(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "x y", "-a", "a-", ".a", "a.", ":a", "a:", "é", "a,b", "a#", strings.Repeat("x", 65), "a\n"} {
		if model.ValidTag(bad) {
			t.Errorf("%q should be invalid", bad)
		}
		_, err := c.svc.UpdateUser(c.ctx, adm, c.aUser.ID, service.UserInput{Tags: tags(bad)})
		if !errors.Is(err, service.ErrInvalid) {
			t.Errorf("user tag %q: %v", bad, err)
		}
	}
	_, err := c.svc.UpdateUser(c.ctx, adm, c.aUser.ID, service.UserInput{Tags: tags("x y")})
	if err == nil || !strings.Contains(err.Error(), `"x y" is not a valid tag: use letters, digits and . _ : / -`) {
		t.Errorf("message: %v", err)
	}
	if got, _ := c.svc.Users.Get(c.ctx, c.aUser.ID); len(got.Tags) != 0 {
		t.Fatalf("invalid update stored tags: %v", got.Tags)
	}

	// Normalized: deduplicated, sorted, case kept; nil leaves tags alone; empty clears.
	u, err := c.svc.UpdateUser(c.ctx, adm, c.aUser.ID, service.UserInput{Tags: tags("b", "dept:Finance", "a", "b", "a")})
	if err != nil || !slices.Equal(u.Tags, []string{"a", "b", "dept:Finance"}) {
		t.Fatalf("normalize: %v %v", err, u)
	}
	u, err = c.svc.UpdateUser(c.ctx, adm, c.aUser.ID, service.UserInput{FamilyName: ptr("x")})
	if err != nil || len(u.Tags) != 3 {
		t.Fatalf("untouched: %v %v", err, u.Tags)
	}
	u, err = c.svc.UpdateUser(c.ctx, adm, c.aUser.ID, service.UserInput{Tags: tags()})
	if err != nil || len(u.Tags) != 0 {
		t.Fatalf("clear: %v %v", err, u.Tags)
	}

	// At most 50.
	many := make([]string, 0, 51)
	for i := range 51 {
		many = append(many, "t"+itoa(i))
	}
	if _, err := c.svc.UpdateUser(c.ctx, adm, c.aUser.ID, service.UserInput{Tags: &many}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("51 tags: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, adm, c.aUser.ID, service.UserInput{Tags: tags(many[:50]...)}); err != nil {
		t.Errorf("50 tags: %v", err)
	}

	// Create with tags; groups validate the same way.
	nu, err := c.svc.CreateUser(c.ctx, adm, c.a.ID, service.UserInput{GivenName: gn("T"), Email: ptr("tagged@example.com"), Tags: tags("z", "y")})
	if err != nil || !slices.Equal(nu.Tags, []string{"y", "z"}) {
		t.Fatalf("create: %v %v", err, nu)
	}
	if _, err := c.svc.CreateGroup(c.ctx, adm, c.a.ID, service.GroupInput{DisplayName: ptr("bad"), Tags: tags("no good")}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("group bad tag: %v", err)
	}
	g, err := c.svc.CreateGroup(c.ctx, adm, c.a.ID, service.GroupInput{DisplayName: ptr("ok"), Tags: tags("team:b", "team:a", "team:a")})
	if err != nil || !slices.Equal(g.Tags, []string{"team:a", "team:b"}) {
		t.Fatalf("group create: %v %v", err, g)
	}
	g, err = c.svc.UpdateGroup(c.ctx, adm, g.ID, service.GroupInput{Tags: tags("only")})
	if err != nil || !slices.Equal(g.Tags, []string{"only"}) {
		t.Fatalf("group update: %v %v", err, g)
	}
	if _, err := c.svc.UpdateGroup(c.ctx, adm, g.ID, service.GroupInput{Tags: tags("-x")}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("group update bad tag: %v", err)
	}
}

func TestTagRBAC(t *testing.T) {
	c := newCast(t)
	mgr := actor(c.aManager)
	// A manager may tag a plain user of their org ...
	if u, err := c.svc.UpdateUser(c.ctx, mgr, c.aUser.ID, service.UserInput{Tags: tags("dept:sales")}); err != nil || len(u.Tags) != 1 {
		t.Fatalf("manager tags user: %v", err)
	}
	// ... but not an admin, and not another org's user.
	if _, err := c.svc.UpdateUser(c.ctx, mgr, c.aAdmin.ID, service.UserInput{Tags: tags("x")}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("manager tags admin: %v", err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, mgr, c.bAdmin.ID, service.UserInput{Tags: tags("x")}); err == nil {
		t.Error("manager tagged another org")
	}
	// A plain user cannot change their own tags (nor anyone else's).
	self := actor(c.aUser)
	if _, err := c.svc.UpdateUser(c.ctx, self, c.aUser.ID, service.UserInput{Tags: tags("vip")}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("user tags self: %v", err)
	}
	if _, err := c.svc.UpdateUser(service.SelfService(c.ctx), self, c.aUser.ID, service.UserInput{Tags: tags("vip")}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("user tags self (self-service): %v", err)
	}
	// Creating a user with tags needs the same right as creating the user.
	if _, err := c.svc.CreateUser(c.ctx, self, c.a.ID, service.UserInput{GivenName: gn("T"), Email: ptr("n@example.com"), Tags: tags("a")}); err == nil {
		t.Error("plain user created a tagged user")
	}
	// Groups: org admins only.
	g, err := c.svc.CreateGroup(c.ctx, actor(c.aAdmin), c.a.ID, service.GroupInput{DisplayName: ptr("tg")})
	if err != nil {
		t.Fatal(err)
	}
	for name, a := range map[string]*service.Actor{"manager": mgr, "user": self, "other admin": actor(c.bAdmin)} {
		if _, err := c.svc.UpdateGroup(c.ctx, a, g.ID, service.GroupInput{Tags: tags("x")}); err == nil {
			t.Errorf("%s tagged a group", name)
		}
	}
	// The change is audited.
	if _, err := c.svc.UpdateUser(c.ctx, actor(c.aAdmin), c.aUser.ID, service.UserInput{Tags: tags("b", "a")}); err != nil {
		t.Fatal(err)
	}
	pg, err := c.svc.ListAudit(c.ctx, actor(c.aAdmin), c.a.ID, service.AuditQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	evs := pg.Items
	found := false
	for _, e := range evs {
		if e.Detail["tags"] == "a b" {
			found = true
		}
	}
	if !found {
		t.Errorf("no audit event with the tags: %+v", evs)
	}
}

func TestListUsersTagged(t *testing.T) {
	c := newCast(t)
	adm := actor(c.aAdmin)
	for i := range 5 {
		u := c.user(c.a.ID, "tl"+itoa(i), model.RoleUser)
		tg := []string{"all"}
		if i%2 == 0 {
			tg = append(tg, "even")
		}
		if _, err := c.svc.UpdateUser(c.ctx, adm, u.ID, service.UserInput{Tags: &tg}); err != nil {
			t.Fatal(err)
		}
	}
	got, total, err := c.svc.ListUsersTagged(c.ctx, adm, c.a.ID, store.ListQuery{Sort: "username", Limit: 2}, "even")
	if err != nil || total != 3 || len(got) != 2 || got[0].Username != "tl0" || got[1].Username != "tl2" {
		t.Fatalf("tagged: %v total=%d %v", err, total, got)
	}
	got, total, _ = c.svc.ListUsersTagged(c.ctx, adm, c.a.ID, store.ListQuery{Sort: "username", Limit: 2, Offset: 2}, "even")
	if total != 3 || len(got) != 1 || got[0].Username != "tl4" {
		t.Fatalf("page 2: total=%d %v", total, got)
	}
	// exact match only; the search field also finds users by tag
	if _, total, _ = c.svc.ListUsersTagged(c.ctx, adm, c.a.ID, store.ListQuery{}, "eve"); total != 0 {
		t.Errorf("substring matched: %d", total)
	}
	if _, total, _ = c.svc.ListUsers(c.ctx, adm, c.a.ID, store.ListQuery{Search: "even"}); total != 3 {
		t.Errorf("search by tag: %d", total)
	}
	if _, _, err := c.svc.ListUsersTagged(c.ctx, actor(c.aUser), c.a.ID, store.ListQuery{}, "even"); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("plain user: %v", err)
	}
}
