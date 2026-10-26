package service_test

import (
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// e2 makes another plain user of org (a peer who may not manage c.aUser).
func (c *cast) e2(orgID string) *model.User { return c.user(orgID, c.next("peer"), model.RoleUser) }

// cast is a fixed set of actors used by the RBAC matrix: one of each role in the primary org and in org A, and an
// admin of org B.
type cast struct {
	*env
	a, b                           *model.Org
	super, pAdmin, pManager, pUser *model.User
	aAdmin, aManager, aUser        *model.User
	bAdmin                         *model.User
}

func newCast(t testing.TB) *cast {
	e := newEnv(t)
	c := &cast{env: e, a: e.org("org-a"), b: e.org("org-b")}
	c.super = e.super
	c.pAdmin = e.user(e.primary.ID, "padmin", model.RoleAdmin)
	c.pManager = e.user(e.primary.ID, "pmanager", model.RoleManager)
	c.pUser = e.user(e.primary.ID, "puser", model.RoleUser)
	c.aAdmin = e.user(c.a.ID, "aadmin", model.RoleAdmin)
	c.aManager = e.user(c.a.ID, "amanager", model.RoleManager)
	c.aUser = e.user(c.a.ID, "auser", model.RoleUser)
	c.bAdmin = e.user(c.b.ID, "badmin", model.RoleAdmin)
	return c
}

type actorCase struct {
	name string
	u    *model.User
}

func (c *cast) actors() []actorCase {
	return []actorCase{
		{"super", c.super}, {"primary-admin", c.pAdmin}, {"primary-manager", c.pManager}, {"primary-user", c.pUser},
		{"a-admin", c.aAdmin}, {"a-manager", c.aManager}, {"a-user", c.aUser}, {"b-admin", c.bAdmin},
	}
}

// match compares an outcome with an expectation; "denied" accepts forbidden or notfound.
func match(got, want string) bool {
	if want == "denied" {
		return got == "forbidden" || got == "notfound"
	}
	return got == want
}

func (c *cast) check(t *testing.T, name string, err error, want string) {
	t.Helper()
	if got := outcome(err); !match(got, want) {
		t.Errorf("%s: got %s (%v), want %s", name, got, err, want)
	}
}

func goodProvider(name string) service.ProviderInput {
	return service.ProviderInput{Name: &name, Issuer: ptr("https://login.example.com"), ClientID: ptr("cid"),
		ClientSecret: ptr("csecret")}
}
