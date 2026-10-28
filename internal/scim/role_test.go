package scim_test

import (
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Raising a user to manager through SCIM ends as any promotion does (service.UpdateUser, applyRole): the sign-in links
// the user did not make themselves are dropped (by email, by the provider creating the account, by an administrator),
// and a link the user connected stays.
func TestRoleMappingToManagerDropsEmailLinks(t *testing.T) {
	e := newEnv(t)
	id := e.mk("promote-me", nil)
	u, err := e.Svc.Users.Get(e.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	var links []*model.Identity
	for _, c := range []struct{ name, via string }{{"sso-a", "email"}, {"sso-b", "provision"}, {"sso-c", "admin"}, {"sso-d", "connect"}} {
		p, err := e.Svc.CreateProvider(e.ctx, service.System, e.orgA.ID, service.ProviderInput{Name: ptr(c.name),
			Issuer: ptr("https://login.example.com"), ClientID: ptr("cid"), ClientSecret: ptr("csecret")})
		if err != nil {
			t.Fatal(err)
		}
		i := model.NewIdentity(u, p, c.name, u.Email, c.via)
		if err := e.Svc.Identities.Create(e.ctx, i); err != nil {
			t.Fatal(err)
		}
		links = append(links, i)
	}
	if r := e.do("PATCH", "/scim/v2/acme/Users/"+id, e.admA, patchBody(op("replace", quisoraURN+":role", "manager"))); r.Status != 200 {
		t.Fatalf("promote: %d %s", r.Status, r.Raw)
	}
	left, err := e.Svc.Identities.All(e.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := e.Svc.Users.Get(e.ctx, id); got.Role != model.RoleManager || len(left) != 1 || left[0].ID != links[3].ID {
		t.Fatalf("role %s, %d links left (want the manager with only the link the user connected)", got.Role, len(left))
	}
}
