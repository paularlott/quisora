package service_test

import (
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Promotion to manager or above removes every provider link the user did not make themselves from their account page
// (by email address, by the provider that created the account, by an administrator); a link the user connected stays.
func TestPromotionDropsEmailLinks(t *testing.T) {
	e := newEnv(t)
	o := e.org("acme")
	u := e.user(o.ID, "pat", model.RoleUser)
	p := &model.Provider{OrgID: o.ID, Name: "corp", Type: model.ProviderOIDC, Issuer: "https://idp.example", Enabled: true}
	if err := e.svc.Providers.Create(e.ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, via := range []string{"email", "connect", "provision", ""} {
		id := model.NewIdentity(u, p, "sub-"+via, "pat@example.com", via)
		if err := e.svc.Identities.Create(e.ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	// a change that is no promotion keeps everything
	if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{GivenName: ptr("Pat")}); err != nil {
		t.Fatal(err)
	}
	if ids, _ := e.svc.Identities.All(e.ctx, u.ID); len(ids) != 4 {
		t.Fatalf("links before promotion: %d", len(ids))
	}
	if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Role: ptr(model.RoleManager)}); err != nil {
		t.Fatal(err)
	}
	ids, _ := e.svc.Identities.All(e.ctx, u.ID)
	kept := map[string]bool{}
	for _, id := range ids {
		kept[id.Via] = true
	}
	if len(ids) != 1 || !kept["connect"] {
		t.Fatalf("after promotion: %v", kept)
	}
}

// A unique value (a provider link's subject) held by a record that counts for nothing is freed at once, not left to
// the orphan sweep: deleting an account never blocks linking that provider identity to another. A record that counts
// keeps its value.
func TestReleaseUniqueFreesOnlyDeadHolders(t *testing.T) {
	c := newCast(t)
	prov, err := c.svc.CreateProvider(c.ctx, service.System, c.a.ID, goodProvider("sso"))
	if err != nil {
		t.Fatal(err)
	}
	gone, next := c.user(c.a.ID, "gone", model.RoleUser), c.user(c.a.ID, "next", model.RoleUser)
	key := model.IdentityKey(prov.ID, "sub-1")
	if err := c.svc.Identities.Create(c.ctx, model.NewIdentity(gone, prov, "sub-1", "", "admin")); err != nil {
		t.Fatal(err)
	}
	if freed, err := c.svc.ReleaseUnique(c.ctx, model.KindIdentity, key); err != nil || freed {
		t.Errorf("live link released: %v %v", freed, err)
	}
	if err := c.svc.DeleteUser(c.ctx, actor(c.aAdmin), gone.ID); err != nil {
		t.Fatal(err)
	}
	if freed, err := c.svc.ReleaseUnique(c.ctx, model.KindIdentity, key); err != nil || !freed {
		t.Fatalf("link of a deleted user kept: %v %v", freed, err)
	}
	if err := c.svc.Identities.Create(c.ctx, model.NewIdentity(next, prov, "sub-1", "", "admin")); err != nil {
		t.Fatalf("relink: %v", err)
	}
	if freed, err := c.svc.ReleaseUnique(c.ctx, model.KindIdentity, "nothing-holds-this"); err != nil || !freed {
		t.Errorf("an unheld value: %v %v", freed, err)
	}
}
