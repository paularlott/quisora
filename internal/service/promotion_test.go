package service_test

import (
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Promotion to manager or above removes the provider links made automatically by email address; links the user
// connected themselves, and the provider that created the account, stay.
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
	if len(ids) != 2 || !kept["connect"] || !kept["provision"] {
		t.Fatalf("after promotion: %v", kept)
	}
}
