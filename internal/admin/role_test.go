package admin_test

import (
	"context"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Promoting a user in the console ends as any promotion does (service.UpdateUser, applyRole): the sign-in links nobody
// chose are dropped, and a link the user made themselves stays.
func TestConsolePromotionDropsEmailLinks(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	u := w.users["user"]
	var links []*model.Identity
	for _, c := range []struct{ name, via string }{{"sso-a", "email"}, {"sso-b", "admin"}} {
		p, err := w.env.Svc.CreateProvider(ctx, service.System, w.acme.ID, service.ProviderInput{Name: ptr(c.name),
			Issuer: ptr("https://login.example.com"), ClientID: ptr("cid"), ClientSecret: ptr("csecret")})
		if err != nil {
			t.Fatal(err)
		}
		i := model.NewIdentity(u, p, c.name, u.Email, c.via)
		if err := w.env.Svc.Identities.Create(ctx, i); err != nil {
			t.Fatal(err)
		}
		links = append(links, i)
	}
	want(t, w.as("admin").patch(AU+"/"+u.ID, map[string]any{"role": "manager"}), 200)
	left, err := w.env.Svc.Identities.All(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 || left[0].ID != links[1].ID {
		t.Fatalf("%d links left after the promotion (want only the link the user made)", len(left))
	}
}
