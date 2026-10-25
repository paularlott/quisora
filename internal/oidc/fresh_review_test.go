package oidc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestFreshReviewGrantMaintenanceCannotReopenRefreshGrace(t *testing.T) {
	for _, maintenance := range []bool{false, true} {
		name := "expired grace"
		if maintenance {
			name = "expired grace after maintenance"
		}
		t.Run(name, func(t *testing.T) {
			h := setup(t, nil)
			ctx := context.Background()
			cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
			initial, _ := h.login(cl, secret, nil)
			old := initial.str("refresh_token")
			if r := h.refreshWith(cl, secret, old); r.status != 200 {
				t.Fatalf("rotation: %d %v", r.status, r.m)
			}
			g, err := h.env.Svc.Grants.Get(ctx, strings.SplitN(old, ".", 2)[0])
			if err != nil {
				t.Fatal(err)
			}
			// Model an otherwise identical rotation whose response was lost more than a grace interval ago.
			g.Updated = time.Now().Add(-2 * refreshRetryGrace)
			raw, err := store.EncodeAsIs(g)
			if err != nil {
				t.Fatal(err)
			}
			raw.Version = store.Clock.Now()
			if err := h.env.Svc.Store.Put(ctx, raw); err != nil {
				t.Fatal(err)
			}
			g, err = h.env.Svc.Grants.Get(ctx, g.ID)
			if err != nil {
				t.Fatal(err)
			}
			if maintenance {
				// Resealing g.Key calls this same update without changing the rotation counter (service/reseal.go).
				if err := h.env.Svc.Grants.Update(ctx, g); err != nil {
					t.Fatal(err)
				}
			}
			if r := h.refreshWith(cl, secret, old); r.status == 200 {
				t.Fatalf("expired previous refresh token accepted after non-rotation grant update: counter=%d status=%d", g.Counter, r.status)
			}
		})
	}
}
