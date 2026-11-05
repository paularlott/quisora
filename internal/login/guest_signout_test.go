package login_test

import (
	"context"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// Ending a user's sessions ends their guest accounts' too: the accounts other organizations hold for them through an
// organization provider, which would otherwise stay signed in (an organization provider has no refresh token to notice
// a leaver with). Other people's guest accounts are left alone.
func TestEndingASourceUsersSessionsEndsTheirGuestAccounts(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(g *guestEnv, userID string) error
	}{
		{"signed out everywhere", func(g *guestEnv, id string) error {
			return g.Svc.RevokeSessions(context.Background(), service.System, id)
		}},
		{"disabled", func(g *guestEnv, id string) error {
			_, err := g.Svc.UpdateUser(context.Background(), service.System, id, service.UserInput{Active: ptr(false)})
			return err
		}},
		{"deleted", func(g *guestEnv, id string) error {
			return g.Svc.DeleteUser(context.Background(), service.System, id)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newGuestEnv(t, func(in *service.ProviderInput) { in.LinkByEmail = ptr(true) })
			pat := g.person(t, g.Primary, "pat", "pat@example.com")
			patGuest := g.person(t, g.acme, "pat-guest", "pat@example.com")
			sam := g.person(t, g.Primary, "sam", "sam@example.com")
			samGuest := g.person(t, g.acme, "sam-guest", "sam@example.com")
			g.continueAs(t, pat)
			g.continueAs(t, sam)
			if len(sessionsOf(t, g.env, patGuest)) != 1 || len(sessionsOf(t, g.env, samGuest)) != 1 {
				t.Fatal("the guests did not sign in")
			}

			if err := tc.end(g, pat.ID); err != nil {
				t.Fatal(err)
			}
			if s := sessionsOf(t, g.env, patGuest); len(s) != 0 {
				t.Fatalf("pat's guest account is still signed in: %+v", s)
			}
			if len(sessionsOf(t, g.env, samGuest)) != 1 {
				t.Fatal("sam's guest account was signed out too")
			}
		})
	}
}
