package service_test

import (
	"errors"
	"strconv"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// A guest's personal API token stands on the account its sign-in came from (APIToken.Sources) as that person's own
// tokens do: it outlives a sign-out there, and ends when that account is disabled, reset or deleted. A token cannot be
// made under a sign-in whose source has ended.
func TestGuestAPITokenStandsOnItsSource(t *testing.T) {
	c := newCast(t)
	n := 0
	guestOf := func() (src, g *model.User, a *service.Actor) {
		n++
		src = c.user(c.a.ID, "home"+strconv.Itoa(n), model.RoleUser)
		g = c.user(c.b.ID, "guest"+strconv.Itoa(n), model.RoleUser)
		a = actor(g)
		a.Sources = []model.GuestSource{{UserID: src.ID, Epoch: c.fresh(src).SessionEpoch}}
		return src, g, a
	}
	mint := func(a *service.Actor) (string, error) {
		_, plain, err := c.svc.CreateAPIToken(c.ctx, a, service.APITokenInput{Name: "t", Scopes: []string{service.ScopeAPI}})
		return plain, err
	}
	valid := func(plain string) bool {
		_, _, err := c.svc.ValidateAPIToken(c.ctx, plain)
		if err != nil && !errors.Is(err, service.ErrBadToken) {
			t.Fatal(err)
		}
		return err == nil
	}

	// signing out at home ends the guest's sessions, not the token: as for the person's own tokens there
	src, _, a := guestOf()
	plain, err := mint(a)
	if err != nil || !valid(plain) {
		t.Fatalf("a guest's token while its source stands: %v", err)
	}
	if err := c.svc.RevokeSessions(c.ctx, service.System, src.ID); err != nil {
		t.Fatal(err)
	}
	if !valid(plain) {
		t.Error("its source signing out ended the token")
	}
	if _, err := mint(a); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("a token made under a sign-in whose source has ended: %v", err)
	}

	// disabled at home: stops, and works again once enabled
	src, _, a = guestOf()
	plain, _ = mint(a)
	if _, err := c.svc.UpdateUser(c.ctx, service.System, src.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if valid(plain) {
		t.Error("its source disabled")
	}
	if _, err := c.svc.UpdateUser(c.ctx, service.System, src.ID, service.UserInput{Active: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if !valid(plain) {
		t.Error("its source enabled again")
	}

	// credentials reset at home
	src, _, a = guestOf()
	plain, _ = mint(a)
	if err := c.svc.ResetCredentials(c.ctx, src.ID); err != nil {
		t.Fatal(err)
	}
	if valid(plain) {
		t.Error("its source's credentials reset")
	}

	// deleted at home
	src, _, a = guestOf()
	plain, _ = mint(a)
	if err := c.svc.DeleteUser(c.ctx, service.System, src.ID); err != nil {
		t.Fatal(err)
	}
	if valid(plain) {
		t.Error("its source deleted")
	}

	// a guest's regenerated token keeps standing on its source
	src, _, a = guestOf()
	tok, _, err := c.svc.CreateAPIToken(c.ctx, a, service.APITokenInput{Name: "r", Scopes: []string{service.ScopeAPI}})
	if err != nil {
		t.Fatal(err)
	}
	_, plain, err = c.svc.RegenerateAPIToken(c.ctx, a, tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.svc.ResetCredentials(c.ctx, src.ID); err != nil {
		t.Fatal(err)
	}
	if valid(plain) {
		t.Error("a regenerated token outlived its source's reset")
	}
}
