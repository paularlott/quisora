package service_test

import (
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// An invitation or reset link is bound to the address the account had when it was issued: once an administrator
// corrects a mistyped address, the link that went to the wrong mailbox opens nothing (it would have set the
// account's credentials). A break-glass invitation goes to whoever runs the command, not to an address.
func TestLinksStopWhenTheAddressChanges(t *testing.T) {
	e := newEnv(t)
	u := e.user(e.primary.ID, "bob", model.RoleUser)
	invite, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	reset, _, err := e.svc.IssueLink(e.ctx, u, service.LinkReset, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, tokenFrom(invite), service.LinkInvite); err != nil {
		t.Fatalf("invitation before the change: %v", err)
	}
	if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Email: ptr("bob.right@example.com")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, tokenFrom(invite), service.LinkInvite); !errors.Is(err, service.ErrLink) {
		t.Fatalf("invitation for the old address still opens: %v", err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, reset, service.LinkReset); !errors.Is(err, service.ErrLink) {
		t.Fatalf("reset link for the old address still opens: %v", err)
	}
	// A new invitation, for the address on file now, works.
	invite, _, err = e.svc.CreateInvite(e.ctx, service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, tokenFrom(invite), service.LinkInvite); err != nil {
		t.Fatalf("new invitation: %v", err)
	}
	bg, _, err := e.svc.CreateBreakGlassInvite(e.ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Email: ptr("bob.again@example.com")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.PeekLink(e.ctx, tokenFrom(bg), service.LinkInvite); err != nil {
		t.Fatalf("break-glass invitation: %v", err)
	}
}
