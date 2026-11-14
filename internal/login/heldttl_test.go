package login_test

import (
	"context"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
)

// setEph counts the values set in namespace ns.
type setEph struct {
	ephemeral.Store
	ns   string
	sets *int
}

func (e setEph) Set(ctx context.Context, ns, id string, v []byte, ttl time.Duration) error {
	if ns == e.ns {
		*e.sets++
	}
	return e.Store.Set(ctx, ns, id, v, ttl)
}

// A step that stores a sign-in's ticket again keeps it until the ticket's own end, not for a new ten minutes: its
// address was charged for it for that long, and a ticket each request kept alive would be held past it. It is
// replaced where it is, with the expiry it has (ephemeral.Store.Replace), never set for a time of the step's own.
func TestTicketStoredAgainKeepsItsExpiry(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)
	quinn := e.user(t, org, "quinn", model.RoleUser)
	tid, err := e.Mod.PutEnrolTicket(quinn.ID)
	if err != nil {
		t.Fatal(err)
	}
	b := e.browserAt(t, org)
	sets := 0
	orig := e.Server.Eph
	e.Server.Eph = setEph{Store: orig, ns: "login", sets: &sets}
	t.Cleanup(func() { e.Server.Eph = orig })
	before, _ := orig.Get(context.Background(), "login", tid)
	res, out := b.post("/api-internal/login/enrol/totp/begin", map[string]any{"ticket": tid})
	wantStatus(t, res, out, 200)
	after, err := orig.Get(context.Background(), "login", tid)
	if err != nil || string(after) == string(before) {
		t.Fatalf("the ticket was not stored again with its pending secret: %v", err)
	}
	if sets != 0 {
		t.Fatal("a ticket was stored again for a time of the step's own, not replaced with the expiry it had")
	}
}
