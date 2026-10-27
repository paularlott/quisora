package service_test

import (
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// The primary organization never changes: a store that has a second one marked primary (an interrupted set-primary
// of an earlier build) answers ErrTwoPrimaries, naming both, rather than choosing one.
func TestPrimaryOrgRefusesTwoMarked(t *testing.T) {
	e := newEnv(t)
	if p, err := e.svc.PrimaryOrg(e.ctx); err != nil || p.ID != e.primary.ID {
		t.Fatalf("the primary: %v %v", p, err)
	}
	other := e.org("other")
	o, err := e.svc.Orgs.Get(e.ctx, other.ID)
	if err != nil {
		t.Fatal(err)
	}
	o.Primary = true
	if err := e.svc.Orgs.Update(e.ctx, o); err != nil {
		t.Fatal(err)
	}
	fresh := service.New(e.svc.Cfg, e.svc.Store, e.svc.Sealer) // another node: nothing remembered
	if _, err := fresh.PrimaryOrg(e.ctx); !errors.Is(err, service.ErrTwoPrimaries) {
		t.Fatalf("two marked primary: %v", err)
	}
}
