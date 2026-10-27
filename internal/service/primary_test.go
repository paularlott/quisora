package service_test

import (
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// The primary organization never changes: it is the one with the fixed id, whichever node asks and whatever else is
// stored, so there can never be two.
func TestPrimaryOrgIsTheOneWithTheFixedID(t *testing.T) {
	e := newEnv(t)
	other := e.org("other")
	if p, err := e.svc.PrimaryOrg(e.ctx); err != nil || p.ID != model.PrimaryOrgID || !p.Primary() || other.Primary() {
		t.Fatalf("the primary: %v %v (another: %v)", p, err, other.Primary())
	}
	fresh := service.New(e.svc.Cfg, e.svc.Store, e.svc.Sealer) // another node: nothing remembered
	if p, err := fresh.PrimaryOrg(e.ctx); err != nil || p.ID != e.primary.ID {
		t.Fatalf("the primary on another node: %v %v", p, err)
	}
}
