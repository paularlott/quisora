package upstream_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// provisionFaults is a store that fails the transaction an upstream auto-provision makes (the account and its link):
// refused while identities are down, or landed and then reported of unknown outcome, once.
type provisionFaults struct {
	store.Store
	identityDown atomic.Bool
	unknown      atomic.Bool // the next transaction creating a user lands and ends unconfirmed
}

func (f *provisionFaults) Tx(ctx context.Context, ops []store.Op) error {
	creates := false
	for _, op := range ops {
		if op.Rec.Kind == model.KindIdentity && f.identityDown.Load() {
			return store.ErrUnavailable
		}
		creates = creates || op.Rec.Kind == model.KindUser && op.Match && op.Expect == 0
	}
	if creates && f.unknown.CompareAndSwap(true, false) {
		if err := f.Store.Tx(ctx, ops); err != nil {
			return err
		}
		return store.ErrUnconfirmed
	}
	return f.Store.Tx(ctx, ops)
}

// A first sign-in whose account and link were written but reported of unknown outcome is answered as such, and its
// retry signs in through the link it made: one account.
func TestAutoProvisionOfUnknownOutcomeSignsInOnRetry(t *testing.T) {
	f := &provisionFaults{Store: memstore.New()}
	e := setupOn(t, f)
	p := e.oidcProvider(t, nil)
	f.unknown.Store(true)
	if _, err := e.signIn(p, std("sub-1", "new@example.com")); !errors.Is(err, service.ErrOutcomeUnknown) {
		t.Fatalf("a sign-in whose provisioning was of unknown outcome: %v", err)
	}
	res, err := e.signIn(p, std("sub-1", "new@example.com"))
	if err != nil || res.User == nil {
		t.Fatalf("the retry: %v %+v", err, res)
	}
	if n, _ := e.svc.Users.Count(e.ctx, e.org.ID); n != 1 {
		t.Fatalf("%d accounts", n)
	}
}

// When the link cannot be written, neither is the account (one transaction): nothing blocks the address, and the retry
// provisions it.
func TestAutoProvisionWritesNoAccountWithoutItsLink(t *testing.T) {
	f := &provisionFaults{Store: memstore.New()}
	e := setupOn(t, f)
	p := e.oidcProvider(t, nil)
	f.identityDown.Store(true)
	if _, err := e.signIn(p, std("sub-2", "other@example.com")); err == nil {
		t.Fatal("a sign-in whose link could not be made succeeded")
	}
	if n, _ := e.svc.Users.Count(e.ctx, e.org.ID); n != 0 {
		t.Fatalf("%d account(s) without their link", n)
	}
	f.identityDown.Store(false)
	if res, err := e.signIn(p, std("sub-2", "other@example.com")); err != nil || !res.Provisioned {
		t.Fatalf("the retry: %v", err)
	}
}
