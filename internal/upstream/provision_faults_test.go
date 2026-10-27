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
	"github.com/paularlott/quisora/internal/upstream"
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

// promoteFirst promotes the user of the first transaction that links an identity, just before it runs: a promotion
// committed between the account's check and the link.
type promoteFirst struct {
	store.Store
	svc  *service.Service
	done atomic.Bool
}

func (f *promoteFirst) Tx(ctx context.Context, ops []store.Op) error {
	for _, op := range ops {
		if op.Rec.Kind != model.KindIdentity || !f.done.CompareAndSwap(false, true) {
			continue
		}
		var id model.Identity
		if err := store.Decode(op.Rec, &id); err != nil {
			return err
		}
		u, err := f.svc.Users.Get(ctx, id.UserID)
		if err != nil {
			return err
		}
		u.Role = model.RoleManager
		if err := f.svc.Users.Update(ctx, u); err != nil {
			return err
		}
	}
	return f.Store.Tx(ctx, ops)
}

// A link by email address is made only while the account is not privileged as the link's own write finds it: a
// promotion committed after the account was read and before the link makes that write stale, and the account, read
// again, is refused as privileged, with no link made.
func TestLinkByEmailSeesAPromotionCommittedMeanwhile(t *testing.T) {
	f := &promoteFirst{Store: memstore.New()}
	e := setupOn(t, f)
	f.svc = e.svc
	p := e.oidcProvider(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(false) })
	u := e.mkUser(t, "pia", "pia@example.com", true)
	if _, err := e.signIn(p, std("pia-sub", "pia@example.com")); !errors.Is(err, upstream.ErrPrivileged) {
		t.Fatalf("a link by email of an account promoted meanwhile: want ErrPrivileged, got %v", err)
	}
	if !f.done.Load() {
		t.Fatal("test set-up: the link's transaction was never made")
	}
	if _, err := e.svc.Identities.GetByUnique(e.ctx, model.IdentityKey(p.ID, "pia-sub")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an identity was made for a privileged account: %v", err)
	}
	if got, _ := e.svc.Users.Get(e.ctx, u.ID); got.Role != model.RoleManager {
		t.Fatalf("role %v", got.Role)
	}
}

// readdressFirst changes the address of the user of the first transaction that links an identity, just before it runs:
// an address corrected between the account's lookup by its verified address and the link.
type readdressFirst struct {
	store.Store
	svc  *service.Service
	done atomic.Bool
}

func (f *readdressFirst) Tx(ctx context.Context, ops []store.Op) error {
	for _, op := range ops {
		if op.Rec.Kind != model.KindIdentity || !f.done.CompareAndSwap(false, true) {
			continue
		}
		var id model.Identity
		if err := store.Decode(op.Rec, &id); err != nil {
			return err
		}
		u, err := f.svc.Users.Get(ctx, id.UserID)
		if err != nil {
			return err
		}
		u.Email = "pia.new@example.com"
		if err := f.svc.Users.Update(ctx, u); err != nil {
			return err
		}
	}
	return f.Store.Tx(ctx, ops)
}

// A link by email address is made only while the address the provider verified is still a verified address of the
// account as the link's own write finds it: an address changed after the account was found by it and before the link
// makes that write stale, and the account, read again, no longer matches: no link is made.
func TestLinkByEmailSeesAnAddressChangedMeanwhile(t *testing.T) {
	f := &readdressFirst{Store: memstore.New()}
	e := setupOn(t, f)
	f.svc = e.svc
	p := e.oidcProvider(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(false) })
	u := e.mkUser(t, "pia", "pia@example.com", true)
	res, err := e.signIn(p, std("pia-sub", "pia@example.com"))
	if !f.done.Load() {
		t.Fatal("test set-up: the link's transaction was never made")
	}
	if err == nil && res.User != nil && res.User.ID == u.ID {
		t.Fatal("signed in to an account by an address it no longer has")
	}
	if _, err := e.svc.Identities.GetByUnique(e.ctx, model.IdentityKey(p.ID, "pia-sub")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an identity was made for an address the account no longer has: %v", err)
	}
}
