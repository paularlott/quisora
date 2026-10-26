package upstream_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
	"github.com/paularlott/quisora/internal/upstream"
)

// provisionFaults is a store that fails the writes an upstream auto-provision makes: the identity (all of them), the
// first deletions of a user, and the creation of a user, which lands and then reports store.ErrUnconfirmed.
type provisionFaults struct {
	store.Store
	identityDown  atomic.Bool
	userDeleteErr atomic.Int32 // deletions of a user that fail
	userUnknown   atomic.Bool  // the next creation of a user lands and ends unconfirmed
}

func (f *provisionFaults) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindIdentity && f.identityDown.Load() {
		return store.ErrNotWritable
	}
	if r.Kind == model.KindUser && expect == 0 && f.userUnknown.CompareAndSwap(true, false) {
		if err := f.Store.CompareAndPut(ctx, r, expect); err != nil {
			return err
		}
		return store.ErrUnconfirmed
	}
	return f.Store.CompareAndPut(ctx, r, expect)
}

func (f *provisionFaults) Put(ctx context.Context, r *store.Record) error {
	if r.Kind == model.KindUser && r.Deleted && f.userDeleteErr.Add(-1) >= 0 {
		return store.ErrNotWritable
	}
	return f.Store.Put(ctx, r)
}

// A creation of the account that lands but is not confirmed does not strand it: the account is linked in the same
// sign-in (a retry would meet it as an address clash it cannot resolve).
func TestAutoProvisionLinksAnAccountWhoseCreationWasUnconfirmed(t *testing.T) {
	f := &provisionFaults{Store: memstore.New()}
	e := setupOn(t, f)
	p := e.oidcProvider(t, nil)
	f.userUnknown.Store(true)
	res, err := e.signIn(p, std("sub-1", "new@example.com"))
	if err != nil || !res.Provisioned {
		t.Fatalf("sign-in after an unconfirmed creation: %v %+v", err, res)
	}
	if _, err := e.svc.Identities.GetByUnique(e.ctx, model.IdentityKey(p.ID, "sub-1")); err != nil {
		t.Fatalf("the account has no link: %v", err)
	}
	if res2, err := e.signIn(p, std("sub-1", "new@example.com")); err != nil || res2.User.ID != res.User.ID {
		t.Fatalf("the next sign-in: %v", err)
	}
}

// An account whose link could not be made is removed, and a deletion that fails once is tried again, so the address is
// not blocked for good.
func TestAutoProvisionRemovesTheAccountWhenItsLinkFails(t *testing.T) {
	f := &provisionFaults{Store: memstore.New()}
	e := setupOn(t, f)
	p := e.oidcProvider(t, nil)
	f.identityDown.Store(true)
	f.userDeleteErr.Store(1)
	if _, err := e.signIn(p, std("sub-2", "other@example.com")); err == nil {
		t.Fatal("a sign-in whose link could not be made succeeded")
	} else if errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if n, _ := e.svc.Users.Count(e.ctx, e.org.ID); n != 0 {
		t.Fatalf("%d account(s) stranded", n)
	}
	f.identityDown.Store(false)
	if res, err := e.signIn(p, std("sub-2", "other@example.com")); err != nil || !res.Provisioned {
		t.Fatalf("the retry: %v", err)
	}
}

// An account stranded when the store refused for the whole sign-in (the link failed and so did every removal) is the
// provider's to take up: the next sign-in links it, without linking by email (which would find it anyway). An account
// an administrator made for the same address is not.
func TestAutoProvisionTakesUpTheAccountItStranded(t *testing.T) {
	f := &provisionFaults{Store: memstore.New()}
	e := setupOn(t, f)
	p := e.oidcProvider(t, func(in *service.ProviderInput) { in.LinkByEmail = ptr(false) })
	f.identityDown.Store(true)
	f.userDeleteErr.Store(3)
	if _, err := e.signIn(p, std("sub-3", "stuck@example.com")); err == nil {
		t.Fatal("a sign-in whose link could not be made succeeded")
	}
	if n, _ := e.svc.Users.Count(e.ctx, e.org.ID); n != 1 {
		t.Fatalf("setup: %d accounts, want the stranded one", n)
	}
	f.identityDown.Store(false)
	res, err := e.signIn(p, std("sub-3", "stuck@example.com"))
	if err != nil || !res.Provisioned {
		t.Fatalf("the retry: %v %+v", err, res)
	}
	if n, _ := e.svc.Users.Count(e.ctx, e.org.ID); n != 1 {
		t.Fatalf("%d accounts after the retry", n)
	}

	email := "staff@example.com"
	if _, err := e.svc.CreateUser(e.ctx, service.System, e.org.ID, service.UserInput{Email: &email, GivenName: ptr("Sam")}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.signIn(p, std("sub-4", email)); !errors.Is(err, upstream.ErrExists) {
		t.Fatalf("an administrator's account was taken up: %v", err)
	}
}
