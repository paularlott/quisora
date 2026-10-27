package passkey_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/passkey"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func TestSignCountRegression(t *testing.T) {
	e := setup(t)
	c := e.register(t, "Key")
	for want := uint32(1); want <= 3; want++ {
		id, opts := e.options(t, nil)
		a, _, _ := e.auth.Get(opts)
		if _, err := e.pk.FinishLoginAs(e.ctx, id, a); err != nil {
			t.Fatalf("login %d: %v", want, err)
		}
	}
	// sessions signed in with this passkey (one of them may be the copy's holder's) and one signed in otherwise
	list0, _ := e.svc.Passkeys.All(e.ctx, e.user.ID)
	for i, pk := range []string{list0[0].ID, list0[0].ID, ""} {
		if err := e.svc.Sessions.Create(e.ctx, &model.Session{Meta: model.Meta{ID: fmt.Sprintf("s%d", i)}, UserID: e.user.ID,
			OrgID: e.user.OrgID, Passkey: pk, Expires: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	id, opts := e.options(t, nil)
	stale, err := e.auth.GetWith(opts, c, 2, origin)
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.pk.FinishLoginAs(e.ctx, id, stale)
	if !errors.Is(err, passkey.ErrCloneDetected) || res == nil || res.User.ID != e.user.ID {
		t.Fatalf("want ErrCloneDetected with user, got %v %v", res, err)
	}
	list, _ := e.svc.Passkeys.All(e.ctx, e.user.ID)
	if list[0].SignCount != 3 {
		t.Fatalf("counter moved to %d", list[0].SignCount)
	}
	// Every session the passkey signed in has ended; the other one stays.
	if left, _ := e.svc.Sessions.All(e.ctx, e.user.ID); len(left) != 1 || left[0].ID != "s2" {
		t.Fatalf("sessions after a clone warning: %d", len(left))
	}
	// The suspected clone is disabled: even the genuine authenticator no longer signs in with it.
	if !list[0].Disabled || list[0].Usable() {
		t.Fatalf("passkey not disabled after a clone warning: %+v", list[0])
	}
	id, opts = e.options(t, nil)
	a, _, _ := e.auth.Get(opts)
	if _, err := e.pk.FinishLoginAs(e.ctx, id, a); !errors.Is(err, passkey.ErrUnusable) {
		t.Fatalf("disabled passkey signed in: %v", err)
	}
	if _, _, err := e.pk.BeginLogin(e.ctx, e.user, nil); !errors.Is(err, passkey.ErrUnknownCredential) {
		t.Fatalf("a disabled passkey is still offered: %v", err)
	}
}

func TestZeroCounterSyncedPasskey(t *testing.T) {
	e := setup(t)
	e.auth.CounterStep = 0
	e.auth.BackupEligible, e.auth.BackupState = true, true
	e.register(t, "iCloud")
	for range 3 {
		id, opts := e.options(t, nil)
		a, _, _ := e.auth.Get(opts)
		res, err := e.pk.FinishLoginAs(e.ctx, id, a)
		if err != nil {
			t.Fatalf("zero counters must be accepted: %v", err)
		}
		if got := res.AMR(); got[0] != "swk" {
			t.Fatalf("synced key amr %v", got)
		}
	}
	list, _ := e.svc.Passkeys.All(e.ctx, e.user.ID)
	if !list[0].BackupEligible || !list[0].BackupState {
		t.Fatalf("backup flags not stored: %+v", list[0])
	}
}

// racingPasskeyWrite makes the first write of a passkey lose a race: before it lands, change edits the stored passkey
// as another sign-in (or the user) would have, so the write is refused as stale and made again on what is stored now.
type racingPasskeyWrite struct {
	store.Store
	change func(pk *model.Passkey)
	done   bool
}

func (r *racingPasskeyWrite) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	if rec.Kind == model.KindPasskey && !r.done {
		r.done = true
		cur, err := r.Store.Get(ctx, model.KindPasskey, rec.ID)
		if err != nil {
			return err
		}
		var pk model.Passkey
		if err := store.Decode(cur, &pk); err != nil {
			return err
		}
		r.change(&pk)
		other, err := store.Encode(&pk)
		if err != nil {
			return err
		}
		if err := r.Store.CompareAndPut(ctx, other, cur.Version); err != nil {
			return err
		}
	}
	return r.Store.CompareAndPut(ctx, rec, expect)
}

// A sign-in whose write of the new counter loses to another sign-in that stored a counter the presented one does not
// exceed is a copy at work, as a counter that did not rise is at the check (TestSignCountRegression): the passkey is
// disabled and the sessions it signed in end. The counter the authenticator presented here (1) was stored by the
// other already: two uses, one count.
func TestSignCountRaceIsACloneSignal(t *testing.T) {
	e := setup(t)
	e.register(t, "Key")
	list, _ := e.svc.Passkeys.All(e.ctx, e.user.ID)
	if err := e.svc.Sessions.Create(e.ctx, &model.Session{Meta: model.Meta{ID: "s-pk"}, UserID: e.user.ID, OrgID: e.user.OrgID,
		Passkey: list[0].ID, Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	race := &racingPasskeyWrite{Store: e.svc.Passkeys.S, change: func(pk *model.Passkey) { pk.SignCount = 1; pk.LastUsed = time.Now() }}
	e.svc.Passkeys.S = race
	id, opts := e.options(t, nil)
	a, _, _ := e.auth.Get(opts)
	res, err := e.pk.FinishLoginAs(e.ctx, id, a)
	if !errors.Is(err, passkey.ErrCloneDetected) || res == nil || res.User.ID != e.user.ID {
		t.Fatalf("a counter another sign-in stored first: %v %v", res, err)
	}
	list, _ = e.svc.Passkeys.All(e.ctx, e.user.ID)
	if !list[0].Disabled || list[0].SignCount != 1 {
		t.Fatalf("passkey after the clone signal: %+v", list[0])
	}
	if left, _ := e.svc.Sessions.All(e.ctx, e.user.ID); len(left) != 0 {
		t.Fatalf("%d sessions survive a clone signal", len(left))
	}
}

// Losing the race to a change that is not a sign-in (a rename) is no clone signal: the write is made again on the
// newer record and the sign-in succeeds. A passkey with no counter (synced: zero before and after) has no signal at all.
func TestSignCountRaceWithoutACloneSignal(t *testing.T) {
	for name, step := range map[string]uint32{"counter": 1, "no counter": 0} {
		t.Run(name, func(t *testing.T) {
			e := setup(t)
			e.auth.CounterStep = step
			e.register(t, "Key")
			e.svc.Passkeys.S = &racingPasskeyWrite{Store: e.svc.Passkeys.S, change: func(pk *model.Passkey) { pk.Name = "Renamed" }}
			id, opts := e.options(t, nil)
			a, _, _ := e.auth.Get(opts)
			if _, err := e.pk.FinishLoginAs(e.ctx, id, a); err != nil {
				t.Fatalf("a rename won the race: %v", err)
			}
			list, _ := e.svc.Passkeys.All(e.ctx, e.user.ID)
			if list[0].Name != "Renamed" || list[0].Disabled || list[0].SignCount != step {
				t.Fatalf("passkey: %+v", list[0])
			}
		})
	}
}

// failingPasskeyWrites fails every write of a passkey with err while err is set.
type failingPasskeyWrites struct {
	store.Store
	err error
}

func (f *failingPasskeyWrites) CompareAndPut(ctx context.Context, rec *store.Record, expect hlc.Timestamp) error {
	if rec.Kind == model.KindPasskey && f.err != nil {
		return f.err
	}
	return f.Store.CompareAndPut(ctx, rec, expect)
}

// A sign-in whose new sign count cannot be stored does not go on (the next use of a copy would be compared with an old
// count): the user is asked to try again.
func TestSignInFailsWhenTheCounterCannotBeStored(t *testing.T) {
	e := setup(t)
	e.register(t, "Key")
	f := &failingPasskeyWrites{Store: e.svc.Passkeys.S, err: store.ErrUnconfirmed}
	e.svc.Passkeys.S = f
	id, opts := e.options(t, nil)
	a, _, _ := e.auth.Get(opts)
	res, err := e.pk.FinishLoginAs(e.ctx, id, a)
	if !errors.Is(err, service.ErrUnavailable) || res != nil {
		t.Fatalf("a sign-in whose counter was not stored: %v %v", res, err)
	}
	f.err = nil
	id, opts = e.options(t, nil)
	a, _, _ = e.auth.Get(opts)
	if _, err := e.pk.FinishLoginAs(e.ctx, id, a); err != nil {
		t.Fatalf("the sign-in once the store answers: %v", err)
	}
}

// A detected clone that cannot be disabled is not reported as disabled: the sign-in fails as unavailable (try again,
// which detects it again) and the passkey is disabled once the write can be made.
func TestCloneThatCannotBeDisabledIsNotReportedAsDisabled(t *testing.T) {
	e := setup(t)
	c := e.register(t, "Key")
	for range 3 {
		id, opts := e.options(t, nil)
		a, _, _ := e.auth.Get(opts)
		if _, err := e.pk.FinishLoginAs(e.ctx, id, a); err != nil {
			t.Fatal(err)
		}
	}
	f := &failingPasskeyWrites{Store: e.svc.Passkeys.S, err: store.ErrUnavailable}
	e.svc.Passkeys.S = f
	id, opts := e.options(t, nil)
	stale, err := e.auth.GetWith(opts, c, 2, origin)
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.pk.FinishLoginAs(e.ctx, id, stale)
	if !errors.Is(err, service.ErrUnavailable) || errors.Is(err, passkey.ErrCloneDetected) || res != nil {
		t.Fatalf("a clone that could not be disabled: %v %v", res, err)
	}
	f.err = nil
	if list, _ := e.svc.Passkeys.All(e.ctx, e.user.ID); list[0].Disabled {
		t.Fatal("the passkey was disabled although its write failed")
	}
	id, opts = e.options(t, nil)
	stale, _ = e.auth.GetWith(opts, c, 2, origin)
	if _, err := e.pk.FinishLoginAs(e.ctx, id, stale); !errors.Is(err, passkey.ErrCloneDetected) {
		t.Fatalf("the retry: %v", err)
	}
	if list, _ := e.svc.Passkeys.All(e.ctx, e.user.ID); !list[0].Disabled {
		t.Fatal("the passkey stays enabled")
	}
}
