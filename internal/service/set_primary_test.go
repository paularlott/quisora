package service_test

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// Another organization made primary: it gets the super admin named, the old primary's super admins become
// administrators, and every service (another process on the same store included) sees the new primary.
func TestSetPrimaryOrg(t *testing.T) {
	e := newEnv(t)
	other := service.New(e.svc.Cfg, e.svc.Store, e.svc.Sealer) // a second server on the same database
	if p, _ := other.PrimaryOrg(e.ctx); p.ID != e.primary.ID {
		t.Fatal("setup")
	}
	acme := e.org("acme")
	boss := e.user(acme.ID, "boss", model.RoleAdmin)
	off := e.user(acme.ID, "off", model.RoleUser)
	disabled := false
	if _, err := e.svc.UpdateUser(e.ctx, service.System, off.ID, service.UserInput{Active: &disabled}); err != nil {
		t.Fatal(err)
	}
	stranger := e.user(e.primary.ID, "stranger", model.RoleUser)
	for name, tc := range map[string]struct{ org, user string }{
		"already primary":     {e.primary.ID, stranger.ID},
		"user elsewhere":      {acme.ID, stranger.ID},
		"user disabled":       {acme.ID, off.ID},
		"unknown super admin": {acme.ID, "nobody"},
	} {
		if _, _, err := e.svc.SetPrimaryOrg(e.ctx, tc.org, tc.user); !errors.As(err, new(*service.FieldError)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := e.svc.SetPrimaryOrg(e.ctx, "missing", boss.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown org: %v", err)
	}
	if p, _ := e.svc.PrimaryOrg(e.ctx); p.ID != e.primary.ID {
		t.Fatal("the primary moved by refused calls")
	}
	old, demoted, err := e.svc.SetPrimaryOrg(e.ctx, acme.ID, boss.ID)
	if err != nil || old.ID != e.primary.ID || len(demoted) != 1 || demoted[0].ID != e.super.ID {
		t.Fatalf("set primary: %v %v %v", old, demoted, err)
	}
	for _, s := range []*service.Service{e.svc, other} {
		if p, err := s.PrimaryOrg(e.ctx); err != nil || p.ID != acme.ID {
			t.Fatalf("primary seen: %v %v", p, err)
		}
	}
	if u, _ := e.svc.Users.Get(e.ctx, boss.ID); u.Role != model.RoleSuperAdmin {
		t.Fatalf("new super admin: %s", u.Role)
	}
	if u, _ := e.svc.Users.Get(e.ctx, e.super.ID); u.Role != model.RoleAdmin {
		t.Fatalf("old super admin: %s", u.Role)
	}
	if o, _ := e.svc.Orgs.Get(e.ctx, e.primary.ID); o.Primary {
		t.Fatal("the old primary is still primary")
	}
	// the demoted super admin no longer acts as one, and the new one does
	if e.svc.CanAdminOrg(actor(e.fresh(e.super)), e.org("other").ID) {
		t.Error("the demoted super admin still administers other organizations")
	}
	if !e.svc.CanAdminOrg(actor(e.fresh(boss)), e.primary.ID) {
		t.Error("the new super admin cannot administer other organizations")
	}
	// the old primary can now be deleted like any organization; the new one cannot
	if err := e.svc.DeleteOrg(e.ctx, service.System, acme.ID, true); !errors.Is(err, service.ErrPrimaryOrg) {
		t.Fatalf("deleting the new primary: %v", err)
	}
}

// primaryMove is a cast for the set-primary tests: the primary, an organization to move it to with its administrator,
// and an extra super admin of the old primary, behind a store whose writes can be made to fail.
type primaryMove struct {
	*env
	h      *faultStore
	acme   *model.Org
	boss   *model.User
	second *model.User // a second super admin of the old primary
}

func newPrimaryMove(t *testing.T) *primaryMove {
	e := newEnv(t)
	m := &primaryMove{env: e, h: &faultStore{Store: e.svc.Store}}
	m.acme = e.org("acme")
	m.boss = e.user(m.acme.ID, "boss", model.RoleAdmin)
	m.second = e.user(e.primary.ID, "second", model.RoleSuperAdmin)
	e.svc.Orgs.S = m.h
	e.svc.Users.S = m.h
	return m
}

func (m *primaryMove) failOn(kind model.Kind, id string, err error) {
	m.h.beforeCAS = func(r *store.Record, _ hlc.Timestamp) error {
		if r.Kind == kind && r.ID == id {
			return err
		}
		return nil
	}
}

// done checks the state a finished change leaves.
func (m *primaryMove) done() {
	m.t.Helper()
	orgs, err := m.svc.Store.List(m.ctx, model.KindOrg, store.ListQuery{Filters: []store.Filter{{Field: "primary", Value: true}}})
	if err != nil || len(orgs.Records) != 1 || orgs.Records[0].ID != m.acme.ID {
		m.t.Fatalf("primary organizations: %v %v", orgs, err)
	}
	if p, err := m.svc.PrimaryOrg(m.ctx); err != nil || p.ID != m.acme.ID {
		m.t.Fatalf("PrimaryOrg: %v %v", p, err)
	}
	for id, want := range map[string]model.Role{m.boss.ID: model.RoleSuperAdmin, m.super.ID: model.RoleAdmin, m.second.ID: model.RoleAdmin} {
		if u, err := m.svc.Users.Get(m.ctx, id); err != nil || u.Role != want {
			m.t.Fatalf("role of %s: %v %v, want %s", id, u, err, want)
		}
	}
}

// A change that fails at any of its four steps is finished by running it again: the target is primary already, or
// the old primary still is, or only its super admins are left; each rerun does what is missing and audits the change.
func TestSetPrimaryOrgResumesAtEveryStep(t *testing.T) {
	steps := []struct {
		name string
		kind func(m *primaryMove) (model.Kind, string)
	}{
		{"new primary marked", func(m *primaryMove) (model.Kind, string) { return model.KindOrg, m.acme.ID }},
		{"new super admin promoted", func(m *primaryMove) (model.Kind, string) { return model.KindUser, m.boss.ID }},
		{"old super admins demoted", func(m *primaryMove) (model.Kind, string) { return model.KindUser, m.second.ID }},
		{"old primary unmarked", func(m *primaryMove) (model.Kind, string) { return model.KindOrg, m.primary.ID }},
	}
	for i, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			m := newPrimaryMove(t)
			kind, id := step.kind(m)
			m.failOn(kind, id, store.ErrNotWritable)
			if _, _, err := m.svc.SetPrimaryOrg(m.ctx, m.acme.ID, m.boss.ID); !errors.Is(err, service.ErrUnavailable) {
				t.Fatalf("failing write: %v", err)
			}
			// What took effect is on record: a change stopped after a write landed is audited as incomplete.
			wantIncomplete := 0
			if i > 0 {
				wantIncomplete = 1
			}
			if got := m.audited(m.acme.ID, "org.primary"); len(got) != wantIncomplete || outcomes(got, service.OutcomeIncomplete) != wantIncomplete {
				t.Fatalf("audit of the unfinished change: %d events, %d incomplete; want %d", len(got), outcomes(got, service.OutcomeIncomplete), wantIncomplete)
			}
			// Whatever state it stopped in, the server has a primary organization.
			if p, err := m.svc.PrimaryOrg(m.ctx); err != nil || (p.ID != m.acme.ID && p.ID != m.primary.ID) {
				t.Fatalf("primary in between: %v %v", p, err)
			}
			// Once anything has changed, both are marked until the rerun: every node logs that at error level.
			if marked, err := m.svc.Store.List(m.ctx, model.KindOrg, store.ListQuery{Filters: []store.Filter{{Field: "primary", Value: true}}}); i > 0 && (err != nil || len(marked.Records) != 2) {
				t.Fatalf("organizations marked primary after an interruption: %v %v", marked, err)
			}
			m.h.beforeCAS = nil
			old, demoted, err := m.svc.SetPrimaryOrg(m.ctx, m.acme.ID, m.boss.ID)
			if err != nil {
				t.Fatalf("rerun: %v", err)
			}
			m.done()
			if old == nil || old.ID != m.primary.ID {
				t.Errorf("old primary reported: %+v", old)
			}
			// What the first run had demoted already is not demoted again; everything the rerun demoted is reported.
			wantDemoted := 2
			switch i {
			case 2:
				wantDemoted = 1 // the failing write was the second super admin's (the order of the two is not fixed)
			case 3:
				wantDemoted = 0 // both were demoted before the old primary was unmarked
			}
			if i == 2 && len(demoted) < wantDemoted || i != 2 && len(demoted) != wantDemoted {
				t.Errorf("demoted %d users", len(demoted))
			}
			finished := func(org string) int {
				got := m.audited(org, "org.primary")
				return len(got) - outcomes(got, service.OutcomeIncomplete)
			}
			if finished(m.acme.ID) != 1 || finished(m.primary.ID) != 1 {
				t.Errorf("audit of the rerun: new %d old %d", finished(m.acme.ID), finished(m.primary.ID))
			}
			// Nothing is left: a third run refuses, as it always did for the primary.
			if _, _, err := m.svc.SetPrimaryOrg(m.ctx, m.acme.ID, m.boss.ID); !isInvalid(err) {
				t.Errorf("run after it is finished: %v", err)
			}
		})
	}
}

// A write refused as stale (the record changed under it) is made again on the record as it is now, so the change
// that landed first is kept.
func TestSetPrimaryOrgRetriesStaleWrites(t *testing.T) {
	m := newPrimaryMove(t)
	var mu sync.Mutex
	raced := map[string]bool{}
	m.h.beforeCAS = func(r *store.Record, _ hlc.Timestamp) error {
		mu.Lock()
		defer mu.Unlock()
		if raced[r.ID] || (r.Kind != model.KindOrg && r.Kind != model.KindUser) {
			return nil
		}
		raced[r.ID] = true
		switch r.ID {
		case m.second.ID: // another change of the account lands first, on another node: its tags must survive
			u, err := m.svc.Users.Get(m.ctx, m.second.ID)
			if err != nil {
				return err
			}
			u.Tags = []string{"kept"}
			expect := u.Version
			rec, err := store.Encode(u)
			if err != nil {
				return err
			}
			if err := m.h.Store.CompareAndPut(m.ctx, rec, expect); err != nil {
				return err
			}
		}
		return store.ErrStale
	}
	if _, _, err := m.svc.SetPrimaryOrg(m.ctx, m.acme.ID, m.boss.ID); err != nil {
		t.Fatalf("stale writes were not retried: %v", err)
	}
	m.done()
	if u, _ := m.svc.Users.Get(m.ctx, m.second.ID); !slices.Equal(u.Tags, []string{"kept"}) {
		t.Errorf("the change that landed first was overwritten: %v", u.Tags)
	}
	for _, id := range []string{m.acme.ID, m.primary.ID, m.boss.ID, m.second.ID, m.super.ID} {
		if !raced[id] {
			t.Errorf("no write of %s was refused", id)
		}
	}
}

// A write that stays stale ends the change with an error (and it can be run again).
func TestSetPrimaryOrgGivesUpOnPersistentStale(t *testing.T) {
	m := newPrimaryMove(t)
	m.failOn(model.KindOrg, m.acme.ID, store.ErrStale)
	if _, _, err := m.svc.SetPrimaryOrg(m.ctx, m.acme.ID, m.boss.ID); !errors.Is(err, service.ErrStale) {
		t.Fatalf("persistently stale: %v", err)
	}
	m.h.beforeCAS = nil
	if _, _, err := m.svc.SetPrimaryOrg(m.ctx, m.acme.ID, m.boss.ID); err != nil {
		t.Fatal(err)
	}
	m.done()
}

// Two organizations marked primary (the state between the writes): every service on the store chooses the same, the
// one with the lowest id, and says so at error level.
func TestPrimaryOrgChoosesDeterministicallyWhenTwoAreMarked(t *testing.T) {
	m := newPrimaryMove(t)
	m.failOn(model.KindOrg, m.primary.ID, store.ErrNotWritable) // stops after marking acme
	if _, _, err := m.svc.SetPrimaryOrg(m.ctx, m.acme.ID, m.boss.ID); err == nil {
		t.Fatal("setup")
	}
	m.h.beforeCAS = nil
	want := min(m.acme.ID, m.primary.ID)
	for i := 0; i < 3; i++ {
		other := service.New(m.svc.Cfg, m.svc.Store, m.svc.Sealer) // another node: no cache
		log := newRecLog()
		other.Log = log
		p, err := other.PrimaryOrg(m.ctx)
		if err != nil || p.ID != want {
			t.Fatalf("service %d chose %v %v, want %s", i, p, err, want)
		}
		if !log.has("error more than one organization is marked primary (an interrupted set-primary): using " + p.Name +
			"; run quisora set-primary again for the organization that should be primary to finish it") {
			t.Fatalf("no error logged: %v", *log.entries)
		}
		if again, _ := other.PrimaryOrg(m.ctx); again.ID != want {
			t.Fatal("the choice changed on the second call")
		}
	}
}

// While two organizations are marked primary (an interrupted set-primary), every server chooses the same one, the one
// with the lowest id, whatever it chose before: a server running since the earlier primary and one just started agree.
func TestTwoPrimariesChooseTheSameOnEveryServer(t *testing.T) {
	service.SetPrimaryChoiceTTL(t, 50*time.Millisecond)
	e := newEnv(t)
	first := e.primary
	acme := e.org("acme") // created after the primary: a higher id
	boss := e.user(acme.ID, "boss", model.RoleAdmin)
	if _, _, err := e.svc.SetPrimaryOrg(e.ctx, acme.ID, boss.ID); err != nil {
		t.Fatal(err)
	}
	if p, err := e.svc.PrimaryOrg(e.ctx); err != nil || p.ID != acme.ID {
		t.Fatalf("after set-primary: %+v %v", p, err)
	}
	// set-primary back to the first organization, interrupted after its first write: both are marked primary
	o, err := e.svc.Orgs.Get(e.ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	o.Primary = true
	if err := e.svc.Orgs.Update(e.ctx, o); err != nil {
		t.Fatal(err)
	}
	fresh := service.New(e.svc.Cfg, e.svc.Store, e.svc.Sealer)
	time.Sleep(60 * time.Millisecond) // past the time a server remembers its choice
	for name, svc := range map[string]*service.Service{"running": e.svc, "just started": fresh} {
		if p, err := svc.PrimaryOrg(e.ctx); err != nil || p.ID != min(first.ID, acme.ID) {
			t.Errorf("%s server: %v %v, want the lowest id %s", name, p.ID, err, min(first.ID, acme.ID))
		}
	}
}

// outcomes counts the events of items with outcome o.
func outcomes(items []*model.Audit, o string) int {
	n := 0
	for _, e := range items {
		if e.Outcome == o {
			n++
		}
	}
	return n
}

// A server-wide sign-out counted on the old primary while the change runs (here, just before the old primary is
// unmarked) is not lost when it stops counting: the new primary holds it.
func TestSetPrimaryOrgKeepsASignOutCountedMeanwhile(t *testing.T) {
	m := newPrimaryMove(t)
	before, err := m.svc.SessionStamp(m.ctx, m.acme.ID)
	if err != nil {
		t.Fatal(err)
	}
	m.h.beforeCAS = func(r *store.Record, _ hlc.Timestamp) error {
		if r.Kind != model.KindOrg || r.ID != m.primary.ID {
			return nil
		}
		m.h.beforeCAS = nil // once: the sign-out lands just before the unmark
		o, err := m.svc.Orgs.Get(m.ctx, m.primary.ID)
		if err != nil {
			return err
		}
		o.ServerSignOut.Sessions++
		return m.svc.Orgs.Update(m.ctx, o)
	}
	if _, _, err := m.svc.SetPrimaryOrg(m.ctx, m.acme.ID, m.boss.ID); err != nil {
		t.Fatal(err)
	}
	m.done()
	m.svc.InvalidateSignOut()
	after, err := m.svc.SessionStamp(m.ctx, m.acme.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Server != before.Server+1 {
		t.Fatalf("server sign-out counter %d after the move, want %d: the sign-out counted meanwhile was lost", after.Server, before.Server+1)
	}
}

// A server-wide sign-out that read the old primary just before a set-primary finished is counted on the new one: its
// write is refused as stale, and the copy it reads again is no longer primary.
func TestServerSignOutRacingSetPrimaryCountsOnTheNewPrimary(t *testing.T) {
	m := newPrimaryMove(t)
	before, err := m.svc.SessionStamp(m.ctx, m.acme.ID)
	if err != nil {
		t.Fatal(err)
	}
	m.h.beforeCAS = func(r *store.Record, _ hlc.Timestamp) error {
		if r.Kind != model.KindOrg || r.ID != m.primary.ID {
			return nil
		}
		m.h.beforeCAS = nil // the move runs, whole, just before the sign-out's write
		_, _, err := m.svc.SetPrimaryOrg(m.ctx, m.acme.ID, m.boss.ID)
		return err
	}
	if _, err := m.svc.SignOutServer(m.ctx, actor(m.super), service.SignOutOptions{Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	m.svc.InvalidateSignOut()
	after, err := m.svc.SessionStamp(m.ctx, m.acme.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Server != before.Server+1 {
		t.Fatalf("server sign-out counter %d, want %d: the sign-out was counted on the old primary", after.Server, before.Server+1)
	}
}
