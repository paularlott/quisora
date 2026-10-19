package service_test

import (
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Language, time zone, user type, end date and work details: normalised, validated, and the manager kept within the
// organization and free of loops; a user cannot set their own work details or end date; deleting a manager clears
// it on their reports.
func TestProfileFields(t *testing.T) {
	e := newEnv(t)
	o := e.org("acme")
	boss := e.user(o.ID, "boss", model.RoleUser)
	pat := e.user(o.ID, "pat", model.RoleUser)
	other := e.user(e.org("other").ID, "x", model.RoleUser)

	u, err := e.svc.UpdateUser(e.ctx, service.System, pat.ID, service.UserInput{Locale: ptr("en_gb"), ZoneInfo: ptr("Europe/London"),
		UserType: ptr("contractor"), ValidUntil: ptr("2099-01-31"), Work: &service.WorkInput{Title: ptr("Engineer"),
			Department: ptr("QA"), EmployeeNumber: ptr("E-17"), ManagerID: &boss.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if u.Locale != "en-GB" || u.ZoneInfo != "Europe/London" || u.UserType != "contractor" || u.ValidUntil == nil ||
		!u.ValidUntil.Equal(time.Date(2099, 1, 31, 0, 0, 0, 0, time.UTC)) || u.Work.Department != "QA" || u.Work.ManagerID != boss.ID {
		t.Fatalf("stored %+v", u)
	}
	for name, in := range map[string]service.UserInput{
		"locale":            {Locale: ptr("not a tag!")},
		"zoneinfo":          {ZoneInfo: ptr("Mars/Olympus")},
		"local zone":        {ZoneInfo: ptr("Local")},
		"valid_until":       {ValidUntil: ptr("next tuesday")},
		"manager elsewhere": {Work: &service.WorkInput{ManagerID: &other.ID}},
		"own manager":       {Work: &service.WorkInput{ManagerID: &pat.ID}},
	} {
		if _, err := e.svc.UpdateUser(e.ctx, service.System, pat.ID, in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a loop: boss reporting to pat, who reports to boss
	if _, err := e.svc.UpdateUser(e.ctx, service.System, boss.ID, service.UserInput{Work: &service.WorkInput{ManagerID: &pat.ID}}); err == nil {
		t.Error("a reporting loop was accepted")
	}
	// clearing
	if u, err = e.svc.UpdateUser(e.ctx, service.System, pat.ID, service.UserInput{Locale: ptr(""), ValidUntil: ptr("")}); err != nil || u.Locale != "" || u.ValidUntil != nil {
		t.Fatalf("clear: %+v %v", u, err)
	}
	// own details are the administrator's
	self := service.ActorForUser(pat, "")
	if _, err := e.svc.UpdateUser(e.ctx, self, pat.ID, service.UserInput{Work: &service.WorkInput{Title: ptr("CEO")}}); err == nil {
		t.Error("a user changed their own work details")
	}
	if _, err := e.svc.UpdateUser(e.ctx, self, pat.ID, service.UserInput{ZoneInfo: ptr("Asia/Tokyo")}); err != nil {
		t.Errorf("own time zone: %v", err)
	}
	// deleting the manager clears it
	if err := e.svc.DeleteUser(e.ctx, service.System, boss.ID); err != nil {
		t.Fatal(err)
	}
	if u, _ := e.svc.Users.Get(e.ctx, pat.ID); u.Work.ManagerID != "" {
		t.Fatal("a deleted manager is still referenced")
	}
}

// Past their end date a user is not enabled at once; the sweep disables them (ending sessions) and leaves others.
func TestExpireUsers(t *testing.T) {
	e := newEnv(t)
	o := e.org("acme")
	gone := e.user(o.ID, "gone", model.RoleUser)
	later := e.user(o.ID, "later", model.RoleUser)
	stays := e.user(o.ID, "stays", model.RoleUser)
	past, future := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	for id, at := range map[string]time.Time{gone.ID: past, later.ID: future} {
		u, _ := e.svc.Users.Get(e.ctx, id)
		u.ValidUntil = &at
		if err := e.svc.Users.Update(e.ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.svc.Sessions.Create(e.ctx, &model.Session{Meta: model.Meta{ID: "s-gone"}, UserID: gone.ID, OrgID: o.ID,
		Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if u, _ := e.svc.Users.Get(e.ctx, gone.ID); u.Enabled(time.Now()) || !u.Active {
		t.Fatal("past the end date: active, but not enabled, before the sweep")
	}
	n, err := e.svc.ExpireUsers(e.ctx)
	if err != nil || n != 1 {
		t.Fatalf("expired %d (%v), want 1", n, err)
	}
	for id, want := range map[string]bool{gone.ID: false, later.ID: true, stays.ID: true} {
		if u, _ := e.svc.Users.Get(e.ctx, id); u.Active != want {
			t.Errorf("%s active=%v, want %v", u.Username, u.Active, want)
		}
	}
	if s, _ := e.svc.Sessions.All(e.ctx, gone.ID); len(s) != 0 {
		t.Fatal("the expired user's sessions survived")
	}
}
