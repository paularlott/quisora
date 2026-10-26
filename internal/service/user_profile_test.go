package service_test

import (
	"errors"
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

// Phone numbers are kept in E.164 form; a changed number is unverified unless set otherwise, and users cannot mark
// their own number verified.
func TestPhoneNumber(t *testing.T) {
	for in, want := range map[string]string{"+44 20 7946 0958": "+442079460958",
		"+1.415.555.0100": "+14155550100", "": "", "020 7946 0958": "", "+0123456789": "", "+12": ""} {
		got, err := service.NormalizePhone(in)
		if (want == "" && in != "") != (err != nil) || got != want {
			t.Errorf("NormalizePhone(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	e := newEnv(t)
	o := e.org("acme")
	admin := e.user(o.ID, "boss", model.RoleAdmin)
	u := e.user(o.ID, "pat", model.RoleUser)
	got, err := e.svc.UpdateUser(e.ctx, actor(admin), u.ID, service.UserInput{Phone: ptr("+44 20 7946 0958"), PhoneVerified: ptr(true)})
	if err != nil || got.PhoneNumber != "+442079460958" || !got.PhoneVerified {
		t.Fatalf("admin set: %+v %v", got, err)
	}
	if _, err := e.svc.UpdateUser(e.ctx, actor(admin), u.ID, service.UserInput{PhoneVerified: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.UpdateUser(e.ctx, actor(u), u.ID, service.UserInput{PhoneVerified: ptr(true)}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("self-verify: %v", err)
	}
	got, err = e.svc.UpdateUser(e.ctx, actor(u), u.ID, service.UserInput{Phone: ptr("+1 415 555 0100")})
	if err != nil || got.PhoneNumber != "+14155550100" || got.PhoneVerified {
		t.Fatalf("self change: %+v %v", got, err)
	}
	if _, err := e.svc.UpdateUser(e.ctx, actor(u), u.ID, service.UserInput{Phone: ptr("12345")}); err == nil {
		t.Fatal("a short local number was accepted")
	}
	got, err = e.svc.UpdateUser(e.ctx, actor(admin), u.ID, service.UserInput{Phone: ptr(""), PhoneVerified: ptr(true)})
	if err != nil || got.PhoneNumber != "" || got.PhoneVerified {
		t.Fatalf("cleared: %+v %v", got, err)
	}
}

func TestFullNameAndGivenNameRequired(t *testing.T) {
	c := newCast(t)
	adm := actor(c.aAdmin)
	if _, err := c.svc.CreateUser(c.ctx, adm, c.a.ID, service.UserInput{Email: ptr("noname@example.org")}); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("create without a first name: %v", err)
	}
	empty := " "
	if _, err := c.svc.UpdateUser(c.ctx, adm, c.aUser.ID, service.UserInput{GivenName: &empty}); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("clearing the first name: %v", err)
	}
	u, err := c.svc.CreateUser(c.ctx, adm, c.a.ID, service.UserInput{Email: ptr("one@example.org"), GivenName: ptr("Cher")})
	if err != nil || u.FullName() != "Cher" {
		t.Fatalf("single name: %v %q", err, u.FullName())
	}
	u, _ = c.svc.UpdateUser(c.ctx, adm, u.ID, service.UserInput{FamilyName: ptr("Sarkisian")})
	if u.FullName() != "Cher Sarkisian" {
		t.Fatal(u.FullName())
	}
	if (&model.User{Username: "u", Email: "e@x.test"}).FullName() != "u" || (&model.User{Email: "e@x.test"}).FullName() != "e@x.test" {
		t.Fatal("full name fallbacks")
	}
}
