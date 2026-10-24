package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/kvstore"
)

// Disabling and enabling an account record who, when and why on the user (the latest change); a password set or
// removed records when.
func TestUserLifecycleFacts(t *testing.T) {
	e := newEnv(t)
	o := e.org("acme")
	admin := e.user(o.ID, "boss", model.RoleAdmin)
	u := e.user(o.ID, "pat", model.RoleUser)
	if u.StatusChanged != nil || u.PasswordChangedAt != nil || u.MFAEnrolledAt != nil {
		t.Fatalf("new user has lifecycle facts: %+v", u)
	}
	before := time.Now().Add(-time.Second)
	off := false
	got, err := e.svc.UpdateUser(e.ctx, actor(admin), u.ID, service.UserInput{Active: &off, StatusReason: ptr("  Left the company  ")})
	if err != nil {
		t.Fatal(err)
	}
	sc := got.StatusChanged
	if sc == nil || sc.By != "boss" || sc.ByID != admin.ID || sc.Reason != "Left the company" || sc.At.Before(before) {
		t.Fatalf("disabled: %+v", sc)
	}
	// An edit that does not change the status keeps the record (and ignores a reason).
	got, err = e.svc.UpdateUser(e.ctx, actor(admin), u.ID, service.UserInput{FamilyName: ptr("Lee"), StatusReason: ptr("ignored")})
	if err != nil || got.StatusChanged.Reason != "Left the company" {
		t.Fatalf("unrelated edit: %+v %v", got.StatusChanged, err)
	}
	on := true
	got, err = e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Active: &on})
	if err != nil || got.StatusChanged.By != "system" || got.StatusChanged.Reason != "" || !got.Active {
		t.Fatalf("enabled: %+v %v", got.StatusChanged, err)
	}
	long := make([]byte, model.MaxStatusReason+1)
	for i := range long {
		long[i] = 'x'
	}
	if _, err := e.svc.UpdateUser(e.ctx, actor(admin), u.ID, service.UserInput{Active: &off, StatusReason: ptr(string(long))}); !errors.As(err, new(*service.FieldError)) {
		t.Fatalf("over-long reason: %v", err)
	}

	pw := "a long enough password"
	got, err = e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Password: &pw})
	if err != nil || got.PasswordChangedAt == nil || got.PasswordChangedAt.Before(before) {
		t.Fatalf("password set: %v %v", got.PasswordChangedAt, err)
	}
	set := *got.PasswordChangedAt
	time.Sleep(5 * time.Millisecond)
	if err := e.svc.RemovePassword(e.ctx, actor(admin), u.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.svc.Users.Get(e.ctx, u.ID); got.PasswordChangedAt == nil || !got.PasswordChangedAt.After(set) {
		t.Fatalf("password removed: %v", got.PasswordChangedAt)
	}
}

// The end-date sweep records itself and its reason.
func TestExpireUsersRecordsReason(t *testing.T) {
	e := newEnv(t)
	o := e.org("acme")
	u := e.user(o.ID, "gone", model.RoleUser)
	past := time.Now().Add(-time.Minute)
	u.ValidUntil = &past
	if err := e.svc.Users.Update(e.ctx, u); err != nil {
		t.Fatal(err)
	}
	if n, err := e.svc.ExpireUsers(e.ctx); err != nil || n != 1 {
		t.Fatalf("expired %d %v", n, err)
	}
	got, _ := e.svc.Users.Get(e.ctx, u.ID)
	if got.StatusChanged == nil || got.StatusChanged.By != "system" || got.StatusChanged.Reason != "The end date was reached." {
		t.Fatalf("sweep: %+v", got.StatusChanged)
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

// The audit log: an organization's administrators read their own organization's events only; every organization
// at once is for super admins. Sorting by action and searching work through the same query.
func TestAuditAccessAndQuery(t *testing.T) {
	c := newCast(t)
	c.svc.Audit(c.ctx, actor(c.aAdmin), c.a.ID, "user.update", "alpha", nil)
	c.svc.Audit(c.ctx, actor(c.aAdmin), c.a.ID, "group.create", "beta", nil)
	c.svc.Audit(c.ctx, actor(c.bAdmin), c.b.ID, "user.delete", "gamma", nil)

	pg, err := c.svc.ListAudit(c.ctx, actor(c.aAdmin), c.a.ID, service.AuditQuery{Limit: 50})
	if err != nil || pg.Source != "store" {
		t.Fatal(pg, err)
	}
	for _, e := range pg.Items {
		if e.OrgID != c.a.ID {
			t.Fatalf("an event of another organization: %+v", e)
		}
	}
	if _, err := c.svc.ListAudit(c.ctx, actor(c.aAdmin), c.b.ID, service.AuditQuery{}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("admin of a reads b: %v", err)
	}
	if _, err := c.svc.ListAudit(c.ctx, actor(c.aAdmin), "", service.AuditQuery{}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("admin reads every organization: %v", err)
	}
	all, err := c.svc.ListAudit(c.ctx, actor(c.super), "", service.AuditQuery{Search: "GAMMA", Limit: 50})
	if err != nil || len(all.Items) != 1 || all.Items[0].OrgID != c.b.ID {
		t.Fatalf("super admin search across organizations: %+v %v", all, err)
	}
	sorted, _ := c.svc.ListAudit(c.ctx, actor(c.super), c.a.ID, service.AuditQuery{Sort: "action", Limit: 50})
	for i := 1; i < len(sorted.Items); i++ {
		if sorted.Items[i-1].Action > sorted.Items[i].Action {
			t.Fatalf("not sorted by action: %v then %v", sorted.Items[i-1].Action, sorted.Items[i].Action)
		}
	}
	// the retention is a week unless configured: events expire then
	if e := pg.Items[0]; e.Expires.Before(e.Created.Add(6*24*time.Hour)) || e.Expires.After(e.Created.Add(8*24*time.Hour)) {
		t.Fatalf("expiry %v for an event at %v", e.Expires, e.Created)
	}
}

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
		"already primary": {e.primary.ID, stranger.ID},
		"user elsewhere":  {acme.ID, stranger.ID},
		"user disabled":   {acme.ID, off.ID},
	} {
		if _, _, err := e.svc.SetPrimaryOrg(e.ctx, tc.org, tc.user); !errors.As(err, new(*service.FieldError)) {
			t.Errorf("%s: %v", name, err)
		}
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
	// the old primary can now be deleted like any organization; the new one cannot
	if err := e.svc.DeleteOrg(e.ctx, service.System, acme.ID, true); !errors.Is(err, service.ErrPrimaryOrg) {
		t.Fatalf("deleting the new primary: %v", err)
	}
}

// noUserScan fails any query that would read every user (a filtered list of the whole kind): on a key-value store
// that decodes all of them.
type noUserScan struct{ *kvstore.Store }

func (s noUserScan) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if kind == model.KindUser && q.Scope == "" && len(q.Filters) > 0 {
		return nil, errors.New("read every user")
	}
	return s.Store.List(ctx, kind, q)
}

// On a key-value store the end-date sweep reads the due index, never the whole user kind (5M users every minute).
func TestExpireUsersUsesDueIndex(t *testing.T) {
	kv, err := kvstore.OpenBadger(context.Background(), t.TempDir(), kvstore.BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { kv.Close() })
	e := newEnvOn(t, noUserScan{kv})
	o := e.org("acme")
	gone := e.user(o.ID, "gone", model.RoleUser)
	stays := e.user(o.ID, "stays", model.RoleUser)
	past, future := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	gone.ValidUntil, stays.ValidUntil = &past, &future
	for _, u := range []*model.User{gone, stays} {
		if err := e.svc.Users.Update(e.ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := e.svc.ExpireUsers(e.ctx); err != nil || n != 1 {
		t.Fatalf("expired %d %v", n, err)
	}
	if g, _ := e.svc.Users.Get(e.ctx, gone.ID); g.Active {
		t.Fatal("the user past their end date is still active")
	}
	if g, _ := e.svc.Users.Get(e.ctx, stays.ID); !g.Active {
		t.Fatal("a user before their end date was disabled")
	}
	if n, err := e.svc.ExpireUsers(e.ctx); err != nil || n != 0 {
		t.Fatalf("second sweep: %d %v", n, err)
	}
}
