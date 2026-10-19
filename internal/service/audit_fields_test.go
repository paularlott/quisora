package service_test

import (
	"context"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func lastAudit(t *testing.T, c *cast, action string) *model.Audit {
	t.Helper()
	l, _, err := c.svc.Audits.List(context.Background(), store.ListQuery{})
	if err != nil {
		t.Fatal(err)
	}
	var out *model.Audit
	for _, a := range l {
		if a.Action == action && (out == nil || !a.Created.Before(out.Created)) {
			out = a
		}
	}
	if out == nil {
		t.Fatalf("no %s event", action)
	}
	return out
}

// Updates record what changed, old → new (a role change, an email, organization settings), and never a secret.
func TestAuditRecordsChanges(t *testing.T) {
	c := newCast(t)
	admin := service.ActorForUser(c.aAdmin, "192.0.2.1")
	manager := model.RoleManager
	if _, err := c.svc.UpdateUser(c.ctx, admin, c.aUser.ID, service.UserInput{Role: &manager, Email: ptr("new@example.com")}); err != nil {
		t.Fatal(err)
	}
	e := lastAudit(t, c, "user.update")
	if e.Detail["changed.role"] != "user → manager" || e.Detail["changed.email"] != "auser@example.com → new@example.com" {
		t.Fatalf("user.update detail: %v", e.Detail)
	}
	if e.Outcome != "success" || e.IP != "192.0.2.1" {
		t.Fatalf("fields: %+v", e)
	}
	for k := range e.Detail {
		if k == "changed.password_hash" || k == "changed.totp_secret" {
			t.Fatalf("a secret in the audit detail: %s", k)
		}
	}

	o, _ := c.svc.Orgs.Get(c.ctx, c.a.ID)
	st := o.Settings
	st.RequireMFA = !st.RequireMFA
	if _, err := c.svc.UpdateOrg(c.ctx, admin, c.a.ID, service.OrgInput{Settings: &st}); err != nil {
		t.Fatal(err)
	}
	if d := lastAudit(t, c, "org.update").Detail; d["changed.settings.require_mfa"] == "" {
		t.Fatalf("org.update detail: %v", d)
	}
}

// Events made for a request carry its id, user agent and session; refusals are recorded as failures; a command's
// events name who ran it, where.
func TestAuditRequestAndCommandFields(t *testing.T) {
	c := newCast(t)
	ctx := service.WithRequest(c.ctx, &service.RequestInfo{ID: "req-1", IP: "198.51.100.7", UserAgent: "test-agent",
		SessionID: "sess-1"})
	c.svc.Audit(ctx, &service.Actor{Name: "x"}, c.a.ID, "login.failure", "x", nil)
	e := lastAudit(t, c, "login.failure")
	if e.RequestID != "req-1" || e.UserAgent != "test-agent" || e.SessionID != "sess-1" || e.IP != "198.51.100.7" ||
		e.Outcome != "failure" {
		t.Fatalf("request fields: %+v", e)
	}

	c.svc.Origin = service.CommandOrigin("invite")
	c.svc.Audit(c.ctx, service.System, c.a.ID, "user.invite", "x", map[string]string{"k": "v"})
	e = lastAudit(t, c, "user.invite")
	if e.Detail["command"] != "invite" || e.Detail["pid"] == "" || e.Detail["k"] != "v" || e.Actor == "system" {
		t.Fatalf("command fields: actor %q detail %v", e.Actor, e.Detail)
	}
}

// An organization's session lifetimes stay within the server's; the primary organization's sign-in settings are
// changed by super admins only (its admins may still rename it).
func TestOrgSessionSettingsAndPrimary(t *testing.T) {
	c := newCast(t)
	aAdmin := service.ActorForUser(c.aAdmin, "")
	too := model.OrgSettings{PasswordLogin: true, SessionTTL: c.svc.Cfg.Session.TTL + 1}
	if _, err := c.svc.UpdateOrg(c.ctx, aAdmin, c.a.ID, service.OrgInput{Settings: &too}); err == nil {
		t.Fatal("a session lifetime above the server's was accepted")
	}
	ok := model.OrgSettings{PasswordLogin: true, SessionTTL: 3600}
	if _, err := c.svc.UpdateOrg(c.ctx, aAdmin, c.a.ID, service.OrgInput{Settings: &ok}); err != nil {
		t.Fatal(err)
	}

	pAdmin := service.ActorForUser(c.pAdmin, "")
	st := c.primary.Settings
	st.RequireMFA = !st.RequireMFA
	if _, err := c.svc.UpdateOrg(c.ctx, pAdmin, c.primary.ID, service.OrgInput{Settings: &st}); err == nil {
		t.Fatal("a primary-org admin changed its sign-in settings")
	}
	same := c.primary.Settings
	if _, err := c.svc.UpdateOrg(c.ctx, pAdmin, c.primary.ID, service.OrgInput{DisplayName: ptr("Main"), Settings: &same}); err != nil {
		t.Fatalf("a primary-org admin renaming it: %v", err)
	}
	if _, err := c.svc.UpdateOrg(c.ctx, service.ActorForUser(c.super, ""), c.primary.ID, service.OrgInput{Settings: &st}); err != nil {
		t.Fatalf("a super admin: %v", err)
	}
}
