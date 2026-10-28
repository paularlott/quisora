package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// Updates record what changed, old → new (a role change, an email, organization settings), and never a secret.
func TestAuditRecordsChanges(t *testing.T) {
	c := newCast(t)
	admin := service.ActorForUser(c.aAdmin, "192.0.2.1")
	manager := model.RoleManager
	if _, err := c.svc.UpdateUser(c.ctx, admin, c.aUser.ID, service.UserInput{Role: &manager, Email: ptr("new@example.com")}); err != nil {
		t.Fatal(err)
	}
	e := c.lastAudit("user.update")
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
	if _, err := c.svc.UpdateOrg(c.ctx, service.ActorForUser(c.super, "192.0.2.1"), c.a.ID, service.OrgInput{Settings: &st}); err != nil {
		t.Fatal(err)
	}
	if d := c.lastAudit("org.update").Detail; d["changed.settings.require_mfa"] == "" {
		t.Fatalf("org.update detail: %v", d)
	}
}

// Who an audit event names and where it came from: the request that made it, a command's operator, the system itself.
func TestAuditAttribution(t *testing.T) {
	t.Run("request_fields", func(t *testing.T) {
		// Events made for a request carry its id, user agent and session; refusals are recorded as failures.
		c := newCast(t)
		ctx := service.WithRequest(c.ctx, &service.RequestInfo{ID: "req-1", IP: "198.51.100.7", UserAgent: "test-agent",
			SessionID: "sess-1"})
		c.svc.Audit(ctx, &service.Actor{Name: "x"}, c.a.ID, "login.failure", "x", nil)
		e := c.lastAudit("login.failure")
		if e.RequestID != "req-1" || e.UserAgent != "test-agent" || e.SessionID != "sess-1" || e.IP != "198.51.100.7" ||
			e.Outcome != "failure" {
			t.Fatalf("request fields: %+v", e)
		}
	})

	t.Run("command_origin", func(t *testing.T) {
		// A command's events name who ran it, where.
		c := newCast(t)
		c.svc.Origin = service.CommandOrigin("invite")
		c.svc.Audit(c.ctx, service.System, c.a.ID, "user.invite", "x", map[string]string{"k": "v"})
		e := c.lastAudit("user.invite")
		if e.Detail["command"] != "invite" || e.Detail["pid"] == "" || e.Detail["k"] != "v" || e.Actor == "system" {
			t.Fatalf("command fields: actor %q detail %v", e.Actor, e.Detail)
		}
	})

	t.Run("operator_command", func(t *testing.T) {
		// An operator's command carried out by a running node (WithCommand) is recorded as that command, not as the
		// system, with how it was authenticated and the address of the request; the system's own work, and any other
		// actor's, is not touched.
		c := newCast(t)
		ctx := service.WithRequest(service.WithCommand(c.ctx, "sign-out", "request signed with the master key"),
			&service.RequestInfo{ID: "r", IP: "198.51.100.9"})
		c.svc.Audit(ctx, service.System, c.a.ID, "org.signout", "acme", map[string]string{"reason": "drill"})
		e := c.lastAudit("org.signout")
		if e.Actor != "command:sign-out" || e.IP != "198.51.100.9" || e.Detail["command"] != "sign-out" ||
			e.Detail["authenticated"] != "request signed with the master key" || e.Detail["reason"] != "drill" {
			t.Fatalf("a command's event: actor %q ip %q detail %v", e.Actor, e.IP, e.Detail)
		}
		c.svc.Audit(ctx, &service.Actor{Name: "pat"}, c.a.ID, "user.update", "x", nil)
		if e := c.lastAudit("user.update"); e.Actor != "pat" || e.Detail["command"] != "" {
			t.Fatalf("another actor under a command: %q %v", e.Actor, e.Detail)
		}
		c.svc.Audit(c.ctx, service.System, c.a.ID, "keys.create", "k", nil)
		if e := c.lastAudit("keys.create"); e.Actor != "system" || e.Detail["command"] != "" {
			t.Fatalf("the system's own work: %q %v", e.Actor, e.Detail)
		}
	})
}

// A refused API request is audited once a minute per caller and reason, with the reason and the target recorded.
func TestAuditRefusedOncePerCallerAndReason(t *testing.T) {
	e := newEnv(t)
	a := actor(e.super)
	e.svc.AuditRefused(e.ctx, a, "POST", "/api/users", "scope")
	e.svc.AuditRefused(e.ctx, a, "POST", "/api/users", "scope") // rate limited
	e.svc.AuditRefused(e.ctx, a, "GET", "/api/orgs", "role")
	ev := e.audited(e.super.OrgID, "api.request.refused")
	if len(ev) != 2 {
		t.Fatalf("events %d, want 2 (one per reason)", len(ev))
	}
	for _, x := range ev {
		if x.Detail["reason"] == "" || x.Target == "" {
			t.Errorf("event %+v", x)
		}
	}
}

// Every audit event goes to the structured log; one the store cannot keep is logged as an error, not dropped.
func TestAuditEventsReachTheLog(t *testing.T) {
	e := newEnv(t)
	log := newRecLog()
	e.svc.Log = log
	e.svc.Audit(e.ctx, nil, e.primary.ID, "user.update", "pat", map[string]string{"tags": "a"})
	if !log.has("info audit") || log.has("error audit event not stored") {
		t.Fatalf("stored event: %v", *log.entries)
	}
	e.svc.Audits = store.NewTable[model.Audit](&faultStore{Store: e.svc.Store, beforePut: func(r *store.Record) error {
		if r.Kind == model.KindAudit {
			return errors.New("disk full")
		}
		return nil
	}})
	e.svc.Audit(e.ctx, nil, e.primary.ID, "user.delete", "pat", nil)
	if !log.has("error audit event not stored") {
		t.Fatalf("a lost audit event was not logged: %v", *log.entries)
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

func TestAuditTrail(t *testing.T) {
	c := newCast(t)
	u := c.user(c.a.ID, "audited", model.RoleUser)
	_, _ = c.svc.UpdateUser(c.ctx, actor(c.aAdmin), u.ID, service.UserInput{FamilyName: ptr("x")})
	_ = c.svc.DeleteUser(c.ctx, actor(c.aAdmin), u.ID)
	pg, err := c.svc.ListAudit(c.ctx, actor(c.aAdmin), c.a.ID, service.AuditQuery{Limit: 100})
	list, n := pg.Items, pg.Total
	if err != nil || n == 0 {
		t.Fatalf("audit: %v %d", err, n)
	}
	seen := map[string]bool{}
	for _, e := range list {
		seen[e.Action] = true
		if e.Action == "user.delete" && (e.Actor != "aadmin" || e.ActorID != c.aAdmin.ID || e.Target != "audited") {
			t.Errorf("audit entry %+v", e)
		}
	}
	for _, a := range []string{"user.create", "user.update", "user.delete"} {
		if !seen[a] {
			t.Errorf("missing audit action %s", a)
		}
	}
}

// A change whose outcome is not known (it may have been made: the cluster lost the owner mid-write) is returned as
// ErrOutcomeUnknown and still audited, with outcome "unknown"; a change refused with nothing written is not audited.
func TestOutcomeUnknownChangesAreAudited(t *testing.T) {
	// A client write ends as a cluster write whose owner was lost does: made, or not, with fail either way. The write
	// is made first when fail is store.ErrUnconfirmed.
	var fail error
	inner := memstore.New()
	st := &faultStore{Store: inner}
	st.beforePut = func(r *store.Record) error {
		if r.Kind != model.KindClient || fail == nil {
			return nil
		}
		if errors.Is(fail, store.ErrUnconfirmed) {
			_ = inner.Put(context.Background(), r)
		}
		return fail
	}
	st.beforeCAS = func(r *store.Record, expect hlc.Timestamp) error {
		if r.Kind != model.KindClient || fail == nil {
			return nil
		}
		if errors.Is(fail, store.ErrUnconfirmed) {
			_ = inner.CompareAndPut(context.Background(), r, expect)
		}
		return fail
	}
	e := newEnvOn(t, st)
	org := e.org("unknown-outcomes")
	in := func(name string) service.ClientInput {
		return service.ClientInput{Name: &name, RedirectURIs: &[]string{"https://app.example/cb"},
			GrantTypes: &[]string{"authorization_code"}, Scopes: &[]string{"openid"}}
	}

	fail = store.ErrUnavailable
	if _, _, err := e.svc.CreateClient(e.ctx, service.System, org.ID, in("refused")); !errors.Is(err, service.ErrUnavailable) || errors.Is(err, service.ErrOutcomeUnknown) {
		t.Fatalf("a refused write: %v", err)
	}
	if n := len(e.audits("client.create")); n != 0 {
		t.Fatalf("a change refused with nothing written was audited (%d events)", n)
	}

	fail = store.ErrUnconfirmed
	if _, _, err := e.svc.CreateClient(e.ctx, service.System, org.ID, in("unknown")); !errors.Is(err, service.ErrOutcomeUnknown) || !errors.Is(err, service.ErrUnavailable) {
		t.Fatalf("a write whose outcome is not known: %v", err)
	}
	l := e.audits("client.create")
	if len(l) != 1 || l[0].Outcome != service.OutcomeUnknown || l[0].Target != "unknown" {
		t.Fatalf("the change of unknown outcome is not audited as such: %+v", l)
	}

	fail = nil
	if _, _, err := e.svc.CreateClient(e.ctx, service.System, org.ID, in("made")); err != nil {
		t.Fatal(err)
	}
	if l := e.audits("client.create"); len(l) != 2 || l[1].Outcome != "success" {
		t.Fatalf("a change made: %+v", l)
	}
}

// Super admins are invisible below them everywhere, so the audit log leaves out what names one as its actor or target
// for an administrator (here of the primary organization, whose log holds their sign-ins and the changes made to them,
// and of another organization they acted in), and the page and its total agree: nothing says that such events exist.
// Their own and other administrators' events stay, and a super admin sees everything.
func TestAuditLeavesOutSuperAdminsForOthers(t *testing.T) {
	c := newCast(t)
	sup, padmin := actor(c.super), actor(c.pAdmin)
	// a user of organization a with the username of the super admin: unrelated, and seen in full
	namesake, err := c.svc.CreateUser(c.ctx, service.System, c.a.ID, service.UserInput{Username: ptr(c.super.Username),
		GivenName: ptr("Namesake"), Email: ptr("namesake@example.com")})
	if err != nil {
		t.Fatal(err)
	}

	// the first thing every page of the administrator holds: its own events, then the hidden ones among them
	c.svc.Audit(c.ctx, padmin, c.primary.ID, "user.update", "puser", nil)
	for i := 0; i < 3; i++ {
		c.svc.Audit(c.ctx, sup, c.primary.ID, "login.success", c.super.Username, map[string]string{"amr": "pwd otp"})
		c.svc.Audit(c.ctx, padmin, c.primary.ID, "user.update", c.super.Username, nil) // a change targeting a super admin
		c.svc.Audit(c.ctx, padmin, c.primary.ID, "user.update", "pmanager", nil)
	}
	c.svc.Audit(c.ctx, padmin, c.primary.ID, "identity.unlink", c.super.ID, nil) // a target named by id
	c.svc.Audit(c.ctx, sup, c.a.ID, "org.update", "org-a", nil)                  // a super admin acting in organization a
	c.svc.Audit(c.ctx, actor(namesake), c.a.ID, "login.success", namesake.Username, nil)
	c.svc.Audit(c.ctx, actor(c.aAdmin), c.a.ID, "user.update", "auser", nil)

	names := func(p service.AuditPage) (n []string) {
		for _, e := range p.Items {
			n = append(n, e.Actor+" "+e.Action+" "+e.Target)
		}
		return n
	}
	hidden := func(e *model.Audit) bool {
		return e.Actor == c.super.Username && e.OrgID != c.a.ID || e.Target == c.super.Username && e.OrgID != c.a.ID ||
			e.Target == c.super.ID || e.ActorID == c.super.ID
	}

	// each reader of an organization's log against what is read as a super admin
	for _, tc := range []struct {
		name   string
		reader *service.Actor
		org    string
	}{{"primary admin", padmin, c.primary.ID}, {"admin of another organization", actor(c.aAdmin), c.a.ID}} {
		t.Run(tc.name, func(t *testing.T) {
			full, err := c.svc.ListAudit(c.ctx, sup, tc.org, service.AuditQuery{Limit: 500})
			if err != nil {
				t.Fatal(err)
			}
			var want []*model.Audit
			for _, e := range full.Items {
				if !hidden(e) {
					want = append(want, e)
				}
			}
			if len(want) == len(full.Items) {
				t.Fatal("the test made no event to hide")
			}
			pg, err := c.svc.ListAudit(c.ctx, tc.reader, tc.org, service.AuditQuery{Limit: 500})
			if err != nil {
				t.Fatal(err)
			}
			if len(pg.Items) != len(want) || pg.Total != len(want) {
				t.Fatalf("%d events (total %d), want %d: %v", len(pg.Items), pg.Total, len(want), names(pg))
			}
			for i, e := range pg.Items {
				if hidden(e) || e.ID != want[i].ID {
					t.Fatalf("event %d: %+v", i, e)
				}
			}
			// pages of 2, in either order, tile the same list without a gap, and every total is the same
			for _, desc := range []bool{false, true} {
				var ids []string
				for off := 0; ; off += 2 {
					p, err := c.svc.ListAudit(c.ctx, tc.reader, tc.org, service.AuditQuery{Offset: off, Limit: 2, Desc: desc})
					if err != nil || p.Total != len(want) {
						t.Fatalf("page at %d: total %d, err %v", off, p.Total, err)
					}
					if len(p.Items) == 0 {
						break
					}
					for _, e := range p.Items {
						ids = append(ids, e.ID)
					}
				}
				if len(ids) != len(want) {
					t.Fatalf("pages (desc %v) hold %d events, want %d", desc, len(ids), len(want))
				}
			}
		})
	}

	// what is left is theirs and the others'
	pg, _ := c.svc.ListAudit(c.ctx, padmin, c.primary.ID, service.AuditQuery{Limit: 500})
	var own, other bool
	for _, e := range pg.Items {
		own = own || e.Actor == c.pAdmin.Username
	}
	pg, _ = c.svc.ListAudit(c.ctx, actor(c.aAdmin), c.a.ID, service.AuditQuery{Limit: 500})
	for _, e := range pg.Items {
		other = other || e.Actor == namesake.Username && e.Action == "login.success"
	}
	if !own || !other {
		t.Errorf("an event of the reader or of an unrelated user is missing (own %v, same username in another organization %v)", own, other)
	}
	// a search and a filter narrow what is shown, not what is hidden
	if p, _ := c.svc.ListAudit(c.ctx, padmin, c.primary.ID, service.AuditQuery{Search: c.super.Username, Limit: 50}); len(p.Items) != 0 || p.Total != 0 {
		t.Errorf("a search for the super admin finds %d events (total %d)", len(p.Items), p.Total)
	}
	if p, _ := c.svc.ListAudit(c.ctx, padmin, c.primary.ID, service.AuditQuery{Action: "login.success", Limit: 50}); len(p.Items) != 0 || p.Total != 0 {
		t.Errorf("the sign-ins of a super admin: %d events (total %d)", len(p.Items), p.Total)
	}
	// a super admin sees all of it
	if p, _ := c.svc.ListAudit(c.ctx, sup, c.primary.ID, service.AuditQuery{Action: "login.success", Limit: 50}); len(p.Items) != 3 {
		t.Errorf("a super admin sees %d sign-ins, want 3", len(p.Items))
	}
}

// Hidden events are found a read at a time, so more of them than one read holds are all left out, and a reader that is
// not the store (VictoriaLogs, the cluster) is asked for the actor and target it is given.
func TestAuditLeavesOutManyHiddenEventsThroughAnyReader(t *testing.T) {
	c := newCast(t)
	c.svc.AuditReader = storeReader{c}
	for i := 0; i < 1100; i++ {
		c.svc.Audit(c.ctx, actor(c.super), c.primary.ID, "login.success", c.super.Username, nil)
	}
	c.svc.Audit(c.ctx, actor(c.pAdmin), c.primary.ID, "user.update", "puser", nil)
	pg, err := c.svc.ListAudit(c.ctx, actor(c.pAdmin), c.primary.ID, service.AuditQuery{Action: "login.success", Limit: 50})
	if err != nil || len(pg.Items) != 0 || pg.Total != 0 {
		t.Fatalf("sign-ins of a super admin: %d events (total %d), %v", len(pg.Items), pg.Total, err)
	}
	pg, err = c.svc.ListAudit(c.ctx, actor(c.pAdmin), c.primary.ID, service.AuditQuery{Limit: 50})
	if err != nil || pg.Total != len(pg.Items) || len(pg.Items) == 0 {
		t.Fatalf("the rest: %d events (total %d), %v", len(pg.Items), pg.Total, err)
	}
	for _, e := range pg.Items {
		if e.Actor == c.super.Username {
			t.Fatalf("a super admin's event: %+v", e)
		}
	}
}

// storeReader is an AuditReader that answers from the store as the cluster's does: through AuditListQuery.
type storeReader struct{ c *cast }

func (r storeReader) ReadAudit(ctx context.Context, q service.AuditQuery) (service.AuditPage, error) {
	items, total, err := r.c.svc.Audits.List(ctx, service.AuditListQuery(q))
	return service.AuditPage{Items: items, Total: total, Nodes: 1, Answered: 1, Source: "test"}, err
}

// When what a reader may not see cannot be read, the audit log is not shown to them (a super admin, who sees all, needs
// no such read).
func TestAuditFailsClosedWhenTheHiddenUsersCannotBeRead(t *testing.T) {
	c := newCast(t)
	c.svc.Audit(c.ctx, actor(c.super), c.primary.ID, "login.success", c.super.Username, nil)
	c.svc.Users.S = &faultStore{Store: c.svc.Users.S, beforeList: func(kind model.Kind, q store.ListQuery) error {
		return errInjected
	}}
	if pg, err := c.svc.ListAudit(c.ctx, actor(c.pAdmin), c.primary.ID, service.AuditQuery{Limit: 50}); err == nil {
		t.Fatalf("the audit log was shown: %d events", len(pg.Items))
	}
	if pg, err := c.svc.ListAudit(c.ctx, actor(c.super), c.primary.ID, service.AuditQuery{Limit: 50}); err != nil || len(pg.Items) == 0 {
		t.Fatalf("a super admin: %d events, %v", len(pg.Items), err)
	}
}
