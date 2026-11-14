package service_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
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

// An audit event's detail is bounded: each value at 4 KiB and all of them at 16 KiB, a clipped value marked, and the
// clipped keys named with their full length and digest in the event's own "clipped" detail, which a caller cannot set.
// The caller's map is left as it was.
func TestAuditDetailClipped(t *testing.T) {
	e := newEnv(t)
	long, other := strings.Repeat("a", 10_000), strings.Repeat("b", 3_000)
	detail := map[string]string{"redirect_uris": long, "clipped": "nothing", "short": "kept"}
	for i := range 6 {
		detail["other"+strconv.Itoa(i)] = other
	}
	e.svc.Audit(e.ctx, nil, e.primary.ID, "client.self_register", "app", detail)
	ev := e.audited(e.primary.ID, "client.self_register")
	if len(ev) != 1 {
		t.Fatalf("events %d", len(ev))
	}
	d := ev[0].Detail
	size := 0
	for k, v := range d {
		size += len(k) + len(v)
	}
	if size > 16<<10 || len(d["redirect_uris"]) > 4<<10 || !strings.HasSuffix(d["redirect_uris"], "…") || d["short"] != "kept" {
		t.Fatalf("detail not bounded: %d bytes, redirect_uris %d", size, len(d["redirect_uris"]))
	}
	if !strings.Contains(d["clipped"], "redirect_uris (10000 bytes, sha256 ") || !strings.Contains(d["clipped"], "other") {
		t.Fatalf("clipped values not named: %q", d["clipped"])
	}
	if len(detail["redirect_uris"]) != 10_000 || detail["clipped"] != "nothing" {
		t.Fatal("the caller's detail was changed")
	}
	e.svc.Audit(e.ctx, nil, e.primary.ID, "client.update", "app", map[string]string{"name": "x"})
	if d := e.audited(e.primary.ID, "client.update")[0].Detail; len(d) != 1 || d["name"] != "x" {
		t.Fatalf("a small detail changed: %v", d)
	}
}

// The "clipped" detail is the writer's alone, whether or not it clips anything: one a caller set (from whatever a
// request sent) is removed from an event with nothing clipped too, where it would read as the writer's own account of
// values cut that never were. The caller's map is left as it was.
func TestAuditClippedDetailNeverTheCallers(t *testing.T) {
	e := newEnv(t)
	detail := map[string]string{"name": "x", "clipped": "redirect_uris (10000 bytes, sha256 0123456789abcdef)"}
	e.svc.Audit(e.ctx, nil, e.primary.ID, "client.update", "app", detail)
	d := e.audited(e.primary.ID, "client.update")[0].Detail
	if _, set := d["clipped"]; set || d["name"] != "x" || len(d) != 1 {
		t.Fatalf("an event with nothing clipped: %v", d)
	}
	if detail["clipped"] == "" {
		t.Fatal("the caller's detail was changed")
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
	// the retention is 90 days unless configured: events expire then
	if e := pg.Items[0]; e.Expires.Before(e.Created.Add(89*24*time.Hour)) || e.Expires.After(e.Created.Add(91*24*time.Hour)) {
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
		if e.Action == "user.delete" && (e.Actor != "aadmin" || e.ActorID != c.aAdmin.ID || e.Target != "audited" || e.TargetID != u.ID) {
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

// Super admins are invisible below them everywhere, so the audit log leaves out the events that name one as their actor
// or target user (here of the primary organization, whose log holds their sign-ins and the changes made to them, and
// of another organization they acted in) for an administrator, and the page and its total agree: nothing says that
// such events exist. Their own and other administrators' events stay, and a super admin sees everything.
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
	c.svc.AuditUser(c.ctx, padmin, c.pUser, "user.update", nil)
	for i := 0; i < 3; i++ {
		c.svc.AuditUser(c.ctx, sup, c.super, "login.success", map[string]string{"amr": "pwd otp"})
		c.svc.AuditUser(c.ctx, padmin, c.super, "user.update", nil) // a change targeting a super admin
		c.svc.AuditUser(c.ctx, padmin, c.pManager, "user.update", nil)
	}
	// a target known by its id only
	c.svc.AuditUser(c.ctx, padmin, c.svc.AuditTargetUser(c.ctx, c.primary.ID, c.super.ID), "identity.unlink", nil)
	c.svc.Audit(c.ctx, sup, c.a.ID, "org.update", "org-a", nil) // a super admin acting in organization a
	c.svc.AuditUser(c.ctx, actor(namesake), namesake, "login.success", nil)
	c.svc.AuditUser(c.ctx, actor(c.aAdmin), c.aUser, "user.update", nil)

	names := func(p service.AuditPage) (n []string) {
		for _, e := range p.Items {
			n = append(n, e.Actor+" "+e.Action+" "+e.Target)
		}
		return n
	}
	hidden := func(e *model.Audit) bool { return e.ActorID == c.super.ID || e.TargetID == c.super.ID }

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

// A renamed super admin's past stays hidden: what hides an event is recorded on it when it is written, not looked up
// by the name its users have now. Among the events is the one that made them (bootstrap: the system's, naming them by
// their first username), and the total counts only what is shown.
func TestAuditHidesARenamedSuperAdminsPast(t *testing.T) {
	c := newCast(t)
	sup, padmin := actor(c.super), actor(c.pAdmin)
	first := c.super.Username
	if _, err := c.svc.UpdateUser(c.ctx, sup, c.pUser.ID, service.UserInput{FamilyName: ptr("Changed")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.UpdateUser(c.ctx, sup, c.super.ID, service.UserInput{Username: ptr("renamed")}); err != nil {
		t.Fatal(err)
	}
	names := func(e *model.Audit) bool {
		return e.ActorID == c.super.ID || e.Actor == first || e.Target == first || e.Target == "renamed" || e.Target == c.super.ID
	}
	all, err := c.svc.ListAudit(c.ctx, sup, c.primary.ID, service.AuditQuery{Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	seen, bootstrap := 0, false
	for _, e := range all.Items {
		if !names(e) {
			seen++
		}
		bootstrap = bootstrap || e.Action == "bootstrap" && e.Target == first
	}
	if !bootstrap || seen == len(all.Items) {
		t.Fatalf("the super admin's events: bootstrap %v, %d of %d not theirs", bootstrap, seen, len(all.Items))
	}
	pg, err := c.svc.ListAudit(c.ctx, padmin, c.primary.ID, service.AuditQuery{Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range pg.Items {
		if names(e) {
			t.Errorf("an event of the renamed super admin: %s %s %s", e.Actor, e.Action, e.Target)
		}
	}
	if len(pg.Items) != seen || pg.Total != seen {
		t.Fatalf("%d events (total %d), want %d", len(pg.Items), pg.Total, seen)
	}
}

// What hides an event is decided when it is written. A plain user's events stay in view after they are made a super
// admin: they were seen then, and the audit log is never rewritten. From the promotion on (the promotion included,
// a super admin's doing) their events are hidden.
func TestAuditVisibilityIsDecidedWhenWritten(t *testing.T) {
	c := newCast(t)
	sup, padmin := actor(c.super), actor(c.pAdmin)
	c.svc.AuditUser(c.ctx, actor(c.pUser), c.pUser, "login.success", nil)
	if _, err := c.svc.UpdateUser(c.ctx, sup, c.pUser.ID, service.UserInput{Role: ptr(model.RoleSuperAdmin)}); err != nil {
		t.Fatal(err)
	}
	promoted, err := c.svc.Users.Get(c.ctx, c.pUser.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.svc.AuditUser(c.ctx, actor(promoted), promoted, "login.success", nil)
	pg, err := c.svc.ListAudit(c.ctx, padmin, c.primary.ID, service.AuditQuery{Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	var before, after, promotion int
	for _, e := range pg.Items {
		switch {
		case e.Action == "login.success" && e.TargetID == c.pUser.ID && e.SuperAdmin:
			after++
		case e.Action == "login.success" && e.TargetID == c.pUser.ID:
			before++
		case e.Action == "user.update" && e.TargetID == c.pUser.ID:
			promotion++
		}
	}
	if before != 1 || after != 0 || promotion != 0 || pg.Total != len(pg.Items) {
		t.Fatalf("sign-ins as a user %d, as a super admin %d, the promotion %d (%d events, total %d)", before, after,
			promotion, len(pg.Items), pg.Total)
	}
}

// An event whose target is known only by an id that cannot be read is taken for a super admin's: it is never shown
// below them on a guess. One whose user does not exist is named by the id, and shown.
func TestAuditTargetThatCannotBeReadIsHidden(t *testing.T) {
	c := newCast(t)
	gone := model.NewID()
	c.svc.AuditUser(c.ctx, service.System, c.svc.AuditTargetUser(c.ctx, c.primary.ID, gone), "identity.unlink", nil)
	c.svc.Users.S = &faultStore{Store: c.svc.Users.S, beforeGet: func(model.Kind, string) error { return errInjected }}
	c.svc.AuditUser(c.ctx, service.System, c.svc.AuditTargetUser(c.ctx, c.primary.ID, c.pUser.ID), "identity.unlink", nil)
	pg, err := c.svc.ListAudit(c.ctx, actor(c.pAdmin), c.primary.ID, service.AuditQuery{Action: "identity.unlink", Limit: 50})
	if err != nil || len(pg.Items) != 1 || pg.Total != 1 || pg.Items[0].Target != gone || pg.Items[0].TargetID != gone {
		t.Fatalf("%+v, %v", pg, err)
	}
	if pg, _ := c.svc.ListAudit(c.ctx, actor(c.super), c.primary.ID, service.AuditQuery{Action: "identity.unlink", Limit: 50}); pg.Total != 2 {
		t.Fatalf("a super admin sees %d events, want 2", pg.Total)
	}
}

// An audit page below super admins reads the page, however many events it leaves out, and nothing else: the store is
// asked for the page with the filter that leaves them out (model.Audit.SuperAdmin), not for the users to hide nor for
// their events first.
func TestAuditPageReadsOnlyThePage(t *testing.T) {
	c := newCast(t)
	for range 1000 {
		c.svc.Audit(c.ctx, actor(c.super), c.primary.ID, "login.success", c.super.Username, nil)
	}
	for range 20 {
		c.svc.Audit(c.ctx, actor(c.pAdmin), c.primary.ID, "user.update", "puser", nil)
	}
	all, err := c.svc.ListAudit(c.ctx, actor(c.super), c.primary.ID, service.AuditQuery{Limit: 2000})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range all.Items {
		if e.ActorID != c.super.ID && e.Target != c.super.Username {
			seen++
		}
	}
	cs := &countingStore{Store: c.svc.Audits.S, rows: map[model.Kind]int{}}
	c.svc.Audits.S, c.svc.Users.S = cs, cs
	for _, reader := range []service.AuditReader{nil, storeReader{c}} { // this node's store, and a reader given the query
		c.svc.AuditReader = reader
		clear(cs.rows)
		pg, err := c.svc.ListAudit(c.ctx, actor(c.pAdmin), c.primary.ID, service.AuditQuery{Limit: 10})
		if err != nil || len(pg.Items) != 10 || pg.Total != seen {
			t.Fatalf("%d events (total %d, want %d), %v", len(pg.Items), pg.Total, seen, err)
		}
		for _, e := range pg.Items {
			if e.ActorID == c.super.ID {
				t.Fatalf("a super admin's event: %+v", e)
			}
		}
		if cs.rows[model.KindAudit] > 10 || len(cs.rows) > 1 {
			t.Fatalf("a page of 10 read %v", cs.rows)
		}
	}
}

// An audit page counts the matching events up to 10,000 and then says there are more (AuditPage.More): an exact
// total would read the whole retained log on every page. A page past the bound counts to its own end, so the next is
// offered while there are more; the last page's total is exact again.
func TestAuditTotalStopsAtTheBound(t *testing.T) {
	c := newCast(t)
	before, err := c.svc.ListAudit(c.ctx, actor(c.aAdmin), c.a.ID, service.AuditQuery{Limit: 10})
	if err != nil || before.More {
		t.Fatal(before, err)
	}
	const n = 10050
	for i := range n {
		e := &model.Audit{OrgID: c.a.ID, Action: "login.success", Actor: "u" + strconv.Itoa(i), Outcome: "success",
			Expires: time.Now().Add(time.Hour)}
		if err := c.svc.Audits.Put(c.ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	all := before.Total + n
	for _, reader := range []service.AuditReader{nil, storeReader{c}} { // this node's store, and a reader given the query
		c.svc.AuditReader = reader
		for _, tc := range []struct {
			offset, limit, total int
			more                 bool
		}{
			{0, 10, 10000, true},
			{9990, 50, 10040, true}, // past the bound: counted to the page's end, and more after it
			{all - 5, 50, all, false},
		} {
			pg, err := c.svc.ListAudit(c.ctx, actor(c.aAdmin), c.a.ID, service.AuditQuery{Offset: tc.offset, Limit: tc.limit})
			if err != nil || pg.Total != tc.total || pg.More != tc.more || len(pg.Items) != min(tc.limit, all-tc.offset) {
				t.Fatalf("offset %d: %d events, total %d more %v; want total %d more %v (%v)", tc.offset, len(pg.Items),
					pg.Total, pg.More, tc.total, tc.more, err)
			}
		}
	}
}

// countingStore counts the records each kind's listings and reads return.
type countingStore struct {
	store.Store
	mu   sync.Mutex
	rows map[model.Kind]int
}

func (s *countingStore) count(kind model.Kind, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[kind] += n
}

func (s *countingStore) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	res, err := s.Store.List(ctx, kind, q)
	if err == nil {
		s.count(kind, len(res.Records))
	}
	return res, err
}

func (s *countingStore) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	r, err := s.Store.Get(ctx, kind, id)
	if err == nil {
		s.count(kind, 1)
	}
	return r, err
}

// storeReader is an AuditReader that answers from the store as the cluster's does: through AuditListQuery.
type storeReader struct{ c *cast }

func (r storeReader) ReadAudit(ctx context.Context, q service.AuditQuery) (service.AuditPage, error) {
	items, total, err := r.c.svc.Audits.List(ctx, service.AuditListQuery(q))
	return service.AuditPage{Items: items, Total: total, Nodes: 1, Answered: 1, Source: "test"}, err
}
