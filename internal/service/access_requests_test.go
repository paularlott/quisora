package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// requestWorld is an organization set up for access requests: CST (pat and sam) may ask, approved by CST Approval
// (alex); a members-only tenant "customer-b" with access defaults, and an open one.
type requestWorld struct {
	*env
	org                *model.Org
	admin, mgr         *model.User
	pat, sam, alex     *model.User
	cst, approvers     *model.Group
	tenant, openTenant *model.Tenant
}

func newRequestWorld(t *testing.T) *requestWorld {
	t.Helper()
	e := newEnv(t)
	w := &requestWorld{env: e, org: e.org("vendor")}
	w.admin = e.user(w.org.ID, "admin", model.RoleAdmin)
	w.mgr = e.user(w.org.ID, "mgr", model.RoleManager)
	w.pat = e.user(w.org.ID, "pat", model.RoleUser)
	w.sam = e.user(w.org.ID, "sam", model.RoleUser)
	w.alex = e.user(w.org.ID, "alex", model.RoleUser)
	var err error
	if w.approvers, err = e.svc.CreateGroupWithMembers(e.ctx, service.System, w.org.ID, service.GroupInput{DisplayName: ptr("CST Approval"), ApprovesRequests: ptr(true)},
		[]string{w.alex.ID}); err != nil {
		t.Fatal(err)
	}
	if w.cst, err = e.svc.CreateGroupWithMembers(e.ctx, service.System, w.org.ID, service.GroupInput{DisplayName: ptr("CST"),
		AccessRequests: &service.GroupRequestsInput{Enabled: true, Approvers: w.approvers.ID, Lengths: []int{3600, 86400}}},
		[]string{w.pat.ID, w.sam.ID}); err != nil {
		t.Fatal(err)
	}
	if w.tenant, err = e.svc.CreateTenant(e.ctx, service.System, w.org.ID, service.TenantInput{Name: ptr("customer-b"),
		AccessDefaults: &service.AccessDefaultsInput{Roles: &[]string{"support"}, Tags: &[]string{"vendor"}}}); err != nil {
		t.Fatal(err)
	}
	open := model.DefaultTenantSettings()
	if w.openTenant, err = e.svc.CreateTenant(e.ctx, service.System, w.org.ID, service.TenantInput{Name: ptr("everyone"), Settings: &open}); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *requestWorld) ask(u *model.User, tenant string, length int) (*model.AccessRequest, error) {
	return w.svc.CreateAccessRequest(w.ctx, actor(u), service.AccessRequestInput{TenantID: tenant, Length: length, Reason: "SUP-1"})
}

func (w *requestWorld) entry(t *testing.T, u *model.User) *model.TenantAccess {
	t.Helper()
	acc, err := w.svc.Access.Get(w.ctx, model.AccessID(w.tenant.ID, u.ID))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return acc
}

func fieldOfErr(err error) string {
	var fe *service.FieldError
	if errors.As(err, &fe) {
		return fe.Field
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

// The groups that ask for and approve access are protected: a manager, who adds plain users to groups, cannot add
// anyone to a requester group or a group that approves (they could approve their own way in), even one no group
// names yet; an administrator can. Only a group that approves may be named as approvers; one named cannot stop
// approving, nor be deleted; and the settings are checked.
func TestAccessRequestGroupsAreProtected(t *testing.T) {
	w := newRequestWorld(t)
	other := w.user(w.org.ID, "other", model.RoleUser)
	for _, g := range []*model.Group{w.cst, w.approvers} {
		if err := w.svc.SetMembership(w.ctx, actor(w.mgr), g.ID, other.ID, true); fieldOfErr(err) != "members" {
			t.Errorf("a manager added someone to %s: %v", g.DisplayName, err)
		}
		if err := w.svc.SetMembership(w.ctx, actor(w.admin), g.ID, other.ID, true); err != nil {
			t.Errorf("an administrator could not add someone to %s: %v", g.DisplayName, err)
		}
	}
	plain, err := w.svc.CreateGroup(w.ctx, service.System, w.org.ID, service.GroupInput{DisplayName: ptr("Plain")})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.svc.SetMembership(w.ctx, actor(w.mgr), plain.ID, other.ID, true); err != nil {
		t.Errorf("a manager could not add someone to an ordinary group: %v", err)
	}
	spare, err := w.svc.CreateGroup(w.ctx, service.System, w.org.ID, service.GroupInput{DisplayName: ptr("Spare approvers"), ApprovesRequests: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.svc.SetMembership(w.ctx, actor(w.mgr), spare.ID, other.ID, true); fieldOfErr(err) != "members" {
		t.Errorf("a manager added someone to a group that approves, named by none yet: %v", err)
	}
	if _, err := w.svc.UpdateGroup(w.ctx, actor(w.mgr), spare.ID, service.GroupInput{ApprovesRequests: ptr(false)}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("a manager turned approving off: %v", err)
	}
	if _, err := w.svc.UpdateGroup(w.ctx, actor(w.admin), w.approvers.ID, service.GroupInput{ApprovesRequests: ptr(false)}); fieldOfErr(err) != "approves_requests" {
		t.Errorf("a group named as approvers stopped approving: %v", err)
	}
	if g, err := w.svc.UpdateGroup(w.ctx, actor(w.admin), spare.ID, service.GroupInput{ApprovesRequests: ptr(false)}); err != nil || g.ApprovesRequests {
		t.Errorf("a group nobody names stopped approving: %v %+v", err, g)
	}
	if err := w.svc.DeleteGroup(w.ctx, actor(w.admin), w.approvers.ID); fieldOfErr(err) != "access_requests" {
		t.Errorf("the approver group in use was deleted: %v", err)
	}
	for name, in := range map[string]service.GroupRequestsInput{
		"no approvers":   {Enabled: true},
		"itself":         {Enabled: true, Approvers: plain.ID},
		"not approving":  {Enabled: true, Approvers: spare.ID},
		"unknown group":  {Enabled: true, Approvers: model.NewID()},
		"unknown length": {Enabled: true, Approvers: w.approvers.ID, Lengths: []int{60}},
	} {
		if _, err := w.svc.UpdateGroup(w.ctx, actor(w.admin), plain.ID, service.GroupInput{AccessRequests: &in}); fieldOfErr(err) != "access_requests" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := w.svc.UpdateGroup(w.ctx, actor(w.mgr), plain.ID, service.GroupInput{AccessRequests: &service.GroupRequestsInput{Enabled: true,
		Approvers: w.approvers.ID}}); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("a manager turned access requests on: %v", err)
	}
	g, err := w.svc.UpdateGroup(w.ctx, actor(w.admin), plain.ID, service.GroupInput{AccessRequests: &service.GroupRequestsInput{Enabled: true,
		Approvers: w.approvers.ID}})
	if err != nil || g.Requests == nil || !slices.Equal(g.Requests.Lengths, model.AccessLengths) {
		t.Fatalf("all lengths when none are chosen: %v %+v", err, g.Requests)
	}
	if g, err = w.svc.UpdateGroup(w.ctx, actor(w.admin), plain.ID, service.GroupInput{AccessRequests: &service.GroupRequestsInput{}}); err != nil || g.Requests != nil {
		t.Fatalf("turned off: %v %+v", err, g.Requests)
	}
}

// A tenant's access defaults are copied into every new entry that does not give its own (field by field), as a
// snapshot: changing them later changes no entry.
func TestTenantAccessDefaults(t *testing.T) {
	w := newRequestWorld(t)
	details := json.RawMessage(`[{"type":"payment"}]`)
	tn, err := w.svc.UpdateTenant(w.ctx, actor(w.admin), w.tenant.ID, service.TenantInput{AccessDefaults: &service.AccessDefaultsInput{AuthorizationDetails: &details}})
	if err != nil || tn.AccessDefaults == nil || !slices.Equal(tn.AccessDefaults.Roles, []string{"support"}) || len(tn.AccessDefaults.AuthorizationDetails) == 0 {
		t.Fatalf("defaults: %v %+v", err, tn.AccessDefaults)
	}
	if _, err := w.svc.UpdateTenant(w.ctx, actor(w.admin), w.tenant.ID, service.TenantInput{AccessDefaults: &service.AccessDefaultsInput{Roles: &[]string{"bad role!"}}}); fieldOfErr(err) != "roles" {
		t.Errorf("a bad role default: %v", err)
	}
	e, err := w.svc.AddAccess(w.ctx, actor(w.admin), w.tenant.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: w.pat.ID})
	if err != nil || !slices.Equal(e.Roles, []string{"support"}) || !slices.Equal(e.Tags, []string{"vendor"}) || len(e.AuthorizationDetails) == 0 {
		t.Fatalf("an entry given nothing: %v %+v", err, e)
	}
	e, err = w.svc.AddAccess(w.ctx, actor(w.admin), w.tenant.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: w.sam.ID,
		Tags: &[]string{"own"}, Roles: &[]string{}})
	if err != nil || len(e.Roles) != 0 || !slices.Equal(e.Tags, []string{"own"}) || len(e.AuthorizationDetails) == 0 {
		t.Fatalf("an entry giving its own tags and no roles: %v %+v", err, e)
	}
	if _, err := w.svc.UpdateTenant(w.ctx, actor(w.admin), w.tenant.ID, service.TenantInput{AccessDefaults: &service.AccessDefaultsInput{Roles: &[]string{"changed"}}}); err != nil {
		t.Fatal(err)
	}
	if acc := w.entry(t, w.pat); !slices.Equal(acc.Roles, []string{"support"}) {
		t.Errorf("changing the defaults changed an entry: %v", acc.Roles)
	}
}

// The whole of a request: asking (checked), the approver's queue, approving (a timed entry with the tenant's
// defaults, after confirming it is them), extending, denying, cancelling and ending early.
func TestAccessRequestFlow(t *testing.T) {
	w := newRequestWorld(t)
	// asking: checked
	for name, c := range map[string]struct {
		u      *model.User
		in     service.AccessRequestInput
		field  string
		forbid bool
	}{
		"not in a requester group": {u: w.alex, in: service.AccessRequestInput{TenantID: w.tenant.ID, Length: 3600, Reason: "x"}, forbid: true},
		"an open tenant":           {u: w.pat, in: service.AccessRequestInput{TenantID: w.openTenant.ID, Length: 3600, Reason: "x"}, field: "tenant_id"},
		"no reason":                {u: w.pat, in: service.AccessRequestInput{TenantID: w.tenant.ID, Length: 3600}, field: "reason"},
		"a length not offered":     {u: w.pat, in: service.AccessRequestInput{TenantID: w.tenant.ID, Length: 7 * 86400, Reason: "x"}, field: "length"},
		"unknown approvers":        {u: w.pat, in: service.AccessRequestInput{TenantID: w.tenant.ID, Length: 3600, Reason: "x", Approvers: w.cst.ID}, field: "approvers"},
		"unknown tenant":           {u: w.pat, in: service.AccessRequestInput{TenantID: "nosuch", Length: 3600, Reason: "x"}, field: "tenant_id"},
	} {
		_, err := w.svc.CreateAccessRequest(w.ctx, actor(c.u), c.in)
		if c.forbid && !errors.Is(err, service.ErrForbidden) || !c.forbid && fieldOfErr(err) != c.field {
			t.Errorf("%s: %v", name, err)
		}
	}
	guest := actor(w.pat)
	guest.Sources = []model.GuestSource{{UserID: "elsewhere"}}
	if _, err := w.svc.CreateAccessRequest(w.ctx, guest, service.AccessRequestInput{TenantID: w.tenant.ID, Length: 3600, Reason: "x"}); err == nil {
		t.Error("a guest from another organization asked here")
	}
	r, err := w.ask(w.pat, "customer-b", 3600) // by the tenant's name
	if err != nil || r.State != model.RequestPending || r.Approvers != w.approvers.ID {
		t.Fatalf("asked: %v %+v", err, r)
	}
	if _, err := w.ask(w.pat, w.tenant.ID, 86400); fieldOfErr(err) != "tenant_id" {
		t.Errorf("a second request for the same tenant while one waits: %v", err)
	}

	// the queue: the approvers', never the requester's own
	q, _, err := w.svc.ApprovalQueue(w.ctx, actor(w.alex), store.ListQuery{})
	if err != nil || len(q) != 1 || q[0].ID != r.ID {
		t.Fatalf("alex's queue: %v %d", err, len(q))
	}
	if q, _, err := w.svc.ApprovalQueue(w.ctx, actor(w.pat), store.ListQuery{}); err != nil || len(q) != 0 {
		t.Errorf("pat's queue: %v %d", err, len(q))
	}
	if req, appr := w.svc.AccessRequestRoles(w.ctx, w.pat); !req || appr {
		t.Errorf("pat's roles: %v %v", req, appr)
	}
	if req, appr := w.svc.AccessRequestRoles(w.ctx, w.alex); req || !appr {
		t.Errorf("alex's roles: %v %v", req, appr)
	}

	// deciding: an approver who confirmed it is them; not the requester, not someone outside the approver group
	if _, err := w.svc.DecideAccessRequest(w.ctx, actor(w.sam), r.ID, true, "", true); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("sam (not an approver) decided: %v", err)
	}
	if _, err := w.svc.DecideAccessRequest(w.ctx, actor(w.alex), r.ID, true, "", false); !errors.Is(err, service.ErrReauth) {
		t.Errorf("approved without confirming it is them: %v", err)
	}
	token := actor(w.alex)
	token.TokenID = "tok"
	if _, err := w.svc.DecideAccessRequest(w.ctx, token, r.ID, true, "", true); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("approved with a personal API token: %v", err)
	}
	before := time.Now()
	r, err = w.svc.DecideAccessRequest(w.ctx, actor(w.alex), r.ID, true, "ok", true)
	if err != nil || r.State != model.RequestApproved || r.DecidedBy != w.alex.ID {
		t.Fatalf("approved: %v %+v", err, r)
	}
	acc := w.entry(t, w.pat)
	if acc == nil || !acc.AllClients || !slices.Equal(acc.Roles, []string{"support"}) || !acc.Expires.Equal(r.Ends) ||
		acc.Expires.Before(before.Add(time.Hour-time.Second)) || acc.Expires.After(time.Now().Add(time.Hour)) {
		t.Fatalf("the entry it gave: %+v (request ends %v)", acc, r.Ends)
	}
	if _, err := w.svc.DecideAccessRequest(w.ctx, actor(w.alex), r.ID, false, "", true); fieldOfErr(err) != "state" {
		t.Errorf("decided twice: %v", err)
	}

	// extending: a day more moves the end later, and changes nothing else
	r2, err := w.ask(w.pat, w.tenant.ID, 86400)
	if err != nil {
		t.Fatal(err)
	}
	if r2, err = w.svc.DecideAccessRequest(w.ctx, actor(w.alex), r2.ID, true, "", true); err != nil {
		t.Fatal(err)
	}
	if acc2 := w.entry(t, w.pat); !acc2.Expires.After(acc.Expires) || !acc2.Expires.Equal(r2.Ends) || !slices.Equal(acc2.Roles, acc.Roles) {
		t.Errorf("extended: %+v", acc2)
	}

	// denied, with a note; cancelled
	r3, err := w.ask(w.sam, w.tenant.ID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if r3, err = w.svc.DecideAccessRequest(w.ctx, actor(w.alex), r3.ID, false, "not this one", true); err != nil || r3.State != model.RequestDenied || r3.Note != "not this one" {
		t.Fatalf("denied: %v %+v", err, r3)
	}
	if w.entry(t, w.sam) != nil {
		t.Error("a denied request gave access")
	}
	r4, err := w.ask(w.sam, w.tenant.ID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.CancelAccessRequest(w.ctx, actor(w.pat), r4.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("pat cancelled sam's request: %v", err)
	}
	if r4, err = w.svc.CancelAccessRequest(w.ctx, actor(w.sam), r4.ID); err != nil || r4.State != model.RequestCancelled {
		t.Fatalf("cancelled: %v %+v", err, r4)
	}

	// ending early: by the requester, and the entry goes
	if _, err := w.svc.EndAccessRequest(w.ctx, actor(w.sam), r2.ID, true); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("sam ended pat's access: %v", err)
	}
	if r2, err = w.svc.EndAccessRequest(w.ctx, actor(w.pat), r2.ID, false); err != nil || r2.State != model.RequestEnded || r2.EndedBy != w.pat.ID {
		t.Fatalf("ended: %v %+v", err, r2)
	}
	if w.entry(t, w.pat) != nil {
		t.Error("the entry is still there after ending the access")
	}
	if first, err := w.svc.Requests.Get(w.ctx, r.ID); err != nil || first.State != model.RequestEnded {
		t.Errorf("the request it extended still shows its access: %v %+v", err, first)
	}

	// access with no end already: nothing to ask for
	if _, err := w.svc.AddAccess(w.ctx, actor(w.admin), w.tenant.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: w.sam.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ask(w.sam, w.tenant.ID, 3600); fieldOfErr(err) != "tenant_id" {
		t.Errorf("asked for access they have with no end: %v", err)
	}

	// the requester left the requester group: an approval is refused (a denial is not)
	r5, err := w.ask(w.pat, w.tenant.ID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.svc.SetMembership(w.ctx, actor(w.admin), w.cst.ID, w.pat.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.DecideAccessRequest(w.ctx, actor(w.alex), r5.ID, true, "", true); fieldOfErr(err) != "state" {
		t.Errorf("approved for someone no longer in the group: %v", err)
	}
	if _, err := w.svc.DecideAccessRequest(w.ctx, actor(w.alex), r5.ID, false, "", true); err != nil {
		t.Errorf("denied for someone no longer in the group: %v", err)
	}
}

// A service account with access_requests:approve decides the requests of the groups that allow it, and no others;
// without the scope it decides nothing.
func TestAccessRequestServiceAccountApproval(t *testing.T) {
	w := newRequestWorld(t)
	sa, _, err := w.svc.CreateServiceAccount(w.ctx, actor(w.admin), w.org.ID, service.ServiceAccountInput{Name: ptr("bot"),
		Scopes: &[]string{service.ScopeAccessRequestsApprove}})
	if err != nil {
		t.Fatal(err)
	}
	bot := service.ActorForServiceAccount(sa, sa.Scopes, "127.0.0.1")
	r, err := w.ask(w.pat, w.tenant.ID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if q, _, err := w.svc.ApprovalQueue(w.ctx, bot, store.ListQuery{}); err != nil || len(q) != 0 {
		t.Errorf("the bot's queue before the group allows it: %v %d", err, len(q))
	}
	if _, err := w.svc.DecideAccessRequest(w.ctx, bot, r.ID, true, "", false); fieldOfErr(err) != "state" {
		t.Errorf("the bot decided before the group allowed it: %v", err)
	}
	if _, err := w.svc.UpdateGroup(w.ctx, actor(w.admin), w.cst.ID, service.GroupInput{AccessRequests: &service.GroupRequestsInput{Enabled: true,
		Approvers: w.approvers.ID, Lengths: []int{3600}, ServiceAccounts: true}}); err != nil {
		t.Fatal(err)
	}
	if q, _, err := w.svc.ApprovalQueue(w.ctx, bot, store.ListQuery{}); err != nil || len(q) != 1 {
		t.Fatalf("the bot's queue: %v %d", err, len(q))
	}
	noScope := service.ActorForServiceAccount(sa, []string{service.ScopeAccess}, "127.0.0.1")
	if _, err := w.svc.DecideAccessRequest(w.ctx, noScope, r.ID, true, "", false); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("a service account without the scope decided: %v", err)
	}
	if r, err = w.svc.DecideAccessRequest(w.ctx, bot, r.ID, true, "", false); err != nil || r.DecidedVia != "api" || r.DecidedBy != sa.ID {
		t.Fatalf("the bot approved: %v %+v", err, r)
	}
	if w.entry(t, w.pat) == nil {
		t.Error("the bot's approval gave no access")
	}
}

// Housekeeping: a request nobody decides lapses after a day, and closed requests go after 90 days.
func TestAccessRequestsLapseAndGo(t *testing.T) {
	w := newRequestWorld(t)
	r, err := w.ask(w.pat, w.tenant.ID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	r.Lapses = time.Now().Add(-time.Minute).UTC()
	if err := w.svc.Requests.Update(w.ctx, r); err != nil {
		t.Fatal(err)
	}
	if q, _, _ := w.svc.ApprovalQueue(w.ctx, actor(w.alex), store.ListQuery{}); len(q) != 0 {
		t.Error("a lapsed request is still in the queue")
	}
	if _, err := w.svc.DecideAccessRequest(w.ctx, actor(w.alex), r.ID, true, "", true); fieldOfErr(err) != "state" {
		t.Errorf("a lapsed request was approved: %v", err)
	}
	if n, err := w.svc.ExpireAccessRequests(w.ctx); err != nil || n != 1 {
		t.Fatalf("lapse: %d %v", n, err)
	}
	if r, err = w.svc.Requests.Get(w.ctx, r.ID); err != nil || r.State != model.RequestLapsed {
		t.Fatalf("lapsed: %v %+v", err, r)
	}
	if _, err := w.ask(w.pat, w.tenant.ID, 3600); err != nil {
		t.Errorf("asking again after a lapse: %v", err)
	}
	r.Lapses = time.Now().Add(-model.RequestKeptFor - time.Hour).UTC()
	if err := w.svc.Requests.Update(w.ctx, r); err != nil {
		t.Fatal(err)
	}
	if n, err := w.svc.ExpireAccessRequests(w.ctx); err != nil || n != 1 {
		t.Fatalf("removal: %d %v", n, err)
	}
	if _, err := w.svc.Requests.Get(w.ctx, r.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a request closed long ago is still kept: %v", err)
	}
}

// The service tells OnAccessRequest (the emails) of each request made, decided and ended by someone else, with who
// did it; the person ending their own access is not told.
func TestAccessRequestNotices(t *testing.T) {
	w := newRequestWorld(t)
	var got []string
	w.svc.OnAccessRequest = func(_ context.Context, n service.AccessRequestNotice) { got = append(got, n.Event+" by "+n.By) }
	r, err := w.ask(w.pat, w.tenant.ID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.svc.DecideAccessRequest(w.ctx, actor(w.alex), r.ID, false, "", true); err != nil {
		t.Fatal(err)
	}
	r, _ = w.ask(w.pat, w.tenant.ID, 3600)
	if _, err = w.svc.DecideAccessRequest(w.ctx, actor(w.alex), r.ID, true, "", true); err != nil {
		t.Fatal(err)
	}
	if _, err = w.svc.EndAccessRequest(w.ctx, actor(w.alex), r.ID, true); err != nil {
		t.Fatal(err)
	}
	r, _ = w.ask(w.pat, w.tenant.ID, 3600)
	if _, err = w.svc.DecideAccessRequest(w.ctx, actor(w.alex), r.ID, true, "", true); err != nil {
		t.Fatal(err)
	}
	if _, err = w.svc.EndAccessRequest(w.ctx, actor(w.pat), r.ID, false); err != nil {
		t.Fatal(err)
	}
	alex := w.alex.FullName()
	want := []string{"new by " + w.pat.Username, "denied by " + alex, "new by " + w.pat.Username, "approved by " + alex, "ended by " + alex,
		"new by " + w.pat.Username, "approved by " + alex}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("notices:\n got %v\nwant %v", got, want)
	}
}

// Every member of a group that approves sees its lists, not only who decided: the waiting requests and the access the
// group gave that runs, which any of them may end. A group that approves sees them even when no group names it (any
// more), and its members get Approvals in the account menu.
func TestApproverGroupMembersAllSeeItsLists(t *testing.T) {
	w := newRequestWorld(t)
	kim := w.user(w.org.ID, "kim", model.RoleUser)
	if err := w.svc.SetMembership(w.ctx, actor(w.admin), w.approvers.ID, kim.ID, true); err != nil {
		t.Fatal(err)
	}
	r, err := w.ask(w.pat, w.tenant.ID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if q, n, err := w.svc.ApprovalQueue(w.ctx, actor(kim), store.ListQuery{}); err != nil || n != 1 || q[0].ID != r.ID {
		t.Fatalf("kim's queue: %v %d", err, n)
	}
	if _, err := w.svc.DecideAccessRequest(w.ctx, actor(w.alex), r.ID, true, "", true); err != nil {
		t.Fatal(err)
	}
	if l, n, err := w.svc.ApprovedByGroups(w.ctx, actor(kim), store.ListQuery{}); err != nil || n != 1 || l[0].ID != r.ID {
		t.Fatalf("the access alex approved, as kim sees it: %v %d", err, n)
	}

	// the requester group moves to other approvers: the old group still sees, and may end, the access it gave
	other, err := w.svc.CreateGroupWithMembers(w.ctx, service.System, w.org.ID, service.GroupInput{DisplayName: ptr("Other approvers"),
		ApprovesRequests: ptr(true)}, []string{w.sam.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.UpdateGroup(w.ctx, actor(w.admin), w.cst.ID, service.GroupInput{AccessRequests: &service.GroupRequestsInput{Enabled: true,
		Approvers: other.ID}}); err != nil {
		t.Fatal(err)
	}
	if req, appr := w.svc.AccessRequestRoles(w.ctx, kim); req || !appr {
		t.Errorf("kim's roles, the group named by none now: %v %v", req, appr)
	}
	if l, n, err := w.svc.ApprovedByGroups(w.ctx, actor(kim), store.ListQuery{}); err != nil || n != 1 || l[0].ID != r.ID {
		t.Fatalf("the running access, the group named by none now: %v %d", err, n)
	}
	if r, err = w.svc.EndAccessRequest(w.ctx, actor(kim), r.ID, true); err != nil || r.State != model.RequestEnded {
		t.Fatalf("kim ended it: %v %+v", err, r)
	}
}
