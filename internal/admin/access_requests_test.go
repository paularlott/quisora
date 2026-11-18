package admin_test

import (
	"context"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Access requests through the management API: a person asks, lists and cancels with a personal API token holding
// access_requests (no admin scope needed), but never decides with one; a service account with
// access_requests:approve decides the requests of the groups that allow it; administrators list every request.
func TestAccessRequestsAPI(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	user := w.users["user"]
	approver := w.users["manager"]
	appr, err := w.env.Svc.CreateGroupWithMembers(ctx, service.System, w.acme.ID, service.GroupInput{DisplayName: ptr("Approvers"), ApprovesRequests: ptr(true)}, []string{approver.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.env.Svc.CreateGroupWithMembers(ctx, service.System, w.acme.ID, service.GroupInput{DisplayName: ptr("Support"),
		AccessRequests: &service.GroupRequestsInput{Enabled: true, Approvers: appr.ID, ServiceAccounts: true}}, []string{user.ID}); err != nil {
		t.Fatal(err)
	}
	tn, err := w.env.Svc.CreateTenant(ctx, service.System, w.acme.ID, service.TenantInput{Name: ptr("ops")})
	if err != nil {
		t.Fatal(err)
	}
	const R = "/api/orgs/acme/access-requests"

	// the person, with a token holding only access_requests
	me := w.withBearer("user", service.ScopeAccessRequests)
	opts := me.get(R + "/options?q=op")
	want(t, opts, 200)
	if a := opts.JSON["approvers"].([]any); len(a) != 1 || len(opts.JSON["tenants"].([]any)) != 1 {
		t.Fatalf("options: %s", opts.Raw)
	}
	made := me.post(R, map[string]any{"tenant_id": "ops", "length": 3600, "reason": "SUP-9"})
	want(t, made, 201)
	id := made.str("id")
	if made.str("state") != "pending" || made.str("tenant_display_name") != tn.DisplayName || made.str("approvers_name") != "Approvers" {
		t.Fatalf("made: %s", made.Raw)
	}
	wantField(t, me.post(R, map[string]any{"tenant_id": "ops", "length": 3600, "reason": "again"}), 409, "tenant_id")
	if l := me.get(R); l.Status != 200 || len(l.JSON["items"].([]any)) != 1 {
		t.Fatalf("own list: %s", l.Raw)
	}
	want(t, me.post(R+"/"+id+"/approve", nil), 403) // a personal token never decides
	want(t, me.get(R+"/all"), 403)                  // nor lists everyone's
	// a token without the scope reaches nothing here
	want(t, w.withBearer("user", "api").get(R), 403)

	// a service account with access_requests:approve: the queue, and approving
	bot := w.asServiceAccount(w.acme, service.ScopeAccessRequestsApprove)
	q := bot.get(R + "/pending")
	want(t, q, 200)
	if len(q.JSON["items"].([]any)) != 1 {
		t.Fatalf("the bot's queue: %s", q.Raw)
	}
	want(t, bot.get(R), 403) // its own requests: a service account asks for nothing
	ok := bot.post(R+"/"+id+"/approve", map[string]any{"note": "auto"})
	want(t, ok, 200)
	if ok.str("state") != "approved" || ok.str("decided_via") != "api" || ok.str("ends") == "" {
		t.Fatalf("approved: %s", ok.Raw)
	}
	if acc, err := w.env.Svc.Access.Get(ctx, model.AccessID(tn.ID, user.ID)); err != nil || acc.Expires.IsZero() {
		t.Fatalf("the access it gave: %v %+v", err, acc)
	}
	wantField(t, bot.post(R+"/"+id+"/deny", nil), 422, "state") // decided already

	// administrators see every request; the person ends their own access with their token
	all := w.as("admin").get(R + "/all?state=approved")
	want(t, all, 200)
	if all.JSON["total"].(float64) != 1 {
		t.Fatalf("all: %s", all.Raw)
	}
	me = w.withBearer("user", service.ScopeAccessRequests)
	ended := me.post(R+"/"+id+"/end", nil)
	want(t, ended, 200)
	if ended.str("state") != "ended" {
		t.Fatalf("ended: %s", ended.Raw)
	}
	if _, err := w.env.Svc.Access.Get(ctx, model.AccessID(tn.ID, user.ID)); err == nil {
		t.Fatal("the access is still there after it was ended")
	}
}
