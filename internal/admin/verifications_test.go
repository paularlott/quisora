package admin_test

import (
	"context"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Caller verification through the management API with the agent's personal API token (call_verify): the whole of it
// from a CRM's side, and who may not (a token without the scope, a person who is not an agent, a service account).
// The agent's own sign-in token (the API's resource) is tested end to end with the OAuth provider in internal/app.
func TestCallVerificationAPI(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	agent, customer := w.users["manager"], w.users["user"]
	g, err := w.env.Svc.CreateGroupWithMembers(ctx, service.System, w.acme.ID, service.GroupInput{DisplayName: ptr("Support")}, []string{agent.ID})
	if err != nil {
		t.Fatal(err)
	}
	o, _ := w.env.Svc.Orgs.Get(ctx, w.acme.ID)
	set := o.Settings
	set.VerifyCallers, set.VerifyAgentGroups = true, []string{g.ID}
	if _, err := w.env.Svc.UpdateOrg(ctx, service.System, w.acme.ID, service.OrgInput{Settings: &set}); err != nil {
		t.Fatal(err)
	}
	const R = "/api/orgs/acme/verifications"
	crm := w.withBearer("manager", service.ScopeCallVerify)

	orgs := crm.get(R + "/orgs")
	want(t, orgs, 200)
	if items := orgs.JSON["items"].([]any); len(items) != 1 || items[0].(map[string]any)["own"] != true {
		t.Fatalf("organizations: %s", orgs.Raw)
	}
	people := crm.get(R + "/users?q=" + customer.Username)
	want(t, people, 200)
	if items := people.JSON["items"].([]any); len(items) != 1 || items[0].(map[string]any)["id"] != customer.ID {
		t.Fatalf("people: %s", people.Raw)
	}
	wantField(t, crm.post(R, map[string]any{"user_id": customer.ID}), 422, "direction")
	started := crm.post(R, map[string]any{"user_id": customer.ID, "direction": model.VerifyOutbound, "reason": "CRM-42"})
	want(t, started, 201)
	v := started.JSON["verification"].(map[string]any)
	if c, _ := started.JSON["code"].(string); len(c) != 6 || v["agent_id"] != agent.ID || v["state"] != model.VerifyPending {
		t.Fatalf("started: %s", started.Raw)
	}
	id := v["id"].(string)
	if got := crm.get(R + "/" + id); got.Status != 200 || got.str("state") != model.VerifyPending {
		t.Fatalf("how it stands: %s", got.Raw)
	}
	if l := crm.get(R); l.Status != 200 || len(l.JSON["items"].([]any)) != 1 {
		t.Fatalf("the day's: %s", l.Raw)
	}
	cancelled := crm.post(R+"/"+id+"/cancel", nil)
	want(t, cancelled, 200)
	if cancelled.str("state") != model.VerifyCancelled {
		t.Fatalf("cancelled: %s", cancelled.Raw)
	}

	// not: a token without the scope, a person who is not an agent, a service account
	want(t, w.withBearer("manager", "api").post(R, map[string]any{"user_id": customer.ID, "direction": model.VerifyInbound}), 403)
	want(t, w.withBearer("user", service.ScopeCallVerify).post(R, map[string]any{"user_id": w.users["manager"].ID, "direction": model.VerifyInbound}), 403)
	want(t, w.asServiceAccount(w.acme, service.ScopeUsers).post(R, map[string]any{"user_id": customer.ID, "direction": model.VerifyInbound}), 403)
	// someone else's verification is not found, rather than refused: it says nothing of whether there is one
	want(t, w.withBearer("user", service.ScopeCallVerify).get(R+"/"+id), 404)
}
