package admin_test

import (
	"context"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// owner returns a caller acting as a new service account of the primary organization with orgs:create and
// orgs:manage, the account that owns the organizations it creates, and the primary organization.
func (w *world) owner() (*caller, *model.Org) {
	w.t.Helper()
	primary, err := w.env.Svc.PrimaryOrg(context.Background())
	if err != nil {
		w.t.Fatal(err)
	}
	return w.asServiceAccount(primary, service.ScopeOrgsCreate, service.ScopeOrgsManage), primary
}

// An account with orgs:manage configures an organization it created as a super admin would: users of every role,
// service accounts, the settings, branding, email templates and audit log that are closed to other service accounts,
// and an organization provider from the primary organization; what it does is audited as the owner's.
func TestOwnerConfiguresItsOrganization(t *testing.T) {
	w := newWorld(t)
	own, primary := w.owner()
	want(t, own.post("/api/orgs", map[string]any{"name": "cust1"}), 201)
	const C = "/api/orgs/cust1"

	want(t, own.post(C+"/users", map[string]any{"email": "boss@cust1.example", "username": "boss", "given_name": "Bo",
		"family_name": "Ss", "role": "admin"}), 201)
	want(t, own.patch(C, map[string]any{"display_name": "Customer One"}), 200)
	want(t, own.patch(C+"/branding", map[string]any{"primary_color": "#123456"}), 200)
	want(t, own.get(C+"/email-templates"), 200)
	want(t, own.post(C+"/tenants", map[string]any{"name": "app"}), 201)
	want(t, own.post(C+"/service-accounts", map[string]any{"name": "setup", "scopes": []string{"users", "import"}}), 201)
	// the primary organization's scopes are never given in another organization
	wantField(t, own.post(C+"/service-accounts", map[string]any{"name": "x", "scopes": []string{"orgs:manage"}}), 422, "scopes")

	p := own.post(C+"/providers", map[string]any{"type": "organization", "source_org": primary.Name})
	want(t, p, 201)
	want(t, own.patch(C+"/providers/"+p.str("id"), map[string]any{"name": "Vendor support"}), 200)
	want(t, own.delete(C+"/providers/"+p.str("id")), 200)

	a := own.get(C + "/audit")
	want(t, a, 200)
	if !strings.Contains(string(a.Raw), `"acting_as":"owner"`) {
		t.Fatalf("the owner's changes are not audited as the owner's: %s", a.Raw)
	}
}

// The owner is a super admin only in the organizations it created: in another organization, the primary one and an
// organization another account created, every organization route refuses it as it refuses any service account
// (404, or the scope guard), and the server's own routes stay closed.
func TestOwnerReachesNothingElse(t *testing.T) {
	w := newWorld(t)
	other, primary := w.owner()
	want(t, other.post("/api/orgs", map[string]any{"name": "theirs"}), 201)
	own, _ := w.owner()
	want(t, own.post("/api/orgs", map[string]any{"name": "mine"}), 201)

	for _, org := range []string{"acme", primary.Name, "theirs"} {
		for _, rt := range w.mod.Routes() {
			if !strings.HasPrefix(rt.Path, "/api/orgs/{org}") || org == primary.Name && rt.Scope == web.AnyScope {
				continue // any service account reads its own organization's tenants and applications, as before
			}
			p := concretePath(rt.Path, org, "nope")
			var body any
			if rt.Method != "GET" && rt.Method != "DELETE" {
				body = map[string]any{}
			}
			if r := own.do(rt.Method, p, body); r.Status != 404 && r.Status != 403 {
				t.Errorf("%s %s as the owner of another organization: %d %s", rt.Method, p, r.Status, r.Raw)
			}
		}
	}
	for _, rt := range w.mod.Routes() {
		if strings.HasPrefix(rt.Path, "/api/orgs") {
			continue
		}
		p := concretePath(rt.Path, "mine", "nope")
		if r := own.do(rt.Method, p, nil); !guardRefused(r) {
			t.Errorf("%s %s (a route of the server) as an owner: %d %s", rt.Method, p, r.Status, r.Raw)
		}
	}
	// without orgs:manage, an account that created an organization is no more than before there
	primaryOnly := w.asServiceAccount(primary, service.ScopeOrgsCreate)
	want(t, primaryOnly.post("/api/orgs", map[string]any{"name": "plain"}), 201)
	if r := primaryOnly.get("/api/orgs/plain/users"); r.Status < 400 {
		t.Fatalf("an account without orgs:manage reached its organization: %d %s", r.Status, r.Raw)
	}
}

// An owner's organization provider has its client in the primary organization or another organization the owner
// created, never in one it has no say in; and a provider a super admin pointed at such an organization is beyond the
// owner's reach.
func TestOwnerProviderSources(t *testing.T) {
	w := newWorld(t)
	own, primary := w.owner()
	want(t, own.post("/api/orgs", map[string]any{"name": "cust1"}), 201)
	want(t, own.post("/api/orgs", map[string]any{"name": "cust2"}), 201)
	const P = "/api/orgs/cust1/providers"

	wantField(t, own.post(P, map[string]any{"type": "organization", "source_org": "acme"}), 422, "source_org")
	want(t, own.post(P, map[string]any{"type": "organization", "source_org": "cust2"}), 201)
	mine := own.post(P, map[string]any{"type": "organization", "source_org": primary.Name, "name": "Primary"})
	want(t, mine, 201)
	// moving one of its providers to an organization it has no say in is refused too
	wantField(t, own.patch(P+"/"+mine.str("id"), map[string]any{"source_org": "acme"}), 422, "source_org")

	su := w.as("super")
	theirs := su.post(P, map[string]any{"type": "organization", "source_org": "acme", "name": "Acme"})
	want(t, theirs, 201)
	want(t, own.patch(P+"/"+theirs.str("id"), map[string]any{"name": "Renamed"}), 403)
	want(t, own.delete(P+"/"+theirs.str("id")), 403)
	want(t, su.delete(P+"/"+theirs.str("id")), 200)
}

// Ownership is the account's, not its secret's: after the secret is rotated the account still owns what it created.
func TestOwnerKeepsItsOrganizationsAcrossRotation(t *testing.T) {
	w := newWorld(t)
	own, primary := w.owner()
	want(t, own.post("/api/orgs", map[string]any{"name": "cust1"}), 201)
	id := strings.TrimPrefix(own.bearer, "sa:")
	if _, err := w.env.Svc.RotateServiceAccountSecret(context.Background(), service.System, primary.ID, id); err != nil {
		t.Fatal(err)
	}
	o, err := w.env.Svc.OrgByRef(context.Background(), "cust1")
	if err != nil {
		t.Fatal(err)
	}
	if o.CreatedBy != id {
		t.Fatalf("created by %q, want %q", o.CreatedBy, id)
	}
	want(t, own.get("/api/orgs/cust1/users"), 200)
}

// OwnerActor is the owner's alone: an account that did not create the organization, one without orgs:manage, a
// person, and the primary organization get nothing.
func TestOwnerActor(t *testing.T) {
	sa := &service.Actor{OrgID: "p", Role: model.RoleAdmin, ClientID: "sa1", Scopes: []string{service.ScopeOrgsManage}}
	o := &model.Org{Meta: model.Meta{ID: "o1"}, CreatedBy: "sa1"}
	up := service.OwnerActor(sa, o)
	if up == nil || !up.IsSuper() || up.Owner != "o1" || !up.HasScope(service.ScopeManageAdmins) || sa.IsSuper() {
		t.Fatalf("owner: %+v", up)
	}
	if service.OwnerActor(sa, &model.Org{CreatedBy: "sa2"}) != nil {
		t.Error("another account's organization")
	}
	if service.OwnerActor(&service.Actor{ClientID: "sa1", Scopes: []string{service.ScopeOrgsCreate}}, o) != nil {
		t.Error("without orgs:manage")
	}
	if service.OwnerActor(&service.Actor{UserID: "u", Role: model.RoleAdmin, Unscoped: true}, &model.Org{}) != nil {
		t.Error("a person, on an organization no account created")
	}
	if service.OwnerActor(sa, &model.Org{CreatedBy: "sa1", Primary: true}) != nil {
		t.Error("the primary organization")
	}
	if service.OwnerActor(sa, nil) != nil {
		t.Error("no organization")
	}
}
