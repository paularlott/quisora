package admin_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// scriptling runs the Scriptling CLI from the repository's scriptling folder (-L lib) against w's server as the
// bearer token, and returns its output and whether it succeeded. The test is skipped where Scriptling is not
// installed.
func (w *world) scriptling(t *testing.T, token string, args ...string) (string, bool) {
	t.Helper()
	bin, err := exec.LookPath("scriptling")
	if err != nil {
		t.Skip("scriptling is not installed")
	}
	dir, err := filepath.Abs("../../scriptling")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, append([]string{"-L", "lib"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "QUISORA_URL="+w.env.URL, "QUISORA_TOKEN="+token, "QUISORA_INSECURE=1")
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// The Scriptling example an external approval tool would run: give a user timed access to a members-only tenant
// (with roles and a reason), extend it by giving it again, list it, and take it away; with a service account holding
// only the access, tenants and users scopes.
func TestScriptlingTimedAccess(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	set := model.DefaultTenantSettings()
	set.MembersOnly = true
	tn, err := w.env.Svc.CreateTenant(ctx, service.System, w.acme.ID, service.TenantInput{Name: ptr("support"), Settings: &set})
	if err != nil {
		t.Fatal(err)
	}
	sa := w.asServiceAccount(w.acme, service.ScopeAccess, service.ScopeTenants, service.ScopeUsers)
	alan := w.users["user"]
	id := model.AccessID(tn.ID, alan.ID)
	entry := func() *model.TenantAccess {
		t.Helper()
		acc, err := w.env.Svc.Access.Get(ctx, id)
		if err != nil {
			t.Fatalf("the entry: %v", err)
		}
		return acc
	}
	around := func(got time.Time, want time.Duration) bool {
		d := time.Until(got)
		return d > want-time.Minute && d <= want
	}

	out, ok := w.scriptling(t, sa.bearer, "examples/timed_access.py", "acme", "give", "support", "alan", "3", "SUP-1 approved by sam", "--roles", "support")
	if !ok || !strings.Contains(out, "alan has access to support until") {
		t.Fatalf("give: %v\n%s", ok, out)
	}
	if acc := entry(); !around(acc.Expires, 3*time.Hour) || !acc.AllClients || len(acc.Roles) != 1 || acc.Roles[0] != "support" {
		t.Fatalf("given: %+v", acc)
	}
	audits, _, err := w.env.Svc.Audits.List(ctx, store.ListQuery{Scope: w.acme.ID, Filters: []store.Filter{{Field: "action", Value: "tenant.access.add"}}})
	if err != nil || len(audits) != 1 || audits[0].Detail["reason"] != "SUP-1 approved by sam" || audits[0].Detail["expires"] == "" {
		t.Fatalf("audit: %v %+v", err, audits)
	}

	out, ok = w.scriptling(t, sa.bearer, "examples/timed_access.py", "acme", "give", "support", "alan", "5", "SUP-1 extended")
	if !ok || !strings.Contains(out, "until") {
		t.Fatalf("give again: %v\n%s", ok, out)
	}
	if acc := entry(); !around(acc.Expires, 5*time.Hour) || len(acc.Roles) != 1 {
		t.Fatalf("extended (roles kept): %+v", acc)
	}

	out, ok = w.scriptling(t, sa.bearer, "examples/timed_access.py", "acme", "list", "support")
	if !ok || !strings.Contains(out, "user") || !strings.Contains(out, entry().Expires.Format("2006-01-02T15:04")) {
		t.Fatalf("list: %v\n%s", ok, out)
	}

	out, ok = w.scriptling(t, sa.bearer, "examples/timed_access.py", "acme", "remove", "support", "alan")
	if !ok || !strings.Contains(out, "Removed alan's access to support") {
		t.Fatalf("remove: %v\n%s", ok, out)
	}
	if _, err := w.env.Svc.Access.Get(ctx, id); err == nil {
		t.Fatal("the entry is still there")
	}

	if out, ok = w.scriptling(t, sa.bearer, "examples/timed_access.py", "acme", "give", "nosuch", "alan", "1", "x"); ok || !strings.Contains(out, "No tenant nosuch") {
		t.Fatalf("unknown tenant: %v\n%s", ok, out)
	}

	// the library on its own: a group, some clients, an end given as a time with its offset, then taken off
	cl, _, err := w.env.Svc.CreateClient(ctx, service.System, w.acme.ID, service.ClientInput{Name: ptr("App"), TenantID: &tn.ID,
		RedirectURIs: &[]string{"https://app.example/cb"}})
	if err != nil {
		t.Fatal(err)
	}
	grp, err := w.env.Svc.CreateGroup(ctx, service.System, w.acme.ID, service.GroupInput{DisplayName: ptr("Support")})
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().Add(2 * time.Hour).In(time.FixedZone("AWST", 8*3600)).Truncate(time.Second)
	script := filepath.Join(t.TempDir(), "lib_test.py")
	src := `import quisora
qs = quisora.from_env()
t = qs.find_tenant("acme", "support")
e = qs.give_access("acme", t["id"], "` + grp.ID + `", subject_type="group", expires="` + end.Format(time.RFC3339) + `",
                   clients=["` + cl.ID + `"], reason="group test")
print("expires", e["expires"])
e = qs.update_access("acme", t["id"], e["id"], expires="")
print("after", e.get("expires") or "none")
print("entries", len(list(qs.iter_access("acme", t["id"]))))
`
	if err := os.WriteFile(script, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	out, ok = w.scriptling(t, sa.bearer, script)
	want := "expires " + end.UTC().Format(time.RFC3339)
	if !ok || !strings.Contains(out, want) || !strings.Contains(out, "after none") || !strings.Contains(out, "entries 1") {
		t.Fatalf("library: %v, want %q in\n%s", ok, want, out)
	}
	acc, err := w.env.Svc.Access.Get(ctx, model.AccessID(tn.ID, grp.ID))
	if err != nil || acc.AllClients || len(acc.Clients) != 1 || acc.Clients[0] != cl.ID || !acc.Expires.IsZero() {
		t.Fatalf("the group's entry: %v %+v", err, acc)
	}
}

// The Scriptling example that sets up a customer organization, as the primary organization's account that owns what it
// creates: --guests makes the organization provider, whose own members-only tenant in the primary organization lets
// nobody in, and gives the guest groups access there (the account's access scope).
func TestScriptlingSetupOrgGivesTheGuestGroupsAccess(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	primary, err := w.env.Svc.PrimaryOrg(ctx)
	if err != nil {
		t.Fatal(err)
	}
	grp, err := w.env.Svc.CreateGroup(ctx, service.System, primary.ID, service.GroupInput{DisplayName: ptr("Support")})
	if err != nil {
		t.Fatal(err)
	}
	sa := w.asServiceAccount(primary, service.ScopeOrgsCreate, service.ScopeOrgsManage, service.ScopeAccess)
	out, ok := w.scriptling(t, sa.bearer, "examples/setup_org.py", "cust2", "Customer Two", "--admin", "boss@cust2.example", "Bo",
		"--guests", primary.Name, grp.ID)
	if !ok || !strings.Contains(out, "1 group(s) of "+primary.Name+" given access") {
		t.Fatalf("setup_org: %v\n%s", ok, out)
	}
	org, err := w.env.Svc.OrgByRef(ctx, "cust2")
	if err != nil {
		t.Fatal(err)
	}
	ps, _, err := w.env.Svc.ListProviders(ctx, nil, org.ID, store.ListQuery{})
	if err != nil || len(ps) != 1 {
		t.Fatalf("providers: %v %d", err, len(ps))
	}
	own, err := w.env.Svc.Tenants.Get(ctx, ps[0].SourceTenant)
	if err != nil || own.OrgID != primary.ID || own.ProviderID != ps[0].ID || !own.Settings.MembersOnly {
		t.Fatalf("the provider's tenant: %v %+v", err, own)
	}
	acc, err := w.env.Svc.Access.Get(ctx, model.AccessID(own.ID, grp.ID))
	if err != nil || acc.SubjectType != model.SubjectGroup || !acc.Expires.IsZero() {
		t.Fatalf("the guest group's access: %v %+v", err, acc)
	}
}

// The Scriptling approval bot: as a service account with access_requests:approve, it approves the waiting requests
// whose reason starts with a ticket prefix and leaves the others; a group that does not let service accounts approve
// keeps its requests from it.
func TestScriptlingApprovalBot(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	user, other := w.users["user"], w.users["manager"]
	appr, err := w.env.Svc.CreateGroupWithMembers(ctx, service.System, w.acme.ID, service.GroupInput{DisplayName: ptr("Approvers"), ApprovesRequests: ptr(true)}, []string{w.users["admin"].ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.env.Svc.CreateGroupWithMembers(ctx, service.System, w.acme.ID, service.GroupInput{DisplayName: ptr("Support"),
		AccessRequests: &service.GroupRequestsInput{Enabled: true, Approvers: appr.ID, ServiceAccounts: true}}, []string{user.ID, other.ID}); err != nil {
		t.Fatal(err)
	}
	tn, err := w.env.Svc.CreateTenant(ctx, service.System, w.acme.ID, service.TenantInput{Name: ptr("ops")})
	if err != nil {
		t.Fatal(err)
	}
	ask := func(u *model.User, reason string) {
		t.Helper()
		if _, err := w.env.Svc.CreateAccessRequest(ctx, service.ActorForUser(u, ""), service.AccessRequestInput{TenantID: tn.ID, Length: 3600, Reason: reason}); err != nil {
			t.Fatal(err)
		}
	}
	ask(user, "SUP-7 their sign-in fails")
	ask(other, "just looking")
	bot := w.asServiceAccount(w.acme, service.ScopeAccessRequestsApprove)
	out, ok := w.scriptling(t, bot.bearer, "examples/approve_requests.py", "acme", "SUP-,INC-")
	if !ok || !strings.Contains(out, "Approved "+user.FullName()+" for "+tn.DisplayName) || !strings.Contains(out, "Left for a person: "+other.FullName()) {
		t.Fatalf("bot: %v\n%s", ok, out)
	}
	if acc, err := w.env.Svc.Access.Get(ctx, model.AccessID(tn.ID, user.ID)); err != nil || acc.Expires.IsZero() {
		t.Fatalf("the approved access: %v %+v", err, acc)
	}
	if _, err := w.env.Svc.Access.Get(ctx, model.AccessID(tn.ID, other.ID)); err == nil {
		t.Fatal("the request left for a person was approved")
	}
	out, ok = w.scriptling(t, bot.bearer, "examples/approve_requests.py", "acme", "SUP-", "--deny")
	if !ok || !strings.Contains(out, "Denied "+other.FullName()) {
		t.Fatalf("bot --deny: %v\n%s", ok, out)
	}
}
