package service_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/kvstore"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// Access requests in a busy organization: thousands of open tenants beside a few members-only ones, an approver group
// with hundreds of finished requests behind the few that run, a person with a long history. Each list reads the page
// it shows (and pages exactly: total, offset, two approver groups merged), not the organization's or a group's or a
// person's history; the account menu's roles are read once an hour, again after a group change.
func TestAccessRequestsReadOnlyWhatTheyShow(t *testing.T) {
	t.Run("memstore", func(t *testing.T) {
		st := memstore.New()
		t.Cleanup(func() { _ = st.Close() })
		busyRequests(t, st)
	})
	t.Run("badger", func(t *testing.T) {
		st, err := kvstore.OpenBadger(t.Context(), t.TempDir(), kvstore.BadgerOptions{NoSync: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		busyRequests(t, st)
	})
}

func busyRequests(t *testing.T, st store.Store) {
	openTenants, history := 2000, 600
	if testing.Short() {
		openTenants, history = 300, 150
	}
	e := newEnvOn(t, st)
	ctx := e.ctx
	org := e.org("vendor")
	admin := e.user(org.ID, "admin", model.RoleAdmin)
	pat := e.user(org.ID, "pat", model.RoleUser)
	alex := e.user(org.ID, "alex", model.RoleUser)

	// alex approves for two requester groups, through two approver groups
	group := func(name string, members []string, in *service.GroupRequestsInput) *model.Group {
		t.Helper()
		g, err := e.svc.CreateGroupWithMembers(ctx, service.System, org.ID, service.GroupInput{DisplayName: ptr(name), AccessRequests: in,
			ApprovesRequests: ptr(in == nil)}, members)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	leads := group("On-call leads", []string{alex.ID}, nil)
	managers := group("Account managers", []string{alex.ID}, nil)
	group("On-call", []string{pat.ID}, &service.GroupRequestsInput{Enabled: true, Approvers: leads.ID, ServiceAccounts: true})
	group("Sales", []string{pat.ID}, &service.GroupRequestsInput{Enabled: true, Approvers: managers.ID})

	open := model.DefaultTenantSettings()
	var tenants []*model.Tenant
	for i := range openTenants {
		tn, err := e.svc.CreateTenant(ctx, service.System, org.ID, service.TenantInput{Name: ptr("open-" + strconv.Itoa(i)), Settings: &open})
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, tn)
	}
	var customers []*model.Tenant
	for _, name := range []string{"customer-a", "customer-b", "customer-c"} {
		tn, err := e.svc.CreateTenant(ctx, service.System, org.ID, service.TenantInput{Name: ptr(name)}) // members-only
		if err != nil {
			t.Fatal(err)
		}
		customers = append(customers, tn)
	}

	// the history, as housekeeping leaves it: finished requests of both approver groups, and pat's
	now := time.Now().UTC()
	put := func(r *model.AccessRequest) {
		t.Helper()
		r.ID, r.OrgID = model.NewID(), org.ID
		if err := e.svc.Requests.Create(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	for i := range history {
		g := leads.ID
		if i%2 == 1 {
			g = managers.ID
		}
		put(&model.AccessRequest{TenantID: tenants[i%openTenants].ID, UserID: pat.ID, Approvers: g, Length: 3600, Reason: "old",
			State: model.RequestExpired, DecidedAt: now.Add(-48 * time.Hour), Ends: now.Add(-47 * time.Hour)})
	}
	// what runs: 5 through the leads, 3 through the managers; and what waits: 30 for the leads (20 a bot may decide), 4
	// for the managers
	for i := range 8 {
		g := leads.ID
		if i >= 5 {
			g = managers.ID
		}
		put(&model.AccessRequest{TenantID: tenants[i].ID, UserID: pat.ID, Approvers: g, Length: 3600, Reason: "now",
			State: model.RequestApproved, DecidedAt: now, Ends: now.Add(time.Duration(i+1) * time.Hour)})
	}
	for i := range 34 {
		g := leads.ID
		if i >= 30 {
			g = managers.ID
		}
		put(&model.AccessRequest{TenantID: tenants[100+i].ID, UserID: pat.ID, Approvers: g, Length: 3600, Reason: "waiting",
			State: model.RequestPending, Lapses: now.Add(time.Hour), Bots: g == leads.ID && i < 20})
	}

	counter := &readCounter{Store: st}
	svc := service.New(e.svc.Cfg, counter, e.svc.Sealer)
	const most = 40 // records any of these may read, however many tenants and requests there are
	var err error

	// the request form's tenants: the members-only ones only, however many are open
	var found []service.RequestableTenant
	if r := counter.reads(t, "requestable tenants", func() { found, err = svc.RequestableTenants(ctx, actor(pat), "", 20) }); err != nil || len(found) != 3 || r > most {
		t.Errorf("requestable tenants: %d records read, %v %d", r, err, len(found))
	}
	if r := counter.reads(t, "requestable tenants (q)", func() { found, err = svc.RequestableTenants(ctx, actor(pat), "customer-b", 20) }); err != nil || len(found) != 1 || r > most {
		t.Errorf("requestable tenants matching: %d records read, %v %d", r, err, len(found))
	}

	// the account menu: read once, then kept until a group changes
	var asks, approves bool
	if r := counter.reads(t, "menu roles", func() { asks, approves = svc.AccessRequestRoles(ctx, alex) }); asks || !approves || r > most {
		t.Errorf("alex's menu roles: %d records read, %v %v", r, asks, approves)
	}
	if r := counter.reads(t, "menu roles (kept)", func() { asks, approves = svc.AccessRequestRoles(ctx, pat) }); !asks || approves || r > most {
		t.Errorf("pat's menu roles: %d records read, %v %v", r, asks, approves)
	}
	if r := counter.reads(t, "menu roles (again)", func() { svc.AccessRequestRoles(ctx, alex) }); r != 0 {
		t.Errorf("alex's menu roles again: %d records read, want none", r)
	}
	if _, err := svc.UpdateGroup(ctx, actor(admin), managers.ID, service.GroupInput{DisplayName: ptr("Account leads")}); err != nil {
		t.Fatal(err)
	}
	svc.InvalidateRequestGroups() // as the cluster's change hook does for any group written, here or elsewhere
	if r := counter.reads(t, "menu roles (group changed)", func() { svc.AccessRequestRoles(ctx, alex) }); r == 0 {
		t.Error("alex's menu roles after a group changed: read nothing, want them read again")
	}

	// the approver's waiting requests: both queues merged, oldest first, paged exactly
	var page []*model.AccessRequest
	var total int
	seen := map[string]bool{}
	for offset := 0; offset < 34; offset += 10 {
		if r := counter.reads(t, "approver queue page", func() {
			page, total, err = svc.ApprovalQueue(ctx, actor(alex), store.ListQuery{Offset: offset, Limit: 10})
		}); err != nil || total != 34 || len(page) != min(10, 34-offset) || r > int64(most+offset) {
			t.Fatalf("alex's queue at %d: %d records read, %v total %d, %d on the page", offset, r, err, total, len(page))
		}
		for i, p := range page {
			if seen[p.ID] || i > 0 && p.Created.Before(page[i-1].Created) {
				t.Fatalf("alex's queue at %d: %s twice, or out of order", offset, p.ID)
			}
			seen[p.ID] = true
		}
	}
	// a service account's: the requests it may decide, paged in the store
	sa, _, err := e.svc.CreateServiceAccount(ctx, actor(admin), org.ID, service.ServiceAccountInput{Name: ptr("bot"),
		Scopes: &[]string{service.ScopeAccessRequestsApprove}})
	if err != nil {
		t.Fatal(err)
	}
	bot := service.ActorForServiceAccount(sa, sa.Scopes, "127.0.0.1")
	if r := counter.reads(t, "bot queue page", func() { page, total, err = svc.ApprovalQueue(ctx, bot, store.ListQuery{Limit: 10}) }); err != nil || total != 20 || len(page) != 10 || r > most {
		t.Errorf("the bot's queue: %d records read, %v total %d, %d on the page", r, err, total, len(page))
	}

	// the access the approver's groups gave that runs: 8, behind hundreds that ran out
	if r := counter.reads(t, "running access page 1", func() {
		page, total, err = svc.GroupDecisions(ctx, actor(alex), service.DecisionsActive, store.ListQuery{Limit: 5})
	}); err != nil || total != 8 || len(page) != 5 || r > most {
		t.Errorf("running access, page 1: %d records read, %v total %d, %d on the page", r, err, total, len(page))
	}
	if r := counter.reads(t, "running access page 2", func() {
		page, total, err = svc.GroupDecisions(ctx, actor(alex), service.DecisionsActive, store.ListQuery{Offset: 5, Limit: 5})
	}); err != nil || total != 8 || len(page) != 3 || r > most {
		t.Errorf("running access, page 2: %d records read, %v total %d, %d on the page", r, err, total, len(page))
	}

	// the groups' decisions: the ended ones, behind the running ones, and found by a search of their reason
	if r := counter.reads(t, "ended decisions page", func() {
		page, total, err = svc.GroupDecisions(ctx, actor(alex), service.DecisionsEnded, store.ListQuery{Limit: 10})
	}); err != nil || total != history || len(page) != 10 || r > most {
		t.Errorf("ended decisions: %d records read, %v total %d, %d on the page", r, err, total, len(page))
	}
	if _, total, err = svc.GroupDecisions(ctx, actor(alex), service.DecisionsAll, store.ListQuery{Limit: 10}); err != nil || total != history+8 {
		t.Errorf("all decisions: %v %d, want %d", err, total, history+8)
	}
	if _, total, err = svc.GroupDecisions(ctx, actor(alex), service.DecisionsDenied, store.ListQuery{Limit: 10}); err != nil || total != 0 {
		t.Errorf("denied decisions: %v %d", err, total)
	}
	if _, total, err = svc.GroupDecisions(ctx, actor(alex), service.DecisionsAll, store.ListQuery{Limit: 10, Search: "NOW"}); err != nil || total != 8 {
		t.Errorf("decisions whose reason starts with now: %v %d, want 8", err, total)
	}

	// pat's own requests: a page of a long history
	if r := counter.reads(t, "own requests page", func() { page, total, err = svc.OwnAccessRequests(ctx, actor(pat), store.ListQuery{Limit: 10}) }); err != nil || total != history+8+34 || len(page) != 10 || r > most {
		t.Errorf("pat's requests: %d records read, %v total %d, %d on the page", r, err, total, len(page))
	}

	// asking counts pat's waiting requests, not their history: pat has 34 waiting, more than the limit of 10
	if r := counter.reads(t, "asking (over the limit)", func() {
		_, err = svc.CreateAccessRequest(ctx, actor(pat), service.AccessRequestInput{TenantID: customers[0].ID, Approvers: leads.ID, Length: 3600, Reason: "x"})
	}); fieldOfErr(err) != "tenant_id" || r > most {
		t.Errorf("asking with 34 waiting: %d records read, %v", r, err)
	}

	// ending one of two running requests for a tenant (an extension) ends the other too, found among pat's history
	ext := &model.AccessRequest{TenantID: tenants[0].ID, UserID: pat.ID, Approvers: leads.ID, Length: 3600, Reason: "more",
		State: model.RequestApproved, DecidedAt: now, Ends: now.Add(9 * time.Hour)}
	put(ext)
	if err := e.svc.Access.Create(ctx, &model.TenantAccess{Meta: model.Meta{ID: model.AccessID(tenants[0].ID, pat.ID)}, OrgID: org.ID,
		TenantID: tenants[0].ID, SubjectType: model.SubjectUser, SubjectID: pat.ID, AllClients: true, Expires: ext.Ends}); err != nil {
		t.Fatal(err)
	}
	if r := counter.reads(t, "ending an extension", func() { _, err = svc.EndAccessRequest(ctx, actor(pat), ext.ID, false) }); err != nil || r > most {
		t.Errorf("ending: %d records read, %v", r, err)
	}
	l, _, err := e.svc.Requests.List(ctx, store.ListQuery{Scope: org.ID, Filters: []store.Filter{
		{Field: "running", Value: model.AccessRequestRunning(pat.ID, tenants[0].ID)}}})
	if err != nil || len(l) != 0 {
		t.Errorf("pat's running requests for the tenant after ending one: %v %d, want none", err, len(l))
	}

	// housekeeping marks running requests expired at their end: they leave the approvers' list
	first, _, err := e.svc.Requests.List(ctx, store.ListQuery{Scope: org.ID, Filters: []store.Filter{
		{Field: "running", Value: model.AccessRequestRunning(pat.ID, tenants[1].ID)}}})
	if err != nil || len(first) != 1 {
		t.Fatalf("pat's running request for tenant 1: %v %d", err, len(first))
	}
	first[0].Ends = now.Add(-time.Second)
	if err := e.svc.Requests.Update(ctx, first[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ExpireAccessRequests(ctx); err != nil {
		t.Fatal(err)
	}
	if r, err := e.svc.Requests.Get(ctx, first[0].ID); err != nil || r.State != model.RequestExpired {
		t.Errorf("a running request past its end after housekeeping: %v %+v", err, r)
	}
	if _, total, err = svc.GroupDecisions(ctx, actor(alex), service.DecisionsActive, store.ListQuery{Limit: 5}); err != nil || total != 6 {
		t.Errorf("running access after one ended and one ran out: %v %d, want 6", err, total)
	}
}
