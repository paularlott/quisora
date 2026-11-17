package service_test

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/kvstore"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// readCounter is a store that counts the records it hands out (Get, GetByUnique, List): what a call reads.
type readCounter struct {
	store.Store
	n atomic.Int64
}

func (c *readCounter) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	c.n.Add(1)
	return c.Store.Get(ctx, kind, id)
}

func (c *readCounter) GetByUnique(ctx context.Context, kind model.Kind, value string) (*store.Record, error) {
	c.n.Add(1)
	return c.Store.GetByUnique(ctx, kind, value)
}

func (c *readCounter) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	r, err := c.Store.List(ctx, kind, q)
	if r != nil {
		c.n.Add(int64(len(r.Records)))
	}
	return r, err
}

// reads is how many records f read through c; the time it took is logged as what.
func (c *readCounter) reads(t *testing.T, what string, f func()) int64 {
	before := c.n.Load()
	start := time.Now()
	f()
	r := c.n.Load() - before
	t.Logf("%-28s %4d records %10v", what, r, time.Since(start).Round(time.Microsecond))
	return r
}

// An organization with thousands of tenants, each with a client (a vendor whose customers sign in through it: one
// members-only tenant and sign-in client per customer): what a user of it does reads as many records as the answer
// needs, not one per tenant or client. Each path once read the whole organization: the applications a personal API
// token can be for, the tenants with SSH on (the account page), whether a tenant takes self-registered applications
// (dynamic registration), and a person's guest accounts in other organizations (signing them out); deciding a sign-in
// never did, and is held to it too.
func TestManyTenantsReadOnlyWhatIsNeeded(t *testing.T) {
	t.Run("memstore", func(t *testing.T) {
		st := memstore.New()
		t.Cleanup(func() { _ = st.Close() })
		manyTenants(t, st)
	})
	t.Run("badger", func(t *testing.T) {
		st, err := kvstore.OpenBadger(t.Context(), t.TempDir(), kvstore.BadgerOptions{NoSync: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		manyTenants(t, st)
	})
}

func manyTenants(t *testing.T, st store.Store) {
	n := 5000
	if testing.Short() {
		n = 500
	}
	e := newEnvOn(t, st)
	e.svc.Cfg.Server.PublicURL = "https://idp.example.com"
	vendor := e.org("vendor")
	pat := e.user(vendor.ID, "pat", model.RoleUser)

	start := time.Now()
	var last *model.Tenant
	var lastClient *model.Client
	for i := range n {
		tn, err := e.svc.CreateTenant(e.ctx, service.System, vendor.ID, service.TenantInput{Name: ptr("customer-" + strconv.Itoa(i))})
		if err != nil {
			t.Fatal(err)
		}
		c, _, err := e.svc.CreateClient(e.ctx, service.System, vendor.ID, service.ClientInput{Name: ptr("Sign-in to customer " + strconv.Itoa(i)),
			TenantID: &tn.ID, RedirectURIs: &[]string{"https://idp.example.com/cb"}})
		if err != nil {
			t.Fatal(err)
		}
		last, lastClient = tn, c
	}
	t.Logf("%d tenants and clients made in %v", n, time.Since(start).Round(time.Millisecond))
	if _, total, err := e.svc.Tenants.List(e.ctx, store.ListQuery{Scope: vendor.ID, Limit: 1}); err != nil || total != n+1 { // and the default one
		t.Fatalf("the vendor's tenants: %d %v", total, err)
	}
	if _, total, err := e.svc.Clients.List(e.ctx, store.ListQuery{Scope: vendor.ID, Limit: 1}); err != nil || total < n {
		t.Fatalf("the vendor's clients: %d %v", total, err)
	}

	// the few the paths look for: an application taking API tokens, a tenant with SSH on, one taking self-registered
	// applications, and a guest account of pat's in a customer organization
	open := model.DefaultTenantSettings() // new tenants are members-only; this one is everyone's
	tools, err := e.svc.CreateTenant(e.ctx, service.System, vendor.ID, service.TenantInput{Name: ptr("tools"), Settings: &open})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.CreateClient(e.ctx, service.System, vendor.ID, service.ClientInput{Name: ptr("Tools API"), TenantID: &tools.ID,
		RedirectURIs: &[]string{"https://tools.example/cb"}, AcceptsAPITokens: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.UpdateTenantSSH(e.ctx, service.System, tools.ID, service.SSHSettingsInput{Enabled: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	customer := e.org("customer")
	p, err := e.svc.CreateProvider(e.ctx, actor(e.super), customer.ID, service.ProviderInput{Type: ptr(model.ProviderOrganization), SourceOrg: &vendor.ID})
	if err != nil {
		t.Fatal(err)
	}
	guest := e.user(customer.ID, "pat-guest", model.RoleUser)
	if err := e.svc.Identities.Create(e.ctx, model.NewIdentity(e.fresh(guest), p, pat.ID, "", "email")); err != nil {
		t.Fatal(err)
	}

	// pat may sign in to the last customer for a few hours (as an approved access request gives)
	end := time.Now().Add(3 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := e.svc.AddAccess(e.ctx, service.System, last.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: pat.ID,
		Expires: &end}); err != nil {
		t.Fatal(err)
	}

	counter := &readCounter{Store: st}
	svc := service.New(e.svc.Cfg, counter, e.svc.Sealer)
	ctx := e.ctx
	const most = 30 // records any of these may read, whatever n is

	var apps []service.TokenApp
	if r := counter.reads(t, "API token applications", func() { apps, err = svc.TokenApps(ctx, actor(pat)) }); err != nil || len(apps) != 1 || apps[0].Name != "Tools API" || r > most {
		t.Errorf("API token applications: %d records read, %v %+v", r, err, apps)
	}
	var uses []*service.SSHTenantUse
	var blocked []*service.SSHTenantBlocked
	if r := counter.reads(t, "SSH tenants", func() { uses, blocked, err = svc.SSHAccountTenants(ctx, e.fresh(pat), nil) }); err != nil || len(uses)+len(blocked) != 1 || r > most {
		t.Errorf("SSH tenants: %d records read, %v %d %d", r, err, len(uses), len(blocked))
	}
	var takes bool
	if r := counter.reads(t, "self-registration (none)", func() { takes, err = svc.AcceptsSelfRegistered(ctx, vendor.ID) }); err != nil || takes || r > most {
		t.Errorf("self-registration, none taking it: %d records read, %v %v", r, err, takes)
	}
	set := model.DefaultTenantSettings()
	set.SelfRegistration = true
	if _, err := e.svc.UpdateTenant(ctx, service.System, last.ID, service.TenantInput{Settings: &set, Resources: &[]string{"https://mcp.example/mcp"}}); err != nil {
		t.Fatal(err)
	}
	if r := counter.reads(t, "self-registration (one)", func() { takes, err = svc.AcceptsSelfRegistered(ctx, vendor.ID) }); err != nil || !takes || r > most {
		t.Errorf("self-registration, one taking it: %d records read, %v %v", r, err, takes)
	}
	var guests []*model.User
	if r := counter.reads(t, "guest accounts", func() { guests = svc.GuestsOf(ctx, vendor.ID, pat.ID) }); len(guests) != 1 || guests[0].ID != guest.ID || r > most {
		t.Errorf("guest accounts: %d records read, %+v", r, guests)
	}
	if r := counter.reads(t, "deciding a sign-in", func() {
		var app *service.AppAccess
		app, err = svc.ClientAccess(ctx, last, lastClient, e.fresh(pat), nil)
		if err == nil && (!app.Allowed || app.Until.IsZero()) {
			t.Errorf("the customer's sign-in client, with timed access: %+v", app)
		}
	}); err != nil || r > most {
		t.Errorf("deciding a sign-in: %d records read, %v", r, err)
	}
}
