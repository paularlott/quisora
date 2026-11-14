package admin_test

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// addAdmin adds an administrator of Acme under key.
func (w *world) addAdmin(key string) {
	w.t.Helper()
	u, err := w.env.Svc.CreateUser(context.Background(), service.System, w.acme.ID, service.UserInput{GivenName: ptr("T"),
		Username: ptr(key), Email: ptr(key + "@x.example"), Role: ptr(model.RoleAdmin), Password: ptr("correct horse battery")})
	if err != nil {
		w.t.Fatal(err)
	}
	w.users[key] = u
}

// The audit log is shared by every organization, so its pages are read on budgets: an organization's administrators
// share theirs (web.AuditReadsPerMinute a minute), past it they are answered 429 with Retry-After, and nobody else is
// held up by it: another organization, a super admin. A request ListAudit refuses (a manager) spends nothing, so a
// non-administrator cannot hold the administrators out.
func TestAuditReadBudgetPerOrganization(t *testing.T) {
	w := newWorld(t)
	w.addAdmin("bea")
	w.addAdmin("cy")
	mgr := w.as("manager")
	for range 5 {
		want(t, mgr.get(A+"/audit"), 403)
	}
	for _, key := range []string{"admin", "bea"} {
		ad := w.as(key)
		for i := range web.AuditReadsPerMinute / 2 {
			if r := ad.get(A + "/audit?limit=1"); r.Status != 200 {
				t.Fatalf("%s, read %d: %d %s", key, i+1, r.Status, r.Raw)
			}
		}
	}
	r := w.as("cy").get(A + "/audit")
	want(t, r, 429)
	if ra, _ := strconv.Atoi(r.Header.Get("Retry-After")); ra < 1 || !strings.Contains(string(r.Raw), "was searched") {
		t.Fatalf("Retry-After %q: %s", r.Header.Get("Retry-After"), r.Raw)
	}
	// Refused by the organization's budget, not their own: it is given back to their allowance.
	if n, err := w.env.Server.Eph.Incr(context.Background(), "oauth.rate",
		web.AuditBudgetOrg(w.acme.ID)+"|by|user|"+w.users["cy"].ID, 0, time.Minute); err != nil || n != 0 {
		t.Fatalf("a page the organization's budget refused was kept against its reader's allowance: %d %v", n, err)
	}
	want(t, w.as("other").get(G+"/audit"), 200) // another organization
	su := w.as("super")
	want(t, su.get(A+"/audit"), 200) // a super admin, on their own budget
	want(t, su.get("/api/audit?org=acme"), 200)
}

// One administrator cannot spend the organization's whole budget and hold the others out of their own audit log:
// each has web.AuditReadsPerMinuteActor of it, the pages refused past that are not counted against the
// organization, and a second administrator still reads however long the first keeps asking.
func TestAuditReadAllowancePerAdministrator(t *testing.T) {
	w := newWorld(t)
	w.addAdmin("bea")
	ad := w.as("admin")
	for i := range web.AuditReadsPerMinute + 30 {
		r := ad.get(A + "/audit?limit=1")
		if within := i < web.AuditReadsPerMinuteActor; within != (r.Status == 200) || (!within && r.Status != 429) {
			t.Fatalf("read %d: %d %s", i+1, r.Status, r.Raw)
		}
		if r.Status == 429 && (r.Header.Get("Retry-After") != "60" || !strings.Contains(string(r.Raw), "You searched")) {
			t.Fatalf("refusal: Retry-After %q, %s", r.Header.Get("Retry-After"), r.Raw)
		}
	}
	bea := w.as("bea")
	for i := range web.AuditReadsPerMinuteActor {
		if r := bea.get(A + "/audit?limit=1"); r.Status != 200 {
			t.Fatalf("the second administrator, read %d: %d %s", i+1, r.Status, r.Raw)
		}
	}
	// The same person through a token of theirs is the same reader.
	want(t, w.withBearer("admin", service.ScopeAdmin).get(A+"/audit"), 429)
}

// contendedCounters is the server's short-lived state with counters that cannot be kept: Incr reports
// ephemeral.Contended, as it does when this node's counters are at their cap.
type contendedCounters struct{ ephemeral.Store }

func (contendedCounters) Incr(context.Context, string, string, int64, time.Duration) (int64, error) {
	return ephemeral.Contended, nil
}

// While the counters cannot be kept (at their cap under a flood of other counters, or too contended), an
// administrator still reads the audit log: the places and the timeout bound the load, and the page is not refused
// with a 429 that says the log was searched 120 times when it was not.
func TestAuditReadWhileCountersAreContended(t *testing.T) {
	w := newWorld(t)
	w.env.Server.Eph = contendedCounters{w.env.Server.Eph}
	want(t, w.as("admin").get(A+"/audit"), 200)
	want(t, w.as("super").get("/api/audit"), 200)
}

// stuckBudget is short-lived state whose counts of the audit pages' budgets never answer (an owner in a gossip
// cluster that does not reply) until the request's context ends.
type stuckBudget struct{ ephemeral.Store }

func (s stuckBudget) Incr(ctx context.Context, ns, key string, delta int64, window time.Duration) (int64, error) {
	if strings.HasPrefix(key, "audit-read|") {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	return s.Store.Incr(ctx, ns, key, delta, window)
}

// Counting an audit page against its budget is bounded as the read is (web.AuditReadTimeout): a count that does not
// answer is given up (503) and the place it holds is free again, so pages whose counts hang cannot hold the node's
// places for as long as the client waits.
func TestAuditBudgetCountTimesOut(t *testing.T) {
	limit := web.AuditReadTimeout
	t.Cleanup(func() { web.AuditReadTimeout = limit })
	web.AuditReadTimeout = 200 * time.Millisecond
	w := newWorld(t)
	w.env.Server.Eph = stuckBudget{w.env.Server.Eph}
	ad := w.as("admin")
	for range web.AuditReadsInFlightPerBudget + 1 { // one after another: each gets the place the last gave up
		done := make(chan resp, 1)
		go func() { done <- ad.get(A + "/audit") }()
		select {
		case r := <-done:
			want(t, r, 503)
		case <-time.After(10 * time.Second):
			t.Fatal("a page whose count does not answer was held past the timeout")
		}
	}
}

// gatedReader is an audit log whose reads of one organization wait until release is closed, counting them in entered.
type gatedReader struct {
	org     string
	entered chan struct{}
	release chan struct{}
}

func (g gatedReader) ReadAudit(ctx context.Context, q service.AuditQuery) (service.AuditPage, error) {
	if q.Org == g.org {
		g.entered <- struct{}{}
		select {
		case <-g.release:
		case <-ctx.Done():
		}
	}
	return service.AuditPage{Items: nil, Nodes: 1, Answered: 1, Source: "victorialogs"}, nil
}

// Slow searches of one organization take at most web.AuditReadsInFlightPerBudget of the pages a node reads at once:
// the next of that organization is answered 429 (Retry-After) at once rather than added to the load, another
// organization's page is read, and the place is free again once a search ends. The pages refused for want of a place
// spend nothing of the organization's budget or of their reader's allowance: a client that retries every
// Retry-After while the node is busy has its minute's pages left when the searches end.
func TestAuditReadsInFlightPerOrganization(t *testing.T) {
	w := newWorld(t)
	w.addAdmin("bea")
	g := gatedReader{org: w.acme.ID, entered: make(chan struct{}, web.AuditReadsInFlightPerBudget+1), release: make(chan struct{})}
	w.env.Svc.AuditReader = g
	ad := w.as("admin")
	var wg sync.WaitGroup
	statuses := make(chan int, web.AuditReadsInFlightPerBudget)
	for range web.AuditReadsInFlightPerBudget {
		wg.Add(1)
		go func() { defer wg.Done(); statuses <- ad.get(A + "/audit").Status }()
	}
	released := false
	defer func() {
		if !released {
			close(g.release)
		}
		wg.Wait()
	}()
	for i := range web.AuditReadsInFlightPerBudget {
		select {
		case <-g.entered:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d searches started", i)
		}
	}
	// One more must be refused at once, not read (or queued) while the others hold their places.
	over := make(chan resp, 1)
	wg.Add(1)
	go func() { defer wg.Done(); over <- ad.get(A + "/audit") }()
	select {
	case r := <-over:
		want(t, r, 429)
		if r.Header.Get("Retry-After") != "2" {
			t.Fatalf("Retry-After %q", r.Header.Get("Retry-After"))
		}
	case <-g.entered:
		t.Fatal("a search past the organization's places was read")
	case <-time.After(10 * time.Second):
		t.Fatal("a search past the organization's places was held")
	}
	bea := w.as("bea")
	for range web.AuditReadsPerMinute + 10 { // a console retrying while the node is busy
		if r := bea.get(A + "/audit"); r.Status != 429 || r.Header.Get("Retry-After") != "2" {
			t.Fatalf("while the places are taken: %d, Retry-After %q", r.Status, r.Header.Get("Retry-After"))
		}
	}
	want(t, w.as("other").get(G+"/audit"), 200)
	close(g.release)
	released = true
	wg.Wait()
	close(statuses)
	for st := range statuses {
		if st != 200 {
			t.Fatalf("a search held up: %d", st)
		}
	}
	want(t, ad.get(A+"/audit"), 200)  // (released: the reader no longer waits; entered has room for it)
	want(t, bea.get(A+"/audit"), 200) // the refusals spent nothing
}

// An audit page that the log does not answer is given up after web.AuditReadTimeout, whichever log it is read from,
// with a 503 and Retry-After, and its place is free again: a search cannot hold a place for as long as the log
// takes.
func TestAuditReadTimesOut(t *testing.T) {
	limit := web.AuditReadTimeout
	t.Cleanup(func() { web.AuditReadTimeout = limit })
	web.AuditReadTimeout = 200 * time.Millisecond
	w := newWorld(t)
	g := gatedReader{org: w.acme.ID, entered: make(chan struct{}, 8), release: make(chan struct{})}
	defer close(g.release)
	w.env.Svc.AuditReader = hangingReader{g}
	ad := w.as("admin")
	for range web.AuditReadsInFlightPerBudget + 1 { // one after another: each gets the place the last gave up
		done := make(chan resp, 1)
		go func() { done <- ad.get(A + "/audit") }()
		select {
		case r := <-done:
			want(t, r, 503)
			if r.Header.Get("Retry-After") == "" || !strings.Contains(string(r.Raw), "too long") {
				t.Fatalf("Retry-After %q: %s", r.Header.Get("Retry-After"), r.Raw)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a page the log does not answer was held past the timeout")
		}
	}
}

// hangingReader is gatedReader that answers a read given up as a log does: with the context's error.
type hangingReader struct{ gatedReader }

func (h hangingReader) ReadAudit(ctx context.Context, q service.AuditQuery) (service.AuditPage, error) {
	p, err := h.gatedReader.ReadAudit(ctx, q)
	if ctx.Err() != nil {
		return service.AuditPage{}, ctx.Err()
	}
	return p, err
}

// slowOrgs is an audit log whose reads of any one organization wait until release is closed, counting them in
// entered; the log of every organization together (a super admin's page) answers at once.
type slowOrgs struct {
	entered chan struct{}
	release chan struct{}
}

func (g slowOrgs) ReadAudit(ctx context.Context, q service.AuditQuery) (service.AuditPage, error) {
	if q.Org != "" {
		g.entered <- struct{}{}
		select {
		case <-g.release:
		case <-ctx.Done():
		}
	}
	return service.AuditPage{Items: nil, Nodes: 1, Answered: 1, Source: "victorialogs"}, nil
}

// However many organizations search slowly at once, a super admin still reads the log: some of the node's places
// are kept for the super admins, so the organizations' searches cannot hold them all. (Four organizations with four
// slow searches each once held all 16, and every other organization and every operator was answered 429.)
func TestSlowOrganizationsCannotHoldOutSuperAdmins(t *testing.T) {
	w := newWorld(t)
	const orgs = 8
	searches := orgs * web.AuditReadsInFlightPerBudget
	g := slowOrgs{entered: make(chan struct{}, searches), release: make(chan struct{})}
	w.env.Svc.AuditReader = g
	st := model.DefaultOrgSettings()
	var wg sync.WaitGroup
	defer wg.Wait()
	defer close(g.release)
	refused := make(chan struct{}, searches)
	for i := range orgs {
		name := "slow" + strconv.Itoa(i)
		o, err := w.env.Svc.CreateOrg(context.Background(), service.System, service.OrgInput{Name: ptr(name), DisplayName: ptr(name), Settings: &st})
		if err != nil {
			t.Fatal(err)
		}
		u, err := w.env.Svc.CreateUser(context.Background(), service.System, o.ID, service.UserInput{GivenName: ptr("T"),
			Username: ptr("ada"), Email: ptr("ada@" + name + ".example"), Role: ptr(model.RoleAdmin), Password: ptr("correct horse battery")})
		if err != nil {
			t.Fatal(err)
		}
		w.users[name] = u
		ad := w.as(name)
		for range web.AuditReadsInFlightPerBudget {
			wg.Go(func() {
				if ad.get("/api/orgs/"+name+"/audit").Status == 429 {
					refused <- struct{}{}
				}
			})
		}
	}
	for i := range searches { // every search is being read, or was refused for want of a place
		select {
		case <-g.entered:
		case <-refused:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d searches started or were refused", i, searches)
		}
	}
	su := w.as("super")
	want(t, su.get("/api/audit"), 200)
	want(t, su.get("/api/audit?limit=1"), 200)
}
