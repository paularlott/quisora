package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/metrics"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/queue"
	"github.com/paularlott/quisora/internal/service"
)

func TestBackchannelLogoutAPIAndFailures(t *testing.T) {
	t.Parallel()
	rp := newRP()
	defer rp.Close()
	failing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) }))
	defer failing.Close()
	h := setup(t, nil)
	good, gs := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL) })
	bad, bs := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(failing.URL) })
	c, _ := h.session(h.user)
	for _, cs := range []struct {
		cl *model.Client
		s  string
	}{{good, gs}, {bad, bs}} {
		v, ch := pkce()
		code := h.getCode(c, cs.cl, ch, nil)
		if r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}}, cs.cl, cs.s); r.status != 200 {
			t.Fatal(r.m)
		}
	}
	list, _ := h.env.Svc.Sessions.All(context.Background(), h.user.ID)
	var ids []string
	for _, s := range list {
		ids = append(ids, s.ID)
	}
	h.p.BackchannelLogout(context.Background(), ids...)
	h.p.Wait() // the failing RP must not block or panic anything
	select {
	case <-rp.got:
	default:
		t.Fatal("API did not deliver the logout token")
	}
	h.p.BackchannelLogoutUser(context.Background(), h.user.ID)
	h.p.Wait()
	select {
	case <-rp.got:
	default:
		t.Fatal("BackchannelLogoutUser did not deliver")
	}
}

// An application whose refresh grant was revoked still holds the user's sign-in: it is told when the session ends.
func TestBackchannelAfterGrantRevoked(t *testing.T) {
	t.Parallel()
	rp := newRP()
	defer rp.Close()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL + "/logout") })
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	r := h.exchangeCode(cl, secret, code, v)
	if r.status != 200 {
		t.Fatal(r.m)
	}
	// the application revokes its refresh token: no grant is left on the session
	if res := h.clientPost(h.orgBase+"/oauth/revoke", url.Values{"token": {r.str("refresh_token")}}, cl, secret); res.status != 200 {
		t.Fatalf("revoke: %d", res.status)
	}
	if gs, _ := h.env.Svc.Grants.All(context.Background(), h.user.ID); len(gs) != 0 {
		t.Fatalf("grants left: %d", len(gs))
	}
	// the user signs out everywhere
	if err := h.env.Svc.RevokeSessions(context.Background(), h.admin, h.user.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case lt := <-rp.got:
		if claimsOf(t, lt)["aud"] != cl.ID {
			t.Fatal("logout token for another client")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an application without a grant was not told its session ended")
	}
	h.p.Wait()
}

// Revoking sessions through the service (admin "sign out everywhere", disabling a user) must reach the relying
// party's back-channel endpoint, not only RP-initiated logout.
func TestBackchannelOnServiceRevocation(t *testing.T) {
	t.Parallel()
	for name, revoke := range map[string]func(h *harness){
		"revoke sessions": func(h *harness) {
			if err := h.env.Svc.RevokeSessions(context.Background(), service.System, h.user.ID); err != nil {
				t.Fatal(err)
			}
		},
		"disable user": func(h *harness) {
			f := false
			if _, err := h.env.Svc.UpdateUser(context.Background(), service.System, h.user.ID, service.UserInput{Active: &f}); err != nil {
				t.Fatal(err)
			}
		},
		"session delete": func(h *harness) {
			list, _ := h.env.Svc.Sessions.All(context.Background(), h.user.ID)
			for _, s := range list {
				_ = h.env.Server.Sessions.Delete(context.Background(), s.ID)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			rp := newRP()
			defer rp.Close()
			h := setup(t, nil)
			cl, sec := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL) })
			c, _ := h.session(h.user)
			v, ch := pkce()
			code := h.getCode(c, cl, ch, nil)
			if r := h.exchangeCode(cl, sec, code, v); r.status != 200 {
				t.Fatal(r.m)
			}
			revoke(h)
			h.p.Wait()
			select {
			case <-rp.got:
			default:
				t.Fatal("no back-channel logout token delivered")
			}
		})
	}
}

// Removing one application's access from the account page signs the user out of that application (back-channel
// logout) and kills its refresh token at once; other applications are not contacted.
func TestBackchannelOnAppAccessRemoved(t *testing.T) {
	t.Parallel()
	rp, other := newRP(), newRP()
	defer rp.Close()
	defer other.Close()
	h := setup(t, nil)
	cl, sec := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL) })
	cl2, sec2 := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(other.URL) })
	c, _ := h.session(h.user)
	refresh := map[string]string{}
	for _, x := range []struct {
		cl  *model.Client
		sec string
	}{{cl, sec}, {cl2, sec2}} {
		v, ch := pkce()
		code := h.getCode(c, x.cl, ch, url.Values{"scope": {"openid offline_access"}})
		r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback}, "code_verifier": {v}}, x.cl, x.sec)
		if r.status != 200 || r.str("refresh_token") == "" {
			t.Fatal(r.m)
		}
		refresh[x.cl.ID] = r.str("refresh_token")
	}
	// warm the grant cache: a cached "alive" must not outlive the removal
	if r := h.refreshWith(cl, sec, refresh[cl.ID]); r.status != 200 {
		t.Fatal(r.m)
	}
	refresh[cl.ID] = h.refreshWith(cl, sec, refresh[cl.ID]).str("refresh_token")

	n, err := h.env.Svc.RevokeAppAccess(context.Background(), h.user.ID, cl.ID)
	if err != nil || n == 0 {
		t.Fatalf("revoke: %d %v", n, err)
	}
	h.p.Wait()
	select {
	case tok := <-rp.got:
		if claimsOf(t, tok)["sub"] != h.user.ID {
			t.Fatalf("logout token for the wrong user: %s", tok)
		}
	default:
		t.Fatal("no back-channel logout token delivered")
	}
	select {
	case <-other.got:
		t.Fatal("another application was signed out")
	default:
	}
	if r := h.refreshWith(cl, sec, refresh[cl.ID]); r.status == 200 {
		t.Fatal("refresh token still works after access was removed")
	}
	if r := h.refreshWith(cl2, sec2, refresh[cl2.ID]); r.status != 200 {
		t.Fatalf("the other application's refresh token stopped working: %v", r.m)
	}
	if n, _ := h.env.Svc.RevokeAppAccess(context.Background(), h.user.ID, cl.ID); n != 0 {
		t.Fatalf("second removal found %d grants", n)
	}
}

// A sign-out of very many sessions queues their back-channel logouts for a bounded number of senders per organization:
// it does not start a sender per logout, and what the organization's share of the queue cannot hold goes to the retry
// queue on disk, not memory. A logout that fails on the way (a connection the relying party closed, under load) is
// retried from there too: none of those queued is lost.
func TestBackchannelFanOutBounded(t *testing.T) {
	release := make(chan struct{})
	var got, inFlight, mostInFlight atomic.Int64
	rp, _ := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		for m := mostInFlight.Load(); n > m && !mostInFlight.CompareAndSwap(m, n); m = mostInFlight.Load() {
		}
		<-release
		inFlight.Add(-1)
		got.Add(1)
	})
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }
	defer open() // a failure does not leave handlers holding the server
	h := setup(t, nil)
	withLogoutBackoff(t, 500*time.Millisecond, 10*time.Millisecond, 10*time.Millisecond)
	retries := h.p.OpenLogoutQueue("node-1")
	defer retries.Close()
	cl, _ := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL) })
	ce, err := h.p.client(t.Context(), cl.OrgID, cl.ID)
	if err != nil {
		t.Fatal(err)
	}
	const overflow = 100
	targets := make([]bcTarget, bcOrgQueueMax+overflow)
	for i := range targets {
		targets[i] = bcTarget{client: ce.c, sub: "user", sid: "s"}
	}
	h.p.dispatch(targets, nil)
	// the organization's senders are all busy with a request the relying party holds, and no more than its share are
	deadline := time.Now().Add(10 * time.Second)
	for inFlight.Load() < bcOrgWorkersMax && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // for any further sender that should not start
	h.p.bcMu.Lock()
	queued := h.p.bcQueued
	h.p.bcMu.Unlock()
	if m := mostInFlight.Load(); m != bcOrgWorkersMax {
		t.Fatalf("up to %d logouts in flight for %d queued, want the organization's %d senders", m, len(targets), bcOrgWorkersMax)
	}
	if queued > bcOrgQueueMax {
		t.Fatalf("queue holds %d, want at most %d for one organization", queued, bcOrgQueueMax)
	}
	// what did not fit is on disk, waiting for its first try
	for retries.Queued() < overflow && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if n := retries.Queued(); n != overflow {
		t.Fatalf("%d logouts in the retry queue, want the %d that did not fit", n, overflow)
	}
	open()
	h.p.Wait()
	for retries.Queued() > 0 && time.Now().Before(deadline.Add(20*time.Second)) {
		time.Sleep(10 * time.Millisecond)
	}
	// Each logout arrives (a retried one may arrive twice: the first attempt can reach the relying party and still
	// fail on the way back).
	if n := got.Load(); n < int64(len(targets)) || n > int64(len(targets)+2*bcWorkersMax) || retries.Queued() > 0 {
		t.Fatalf("%d logouts sent, want the %d queued; %d waiting to retry", n, len(targets), retries.Queued())
	}
}

// An organization whose applications never answer holds only its own share of the senders and of the queue: another
// organization's logout is sent at once, though the first has far more queued than the queue can hold.
func TestBackchannelOrganizationsDoNotStarveEachOther(t *testing.T) {
	release := make(chan struct{})
	var stuck atomic.Int64
	tarpit, _ := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		stuck.Add(1)
		<-release
	})
	delivered := make(chan struct{}, 1)
	fast, _ := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) { delivered <- struct{}{} })
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }
	defer open() // a failure does not leave handlers holding the server
	h := setup(t, nil)
	ctx := context.Background()
	slow, _ := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(tarpit.URL) })
	slowEntry, err := h.p.client(ctx, slow.OrgID, slow.ID)
	if err != nil {
		t.Fatal(err)
	}
	org2, err := h.env.Svc.CreateOrg(ctx, h.admin, service.OrgInput{Name: ptr("acme"), DisplayName: ptr("Acme")})
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := h.env.Svc.CreateClient(ctx, h.admin, org2.ID, service.ClientInput{Name: ptr("other"),
		GrantTypes: &[]string{"client_credentials"}, BackchannelURI: ptr(fast.URL)})
	if err != nil {
		t.Fatal(err)
	}
	flood := make([]bcTarget, 2*bcQueueMax)
	for i := range flood {
		flood[i] = bcTarget{client: slowEntry.c, sub: "user", sid: "s"}
	}
	h.p.dispatch(flood, nil)
	deadline := time.Now().Add(10 * time.Second)
	for stuck.Load() < bcOrgWorkersMax && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	h.p.dispatch([]bcTarget{{client: other, sub: "user", sid: "s"}}, nil)
	select {
	case <-delivered:
	case <-time.After(3 * time.Second):
		t.Fatal("another organization's logout was not sent while one organization's applications do not answer")
	}
	if n := stuck.Load(); n > bcOrgWorkersMax {
		t.Fatalf("%d requests to the unresponsive organization's application at once, want at most %d", n, bcOrgWorkersMax)
	}
	open()
	h.p.Wait()
}

// A few organizations at their share of the queue at once do not fill it between them: each holds no more than the
// room left for the others, so a fifth organization's logout still finds a place.
func TestBackchannelQueueLeavesRoomForAnotherOrganization(t *testing.T) {
	release := make(chan struct{})
	tarpit, _ := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) { <-release })
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }
	defer open()
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(tarpit.URL) })
	ce, err := h.p.client(t.Context(), cl.OrgID, cl.ID)
	if err != nil {
		t.Fatal(err)
	}
	of := func(org string) *model.Client { c := *ce.c; c.OrgID = org; return &c }
	var targets []bcTarget
	for range bcOrgQueueMax {
		for _, org := range []string{"o1", "o2", "o3", "o4"} {
			targets = append(targets, bcTarget{client: of(org), sub: "user", sid: "s"})
		}
	}
	targets = append(targets, bcTarget{client: of("o5"), sub: "user", sid: "s"})
	h.p.dispatch(targets, nil)
	h.p.bcMu.Lock()
	o5 := h.p.bcOrgs["o5"]
	h.p.bcMu.Unlock()
	if o5 == nil {
		t.Fatal("four organizations at their share left no room for a fifth's logout")
	}
	open()
	h.p.Wait()
}

// A logout the relying party refuses is tried again from the retry queue until it is taken or the retries are used up,
// and one for an application that stopped wanting notices (or went) before its retry is never sent.
func TestBackchannelRetry(t *testing.T) {
	// requests counts by path, so each application is told apart
	requests := map[string]*atomic.Int64{}
	for _, name := range []string{"/recovers", "/refuses", "/disabled", "/deleted"} {
		requests[name] = new(atomic.Int64)
	}
	rp, _ := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := requests[r.URL.Path].Add(1)
		if r.URL.Path != "/recovers" || n < 3 { // /recovers takes the third attempt, every other path always refuses
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
	h := setup(t, nil)
	ctx := context.Background()
	withLogoutBackoff(t, 5*time.Millisecond, 5*time.Millisecond)
	retries := h.p.OpenLogoutQueue("node-1")
	defer retries.Close()
	app := func(path string) *model.Client {
		c, _ := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL + path) })
		return c
	}
	recovers, refuses, disabled, deleted := app("/recovers"), app("/refuses"), app("/disabled"), app("/deleted")
	entry := func(c *model.Client) *clientEntry {
		ce, err := h.p.client(ctx, c.OrgID, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		return ce
	}
	// the retries below are queued as if earlier attempts had failed; the application's state is read when they fire
	if _, err := h.env.Svc.UpdateClient(ctx, h.admin, disabled.ID, service.ClientInput{Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if err := h.env.Svc.DeleteClient(ctx, h.admin, deleted.ID); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(disabled.ID)
	h.p.InvalidateClient(deleted.ID)
	for _, c := range []*model.Client{disabled, deleted} {
		if err := retries.Add(LogoutRetry{OrgID: c.OrgID, ClientID: c.ID, Sub: "u", SID: "s"}, 20*time.Millisecond, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := retries.Add(LogoutRetry{ClientID: "nosuchclient", Sub: "u"}, 20*time.Millisecond, 1); err != nil {
		t.Fatal(err)
	}
	h.p.dispatch([]bcTarget{{client: entry(recovers).c, sub: "u", sid: "s"}, {client: entry(refuses).c, sub: "u", sid: "s"}}, nil)
	h.p.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for (requests["/recovers"].Load() < 3 || requests["/refuses"].Load() < 3 || retries.Queued() > 0) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := requests["/recovers"].Load(); n != 3 {
		t.Errorf("the application that recovers was told %d times, want 3", n)
	}
	// one attempt, then a retry for each wait in the backoff list, then it is given up on
	if n := requests["/refuses"].Load(); n != 3 {
		t.Errorf("the application that keeps refusing was told %d times, want 3", n)
	}
	for _, path := range []string{"/disabled", "/deleted"} {
		if n := requests[path].Load(); n != 0 {
			t.Errorf("%s was told %d times, want none", path, n)
		}
	}
	if retries.Queued() != 0 {
		t.Errorf("%d logouts still queued", retries.Queued())
	}
}

// waitUntil polls cond for up to ten seconds.
func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
	}
}

// One organization whose applications never answer does not hold back another organization's retried logout: it has
// at most logoutRetryPerOrg of the retry queue's senders, the rest serve the other organizations.
func TestBackchannelRetrySlowOrgDoesNotDelayAnother(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }
	defer open() // a failure does not leave handlers holding the server
	var stuck, mostStuck atomic.Int64
	silent, _ := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := stuck.Add(1)
		for m := mostStuck.Load(); n > m && !mostStuck.CompareAndSwap(m, n); m = mostStuck.Load() {
		}
		defer stuck.Add(-1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	answering, answered := newTLSServer(t, func(http.ResponseWriter, *http.Request) {})
	h := setup(t, nil)
	retries := h.p.OpenLogoutQueue("node-1")
	name := "slow"
	slow, err := h.env.Svc.CreateOrg(t.Context(), service.System, service.OrgInput{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	in := func(uri string) service.ClientInput {
		return service.ClientInput{Name: ptr("app"), RedirectURIs: &[]string{rpCallback}, BackchannelURI: ptr(uri),
			GrantTypes: &[]string{"authorization_code"}, Scopes: &[]string{"openid"}, FirstParty: ptr(true)}
	}
	stuckClient, _, err := h.env.Svc.CreateClient(t.Context(), h.admin, slow.ID, in(silent.URL))
	if err != nil {
		t.Fatal(err)
	}
	okClient, _ := h.newClient(func(i *service.ClientInput) { i.BackchannelURI = ptr(answering.URL) })
	// the slow organization's retries are older, and more than its share of senders: they would hold them all
	const due = 200 * time.Millisecond
	for range 6 {
		if err := retries.Add(LogoutRetry{OrgID: stuckClient.OrgID, ClientID: stuckClient.ID, Sub: "u", SID: "s"}, due, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := retries.Add(LogoutRetry{OrgID: okClient.OrgID, ClientID: okClient.ID, Sub: "u", SID: "s"}, due, 1); err != nil {
		t.Fatal(err)
	}
	// They are due together, as after a restart (a delivery pass takes what is due when it starts, and these fall due
	// a few milliseconds apart).
	retries.Close()
	time.Sleep(due)
	retries = h.p.OpenLogoutQueue("node-1")
	defer retries.Close()
	// The other organization's logout is answered while the slow one's senders are held (they are started in the same
	// pass, so the answer may come before the second of them reaches its server).
	waitUntil(t, func() bool { return answered.Load() == 1 && stuck.Load() == logoutRetryPerOrg })
	open()
	waitUntil(t, func() bool { return retries.Queued() == 0 })
	if m := mostStuck.Load(); m > logoutRetryPerOrg {
		t.Errorf("up to %d retries at once for one organization, want at most %d", m, logoutRetryPerOrg)
	}
}

// An organization whose retries fill its share of the retry queue (its applications never answer) loses only its own
// further logouts: another organization's failed logouts, and ones that overflowed the in-memory queue, are still
// queued.
func TestBackchannelRetryShareFullDropsOnlyItsOrganization(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	retries := h.p.OpenLogoutQueue("node-1")
	defer retries.Close()
	name := "stuck"
	org, err := h.env.Svc.CreateOrg(t.Context(), service.System, service.OrgInput{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	stuckClient, _, err := h.env.Svc.CreateClient(t.Context(), h.admin, org.ID, service.ClientInput{Name: ptr("app"),
		RedirectURIs: &[]string{rpCallback}, BackchannelURI: ptr("https://rp.example/logout"),
		GrantTypes: &[]string{"authorization_code"}, Scopes: &[]string{"openid"}, FirstParty: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	okClient, _ := h.newClient(func(i *service.ClientInput) { i.BackchannelURI = ptr("https://rp.example/logout") })
	for range logoutRetryOrgMax { // waiting for their first retry, long after this test
		if err := retries.Add(LogoutRetry{OrgID: stuckClient.OrgID, ClientID: stuckClient.ID, Sub: "u"}, time.Hour, 1); err != nil {
			t.Fatal(err)
		}
	}
	stuck, ok := bcTarget{client: stuckClient, sub: "u2"}, bcTarget{client: okClient, sub: "u2"}
	failed := metrics.BackchannelFailed.Value()
	if err := retries.Add(stuck.retry(), time.Hour, 1); !errors.Is(err, queue.ErrFull) {
		t.Fatalf("a retry of the organization at its share: %v, want queue.ErrFull", err)
	}
	h.p.retryLogout(stuck, errors.New("down")) // logged, not queued
	h.p.retryLogout(ok, errors.New("down"))
	h.p.bcWG.Add(1)
	h.p.spill([]LogoutRetry{stuck.retry(), ok.retry()}, "full") // an overflow of the in-memory queue: the same
	if n := retries.Queued(); n != logoutRetryOrgMax+2 {
		t.Fatalf("%d queued, want the organization's %d and the other's two", n, logoutRetryOrgMax)
	}
	if n := metrics.BackchannelFailed.Value() - failed; n < 2 { // (others' tests run at once and may add)
		t.Fatalf("%d logouts counted as failed, want the organization's two", n)
	}
}

func TestBackchannelTargets(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	rp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer rp.Close()
	h := setup(t, nil)
	ctx := context.Background()
	cl, secret := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL) })
	// two sessions of the user, each with a grant of the client
	var sids []string
	for range 2 {
		r, _ := h.login(cl, secret, nil)
		sids = append(sids, claimsOf(t, r.str("access_token"))["sid"].(string))
	}
	// a session that is not the user's, and one that does not exist, are not counted; only the named one is told
	h.p.BackchannelLogout(ctx, sids[0], "nosuchsession")
	h.p.Wait()
	if hits.Load() != 1 {
		t.Fatalf("told %d times, want 1", hits.Load())
	}
	// listings that fail are logged, not fatal, and nobody is told
	sessions, grants := h.env.Svc.Sessions.S, h.env.Svc.Grants.S
	h.env.Svc.Sessions.S = failLists(sessions, model.KindSession)
	h.env.Svc.Grants.S = failLists(grants, model.KindGrant)
	h.p.BackchannelLogoutUser(ctx, h.user.ID)
	h.p.Wait()
	h.env.Svc.Sessions.S, h.env.Svc.Grants.S = sessions, grants
	if hits.Load() != 1 {
		t.Fatalf("told %d times with unreadable listings, want still 1", hits.Load())
	}
	// collect returns the listing error for the caller to log
	h.env.Svc.Sessions.S = failLists(sessions, model.KindSession)
	if _, _, err := h.p.collect(ctx, h.user.ID, nil); !errors.Is(err, errFault) {
		t.Fatalf("collect with an unreadable session listing: %v", err)
	}
	// a listing that fails once is read again, and nothing is lost
	var failed atomic.Bool
	h.env.Svc.Sessions.S = &onceFailStore{Store: sessions, failed: &failed}
	if targets, _, err := h.p.collect(ctx, h.user.ID, nil); err != nil || len(targets) != 2 {
		t.Fatalf("collect after one failed listing: %d targets, %v", len(targets), err)
	}
	h.env.Svc.Sessions.S = sessions
	// noting a client on a session: one that is gone, one at the bound, one already noted
	h.p.noteSessionClient(ctx, "nosuchsession", cl.ID)
	s, err := h.env.Svc.Sessions.Get(ctx, sids[1])
	if err != nil {
		t.Fatal(err)
	}
	s.Clients = make([]string, 100)
	for i := range s.Clients {
		s.Clients[i] = "client" + string(rune('A'+i%26)) + string(rune('a'+i/26))
	}
	if err := h.env.Svc.Sessions.Update(ctx, s); err != nil {
		t.Fatal(err)
	}
	h.p.noteSessionClient(ctx, sids[1], "one-more")
	if s2, _ := h.env.Svc.Sessions.Get(ctx, sids[1]); len(s2.Clients) != 100 {
		t.Fatalf("clients: %d", len(s2.Clients))
	}
	h.p.noteSessionClient(ctx, sids[1], s.Clients[3]) // already noted
	if s2, _ := h.env.Svc.Sessions.Get(ctx, sids[1]); !slices.Equal(s2.Clients, s.Clients) {
		t.Fatalf("a client already noted changed the session's list: %v", s2.Clients)
	}
}

// A logout token that cannot be delivered fails at each step: the connection, the address, the signing key.
func TestBackchannelSendFailures(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	rp, _ := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {})
	cl, _ := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL) })
	ce, err := h.p.client(context.Background(), cl.OrgID, cl.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.p.sendLogoutToken(bcTarget{client: ce.c, sub: "u"}); err != nil {
		t.Fatalf("control: %v", err)
	}
	if err := h.p.sendLogoutToken(bcTarget{client: &model.Client{Meta: model.Meta{ID: "c"}, BackchannelURI: "https://127.0.0.1:1/x"}, sub: "u"}); err == nil {
		t.Error("unreachable relying party")
	}
	if err := h.p.sendLogoutToken(bcTarget{client: &model.Client{Meta: model.Meta{ID: "c"}, BackchannelURI: "https://a b/x"}, sub: "u"}); err == nil {
		t.Error("unparsable address")
	}
	keys := h.env.Svc.Keys.S
	h.env.Svc.Keys.S = failLists(keys, model.KindKey)
	h.p.Invalidate()
	if err := h.p.sendLogoutToken(bcTarget{client: ce.c, sub: "u"}); err == nil {
		t.Error("without a signing key")
	}
	h.env.Svc.Keys.S = keys
	h.p.Invalidate()
	// with the retry queue closed, a failure is only logged
	retries := h.p.OpenLogoutQueue("node-1")
	retries.Close()
	h.p.retryLogout(bcTarget{client: ce.c, sub: "u"}, errors.New("refused"))
}

// A logout keeps its token id (jti) for every attempt to deliver it, so a relying party that acted on it can tell a
// retry from a new logout; each logout has its own. A retry queued before the id was kept is still sent, with one.
func TestBackchannelRetryKeepsTheLogoutsJTI(t *testing.T) {
	var mu sync.Mutex
	got := map[string][]map[string]any{} // the claims of each token delivered, by path
	var attempts atomic.Int64
	rp, _ := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		got[r.URL.Path] = append(got[r.URL.Path], claimsOf(t, r.PostForm.Get("logout_token")))
		mu.Unlock()
		if r.URL.Path == "/retried" && attempts.Add(1) < 3 { // taken at the third attempt
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
	h := setup(t, nil)
	ctx := context.Background()
	withLogoutBackoff(t, 5*time.Millisecond, 5*time.Millisecond)
	retries := h.p.OpenLogoutQueue("node-1")
	defer retries.Close()
	cl, secret := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL + "/retried") })
	for range 2 { // two sessions of the user, each with a grant of the client
		if r, _ := h.login(cl, secret, nil); r.status != 200 {
			t.Fatal(r.m)
		}
	}

	targets, _, _ := h.p.collect(ctx, h.user.ID, nil)
	if len(targets) != 2 {
		t.Fatalf("%d logouts collected, want one for each session", len(targets))
	}
	if targets[0].jti == "" || targets[0].jti == targets[1].jti {
		t.Fatalf("token ids %q and %q: want one of its own for each logout", targets[0].jti, targets[1].jti)
	}

	h.p.dispatch(targets[:1], nil)
	h.p.Wait()
	waitUntil(t, func() bool { return attempts.Load() >= 3 && retries.Queued() == 0 })
	mu.Lock()
	delivered := got["/retried"]
	mu.Unlock()
	if len(delivered) != 3 {
		t.Fatalf("%d attempts, want 3", len(delivered))
	}
	for i, c := range delivered {
		if c["jti"] != targets[0].jti || c["sid"] != targets[0].sid {
			t.Errorf("attempt %d: jti %v sid %v, want the logout's own %q and %q", i+1, c["jti"], c["sid"],
				targets[0].jti, targets[0].sid)
		}
	}

	// a retry queued before the token id was kept (none in the item) is sent with one
	old, _ := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL + "/old") })
	if err := retries.Add(LogoutRetry{OrgID: old.OrgID, ClientID: old.ID, Sub: "u", SID: "s"}, time.Millisecond, 1); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(got["/old"]) == 1 })
	mu.Lock()
	defer mu.Unlock()
	if jti, _ := got["/old"][0]["jti"].(string); jti == "" {
		t.Error("a retry queued without a token id was sent without one")
	}
}

// A logout whose application could not be read (the store failed: the application is not gone) is not lost: it goes
// to the retry queue, which reads the application again and tells it then.
func TestBackchannelUnreadClientIsRetried(t *testing.T) {
	rp, hits := newTLSServer(t, func(http.ResponseWriter, *http.Request) {})
	h := setup(t, nil)
	withLogoutBackoff(t, 200*time.Millisecond, 200*time.Millisecond, 200*time.Millisecond)
	retries := h.p.OpenLogoutQueue("node-1")
	defer retries.Close()
	cl, secret := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL) })
	if r, _ := h.login(cl, secret, nil); r.status != 200 {
		t.Fatal(r.m)
	}
	failing := failReads(h.env.Svc.Clients.S, model.KindClient)
	h.env.Svc.Clients.S = failing // before any logout is queued: the retry worker reads it only after
	h.p.InvalidateClient(cl.ID)
	h.p.BackchannelLogoutUser(t.Context(), h.user.ID)
	h.p.Wait()
	if n := retries.Queued(); n != 1 || hits.Load() != 0 {
		t.Fatalf("%d logouts in the retry queue and %d sent while the application could not be read, want 1 and none",
			n, hits.Load())
	}
	failing.healed.Store(true)
	waitUntil(t, func() bool { return hits.Load() == 1 && retries.Queued() == 0 })
}

// Logouts still queued in memory when the server shuts down are not lost: once the shutdown wait is over they go to
// the retry queue, which sends them after the restart, and the wait stays bounded.
func TestBackchannelShutdownSpillsQueue(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }
	defer open() // a failure does not leave handlers holding the server
	var stuck atomic.Int64
	tarpit, _ := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		stuck.Add(1)
		<-release
	})
	h := setup(t, nil)
	withLogoutBackoff(t, time.Hour) // the retries wait for the next start
	saved := bcShutdownWait
	bcShutdownWait = 100 * time.Millisecond
	t.Cleanup(func() { bcShutdownWait = saved })
	retries := h.p.OpenLogoutQueue("node-1")
	defer retries.Close()
	cl, _ := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(tarpit.URL) })
	ce, err := h.p.client(t.Context(), cl.OrgID, cl.ID)
	if err != nil {
		t.Fatal(err)
	}
	// the organization's senders are all held by the relying party, and more logouts wait behind them
	const left = 5
	targets := make([]bcTarget, bcOrgWorkersMax+left)
	for i := range targets {
		targets[i] = bcTarget{client: ce.c, sub: "user", sid: "s", jti: newJTI()}
	}
	h.p.dispatch(targets, nil)
	waitUntil(t, func() bool { return stuck.Load() == bcOrgWorkersMax })
	start := time.Now()
	h.p.Wait()
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the shutdown waited %v", d)
	}
	if n := retries.Queued(); n != left {
		t.Fatalf("%d logouts in the retry queue after the shutdown wait, want the %d still queued", n, left)
	}
	open()
	h.p.Wait()
}
