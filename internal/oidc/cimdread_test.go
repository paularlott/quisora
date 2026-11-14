package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// storedDocApp signs the user in to the metadata-document application at srv (which stores it), then makes its stored
// copy as old as age, with nothing cached of it and its organization's read of the minute unspent: the state of an
// application whose document is due a read. It returns the application and its record id.
func (h *harness) storedDocApp(srv string, redirect string, age time.Duration) (*model.Client, string) {
	h.t.Helper()
	ctx := context.Background()
	cl := &model.Client{Meta: model.Meta{ID: srv + "/app.json"}, RedirectURIs: []string{redirect}}
	if r, _ := h.publicLogin(cl, url.Values{"resource": {mcpResource}}); r.status != http.StatusOK {
		h.t.Fatalf("first sign-in: %d %v", r.status, r.m)
	}
	rid := model.ClientRecordID(h.env.Primary.ID, cl.ID)
	stored, err := h.env.Svc.Clients.Get(ctx, rid)
	if err != nil {
		h.t.Fatal(err)
	}
	stored.MetadataFetched = time.Now().Add(-age)
	if err := h.env.Svc.Clients.Update(ctx, stored); err != nil {
		h.t.Fatal(err)
	}
	h.p.clients.Del(rid)
	_ = h.env.Server.Eph.Delete(ctx, nsCIMD, cl.ID)
	_ = h.env.Server.Eph.Delete(ctx, nsRateOIDC, "cimd|"+h.env.Primary.ID+"|"+cl.ID) // a minute later
	return cl, rid
}

// waitStored waits until the stored application rid satisfies ok (a refresh done in the background).
func (h *harness) waitStored(rid string, ok func(*model.Client) bool) *model.Client {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := h.env.Svc.Clients.Get(context.Background(), rid)
		if err == nil && ok(c) {
			return c
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("the stored application never changed as expected: %+v %v", c, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A stored application whose document is due its daily read is answered from the stored copy at once, by every
// request naming it, while the document is read again in the background: no request waits for its document server
// (no per-address limit bounds requests naming a stored application, so waiting ones would hold the node's request
// slots for as long as a stalled server kept them). What is read then replaces the stored copy.
func TestStoredMetadataRefreshNeverWaits(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	redirect := "http://127.0.0.1:44110/callback"
	var slow atomic.Bool
	g := newGate(t)
	srv, hits := metadataDocServer(t, redirect, 0, func() {
		if slow.Load() {
			g.hold()
		}
	})
	defer g.open() // before the server's cleanup, which waits for the read it holds
	h.p.HTTP = srv.Client()
	cl, rid := h.storedDocApp(srv.URL, redirect, 25*time.Hour)
	slow.Store(true)
	_, ch := pkce()
	const n = 50
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- h.startFrom("198.51.100.110", authzQuery(cl, ch, url.Values{"resource": {mcpResource}})).Code
		}()
	}
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("requests naming a stored application wait for its document's read")
	}
	close(codes)
	for code := range codes {
		if code != http.StatusFound {
			t.Errorf("a request answered from the stored copy: %d, want a sign-in started (302)", code)
		}
	}
	g.waitHeld(t) // the read is under way meanwhile, once
	g.open()
	h.waitStored(rid, func(c *model.Client) bool { return time.Since(c.MetadataFetched) < time.Hour })
	if got := hits.Load(); got != 2 {
		t.Errorf("%d reads, want the first sign-in's and one refresh", got)
	}
}

// A stored application whose copy is past service.MetadataStale has nothing to answer from: its document is read for
// the request, as an application not stored is, and the request goes on with what was read.
func TestStaleStoredMetadataReadForTheRequest(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	redirect := "http://127.0.0.1:44111/callback"
	srv, hits := metadataDocServer(t, redirect, 0, nil)
	h.p.HTTP = srv.Client()
	cl, rid := h.storedDocApp(srv.URL, redirect, service.MetadataStale+time.Hour)
	_, ch := pkce()
	if rec := h.startFrom("198.51.100.111", authzQuery(cl, ch, url.Values{"resource": {mcpResource}})); rec.Code != http.StatusFound {
		t.Fatalf("a stored application past its stale copy: %d %.200s", rec.Code, rec.Body)
	}
	if hits.Load() != 2 {
		t.Errorf("%d reads, want the first sign-in's and this request's", hits.Load())
	}
	if c, _ := h.env.Svc.Clients.Get(context.Background(), rid); c == nil || time.Since(c.MetadataFetched) > time.Hour {
		t.Error("the stored copy was not replaced by what was read")
	}
}

// With the node's caches at their cap, a document read is still shared for the minute: the newest entries take the
// room of the oldest. A second sign-in to an application not stored yet, in the minute its organization's read was
// spent, finds that read and starts, rather than being told the application is unknown.
func TestFullMetadataCacheRefusesNoSignIn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	local, ok := h.env.Server.Eph.(*ephemeral.Local)
	if !ok {
		t.Fatalf("the test server's ephemeral store is %T", h.env.Server.Eph)
	}
	local.CacheBudget = 64 << 10
	// the caches filled by other documents, to within less than the room this application's document takes
	for i, size := 0, 4<<10; size > 0; i++ {
		key := "https://other.example/" + strconv.Itoa(i)
		if local.Cached()+int64(len(nsCIMD)+1+len(key)+size)+200 > local.CacheLimit() {
			size /= 2
			continue
		}
		if err := local.Set(ctx, nsCIMD, key, make([]byte, size), time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if left := local.CacheLimit() - local.Cached(); left > 400 {
		t.Fatalf("%d bytes left in the caches", left)
	}
	redirect := "http://127.0.0.1:44112/callback"
	srv, hits := metadataDocServer(t, redirect, 0, nil)
	h.p.HTTP = srv.Client()
	cl := &model.Client{Meta: model.Meta{ID: srv.URL + "/app.json"}, RedirectURIs: []string{redirect}}
	_, ch := pkce()
	for i, ip := range []string{"198.51.100.112", "198.51.100.113"} {
		if rec := h.startFrom(ip, authzQuery(cl, ch, url.Values{"resource": {mcpResource}})); rec.Code != http.StatusFound {
			t.Fatalf("sign-in %d with the caches full: %d %.200s", i+1, rec.Code, rec.Body)
		}
	}
	if hits.Load() != 1 {
		t.Errorf("%d reads, want one a minute", hits.Load())
	}
	if local.Cached() > local.CacheLimit() {
		t.Errorf("caches %d past their cap %d", local.Cached(), local.CacheLimit())
	}
}

// In a cluster the read that spent an organization's minute for a URL may be another node's, still under way: a first
// request here then waits for what that node shares, rather than answering "unknown application" at once. When the
// other node's read is noted as having found nothing, it answers at once.
func TestMetadataReadOfAnotherNodeWaitedFor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	redirect := "http://127.0.0.1:44113/callback"
	srv, hits := metadataDocServer(t, redirect, 0, nil)
	h.p.HTTP = srv.Client()
	org := h.env.Primary.ID
	otherNodeReads := func(id string) { // its read takes the organization's minute, here as there (the counter is shared)
		if _, err := h.env.Server.Eph.Incr(ctx, nsRateOIDC, "cimd|"+org+"|"+id, 1, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	_, ch := pkce()

	cl := &model.Client{Meta: model.Meta{ID: srv.URL + "/app.json"}, RedirectURIs: []string{redirect}}
	otherNodeReads(cl.ID)
	done := make(chan int, 1)
	go func() {
		done <- h.startFrom("198.51.100.114", authzQuery(cl, ch, url.Values{"resource": {mcpResource}})).Code
	}()
	time.Sleep(300 * time.Millisecond) // the other node's read is under way
	doc := `{"client_id":"` + cl.ID + `","client_name":"Gen","redirect_uris":["` + redirect + `"]}`
	if err := h.env.Server.Eph.Set(ctx, nsCIMD, cl.ID, []byte(doc), time.Minute); err != nil { // and shared
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != http.StatusFound {
			t.Fatalf("a first request while another node read the document: %d, want a sign-in started (302)", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the shared read was never found")
	}
	if hits.Load() != 0 {
		t.Errorf("%d reads here, past the organization's one a minute", hits.Load())
	}

	bad := &model.Client{Meta: model.Meta{ID: srv.URL + "/bad.json"}, RedirectURIs: []string{redirect}}
	otherNodeReads(bad.ID)
	if err := h.env.Server.Eph.Set(ctx, nsCIMD, metadataFailedKey(org, bad.ID), []byte{1}, time.Minute); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if rec := h.startFrom("198.51.100.115", authzQuery(bad, ch, url.Values{"resource": {mcpResource}})); rec.Code == http.StatusFound {
		t.Fatal("a sign-in started for a document the minute's read found nothing at")
	}
	if waited := time.Since(start); waited > time.Second {
		t.Errorf("waited %v for a read noted as having found nothing", waited)
	}
}

// A flow begun before its application's document dropped the redirect URI it names ends once the document read again
// says so: no code is issued for the dropped address, which the refreshed application's consent generation would let
// be redeemed.
func TestMetadataFlowEndsWhenRedirectDropped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	// another path: a loopback redirect URI's port is the application's to choose (RFC 8252 §7.3), so a document that
	// changed only the port would still name the old address
	oldR, newR := "http://127.0.0.1:44114/callback", "http://127.0.0.1:44114/moved"
	var redirect atomic.Value
	redirect.Store(oldR)
	srv, _ := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		id := "https://" + r.Host + r.URL.Path
		_, _ = w.Write([]byte(`{"client_id":"` + id + `","client_name":"Gen","redirect_uris":["` + redirect.Load().(string) + `"]}`))
	})
	h.p.HTTP = srv.Client()
	cl, rid := h.storedDocApp(srv.URL, oldR, 0)
	c, csrf := h.session(h.user)
	v, ch := pkce()
	to := h.authorize(c, authzQuery(cl, ch, url.Values{"resource": {mcpResource}})) // checked against the old document
	redirect.Store(newR)
	stored, _ := h.env.Svc.Clients.Get(ctx, rid)
	stored.MetadataFetched = time.Now().Add(-25 * time.Hour) // due its daily read
	if err := h.env.Svc.Clients.Update(ctx, stored); err != nil {
		t.Fatal(err)
	}
	h.p.clients.Del(rid)
	_, resume := h.decideConsent(c, csrf, to.Query().Get("flow"), true)
	h.waitStored(rid, func(c *model.Client) bool { return len(c.RedirectURIs) == 1 && c.RedirectURIs[0] == newR })
	h.p.clients.Del(rid)
	if resume == "" {
		return // ended at consent
	}
	resp := h.get(c, resume)
	text := body(resp)
	u, _ := url.Parse(resp.Header.Get("Location"))
	if code := u.Query().Get("code"); code != "" {
		r := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {cl.ID},
			"redirect_uri": {oldR}, "code_verifier": {v}}, "", "")
		t.Fatalf("a code issued for the dropped redirect URI (%s), redeemed: %d", u.Host, r.status)
	}
	if resp.StatusCode == http.StatusFound && u.Host == "127.0.0.1:44114" && u.Path == "/callback" {
		t.Fatalf("sent to the dropped redirect URI: %s", u)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("resume of the ended flow: %d %.200s", resp.StatusCode, text)
	}
}

// The same holds for an administrator's application: a flow begun at a redirect URI an administrator then removes
// ends, rather than issuing a code for an address the application no longer has.
func TestFlowEndsWhenAdminDropsRedirect(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	const dropped = "https://rp.example/old"
	cl, secret := h.newClient(func(in *service.ClientInput) {
		in.RedirectURIs = &[]string{dropped, rpCallback}
		in.FirstParty = ptr(false)
	})
	c, csrf := h.session(h.user)
	v, ch := pkce()
	to := h.authorize(c, authzQuery(cl, ch, nil))
	if to.Path != h.orgBase+"/oauth/consent" {
		t.Fatalf("no consent page: %s", to)
	}
	if _, err := h.env.Svc.UpdateClient(ctx, h.admin, cl.ID, service.ClientInput{RedirectURIs: &[]string{rpCallback}}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	status, resume := h.decideConsent(c, csrf, to.Query().Get("flow"), true)
	if resume == "" {
		if status == http.StatusOK {
			t.Fatal("consent accepted with nowhere to continue")
		}
		return // ended at consent
	}
	resp := h.get(c, resume)
	body(resp)
	u, _ := url.Parse(resp.Header.Get("Location"))
	if code := u.Query().Get("code"); code != "" {
		r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {dropped},
			"code_verifier": {v}}, cl, secret)
		t.Fatalf("a code issued for the removed redirect URI %s, redeemed: %d", u, r.status)
	}
}
