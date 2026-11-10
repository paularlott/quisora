package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/ttlcache"
	"github.com/paularlott/quisora/internal/web"
)

func TestPublicClientFlow(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.publicClient(nil)
	r, _ := h.publicLogin(cl, nil)
	if r.status != 200 || r.str("access_token") == "" || r.str("id_token") == "" {
		t.Fatalf("%v", r)
	}
	rt := r.str("refresh_token")
	if len(strings.Split(rt, ".")) != 3 {
		t.Fatalf("public client refresh token must rotate: %s", rt)
	}
	c, _ := h.session(h.user)
	// PKCE is mandatory at authorize for public clients too
	_, ch3 := pkce()
	if u := h.authorize(c, authzQuery(cl, ch3, url.Values{"code_challenge": {""}, "code_challenge_method": {""}})); u.Query().Get("error") != "invalid_request" {
		t.Fatalf("%s", u)
	}
	// refresh rotation and reuse detection, with client_id only
	rf := func(tok string) tokResp {
		return h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok}, "client_id": {cl.ID}}, "", "")
	}
	r1 := rf(rt)
	if r1.status != 200 || r1.str("refresh_token") == "" || r1.str("refresh_token") == rt {
		t.Fatalf("%v", r1)
	}
	if rf(rt).status != 400 {
		t.Fatal("old public refresh token accepted")
	}
	if rf(r1.str("refresh_token")).status != 400 {
		t.Fatal("reuse did not revoke the family")
	}
	// the private-use scheme redirect is accepted exactly
	if u := h.authorize(c, authzQuery(cl, ch3, url.Values{"redirect_uri": {"com.example.app:/cb"}})); u.Path != h.orgBase+"/oauth/consent" {
		t.Fatalf("private scheme: %s", u)
	}
	if resp := h.get(c, h.orgBase+"/oauth/authorize?"+authzQuery(cl, ch3, url.Values{"redirect_uri": {"com.example.app:/other"}}).Encode()); resp.StatusCode != 400 {
		t.Fatal("private scheme prefix accepted")
	}
}

func TestPublicClientTokenEndpointRules(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.publicClient(nil)
	conf, _ := h.newClient(nil)
	// client_credentials is never available to public clients (even if misconfigured)
	if r := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {cl.ID}}, "", ""); r.status != 400 || r.m["error"] != "unauthorized_client" {
		t.Fatalf("cc for public: %v", r)
	}
	// a public client presenting a secret (post or basic) or an assertion is refused
	for name, r := range map[string]tokResp{
		"post":  h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"a.b"}, "client_id": {cl.ID}, "client_secret": {"qsrs_x"}}, "", ""),
		"basic": h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"a.b"}}, cl.ID, "qsrs_x"),
		"jwt": h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"a.b"}, "client_id": {cl.ID},
			"client_assertion_type": {assertionType}, "client_assertion": {"x.y.z"}}, "", ""),
	} {
		if r.status != 401 {
			t.Errorf("%s: public client with credentials got %d", name, r.status)
		}
	}
	// a confidential client never falls back to "none"
	if r := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {conf.ID}}, "", ""); r.status != 401 {
		t.Fatalf("confidential client authenticated without a secret: %d", r.status)
	}
	// unknown public client
	if r := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"nope"}}, "", ""); r.status != 401 {
		t.Fatal(r.status)
	}
}

func TestPublicClientVerifier(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.publicClient(nil)
	run := func(verifier func(v string) string) tokResp {
		c, csrf := h.session(h.user)
		v, ch := pkce()
		u := h.authorize(c, authzQuery(cl, ch, nil))
		_, redirect := h.decideConsent(c, csrf, u.Query().Get("flow"), true)
		code := loc(t, h.get(c, redirect)).Query().Get("code")
		f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {cl.ID}, "redirect_uri": {cl.RedirectURIs[0]}}
		if vv := verifier(v); vv != "" {
			f.Set("code_verifier", vv)
		}
		return h.post(h.orgBase+"/oauth/token", f, "", "")
	}
	if r := run(func(v string) string { return v }); r.status != 200 {
		t.Fatalf("%v", r)
	}
	if r := run(func(string) string { return "" }); r.status != 400 || r.m["error"] != "invalid_grant" {
		t.Fatalf("missing verifier: %v", r)
	}
	if r := run(func(string) string { return strings.Repeat("b", 43) }); r.status != 400 || r.m["error"] != "invalid_grant" {
		t.Fatalf("wrong verifier: %v", r)
	}
}

func TestPublicClientCORS(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.publicClient(nil)
	other := h.publicClient(func(in *service.ClientInput) { in.RedirectURIs = &[]string{"https://other.example/cb"} })
	preflight := func(path, origin string) *http.Response {
		req, _ := http.NewRequest("OPTIONS", h.env.URL+path, nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "authorization, content-type")
		resp, err := h.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	for _, path := range []string{h.orgBase + "/oauth/token", h.orgBase + "/oauth/revoke", h.orgBase + "/oauth/userinfo"} {
		resp := preflight(path, "https://spa.example")
		if resp.StatusCode != 204 || resp.Header.Get("Access-Control-Allow-Origin") != "https://spa.example" ||
			!strings.Contains(resp.Header.Get("Vary"), "Origin") || resp.Header.Get("Access-Control-Allow-Credentials") != "" ||
			!strings.Contains(resp.Header.Get("Access-Control-Allow-Headers"), "DPoP") || len(resp.Header.Values("Vary")) != 1 ||
			!strings.Contains(resp.Header.Get("Access-Control-Allow-Headers"), "Authorization") ||
			resp.Header.Get("Access-Control-Max-Age") == "" {
			t.Errorf("%s preflight: %d %v", path, resp.StatusCode, resp.Header)
		}
		// loopback on any port
		if resp := preflight(path, "http://127.0.0.1:5173"); resp.Header.Get("Access-Control-Allow-Origin") != "http://127.0.0.1:5173" {
			t.Errorf("%s: loopback origin refused", path)
		}
		for _, o := range []string{"https://evil.example", "http://spa.example", "https://spa.example:8443", "http://localhost:5173", "null"} {
			if resp := preflight(path, o); resp.Header.Get("Access-Control-Allow-Origin") != "" {
				t.Errorf("%s: origin %s allowed", path, o)
			}
		}
	}
	// actual requests
	r := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x.y"}, "client_id": {cl.ID}}, "", "", "Origin", "https://spa.example")
	if r.hdr.Get("Access-Control-Allow-Origin") != "https://spa.example" || !strings.Contains(r.hdr.Get("Vary"), "Origin") {
		t.Errorf("token actual: %v", r.hdr)
	}
	// the origin of ANOTHER public client does not work for this client
	r = h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x.y"}, "client_id": {cl.ID}}, "", "", "Origin", "https://other.example")
	if r.hdr.Get("Access-Control-Allow-Origin") != "" {
		t.Error("cross-client origin allowed on token endpoint")
	}
	r = h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x.y"}, "client_id": {other.ID}}, "", "", "Origin", "https://other.example")
	if r.hdr.Get("Access-Control-Allow-Origin") != "https://other.example" {
		t.Error("own origin refused")
	}
	// userinfo for a public client's token from its origin, and not from another
	pr, _ := h.publicLogin(cl, nil)
	resp := h.get(h.http, h.orgBase+"/oauth/userinfo", "Authorization", "Bearer "+pr.str("access_token"), "Origin", "https://spa.example")
	if resp.StatusCode != 200 || resp.Header.Get("Access-Control-Allow-Origin") != "https://spa.example" {
		t.Errorf("userinfo CORS: %d %v", resp.StatusCode, resp.Header)
	}
	resp = h.get(h.http, h.orgBase+"/oauth/userinfo", "Authorization", "Bearer "+pr.str("access_token"), "Origin", "https://other.example")
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("userinfo CORS for another client's origin")
	}
	// no Origin header, no CORS headers
	resp = h.get(h.http, h.orgBase+"/oauth/userinfo", "Authorization", "Bearer "+pr.str("access_token"))
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS without Origin")
	}
	// a disabled public client's origin stops being allowed once evicted
	h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{Enabled: ptr(false)})
	h.p.InvalidateClient(cl.ID)
	if resp := preflight(h.orgBase+"/oauth/token", "https://spa.example"); resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("disabled client's origin still allowed")
	}
}

func TestPublicClientRevokeAndIntrospect(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.publicClient(nil)
	r, _ := h.publicLogin(cl, nil)
	rt := r.str("refresh_token")
	// introspection is for confidential clients only
	if x := h.post(h.orgBase+"/oauth/introspect", url.Values{"token": {r.str("access_token")}, "client_id": {cl.ID}}, "", ""); x.status != 401 || x.m["error"] != "invalid_client" {
		t.Fatalf("public introspect: %v", x)
	}
	// a public client may revoke its own refresh token
	if x := h.post(h.orgBase+"/oauth/revoke", url.Values{"token": {rt}, "client_id": {cl.ID}}, "", ""); x.status != 200 {
		t.Fatalf("revoke: %d", x.status)
	}
	if x := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {cl.ID}}, "", ""); x.status != 400 {
		t.Fatal("revoked token still refreshes")
	}
	// but not someone else's
	r2, _ := h.publicLogin(cl, nil)
	other := h.publicClient(nil)
	h.post(h.orgBase+"/oauth/revoke", url.Values{"token": {r2.str("refresh_token")}, "client_id": {other.ID}}, "", "")
	if x := h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r2.str("refresh_token")}, "client_id": {cl.ID}}, "", ""); x.status != 200 {
		t.Fatal("foreign public client revoked a token")
	}
}

// The origins of an organization's public clients are cached per organization and bounded like every cache here
// (cacheTTL), whatever the store: within the bound they are served, past it read again.
func TestOriginCacheTTL(t *testing.T) {
	t.Parallel()
	if cacheTTL > 5*time.Second {
		t.Fatalf("origins are cached for %v, more than the 5s bound", cacheTTL)
	}
	h := setup(t, nil)
	const bound = time.Second // shortened here, so the test need not wait for cacheTTL
	h.p.origins = ttlcache.New[*originSet](bound, 10)
	h.publicClient(nil)
	origins := func() *originSet {
		var set *originSet
		req := httptest.NewRequest("OPTIONS", h.orgBase+"/oauth/token", nil)
		req.SetPathValue("org", h.env.Primary.ID)
		h.p.s.InOrg(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { set = h.p.publicOrigins(r) })).
			ServeHTTP(httptest.NewRecorder(), req)
		return set
	}
	first := origins()
	if !first.exact["https://spa.example"] || origins() != first {
		t.Error("the origins were read again within the bound")
	}
	time.Sleep(bound)
	if origins() == first {
		t.Errorf("the origins were not read again after %v", bound)
	}
}

// A public client's origins are allowed at its own organization's endpoints only.
func TestPublicClientCORSIsPerOrganization(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	h.publicClient(nil) // https://spa.example, of the primary organization
	org2, _ := h.secondOrg()
	_, _, err := h.env.Svc.CreateClient(context.Background(), h.admin, org2.ID, service.ClientInput{Name: ptr("acme app"),
		AuthMethod: ptr(model.AuthMethodNone), RedirectURIs: &[]string{"https://acme-spa.example/cb"},
		GrantTypes: &[]string{"authorization_code"}, FirstParty: ptr(false)})
	if err != nil {
		t.Fatal(err)
	}
	allowed := func(orgID, origin string) bool {
		req, _ := http.NewRequest("OPTIONS", h.env.URL+web.OrgPath(orgID, "/oauth/token"), nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		resp, err := h.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusNoContent && resp.Header.Get("Access-Control-Allow-Origin") == origin
	}
	for _, c := range []struct {
		org, origin string
		want        bool
	}{
		{h.env.Primary.ID, "https://spa.example", true}, {h.env.Primary.ID, "https://acme-spa.example", false},
		{org2.ID, "https://acme-spa.example", true}, {org2.ID, "https://spa.example", false},
	} {
		if got := allowed(c.org, c.origin); got != c.want {
			t.Errorf("%s allowed at organization %s: %v, want %v", c.origin, c.org, got, c.want)
		}
	}
}

// A public client is identified by client_id alone, so a client that cannot be read is not "authentication required"
// (401 invalid_client, which a client answers by signing the user in again): the request is valid and the server
// cannot decide now, so the answer is 503 and the same request succeeds once the store answers.
func TestPublicClientTokenRequestFailsClosedOnUnreadableClient(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.publicClient(nil)
	r, _ := h.publicLogin(cl, nil)
	refresh := func() tokResp {
		return h.post(h.orgBase+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r.str("refresh_token")},
			"client_id": {cl.ID}}, "", "")
	}
	good := h.env.Svc.Clients.S
	h.env.Svc.Clients.S = failReads(good, model.KindClient)
	h.p.InvalidateClient(cl.ID)
	expectUnavailable(t, "public client with an unreadable record", refresh())
	h.env.Svc.Clients.S = good
	if r1 := refresh(); r1.status != 200 {
		t.Fatalf("the same request once the store answers again: %d %v", r1.status, r1.m)
	}
}

// originsAt returns the origins publicOrigins finds for a request to organization orgID made under ctx.
func (h *harness) originsAt(ctx context.Context, orgID string) *originSet {
	var set *originSet
	req := httptest.NewRequestWithContext(ctx, "OPTIONS", web.OrgPath(orgID, "/oauth/token"), nil)
	req.SetPathValue("org", orgID)
	h.p.s.InOrg(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { set = h.p.publicOrigins(r) })).
		ServeHTTP(httptest.NewRecorder(), req)
	return set
}

// heldLists holds every List until release is closed (or the caller's context ends, as a store's read would).
type heldLists struct {
	store.Store
	release chan struct{}
	lists   atomic.Int32
}

func (s *heldLists) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	s.lists.Add(1)
	select {
	case <-s.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return s.Store.List(ctx, kind, q)
}

// The CORS preflight is unauthenticated: the requests that miss an organization's origins while they are being read
// wait for that read rather than each reading every public client again, and the read is not the first requester's
// own: one that hangs up does not leave the others (and the cache) without the origins.
func TestOriginsReadOncePerOrganizationAtATime(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	h.publicClient(nil)
	org := h.env.Primary.ID
	held := &heldLists{Store: h.p.svc.Clients.S, release: make(chan struct{})}
	h.p.svc.Clients.S = held
	ctx, hangUp := context.WithCancel(context.Background())
	sets := make([]*originSet, 8)
	var wg sync.WaitGroup
	wg.Go(func() { sets[0] = h.originsAt(ctx, org) })
	for held.lists.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	for i := 1; i < len(sets); i++ {
		wg.Go(func() { sets[i] = h.originsAt(context.Background(), org) })
	}
	time.Sleep(50 * time.Millisecond) // the others miss while the first read is under way
	hangUp()
	close(held.release)
	wg.Wait()
	if n := held.lists.Load(); n != 1 {
		t.Errorf("%d reads of the clients for %d concurrent misses", n, len(sets))
	}
	for i, s := range sets[1:] {
		if !s.allows("https://spa.example") {
			t.Errorf("request %d: the origin is not allowed after the first requester hung up", i+1)
		}
	}
	if s, ok := h.p.origins.Get(org); !ok || !s.allows("https://spa.example") {
		t.Error("the origins read were not kept")
	}
}

// A change to one organization's client makes only that organization read its origins again: registrations at one
// organization do not empty every organization's. A change that does not say whose it was clears them all.
func TestClientChangeReloadsOnlyItsOrganizationsOrigins(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	h.publicClient(nil)
	org2, _ := h.secondOrg()
	ctx := context.Background()
	fill := func() {
		h.originsAt(ctx, h.env.Primary.ID)
		h.originsAt(ctx, org2.ID)
	}
	cached := func(org string) bool { _, ok := h.p.origins.Get(org); return ok }
	fill()
	h.p.InvalidateClientIn(org2.ID, "dyn-x")
	if !cached(h.env.Primary.ID) || cached(org2.ID) {
		t.Errorf("a client change at one organization: primary cached %v, the other %v", cached(h.env.Primary.ID), cached(org2.ID))
	}
	fill()
	h.p.InvalidateClient("dyn-x")
	if cached(h.env.Primary.ID) || cached(org2.ID) {
		t.Error("a change of an unknown organization did not clear every organization's origins")
	}
}

// A self-registered application nobody has let sign in has no browser origin to allow yet, and anyone may register
// one: its redirect URIs' origins count only once it has been used.
func TestUnusedSelfRegisteredOriginsNotAllowed(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	tn := h.mcpTenant("mcp", true)
	cl := h.register("https://registered.example/cb")
	ctx, org := context.Background(), h.env.Primary.ID
	if h.originsAt(ctx, org).allows("https://registered.example") {
		t.Fatal("an unused self-registered application's origin is allowed")
	}
	stored, err := h.env.Svc.Clients.Get(ctx, cl.ID)
	if err != nil {
		t.Fatal(err)
	}
	h.env.Svc.NoteSelfRegisteredUse(ctx, stored, tn)
	h.p.InvalidateClientIn(org, cl.ID) // the cluster does this in a server, on every change to the record
	if !h.originsAt(ctx, org).allows("https://registered.example") {
		t.Fatal("a used self-registered application's origin is not allowed")
	}
}
