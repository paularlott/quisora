package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// Introspection must not be a cross-tenant oracle.
func TestIntrospectionTenantIsolation(t *testing.T) {
	h := setup(t, nil)
	ctx := context.Background()
	cl, secret := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	at := r.str("access_token")
	_, plain, err := h.env.Svc.CreateAPIToken(ctx, service.ActorForUser(h.user, ""), service.APITokenInput{Name: "t", Scopes: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	isInactive := func(c *model.Client, s, tok string) {
		t.Helper()
		resp := h.clientPost("/oauth/introspect", url.Values{"token": {tok}}, c, s)
		if resp.status != 200 || len(resp.m) != 1 || resp.m["active"] != false {
			t.Fatalf("want exactly {active:false}, got %v", resp.m)
		}
	}

	// a same-org client that is not the audience sees the API token (it has no audience) but not the access token;
	// a resource server allowed to introspect every token of the organization sees both
	other, otherSecret := h.newClient(nil)
	if h.introspect(other, otherSecret, at)["active"] != false || h.introspect(other, otherSecret, plain)["active"] != true {
		t.Fatal("same-org client without introspect_org")
	}
	rs, rsSecret := h.newClient(func(in *service.ClientInput) { in.IntrospectOrg = ptr(true) })
	if h.introspect(rs, rsSecret, at)["active"] != true || h.introspect(rs, rsSecret, plain)["active"] != true {
		t.Fatal("same-org introspect_org client cannot introspect")
	}

	// a client of another org gets nothing
	org2, err := h.env.Svc.CreateOrg(ctx, h.admin, service.OrgInput{Name: ptr("acme"), DisplayName: ptr("Acme")})
	if err != nil {
		t.Fatal(err)
	}
	foreign, fsecret, err := h.env.Svc.CreateClient(ctx, h.admin, org2.ID, service.ClientInput{Name: ptr("foreign"),
		RedirectURIs: &[]string{rpCallback}, GrantTypes: &[]string{"authorization_code"}, FirstParty: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	isInactive(foreign, fsecret, at)
	isInactive(foreign, fsecret, plain)

	// a foreign-org user's token is invisible to our org's client, visible to its own org's client
	pw := "correct horse battery"
	u2, err := h.env.Svc.CreateUser(ctx, service.System, org2.ID, service.UserInput{GivenName: gn("T"), Username: ptr("bob"), Email: ptr("bob@acme.test"),
		Password: &pw, Verified: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	_, plain2, err := h.env.Svc.CreateAPIToken(ctx, service.ActorForUser(u2, ""), service.APITokenInput{Name: "t", Scopes: []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	isInactive(rs, rsSecret, plain2)
	if h.introspect(foreign, fsecret, plain2)["active"] != true {
		t.Fatal("own-org API token not visible")
	}
}

// Flow binding (flow fixation).
func TestFlowBoundToBrowser(t *testing.T) {
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	_, ch := pkce()

	// browser A starts a flow signed out
	a := h.anon()
	u := h.authorize(a, authzQuery(cl, ch, nil))
	next := u.Query().Get("next")
	if !strings.HasPrefix(next, "/oauth/authorize/resume?flow=") {
		t.Fatal(u)
	}
	// browser B (signed in, but never started the flow) cannot resume it
	b, _ := h.session(h.user)
	resp := h.get(b, next)
	page := body(resp)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(page, "started in another browser") {
		t.Fatalf("foreign browser: %d %s", resp.StatusCode, page)
	}
	// a wrong cookie value does not do either
	pu, _ := url.Parse(h.env.URL)
	bad, _ := h.session(h.user)
	for _, ck := range a.Jar.Cookies(pu) {
		if strings.HasPrefix(ck.Name, flowCookiePrefix) {
			bad.Jar.SetCookies(pu, []*http.Cookie{{Name: ck.Name, Value: ck.Value + "x", Path: "/", Secure: true}})
		}
	}
	if resp := h.get(bad, next); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong cookie value: %d", resp.StatusCode)
	}
	// the flow survives those attempts; the starting browser (after signing in) completes it
	same, _ := h.session(h.user)
	h.copyFlowCookies(a, same)
	resp = h.get(same, next)
	if resp.StatusCode != 302 || loc(t, resp).Query().Get("code") == "" {
		t.Fatalf("same browser: %d", resp.StatusCode)
	}
}

func TestFlowCookieAttributes(t *testing.T) {
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	_, ch := pkce()
	resp := h.get(h.anon(), "/oauth/authorize?"+authzQuery(cl, ch, nil).Encode())
	body(resp)
	var got *http.Cookie
	for _, ck := range resp.Cookies() {
		if strings.HasPrefix(ck.Name, "__Host-quisora_flow") {
			got = ck
		}
	}
	if got == nil || !got.Secure || !got.HttpOnly || got.SameSite != http.SameSiteLaxMode || got.Path != "/" ||
		got.Domain != "" || got.MaxAge <= 0 || got.MaxAge > int(flowTTL/time.Second) || len(got.Value) < 32 {
		t.Fatalf("flow cookie: %+v", got)
	}
}

func TestConsentBoundToBrowserAndParallelFlows(t *testing.T) {
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) { in.FirstParty = ptr(false) })
	a, csrfA := h.session(h.user)
	b, csrfB := h.session(h.user)

	consent := func(c *http.Client, csrf, flowID string, approve bool) int {
		bb, _ := json.Marshal(map[string]any{"flow": flowID, "approve": approve})
		req, _ := http.NewRequest("POST", h.env.URL+"/api-internal/oauth/consent", strings.NewReader(string(bb)))
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Content-Type", "application/json")
		r, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]string
		_ = json.Unmarshal([]byte(body(r)), &out)
		if r.StatusCode == 200 {
			resp := h.get(c, out["redirect"])
			if resp.StatusCode != 302 || loc(t, resp).Query().Get("code") == "" {
				t.Fatalf("resume after consent: %d", resp.StatusCode)
			}
		}
		return r.StatusCode
	}

	// two flows in browser A at the same time
	_, ch1 := pkce()
	_, ch2 := pkce()
	u1 := h.authorize(a, authzQuery(cl, ch1, nil))
	u2 := h.authorize(a, authzQuery(cl, ch2, nil))
	f1, f2 := u1.Query().Get("flow"), u2.Query().Get("flow")
	if u1.Path != "/oauth/consent" || u2.Path != "/oauth/consent" || f1 == f2 {
		t.Fatalf("%s %s", u1, u2)
	}
	// browser B cannot view or answer A's consent
	if resp := h.get(b, u1.RequestURI()); resp.StatusCode != 403 {
		t.Fatalf("consent page in other browser: %d", resp.StatusCode)
	}
	if st := consent(b, csrfB, f1, true); st != 403 {
		t.Fatalf("consent POST in other browser: %d", st)
	}
	// browser A can answer both, in either order
	if resp := h.get(a, u2.RequestURI()); resp.StatusCode != 200 {
		t.Fatalf("consent page: %d", resp.StatusCode)
	}
	if st := consent(a, csrfA, f2, true); st != 200 {
		t.Fatalf("flow 2: %d", st)
	}
	if st := consent(a, csrfA, f1, true); st != 200 {
		t.Fatalf("flow 1: %d", st)
	}
}

// jwks_uri refetch policy.
func TestJWKSURIRefetchPolicy(t *testing.T) {
	oldForce, oldMax := jwksForceEvery, jwksBackoffMax
	jwksForceEvery, jwksBackoffMax = 200*time.Millisecond, time.Second
	defer func() { jwksForceEvery, jwksBackoffMax = oldForce, oldMax }()

	keys := newAssertionKeys(t)
	good, other := keys[0], newAssertionKeys(t)[0] // same alg, same kid "ck1", different key
	var hits, badHits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad" {
			badHits.Add(1)
			http.Error(w, "no", http.StatusInternalServerError)
			return
		}
		hits.Add(1)
		_, _ = w.Write([]byte(good.jwks))
	}))
	defer srv.Close()
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) {
		in.AuthMethod = ptr(model.AuthMethodPrivateJWT)
		in.JWKSURI = ptr(srv.URL + "/jwks")
	})
	signWith := func(c *model.Client, k assertionKey, kid string) string {
		b, _ := json.Marshal(h.assertionClaims(c, nil))
		tok, err := signJWT(k.alg, k.priv, mkHeader(k.alg, kid, "JWT"), b)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	if r := h.ccWithAssertion(cl, signWith(cl, good, "ck1")); r.status != 200 {
		t.Fatal(r.m)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits %d", hits.Load())
	}
	// known kid, wrong signature: never refetch, even after the interval
	time.Sleep(250 * time.Millisecond)
	for range 5 {
		if r := h.ccWithAssertion(cl, signWith(cl, other, "ck1")); r.status != 401 {
			t.Fatalf("bogus assertion accepted: %v", r.m)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("known kid caused refetch: %d", hits.Load())
	}
	// unknown kid: at most one refetch per interval
	for range 5 {
		h.ccWithAssertion(cl, signWith(cl, other, "nope"))
	}
	if hits.Load() != 2 {
		t.Fatalf("unknown kid refetches: %d, want 2 total", hits.Load())
	}
	time.Sleep(250 * time.Millisecond)
	for range 5 {
		h.ccWithAssertion(cl, signWith(cl, other, "nope"))
	}
	if hits.Load() != 3 {
		t.Fatalf("after interval: %d, want 3 total", hits.Load())
	}

	// failing endpoint: exponential backoff
	bad, _ := h.newClient(func(in *service.ClientInput) {
		in.AuthMethod = ptr(model.AuthMethodPrivateJWT)
		in.JWKSURI = ptr(srv.URL + "/bad")
	})
	try := func() {
		for range 4 {
			h.ccWithAssertion(bad, signWith(bad, good, "ck1"))
		}
	}
	try()
	if badHits.Load() != 1 {
		t.Fatalf("failing uri hit %d times in a burst", badHits.Load())
	}
	time.Sleep(250 * time.Millisecond) // past the first backoff (200ms)
	try()
	if badHits.Load() != 2 {
		t.Fatalf("after first backoff: %d", badHits.Load())
	}
	time.Sleep(250 * time.Millisecond) // inside the doubled backoff (400ms)
	try()
	if badHits.Load() != 2 {
		t.Fatalf("backoff did not grow: %d", badHits.Load())
	}
	time.Sleep(250 * time.Millisecond)
	try()
	if badHits.Load() != 3 {
		t.Fatalf("after second backoff: %d", badHits.Load())
	}
	// the delay is capped
	for range 40 {
		h.p.jwksMu.Lock()
		rj := h.p.remoteKey[srv.URL+"/bad"]
		rj.retryAt = time.Time{}
		h.p.jwksMu.Unlock()
		h.p.remoteKeys(context.Background(), srv.URL+"/bad", false)
	}
	h.p.jwksMu.Lock()
	d := time.Until(h.p.remoteKey[srv.URL+"/bad"].retryAt)
	h.p.jwksMu.Unlock()
	if d > jwksBackoffMax {
		t.Fatalf("backoff %v exceeds cap", d)
	}
}
