package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
)

type fakeHealth struct{ ready bool }

func (f *fakeHealth) Ready() (bool, string) {
	if f.ready {
		return true, ""
	}
	return false, "catching up"
}

// A node that is not ready (starting, catching up, copying, out of date, cut off) serves nothing but the probes
// and static files — management and SCIM reads, authorization pages, discovery and JWKS alike — so a caller that
// bypasses the load balancer never gets partial or resurrected data. The token, userinfo and introspection endpoints
// answer only within the grace of a node that was serving and got cut off.
func TestServeGate(t *testing.T) {
	h := &fakeHealth{}
	tokens := false
	s := &Server{Health: h, ServesTokens: func() bool { return tokens }}
	gate := s.serveGate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) }))
	do := func(method, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		gate.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec
	}
	for _, p := range []string{"/healthz", "/readyz", "/assets/app.js", "/branding/logo-light"} {
		if c := do("GET", p).Code; c != 299 {
			t.Errorf("not ready, %s: %d, want served", p, c)
		}
	}
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/orgs/acme/users"}, {"GET", "/scim/v2/Users"}, {"GET", "/oauth/authorize?client_id=x"},
		{"GET", "/oauth/jwks"}, {"GET", "/.well-known/openid-configuration"}, {"GET", "/admin"}, {"GET", "/account"},
		{"POST", "/oauth/token"}, {"GET", "/oauth/userinfo"}, {"POST", "/api-internal/login/password"},
	} {
		rec := do(c.method, c.path)
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
			t.Errorf("not ready, %s %s: %d, want 503 with Retry-After", c.method, c.path, rec.Code)
		}
	}
	tokens = true // cut off after serving, within the grace
	for _, p := range []string{"/oauth/token", "/oauth/userinfo", "/oauth/introspect"} {
		if c := do("POST", p).Code; c != 299 {
			t.Errorf("within the grace, %s: %d", p, c)
		}
	}
	if c := do("GET", "/oauth/jwks").Code; c != http.StatusServiceUnavailable {
		t.Errorf("within the grace, jwks: %d", c)
	}
	h.ready = true
	if c := do("GET", "/api/orgs/acme/users").Code; c != 299 {
		t.Errorf("ready: %d", c)
	}
}

// The load shedder never refuses the probes, discovery or the signing keys: a busy node must not look dead or
// unready to its orchestrator, and relying parties must still validate tokens.
func TestShedExemptions(t *testing.T) {
	release := make(chan struct{})
	busy := make(chan struct{})
	h := shed(1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(busy)
			<-release
		}
		w.WriteHeader(299)
	}))
	go h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/slow", nil))
	select {
	case <-busy:
	case <-time.After(5 * time.Second):
		t.Fatal("the slow request did not start")
	}
	defer close(release)
	for _, p := range []string{"/healthz", "/readyz", "/oauth/jwks", "/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server", EventsPath} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != 299 {
			t.Errorf("shed %s: %d", p, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/orgs", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("an ordinary request at the limit: %d", rec.Code)
	}
}

// /readyz reports the cluster's counts (size, quorum, unconfirmed and refused writes, clock skew) with its
// status, ready or not.
func TestReadyzReportsClusterStatus(t *testing.T) {
	h := &fakeHealth{}
	s := &Server{Health: h, Log: logger.NewNullLogger(), Mux: http.NewServeMux(),
		Status: func() any { return map[string]int{"size": 3, "quorum": 2, "unconfirmed": 1} }}
	s.baseRoutes()
	for _, ready := range []bool{false, true} {
		h.ready = ready
		rec := httptest.NewRecorder()
		s.Mux.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
		var body struct {
			Status  string         `json:"status"`
			Cluster map[string]int `json:"cluster"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		want := map[bool]int{false: 503, true: 200}[ready]
		if rec.Code != want || body.Cluster["size"] != 3 || body.Cluster["quorum"] != 2 || body.Cluster["unconfirmed"] != 1 {
			t.Fatalf("ready %v: %d %s", ready, rec.Code, rec.Body.String())
		}
	}
}

// A node cut off from the majority refuses state-changing requests (management and SCIM writes, sign-ins including a
// provider's callback) but keeps serving reads, the token endpoint and sign-out.
func TestWriteGuard(t *testing.T) {
	writable := false
	s := &Server{Writable: func() bool { return writable }}
	h := s.writeGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) }))
	do := func(method, path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec.Code
	}
	for _, c := range []struct {
		method, path string
		refused      bool
	}{
		{"POST", "/api-internal/login/password", true},
		{"DELETE", "/api/orgs/acme/users/x", true},
		{"PATCH", "/scim/v2/Users/x", true},
		{"GET", "/login/callback/0192f3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b", true},
		{"HEAD", "/login/callback/0192f3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b", true},
		{"POST", "/verify-email", true},
		{"GET", "/verify-email?token=x", false}, // the page only: confirming it writes
		{"HEAD", "/account", false},
		{"GET", "/api/orgs/acme/users", false},
		{"GET", "/account", false},
		{"POST", "/oauth/token", false},
		{"POST", "/oauth/introspect", false},
		{"POST", "/oauth/logout/confirm", false},
	} {
		want := 299
		if c.refused {
			want = http.StatusServiceUnavailable
		}
		if got := do(c.method, c.path); got != want {
			t.Errorf("%s %s: %d, want %d", c.method, c.path, got, want)
		}
	}
	writable = true
	if got := do("GET", "/login/callback/x"); got != 299 {
		t.Errorf("writable node refused the callback: %d", got)
	}
}

// /metrics exists only with metrics.token set, and answers only that token as a bearer token.
func TestMetricsEndpoint(t *testing.T) {
	s := &Server{Cfg: config.Default()}
	get := func(auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/metrics", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		s.metrics(rec, r)
		return rec
	}
	if rec := get(""); rec.Code != 404 {
		t.Fatalf("no token configured: %d", rec.Code)
	}
	s.Cfg.Metrics.Token = "s3cret-token"
	if rec := get(""); rec.Code != 401 || rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("no credentials: %d", rec.Code)
	}
	if rec := get("Bearer wrong"); rec.Code != 401 {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	if rec := get("Basic s3cret-token"); rec.Code != 401 {
		t.Fatalf("wrong scheme: %d", rec.Code)
	}
	rec := get("Bearer s3cret-token")
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
}
