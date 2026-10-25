package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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
