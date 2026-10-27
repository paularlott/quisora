package app

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
)

// GET /metrics answers only with metrics.token (and not at all without one), and reports the request, audit and
// cluster metrics.
func TestMetricsEndpoint(t *testing.T) {
	_, hc, base := startApp(t, "sqlite")
	if r, err := hc.Get(base + "/metrics"); err != nil || r.StatusCode != http.StatusNotFound {
		t.Fatalf("without metrics.token: %v %v", r, err)
	}

	a, hc, base := startAppWith(t, "sqlite", func(c *config.Config) { c.Metrics.Token = "scrape-secret" })
	primary, err := a.Svc.PrimaryOrg(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	get := func(tok string) (int, string) {
		req, _ := http.NewRequest("GET", base+"/metrics", nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		r, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}
	if code, _ := get(""); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := get("wrong"); code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", code)
	}
	// a failed sign-in shows up in the audit counter
	_, _ = hc.Post(base+"/o/"+primary.ID+"/api-internal/login/password", "application/json", strings.NewReader(`{}`))
	code, body := get("scrape-secret")
	if code != http.StatusOK {
		t.Fatalf("with the token: %d", code)
	}
	for _, want := range []string{"quisora_http_requests_total{code=", "quisora_http_request_duration_seconds_bucket",
		"quisora_ready 1", "quisora_writable 1", "quisora_build_info{version=", "quisora_audit_events_total"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
}
