package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
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

// The metrics table of docs/RUNNING.md names every metric a node serves, and only those: the test starts a node with
// everything that adds metrics of its own (VictoriaLogs, email) and compares what /metrics serves with the table.
func TestMetricsDocumented(t *testing.T) {
	vl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer vl.Close()
	_, hc, base := startAppWith(t, "sqlite", func(c *config.Config) {
		c.Metrics.Token = "scrape-secret"
		c.Audit.VictoriaLogs = vl.URL
		c.Mail.SMTPHost, c.Mail.SMTPPort, c.Mail.TLS = "127.0.0.1", 1, "none" // (nothing is sent)
	})
	req, _ := http.NewRequest("GET", base+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer scrape-secret")
	r, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	var served []string
	for _, m := range regexp.MustCompile(`(?m)^# TYPE (\S+) `).FindAllStringSubmatch(string(body), -1) {
		served = append(served, m[1])
	}

	doc, err := os.ReadFile("../../docs/RUNNING.md")
	if err != nil {
		t.Fatal(err)
	}
	section := string(doc)[strings.Index(string(doc), "### Metrics"):]
	section = section[:strings.Index(section, "Alerts worth having")]
	var documented []string
	for _, line := range strings.Split(section, "\n") {
		if cells := strings.Split(line, "|"); len(cells) > 2 && strings.Contains(cells[1], "`quisora_") {
			for _, m := range regexp.MustCompile("`(quisora_[a-z0-9_]+)").FindAllStringSubmatch(cells[1], -1) {
				documented = append(documented, m[1])
			}
		}
	}
	for _, name := range served {
		if !slices.Contains(documented, name) {
			t.Errorf("%s is served but not in the metrics table of docs/RUNNING.md", name)
		}
	}
	for _, name := range documented {
		if !slices.Contains(served, name) {
			t.Errorf("%s is in the metrics table of docs/RUNNING.md but not served", name)
		}
	}
}

// The gauges of the node's short-lived state report its budget (limits.ephemeral_mb), the counters' and caches' caps,
// the memory each takes and its entries, and the refusals counter is served before anything was refused.
func TestEphemeralGauges(t *testing.T) {
	a, hc, base := startAppWith(t, "sqlite", func(c *config.Config) {
		c.Metrics.Token = "scrape-secret"
		c.Limits.EphemeralMB, c.Limits.HeldKB = 3, 0 // (held_kb may be at most 1/128 of it: off, here)
	})
	primary, err := a.Svc.PrimaryOrg(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// an authorization request, even one naming no application, is counted against its address: an entry is kept
	if r, err := hc.Get(base + "/o/" + primary.ID + "/oauth/authorize?client_id=none"); err == nil {
		r.Body.Close()
	}
	// and a cache entry, as a metadata document read is kept: counted apart from both
	if err := a.Node.LocalEphemeral().Set(context.Background(), ephemeral.CachePrefix+"test", "k", make([]byte, 1000), time.Minute); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", base+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer scrape-secret")
	r, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	value := func(name string) float64 {
		t.Helper()
		m := regexp.MustCompile(`(?m)^` + name + ` (\S+)$`).FindStringSubmatch(string(b))
		if m == nil {
			t.Fatalf("%s is not served", name)
		}
		v, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := value("quisora_ephemeral_budget_bytes"); v != 3<<20 {
		t.Errorf("budget %v, want %d", v, 3<<20)
	}
	// the counters' cap is limits.ephemeral_mb as well, but never below 16 MiB
	if v := value("quisora_ephemeral_counter_limit_bytes"); v != 16<<20 {
		t.Errorf("counters' cap %v, want %d", v, 16<<20)
	}
	// the entry is a rate-limit counter: counted apart from the sign-in state limits.ephemeral_mb limits
	if counters, n := value("quisora_ephemeral_counter_bytes"), value("quisora_ephemeral_entries"); counters <= 0 || n <= 0 {
		t.Errorf("counters %v bytes in %v entries", counters, n)
	}
	if used := value("quisora_ephemeral_bytes"); used != 0 {
		t.Errorf("sign-in state %v bytes, want 0 (only a counter is held)", used)
	}
	// the caches' cap is a sixteenth of limits.ephemeral_mb, but never below 4 MiB
	if v := value("quisora_ephemeral_cache_limit_bytes"); v != 4<<20 {
		t.Errorf("caches' cap %v, want %d", v, 4<<20)
	}
	if v := value("quisora_ephemeral_cache_bytes"); v < 1000 || v > 2000 {
		t.Errorf("caches %v bytes, want the one entry's", v)
	}
	if !strings.Contains(string(b), "# TYPE quisora_ephemeral_refused_total counter") {
		t.Error("the refusals counter is not served")
	}
}
