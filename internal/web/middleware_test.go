package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	logtesting "github.com/paularlott/logger/testing"

	"github.com/paularlott/quisora/internal/model"
)

// A signed-out visitor goes to the sign-in page of the organization the page is about (its console pages name it), and
// otherwise to the primary organization's, coming back afterwards.
func TestSignInFor(t *testing.T) {
	var got string
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/orgs/{org}/", func(_ http.ResponseWriter, r *http.Request) { got = signInFor(r) })
	mux.HandleFunc("/admin/orgs/{org}", func(_ http.ResponseWriter, r *http.Request) { got = signInFor(r) })
	mux.HandleFunc("/", func(_ http.ResponseWriter, r *http.Request) { got = signInFor(r) })
	primary := "/o/" + model.PrimaryOrgID + "/login?next="
	for path, want := range map[string]string{
		"/admin/orgs/acme/users?x=1": "/o/acme/login?next=%2Fadmin%2Forgs%2Facme%2Fusers%3Fx%3D1",
		"/admin/orgs/acme":           "/o/acme/login?next=%2Fadmin%2Forgs%2Facme",
		"/admin/system":              primary + "%2Fadmin%2Fsystem",
		"/admin":                     primary + "%2Fadmin",
	} {
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil))
		if got != want {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
}

// The access log names every request by method, path, status and size, never its query string; probes, scrapes and
// static files are not logged. The status logged is the one sent (the first), and a streaming handler can still flush
// and reach the connection through the access log's writer.
func TestAccessLog(t *testing.T) {
	log := logtesting.New()
	var rec *httptest.ResponseRecorder
	h := observe(log, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stream" {
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("hello"))
		w.WriteHeader(http.StatusNotFound) // too late: the 200 was sent
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("flush: %v", err)
		}
		if u, ok := w.(interface{ Unwrap() http.ResponseWriter }); !ok || u.Unwrap() != http.ResponseWriter(rec) {
			t.Error("the access log's writer does not unwrap")
		}
	}))
	for _, p := range []string{"/healthz", "/readyz", "/metrics", "/assets/x.js", "/branding/logo-light", "/favicon.ico"} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
	}
	if es := log.GetEntries(); len(es) != 0 {
		t.Fatalf("quiet paths logged: %v", es)
	}
	field := func(e logtesting.LogEntry, key string) string {
		for i := 0; i+1 < len(e.KeysAndValues); i += 2 {
			if e.KeysAndValues[i] == key {
				return fmt.Sprint(e.KeysAndValues[i+1])
			}
		}
		return ""
	}
	for i, c := range []struct{ url, path, status, bytes string }{
		{"/oauth/authorize?code=SECRETCODE&state=s", "/oauth/authorize", "302", "0"},
		{"/login/acme", "/login/acme", "302", "0"},
		{"/api/orgs", "/api/orgs", "302", "0"},
		{"/stream", "/stream", "200", "5"},
	} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", c.url, nil))
		es := log.GetEntries()
		if len(es) != i+1 {
			t.Fatalf("%s: %d entries after %d logged requests", c.url, len(es), i+1)
		}
		if e := es[i]; field(e, "path") != c.path || field(e, "status") != c.status || field(e, "bytes") != c.bytes ||
			strings.Contains(fmt.Sprint(e.KeysAndValues...), "SECRETCODE") {
			t.Errorf("%s: access log entry %v", c.url, e.KeysAndValues)
		}
		if c.path == "/stream" && !rec.Flushed {
			t.Error("the stream was not flushed")
		}
	}

	off := logtesting.New()
	observe(off, false, http.NotFoundHandler()).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))
	if len(off.GetEntries()) != 0 {
		t.Fatal("logged with log.access off")
	}
}

// Images load only from this server, data: URIs and the hosts of logos configured as https URLs.
func TestCSPImageSources(t *testing.T) {
	if p := contentSecurityPolicy("", ""); !strings.Contains(p, "img-src 'self' data:;") {
		t.Fatalf("default: %s", p)
	}
	p := contentSecurityPolicy("https://cdn.example/logo.svg", "https://cdn.example/dark.svg")
	if !strings.Contains(p, "img-src 'self' data: https://cdn.example;") {
		t.Fatalf("with an https logo: %s", p)
	}
	if p := contentSecurityPolicy("/etc/quisora/logo.svg", "http://plain.example/x.png"); !strings.Contains(p, "img-src 'self' data:;") {
		t.Fatalf("file and http logos add nothing: %s", p)
	}
}
