package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	logtesting "github.com/paularlott/logger/testing"
)

// The access log names every request by method, path and status, never its query string; probes are not logged.
func TestAccessLog(t *testing.T) {
	log := logtesting.New()
	h := observe(log, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusFound)
	}))
	for _, u := range []string{"/oauth/authorize?code=SECRETCODE&state=s", "/healthz"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", u, nil))
	}
	es := log.GetEntries()
	if len(es) != 1 {
		t.Fatalf("logged %d requests", len(es))
	}
	line := fmt.Sprint(es[0].KeysAndValues...)
	if !strings.Contains(line, "/oauth/authorize") || !strings.Contains(line, "302") || strings.Contains(line, "SECRETCODE") {
		t.Fatalf("access log line: %s", line)
	}

	off := logtesting.New()
	observe(off, false, http.NotFoundHandler()).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))
	if len(off.GetEntries()) != 0 {
		t.Fatal("logged with log.access off")
	}
}
