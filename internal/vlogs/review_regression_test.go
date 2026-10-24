package vlogs

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/paularlott/logger"
)

// An accepted event must be persisted before Close returns, even if the first
// delivery attempt is still waiting for VictoriaLogs. The process may exit as
// soon as Close returns.
func TestReviewCloseSpoolsInFlightBeforeReturning(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c, err := New(srv.URL, "review", logger.NewNullLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Spool(t.TempDir(), 1); err != nil {
		t.Fatal(err)
	}
	c.Start()
	defer func() {
		close(release)
		<-c.done
	}()
	c.WriteAudit(event(1))
	<-entered
	c.Close()
	segs, _ := c.spool.segments()
	if len(segs) == 0 {
		t.Fatal("Close returned with an accepted audit event neither delivered nor persisted; process exit loses it")
	}
}
