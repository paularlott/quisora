package vlogs

// Regression tests from the external code reviews, one per finding: each states the failure it guards against.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/paularlott/logger"
)

type deepBlockedTransport struct{ entered chan struct{} }

func (tr deepBlockedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	close(tr.entered)
	<-r.Context().Done()
	return nil, r.Context().Err()
}

// A crash while delivery is blocked must preserve events accepted after the first batch was spooled.
func TestDeepAcceptedAuditSurvivesProcessExit(t *testing.T) {
	if dir := os.Getenv("QUISORA_DEEP_AUDIT_CHILD_DIR"); dir != "" {
		c, err := New("http://example.invalid", "review", logger.NewNullLogger())
		if err != nil {
			t.Fatal(err)
		}
		if err = c.Spool(dir, 1); err != nil {
			t.Fatal(err)
		}
		entered := make(chan struct{})
		c.http.Transport = deepBlockedTransport{entered: entered}
		c.Start()
		c.WriteAudit(event(1))
		<-entered              // first batch is on disk, writer is blocked delivering it
		c.WriteAudit(event(2)) // accepted successfully while writer is busy
		os.Exit(0)             // simulate process termination without graceful Close
	}
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestDeepAcceptedAuditSurvivesProcessExit$")
	cmd.Env = append(os.Environ(), "QUISORA_DEEP_AUDIT_CHILD_DIR="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v %s", err, out)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var all []byte
	for _, entry := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, entry.Name()))
		all = append(all, b...)
	}
	if !bytes.Contains(all, []byte(`"id":"ev-00002"`)) {
		t.Fatal("accepted event ev-00002 was absent from the spool after process exit while spool had free space")
	}
}

// A short append that reports an I/O error can leave a torn final line in the
// active segment. A later, successfully synced event must not be joined to it
// and silently discarded during replay once the disk has recovered.
func TestFreshSpoolAcceptedAppendSurvivesEarlierTornWrite(t *testing.T) {
	s, err := newSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store([]byte("{\"id\":\"first\"}\n")); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(s.dir, s.active), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	// This is precisely the residual file state of f.Write returning a partial
	// byte count and an error; store does not truncate or seal it on that path.
	if _, err := f.Write([]byte("{\"id\":\"torn")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store([]byte("{\"id\":\"accepted-after-recovery\"}\n")); err != nil {
		t.Fatal(err)
	}
	_, body := s.oldest()
	if !bytes.Contains(body, []byte("accepted-after-recovery")) {
		t.Fatalf("successfully synced event lost after earlier partial append: replay body %s", body)
	}
}

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
