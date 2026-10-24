package vlogs

import (
	"bytes"
	"net/http"
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
