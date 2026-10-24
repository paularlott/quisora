package vlogs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

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
