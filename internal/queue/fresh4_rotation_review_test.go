package queue

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/secure"
)

// A failed reseal preserves an old-key item. Callers must use Reseal's result
// before reporting the rotation complete or removing that old key.
func TestFreshReviewFailedResealStillNeedsPreviousKey(t *testing.T) {
	oldKey, newKey := secure.RandomBytes(32), secure.RandomBytes(32)
	ring := sealer(t, oldKey)
	q := open(t, t.TempDir(), ring, &sink{})
	if err := q.Add("queued invitation", time.Hour, 0); err != nil {
		q.Close()
		t.Fatal(err)
	}
	q.Close()
	names, err := q.files()
	if err != nil || len(names) != 1 {
		t.Fatalf("files=%v err=%v", names, err)
	}
	// Deterministically fail the atomic replacement's temporary-file open.
	tmp := filepath.Join(q.dir, "."+names[0]+".tmp")
	if err := os.Mkdir(tmp, 0700); err != nil {
		t.Fatal(err)
	}
	ring.Replace(sealer(t, newKey, oldKey))
	failures := q.Reseal()
	if failures != 1 {
		t.Fatalf("failures=%d", failures)
	}
	if _, err := q.read(names[0]); err != nil {
		t.Fatal("old key should still open preserved item", err)
	}
	ring.Replace(sealer(t, newKey))
	_, err = q.read(names[0])
	if !errors.Is(err, secure.ErrUnknownKey) {
		t.Fatalf("expected missing previous key, got %v", err)
	}
	t.Logf("failed reseals=%d; dropping previous key makes accepted queue item unreadable: %v", failures, err)
}
