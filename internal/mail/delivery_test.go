package mail

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
)

// A queued message survives a failing transport: it is retried after the backoff and then delivered; Queued counts
// what is waiting.
func TestRetryThenDeliver(t *testing.T) {
	cfg := config.Default()
	cfg.Server.DataDir = t.TempDir()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	var calls atomic.Int32
	done := make(chan Message, 1)
	tr := TransportFunc(func(_ context.Context, msg Message) error {
		if calls.Add(1) < 3 {
			return errors.New("smtp down")
		}
		done <- msg
		return nil
	})
	m, err := New(cfg, logger.NewNullLogger(), sealer, tr, 10*time.Millisecond, 10*time.Millisecond, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Send(context.Background(), Message{To: "bob@example.com", Subject: "s", Text: "t"}); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-done:
		if msg.To != "bob@example.com" || calls.Load() != 3 {
			t.Fatalf("%+v after %d calls", msg, calls.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("never delivered")
	}
	deadline := time.Now().Add(5 * time.Second)
	for m.Queued() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if m.Queued() != 0 {
		t.Fatalf("%d still queued", m.Queued())
	}
	if stale, lost := m.Reseal(); stale+lost != 0 {
		t.Fatalf("reseal left %d stale, %d lost", stale, lost)
	}
}

// A message that exhausts its backoff is dropped instead of retried forever.
func TestGiveUpAfterBackoff(t *testing.T) {
	cfg := config.Default()
	cfg.Server.DataDir = t.TempDir()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	var calls atomic.Int32
	m, err := New(cfg, logger.NewNullLogger(), sealer, TransportFunc(func(context.Context, Message) error {
		calls.Add(1)
		return errors.New("nope")
	}), 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	_ = m.Send(context.Background(), Message{To: "bob@example.com", Text: "t"})
	deadline := time.Now().Add(5 * time.Second)
	for (m.Queued() != 0 || calls.Load() < 2) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if m.Queued() != 0 || calls.Load() != 2 {
		t.Fatalf("queued=%d calls=%d", m.Queued(), calls.Load())
	}
}

func TestNewFailsOnUnusableDataDir(t *testing.T) {
	cfg := config.Default()
	f := t.TempDir() + "/file"
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Server.DataDir = f // a file where the directory should be
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	if _, err := New(cfg, logger.NewNullLogger(), sealer, TransportFunc(nil)); err == nil {
		t.Fatal("unusable data dir accepted")
	}
}

// The running mailer gives up the messages no configured master key opens, and only those.
func TestMailerPurgeLost(t *testing.T) {
	m := newMailer(t, nil, TransportFunc(func(context.Context, Message) error { return nil }))
	foreign, _ := secure.NewKeyring(secure.RandomBytes(32))
	p := filepath.Join(m.Cfg.DataPath(config.DirMailQueue), "00000000000000000001-aa.item") // queued long ago
	if err := os.WriteFile(p, []byte(foreign.SealFor("", []byte("x"))), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := m.PurgeLost(time.Now()); err != nil || n != 1 {
		t.Fatalf("purged %d: %v", n, err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("the lost message is still queued")
	}
	if m.Queued() != 0 {
		t.Fatalf("queued %d", m.Queued())
	}
}
