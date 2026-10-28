package mail

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// A queued message survives a failing transport: it is retried after the backoff and then delivered; Queued counts
// what is waiting.
func TestRetryThenDeliver(t *testing.T) {
	cfg := config.Default()
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
	m := New(cfg, logger.NewNullLogger(), memstore.New(), "node-1", sealer, tr, 10*time.Millisecond, 10*time.Millisecond,
		10*time.Millisecond)
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
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	var calls atomic.Int32
	m := New(cfg, logger.NewNullLogger(), memstore.New(), "node-1", sealer, TransportFunc(func(context.Context, Message) error {
		calls.Add(1)
		return errors.New("nope")
	}), 5*time.Millisecond)
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
