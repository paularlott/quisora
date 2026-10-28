package mail

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/logger"
	logtest "github.com/paularlott/logger/testing"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/metrics"
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

// One organization's burst fills its own share of the queue, not the queue: past its share its messages are refused,
// while another organization's, and the server's own (no organization), are still queued.
func TestOneOrgsBurstDoesNotBlockAnother(t *testing.T) {
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	stuck := TransportFunc(func(ctx context.Context, _ Message) error { <-ctx.Done(); return ctx.Err() })
	m := New(config.Default(), logger.NewNullLogger(), memstore.New(), "node-1", sealer, stuck)
	defer m.Close()
	ctx := context.Background()
	msg := func(org string) Message { return Message{To: "bob@example.com", Subject: "s", Text: "t", OrgID: org} }
	for i := range QueueSize / 4 {
		if err := m.Send(ctx, msg("burst")); err != nil {
			t.Fatalf("message %d of the burst: %v", i, err)
		}
	}
	if err := m.Send(ctx, msg("burst")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("past the organization's share: %v, want ErrQueueFull", err)
	}
	for _, org := range []string{"other", ""} {
		if err := m.Send(ctx, msg(org)); err != nil {
			t.Fatalf("organization %q beside the burst: %v", org, err)
		}
	}
}

// Messages go out by 8 at once, at most 2 of one organization: one organization's backlog takes 2 senders, and the
// others' messages go out beside it.
func TestSendersAreSharedBetweenOrganizations(t *testing.T) {
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	var mu sync.Mutex
	inFlight, perOrg, most := 0, map[string]int{}, map[string]int{}
	release := make(chan struct{})
	tr := TransportFunc(func(ctx context.Context, msg Message) error {
		mu.Lock()
		inFlight++
		perOrg[msg.OrgID]++
		most[msg.OrgID] = max(most[msg.OrgID], perOrg[msg.OrgID])
		mu.Unlock()
		select {
		case <-release:
		case <-ctx.Done():
		}
		mu.Lock()
		inFlight--
		perOrg[msg.OrgID]--
		mu.Unlock()
		return ctx.Err()
	})
	m := New(config.Default(), logger.NewNullLogger(), memstore.New(), "node-1", sealer, tr)
	defer m.Close()
	for i := range 20 { // the burst first
		if err := m.Send(context.Background(), Message{To: "bob@example.com", Text: strconv.Itoa(i), OrgID: "burst"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, org := range []string{"a", "b", "c", "d", "e"} {
		for range 2 {
			if err := m.Send(context.Background(), Message{To: "bob@example.com", Text: "t", OrgID: org}); err != nil {
				t.Fatal(err)
			}
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := inFlight
		mu.Unlock()
		if n == 8 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d messages sent at once, want 8", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // (for any that should not start)
	mu.Lock()
	if inFlight != 8 || most["burst"] != 2 {
		t.Errorf("%d sent at once, the burst's organization %d of them: want 8 and 2", inFlight, most["burst"])
	}
	mu.Unlock()
	close(release)
	deadline = time.Now().Add(5 * time.Second)
	for m.Queued() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if m.Queued() != 0 {
		t.Fatalf("%d still queued", m.Queued())
	}
}

// A message whose code or link has expired by the time its turn comes is dropped, not sent late.
func TestExpiredMessageIsNotSent(t *testing.T) {
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	var sent atomic.Int32
	tr := TransportFunc(func(context.Context, Message) error { sent.Add(1); return nil })
	m := New(config.Default(), logger.NewNullLogger(), memstore.New(), "node-1", sealer, tr)
	defer m.Close()
	ctx := context.Background()
	if err := m.Send(ctx, Message{To: "bob@example.com", Text: "stale code", Expires: time.Now().Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	if err := m.Send(ctx, Message{To: "bob@example.com", Text: "fresh code", Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for m.Queued() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if m.Queued() != 0 || sent.Load() != 1 {
		t.Fatalf("%d queued, %d sent: want the fresh one sent and the stale one dropped", m.Queued(), sent.Load())
	}
}

// Mail that is given up on after every retry, and mail whose code expired while it was queued, count in
// quisora_mail_failed_total by reason, and mail that is delivered does not; the retries log no recipient.
func TestFailedMailIsCounted(t *testing.T) {
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	var sentTo atomic.Int32
	tr := TransportFunc(func(_ context.Context, msg Message) error {
		if msg.Text == "ok" {
			sentTo.Add(1)
			return nil
		}
		return errors.New("nope")
	})
	logs := logtest.New()
	m := New(config.Default(), logs, memstore.New(), "node-1", sealer, tr, 5*time.Millisecond, 5*time.Millisecond)
	defer m.Close()
	givenUp, expired := metrics.MailFailed.Value("given_up"), metrics.MailFailed.Value("expired")
	ctx := context.Background()
	for _, msg := range []Message{
		{To: "bob@example.com", Text: "lost"},
		{To: "carol@example.com", Text: "stale", Expires: time.Now().Add(-time.Second)},
		{To: "dave@example.com", Text: "ok"},
	} {
		if err := m.Send(ctx, msg); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for (m.Queued() != 0 || metrics.MailFailed.Value("given_up") == givenUp) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := metrics.MailFailed.Value("given_up") - givenUp; n != 1 {
		t.Errorf("given up: %d, want 1", n)
	}
	if n := metrics.MailFailed.Value("expired") - expired; n != 1 || sentTo.Load() != 1 {
		t.Errorf("expired: %d, delivered %d: want 1 counted and the good one sent", n, sentTo.Load())
	}
	retries := 0
	for _, e := range logs.GetEntries() {
		if e.Message == "mail delivery failed, will retry" {
			retries++
			if strings.Contains(fmt.Sprint(e.KeysAndValues), "@example.com") {
				t.Errorf("a retry logged a recipient: %v", e.KeysAndValues)
			}
		}
	}
	if retries == 0 {
		t.Error("no retry was logged")
	}
}
