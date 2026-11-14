package ephemeral_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/metrics"
)

// A charge whose counter reports Contended (too contended to update, or a new counter past the counters' cap) says
// nothing of what the requester holds: it is ErrContended (answered 503), not ErrHeld (429, "you hold too much"), and
// it is not counted as held_bytes, where the real cause would be hidden.
func TestChargeContendedIsNotHeld(t *testing.T) {
	b := &ephemeral.Budget{Store: &contended{}, Limit: func() int64 { return 8 << 10 }}
	before := metrics.EphemeralRefused.Value("held_bytes")
	for name, charge := range map[string]func() (*ephemeral.Held, error){
		"charge": func() (*ephemeral.Held, error) {
			return b.Charge(context.Background(), ephemeral.Holder{Key: "ip|a"}, "ns", 10, time.Minute)
		},
		"for": func() (*ephemeral.Held, error) {
			return b.ChargeFor(context.Background(), ephemeral.Holder{Key: "ip|a"}, "ns", 10, time.Minute)
		},
		"guard": func() (*ephemeral.Held, error) {
			return b.ChargeGuard(context.Background(), ephemeral.Holder{Key: "ip|a"}, "ns", 10, time.Minute)
		},
	} {
		h, err := charge()
		if h != nil || !errors.Is(err, ephemeral.ErrContended) || errors.Is(err, ephemeral.ErrHeld) {
			t.Fatalf("%s on a contended counter: %v %v, want ErrContended and not ErrHeld", name, h, err)
		}
	}
	if got := metrics.EphemeralRefused.Value("held_bytes") - before; got != 0 {
		t.Fatalf("%d contended charges counted as held_bytes", got)
	}
}

// A refused charge says when the requester's budget frees: the seconds until the window that refused it ends (its
// counter there starts from nothing), not a constant that has compliant clients refused again.
func TestHeldRetryAfterIsWhenTheWindowEnds(t *testing.T) {
	ctx := context.Background()
	for name, st := range stores(t) {
		// 7 minutes 30.2 seconds into a 20-minute window
		at := time.Unix(0, 0).Add(1000*ephemeral.HeldWindow + 7*time.Minute + 30*time.Second + 200*time.Millisecond)
		restore := ephemeral.SetNow(func() time.Time { return at })
		b := &ephemeral.Budget{Store: st, Limit: func() int64 { return 4 << 10 }}
		var err error
		for range 100 {
			if _, err = b.Charge(ctx, ephemeral.Holder{Key: "ip|" + name}, "ns", 1000, 10*time.Minute); err != nil {
				break
			}
		}
		restore()
		if !errors.Is(err, ephemeral.ErrHeld) {
			t.Fatalf("%s: %v, want ErrHeld", name, err)
		}
		if got, want := ephemeral.RetryAfter(err, 60), int((12*time.Minute+30*time.Second)/time.Second); got != want {
			t.Fatalf("%s: Retry-After %d s, want %d (the window's end)", name, got, want)
		}
	}
	if got := ephemeral.RetryAfter(ephemeral.ErrContended, 5); got != 5 {
		t.Fatalf("Retry-After of an error that names no window: %d, want the default", got)
	}
}
