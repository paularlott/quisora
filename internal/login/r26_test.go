package login_test

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/metrics"
)

// contendedHeld is a store whose held budgets' counters are too contended to update (or past the counters' cap).
type contendedHeld struct{ ephemeral.Store }

func (e contendedHeld) Incr(ctx context.Context, ns, key string, delta int64, window time.Duration) (int64, error) {
	if ns == ephemeral.HeldNS {
		return ephemeral.Contended, nil
	}
	return e.Store.Incr(ctx, ns, key, delta, window)
}

// A sign-in at a provider whose state cannot be charged because the budget's counter could not be updated is 503
// with a short Retry-After (the server cannot count it now), not 429 "too many from your network", nor a failed
// sign-in, nor a server error; it is not counted as held_bytes. One refused for what its address holds is told to
// come back when the window that refused it ends, when the address may hold more again.
func TestProviderSignInHeldAnswers(t *testing.T) {
	u := newUpEnv(t, heldKB(64))
	p := u.oidcProvider(t, nil)
	next := u.at("/x?" + strings.Repeat("&", 1900))
	start := "/o/acme/login/provider/" + p.ID + "?next=" + url.QueryEscape(next)
	b := u.browser(t)

	orig := u.env.Server.Eph
	u.env.Server.Eph = contendedHeld{orig}
	held := metrics.EphemeralRefused.Value("held_bytes")
	res, _ := b.get(start)
	u.env.Server.Eph = orig
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a charge whose counter is contended: %d %q, want 503", res.StatusCode, res.Header.Get("Location"))
	}
	if ra, _ := strconv.Atoi(res.Header.Get("Retry-After")); ra < 1 || ra > 10 {
		t.Fatalf("Retry-After %q, want a short one", res.Header.Get("Retry-After"))
	}
	if metrics.EphemeralRefused.Value("held_bytes") != held {
		t.Fatal("a contended counter was counted as the address holding too much")
	}

	for range 60 {
		if res, _ = b.get(start); res.StatusCode != http.StatusFound {
			break
		}
	}
	n := time.Now().UnixNano()
	w := int64(ephemeral.HeldWindow)
	want := int((time.Duration((n/w+1)*w-n) + time.Second - 1) / time.Second)
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("no refusal: %d", res.StatusCode)
	}
	if want >= 55 && want <= 65 {
		t.Skip("the window ends about a minute from now: a constant would pass")
	}
	if got, _ := strconv.Atoi(res.Header.Get("Retry-After")); got < want-2 || got > want+1 {
		t.Fatalf("Retry-After %d s, want %d (the end of the window that refused)", got, want)
	}
}
