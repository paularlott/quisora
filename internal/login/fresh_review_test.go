package login_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

type freshInviteGate struct {
	store.Store
	userID  string
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

// CompareAndPut pauses the first acceptance as it stores its passkey: the last step before its commit (the flow
// stores the new passkey, then commits the account change). (It paused at clearing the old credentials when the flow
// did that before its commit.)
func (s *freshInviteGate) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindPasskey && r.Scope == s.userID && s.armed.CompareAndSwap(true, false) {
		close(s.entered)
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

// The losing acceptance must neither replace the winner's passkey nor register a usable credential.
func TestFreshReviewRejectedInviteCompletionCannotReplaceWinnerPasskey(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.LoginPerIPMin = 0 })
	org := e.org(t, "acme", nil)
	u, link := e.invitee(t, org, "newbie")
	a, b := e.browser(t), e.browser(t)
	bodyA, st, out := a.invitePasskeyBody(tokenOf(link), nil)
	if st != 200 {
		t.Fatalf("begin A: %d %v", st, out)
	}
	bodyB, st, out := b.invitePasskeyBody(tokenOf(link), nil)
	if st != 200 {
		t.Fatalf("begin B: %d %v", st, out)
	}
	gate := &freshInviteGate{Store: e.Svc.Store, userID: u.ID, entered: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-gate.release:
		default:
			close(gate.release)
		}
	}()
	e.Svc.Store = gate
	e.Svc.Passkeys.S = gate
	gate.armed.Store(true)
	done := make(chan int, 1)
	go func() { res, _ := a.post("/api-internal/invite/complete", bodyA); done <- res.StatusCode }()
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request A did not reach storing its passkey")
	}
	res, out := b.post("/api-internal/invite/complete", bodyB)
	wantStatus(t, res, out, 200)
	winner, err := e.Svc.Passkeys.All(context.Background(), u.ID)
	if err != nil || len(winner) != 1 {
		t.Fatalf("winner passkeys: %v %v", winner, err)
	}
	close(gate.release)
	select {
	case st = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("request A did not finish")
	}
	if st != 410 {
		t.Fatalf("loser status: %d", st)
	}
	remaining, err := e.Svc.Passkeys.All(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	probe := e.browser(t)
	probe.auth = a.auth
	loserStatus, loserOut := probe.passkeyLogin(map[string]any{"org": "acme"})
	if len(remaining) != 1 || remaining[0].ID != winner[0].ID || loserStatus == 200 {
		ids := make([]string, 0, len(remaining))
		for _, pk := range remaining {
			ids = append(ids, pk.ID)
		}
		t.Fatalf("rejected completion replaced winner credential: winner=%s remaining=%v rejected passkey login=%d %v", winner[0].ID, ids, loserStatus, loserOut)
	}
}
