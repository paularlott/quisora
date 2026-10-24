package oidc

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/web"
)

// Hold the first PAR read after it took its snapshot, allowing another browser
// request to start and finish the authorization before the delayed read resumes.
type deepReviewPARReadGate struct {
	ephemeral.Store
	captured chan struct{}
	resume   chan struct{}
	held     atomic.Bool
}

func (g *deepReviewPARReadGate) Get(ctx context.Context, ns, id string) ([]byte, error) {
	b, err := g.Store.Get(ctx, ns, id)
	if ns == nsPAR && err == nil && g.held.CompareAndSwap(false, true) {
		close(g.captured)
		<-g.resume
	}
	return b, err
}
func TestDeepReviewDelayedPARStartCannotResurrectConsumedRequest(t *testing.T) {
	ctx := context.Background()
	local := ephemeral.NewLocal("deep-review")
	defer local.Close()
	gate := &deepReviewPARReadGate{Store: local, captured: make(chan struct{}), resume: make(chan struct{})}
	p := &Provider{s: &web.Server{Eph: gate}}
	raw, _ := json.Marshal(pushedRequest{ClientID: "client", Params: "client_id=client&response_type=code"})
	id, err := local.New(ctx, nsPAR, raw, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	loaded := make(chan error, 1)
	go func() { _, _, _, err := p.loadPushed(ctx, "client", parURNPrefix+id); loaded <- err }()
	<-gate.captured
	if _, _, used, err := p.loadPushed(ctx, "client", parURNPrefix+id); err != nil || used {
		t.Fatalf("second visit: used=%v err=%v", used, err)
	}
	if !p.usePushed(ctx, id) {
		t.Fatal("first completion refused")
	}
	close(gate.resume)
	if err := <-loaded; err != nil {
		t.Fatal(err)
	}
	if p.usePushed(ctx, id) {
		t.Fatal("consumed PAR request resurrected by delayed first-visit write; another authorization code can be issued")
	}
}
