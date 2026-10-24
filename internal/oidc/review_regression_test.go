package oidc

import (
	"context"
	"encoding/json"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/web"
	"testing"
	"time"
)

type reviewGateStore struct {
	ephemeral.Store
	taken  chan struct{}
	resume chan struct{}
}

// Set pauses the approval just before it records the decision: the window in which a poll must not see the
// sign-in gone.
func (s *reviewGateStore) Set(ctx context.Context, ns, id string, value []byte, ttl time.Duration) error {
	if ns == nsDevice {
		close(s.taken)
		<-s.resume
	}
	return s.Store.Set(ctx, ns, id, value, ttl)
}
func TestReviewDevicePollDuringApproval(t *testing.T) {
	ctx := context.Background()
	local := ephemeral.NewLocal("review")
	defer local.Close()
	gate := &reviewGateStore{Store: local, taken: make(chan struct{}), resume: make(chan struct{})}
	p := &Provider{s: &web.Server{Eph: gate}}
	raw, _ := json.Marshal(deviceGrant{ClientID: "client", UserCode: "BCDFGHJK", Expires: time.Now().Add(time.Minute).Unix()})
	id, _ := local.New(ctx, nsDevice, raw, time.Minute)
	_ = local.Set(ctx, nsDeviceTurn, id, []byte{1}, time.Minute)
	done := make(chan bool, 1)
	go func() {
		done <- p.decideDevice(ctx, &flow{Device: id}, true, &model.Session{AuthTime: time.Now()}, &model.User{})
	}()
	<-gate.taken
	_, oe := p.deviceToken(ctx, &model.Client{Meta: model.Meta{ID: "client"}}, id, "")
	close(gate.resume)
	if !<-done {
		t.Fatal("approval failed")
	}
	if oe == nil || oe.code != "authorization_pending" {
		t.Fatalf("live device grant returned terminal expiry during approval: %v", oe)
	}
}
