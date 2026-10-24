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

func (s *reviewGateStore) Take(ctx context.Context, ns, id string) ([]byte, error) {
	b, e := s.Store.Take(ctx, ns, id)
	if ns == nsDevice && e == nil {
		close(s.taken)
		<-s.resume
	}
	return b, e
}
func TestReviewDevicePollDuringApproval(t *testing.T) {
	ctx := context.Background()
	local := ephemeral.NewLocal("review")
	defer local.Close()
	gate := &reviewGateStore{Store: local, taken: make(chan struct{}), resume: make(chan struct{})}
	p := &Provider{s: &web.Server{Eph: gate}}
	raw, _ := json.Marshal(deviceGrant{ClientID: "client", UserCode: "BCDFGHJK", Expires: time.Now().Add(time.Minute).Unix()})
	id, _ := local.New(ctx, nsDevice, raw, time.Minute)
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
	if oe == nil || oe.code == "expired_token" {
		t.Fatalf("live device grant returned terminal expiry during approval: %v", oe)
	}
}
