package cluster

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

type fresh6PartialReadFailure struct {
	store.Store
	fail atomic.Bool
}

// A stream dial uses the transport's dial timeout, not the request's context.
// Fresh must still stop awaiting replies when its caller's deadline expires.
func TestFresh6QuorumReadHonorsDeadlineDuringStreamDial(t *testing.T) {
	var slow atomic.Bool
	c := newTCluster(t, 3, memBackend)
	c.opts = func(o *Options) {
		o.Gossip = func(cfg *gossip.Config) {
			fastGossip(cfg)
			cfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
				if !slow.Load() {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(250 * time.Millisecond):
					return nil, errors.New("review: dial timed out")
				}
			}
		}
	}
	c.startAll()
	c.waitReady()
	slow.Store(true)
	defer slow.Store(false)
	ctx, cancel := context.WithTimeout(bg, 25*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.nodes[0].st().Fresh(ctx, model.KindUser, []string{"deadline-user"})
	if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
		t.Fatalf("quorum read ignored 25ms deadline for %s: %v", elapsed, err)
	}
}

func (s *fresh6PartialReadFailure) Lookup(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == model.KindUser && id == "stream-fault" && s.fail.Load() {
		return nil, errors.New("review: fault after earlier streamed records")
	}
	return s.Store.Lookup(ctx, kind, id)
}

// The first record is big enough to flush transport frames before the second
// lookup fails. A complete-looking first record must not count as a peer answer.
func TestFresh6PartialStreamDoesNotCountAsQuorumAnswer(t *testing.T) {
	c := newTCluster(t, 3, memBackend)
	fault := &fresh6PartialReadFailure{Store: memstore.New()}
	c.mks = map[int]backend{2: func(testing.TB, string) store.Store { return fault }}
	c.startAll()
	c.waitReady()
	ids := []string{"stream-first", "stream-fault"}
	for _, id := range ids {
		u := &model.User{Meta: model.Meta{ID: id}, OrgID: "org", Username: id, Active: true, GivenName: strings.Repeat("a", 100_000)}
		r, err := store.Encode(u)
		if err != nil {
			t.Fatal(err)
		}
		for _, tn := range c.nodes {
			if err := tn.st().inner.Put(bg, r); err != nil {
				t.Fatal(err)
			}
		}
	}
	fault.fail.Store(true)
	defer fault.fail.Store(false)
	c.drop(0, 1, true, msgRead)
	if _, err := c.nodes[0].st().Fresh(bg, model.KindUser, ids); !errors.Is(err, store.ErrUnconfirmed) {
		t.Fatalf("partial stream certified a read: %v", err)
	}
	c.drop(0, 1, false, msgRead)
	got, err := c.nodes[0].st().Fresh(bg, model.KindUser, ids)
	if err != nil || len(got) != len(ids) {
		t.Fatalf("healthy peer could not supply quorum after partial-stream failure: records=%d err=%v", len(got), err)
	}
}
