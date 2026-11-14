package cluster

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// stuckAuditStore is a database whose audit queries run until their context ends, counting them in entered.
type stuckAuditStore struct {
	store.Store
	entered chan struct{}
}

func (s stuckAuditStore) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if kind != model.KindAudit {
		return &store.ListResult{}, nil
	}
	s.entered <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}

// A node answers another's audit request within the asker's wait, and auditServeWait at most, rather than for as
// long as the node runs: the asker has given up by then. (The query once ran on the node's own lifetime context, so
// every page abandoned at auditWait left a scan running on every other node.)
func TestPeerAuditQueryHasADeadline(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	n := &Node{ctx: ctx}
	n.st = &Store{n: n, inner: stuckAuditStore{entered: make(chan struct{}, 4)}}
	for _, tc := range []struct {
		wait time.Duration // the asker's
		want time.Duration // the most the node gives it
	}{{0, auditServeWait}, {300 * time.Millisecond, 300 * time.Millisecond}, {time.Hour, auditServeWait}} {
		done := make(chan error, 1)
		start := time.Now()
		go func() {
			_, err := n.handleAudit(nil, packetOf(t, auditReq{Limit: 10, Wait: tc.wait.Milliseconds()}))
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("a query given up answered as if complete")
			}
			if d := time.Since(start); d > tc.want+time.Second {
				t.Fatalf("asker's wait %s: answered after %s", tc.wait, d)
			}
		case <-time.After(tc.want + 2*time.Second):
			t.Fatalf("asker's wait %s: the query ran past its deadline", tc.wait)
		}
	}
}

// A node answers at most auditServeMax audit requests of others at once, and auditServeMaxScope of one log: the
// rest are refused at once as busy, not queued, and a place given back is free again.
func TestPeerAuditQueriesAreBounded(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	n := &Node{ctx: ctx}
	entered := make(chan struct{}, 2*auditServeMax)
	n.st = &Store{n: n, inner: stuckAuditStore{entered: entered}}
	done := make(chan error, 2*auditServeMax)
	ask := func(scope string) {
		go func() {
			_, err := n.handleAudit(nil, packetOf(t, auditReq{Scope: scope, Limit: 10, Wait: time.Hour.Milliseconds()}))
			done <- err
		}()
	}
	for range auditServeMaxScope {
		ask("org-a")
	}
	for range auditServeMaxScope {
		<-entered
	}
	ask("org-a") // past one log's share
	select {
	case err := <-done:
		if !errors.Is(err, errAuditBusy) {
			t.Fatalf("past one log's share: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a request past one log's share was queued")
	}
	for i := range auditServeMax - auditServeMaxScope {
		ask("org-" + string(rune('b'+i)))
	}
	for range auditServeMax - auditServeMaxScope {
		<-entered
	}
	ask("org-z") // past the node's places
	select {
	case err := <-done:
		if !errors.Is(err, errAuditBusy) {
			t.Fatalf("past the node's places: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a request past the node's places was queued")
	}
	stop() // every query ends: the places are free again
	for range auditServeMax {
		<-done
	}
	ctx, stop = context.WithCancel(context.Background())
	defer stop()
	n.ctx = ctx
	ask("org-a")
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("a place given back is not free: %v", err)
	}
}
