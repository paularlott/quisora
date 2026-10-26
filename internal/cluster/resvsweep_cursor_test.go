package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// A sweep that fails part-way through a batch (here: its reads through the owners cannot be made) leaves its position
// where it was, so the next call reads the batch again instead of skipping what it did not reach until the next lap.
func TestReservationSweepKeepsItsPositionOnAnError(t *testing.T) {
	c := started(t, sqliteBackend())
	shortGrace(t, 600*time.Millisecond)
	key := model.TenantResourceKey("https://ghost.example.com")
	if _, err := c.nodes[0].st().claim(bg, &store.Record{Kind: model.KindTenant, ID: model.NewID()}, key); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "the reservation on node 2", func() bool {
		_, ok := c.reservationHolder(c.nodes[2], model.KindTenant, key)
		return ok
	})
	time.Sleep(reservationGrace + 200*time.Millisecond)
	var sw ReservationSweep
	// node 2 cannot ask the owners of the partitions (the holder is read through them)
	for _, j := range []int{0, 1} {
		c.drop(2, j, true, gossip.PartReadMsg)
	}
	ctx, cancel := context.WithTimeout(bg, 3*time.Second)
	defer cancel()
	if _, err := c.nodes[2].n.SweepReservations(ctx, &sw, 1); err == nil {
		t.Fatal("a sweep that could not read the holders succeeded")
	}
	for _, j := range []int{0, 1} {
		c.drop(2, j, false, gossip.PartReadMsg)
	}
	if sw.after != "" {
		t.Fatalf("the position moved on to %q although the batch was not judged", sw.after)
	}
	released, err := c.nodes[2].n.SweepReservations(bg, &sw, 1)
	if err != nil || released != 1 {
		t.Fatalf("the next call: released %d, %v", released, err)
	}
}
