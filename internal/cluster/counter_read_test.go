package cluster

import (
	"strconv"
	"testing"
	"time"
)

// A counter read on a node that does not own the counter is answered from the owner's last answer for up to
// counterReadTTL (no round trip on the requests that pass a limit), and every attempt that counts goes to the owner
// and refreshes it: a node lets at most one attempt past a limit reached through other nodes before it refuses too.
// (A counter starts again when its owner changes, as when gossip suspects a node under load: the scenario is then
// run again on a fresh key.)
func TestCounterReadsUseTheOwnersLastAnswer(t *testing.T) {
	c := covStarted(t)
	reader := c.nodes[0].n
	er := reader.Ephemeral()
	ownerOf := func(key string) *Node {
		mb := reader.hrw("rl", key)
		if mb == nil || mb.id == reader.ID() {
			return nil
		}
		for _, tn := range c.nodes {
			if tn.n.ID() == mb.id {
				return tn.n
			}
		}
		return nil
	}
	scenario := func(key string, owner *Node) (string, bool) {
		if n, err := er.Incr(bg, "rl", key, 0, time.Minute); err != nil || n != 0 {
			return "first read: " + strconv.FormatInt(n, 10), true
		}
		// attempts counted through other nodes: the reader's remembered answer does not see them yet...
		if _, err := owner.eph.local.Incr(bg, "rl", key, 5, time.Minute); err != nil {
			return err.Error(), true
		}
		if n, _ := er.Incr(bg, "rl", key, 0, time.Minute); n != 0 {
			return "a read within the TTL went to the owner: " + strconv.FormatInt(n, 10), true
		}
		// ...until the reader's own attempt, which the owner counts and answers with the true value
		if n, err := er.Incr(bg, "rl", key, 1, time.Minute); err != nil || n != 6 {
			return "counted attempt: " + strconv.FormatInt(n, 10), true
		}
		if n, _ := er.Incr(bg, "rl", key, 0, time.Minute); n != 6 {
			return "a read after the attempt: " + strconv.FormatInt(n, 10), true
		}
		// and past the TTL a read asks the owner again
		if _, err := owner.eph.local.Incr(bg, "rl", key, 1, time.Minute); err != nil {
			return err.Error(), true
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if n, _ := er.Incr(bg, "rl", key, 0, time.Minute); n == 7 {
				return "", false
			}
			time.Sleep(50 * time.Millisecond)
		}
		return "the remembered answer did not expire", true
	}
	for i, tries := 0, 0; tries < 5; i++ {
		key := "k" + strconv.Itoa(i)
		owner := ownerOf(key)
		if owner == nil {
			continue
		}
		tries++
		failure, failed := scenario(key, owner)
		if !failed {
			return
		}
		if ownerOf(key) == owner {
			t.Fatal(failure) // the owner did not change: the failure is real
		}
		t.Logf("the counter's owner changed mid-way (%s): again on a fresh key", failure)
	}
	t.Fatal("the counters' owners kept changing")
}
