package cluster

import (
	"errors"
	"testing"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/quisora/internal/store"
)

// A node that trails an organization's partition refuses to count or list that organization's records (a caller that
// decides on the answer, deleting a non-empty organization, would take a short answer for a true one), while a node
// that follows it answers.
func TestTrailingNodeRefusesToCountAnOrganization(t *testing.T) {
	var fs faults
	c := newTCluster(t, 3, fs.over(badgerBackend()))
	c.startAll()
	c.waitReady()
	org, _ := c.orgNotOwnedBy(1)
	p := partitionNum(org)
	if err := tenants(c.nodes[0]).Create(bg, newTenant(org, "first")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "the tenant on node 1", func() bool {
		n, err := tenants(c.nodes[1]).Count(bg, org)
		return err == nil && n == 1
	})
	fs.of(c.nodes[1]).failImport.Store(int64(p) + 1)
	for _, j := range []int{0, 2} {
		c.drop(j, 1, true, gossip.PartWriteMsg, gossip.PartCommitMsg)
	}
	if err := tenants(c.nodes[0]).Create(bg, newTenant(org, "second")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "node 1 to refuse counting the partition it trails", func() bool {
		_, err := tenants(c.nodes[1]).Count(bg, org)
		return errors.Is(err, store.ErrUnavailable)
	})
	if _, _, err := tenants(c.nodes[1]).List(bg, store.ListQuery{Scope: org}); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a listing on the trailing node: %v", err)
	}
	if n, err := tenants(c.nodes[0]).Count(bg, org); err != nil || n != 2 {
		t.Fatalf("the owner counts %d, %v", n, err)
	}
}
