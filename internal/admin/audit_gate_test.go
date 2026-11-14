package admin

import (
	"fmt"
	"testing"

	"github.com/paularlott/quisora/internal/web"
)

// The gate holds web.AuditReadsInFlightPerBudget pages of one budget and web.AuditReadsInFlight in all, and a place
// given back (once, however often leave runs) is free again.
func TestAuditGate(t *testing.T) {
	var g auditGate
	var leaves []func()
	for i := range web.AuditReadsInFlightPerBudget {
		leave, ok := g.enter("a", true)
		if !ok {
			t.Fatalf("place %d of a budget refused", i+1)
		}
		leaves = append(leaves, leave)
	}
	if _, ok := g.enter("a", true); ok {
		t.Fatal("a budget took more than its places")
	}
	for b := 0; len(leaves) < web.AuditReadsInFlight; b++ {
		leave, ok := g.enter(fmt.Sprint("b", b/web.AuditReadsInFlightPerBudget), true)
		if !ok {
			t.Fatalf("place %d of the node refused", len(leaves)+1)
		}
		leaves = append(leaves, leave)
	}
	if _, ok := g.enter("fresh", true); ok {
		t.Fatal("the node took more than its places")
	}
	leaves[0]()
	leaves[0]() // twice: gives back one place, not two
	if _, ok := g.enter("fresh", true); !ok {
		t.Fatal("a place given back is not free")
	}
	if _, ok := g.enter("fresh2", true); ok {
		t.Fatal("leave gave back more than one place")
	}
	for _, leave := range leaves[1:] {
		leave()
	}
	if g.total != 1 || g.orgs != 0 || len(g.per) != 1 {
		t.Fatalf("after leaving: total %d, organizations' %d, budgets %v", g.total, g.orgs, g.per)
	}
}

// However many organizations search slowly at once, they cannot hold a super admin out of the log: the
// organizations' pages take all but web.AuditReadsInFlightSuper of the node's places, and the next organization is
// refused while a super admin's page still gets one. (With 4 places a budget and none kept back, four organizations
// held all 16.) It takes more than a few organizations to fill their share, and a place one gives back is theirs
// again.
func TestAuditGateKeepsPlacesForSuperAdmins(t *testing.T) {
	var g auditGate
	share := web.AuditReadsInFlight - web.AuditReadsInFlightSuper
	if web.AuditReadsInFlightSuper < web.AuditReadsInFlightPerBudget || share/web.AuditReadsInFlightPerBudget < 6 {
		t.Fatalf("places: %d kept for super admins, %d for organizations, %d a budget", web.AuditReadsInFlightSuper,
			share, web.AuditReadsInFlightPerBudget)
	}
	var leave func()
	for o := 0; ; o++ {
		budget := web.AuditBudgetOrg(fmt.Sprint("org", o))
		l, ok := g.enter(budget, false)
		if !ok {
			if o != share/web.AuditReadsInFlightPerBudget {
				t.Fatalf("organization %d refused its first place", o+1)
			}
			break
		}
		leave = l
		if _, ok := g.enter(budget, false); !ok {
			t.Fatalf("organization %d refused its second place", o+1)
		}
		if o > web.AuditReadsInFlight {
			t.Fatal("the organizations' places are not bounded")
		}
	}
	if g.orgs != share || g.total != share {
		t.Fatalf("organizations hold %d places of %d", g.orgs, g.total)
	}
	for i := range web.AuditReadsInFlightSuper {
		if _, ok := g.enter(web.AuditBudgetSuper(fmt.Sprint("root", i/web.AuditReadsInFlightPerBudget)), true); !ok {
			t.Fatalf("a super admin was refused place %d of those kept for them", i+1)
		}
	}
	if _, ok := g.enter(web.AuditBudgetSuper("another"), true); ok {
		t.Fatal("the node took more than its places")
	}
	leave()
	if _, ok := g.enter(web.AuditBudgetOrg("late"), false); !ok {
		t.Fatal("a place an organization gave back is not free for another")
	}
}
