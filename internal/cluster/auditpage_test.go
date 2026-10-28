package cluster

import (
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
)

// An organization's audit page needs that organization's log only: while a partition holding neither it nor the
// primary organization (where the super admins are) is being imported on the node, and so cannot be read there, an
// administrator of the primary organization still reads their page, without the super admin's events and with a total
// of what it shows.
func TestAuditPageNeedsNoUnrelatedPartition(t *testing.T) {
	c := started(t, badgerBackend())
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svc := service.New(config.Default(), c.nodes[0].st(), sealer)
	root, _, err := svc.Bootstrap(bg, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	primary, err := svc.PrimaryOrg(bg)
	if err != nil {
		t.Fatal(err)
	}
	name, role := "padmin", model.RoleAdmin
	admin, err := svc.CreateUser(bg, service.System, primary.ID, service.UserInput{Username: &name, GivenName: &name,
		Email: ptrTo("padmin@example.test"), Role: &role})
	if err != nil {
		t.Fatal(err)
	}
	unrelated := 1
	for unrelated == partitionNum(primary.ID) {
		unrelated++
	}
	n := c.nodes[0].n
	n.pst.importing[unrelated].Store(true)
	defer n.pst.importing[unrelated].Store(false)

	pg, err := svc.ListAudit(bg, service.ActorForUser(admin, ""), primary.ID, service.AuditQuery{Limit: 10})
	if err != nil {
		t.Fatalf("the audit page with partition %d unreadable: %v", unrelated, err)
	}
	if len(pg.Items) == 0 || pg.Total != len(pg.Items) {
		t.Fatalf("%d events, total %d", len(pg.Items), pg.Total)
	}
	for _, e := range pg.Items {
		if e.ActorID == root.ID || e.TargetID == root.ID {
			t.Fatalf("a super admin's event: %+v", e)
		}
	}
	all, err := svc.ListAudit(bg, service.ActorForUser(root, ""), primary.ID, service.AuditQuery{Action: "bootstrap", Limit: 10})
	if err != nil || all.Total != 1 {
		t.Fatalf("a super admin's page: %+v, %v", all, err)
	}
}
