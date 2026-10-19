package app

import (
	"context"
	"fmt"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/cluster"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/metrics"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/vlogs"
)

// setupAudit picks where audit events go and where the audit pages read them: VictoriaLogs when configured (from
// any node); otherwise the database — with gossip each node keeps its own events and a page asks every node.
func (a *App) setupAudit(c *config.Config, node *cluster.Node, log logger.Logger) error {
	if c.Audit.VictoriaLogs != "" {
		vl, err := vlogs.New(c.Audit.VictoriaLogs, node.ID(), log)
		if err != nil {
			return fmt.Errorf("audit: %w", err)
		}
		if c.Audit.SpoolDir != "" {
			if err := vl.Spool(c.Audit.SpoolDir, c.Audit.SpoolMaxMB); err != nil {
				return fmt.Errorf("audit: %w", err)
			}
		}
		vl.Start()
		a.closers = append(a.closers, vl.Close)
		metrics.Default.Gauge("quisora_audit_spool_bytes", "Disk space the VictoriaLogs spool uses: events VictoriaLogs has not taken yet.",
			nil, metrics.Value(func() float64 { return float64(vl.SpoolBytes()) }))
		a.Svc.AuditWriter, a.Svc.AuditReader = vl, vl
		return nil
	}
	if node.Replicating() {
		a.Svc.AuditReader = clusterAudit{node: node, svc: a.Svc}
	}
	return nil
}

// cliAudit sends a command's audit events to VictoriaLogs when it is configured (where the audit pages read them),
// as the server does; the returned function sends what is queued and must run before the command exits. Commands
// do not use the spool: its directory belongs to the server.
func cliAudit(c *config.Config, svc *service.Service, log logger.Logger) func() {
	if c.Audit.VictoriaLogs == "" {
		return func() {}
	}
	vl, err := vlogs.New(c.Audit.VictoriaLogs, "cli", log)
	if err != nil {
		return func() {}
	}
	vl.Start()
	svc.AuditWriter = vl
	return vl.Close
}

// clusterAudit reads the audit pages from every node of a gossip cluster (cluster.Node.AuditQuery).
type clusterAudit struct {
	node *cluster.Node
	svc  *service.Service
}

func (r clusterAudit) ReadAudit(ctx context.Context, q service.AuditQuery) (service.AuditPage, error) {
	lq := service.AuditListQuery(q)
	lq.Offset, lq.Limit = 0, q.Offset+q.Limit // each node's first offset+limit, merged, then the page
	recs, total, nodes, answered, err := r.node.AuditQuery(ctx, lq)
	if err != nil {
		return service.AuditPage{}, err
	}
	page := service.AuditPage{Total: total, Nodes: nodes, Answered: answered, Source: "cluster"}
	for i, rec := range recs {
		if i < q.Offset {
			continue
		}
		var e model.Audit
		if store.Decode(rec, &e) == nil {
			page.Items = append(page.Items, &e)
		}
	}
	return page, nil
}
