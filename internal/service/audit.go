package service

import (
	"context"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// AuditQuery selects one page of the audit log. Org "" means every organization (super admins only). Sort is
// "created" (the default) or "action"; Search matches the actor, target and IP address (case-insensitive
// substring). The filters narrow it further: From and To bound when (at or after From, before To; zero: open),
// ActionPrefix is a family of actions ("user."), Action one action, Outcome "success" or "failure".
type AuditQuery struct {
	Org          string
	Search       string
	From, To     time.Time
	ActionPrefix string
	Action       string
	Outcome      string
	Sort         string
	Desc         bool
	Offset       int
	Limit        int
}

// AuditPage is one page of audit events. Nodes and Answered say how many nodes the page was gathered from (a gossip
// cluster asks every node; a node that does not answer in time is missing from it); Source names where the events
// come from: "store", "cluster" or "victorialogs".
type AuditPage struct {
	Items    []*model.Audit
	Total    int
	Nodes    int
	Answered int
	Source   string
}

// AuditReader reads the audit log for the audit pages.
type AuditReader interface {
	ReadAudit(ctx context.Context, q AuditQuery) (AuditPage, error)
}

// AuditWriter takes audit events in place of the store (VictoriaLogs). It must not block.
type AuditWriter interface {
	WriteAudit(e *model.Audit)
}

// ListAudit pages the audit log: of one organization for its administrators (and super admins), of every
// organization (org "") for super admins only.
func (s *Service) ListAudit(ctx context.Context, a *Actor, orgID string, q AuditQuery) (AuditPage, error) {
	if orgID == "" {
		if a == nil || !a.IsSuper() {
			return AuditPage{}, ErrForbidden
		}
	} else if !s.canAdminOrg(a, orgID) {
		return AuditPage{}, ErrForbidden
	}
	q.Org = orgID
	switch q.Sort {
	case "": // no order asked for: newest first (desc reverses it)
		q.Sort, q.Desc = "created", !q.Desc
	case "action", "created":
	default:
		return AuditPage{}, Invalid("sort", "the audit log sorts by created or action")
	}
	if q.Limit <= 0 {
		q.Limit = 50
	}
	switch q.Outcome {
	case "", "success", "failure":
	default:
		return AuditPage{}, Invalid("outcome", "is success or failure")
	}
	if !q.From.IsZero() && !q.To.IsZero() && !q.From.Before(q.To) {
		return AuditPage{}, Invalid("to", "must be after from")
	}
	if s.AuditReader != nil {
		return s.AuditReader.ReadAudit(ctx, q)
	}
	return s.ReadAuditStore(ctx, q)
}

// ReadAuditStore reads the audit log from this node's store (a standalone node, or nodes sharing one database).
func (s *Service) ReadAuditStore(ctx context.Context, q AuditQuery) (AuditPage, error) {
	items, total, err := s.Audits.List(ctx, AuditListQuery(q))
	if err != nil {
		return AuditPage{}, mapStore(err)
	}
	return AuditPage{Items: items, Total: total, Nodes: 1, Answered: 1, Source: "store"}, nil
}

// AuditListQuery is the store query of an audit page. Created times break ties by id (UUIDv7: time ordered).
func AuditListQuery(q AuditQuery) store.ListQuery {
	lq := store.ListQuery{Scope: q.Org, Search: q.Search, Sort: q.Sort, Desc: q.Desc, Offset: q.Offset, Limit: q.Limit}
	if !q.From.IsZero() {
		lq.Filters = append(lq.Filters, store.Filter{Field: "created", Op: store.OpGTE, Value: q.From.UTC()})
	}
	if !q.To.IsZero() {
		lq.Filters = append(lq.Filters, store.Filter{Field: "created", Op: store.OpLT, Value: q.To.UTC()})
	}
	if q.ActionPrefix != "" {
		lq.Filters = append(lq.Filters, store.Filter{Field: "action", Op: store.OpPrefix, Value: q.ActionPrefix})
	}
	if q.Action != "" {
		lq.Filters = append(lq.Filters, store.Filter{Field: "action", Value: q.Action})
	}
	if q.Outcome != "" {
		lq.Filters = append(lq.Filters, store.Filter{Field: "outcome", Value: q.Outcome})
	}
	return lq
}
