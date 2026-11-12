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
// ActionPrefix is a family of actions ("user."), Action one action, Outcome "success" or "failure". NoSuperAdmins
// leaves out the events of super admins (model.Audit.SuperAdmin): ListAudit sets it for every reader below them.
type AuditQuery struct {
	Org           string
	Search        string
	From, To      time.Time
	ActionPrefix  string
	Action        string
	Outcome       string
	NoSuperAdmins bool
	Sort          string
	Desc          bool
	Offset        int
	Limit         int
}

// AuditPage is one page of audit events. Total counts the matching events up to a bound (auditCountMax, or the end
// of the page past it): More says there are more than Total, as an exact count would read the whole retained log on
// every page. Nodes and Answered say how many nodes the page was gathered from (a gossip cluster asks every node; a
// node that does not answer in time is missing from it); Source names where the events come from: "store",
// "cluster" or "victorialogs".
type AuditPage struct {
	Items    []*model.Audit
	Total    int
	More     bool
	Nodes    int
	Answered int
	Source   string
}

// AuditReader reads the audit log for the audit pages.
type AuditReader interface {
	ReadAudit(ctx context.Context, q AuditQuery) (AuditPage, error)
}

// AuditWriter takes audit events in place of the store (VictoriaLogs). It may wait for a local disk write (the
// spool) but never for the network.
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
	// Super admins are invisible below them (Visibility), so their events are too. Only administrators read an
	// organization's log, and they see everyone else of it in full: the super admins are all they may not see.
	q.NoSuperAdmins = !seesSuperAdmins(a)
	var p AuditPage
	var err error
	if s.AuditReader != nil {
		p, err = s.AuditReader.ReadAudit(ctx, q)
	} else {
		p, err = s.readAuditStore(ctx, q)
	}
	if most := auditCount(q); err == nil && p.Total > most {
		p.Total, p.More = most, true
	}
	return p, err
}

// auditCountMax is how many matching events an audit page counts: past it the page says there are more
// (AuditPage.More). A page past it counts to its own end, so that the next is offered while there are more.
const auditCountMax = 10000

// auditCount is the most matching events the page q counts, and reports as its total.
func auditCount(q AuditQuery) int { return max(auditCountMax, q.Offset+q.Limit) }

// readAuditStore reads the audit log from this node's store (a standalone node, or nodes sharing one database).
func (s *Service) readAuditStore(ctx context.Context, q AuditQuery) (AuditPage, error) {
	items, total, err := s.Audits.List(ctx, AuditListQuery(q))
	if err != nil {
		return AuditPage{}, mapStore(err)
	}
	return AuditPage{Items: items, Total: total, Nodes: 1, Answered: 1, Source: "store"}, nil
}

// AuditListQuery is the store query of an audit page. Created times break ties by id (model.NewID: time ordered).
// The store counts one match past the page's bound (auditCount), which tells ListAudit there are more.
func AuditListQuery(q AuditQuery) store.ListQuery {
	lq := store.ListQuery{Scope: q.Org, Search: q.Search, Sort: q.Sort, Desc: q.Desc, Offset: q.Offset, Limit: q.Limit,
		CountMax: auditCount(q) + 1}
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
	if q.NoSuperAdmins {
		lq.Filters = append(lq.Filters, store.Filter{Field: "super_admin", Value: false})
	}
	return lq
}
