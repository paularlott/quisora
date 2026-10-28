package service

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// AuditQuery selects one page of the audit log. Org "" means every organization (super admins only). Sort is
// "created" (the default) or "action"; Search matches the actor, target and IP address (case-insensitive
// substring). The filters narrow it further: From and To bound when (at or after From, before To; zero: open),
// ActionPrefix is a family of actions ("user."), Action one action, Outcome "success" or "failure". Actor and Target
// select the events with exactly that actor or target (ListAudit uses them to find what a reader may not see).
type AuditQuery struct {
	Org          string
	Search       string
	From, To     time.Time
	ActionPrefix string
	Action       string
	Outcome      string
	Actor        string
	Target       string
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
	hide, err := s.auditHide(ctx, a)
	if err != nil {
		return AuditPage{}, err // fail closed: what the reader may not see is not known
	}
	if hide == nil {
		return s.readAudit(ctx, q)
	}
	return s.readAuditSeen(ctx, q, hide)
}

// readAudit reads the audit log from where it is kept: the AuditReader (VictoriaLogs, a gossip cluster), else this
// node's store.
func (s *Service) readAudit(ctx context.Context, q AuditQuery) (AuditPage, error) {
	if s.AuditReader != nil {
		return s.AuditReader.ReadAudit(ctx, q)
	}
	return s.readAuditStore(ctx, q)
}

// auditHide is who the audit log does not show to its reader: the events they acted in or were the target of are left
// out, as the users themselves are hidden or shown as directory entries (Visibility).
type auditHide struct {
	users []*model.User
	ids   map[string]bool
	names map[string]bool // organization and username (lower case): events name their users by username
}

// auditHide returns what a may not see in the audit log: the super admins (below them they are invisible, wherever
// they acted) and whoever else a does not see in full in a's organization. Nil for those who see everyone.
func (s *Service) auditHide(ctx context.Context, a *Actor) (*auditHide, error) {
	if seesSuperAdmins(a) {
		return nil, nil
	}
	supers, _, err := s.Users.List(ctx, store.ListQuery{Filters: []store.Filter{{Field: "super_admin", Value: true}}})
	if err != nil {
		return nil, mapStore(err)
	}
	above, err := s.usersNotSeenInFull(ctx, a, a.OrgID)
	if err != nil {
		return nil, err
	}
	h := &auditHide{ids: map[string]bool{}, names: map[string]bool{}}
	for _, u := range append(supers, above...) {
		if h.ids[u.ID] {
			continue
		}
		h.users = append(h.users, u)
		h.ids[u.ID] = true
		h.names[auditNameKey(u.OrgID, u.Username)] = true
	}
	return h, nil
}

func auditNameKey(orgID, name string) string { return orgID + "\x00" + strings.ToLower(name) }

// hides reports whether e names a hidden user as its actor or target. A name counts only in the organization of the
// user who has it (another organization's user may have the same username), an id anywhere.
func (h *auditHide) hides(e *model.Audit) bool {
	return h.ids[e.ActorID] || h.ids[e.Target] || h.names[auditNameKey(e.OrgID, e.Actor)] ||
		h.names[auditNameKey(e.OrgID, e.Target)]
}

// auditScan is how many events one read of the events to leave out takes.
const auditScan = 500

// readAuditSeen reads the page q asks for with the events h hides left out, and the total without them (so neither the
// page nor its count tells a reader that such events exist). The hidden events of q are found first (hiddenEvents); the
// page is then read with room for them, which keeps its offset and order right whichever of its events come first.
func (s *Service) readAuditSeen(ctx context.Context, q AuditQuery, h *auditHide) (AuditPage, error) {
	gone, err := s.hiddenEvents(ctx, q, h)
	if err != nil {
		return AuditPage{}, err
	}
	offset, limit := q.Offset, q.Limit
	q.Offset, q.Limit = 0, offset+limit+len(gone)
	p, err := s.readAudit(ctx, q)
	if err != nil {
		return AuditPage{}, err
	}
	p.Total = max(p.Total-len(gone), 0)
	// an event that arrived since hiddenEvents read is hidden all the same
	p.Items = slices.DeleteFunc(p.Items, func(e *model.Audit) bool { return gone[e.ID] || h.hides(e) })
	p.Items = p.Items[min(offset, len(p.Items)):]
	p.Items = p.Items[:min(limit, len(p.Items))]
	return p, nil
}

// hiddenEvents returns the ids of the events of q that h hides. The audit log has no way to ask for "all but these", so
// it is asked for each hidden user's events, as actor (by username) and as target (by username and by id).
func (s *Service) hiddenEvents(ctx context.Context, q AuditQuery, h *auditHide) (map[string]bool, error) {
	gone := map[string]bool{}
	q.Sort, q.Desc, q.Limit = "created", false, auditScan
	for _, u := range h.users {
		for _, who := range []struct{ actor, target string }{{u.Username, ""}, {"", u.Username}, {"", u.ID}} {
			q.Actor, q.Target, q.Offset = who.actor, who.target, 0
			for {
				p, err := s.readAudit(ctx, q)
				if err != nil {
					return nil, err
				}
				for _, e := range p.Items {
					if h.hides(e) {
						gone[e.ID] = true
					}
				}
				q.Offset += len(p.Items)
				if len(p.Items) == 0 || q.Offset >= p.Total {
					break
				}
			}
		}
	}
	return gone, nil
}

// readAuditStore reads the audit log from this node's store (a standalone node, or nodes sharing one database).
func (s *Service) readAuditStore(ctx context.Context, q AuditQuery) (AuditPage, error) {
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
	if q.Actor != "" {
		lq.Filters = append(lq.Filters, store.Filter{Field: "actor", Value: q.Actor})
	}
	if q.Target != "" {
		lq.Filters = append(lq.Filters, store.Filter{Field: "target", Value: q.Target})
	}
	return lq
}
