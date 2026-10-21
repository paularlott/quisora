package cluster

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Audit events stay on the node that records them (localOnly): an audit page asks every node for its newest
// matching events and merges them (AuditQuery).

// auditWait bounds how long an audit page waits for the other nodes.
const auditWait = 3 * time.Second

type auditReq struct {
	Scope   string // organization id, "" = all
	Search  string
	Sort    string // "created" or "action"
	Desc    bool
	Limit   int
	Filters []auditFilter
}

// auditFilter is a store.Filter on the wire: a string value, or a time (UnixMicro).
type auditFilter struct {
	Field string
	Op    string
	Str   string
	Time  int64
	IsT   bool
}

type auditResp struct {
	Recs  [][]byte
	Total int
	// Filtered says the node applied the request's filters: a node of an older build ignores them and answers with
	// unfiltered events, which are left out of the page (it counts as not answering).
	Filtered bool
}

func toAuditFilters(fs []store.Filter) []auditFilter {
	out := make([]auditFilter, 0, len(fs))
	for _, f := range fs {
		w := auditFilter{Field: f.Field, Op: f.Op}
		switch v := f.Value.(type) {
		case time.Time:
			w.Time, w.IsT = v.UnixMicro(), true
		case string:
			w.Str = v
		}
		out = append(out, w)
	}
	return out
}

func fromAuditFilters(fs []auditFilter) []store.Filter {
	out := make([]store.Filter, 0, len(fs))
	for _, w := range fs {
		f := store.Filter{Field: w.Field, Op: w.Op, Value: w.Str}
		if w.IsT {
			f.Value = time.UnixMicro(w.Time).UTC()
		}
		out = append(out, f)
	}
	return out
}

// handleAudit answers with this node's newest audit events matching the request.
func (n *Node) handleAudit(_ *gossip.Node, pkt *gossip.Packet) (any, error) {
	var req auditReq
	if err := pkt.Unmarshal(&req); err != nil {
		return nil, err
	}
	recs, total, err := n.localAudit(n.ctx, req)
	if err != nil {
		return nil, err
	}
	resp := &auditResp{Total: total, Filtered: true}
	for _, r := range recs {
		if b, err := encodeRecord(r); err == nil {
			resp.Recs = append(resp.Recs, b)
		}
	}
	return resp, nil
}

func (n *Node) localAudit(ctx context.Context, req auditReq) ([]*store.Record, int, error) {
	limit := min(max(req.Limit, 1), 5000)
	res, err := n.st.inner.List(ctx, model.KindAudit, store.ListQuery{Scope: req.Scope, Search: req.Search,
		Filters: fromAuditFilters(req.Filters), Sort: req.Sort, Desc: req.Desc, Limit: limit})
	if err != nil {
		return nil, 0, err
	}
	return res.Records, res.Total, nil
}

// AuditQuery returns the first q.Limit audit events matching q (scope, search, sort; q.Offset is ignored: ask for
// offset+limit and skip) across every node of the cluster, this one included, merged in q's order, with the total
// of matches on the nodes that answered. nodes is the cluster size and answered how many nodes answered within
// auditWait (this one counts): a node that is down or slow is missing from the page, not an error.
func (n *Node) AuditQuery(ctx context.Context, q store.ListQuery) (recs []*store.Record, total, nodes, answered int, err error) {
	req := auditReq{Scope: q.Scope, Search: q.Search, Sort: q.Sort, Desc: q.Desc, Limit: q.Limit,
		Filters: toAuditFilters(q.Filters)}
	own, total, err := n.localAudit(ctx, req)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	recs, nodes, answered = own, 1, 1
	if n.gc == nil {
		return recs, total, nodes, answered, nil
	}
	nodes = n.Size()
	peers := n.otherPeers()
	type reply struct {
		resp auditResp
		err  error
	}
	replies := make(chan reply, len(peers))
	for _, mb := range peers {
		go func(mb *member) {
			var resp auditResp
			err := n.gc.SendToWithResponse(mb.node, msgAudit, &req, &resp)
			replies <- reply{resp, err}
		}(mb)
	}
	timeout := time.NewTimer(auditWait)
	defer timeout.Stop()
	for range peers {
		select {
		case rp := <-replies:
			if rp.err != nil || (len(req.Filters) > 0 && !rp.resp.Filtered) {
				continue
			}
			answered++
			total += rp.resp.Total
			for _, b := range rp.resp.Recs {
				if r, err := decodeRecord(b); err == nil && r.Kind == model.KindAudit {
					recs = append(recs, r)
				}
			}
		case <-timeout.C:
			return mergeAudit(recs, q), total, nodes, answered, nil
		case <-ctx.Done():
			return nil, 0, 0, 0, ctx.Err()
		}
	}
	return mergeAudit(recs, q), total, nodes, answered, nil
}

// mergeAudit orders events from several nodes as q asks (by creation time or action, ties by id) and keeps the
// first q.Limit.
func mergeAudit(recs []*store.Record, q store.ListQuery) []*store.Record {
	created := func(r *store.Record) time.Time { t, _ := r.Fields["created"].(time.Time); return t }
	action := func(r *store.Record) string { s, _ := r.Fields["action"].(string); return strings.ToLower(s) }
	slices.SortStableFunc(recs, func(a, b *store.Record) int {
		c := 0
		if q.Sort == "action" {
			c = strings.Compare(action(a), action(b))
		}
		if c == 0 {
			c = created(a).Compare(created(b))
		}
		if c == 0 {
			c = strings.Compare(a.ID, b.ID)
		}
		if q.Desc {
			c = -c
		}
		return c
	})
	if q.Limit > 0 && len(recs) > q.Limit {
		recs = recs[:q.Limit]
	}
	return recs
}
