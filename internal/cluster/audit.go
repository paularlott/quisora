package cluster

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Audit events stay on the node that records them (localOnly: a local write, never part of a partition write, export,
// import or seeding): an audit page asks every node of the same data set for its newest matching events and merges
// them (AuditQuery). The request travels as gossip, encrypted and authenticated with the cluster key like every message.

// auditWait bounds how long an audit page waits for the other nodes.
const auditWait = 3 * time.Second

type auditReq struct {
	Scope   string // organization id, "" = all
	Search  string
	Sort    string // "created" or "action"
	Desc    bool
	Limit   int // the most events to return, from Offset on
	Filters []auditFilter
	// Offset is how many of this node's matching events, in the request's order, come before the ones asked for: a
	// page cut short by the reply's size (auditResp.More) is followed by one that starts where it ended.
	Offset int
	// CountMax bounds the node's count of matching events (store.ListQuery.CountMax; 0: none, as from a node of an
	// older build).
	CountMax int
}

// auditFilter is a store.Filter on the wire: a string value, a time (UnixMicro), or a bool (the readers below super
// admin leave out the events of super admins: super_admin false).
type auditFilter struct {
	Field string
	Op    string
	Str   string
	Time  int64
	IsT   bool
	Bool  bool
	IsB   bool
}

type auditResp struct {
	Recs  [][]byte
	Total int
	// Filtered says the node applied the request's filters: a node of an older build ignores them and answers with
	// unfiltered events, which are left out of the page (it counts as not answering).
	Filtered bool
	// More says the node had more of the events asked for than fit one reply (auditReplyBytes): ask again from
	// the offset after the ones received.
	More bool
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
		case bool:
			w.Bool, w.IsB = v, true
		}
		out = append(out, w)
	}
	return out
}

func fromAuditFilters(fs []auditFilter) []store.Filter {
	out := make([]store.Filter, 0, len(fs))
	for _, w := range fs {
		f := store.Filter{Field: w.Field, Op: w.Op, Value: w.Str}
		switch {
		case w.IsT:
			f.Value = time.UnixMicro(w.Time).UTC()
		case w.IsB:
			f.Value = w.Bool
		}
		out = append(out, f)
	}
	return out
}

// errOtherDataSet refuses an audit request from a node of another data set (or none): its cluster is not this one.
var errOtherDataSet = errors.New("cluster: the asking node holds another data set")

// sameDataSet reports whether nd publishes the data set this node holds (a node that holds none matches nobody).
func (n *Node) sameDataSet(nd *gossip.Node) bool {
	g := n.genesis.Load()
	return g != nil && nd != nil && nd.Metadata != nil && nd.Metadata.GetString(metaGenesis) == *g
}

// handleAudit answers with this node's newest audit events matching the request: in a gossip cluster only to a node of
// the same data set.
func (n *Node) handleAudit(sender *gossip.Node, pkt *gossip.Packet) (any, error) {
	if n.gc != nil && !n.sameDataSet(sender) {
		return nil, errOtherDataSet
	}
	var req auditReq
	if err := pkt.Unmarshal(&req); err != nil {
		return nil, err
	}
	recs, total, err := n.localAudit(n.ctx, req)
	if err != nil {
		return nil, err
	}
	resp := &auditResp{Total: total, Filtered: true}
	size := 0
	for _, r := range recs {
		b, err := encodeRecord(r)
		if err != nil {
			continue
		}
		if size+len(b) > auditReplyBytes && len(resp.Recs) > 0 { // (a reply holds at least one event)
			resp.More = true
			break
		}
		size += len(b)
		resp.Recs = append(resp.Recs, b)
	}
	return resp, nil
}

// auditReplyBytes bounds the events in one audit reply (one message, the cluster's packet limit being 4 MB, with
// room for the rest of the reply): a node with more matching events than fit says so (auditResp.More) and the
// asker pages. A variable for tests.
var auditReplyBytes = 3 << 20

// auditPageMax is the most events one node returns for a page, over however many replies (a page asks each node for
// its first offset+limit).
const auditPageMax = 5000

// localAudit reads this node's own newest audit events matching req, from req.Offset.
func (n *Node) localAudit(ctx context.Context, req auditReq) ([]*store.Record, int, error) {
	limit := min(max(req.Limit, 1), auditPageMax)
	res, err := n.st.inner.List(ctx, model.KindAudit, store.ListQuery{Scope: req.Scope, Search: req.Search,
		Filters: fromAuditFilters(req.Filters), Sort: req.Sort, Desc: req.Desc, Limit: limit, Offset: max(req.Offset, 0),
		CountMax: req.CountMax})
	if err != nil {
		return nil, 0, err
	}
	return res.Records, res.Total, nil
}

// AuditQuery returns the first q.Limit audit events matching q (scope, search, sort; q.Offset is ignored: ask for
// offset+limit and skip) across every node of the cluster, this one included, merged in q's order, with the total
// of matches on the nodes that answered (each node counting up to q.CountMax). nodes is the cluster size and
// answered how many nodes answered within auditWait (this one counts): a node that is down or slow is missing from
// the page, not an error. Only the nodes that publish this node's data set are asked: a node set up apart is not
// part of this cluster's log.
func (n *Node) AuditQuery(ctx context.Context, q store.ListQuery) (recs []*store.Record, total, nodes, answered int, err error) {
	req := auditReq{Scope: q.Scope, Search: q.Search, Sort: q.Sort, Desc: q.Desc, Limit: q.Limit,
		Filters: toAuditFilters(q.Filters), CountMax: q.CountMax}
	own, total, err := n.localAudit(ctx, req)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	recs, nodes, answered = own, 1, 1
	if n.gc == nil {
		return recs, total, nodes, answered, nil
	}
	nodes = n.Size()
	var peers []*member
	for _, mb := range n.otherPeers() {
		if n.sameDataSet(mb.node) {
			peers = append(peers, mb)
		}
	}
	want := min(max(q.Limit, 1), auditPageMax)
	// Every ask ends by auditWait (the context's deadline), as not answered: a slow node is left out, not an error.
	askCtx, cancel := context.WithTimeout(ctx, auditWait)
	defer cancel()
	replies := make(chan auditAnswer, len(peers))
	for _, mb := range peers {
		go func(mb *member) { replies <- n.askAudit(askCtx, mb.node, req, want) }(mb)
	}
	for range peers {
		if rp := <-replies; rp.answered {
			answered++
			total += rp.total
			recs = append(recs, rp.recs...)
		}
	}
	if err := ctx.Err(); err != nil { // the caller went away: that is an error, a slow node is not
		return nil, 0, 0, 0, err
	}
	return mergeAudit(recs, q), total, nodes, answered, nil
}

// auditAnswer is what one node's replies to an audit request add up to.
type auditAnswer struct {
	recs     []*store.Record
	total    int
	answered bool
}

// askAudit asks one node for its first want events matching req, a reply at a time (the node cuts a reply by size:
// auditResp.More). Events are kept once each, whatever shifts between the pages (a newer event pushes the later ones
// down). A node that fails part-way, or of an older build that ignores the filters, does not count as answering.
func (n *Node) askAudit(ctx context.Context, nd *gossip.Node, req auditReq, want int) (rp auditAnswer) {
	seen := map[string]bool{}
	for len(rp.recs) < want {
		page := req
		page.Offset, page.Limit = len(seen), want-len(seen)
		var resp auditResp
		if err := n.gc.SendToWithResponseContext(ctx, nd, msgAudit, &page, &resp); err != nil ||
			(len(req.Filters) > 0 && !resp.Filtered) {
			return rp
		}
		rp.total = resp.Total
		fresh := 0
		for _, b := range resp.Recs {
			if r, err := decodeRecord(b); err == nil && r.Kind == model.KindAudit && !seen[r.ID] {
				seen[r.ID] = true
				rp.recs = append(rp.recs, r)
				fresh++
			}
		}
		if !resp.More || fresh == 0 {
			break
		}
	}
	rp.answered = true
	return rp
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
