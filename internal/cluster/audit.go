package cluster

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
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

// A node answers another's audit request (handleAudit) within the asker's wait (auditReq.Wait), and never longer than
// auditServeWait: the asker has given up by then, and a query that ran on would be load nobody reads. It answers
// auditServeMax requests at once, and auditServeMaxScope of one organization's log (or every organization's), and
// refuses the rest at once as busy (errAuditBusy: the asker counts the node as not answering), not queued. A page
// fans out to every node, and the asking nodes' places (admin's gate) are each node's own: without these, the pages
// of every node together, each abandoned at auditWait, would pile up as queries on every other.
const (
	auditServeWait     = auditWait + time.Second
	auditServeMax      = 8
	auditServeMaxScope = auditServeMax / 2
)

// errAuditBusy refuses an audit request while the node already answers as many as it may (auditServeMax).
var errAuditBusy = errors.New("cluster: this node is already answering as many audit queries as it may")

// auditServing counts the audit requests a node is answering for others, in all and by scope.
type auditServing struct {
	mu    sync.Mutex
	total int
	scope map[string]int
}

// enter takes a place to answer a request of scope, and the function that gives it back; ok is false when there is
// none.
func (a *auditServing) enter(scope string) (leave func(), ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.total >= auditServeMax || a.scope[scope] >= auditServeMaxScope {
		return nil, false
	}
	if a.scope == nil {
		a.scope = map[string]int{}
	}
	a.total++
	a.scope[scope]++
	return func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.total--
		if a.scope[scope]--; a.scope[scope] <= 0 {
			delete(a.scope, scope)
		}
	}, true
}

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
	// CountMax bounds the node's count of matching events (store.ListQuery.CountMax; 0: none).
	CountMax int
	// Wait is how long the asker still waits for the answer, in milliseconds (0: not said, as from a node of an
	// earlier version): the node gives the query no longer, nor ever more than auditServeWait.
	Wait int64
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
// the same data set, within the asker's wait (auditServeWait at most), and while it answers no more than
// auditServeMax others (auditServing), else busy at once.
func (n *Node) handleAudit(sender *gossip.Node, pkt *gossip.Packet) (any, error) {
	if n.gc != nil && !n.sameDataSet(sender) {
		return nil, errOtherDataSet
	}
	var req auditReq
	if err := pkt.Unmarshal(&req); err != nil {
		return nil, err
	}
	leave, ok := n.auditServing.enter(req.Scope)
	if !ok {
		return nil, errAuditBusy
	}
	defer leave()
	wait := auditServeWait
	if d := time.Duration(req.Wait) * time.Millisecond; d > 0 && d < wait {
		wait = d
	}
	ctx, cancel := context.WithTimeout(n.ctx, wait)
	defer cancel()
	recs, total, err := n.localAudit(ctx, req)
	if err != nil {
		return nil, err
	}
	resp := &auditResp{Total: total}
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
// down). A node that fails part-way does not count as answering.
func (n *Node) askAudit(ctx context.Context, nd *gossip.Node, req auditReq, want int) (rp auditAnswer) {
	seen := map[string]bool{}
	for len(rp.recs) < want {
		page := req
		page.Offset, page.Limit = len(seen), want-len(seen)
		if dl, ok := ctx.Deadline(); ok { // the node gives the query no longer than this ask waits for it
			page.Wait = max(time.Until(dl).Milliseconds(), 1)
		}
		var resp auditResp
		if err := n.gc.SendToWithResponseContext(ctx, nd, msgAudit, &page, &resp); err != nil {
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
