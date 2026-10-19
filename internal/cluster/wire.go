package cluster

import (
	"fmt"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/shamaton/msgpack/v3"
)

// Message types (application range of the gossip library).
const (
	msgRecord  gossip.MessageType = gossip.UserMsg + 1  // broadcast: a replicated record
	_          gossip.MessageType = gossip.UserMsg + 2  // reserved: not to be reused for a different message
	msgPush    gossip.MessageType = gossip.UserMsg + 3  // request/response: apply a record and acknowledge (durable writes)
	msgFeed    gossip.MessageType = gossip.UserMsg + 4  // request/response: a page of the change feed
	msgEph     gossip.MessageType = gossip.UserMsg + 5  // request/response: an ephemeral operation on the owner
	msgPrepare gossip.MessageType = gossip.UserMsg + 6  // request/response: quorum compare-and-swap, phase 1
	msgCommit  gossip.MessageType = gossip.UserMsg + 7  // request/response: quorum compare-and-swap, phase 2
	msgAbort   gossip.MessageType = gossip.UserMsg + 8  // one-way: release a quorum compare-and-swap's intents
	msgRead    gossip.MessageType = gossip.UserMsg + 9  // request/response: records by id (quorum read)
	msgAudit   gossip.MessageType = gossip.UserMsg + 10 // request/response: a page of this node's audit events
)

// recordMsg carries one encoded record (see encodeRecord).
type recordMsg struct {
	B []byte
}

type ackMsg struct {
	OK bool  // the peer holds exactly this version now
	St uint8 // pushApplied, pushSuperseded or pushRefused
}

// feedReq asks for changes after Since in the feed identified by FeedID. When FeedID is not the responder's feed the
// responder serves from 0, and the caller sees the new FeedID in the reply.
type feedReq struct {
	FeedID string
	Since  uint64
	Limit  int
	// Fresh: the requester is a new member copying everything (no replication state of its own). A node restored
	// from a backup offers its data to such nodes only.
	Fresh bool
}

type feedResp struct {
	FeedID string
	Next   uint64
	More   bool
	Stale  bool // the responder refuses to serve (out of date, or misconfigured): nothing to copy
	// Fresh: the responder is a new node that has not copied the cluster's data yet. It is no source for another new
	// node (two of them must not make an empty cluster of their own); there is nothing in it for anyone else.
	Fresh bool
	// Empty (with Fresh): the new node holds no record at all yet. Then it cannot hold a deletion the asker lacks,
	// so the asker counts it as pulled for its sync point (a new cluster's first node next to new, empty peers).
	Empty bool
	Recs  [][]byte
	// Synced is the responder's sync point (unix nanos; see Node.syncPoint): its data holds every deletion made
	// before then that a majority acknowledged. A node whose own sync point is unknown (a first copy made without a
	// majority in view) ages from it.
	Synced int64
	// CatchingUp: the responder has not caught up with the cluster since it started. A node that started empty does
	// not count it towards its own catching up (caughtUpWith).
	CatchingUp bool
	// Origin: the responder holds every write the cluster has confirmed (Node.origin: it has caught up and fewer
	// than a quorum of nodes are ready). A node that started empty has caught up once it has copied everything from
	// it: this is how a new cluster forms around its first node.
	Origin bool
}

// Field type tags.
const (
	ftNil uint8 = iota
	ftString
	ftInt
	ftBool
	ftTime
)

type wireField struct {
	Name string
	Type uint8
	Int  int64
	Nano int32
	Str  string
	Bool bool
}

// wireRecord is the replicated form of a store.Record (array encoded). Field values keep their Go types.
type wireRecord struct {
	Kind    string
	ID      string
	Version uint64
	Origin  string
	Deleted bool
	Scope   string
	Unique  []string
	Fields  []wireField
	Data    []byte
	Expires int64 // unix nanoseconds, 0 = never
	Epoch   uint64
	Created uint64
}

func encodeRecord(r *store.Record) ([]byte, error) {
	w := wireRecord{Kind: string(r.Kind), ID: r.ID, Version: uint64(r.Version), Origin: r.Origin, Deleted: r.Deleted}
	if !r.Deleted {
		w.Scope, w.Unique, w.Data, w.Epoch, w.Created = r.Scope, r.Unique, r.Data, uint64(r.Epoch), uint64(r.Created)
		if !r.Expires.IsZero() {
			w.Expires = r.Expires.UnixNano()
		}
		if len(r.Fields) > 0 {
			w.Fields = make([]wireField, 0, len(r.Fields))
			for name, v := range r.Fields {
				f := wireField{Name: name}
				switch x := v.(type) {
				case nil:
				case string:
					f.Type, f.Str = ftString, x
				case bool:
					f.Type, f.Bool = ftBool, x
				case time.Time:
					f.Type, f.Int, f.Nano = ftTime, x.Unix(), int32(x.Nanosecond())
				case int:
					f.Type, f.Int = ftInt, int64(x)
				case int32:
					f.Type, f.Int = ftInt, int64(x)
				case int64:
					f.Type, f.Int = ftInt, x
				case uint32:
					f.Type, f.Int = ftInt, int64(x)
				case uint64:
					f.Type, f.Int = ftInt, int64(x)
				default:
					return nil, fmt.Errorf("cluster: unsupported field type %T for %q", v, name)
				}
				w.Fields = append(w.Fields, f)
			}
		}
	}
	return msgpack.MarshalAsArray(&w)
}

func decodeRecord(b []byte) (*store.Record, error) {
	var w wireRecord
	if err := msgpack.UnmarshalAsArray(b, &w); err != nil {
		return nil, fmt.Errorf("cluster: decode record: %w", err)
	}
	r := &store.Record{Kind: model.Kind(w.Kind), ID: w.ID, Version: hlc.Timestamp(w.Version), Origin: w.Origin,
		Deleted: w.Deleted, Scope: w.Scope, Unique: w.Unique, Data: w.Data, Epoch: hlc.Timestamp(w.Epoch),
		Created: hlc.Timestamp(w.Created)}
	if !r.Deleted && (r.Epoch >= r.Version || r.Created > r.Version) {
		// a generation cannot start at or after its own version: malformed or forged
		return nil, fmt.Errorf("cluster: decode record %s/%s: bad generation", w.Kind, w.ID)
	}
	if r.Deleted {
		r.Epoch, r.Created = 0, 0
	}
	if w.Expires != 0 {
		r.Expires = time.Unix(0, w.Expires)
	}
	if len(w.Fields) > 0 {
		r.Fields = make(map[string]any, len(w.Fields))
		for _, f := range w.Fields {
			switch f.Type {
			case ftNil:
				r.Fields[f.Name] = nil
			case ftString:
				r.Fields[f.Name] = f.Str
			case ftInt:
				r.Fields[f.Name] = f.Int
			case ftBool:
				r.Fields[f.Name] = f.Bool
			case ftTime:
				r.Fields[f.Name] = time.Unix(f.Int, int64(f.Nano)).UTC()
			}
		}
	}
	return r, nil
}
