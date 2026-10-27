package cluster

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/shamaton/msgpack/v3"
)

// Message types (application range of the gossip library). The partition protocol's own messages are the library's
// (gossip.PartHeartbeatMsg and the others of the partition block); these are Quisora's.
const (
	_         gossip.MessageType = gossip.UserMsg + 1  // reserved: the replicated record broadcast of the earlier gossip mode
	_         gossip.MessageType = gossip.UserMsg + 2  // reserved
	_         gossip.MessageType = gossip.UserMsg + 3  // reserved: durable push
	_         gossip.MessageType = gossip.UserMsg + 4  // reserved: change feed page
	msgEph    gossip.MessageType = gossip.UserMsg + 5  // request/response: an ephemeral operation on the owner
	_         gossip.MessageType = gossip.UserMsg + 6  // reserved: quorum compare-and-swap, phase 1
	_         gossip.MessageType = gossip.UserMsg + 7  // reserved: quorum compare-and-swap, phase 2
	_         gossip.MessageType = gossip.UserMsg + 8  // reserved: release a quorum compare-and-swap's intents
	_         gossip.MessageType = gossip.UserMsg + 9  // reserved: quorum read stream
	msgAudit  gossip.MessageType = gossip.UserMsg + 10 // request/response: a page of this node's own audit events
	msgNotice gossip.MessageType = gossip.UserMsg + 11 // broadcast, notice gossip only (cluster.notify): a record changed
	msgReload gossip.MessageType = gossip.UserMsg + 12 // request/response: re-read the configuration (check, or apply)
	_         gossip.MessageType = gossip.UserMsg + 13 // reserved: small quorum read
	msgClock  gossip.MessageType = gossip.UserMsg + 14 // request/response: this node's clock (the peer clock check)
)

// writeFrame writes b to a stream as one length-prefixed frame; readFrame reads it back (io.EOF at the end of a
// complete stream).
func writeFrame(w io.Writer, b []byte) error {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	if _, err := w.Write(l[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// maxFrame bounds one frame (one encoded record), so a corrupt length cannot cause a huge allocation.
const maxFrame = 16 << 20

func readFrame(r io.Reader) ([]byte, error) {
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err // io.EOF here: the stream ended between frames, complete
	}
	size := binary.BigEndian.Uint32(l[:])
	if size > maxFrame {
		return nil, fmt.Errorf("cluster: frame of %d bytes", size)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, io.ErrUnexpectedEOF
	}
	return b, nil
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
	// Partition is the record's partition key (store.Record.Partition); a tombstone carries it too, and its scope
	// (the change hooks need it: which organization's administrators, which user's pages).
	Partition string
	// Req is the request that wrote the record (store.Record.Req). Last, so records encoded before it decode.
	Req string
}

func encodeRecord(r *store.Record) ([]byte, error) {
	w := wireRecord{Kind: string(r.Kind), ID: r.ID, Version: uint64(r.Version), Origin: r.Origin, Deleted: r.Deleted,
		Epoch: uint64(r.Epoch), Scope: r.Scope, Partition: r.Partition, Req: r.Req}
	if !r.Deleted {
		w.Unique, w.Data, w.Created = r.Unique, r.Data, uint64(r.Created)
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
		Created: hlc.Timestamp(w.Created), Partition: w.Partition, Req: w.Req}
	if !r.Deleted && (r.Epoch >= r.Version || r.Created > r.Version) || r.Deleted && r.Epoch > r.Version {
		// a generation cannot start at or after its own version (a tombstone's may be its own version): malformed
		// or forged
		return nil, fmt.Errorf("cluster: decode record %s/%s: bad generation", w.Kind, w.ID)
	}
	if r.Deleted {
		r.Created = 0
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
