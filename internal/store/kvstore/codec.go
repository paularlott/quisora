package kvstore

import (
	"fmt"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/shamaton/msgpack/v3"
)

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
	Int  int64 // int64 value, or unix seconds for times
	Nano int32 // nanoseconds for times
	Str  string
	Bool bool
}

// wireRecord is the stored form of a store.Record (array encoded, so field names cost nothing).
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
	// Partition is store.Record.Partition (the partition key). PNum and PSeq stamp a record written by ApplyPartition
	// or ImportPartition: the partition number and the sequence of the write that last changed it (PSeq 0: no stamp).
	Partition string
	PNum      uint32
	PSeq      uint64
}

// pstamp is the partition stamp of a stored record (PNum and PSeq of the wire form): zero when there is none.
type pstamp struct {
	num uint32
	seq uint64
}

// stored is a decoded record plus its partition stamp.
type stored struct {
	rec *store.Record
	ps  pstamp
}

func encodeRecord(r *store.Record, ps pstamp) ([]byte, error) {
	w := wireRecord{Kind: string(r.Kind), ID: r.ID, Version: uint64(r.Version), Origin: r.Origin, Deleted: r.Deleted,
		Scope: r.Scope, Unique: r.Unique, Data: r.Data, Epoch: uint64(r.Epoch), Created: uint64(r.Created),
		Partition: r.Partition, PNum: ps.num, PSeq: ps.seq}
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
				return nil, fmt.Errorf("kvstore: unsupported field type %T for %q", v, name)
			}
			w.Fields = append(w.Fields, f)
		}
	}
	return msgpack.MarshalAsArray(&w)
}

func decodeRecord(b []byte) (*stored, error) {
	var w wireRecord
	if err := msgpack.UnmarshalAsArray(b, &w); err != nil {
		return nil, fmt.Errorf("kvstore: decode record: %w", err)
	}
	r := &store.Record{Kind: model.Kind(w.Kind), ID: w.ID, Version: hlc.Timestamp(w.Version), Origin: w.Origin,
		Deleted: w.Deleted, Scope: w.Scope, Unique: w.Unique, Data: w.Data, Epoch: hlc.Timestamp(w.Epoch),
		Created: hlc.Timestamp(w.Created), Partition: w.Partition}
	// Reading a version (one replicated from another node's clock) moves this node's clock past it, so its next
	// write of the record is newer.
	store.Witness(r.Version)
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
	return &stored{rec: r, ps: pstamp{w.PNum, w.PSeq}}, nil
}
