package kvstore

import (
	"errors"
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
	// Req is store.Record.Req. It is the last element of the array: a record stored before it existed is shorter and
	// decodes with Req "" (a retry of its write is then not recognised, as for any write that left no id).
	Req string
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
		Partition: r.Partition, PNum: ps.num, PSeq: ps.seq, Req: r.Req}
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

// decodeRecord reads what encodeRecord writes. It does not use reflection (a record is read on every Get and for
// every record of a listed page: this is the hot path of the store, and the reflecting decoder took twice as long and
// made more allocations): it reads the msgpack array of wireRecord's elements, in order, itself. A record stored
// before Req existed has one element fewer. Every string of the record is a piece of one copy of its body (so
// the strings of a record share that one allocation, and keep it alive as long as any of them does).
func decodeRecord(b []byte) (*stored, error) {
	r := reader{s: string(b)}
	n := r.array()
	if n != wireElements && n != wireElements-1 { // (a corrupt body fails here, or below)
		return nil, errors.New("kvstore: decode record: unexpected layout")
	}
	rec := &store.Record{Kind: model.Kind(r.str()), ID: r.str(), Version: hlc.Timestamp(r.int())}
	rec.Origin, rec.Deleted, rec.Scope = r.str(), r.bool(), r.str()
	if k := r.array(); k > 0 && r.ok() {
		rec.Unique = make([]string, k)
		for i := range rec.Unique {
			rec.Unique[i] = r.str()
		}
	}
	if k := r.array(); k > 0 && r.ok() {
		rec.Fields = make(map[string]any, k)
		for range k {
			if r.array() != 6 {
				r.fail()
				break
			}
			name, typ, i, nano, str, flag := r.str(), r.int(), r.int(), r.int(), r.str(), r.bool()
			switch uint8(typ) {
			case ftNil:
				rec.Fields[name] = nil
			case ftString:
				rec.Fields[name] = str
			case ftInt:
				rec.Fields[name] = i
			case ftBool:
				rec.Fields[name] = flag
			case ftTime:
				rec.Fields[name] = time.Unix(i, nano).UTC()
			}
		}
	}
	rec.Data = r.bin()
	if ns := r.int(); ns != 0 {
		rec.Expires = time.UnixMicro(ns / 1000).UTC() // (store.Record: to the microsecond, in UTC)
	}
	rec.Epoch, rec.Created = hlc.Timestamp(r.int()), hlc.Timestamp(r.int())
	rec.Partition = r.str()
	ps := pstamp{num: uint32(r.int()), seq: uint64(r.int())}
	if n == wireElements {
		rec.Req = r.str()
	}
	if !r.ok() {
		return nil, errors.New("kvstore: decode record: malformed body")
	}
	// Reading a version (one replicated from another node's clock) moves this node's clock past it, so its next
	// write of the record is newer.
	store.Witness(rec.Version)
	return &stored{rec: rec, ps: ps}, nil
}

// wireElements is the number of elements of a stored record (wireRecord's fields).
const wireElements = 16

// reader reads msgpack values from s. A value that is not what was asked for (or is cut off) fails the reader: it
// reads zero values from then on, and ok reports it.
type reader struct {
	s   string
	bad bool
}

func (r *reader) ok() bool { return !r.bad }

func (r *reader) fail() { r.bad, r.s = true, "" }

// take returns the next n bytes.
func (r *reader) take(n int) string {
	if n < 0 || n > len(r.s) {
		r.fail()
		return ""
	}
	v := r.s[:n]
	r.s = r.s[n:]
	return v
}

// uint reads a big endian unsigned integer of n bytes.
func (r *reader) uint(n int) uint64 {
	var v uint64
	for _, c := range []byte(r.take(n)) {
		v = v<<8 | uint64(c)
	}
	return v
}

// nil consumes a msgpack nil, if that is next.
func (r *reader) nil() bool {
	if len(r.s) > 0 && r.s[0] == 0xc0 {
		r.s = r.s[1:]
		return true
	}
	return false
}

// array reads an array header and returns its length (nil: 0).
func (r *reader) array() int {
	if r.nil() {
		return 0
	}
	switch t := r.take(1); {
	case t == "":
	case t[0]&0xf0 == 0x90:
		return int(t[0] & 0x0f)
	case t[0] == 0xdc:
		return int(r.uint(2))
	case t[0] == 0xdd:
		return int(r.uint(4))
	default:
		r.fail()
	}
	return 0
}

// str reads a string (nil: "").
func (r *reader) str() string {
	if r.nil() {
		return ""
	}
	switch t := r.take(1); {
	case t == "":
	case t[0]&0xe0 == 0xa0:
		return r.take(int(t[0] & 0x1f))
	case t[0] == 0xd9:
		return r.take(int(r.uint(1)))
	case t[0] == 0xda:
		return r.take(int(r.uint(2)))
	case t[0] == 0xdb:
		return r.take(int(r.uint(4)))
	default:
		r.fail()
	}
	return ""
}

// bin reads a byte string as a copy (nil: nil).
func (r *reader) bin() []byte {
	if r.nil() {
		return nil
	}
	switch t := r.take(1); {
	case t == "":
	case t[0] == 0xc4:
		return []byte(r.take(int(r.uint(1))))
	case t[0] == 0xc5:
		return []byte(r.take(int(r.uint(2))))
	case t[0] == 0xc6:
		return []byte(r.take(int(r.uint(4))))
	default:
		r.fail()
	}
	return nil
}

func (r *reader) bool() bool {
	t := r.take(1)
	if t == "" || t[0]&^1 != 0xc2 {
		r.fail()
		return false
	}
	return t[0] == 0xc3
}

// int reads an integer of any msgpack width, signed or not (an unsigned 64 bit value comes back wrapped to int64).
func (r *reader) int() int64 {
	t := r.take(1)
	if t == "" {
		return 0
	}
	switch c := t[0]; {
	case c <= 0x7f || c >= 0xe0:
		return int64(int8(c))
	case c == 0xcc:
		return int64(r.uint(1))
	case c == 0xcd:
		return int64(r.uint(2))
	case c == 0xce:
		return int64(r.uint(4))
	case c == 0xcf || c == 0xd3:
		return int64(r.uint(8))
	case c == 0xd0:
		return int64(int8(r.uint(1)))
	case c == 0xd1:
		return int64(int16(r.uint(2)))
	case c == 0xd2:
		return int64(int32(r.uint(4)))
	}
	r.fail()
	return 0
}
