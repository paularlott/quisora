package store

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
)

// ValidateQuery checks the sort and filter fields of q against the kind's schema.
func ValidateQuery(kind model.Kind, q ListQuery) error {
	s, ok := model.Schemas[kind]
	if !ok {
		return fmt.Errorf("%w: unknown kind %q", ErrBadQuery, kind)
	}
	if q.After != "" && (q.Sort != "" || q.Desc) {
		return fmt.Errorf("%w: after needs the default ascending id order", ErrBadQuery)
	}
	if q.Sort != "" {
		f, ok := s.Field(q.Sort)
		if !ok || !f.Sort {
			return fmt.Errorf("%w: cannot sort by %q", ErrBadQuery, q.Sort)
		}
	}
	for _, flt := range q.Filters {
		f, ok := s.Field(flt.Field)
		if !ok {
			return fmt.Errorf("%w: cannot filter by %q", ErrBadQuery, flt.Field)
		}
		switch flt.Op {
		case "":
		case OpPrefix:
			if _, ok := flt.Value.(string); !ok || f.Type != model.FieldString {
				return fmt.Errorf("%w: a prefix filter needs a string field and value (%q)", ErrBadQuery, flt.Field)
			}
		case OpGTE, OpLT:
			if f.Type != model.FieldTime && f.Type != model.FieldInt {
				return fmt.Errorf("%w: a range filter needs a time or integer field (%q)", ErrBadQuery, flt.Field)
			}
		default:
			return fmt.Errorf("%w: unknown filter operator %q", ErrBadQuery, flt.Op)
		}
	}
	return nil
}

// IndexFields recomputes a live record's index fields from its data (as encoding the entity would).
func IndexFields(r *Record) (map[string]any, error) {
	e := model.NewEntity(r.Kind)
	if e == nil {
		return nil, fmt.Errorf("%w: unknown kind %q", ErrBadQuery, r.Kind)
	}
	if err := Decode(r, e); err != nil {
		return nil, err
	}
	return e.Index().Fields, nil
}

// IsPlainScan reports whether q is a plain ID-ordered page (no search, filters or sort field).
func IsPlainScan(q ListQuery) bool {
	return q.Sort == "" && q.Search == "" && len(q.Filters) == 0
}

// ApplyQuery filters, searches, sorts and pages live records in memory. Backends without a query engine (and the
// in-memory store) use it over the records of a scope. recs must contain only records of the queried kind.
func ApplyQuery(kind model.Kind, recs []*Record, q ListQuery) (*ListResult, error) {
	c, err := NewCollector(kind, q)
	if err != nil {
		return nil, err
	}
	c.Add(recs)
	return c.Result(), nil
}

// Collector is ApplyQuery over records offered a batch at a time: it keeps only what the page can need (the first
// Offset+Limit matches in the query's order; every match without a limit) and counts the rest, so a backend that
// must read many records to answer a query holds a page's worth of them, not all.
type Collector struct {
	kind  model.Kind
	q     ListQuery
	keep  int // how many matches the page can need (0: all)
	recs  []*Record
	total int
}

// NewCollector validates q and returns a collector for it.
func NewCollector(kind model.Kind, q ListQuery) (*Collector, error) {
	if err := ValidateQuery(kind, q); err != nil {
		return nil, err
	}
	c := &Collector{kind: kind, q: q}
	if q.Limit > 0 {
		c.keep = q.Limit
		if q.After == "" {
			c.keep += max(q.Offset, 0)
		}
	}
	return c, nil
}

// Add offers records; those q selects are counted, and kept while they may be on the page.
func (c *Collector) Add(recs []*Record) {
	for _, r := range recs {
		if !Match(c.kind, r, c.q) || c.q.After != "" && r.ID <= c.q.After {
			continue
		}
		c.total++
		c.recs = append(c.recs, r)
		if c.keep > 0 && len(c.recs) >= 2*c.keep { // sorted now and then, so at most twice the page is held
			sortRecords(c.recs, c.q.Sort, c.q.Desc)
			clear(c.recs[c.keep:])
			c.recs = c.recs[:c.keep]
		}
	}
}

// Result returns the page and the total.
func (c *Collector) Result() *ListResult {
	sortRecords(c.recs, c.q.Sort, c.q.Desc)
	if c.q.After != "" {
		page := Page(c.recs, 0, c.q.Limit)
		return &ListResult{Records: page, Total: len(page)}
	}
	return &ListResult{Records: Page(c.recs, c.q.Offset, c.q.Limit), Total: c.total}
}

// Match reports whether r (a live record of kind) is selected by q's scope, filters and search; the order and paging
// of q play no part. A backend that streams a scope in the order the result asks for pages with it.
func Match(kind model.Kind, r *Record, q ListQuery) bool {
	if q.Scope != "" && r.Scope != q.Scope {
		return false
	}
	if !matchFilters(r, q.Filters) {
		return false
	}
	return q.Search == "" || matchSearch(r, model.Schemas[kind], strings.ToLower(q.Search))
}

// Page slices recs by offset and limit.
func Page(recs []*Record, offset, limit int) []*Record {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(recs) {
		return []*Record{}
	}
	recs = recs[offset:]
	if limit > 0 && limit < len(recs) {
		recs = recs[:limit]
	}
	return recs
}

func matchFilters(r *Record, filters []Filter) bool {
	for _, f := range filters {
		v := r.Fields[f.Field]
		switch f.Op {
		case OpPrefix:
			sv, _ := v.(string)
			if !strings.HasPrefix(strings.ToLower(sv), strings.ToLower(f.Value.(string))) {
				return false
			}
		case OpGTE:
			if v == nil || CompareValues(v, f.Value) < 0 {
				return false
			}
		case OpLT:
			if v == nil || CompareValues(v, f.Value) >= 0 {
				return false
			}
		default:
			if fld, _ := model.Schemas[r.Kind].Field(f.Field); fld.Words {
				sv, _ := v.(string)
				want, _ := f.Value.(string)
				if !slices.ContainsFunc(strings.Fields(sv), func(w string) bool { return strings.EqualFold(w, want) }) {
					return false
				}
			} else if !EqualValues(v, f.Value) {
				return false
			}
		}
	}
	return true
}

func matchSearch(r *Record, s model.Schema, needle string) bool {
	for _, f := range s.Fields {
		if !f.Search {
			continue
		}
		if v, ok := r.Fields[f.Name].(string); ok && strings.HasPrefix(strings.ToLower(v), needle) {
			return true
		}
	}
	return false
}

// EqualValues compares two field values, normalising integer types and times.
func EqualValues(a, b any) bool {
	switch av := a.(type) {
	case time.Time:
		bv, ok := b.(time.Time)
		return ok && av.Equal(bv)
	case nil:
		return b == nil || b == ""
	}
	if ai, ok := toInt64(a); ok {
		bi, ok := toInt64(b)
		return ok && ai == bi
	}
	return a == b
}

func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint32:
		return int64(n), true
	case uint64:
		return int64(n), true
	}
	return 0, false
}

// CompareValues orders two field values of the same type: strings case-insensitively, false < true, times and
// integers numerically; nil/zero sorts first.
func CompareValues(a, b any) int {
	switch av := a.(type) {
	case string:
		bv, _ := b.(string)
		return strings.Compare(strings.ToLower(av), strings.ToLower(bv))
	case bool:
		bv, _ := b.(bool)
		switch {
		case av == bv:
			return 0
		case !av:
			return -1
		}
		return 1
	case time.Time:
		bv, _ := b.(time.Time)
		return av.Compare(bv)
	case nil:
		if b == nil {
			return 0
		}
		return -1
	}
	ai, _ := toInt64(a)
	bi, _ := toInt64(b)
	switch {
	case ai < bi:
		return -1
	case ai > bi:
		return 1
	}
	return 0
}

func sortRecords(recs []*Record, field string, desc bool) {
	sort.SliceStable(recs, func(i, j int) bool {
		c := 0
		if field != "" {
			c = CompareValues(recs[i].Fields[field], recs[j].Fields[field])
			if desc {
				c = -c
			}
		}
		if c == 0 {
			c = strings.Compare(recs[i].ID, recs[j].ID)
			if field == "" && desc {
				c = -c
			}
		}
		return c < 0
	})
}
