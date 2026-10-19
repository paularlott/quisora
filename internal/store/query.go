package store

import (
	"fmt"
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
		if _, ok := s.Field(flt.Field); !ok {
			return fmt.Errorf("%w: cannot filter by %q", ErrBadQuery, flt.Field)
		}
	}
	return nil
}

// IsPlainScan reports whether q is a plain ID-ordered page (no search, filters or sort field).
func IsPlainScan(q ListQuery) bool {
	return q.Sort == "" && q.Search == "" && len(q.Filters) == 0
}

// ApplyQuery filters, searches, sorts and pages live records in memory. Backends without a query engine (and the
// in-memory store) use it over the records of a scope. recs must contain only records of the queried kind.
func ApplyQuery(kind model.Kind, recs []*Record, q ListQuery) (*ListResult, error) {
	if err := ValidateQuery(kind, q); err != nil {
		return nil, err
	}
	schema := model.Schemas[kind]
	search := strings.ToLower(q.Search)
	out := make([]*Record, 0, len(recs))
	for _, r := range recs {
		if q.Scope != "" && r.Scope != q.Scope {
			continue
		}
		if !matchFilters(r, q.Filters) {
			continue
		}
		if search != "" && !matchSearch(r, schema, search) {
			continue
		}
		if q.After != "" && r.ID <= q.After {
			continue
		}
		out = append(out, r)
	}
	sortRecords(out, q.Sort, q.Desc)
	if q.After != "" {
		page := Page(out, 0, q.Limit)
		return &ListResult{Records: page, Total: len(page)}, nil
	}
	total := len(out)
	return &ListResult{Records: Page(out, q.Offset, q.Limit), Total: total}, nil
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
		if !EqualValues(r.Fields[f.Field], f.Value) {
			return false
		}
	}
	return true
}

func matchSearch(r *Record, s model.Schema, needle string) bool {
	for _, f := range s.Fields {
		if !f.Search {
			continue
		}
		if v, ok := r.Fields[f.Name].(string); ok && strings.Contains(strings.ToLower(v), needle) {
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
