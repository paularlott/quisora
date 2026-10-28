package scim

import (
	"sort"
	"strings"

	"github.com/paularlott/quisora/internal/store"
)

// project applies attributes / excludedAttributes to a resource. id and schemas are always returned.
func project(res map[string]any, attrs, excluded []string, sch *schemaSet) map[string]any {
	if len(attrs) == 0 && len(excluded) == 0 {
		return res
	}
	if len(attrs) > 0 {
		out := map[string]any{}
		for _, k := range []string{"schemas", "id"} {
			if v, ok := res[k]; ok {
				out[k] = v
			}
		}
		for _, a := range attrs {
			p, err := parsePath(a)
			if err != nil {
				continue
			}
			includePath(out, res, p, sch)
		}
		return out
	}
	out := make(map[string]any, len(res))
	for k, v := range res {
		out[k] = v
	}
	for _, a := range excluded {
		p, err := parsePath(a)
		if err != nil {
			continue
		}
		excludePath(out, p, sch)
	}
	return out
}

// container returns the map holding the attributes of p's schema and the key under which they live in res.
func container(res map[string]any, p attrPath, sch *schemaSet) map[string]any {
	if p.URN == "" || strings.EqualFold(p.URN, sch.core) {
		return res
	}
	if k, ok := keyOf(res, p.URN); ok {
		m, _ := res[k].(map[string]any)
		return m
	}
	return nil
}

func includePath(out, res map[string]any, p attrPath, sch *schemaSet) {
	isExt := p.URN != "" && !strings.EqualFold(p.URN, sch.core)
	if isExt && p.Name == "" { // a whole extension
		if k, ok := keyOf(res, p.URN); ok {
			out[k] = res[k]
		}
		return
	}
	src := container(res, p, sch)
	if src == nil {
		return
	}
	dst := out
	if isExt {
		k, _ := keyOf(res, p.URN)
		d, _ := out[k].(map[string]any)
		if d == nil {
			d = map[string]any{}
			out[k] = d
		}
		dst = d
	}
	k, ok := keyOf(src, p.Name)
	if !ok {
		return
	}
	if p.Sub == "" {
		dst[k] = src[k]
		return
	}
	switch v := src[k].(type) {
	case map[string]any:
		if sk, ok := keyOf(v, p.Sub); ok {
			m, _ := dst[k].(map[string]any)
			if m == nil {
				m = map[string]any{}
				dst[k] = m
			}
			m[sk] = v[sk]
		}
	case []any:
		arr, _ := dst[k].([]any)
		if arr == nil {
			arr = make([]any, len(v))
			for i := range v {
				arr[i] = map[string]any{}
			}
		}
		for i, e := range v {
			if em, ok := e.(map[string]any); ok {
				if sk, ok := keyOf(em, p.Sub); ok {
					arr[i].(map[string]any)[sk] = em[sk]
				}
			}
		}
		dst[k] = arr
	}
}

func excludePath(out map[string]any, p attrPath, sch *schemaSet) {
	isExt := p.URN != "" && !strings.EqualFold(p.URN, sch.core)
	if isExt && p.Name == "" {
		if k, ok := keyOf(out, p.URN); ok {
			delete(out, k)
		}
		return
	}
	dst := out
	if isExt {
		k, ok := keyOf(out, p.URN)
		if !ok {
			return
		}
		m, _ := out[k].(map[string]any)
		if m == nil {
			return
		}
		cp := make(map[string]any, len(m))
		for a, b := range m {
			cp[a] = b
		}
		out[k] = cp
		dst = cp
	}
	k, ok := keyOf(dst, p.Name)
	if !ok || (!isExt && (strings.EqualFold(k, "id") || strings.EqualFold(k, "schemas"))) {
		return
	}
	if p.Sub == "" {
		delete(dst, k)
		return
	}
	switch v := dst[k].(type) {
	case map[string]any:
		cp := make(map[string]any, len(v))
		for a, b := range v {
			if !strings.EqualFold(a, p.Sub) {
				cp[a] = b
			}
		}
		dst[k] = cp
	case []any:
		arr := make([]any, len(v))
		for i, e := range v {
			em, ok := e.(map[string]any)
			if !ok {
				arr[i] = e
				continue
			}
			cp := make(map[string]any, len(em))
			for a, b := range em {
				if !strings.EqualFold(a, p.Sub) {
					cp[a] = b
				}
			}
			arr[i] = cp
		}
		dst[k] = arr
	}
}

// pageQuery is q ordered by the store field (descending when the request says so) and cut to the page p asks for. A
// request for no resources (only the total) reads one: a limit of 0 means no limit.
func pageQuery(q store.ListQuery, p *listParams, field string) store.ListQuery {
	q.Sort, q.Desc, q.Offset, q.Limit = field, p.desc, p.start-1, max(p.count, 1)
	return q
}

// ---------------------------------------------------------------------------------------------------------------
// In-memory selection

// selectItems filters, sorts and pages resources held in memory.
func selectItems(items []map[string]any, p *listParams, sch *schemaSet) ([]map[string]any, int) {
	if p.filter != nil {
		kept := items[:0:0]
		for _, it := range items {
			if evalNode(p.filter, it, sch) {
				kept = append(kept, it)
			}
		}
		items = kept
	}
	if p.sortBy != nil {
		sortItems(items, *p.sortBy, p.desc, sch)
	}
	total := len(items)
	lo := min(p.start-1, total)
	hi := min(lo+p.count, total)
	return items[lo:hi], total
}

// sortItems orders resources by an attribute. Missing values sort last when ascending, first when descending.
func sortItems(items []map[string]any, path attrPath, desc bool, sch *schemaSet) {
	info := sch.info(path)
	type keyed struct {
		it  map[string]any
		val any
	}
	ks := make([]keyed, len(items))
	for i, it := range items {
		var v any
		for _, c := range resolve(it, path, sch) {
			if m, ok := c.(map[string]any); ok {
				c = getCI(m, "value")
			}
			if present(c) {
				v = c
				break
			}
		}
		if s, ok := v.(string); ok && !info.caseExact && info.typ != "dateTime" {
			v = strings.ToLower(s)
		}
		ks[i] = keyed{it, v}
	}
	sort.SliceStable(ks, func(i, j int) bool {
		c := compareSort(ks[i].val, ks[j].val)
		if desc {
			c = -c
		}
		return c < 0
	})
	for i := range ks {
		items[i] = ks[i].it
	}
}

func compareSort(a, b any) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1
	case b == nil:
		return -1
	}
	switch av := a.(type) {
	case string:
		if bv, ok := b.(string); ok {
			if ta, ok1 := parseTime(av); ok1 {
				if tb, ok2 := parseTime(bv); ok2 {
					return ta.Compare(tb)
				}
			}
			return strings.Compare(av, bv)
		}
	case bool:
		if bv, ok := b.(bool); ok {
			switch {
			case av == bv:
				return 0
			case !av:
				return -1
			}
			return 1
		}
	default:
		if af, ok := toFloat(a); ok {
			if bf, ok := toFloat(b); ok {
				return floatCmp(af, bf)
			}
		}
	}
	return 0
}

// listResponse writes a ListResponse.
func (rq *request) listResponse(items []map[string]any, total int, p *listParams, sch *schemaSet) {
	out := make([]any, len(items))
	for i, it := range items {
		out[i] = project(it, p.attrs, p.excluded, sch)
	}
	write(rq.w, 200, map[string]any{
		"schemas":      []string{schemaListResponse},
		"totalResults": total,
		"startIndex":   p.start,
		"itemsPerPage": len(out),
		"Resources":    out,
	})
}

// wantsAttr reports whether a top-level attribute is part of the response given attributes / excludedAttributes.
func wantsAttr(p *listParams, name string) bool {
	first := func(a string) string {
		if k := strings.LastIndexByte(a, ':'); k >= 0 {
			a = a[k+1:]
		}
		n, _, _ := strings.Cut(a, ".")
		n, _, _ = strings.Cut(n, "[")
		return n
	}
	for _, e := range p.excluded {
		if strings.EqualFold(e, name) {
			return false
		}
	}
	if len(p.attrs) == 0 {
		return true
	}
	for _, a := range p.attrs {
		if strings.EqualFold(first(a), name) {
			return true
		}
	}
	return false
}
