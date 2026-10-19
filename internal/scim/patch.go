package scim

import (
	"reflect"
	"sort"
	"strings"
)

// patchOp is one entry of a PatchOp request.
type patchOp struct {
	op       string // add, replace, remove
	path     *attrPath
	value    any
	hasValue bool
}

// parsePatch validates a PatchOp body. Operation names are case-insensitive (Entra sends "Add", "Replace",
// "Remove"); the list may be called Operations in any case.
func parsePatch(body map[string]any) ([]patchOp, *Error) {
	raw, ok := getCI(body, "Operations").([]any)
	if !ok || len(raw) == 0 {
		return nil, badSyntax("Operations must be a non-empty list")
	}
	ops := make([]patchOp, 0, len(raw))
	for i, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			return nil, badSyntax("Operations[%d] must be an object", i)
		}
		name, _ := getCI(m, "op").(string)
		op := patchOp{op: strings.ToLower(strings.TrimSpace(name))}
		switch op.op {
		case "add", "replace", "remove":
		default:
			return nil, badSyntax("Operations[%d]: op must be add, remove or replace", i)
		}
		if ps, _ := getCI(m, "path").(string); strings.TrimSpace(ps) != "" {
			p, err := parsePath(strings.TrimSpace(ps))
			if err != nil {
				return nil, badPath("Operations[%d]: %s", i, err.Error())
			}
			op.path = &p
		}
		if k, ok := keyOf(m, "value"); ok {
			op.value, op.hasValue = m[k], true
		}
		if op.op != "remove" && !op.hasValue {
			return nil, badSyntax("Operations[%d]: value is required", i)
		}
		ops = append(ops, op)
	}
	return ops, nil
}

// patchRules says how PATCH operations apply to one resource type.
type patchRules struct {
	sch      *schemaSet
	readOnly map[string]bool // lower-case top-level names that are silently left alone
}

// apply performs one operation on res (a decoded SCIM resource).
func (rl *patchRules) apply(res map[string]any, op patchOp) *Error {
	if op.path == nil {
		if op.op == "remove" {
			return noTarget("remove needs a path")
		}
		obj, ok := op.value.(map[string]any)
		if !ok {
			return badValue("a value without a path must be an object")
		}
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := obj[k]
			if urn, ok := rl.sch.extURN(k); ok || strings.EqualFold(k, rl.sch.core) {
				sub, isMap := v.(map[string]any)
				if !isMap {
					return badValue("%s must be an object", k)
				}
				if !ok {
					urn = ""
				}
				for sk, sv := range sub {
					p, err := parsePath(sk)
					if err != nil {
						return badPath("%s", err.Error())
					}
					p.URN = urn
					if e := rl.set(res, op.op, p, sv, false); e != nil {
						return e
					}
				}
				continue
			}
			p, err := parsePath(k)
			if err != nil {
				return badPath("%s", err.Error())
			}
			if e := rl.set(res, op.op, p, v, false); e != nil {
				return e
			}
		}
		return nil
	}
	return rl.set(res, op.op, *op.path, op.value, op.hasValue)
}

func coerce(info attrInfo, v any) any {
	if info.typ == "boolean" {
		if s, ok := v.(string); ok {
			switch strings.ToLower(strings.TrimSpace(s)) {
			case "true":
				return true
			case "false":
				return false
			}
		}
	}
	return v
}

// set applies op to the attribute named by p.
func (rl *patchRules) set(res map[string]any, op string, p attrPath, value any, hasValue bool) *Error {
	sch := rl.sch
	base := res
	if p.URN != "" && strings.EqualFold(p.URN, sch.core) {
		p.URN = ""
	}
	if p.URN != "" {
		urn, ok := sch.extURN(p.URN)
		if !ok {
			return badPath("unknown schema %q", p.URN)
		}
		p.URN = urn
		if p.Name == "" { // the whole extension
			switch op {
			case "remove":
				delete(res, urn)
			case "replace":
				res[urn] = value
			default:
				m, _ := res[urn].(map[string]any)
				vm, ok := value.(map[string]any)
				if !ok {
					return badValue("%s must be an object", urn)
				}
				if m == nil {
					m = map[string]any{}
					res[urn] = m
				}
				for k, v := range vm {
					m[k] = v
				}
			}
			return nil
		}
		m, _ := res[urn].(map[string]any)
		if m == nil {
			if op == "remove" {
				return nil
			}
			m = map[string]any{}
			res[urn] = m
		}
		base = m
	} else if p.Name == "" {
		return badPath("a path is required")
	} else if rl.readOnly[strings.ToLower(p.Name)] {
		return nil // read-only attributes are ignored, as many provisioning clients send them back
	}

	name := sch.canonName(p.URN, p.Name, "")
	key := name
	if k, ok := keyOf(base, name); ok {
		key = k
	}
	subName := ""
	if p.Sub != "" {
		subName = sch.canonName(p.URN, p.Name, p.Sub)
	}
	info := sch.info(attrPath{URN: p.URN, Name: p.Name})
	subInfo := sch.info(attrPath{URN: p.URN, Name: p.Name, Sub: p.Sub})

	switch op {
	case "remove":
		return removeAttr(base, key, p, subName, value, hasValue, sch)
	}

	// add / replace
	if p.Filter != nil {
		arr, _ := base[key].([]any)
		var matched []map[string]any
		for _, e := range arr {
			if em, ok := e.(map[string]any); ok && evalNode(p.Filter, em, sch) {
				matched = append(matched, em)
			}
		}
		switch {
		case subName != "":
			v := coerce(subInfo, value)
			if len(matched) == 0 { // be lenient: create the element the filter describes
				em := filterSeed(p.Filter)
				em[subName] = v
				arr = append(arr, em)
				matched = []map[string]any{em}
			} else {
				for _, em := range matched {
					setKey(em, subName, v)
				}
			}
			if subName == "primary" && v == true {
				onlyPrimary(arr, matched)
			}
		default:
			vm, ok := value.(map[string]any)
			if !ok {
				return badValue("the value for a filtered path must be an object")
			}
			if len(matched) == 0 {
				em := filterSeed(p.Filter)
				for k, v := range vm {
					em[k] = coercePrimary(k, v)
				}
				arr = append(arr, em)
				matched = []map[string]any{em}
			} else {
				for _, em := range matched {
					if op == "replace" {
						for k := range em {
							delete(em, k)
						}
					}
					for k, v := range vm {
						setKey(em, k, coercePrimary(k, v))
					}
				}
			}
			onlyPrimary(arr, matched)
		}
		base[key] = arr
		return nil
	}

	if subName != "" {
		v := coerce(subInfo, value)
		switch t := base[key].(type) {
		case map[string]any:
			setKey(t, subName, v)
		case []any:
			if len(t) == 0 {
				base[key] = []any{map[string]any{subName: v}}
			} else if first, ok := t[0].(map[string]any); ok {
				setKey(first, subName, v)
			}
		default:
			base[key] = map[string]any{subName: v}
		}
		return nil
	}

	value = coerce(info, value)
	existing, exists := base[key]
	_, existingMulti := existing.([]any)
	if info.multi || existingMulti {
		items := asSlice(value)
		if op == "replace" || !exists {
			base[key] = append([]any(nil), items...)
			onlyPrimaryNew(base[key].([]any))
			return nil
		}
		arr := existing.([]any)
		for _, it := range items {
			if !containsElem(arr, it) {
				arr = append(arr, it)
			} else if im, ok := it.(map[string]any); ok {
				// the element exists already: its attributes (typically primary) are updated from the added one
				for _, e := range arr {
					if em, ok := e.(map[string]any); ok && reflect.DeepEqual(getCI(em, "value"), getCI(im, "value")) {
						for k, v := range im {
							if !strings.EqualFold(k, "value") {
								setKey(em, k, v)
							}
						}
					}
				}
			}
		}
		base[key] = arr
		if hasPrimaryNew(items) {
			onlyPrimaryNew2(arr, items)
		}
		return nil
	}
	if em, ok := existing.(map[string]any); ok && op == "add" {
		if vm, ok := value.(map[string]any); ok {
			for k, v := range vm {
				setKey(em, k, v)
			}
			return nil
		}
	}
	base[key] = value
	return nil
}

func coercePrimary(k string, v any) any {
	if strings.EqualFold(k, "primary") {
		return coerce(attrInfo{typ: "boolean"}, v)
	}
	return v
}

func setKey(m map[string]any, name string, v any) {
	if k, ok := keyOf(m, name); ok {
		m[k] = v
		return
	}
	m[name] = v
}

// filterSeed builds a new element from the equality terms of a value filter: emails[type eq "work"] -> {type: work}.
func filterSeed(f node) map[string]any {
	em := map[string]any{}
	for _, c := range conjuncts(f) {
		if cn, ok := c.(*cmpNode); ok && cn.op == "eq" && cn.path.Sub == "" && cn.path.Filter == nil && cn.val != nil {
			em[cn.path.Name] = cn.val
		}
	}
	return em
}

// containsElem reports whether arr already holds an element equal to it (compared by "value" for objects).
func containsElem(arr []any, it any) bool {
	im, isMap := it.(map[string]any)
	for _, e := range arr {
		if isMap {
			if em, ok := e.(map[string]any); ok {
				a, b := getCI(em, "value"), getCI(im, "value")
				if a != nil && b != nil && reflect.DeepEqual(a, b) {
					return true
				}
				continue
			}
		}
		if reflect.DeepEqual(e, it) {
			return true
		}
	}
	return false
}

// onlyPrimary clears primary on every element of arr except those in keep when one of keep is primary.
func onlyPrimary(arr []any, keep []map[string]any) {
	isKeep := func(m map[string]any) bool {
		for _, k := range keep {
			if reflect.ValueOf(k).Pointer() == reflect.ValueOf(m).Pointer() {
				return true
			}
		}
		return false
	}
	found := false
	for _, k := range keep {
		if b, ok := getCI(k, "primary").(bool); ok && b {
			found = true
		}
	}
	if !found {
		return
	}
	for _, e := range arr {
		if em, ok := e.(map[string]any); ok && !isKeep(em) {
			if _, has := keyOf(em, "primary"); has {
				setKey(em, "primary", false)
			}
		}
	}
}

func onlyPrimaryNew(arr []any) {
	// With several primaries in a replacement the last one wins.
	last := -1
	for i, e := range arr {
		if em, ok := e.(map[string]any); ok {
			if _, has := keyOf(em, "primary"); has {
				em["primary"] = coercePrimary("primary", getCI(em, "primary"))
			}
			if b, _ := getCI(em, "primary").(bool); b {
				last = i
			}
		}
	}
	for i, e := range arr {
		if em, ok := e.(map[string]any); ok && i != last {
			if _, has := keyOf(em, "primary"); has && last >= 0 {
				setKey(em, "primary", false)
			}
		}
	}
}

func hasPrimaryNew(items []any) bool {
	for _, e := range items {
		if em, ok := e.(map[string]any); ok {
			if b, ok := coercePrimary("primary", getCI(em, "primary")).(bool); ok && b {
				return true
			}
		}
	}
	return false
}

func onlyPrimaryNew2(arr, items []any) {
	var keep []map[string]any
	for _, it := range items {
		im, _ := it.(map[string]any)
		for _, e := range arr {
			if em, ok := e.(map[string]any); ok && im != nil {
				if reflect.DeepEqual(getCI(em, "value"), getCI(im, "value")) {
					em["primary"] = coercePrimary("primary", getCI(em, "primary"))
					keep = append(keep, em)
				}
			}
		}
	}
	onlyPrimary(arr, keep)
}

func removeAttr(base map[string]any, key string, p attrPath, subName string, value any, hasValue bool, sch *schemaSet) *Error {
	cur, exists := base[key]
	if !exists {
		return nil
	}
	if p.Filter != nil {
		arr, _ := cur.([]any)
		kept := make([]any, 0, len(arr))
		for _, e := range arr {
			em, ok := e.(map[string]any)
			if !ok || !evalNode(p.Filter, em, sch) {
				kept = append(kept, e)
				continue
			}
			if subName != "" {
				if k, ok := keyOf(em, subName); ok {
					delete(em, k)
				}
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(base, key)
		} else {
			base[key] = kept
		}
		return nil
	}
	if subName != "" {
		switch t := cur.(type) {
		case map[string]any:
			if k, ok := keyOf(t, subName); ok {
				delete(t, k)
			}
		case []any:
			for _, e := range t {
				if em, ok := e.(map[string]any); ok {
					if k, ok := keyOf(em, subName); ok {
						delete(em, k)
					}
				}
			}
		}
		return nil
	}
	if arr, ok := cur.([]any); ok && hasValue {
		// members with a value list: remove those elements.
		kept := make([]any, 0, len(arr))
		for _, e := range arr {
			if !containsElem(asSlice(value), e) {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(base, key)
		} else {
			base[key] = kept
		}
		return nil
	}
	delete(base, key)
	return nil
}
