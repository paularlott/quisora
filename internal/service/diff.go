package service

import (
	"encoding/json"
	"maps"
	"slices"
)

// Change records for the audit log: what an update changed, field by field, as "changed.<field>" = "old → new" in
// the event's detail (nested settings as "changed.settings.<field>"). Snapshots are the records' JSON form, so a
// field that holds a secret (json:"-") never appears.

// snapshot is v's JSON form, flattened to dotted field paths.
func snapshot(v any) map[string]string {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	out := map[string]string{}
	flatten(out, "", m)
	return out
}

func flatten(out map[string]string, prefix string, m map[string]any) {
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			flatten(out, prefix+k+".", sub)
			continue
		}
		b, _ := json.Marshal(v)
		out[prefix+k] = string(b)
	}
}

// bookkeeping fields change with every write: not changes anyone made.
var bookkeeping = []string{"updated", "version", "last_login", "status_changed.at"}

// addChanges adds to detail (made if nil) one "changed.<field>" entry per field that differs between the snapshot
// taken before an update and the record after it, and returns detail.
func addChanges(detail map[string]string, before map[string]string, after any) map[string]string {
	if before == nil {
		return detail
	}
	now := snapshot(after)
	keys := slices.Sorted(maps.Keys(now))
	for k := range before {
		if _, ok := now[k]; !ok {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		if slices.Contains(bookkeeping, k) || before[k] == now[k] {
			continue
		}
		if detail == nil {
			detail = map[string]string{}
		}
		detail["changed."+k] = clip(display(before[k]), 200) + " → " + clip(display(now[k]), 200)
	}
	return detail
}

// display is a JSON value as an audit detail shows it: strings without quotes, nothing as "".
func display(v string) string {
	var s string
	if json.Unmarshal([]byte(v), &s) == nil {
		return s
	}
	if v == "null" {
		return ""
	}
	return v
}
