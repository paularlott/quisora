package model

import (
	"reflect"
	"strings"
	"testing"
)

func TestNewEntityCoversKinds(t *testing.T) {
	for _, k := range Kinds() {
		e := NewEntity(k)
		if e == nil || e.Kind() != k {
			t.Errorf("NewEntity(%s) = %T", k, e)
		}
	}
}

// No field of an entity shares its msgpack key with another, its embedded Meta's included: the outer field would win
// and the other would silently not be stored (a lock's Until once hid Meta.Updated).
func TestMsgpackKeysUnique(t *testing.T) {
	for _, k := range Kinds() {
		seen := map[string]string{}
		var walk func(rt reflect.Type)
		walk = func(rt reflect.Type) {
			for i := range rt.NumField() {
				f := rt.Field(i)
				if f.Anonymous && f.Type.Kind() == reflect.Struct {
					walk(f.Type)
					continue
				}
				key, _, _ := strings.Cut(f.Tag.Get("msgpack"), ",")
				if key == "-" || !f.IsExported() {
					continue
				}
				if key == "" {
					key = f.Name
				}
				if other, ok := seen[key]; ok {
					t.Errorf("%s: %s and %s share the msgpack key %q", k, other, f.Name, key)
				}
				seen[key] = f.Name
			}
		}
		walk(reflect.TypeOf(NewEntity(k)).Elem())
	}
}
