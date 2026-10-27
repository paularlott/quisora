package model

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)

// Every kind's Index fields are registered in its schema, with the declared type, and the index never panics on a
// zero entity.
func TestIndexMatchesSchema(t *testing.T) {
	for _, k := range Kinds() {
		e := NewEntity(k)
		if e == nil || e.Kind() != k {
			t.Errorf("NewEntity(%s) = %T", k, e)
			continue
		}
		ix := e.Index()
		s := Schemas[k]
		for name, v := range ix.Fields {
			f, ok := s.Field(name)
			if !ok {
				t.Errorf("%s: index field %q is not in the schema", k, name)
				continue
			}
			var ok2 bool
			switch f.Type {
			case FieldString:
				_, ok2 = v.(string)
			case FieldInt:
				_, ok2 = v.(int64)
			case FieldBool:
				_, ok2 = v.(bool)
			case FieldTime:
				_, ok2 = v.(time.Time)
			}
			if !ok2 {
				t.Errorf("%s.%s: value %T does not match field type %d", k, name, v, f.Type)
			}
		}
		if e.GetMeta() == nil {
			t.Errorf("%s: nil meta", k)
		}
	}
	if NewEntity("nope") != nil {
		t.Error("unknown kind gave an entity")
	}
	if !Unscoped(KindOrg) || Unscoped(KindUser) {
		t.Error("Unscoped")
	}
	if _, ok := Schemas[KindUser].Field("nope"); ok {
		t.Error("Field found a missing field")
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

// A kind that is NeverExpires gives its records no expiry, whatever they hold, and the other kinds pass the
// expiry of the record on (a member's is made of when it was removed).
func TestExpiryOfMatchesIndex(t *testing.T) {
	for _, k := range Kinds() {
		e := NewEntity(k)
		f := reflect.ValueOf(e).Elem().FieldByName("Expires")
		if !f.IsValid() {
			continue
		}
		f.Set(reflect.ValueOf(t0))
		if got := !e.Index().Expires.IsZero(); got != (ExpiryOf(k) != NeverExpires) {
			t.Errorf("%s: the index carries an expiry: %v, the kind's expiry is %d", k, got, ExpiryOf(k))
		}
	}
}
