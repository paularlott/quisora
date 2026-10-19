package model

import "testing"

func TestNewEntityCoversKinds(t *testing.T) {
	for _, k := range Kinds() {
		e := NewEntity(k)
		if e == nil || e.Kind() != k {
			t.Errorf("NewEntity(%s) = %T", k, e)
		}
	}
}
