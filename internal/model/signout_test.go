package model

import (
	"testing"
)

func TestSignOutCurrent(t *testing.T) {
	want := SignOutStamp{Server: 2, Org: 3}
	for _, c := range []struct {
		s  SignOutStamp
		ok bool
	}{{SignOutStamp{2, 3}, true}, {SignOutStamp{5, 9}, true}, {SignOutStamp{1, 3}, false}, {SignOutStamp{2, 2}, false}, {SignOutStamp{}, false}} {
		if c.s.Current(want) != c.ok {
			t.Errorf("%+v.Current = %v", c.s, !c.ok)
		}
	}
	if !(SignOutStamp{}).Current(SignOutStamp{}) {
		t.Error("zero stamp is current for zero counters")
	}
}
