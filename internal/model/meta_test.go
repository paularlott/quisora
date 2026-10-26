package model

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMetaHelpers(t *testing.T) {
	if Lower("  AbC ") != "abc" {
		t.Error("Lower")
	}
	if a, b := NewID(), NewID(); a == b || uuid.Validate(a) != nil {
		t.Errorf("NewID %q %q", a, b)
	}
	m := &Meta{ID: "x"}
	if m.GetMeta() != m {
		t.Error("GetMeta")
	}
}

func TestDue(t *testing.T) {
	end := t0.Add(time.Hour)
	if got, ok := Due(KindUser, map[string]any{"expiring": true, "active": true, "valid_until": end}); !ok || !got.Equal(end) {
		t.Errorf("due = %v %v", got, ok)
	}
	for name, f := range map[string]map[string]any{
		"inactive":     {"expiring": true, "active": false, "valid_until": end},
		"not expiring": {"expiring": false, "active": true, "valid_until": end},
		"no time":      {"expiring": true, "active": true},
	} {
		if _, ok := Due(KindUser, f); ok {
			t.Errorf("%s: due", name)
		}
	}
	if _, ok := Due(KindGroup, map[string]any{"expiring": true, "active": true, "valid_until": end}); ok {
		t.Error("group due")
	}
}

func TestMFA(t *testing.T) {
	for _, c := range []struct {
		amr []string
		ok  bool
	}{
		{nil, false}, {[]string{"mfa"}, true}, {[]string{"pwd"}, false}, {[]string{"pwd", "otp"}, true},
		{[]string{"otp"}, false}, {[]string{"hwk"}, false}, {[]string{"hwk", "user"}, true},
		{[]string{"swk", "user"}, true}, {[]string{"user"}, false}, {[]string{"pwd", "hwk"}, false},
	} {
		if MFA(c.amr) != c.ok {
			t.Errorf("MFA(%v) = %v", c.amr, !c.ok)
		}
	}
}
