package model

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeLocale(t *testing.T) {
	for in, want := range map[string]string{"": "", "  ": "", "en_gb": "en-GB", "EN-GB": "en-GB", "fr": "fr"} {
		if got, ok := NormalizeLocale(in); !ok || got != want {
			t.Errorf("NormalizeLocale(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"!!", "en gb", strings.Repeat("a", 40), "12345"} {
		if got, ok := NormalizeLocale(in); ok {
			t.Errorf("NormalizeLocale(%q) accepted as %q", in, got)
		}
	}
}

func TestValidTimeZone(t *testing.T) {
	for _, z := range []string{"", "UTC", "Europe/London", "America/New_York"} {
		if !ValidTimeZone(z) {
			t.Errorf("%q rejected", z)
		}
	}
	for _, z := range []string{"Local", "Not/AZone", "Europe London", "../etc", `a\b`, strings.Repeat("a", 65)} {
		if ValidTimeZone(z) {
			t.Errorf("%q accepted", z)
		}
	}
}

func TestWorkAndEnabled(t *testing.T) {
	if !(Work{}).Empty() || (Work{Title: "x"}).Empty() {
		t.Error("Empty")
	}
	past, future := t0.Add(-time.Hour), t0.Add(time.Hour)
	for _, c := range []struct {
		u  User
		ok bool
	}{
		{User{Active: true}, true}, {User{}, false}, {User{Active: true, ValidUntil: &future}, true},
		{User{Active: true, ValidUntil: &past}, false}, {User{Active: true, ValidUntil: &t0}, false},
	} {
		if c.u.Enabled(t0) != c.ok {
			t.Errorf("Enabled(%+v) = %v", c.u, !c.ok)
		}
	}
}
