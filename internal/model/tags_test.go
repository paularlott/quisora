package model

import (
	"slices"
	"strings"
	"testing"
)

func TestTags(t *testing.T) {
	for _, s := range []string{"a", "dept:finance", "a.b_c-d/e", "A1", "9", "marketplace:seller", "a.b_c-d/e:f", strings.Repeat("a", 64)} {
		if !ValidTag(s) {
			t.Errorf("%q invalid", s)
		}
	}
	for _, s := range []string{"", "-a", "a-", ":a", "a b", "a,b", ".a", "a.", "a:", "a#", "x y", "a\n", strings.Repeat("a", 65), "é"} {
		if ValidTag(s) {
			t.Errorf("%q valid", s)
		}
	}
	if NormTags(nil) != nil || NormTags([]string{}) != nil {
		t.Error("empty must be nil")
	}
	in := []string{"b", "a", "b", "A"}
	got := NormTags(in)
	if !slices.Equal(got, []string{"A", "a", "b"}) {
		t.Errorf("NormTags = %v", got)
	}
	if !slices.Equal(in, []string{"b", "a", "b", "A"}) {
		t.Error("NormTags modified its input")
	}
	if got := MergeTags([]string{"z", "a"}, nil, []string{"a", "m"}); !slices.Equal(got, []string{"a", "m", "z"}) {
		t.Errorf("MergeTags = %v", got)
	}
	if MergeTags() != nil {
		t.Error("MergeTags() not nil")
	}
}
