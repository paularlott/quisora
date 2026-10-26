package evictgen

import (
	"strconv"
	"testing"
)

func TestEvictionInvalidatesTokensOfThatKeyOnly(t *testing.T) {
	var g Gens
	other := "b"
	for i := 0; stripe(other) == stripe("a"); i++ {
		other = "b" + strconv.Itoa(i)
	}
	a, b := g.Token("a"), g.Token(other)
	if !g.Valid("a", a) || !g.Valid(other, b) {
		t.Fatal("fresh tokens are valid")
	}
	g.Bump("a")
	if g.Valid("a", a) {
		t.Error("a token survived an eviction of its key")
	}
	if !g.Valid(other, b) {
		t.Error("an eviction of one key invalidated another stripe")
	}
	if !g.Valid("a", g.Token("a")) {
		t.Error("a token taken after the eviction is invalid")
	}
	g.BumpAll()
	if g.Valid(other, b) {
		t.Error("BumpAll left a token valid")
	}
}
