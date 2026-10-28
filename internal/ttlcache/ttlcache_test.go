package ttlcache

import (
	"testing"
	"time"
)

// A fill that began before an eviction must not be stored after it: the copy it read may be the one the eviction was
// for, and would be served until it expired.
func TestFillBeforeEvictionIsNotStored(t *testing.T) {
	t.Parallel()
	c := New[int](time.Hour, 10)
	tok := c.Token("k")
	c.Del("k") // the eviction lands while the store is being read
	c.PutIf("k", 1, tok)
	if _, ok := c.Get("k"); ok {
		t.Fatal("a fill that began before the eviction was stored")
	}
	c.PutIf("k", 2, c.Token("k")) // a fill that began after it is
	if v, ok := c.Get("k"); !ok || v != 2 {
		t.Fatalf("fill after the eviction: %v %v", v, ok)
	}
	tok = c.Token("k")
	c.Clear()
	c.PutIf("k", 3, tok)
	if _, ok := c.Get("k"); ok {
		t.Fatal("a fill that began before a clear was stored")
	}
}

// The cache holds at most two generations of max entries, serves the newest value of a key, and never an expired one.
func TestBounds(t *testing.T) {
	t.Parallel()
	c := New[int](time.Hour, 4)
	for i := range 20 {
		c.Put(string(rune('a'+i)), i)
	}
	if n := len(c.m) + len(c.old); n > 8 {
		t.Fatalf("holds %d entries, more than two generations of 4", n)
	}
	if v, ok := c.Get(string(rune('a' + 19))); !ok || v != 19 {
		t.Fatal("newest entry lost")
	}
	if _, ok := c.Get("a"); ok {
		t.Fatal("an entry of a dropped generation served")
	}
	c.Put("t", 100) // "t" was in a generation: the new value replaces it wherever it was
	if v, _ := c.Get("t"); v != 100 {
		t.Fatalf("stale value %d", v)
	}
	c.Del("t")
	if _, ok := c.Get("t"); ok {
		t.Fatal("deleted entry served")
	}
	// expired entries are never served, in either generation
	d := New[int](-time.Minute, 3) // a negative lifetime: every entry is born expired
	d.Put("x", 1)
	if _, ok := d.Get("x"); ok {
		t.Fatal("expired entry served")
	}
	d.Clear()
	if len(d.m) != 0 || len(d.old) != 0 {
		t.Fatal("clear left entries")
	}
}

// An entry is served for its lifetime and not after it.
func TestEntriesExpire(t *testing.T) {
	t.Parallel()
	c := New[int](50*time.Millisecond, 10)
	c.Put("k", 1)
	if _, ok := c.Get("k"); !ok {
		t.Fatal("a fresh entry was not served")
	}
	time.Sleep(60 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Fatal("an entry past its lifetime was served")
	}
}
