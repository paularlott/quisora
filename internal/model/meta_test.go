package model

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestMetaHelpers(t *testing.T) {
	if Lower("  AbC ") != "abc" {
		t.Error("Lower")
	}
	if a, b := NewID(), NewID(); a == b || !IsID(a) || !IsID(b) {
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

// bigID is FormatID's reference: the 128-bit big-endian value of b in base 62, left-padded to IDLen.
func bigID(b [16]byte) string {
	v, base, r := new(big.Int).SetBytes(b[:]), big.NewInt(62), new(big.Int)
	out := []byte(strings.Repeat("0", IDLen))
	for i := IDLen - 1; v.Sign() > 0; i-- {
		v.DivMod(v, base, r)
		out[i] = base62[r.Int64()]
	}
	return string(out)
}

// An id is its 16 bytes' big-endian value in base 62, fixed-width in an alphabet in ASCII order: the string order of
// two ids is their numeric order, and ids made one after another (across a millisecond boundary too) sort in the order
// they were made, which is the order the store lists and pages a scope in.
func TestIDOrder(t *testing.T) {
	var zero, max [16]byte
	for i := range max {
		max[i] = 0xff
	}
	if got := FormatID(zero); got != "0000000000000000000000" {
		t.Fatalf("zero = %q", got)
	}
	if got := FormatID(max); got != "7n42DGM5Tflk9n8mt7Fhc7" || got != bigID(max) || got != maxID {
		t.Fatalf("max = %q", got)
	}
	for i := range 5000 {
		var a, b [16]byte
		_, _ = rand.Read(a[:])
		_, _ = rand.Read(b[:])
		if i%2 == 0 { // small values too: leading zero digits, and a zero high half
			clear(a[:i%16])
		}
		ia, ib := FormatID(a), FormatID(b)
		if ia != bigID(a) || !IsID(ia) {
			t.Fatalf("FormatID(%x) = %q, want %q", a, ia, bigID(a))
		}
		if bytes.Compare(a[:], b[:]) != strings.Compare(ia, ib) {
			t.Fatalf("order differs: %x %x -> %s %s", a, b, ia, ib)
		}
	}
	var ids []string
	for start := time.Now(); time.Since(start) < 3*time.Millisecond || len(ids) < 1000; {
		ids = append(ids, NewID())
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Fatalf("id %d (%s) does not sort after the one made before it (%s)", i, ids[i], ids[i-1])
		}
	}
	if ids[0][:9] == ids[len(ids)-1][:9] { // a millisecond (2^80) is more than the ninth digit's 62^13
		t.Fatal("setup: the ids did not cross a millisecond boundary")
	}
	if c := NewClientID(); !strings.HasPrefix(c, ClientIDPrefix) || !IsID(c[len(ClientIDPrefix):]) {
		t.Fatalf("NewClientID = %q", c)
	}
}

// IsID accepts exactly the one spelling of each id: 22 letters and digits whose value fits 128 bits.
func TestIsID(t *testing.T) {
	id := NewID()
	for _, s := range []string{id, "0000000000000000000000", "7n42DGM5Tflk9n8mt7Fhc7", "7n42DGM5Tflk9n8mt7Fhc6",
		"0abcdefghijklmnopqrstu", "6zzzzzzzzzzzzzzzzzzzzz"} {
		if !IsID(s) {
			t.Errorf("IsID(%q) = false", s)
		}
	}
	for _, s := range []string{"", id[:21], id + "0", "7n42DGM5Tflk9n8mt7Fhc8", "7n42DGM5Tflk9n8mt7Fhd0", "8000000000000000000000",
		"zzzzzzzzzzzzzzzzzzzzzz", id[:10] + "-" + id[11:], id[:10] + "_" + id[11:], id[:10] + "+" + id[11:],
		id[:10] + "/" + id[11:], id[:10] + "=" + id[11:], id[:10] + "\n" + id[12:], id[:10] + "\xff" + id[11:], "acme"} {
		if IsID(s) {
			t.Errorf("IsID(%q) = true", s)
		}
	}
}

// NewID and IsID run for every record written and every id read from a request.
func BenchmarkNewID(b *testing.B) {
	for b.Loop() {
		_ = NewID()
	}
}

func BenchmarkFormatID(b *testing.B) {
	v := [16]byte{0: 0x01, 5: 0x9a, 6: 0x70, 8: 0x80, 15: 0xff}
	for b.Loop() {
		_ = FormatID(v)
	}
}

func BenchmarkIsID(b *testing.B) {
	id := NewID()
	for b.Loop() {
		if !IsID(id) {
			b.Fatal(id)
		}
	}
}
