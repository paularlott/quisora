package loadtest

import (
	"math"
	"math/rand"
	"slices"
	"testing"
	"time"
)

func TestBucketRoundTrip(t *testing.T) {
	prev := -1
	for _, us := range []uint64{0, 1, 63, 64, 65, 127, 128, 129, 1000, 12345, 1 << 20, 1<<30 + 12345, 1 << 39} {
		b := bucketOf(us)
		if b < prev {
			t.Fatalf("bucket order broke at %d", us)
		}
		prev = b
		up := bucketUpper(b)
		if up < us {
			t.Fatalf("bucketUpper(%d)=%d < %d", b, up, us)
		}
		if us >= histSub && float64(up-us)/float64(us) > 0.02 {
			t.Fatalf("precision at %d: upper %d", us, up)
		}
	}
	if bucketOf(math.MaxUint64) != histBuckets-1 {
		t.Fatal("overflow bucket")
	}
}

func TestQuantiles(t *testing.T) {
	var h Histogram
	rng := rand.New(rand.NewSource(1))
	var vals []time.Duration
	for range 100000 {
		d := time.Duration(rng.ExpFloat64()*float64(5*time.Millisecond)) + 100*time.Microsecond
		d = d.Round(time.Microsecond)
		vals = append(vals, d)
		h.Record(d)
	}
	slices.Sort(vals)
	for _, q := range []float64{0.5, 0.9, 0.99, 0.999} {
		want := vals[int(q*float64(len(vals)))]
		got := h.Quantile(q)
		if got < want || float64(got-want)/float64(want) > 0.03 {
			t.Fatalf("q%v: got %v want ~%v", q, got, want)
		}
	}
	if h.Quantile(1) != vals[len(vals)-1] || h.Max() != vals[len(vals)-1] {
		t.Fatalf("max %v vs %v", h.Max(), vals[len(vals)-1])
	}
	if h.Count() != 100000 {
		t.Fatal("count")
	}
}

func TestMergeAndEmpty(t *testing.T) {
	var a, b, empty Histogram
	if empty.Quantile(0.99) != 0 || empty.Mean() != 0 {
		t.Fatal("empty histogram")
	}
	for i := 1; i <= 100; i++ {
		a.Record(time.Duration(i) * time.Millisecond)
	}
	for i := 101; i <= 200; i++ {
		b.Record(time.Duration(i) * time.Millisecond)
	}
	a.Merge(&b)
	if a.Count() != 200 || a.Max() != 200*time.Millisecond {
		t.Fatalf("merged %d %v", a.Count(), a.Max())
	}
	if p50 := a.Quantile(0.5); p50 < 100*time.Millisecond || p50 > 104*time.Millisecond {
		t.Fatalf("p50 %v", p50)
	}
	if m := a.Mean(); m < 100*time.Millisecond || m > 101*time.Millisecond {
		t.Fatalf("mean %v", m)
	}
}
