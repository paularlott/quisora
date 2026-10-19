// Package loadtest seeds a store with a large synthetic dataset and drives HTTP load against a running server.
package loadtest

import (
	"math/bits"
	"time"
)

// Histogram records latencies with ~1.6% relative precision (64 linear sub-buckets per power of two of the value in
// microseconds). It is not safe for concurrent use: keep one per worker and Merge them afterwards.
type Histogram struct {
	counts [histBuckets]uint64
	n      uint64
	sum    uint64 // microseconds
	max    uint64 // microseconds
}

const (
	histSub     = 64
	histSubBits = 6
	histMaxExp  = 40 // 2^40 us ~ 12.7 days
	histBuckets = (histMaxExp + 1) * histSub
)

func bucketOf(us uint64) int {
	if us < histSub {
		return int(us)
	}
	exp := bits.Len64(us) - histSubBits - 1 // us in [2^(exp+6), 2^(exp+7))
	if exp >= histMaxExp {
		return histBuckets - 1
	}
	sub := us >> uint(exp) // 64..127
	return (exp+1)*histSub + int(sub-histSub)
}

// bucketUpper returns the largest value (us) that falls in bucket i.
func bucketUpper(i int) uint64 {
	if i < histSub {
		return uint64(i)
	}
	exp := i/histSub - 1
	sub := uint64(i%histSub) + histSub
	return (sub+1)<<uint(exp) - 1
}

// Record adds one observation.
func (h *Histogram) Record(d time.Duration) {
	us := uint64(0)
	if d > 0 {
		us = uint64(d / time.Microsecond)
	}
	h.counts[bucketOf(us)]++
	h.n++
	h.sum += us
	if us > h.max {
		h.max = us
	}
}

// Merge adds o's observations to h.
func (h *Histogram) Merge(o *Histogram) {
	for i, c := range o.counts {
		h.counts[i] += c
	}
	h.n += o.n
	h.sum += o.sum
	if o.max > h.max {
		h.max = o.max
	}
}

// Count is the number of observations.
func (h *Histogram) Count() uint64 { return h.n }

// Max is the largest observation (exact to the microsecond).
func (h *Histogram) Max() time.Duration { return time.Duration(h.max) * time.Microsecond }

// Mean is the average observation.
func (h *Histogram) Mean() time.Duration {
	if h.n == 0 {
		return 0
	}
	return time.Duration(h.sum/h.n) * time.Microsecond
}

// Quantile returns the value below which a fraction q (0..1) of observations fall (an upper bound within the
// bucket precision, never more than Max).
func (h *Histogram) Quantile(q float64) time.Duration {
	if h.n == 0 {
		return 0
	}
	if q >= 1 {
		return h.Max()
	}
	if q < 0 {
		q = 0
	}
	rank := uint64(q*float64(h.n)) + 1
	if rank > h.n {
		rank = h.n
	}
	var seen uint64
	for i, c := range h.counts {
		seen += c
		if seen >= rank {
			up := bucketUpper(i)
			if up > h.max {
				up = h.max
			}
			return time.Duration(up) * time.Microsecond
		}
	}
	return h.Max()
}
