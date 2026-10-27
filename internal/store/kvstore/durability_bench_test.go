package kvstore

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// BenchmarkWriteDurability measures session writes from W goroutines (each writes one record after the other, as
// request handlers do) with an fsync per group commit (the default), and with the fsync left out or done every
// SyncInterval. What it shows depends on the disk: run it where the store will live (an fsync of a laptop SSD takes
// tens of microseconds, that of a network disk milliseconds).
func BenchmarkWriteDurability(b *testing.B) {
	for _, m := range []struct {
		name string
		o    BadgerOptions
	}{
		{"fsync", BadgerOptions{}},
		{"nosync", BadgerOptions{NoSync: true}},
		{"interval10ms", BadgerOptions{NoSync: true, SyncInterval: 10 * time.Millisecond}},
		{"interval100ms", BadgerOptions{NoSync: true, SyncInterval: 100 * time.Millisecond}},
	} {
		for _, w := range []int{1, 16, 64, 256} {
			b.Run(fmt.Sprintf("%s/w%d", m.name, w), func(b *testing.B) {
				s := openBadger(b, m.o)
				var n atomic.Int64
				lat := make([][]time.Duration, w)
				var wg sync.WaitGroup
				b.ReportAllocs()
				b.ResetTimer()
				for g := range w {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for i := n.Add(1); i <= int64(b.N); i = n.Add(1) {
							se := &model.Session{Meta: model.Meta{ID: model.NewID()}, UserID: fmt.Sprintf("u%d", i%5000), OrgID: "org",
								Expires: time.Now().Add(time.Hour), LastSeen: time.Now(), IP: "10.0.0.1", UserAgent: "Mozilla/5.0 (X11; Linux x86_64)", CSRF: "abcdefabcdefabcdefabcdef"}
							rec, err := store.Encode(se)
							if err != nil {
								b.Error(err)
								return
							}
							t0 := time.Now()
							if err := s.Put(context.Background(), rec); err != nil {
								b.Error(err)
								return
							}
							if i%16 == 0 {
								lat[g] = append(lat[g], time.Since(t0))
							}
						}
					}()
				}
				wg.Wait()
				b.StopTimer()
				all := slices.Concat(lat...)
				slices.Sort(all)
				if len(all) > 0 {
					b.ReportMetric(float64(all[len(all)/2].Microseconds()), "p50-us")
					b.ReportMetric(float64(all[len(all)*99/100].Microseconds()), "p99-us")
				}
				b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "writes/s")
			})
		}
	}
}
