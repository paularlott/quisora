package cluster

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

func benchRec(i int64) *store.Record {
	r := newRec(model.NewID(), fmt.Sprintf("o|u%d", i))
	r.Scope, r.Partition = "org1", fmt.Sprintf("org%d", i%40) // 40 organizations over the partitions
	r.Data = []byte(strings.Repeat("x", 400))
	return r
}

// BenchmarkReplicatedPut measures Put throughput on a 3-node cluster: writes spread over the nodes, each committed on
// a majority by the owner of its partition, and the time until every node holds every record.
func BenchmarkReplicatedPut(b *testing.B) {
	for _, mk := range localBackends() {
		b.Run(mk.name, func(b *testing.B) {
			c := newTCluster(b, 3, mk)
			c.startAll()
			c.waitReady()
			var seq, rr atomic.Int64
			b.ReportAllocs()
			b.ResetTimer()
			start := time.Now()
			b.RunParallel(func(pb *testing.PB) {
				tn := c.nodes[int(rr.Add(1))%3]
				for pb.Next() {
					if err := tn.st().Put(bg, benchRec(seq.Add(1))); err != nil {
						b.Fatal(err)
					}
				}
			})
			local := time.Since(start)
			waitFor(b, 120*time.Second, "convergence", func() bool {
				for _, tn := range c.nodes {
					if countAll(tn.st()) != b.N {
						return false
					}
				}
				return true
			})
			total := time.Since(start)
			b.StopTimer()
			b.ReportMetric(float64(b.N)/local.Seconds(), "put/s")
			b.ReportMetric(float64(b.N)/total.Seconds(), "converged/s")
		})
	}
}

// BenchmarkEphemeral measures routed ephemeral operations between live nodes.
func BenchmarkEphemeral(b *testing.B) {
	c := newTCluster(b, 3, badgerBackend())
	c.startAll()
	c.waitReady()
	a, r := c.nodes[0].n.Ephemeral(), c.nodes[1].n.Ephemeral()
	b.Run("LocalTake", func(b *testing.B) {
		ids := make([]string, b.N)
		for i := range ids {
			ids[i], _ = a.New(bg, "oauth.code", []byte("v"), time.Minute)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for _, id := range ids {
			if _, err := a.Take(bg, "oauth.code", id); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("RemoteTake", func(b *testing.B) {
		ids := make([]string, b.N)
		for i := range ids {
			ids[i], _ = a.New(bg, "oauth.code", []byte("v"), time.Minute)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for _, id := range ids {
			if _, err := r.Take(bg, "oauth.code", id); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("IncrRoutedParallel", func(b *testing.B) {
		var n atomic.Int64
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			e := c.nodes[int(n.Add(1))%3].n.Ephemeral()
			for i := 0; pb.Next(); i++ {
				if _, err := e.Incr(bg, "rl", fmt.Sprintf("ip-%d", i%64), 1, time.Minute); err != nil {
					b.Fatal(err)
				}
			}
		})
	})
	var _ ephemeral.Store = a
}

// BenchmarkResync times a node with a new disk copying a 100k-record cluster from the other two nodes: the first node
// is seeded with the records as "quisora bootstrap" would, the others copy them, and then one is replaced.
func BenchmarkResync(b *testing.B) {
	const total = 100_000
	for _, mk := range localBackends() {
		b.Run(mk.name, func(b *testing.B) {
			c := newTCluster(b, 3, mk)
			c.noSeed = true
			dir0 := b.TempDir()
			st := mk.open(b, dir0)
			var wg sync.WaitGroup
			var next atomic.Int64
			for range 16 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						i := next.Add(1)
						if i > total {
							return
						}
						if _, err := st.PutReplicated(bg, benchRec(i)); err != nil {
							b.Error(err)
							return
						}
					}
				}()
			}
			wg.Wait()
			if err := StartNewCluster(bg, dir0, st); err != nil {
				b.Fatal(err)
			}
			st.Close()
			c.nodes = []*tnode{c.build(0, dir0, nil), c.build(1, "", nil), c.build(2, "", nil)}
			b.Cleanup(c.closeAll)
			c.start(c.nodes...)
			c.waitReady()
			waitFor(b, 600*time.Second, "the others to copy", func() bool { return countAll(c.nodes[1].st()) == total && countAll(c.nodes[2].st()) == total })
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				stop(c.nodes[2])
				dst := c.build(2, "", nil)
				c.nodes[2] = dst
				b.StartTimer()
				start := time.Now()
				c.start(dst)
				waitFor(b, 600*time.Second, "resync", func() bool { return countAll(dst.st()) == total && !dst.n.Status().Resyncing })
				b.ReportMetric(float64(total)/time.Since(start).Seconds(), "records/s")
			}
		})
	}
}
