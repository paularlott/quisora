package cluster

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/kvstore"
)

func benchRec(i int64) *store.Record {
	r := newRec(newID(), fmt.Sprintf("o|u%d", i))
	r.Data = []byte(strings.Repeat("x", 400))
	return r
}

// BenchmarkReplicatedPut measures local Put throughput on a 3-node cluster (writes spread over the nodes, each Put
// broadcast to the peers) and the throughput including the time until every node holds every record.
func BenchmarkReplicatedPut(b *testing.B) {
	for name, mk := range backends {
		b.Run(name, func(b *testing.B) {
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
			b.ReportMetric(float64(total-local)/float64(time.Millisecond), "lag-ms")
		})
	}
}

// BenchmarkEphemeral measures routed ephemeral operations between two live nodes.
func BenchmarkEphemeral(b *testing.B) {
	c := newTCluster(b, 3, memBackend)
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
	b.Run("RemoteTakeParallel", func(b *testing.B) {
		ids := make([]string, b.N)
		for i := range ids {
			ids[i], _ = a.New(bg, "oauth.code", []byte("v"), time.Minute)
		}
		var n atomic.Int64
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, err := r.Take(bg, "oauth.code", ids[n.Add(1)-1]); err != nil {
					b.Fatal(err)
				}
			}
		})
	})
	b.Run("RemoteGet", func(b *testing.B) {
		id, _ := a.New(bg, "oauth.code", []byte("v"), time.Hour)
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			if _, err := r.Get(bg, "oauth.code", id); err != nil {
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

// BenchmarkAntiEntropyCatchUp times a brand-new node pulling a 100k-record feed from a peer.
func BenchmarkAntiEntropyCatchUp(b *testing.B) {
	const total = 100_000
	for name, mk := range backends {
		b.Run(name, func(b *testing.B) {
			c := newTCluster(b, 2, mk)
			c.opts = func(o *Options) { o.JoinWait = 100 * time.Millisecond }
			src := c.build(0, "", nil)
			c.nodes = append(c.nodes, src)
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
						if err := src.st().Put(bg, benchRec(i)); err != nil {
							b.Error(err)
							return
						}
					}
				}()
			}
			wg.Wait()
			c.start(src)
			b.Cleanup(c.closeAll)
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				dst := c.build(1, "", func(cfg *config.Config) {})
				c.nodes = append(c.nodes, dst)
				b.StartTimer()
				start := time.Now()
				c.start(dst)
				waitFor(b, 300*time.Second, "catch-up", func() bool { return countAll(dst.st()) == total })
				d := time.Since(start)
				b.StopTimer()
				b.ReportMetric(float64(total)/d.Seconds(), "records/s")
				stop(dst)
				c.nodes = c.nodes[:len(c.nodes)-1]
				b.StartTimer()
			}
		})
	}
}

var _ = context.Background

func badgerSyncBackend(t testing.TB, dir string) store.Store {
	s, err := kvstore.OpenBadger(bg, filepath.Join(dir, "badger"), kvstore.BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// BenchmarkCatchUp3Peers reproduces a node joining a 3-node cluster: three converged source nodes (each holds all
// 100k records), and a fresh receiver that lists all three as peers. The receiver variants differ in fsync.
func BenchmarkCatchUp3Peers(b *testing.B) {
	const total = 100_000
	recv := map[string]backend{"memstore": memBackend, "badger-nosync": badgerBackend, "badger-sync": badgerSyncBackend}
	for name, rb := range recv {
		b.Run(name, func(b *testing.B) {
			c := newTCluster(b, 4, badgerBackend)
			c.opts = func(o *Options) { o.JoinWait = 300 * time.Millisecond }
			for i := range 3 {
				c.nodes = append(c.nodes, c.build(i, "", func(cfg *config.Config) { cfg.Cluster.Peers = c.addrs[:3] }))
			}
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
						if err := c.nodes[0].st().Put(bg, benchRec(i)); err != nil {
							b.Error(err)
							return
						}
					}
				}()
			}
			wg.Wait()
			c.start(c.nodes...)
			b.Cleanup(c.closeAll)
			waitFor(b, 300*time.Second, "sources converged", func() bool {
				return countAll(c.nodes[1].st()) == total && countAll(c.nodes[2].st()) == total
			})
			c.mk = rb
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				dst := c.build(3, "", func(cfg *config.Config) { cfg.Cluster.Peers = c.addrs[:3] })
				c.nodes = append(c.nodes, dst)
				b.StartTimer()
				start := time.Now()
				c.start(dst)
				waitFor(b, 600*time.Second, "catch-up", func() bool { return countAll(dst.st()) == total })
				d := time.Since(start)
				b.StopTimer()
				b.ReportMetric(float64(total)/d.Seconds(), "records/s")
				stop(dst)
				c.nodes = c.nodes[:len(c.nodes)-1]
				b.StartTimer()
			}
		})
	}
}

// BenchmarkDurablePut measures a security write that returns once a majority holds it: two peers' acknowledgements
// on five nodes, one on three. Serial: the latency of one write; Parallel: throughput from 15 goroutines.
func BenchmarkDurablePut(b *testing.B) {
	for _, size := range []int{3, 5} {
		c := newTCluster(b, size, memBackend)
		c.startAll()
		c.waitReady()
		var seq atomic.Int64
		ctx := store.WithDurable(bg)
		b.Run(fmt.Sprintf("%dnodes/Serial", size), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if err := c.nodes[0].st().Put(ctx, benchRec(seq.Add(1))); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("%dnodes/Parallel", size), func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if err := c.nodes[0].st().Put(ctx, benchRec(seq.Add(1))); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
		c.closeAll()
	}
}
