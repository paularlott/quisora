package storetest

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Bench runs the standard store benchmarks. Use: func BenchmarkStore(b *testing.B) { storetest.Bench(b, factory) }
func Bench(b *testing.B, f Factory) {
	benchEphemeral(b, f)
	BenchWrites(b, f)
	benchReads(b, f)
}

// BenchWrites runs the write benchmarks: Put and CompareAndPut (Update), serial and from parallel goroutines.
func BenchWrites(b *testing.B, f Factory) {
	b.Run("Put", func(b *testing.B) {
		s := f(b)
		defer s.Close()
		var n atomic.Int64
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				i := n.Add(1)
				if err := users(s).Put(ctx, newUser(fmt.Sprintf("org%d", i%100), fmt.Sprintf("u%d", i))); err != nil {
					b.Fatal(err)
				}
			}
		})
	})
	b.Run("PutSerial", func(b *testing.B) {
		s := f(b)
		defer s.Close()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := users(s).Put(ctx, newUser(fmt.Sprintf("org%d", i%100), fmt.Sprintf("u%d", i))); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("UpdateParallel", func(b *testing.B) { // CompareAndPut from many goroutines, each on its own records
		s := f(b)
		defer s.Close()
		us := seedUsers(b, s, "org1", 1024)
		var g atomic.Int64
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			base := int(g.Add(1)-1) % 64 * 16 // 16 records per goroutine (up to 64 goroutines)
			for i := 0; pb.Next(); i++ {
				u := us[base+i%16]
				u.GivenName = fmt.Sprint(i)
				if err := users(s).Update(ctx, u); err != nil {
					b.Fatal(err)
				}
			}
		})
	})
	b.Run("Update", func(b *testing.B) {
		s := f(b)
		defer s.Close()
		us := seedUsers(b, s, "org1", 1000)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			u := us[i%1000]
			u.GivenName = fmt.Sprint(i)
			if err := users(s).Update(ctx, u); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func benchReads(b *testing.B, f Factory) {
	b.Run("Get", func(b *testing.B) {
		s := f(b)
		defer s.Close()
		us := seedUsers(b, s, "org1", 1000)
		var n atomic.Int64
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, err := users(s).Get(ctx, us[n.Add(1)%1000].ID); err != nil {
					b.Fatal(err)
				}
			}
		})
	})
	b.Run("GetByUnique", func(b *testing.B) {
		s := f(b)
		defer s.Close()
		us := seedUsers(b, s, "org1", 1000)
		var n atomic.Int64
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				u := us[n.Add(1)%1000]
				if _, err := users(s).GetByUnique(ctx, model.UserEmailKey(u.OrgID, u.Email)); err != nil {
					b.Fatal(err)
				}
			}
		})
	})
	b.Run("ListOrg1000SearchSortPage", func(b *testing.B) {
		s := f(b)
		defer s.Close()
		seedUsers(b, s, "org1", 1000)
		seedUsers(b, s, "org2", 1000)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, _, err := users(s).List(ctx, store.ListQuery{Scope: "org1", Search: "user1", Sort: "name",
				Limit: 25}); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("ListOrg1000Page", func(b *testing.B) {
		s := f(b)
		defer s.Close()
		seedUsers(b, s, "org1", 1000)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, _, err := users(s).List(ctx, store.ListQuery{Scope: "org1", Offset: 500, Limit: 25}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// benchEphemeral measures the database-backed ephemeral store (clusters sharing one database): one sign-in step
// writes a value (New) and a later one consumes it (Take); rate limits count with Incr.
func benchEphemeral(b *testing.B, f Factory) {
	b.Run("EphNew", func(b *testing.B) {
		s := f(b)
		defer s.Close()
		e := ephemeral.NewShared(s)
		val := make([]byte, 300)
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, err := e.New(ctx, "code", val, time.Minute); err != nil {
					b.Fatal(err)
				}
			}
		})
	})
	b.Run("EphTake", func(b *testing.B) {
		s := f(b)
		defer s.Close()
		e := ephemeral.NewShared(s)
		ids := make([]string, b.N)
		for i := range ids {
			ids[i], _ = e.New(ctx, "code", make([]byte, 300), time.Minute)
		}
		var n atomic.Int64
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, err := e.Take(ctx, "code", ids[n.Add(1)-1]); err != nil {
					b.Fatal(err)
				}
			}
		})
	})
	b.Run("EphIncrSpread", func(b *testing.B) { // rate limits: many keys (one per IP or account)
		s := f(b)
		defer s.Close()
		e := ephemeral.NewShared(s)
		var n atomic.Int64
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, err := e.Incr(ctx, "rate", fmt.Sprintf("ip|%d", n.Add(1)%1000), 1, time.Minute); err != nil {
					b.Fatal(err)
				}
			}
		})
	})
	b.Run("EphIncrHot", func(b *testing.B) { // the worst case: every request counts on one key
		s := f(b)
		defer s.Close()
		e := ephemeral.NewShared(s)
		b.ReportAllocs()
		b.SetParallelism(1)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, err := e.Incr(ctx, "rate", "hot", 1, time.Hour); err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}
