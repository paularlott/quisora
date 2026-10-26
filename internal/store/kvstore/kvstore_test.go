package kvstore

import (
	"context"
	"testing"

	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/storetest"
)

func TestBadgerConformance(t *testing.T) { storetest.Run(t, badgerFactory) }
func TestBadgerBatch(t *testing.T)       { storetest.RunBatch(t, badgerFactory) }

func BenchmarkStore(b *testing.B) {
	b.Run("Badger", func(b *testing.B) { storetest.Bench(b, badgerFactory) })
	b.Run("BadgerNoGroup", func(b *testing.B) { // one transaction and one fsync per write, for comparison
		storetest.BenchWrites(b, func(t testing.TB) store.Store {
			s, err := OpenBadger(context.Background(), t.TempDir(), BadgerOptions{Group: GroupOptions{Disabled: true}})
			if err != nil {
				t.Fatal(err)
			}
			return s
		})
	})
}
