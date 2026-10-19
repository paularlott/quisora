package kvstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/storetest"
)

func badgerFactory(t testing.TB) store.Store {
	s, err := OpenBadger(context.Background(), t.TempDir(), BadgerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// valkeyFactory returns a store on a fresh key prefix of the server named by QUISORA_TEST_VALKEY_ADDR, or skips.
func valkeyFactory(t testing.TB) store.Store {
	addr := os.Getenv("QUISORA_TEST_VALKEY_ADDR")
	if addr == "" {
		t.Skip("QUISORA_TEST_VALKEY_ADDR not set")
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	s, err := OpenValkey(context.Background(), ValkeyConfig{Addrs: []string{addr}, KeyPrefix: "quisoratest-" + hex.EncodeToString(b[:]) + "/"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// The suite closes the store; use a second connection to clean up the keys.
		e := s.eng.(*valkeyEngine)
		c := &valkeyEngine{prefix: e.prefix}
		s2, err := OpenValkey(context.Background(), ValkeyConfig{Addrs: []string{addr}, KeyPrefix: e.prefix})
		if err != nil {
			return
		}
		c = s2.eng.(*valkeyEngine)
		_ = c.deletePrefix(context.Background())
		s2.Close()
	})
	return s
}

func TestBadgerConformance(t *testing.T) { storetest.Run(t, badgerFactory) }
func TestBadgerBatch(t *testing.T)       { storetest.RunBatch(t, badgerFactory) }
func TestValkeyConformance(t *testing.T) { storetest.Run(t, valkeyFactory) }

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
	b.Run("Valkey", func(b *testing.B) { storetest.Bench(b, valkeyFactory) })
}
