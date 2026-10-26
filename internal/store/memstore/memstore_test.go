package memstore

import (
	"testing"

	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/storetest"
)

func factory(testing.TB) store.Store { return New() }

func TestConformance(t *testing.T) { storetest.Run(t, factory) }
func TestBatch(t *testing.T)       { storetest.RunBatch(t, factory) }
func TestPartition(t *testing.T)   { storetest.RunPartition(t, factory) }

func BenchmarkStore(b *testing.B) { storetest.Bench(b, factory) }
