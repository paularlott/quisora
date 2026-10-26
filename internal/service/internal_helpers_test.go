package service

import (
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store"
)

// newInternalService is a service over st with a master key of its own; st is closed when the test ends.
func newInternalService(t testing.TB, st store.Store) *Service {
	t.Helper()
	t.Cleanup(func() { _ = st.Close() })
	sealer, err := secure.NewSealer(secure.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	return New(config.Default(), st, sealer)
}

// withSweepAge makes the orphan sweep judge records of any age until the test ends.
func withSweepAge(t testing.TB) {
	t.Helper()
	saved := sweepMinAge
	sweepMinAge = -time.Hour
	t.Cleanup(func() { sweepMinAge = saved })
}

// sweepStartingAt is a sweep that begins with the records of kind.
func sweepStartingAt(kind model.Kind) *Sweep {
	sw := &Sweep{}
	for i, k := range sweepKinds {
		if k == kind {
			sw.kind = i
		}
	}
	return sw
}
