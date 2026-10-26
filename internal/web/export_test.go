package web

import (
	"testing"
	"time"
)

// SetDrainUnit sets the unit of server.shutdown_drain for one test.
func SetDrainUnit(t *testing.T, d time.Duration) {
	old := drainUnit
	drainUnit = d
	t.Cleanup(func() { drainUnit = old })
}
