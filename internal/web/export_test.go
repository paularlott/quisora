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

// CachedOrgs is how many references the organization cache holds.
func (s *Server) CachedOrgs() int {
	s.orgs.mu.RLock()
	defer s.orgs.mu.RUnlock()
	return len(s.orgs.m)
}
