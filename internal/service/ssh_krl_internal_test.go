package service

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// A node does not keep the revocation list of every tenant ever asked for: not one of a tenant that is not there, and
// not one nobody has asked for in a while, unless it is being made or its revocations written down.
func TestSSHKRLEntriesAreDropped(t *testing.T) {
	st := memstore.New()
	t.Cleanup(func() { _ = st.Close() })
	sealer, err := secure.NewSealer(secure.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	s := New(config.Default(), st, sealer)
	if _, _, err := s.SSHKRLTagged(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a tenant that is not there: %v", err)
	}
	if len(s.ssh.krl) != 0 {
		t.Fatalf("%d lists kept for a tenant that is not there", len(s.ssh.krl))
	}

	now := time.Now()
	old := now.Add(-sshKRLIdle)
	s.ssh.krl = map[string]*sshKRLEntry{
		"idle":     {asked: old, data: []byte{1}},
		"asked":    {asked: now.Add(-sshKRLIdle / 2)},
		"building": {asked: old, flight: &sshKRLFlight{done: make(chan struct{})}},
		"writing":  {asked: old, persisting: true},
	}
	s.ssh.krlSwept = time.Time{} // (the request above swept)
	keys := func() []string {
		s.ssh.krlMu.Lock()
		defer s.ssh.krlMu.Unlock()
		var ids []string
		for id := range s.ssh.krl {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		return ids
	}
	sweep := func(at time.Time) {
		s.ssh.krlMu.Lock()
		defer s.ssh.krlMu.Unlock()
		s.sshKRLSweep(at)
	}
	sweep(now)
	if got := keys(); !slices.Equal(got, []string{"asked", "building", "writing"}) {
		t.Errorf("kept after a sweep: %v", got)
	}
	// once every sshKRLTTL at most
	s.ssh.krl["idle"] = &sshKRLEntry{asked: old}
	sweep(now.Add(sshKRLTTL / 2))
	if got := keys(); !slices.Contains(got, "idle") {
		t.Errorf("swept again within sshKRLTTL: %v", got)
	}
	sweep(now.Add(sshKRLTTL))
	if got := keys(); !slices.Equal(got, []string{"building", "writing"}) {
		t.Errorf("kept after the next sweep: %v", got)
	}
}
