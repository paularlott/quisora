package cluster

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/paularlott/gossip"
	logtest "github.com/paularlott/logger/testing"
)

// A node that has not formed the cluster names the configured peers it cannot see, and the key among the causes to
// check (a peer with another cluster.key never comes into view: each drops the other's packets as undecryptable):
// once a minute, not once a second, only the peers missing, and nothing once every peer is in view.
func TestFormingNodeNamesPeersNotInView(t *testing.T) {
	t.Parallel()
	log := logtest.New()
	n := &Node{id: "self", log: log}
	n.nodes.Store(3)
	n.seeds, n.seedsSet = []string{"10.0.0.2:7946", "10.0.0.3:7946"}, true
	peer := func(addr string, state gossip.NodeState) *member {
		return &member{id: addr, state: state, node: gossip.NewTestNode(gossip.NodeID(uuid.New()), addr, nil)}
	}
	self := &member{id: "self", state: gossip.NodeAlive}
	n.mem.Store(&membership{self: self, all: []*member{self, peer("10.0.0.2:7946", gossip.NodeAlive), peer("10.0.0.3:7946", gossip.NodeDead)}, alive: 2})
	warnings := peerWarnings(log)

	start := time.Now()
	check := checker(n)
	check(start)
	w := warnings()
	if len(w) != 1 {
		t.Fatalf("%d warnings, want 1", len(w))
	}
	kv := w[0].KeysAndValues
	if len(kv) < 2 || kv[0] != "peers" || kv[1] != "10.0.0.3:7946" {
		t.Fatalf("named %v, want only the peer not in view (10.0.0.3:7946; a dead member is not in view)", kv)
	}
	for s := 1; s < 60; s++ { // watchLoop's ticks over the next minute
		check(start.Add(time.Duration(s) * time.Second))
	}
	if len(warnings()) != 1 {
		t.Fatalf("%d warnings within a minute, want 1", len(warnings()))
	}
	check(start.Add(time.Minute))
	if len(warnings()) != 2 {
		t.Fatalf("%d warnings after a minute, want 2", len(warnings()))
	}

	// Every peer in view (a suspect one too): nothing to name.
	n.mem.Store(&membership{self: self, all: []*member{self, peer("10.0.0.2:7946", gossip.NodeAlive), peer("10.0.0.3:7946", gossip.NodeSuspect)}, alive: 2})
	check(start.Add(3 * time.Minute))
	if len(warnings()) != 2 {
		t.Fatalf("warned with every peer in view: %d warnings", len(warnings()))
	}
}

// checker returns warnMissingPeers for n, waiting for the check it starts (off watchLoop) to finish.
func checker(n *Node) func(time.Time) {
	return func(at time.Time) {
		n.warnMissingPeers(at)
		for n.peersChecking.Load() {
			time.Sleep(time.Millisecond)
		}
	}
}

// peerWarnings returns the warnings naming peers not in view logged to log.
func peerWarnings(log interface{ GetEntries() []logtest.LogEntry }) func() []logtest.LogEntry {
	return func() []logtest.LogEntry {
		var out []logtest.LogEntry
		for _, e := range log.GetEntries() {
			if e.Level == "warn" && strings.Contains(e.Message, "cluster.key") {
				out = append(out, e)
			}
		}
		return out
	}
}

// A node that has not formed the cluster but finds no peer missing (waiting for genesis, an unfit database, fewer
// peers listed than cluster.size) checks again a minute later, not at every watchLoop tick: the check may resolve
// host names, which a DNS outage makes slow. A peer that goes out of view meanwhile is named at the next check.
func TestFormingNodeChecksPeersOnceAMinute(t *testing.T) {
	t.Parallel()
	log := logtest.New()
	n := &Node{id: "self", log: log}
	n.nodes.Store(3)
	n.seeds, n.seedsSet = []string{"10.0.0.2:7946"}, true
	self := &member{id: "self", state: gossip.NodeAlive}
	node := gossip.NewTestNode(gossip.NodeID(uuid.New()), "10.0.0.2:7946", nil)
	n.mem.Store(&membership{self: self, all: []*member{self, {id: "p", state: gossip.NodeAlive, node: node}}, alive: 2})
	warnings := peerWarnings(log)
	check := checker(n)

	start := time.Now()
	check(start) // every peer in view: nothing named
	n.mem.Store(&membership{self: self, all: []*member{self, {id: "p", state: gossip.NodeDead, node: node}}, alive: 1})
	for s := 1; s < 60; s++ { // watchLoop's ticks over the next minute: no check
		check(start.Add(time.Duration(s) * time.Second))
	}
	if len(warnings()) != 0 {
		t.Fatalf("checked again within a minute of a check that found nothing: %d warnings", len(warnings()))
	}
	check(start.Add(time.Minute))
	if len(warnings()) != 1 {
		t.Fatalf("%d warnings a minute on, want 1", len(warnings()))
	}
}
