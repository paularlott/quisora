package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/paularlott/gossip"
	"github.com/paularlott/quisora/internal/durable"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// persisted is the node's state kept in cluster-state.json: what is needed to decide, at the next start, whether the
// partition state in the database can be trusted (partition.Store.Intact).
//
// A node whose data is intact promises, stores and serves from the moment it has heard from a majority. A node whose
// data is not (it is new, or its database was lost, replaced or restored) first copies everything from a majority of
// the other nodes: it may have forgotten promises it made and writes it acknowledged, and counting it before it has
// caught up could let a lower epoch win or lose an acknowledged write.
type persisted struct {
	// Self is the database's own feed id when the state was saved: another one now means the database was replaced
	// since, by hand, and its partition state says nothing about this node's promises.
	Self string `json:"self"`
	// Intact: the partition state of the database can be trusted. Set for the first node of a new cluster
	// (StartNewCluster) and once a resync has completed (Node.resynced); cleared for a forced start until its resync
	// completes, so a crash half way through leaves the node needing it again.
	Intact bool `json:"intact"`
	// ForceAudit is an operator-forced start not yet written to the audit log (it is once the node is writable).
	ForceAudit *forceRecord `json:"force_audit,omitempty"`
	// Genesis names the data set this node's data belongs to (the partition protocol's ClusterID). Only StartNewCluster
	// makes one ("quisora bootstrap --new-cluster", a restore); a node with none adopts the one the other nodes publish
	// (adoptGenesis). Nodes of different data sets ignore each other in the partition protocol: their partitions share
	// sequence numbers that are not the same writes. Like Intact it is trusted only while Self is the database's.
	Genesis string `json:"genesis,omitempty"`
	// Formed is the partition protocol's (partition.Config.Formed, set through setFormed): the node has given a promise,
	// or synchronised with an intact majority, so it takes part in its data set's majorities. Until then it is unformed:
	// a new data set (StartNewCluster) starts unformed on its founder, the first node, and the nodes that join copy it
	// from the founder alone (the protocol's formation rule); a node that adopts a data set starts unformed too. A formed
	// node already holds a data set, and is never made the first node of a new one (CheckNewCluster).
	Formed bool `json:"formed,omitempty"`
	// LegacyEstablished is the name Formed had in earlier files ("established"): read as Formed, never written.
	LegacyEstablished bool `json:"established,omitempty"`
	// Starts counts this node's starts: raised, durably, at every start before the partition protocol runs (and kept in
	// the database too). PeerStarts is the highest count this node has seen each peer publish. Together they find a node
	// restored in place from a snapshot of itself (rollback.go). Starts only grows, whatever happens to the database;
	// PeerStarts is trusted only while Self is the database's.
	Starts     uint64            `json:"starts,omitempty"`
	PeerStarts map[string]uint64 `json:"peer_starts,omitempty"`
}

// readState reads the state file of dataDir. trusted: it was saved for st's database (its Self is st's feed id), so
// what it says about that database (Intact, Genesis, Formed) holds; a state saved for another database (it was
// wiped or replaced since) says nothing about this one.
func readState(dataDir string, st store.Store) (ps persisted, trusted bool) {
	b, err := os.ReadFile(filepath.Join(dataDir, "cluster-state.json"))
	if err != nil || json.Unmarshal(b, &ps) != nil {
		return persisted{}, false
	}
	ps.Formed, ps.LegacyEstablished = ps.Formed || ps.LegacyEstablished, false
	return ps, ps.Self != "" && ps.Self == st.FeedID()
}

// holdsDataSet reports whether a trusted state says its node already holds a data set: it has formed (taken part in its
// cluster), or it adopted the cluster's data set (or was forced to resync) and is copying it. A state StartNewCluster
// wrote for a node that has not run yet (intact, unformed) does not count: running it again is harmless.
func (ps persisted) holdsDataSet() bool {
	return ps.Genesis != "" && (ps.Formed || !ps.Intact)
}

// forceRecord is one forced start ("quisora force-start"), kept until it is in the audit log.
type forceRecord struct {
	At     int64  `json:"at"`
	Reason string `json:"reason"`
}

// ForceStartMarker is the file "quisora force-start" leaves in the data directory: the next start resyncs this node
// from the nodes that answer (fewer than a majority of the others are enough), and removes the file (it applies to one
// start only).
const ForceStartMarker = "force-start"

// loadState decides how this node starts: intact (its database's partition state is trusted), or resyncing. A
// force-start marker is consumed here, whatever the outcome, and always logged and kept for the audit log.
func (n *Node) loadState() {
	// "quisora force-start" applies to this start only, whatever happens: the file goes now.
	forced := n.opt.ForceStart
	if n.dir != "" {
		marker := filepath.Join(n.dir, ForceStartMarker)
		if _, err := os.Stat(marker); err == nil {
			forced = true
			if err := os.Remove(marker); err != nil {
				n.log.WithError(err).Error("could not remove the force-start file: refusing to force", "file", marker)
				forced = false
			}
		}
	}
	var ps persisted
	trusted := false
	if n.dir != "" {
		ps, trusted = readState(n.dir, n.st.inner)
	}
	if ps.ForceAudit != nil {
		n.forceAudit.Store(ps.ForceAudit) // an earlier forced start not audited yet
	}
	if n.pst.unpartitioned() && n.holdsRecords() {
		n.setUnfit("this node's database holds records that no partition write made: it was written by an earlier " +
			"build, or loaded other than by \"quisora restore\". A gossip node starts with an empty database (it copies " +
			"everything from the others) or with a restored backup, never with this. Empty the database and start again")
		return
	}
	intact := trusted && ps.Intact
	if forced {
		reason := "an operator forced this start (quisora force-start): the node copies its data from the nodes that " +
			"answer, even fewer than a majority of the others, so a write that only the nodes it could not reach held is lost"
		n.log.Warn("starting as a node whose data may not be trusted (quisora force-start): it resyncs from the nodes " +
			"that answer")
		n.forced.Store(&reason)
		n.forceAudit.Store(&forceRecord{At: time.Now().UnixNano(), Reason: reason})
		n.forceResync.Store(true)
		intact = false
	}
	if trusted { // a data directory kept while its database was wiped or replaced keeps no identity
		if ps.Genesis != "" {
			g := ps.Genesis
			n.genesis.Store(&g)
		}
		n.formed.Store(ps.Formed)
		n.peerStarts = maps.Clone(ps.PeerStarts)
	}
	// Every start is counted, durably, before the partition protocol runs (rollback.go): the state file is written now
	// (a forced start's pending audit with it, which must survive a crash before the node is writable).
	if n.countStart(ps.Starts) && intact {
		intact = false
		n.log.Warn("this node's database is older than its cluster state: it was restored in place (a point-in-time " +
			"restore, a database file copied back) and has forgotten what it promised and stored since, so it copies " +
			"everything from the other nodes before it takes part")
	}
	n.intact.Store(intact)
	n.saveState()
}

// resynced runs once the partition protocol has copied everything this node was missing from the other nodes: its
// database's partition state can be trusted from now on, across restarts.
func (n *Node) resynced() {
	n.forceResync.Store(false)
	n.intact.Store(true)
	n.saveState()
	n.log.Info("resync complete: this node's data is the cluster's")
}

// holdsRecords reports whether the store holds a record (node-local kinds aside: short-lived state, and the node's own
// audit events, which it records whether it holds a data set or not).
func (n *Node) holdsRecords() bool {
	for _, k := range model.Kinds() {
		if localOnly(k) {
			continue
		}
		if c, err := n.st.inner.Count(n.ctx, k, ""); err != nil || c > 0 {
			return true
		}
	}
	return false
}

// setUnfit stops this node from serving until it is restarted with a usable database.
func (n *Node) setUnfit(why string) {
	if n.unfit.CompareAndSwap(nil, &why) {
		n.log.Error("refusing to serve", "reason", why)
	}
}

// ForcedStart reports why this start was forced with "quisora force-start" ("" when it was not).
func (n *Node) ForcedStart() string {
	if p := n.forced.Load(); p != nil {
		return *p
	}
	return ""
}

// PendingForceStart returns a forced start (this one or an earlier one) that is not in the audit log yet. The
// application writes it once the node is writable and then calls ForceStartAudited.
func (n *Node) PendingForceStart() (at time.Time, reason string, ok bool) {
	p := n.forceAudit.Load()
	if p == nil {
		return time.Time{}, "", false
	}
	return time.Unix(0, p.At), p.Reason, true
}

// ForceStartAudited clears the pending forced start once it is in the audit log.
func (n *Node) ForceStartAudited() {
	if n.forceAudit.Swap(nil) != nil {
		n.saveState()
	}
}

func (n *Node) saveState() {
	if err := n.writeState(); err != nil { // a power loss must not lose "intact"
		n.log.WithError(err).Warn("save cluster state")
	}
}

// writeState writes cluster-state.json durably (whole or not at all).
func (n *Node) writeState() error {
	n.saveMu.Lock()
	defer n.saveMu.Unlock()
	if n.stateFile == "" {
		return nil
	}
	ps := persisted{Self: n.st.inner.FeedID(), Intact: n.intact.Load(), ForceAudit: n.forceAudit.Load(),
		Formed: n.formed.Load(), Starts: n.starts.Load(), PeerStarts: n.startsSnapshot()}
	if g := n.genesis.Load(); g != nil {
		ps.Genesis = *g
	}
	b, _ := json.Marshal(ps)
	return durable.WriteFile(n.stateFile+".tmp", n.stateFile, b)
}

// setFormed records, durably, that this node has formed in the partition protocol's sense (Config.SetFormed: it is about
// to give its first promise, or it synchronised with an intact majority): from then on it takes part in its data set's
// majorities, and it is never made the first node of another data set (CheckNewCluster). The protocol calls it before it
// stores the promise; a failure keeps the node unformed, and the promise is not given.
func (n *Node) setFormed() error {
	if n.formed.Swap(true) {
		return nil
	}
	if err := n.writeState(); err != nil {
		n.formed.Store(false)
		return err
	}
	return nil
}

// StartNewCluster makes st, the database of a node that has not run yet, the first node of a new cluster ("quisora
// bootstrap --new-cluster" and "quisora restore" on a gossip node, and the load test's seed): every record in it is
// written as a write of its partition (a record that was written outside the partition protocol belongs to no write,
// and would never reach another node), and the node's state names a new data set (its genesis, the partition protocol's ClusterID) and says that its data is that data set's.
// The other nodes start with empty databases, adopt the data set and copy everything from it. It refuses a node that
// already holds a data set (CheckNewCluster). Until the node has run, running it again is harmless: every record is
// written once more, as a later write of its partition, and the data set keeps its genesis (and a forced start not
// audited yet stays pending).
func StartNewCluster(ctx context.Context, dataDir string, st store.Store) error {
	pst, ok := st.(store.PartitionStore)
	if !ok {
		return fmt.Errorf("cluster: the %T storage backend cannot hold a gossip cluster's data (no partition support)", st)
	}
	if err := CheckNewCluster(dataDir, st); err != nil {
		return err
	}
	if err := seedPartitions(ctx, st, pst); err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	old, trusted := readState(dataDir, st)
	ps := persisted{Self: st.FeedID(), Intact: true, Genesis: uuid.NewString(), ForceAudit: old.ForceAudit,
		Starts: old.Starts} // (the start count only grows: rollback.go)
	if trusted && old.Genesis != "" {
		ps.Genesis = old.Genesis // a second run on the same database: the same data set
	}
	if ps.Starts > 0 { // the database's count matches the file's: it is not older than the state
		e := &model.Ephemeral{Meta: model.Meta{ID: startsID}, Value: []byte(strconv.FormatUint(ps.Starts, 10))}
		if err := store.NewTable[model.Ephemeral](st).Put(ctx, e); err != nil {
			return err
		}
	}
	b, _ := json.Marshal(ps)
	path := filepath.Join(dataDir, "cluster-state.json")
	return durable.WriteFile(path+".tmp", path, b) // whole or absent, never torn
}

// CheckNewCluster refuses to make st (in dataDir) the first node of a new cluster when it already holds a data set: its
// state, saved for this very database, says it took part in a cluster, or adopted one's data set. StartNewCluster
// would otherwise make that data the first writes of another data set. A state saved for another database (the
// database was wiped or replaced, the data directory kept) is no obstacle. Run before anything is written, by commands
// that write first and call StartNewCluster after.
func CheckNewCluster(dataDir string, st store.Store) error {
	ps, trusted := readState(dataDir, st)
	if !trusted || !ps.holdsDataSet() {
		return nil
	}
	return fmt.Errorf("cluster: this node already holds a cluster's data set (%s, saved for this database, names data "+
		"set %s): a new cluster is started on a node with an empty database and a data directory of its own. A node "+
		"that joins a cluster needs no bootstrap and no restore: start it with an empty database and it copies "+
		"everything. To make this node the first of a new cluster, empty its database and delete %s first",
		filepath.Join(dataDir, "cluster-state.json"), ps.Genesis, filepath.Join(dataDir, "cluster-state.json"))
}

// seedPage is how many records of one kind seedPartitions reads at a time: the most it holds in memory.
const seedPage = 1000

// seedPartitions writes every record of st as a write of its partition, a page of one kind at a time: the records of a
// page that belong to one partition are one write, with the partition's next sequence number (so records written after
// an earlier run, or by a node that has begun to take part, are stamped too).
func seedPartitions(ctx context.Context, st store.Store, pst store.PartitionStore) error {
	var next [partitions]uint64
	for p := range partitions {
		ps, err := pst.PartitionState(ctx, p)
		if err != nil {
			return err
		}
		next[p] = ps.Committed.Seq
	}
	for _, kind := range model.Kinds() {
		if localOnly(kind) { // a node's audit events stay its own
			continue
		}
		after := ""
		for {
			res, err := st.List(ctx, kind, store.ListQuery{After: after, Limit: seedPage})
			if err != nil {
				return err
			}
			byPart := map[int][]*store.Record{}
			for _, r := range res.Records {
				after = r.ID
				byPart[recPartition(r)] = append(byPart[recPartition(r)], r)
			}
			for p, recs := range byPart {
				next[p]++
				if err := pst.ApplyPartition(ctx, p, recs, store.PartitionPos{Seq: next[p]}); err != nil {
					return fmt.Errorf("cluster: seeding partition %d: %w", p, err)
				}
			}
			if len(res.Records) < seedPage {
				break
			}
		}
	}
	return nil
}

// ---- the data set: genesis ----

// metaGenesis is the gossip metadata that names the data set this node holds (persisted.Genesis): a node with none
// publishes nothing.
const metaGenesis = "quisora.genesis"

// noDataSet is why a node that holds no data set waits while no node in view publishes one.
const noDataSet = "no data set: run \"quisora bootstrap --new-cluster\" (or restore a backup) on one node; the nodes " +
	"that start with an empty database copy the data set from it"

func (n *Node) publishGenesis() {
	if g := n.genesis.Load(); g != nil && n.gc != nil {
		n.gc.LocalMetadata().SetString(metaGenesis, *g)
	}
}

// publishedGenesis returns the data sets the alive members other than this node publish, each with the members that
// publish it.
func (n *Node) publishedGenesis(members []*member) map[string][]string {
	seen := map[string][]string{}
	for _, mb := range members {
		if mb.id == n.id || mb.node == nil || mb.node.Metadata == nil || mb.state != gossip.NodeAlive {
			continue
		}
		if g := mb.node.Metadata.GetString(metaGenesis); g != "" {
			seen[g] = append(seen[g], mb.id)
		}
	}
	for _, ids := range seen {
		slices.Sort(ids) // (a stable text for the logs)
	}
	return seen
}

// adoptGenesis gives a node that holds no data set the one the alive members publish, if they all publish the same:
// it is persisted, published, and the node copies everything from the others (it starts in resync mode, not intact).
// Otherwise it waits, saying why (waitDataSet): nobody publishes one (no node has been bootstrapped yet), or the members
// disagree (a node was bootstrapped or restored apart: which data set to join is not this node's guess). It reports
// whether the node has a data set now.
func (n *Node) adoptGenesis() bool {
	if n.genesis.Load() != nil {
		return true
	}
	seen := n.publishedGenesis(n.mem.Load().all)
	if len(seen) != 1 {
		why := noDataSet
		if len(seen) > 1 {
			var names []string
			for g, ids := range seen {
				names = append(names, fmt.Sprintf("%s (%s)", g, strings.Join(ids, ", ")))
			}
			slices.Sort(names)
			why = "the nodes in view hold different data sets: " + strings.Join(names, "; ") + ". This node holds none " +
				"and joins none until they agree: start a node that was bootstrapped or restored by mistake again with " +
				"an empty database"
		}
		n.waitDataSet(why)
		return false
	}
	var g string
	for g = range seen { // the one there is
		break
	}
	n.genesis.Store(&g)
	n.intact.Store(false) // whatever its database holds, it copies the data set from the others
	n.formed.Store(false) // (and it has promised nothing in it yet)
	n.saveState()
	n.publishGenesis()
	n.dataSetWait.Store(nil)
	n.log.Info("joining the cluster's data set: this node copies everything from the other nodes", "data_set", g)
	return true
}

// waitDataSet records (and logs, when it changes) why this node has not started the partition protocol.
func (n *Node) waitDataSet(why string) {
	if old := n.dataSetWait.Swap(&why); old == nil || *old != why {
		n.log.Warn("not starting the partition protocol", "reason", why)
	}
}

// checkGenesis compares this node's data set with the ones the alive members publish. Nodes of different data sets
// ignore each other in the partition protocol (its ClusterID), so nothing passes between them whatever this check
// says; it makes the situation visible. A node whose data set fewer than a majority of the cluster share (itself
// included) while another is in view is the one set up apart (a bootstrap or restore on a node meant to join, or a
// second cluster with the same key and peers): it refuses to serve, saying why, until it is started with an empty
// database (it then adopts the cluster's data set and copies everything). The nodes of the majority log the stranger
// and carry on.
func (n *Node) checkGenesis(members []*member) {
	own := n.genesis.Load()
	var why, stranger string
	if own != nil {
		same := 1
		for g, ids := range n.publishedGenesis(members) {
			if g == *own {
				same += len(ids)
			} else {
				stranger = fmt.Sprintf("node %s holds data set %s, this node %s", strings.Join(ids, ", "), g, *own)
			}
		}
		if stranger != "" && same < n.Quorum() {
			why = "another data set is in view (" + stranger + ") and fewer than a majority of the cluster share this " +
				"node's: this node was set up apart from the cluster (quisora bootstrap or restore), and nodes of " +
				"different data sets never exchange data. A node that joins a cluster needs no bootstrap and no " +
				"restore: start it with an empty database and it copies everything from the cluster"
		}
	}
	if why != "" {
		if n.otherCluster.Swap(&why) == nil {
			n.log.Error("refusing to serve", "reason", why)
		}
	} else if n.otherCluster.Swap(nil) != nil {
		n.log.Info("no other data set in view any more")
	}
	switch {
	case stranger == "":
		n.stranger.Store(nil)
	case why == "":
		if old := n.stranger.Swap(&stranger); old == nil || *old != stranger {
			n.log.Warn("a node of another data set is in view: the partition protocol ignores it", "detail", stranger)
		}
	}
}
