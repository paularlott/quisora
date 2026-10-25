package service

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
)

// Every node reports its master keys (their ids, secure.KeyID: the one it seals with first, then its previous ones),
// in a replicated record that expires unless renewed: during a rotation the housekeeping leader re-seals only once
// every live node seals with the same key as itself, and only then says the previous keys can go. Otherwise a leader still on the old key would re-seal back to
// it, and a node still on the old key would keep sealing new secrets with it after the re-seal.

const (
	masterKeyReportPrefix = "master-key/"
	// MasterKeyReportTTL is how long a node's report counts without being renewed (a stopped node stops counting).
	MasterKeyReportTTL = 15 * time.Minute
)

// ReportMasterKey records node nodeID's master keys (this service's keyring), for MasterKeyReportTTL.
func (s *Service) ReportMasterKey(ctx context.Context, nodeID string) error {
	id := masterKeyReportPrefix + nodeID
	for range 5 {
		// "<active>,<previous>...|<queued items needing a previous key>|<queued items needing a key not configured>"
		// (QueuesStale)
		until, keys := time.Now().Add(MasterKeyReportTTL), strings.Join(s.Sealer.KeyIDs(), ",")
		if s.QueuesStale != nil {
			stale, lost := s.QueuesStale()
			keys += "|" + strconv.Itoa(stale) + "|" + strconv.Itoa(lost)
		}
		l, err := s.Locks.Get(ctx, id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			err = s.Locks.Create(ctx, &model.Lock{Meta: model.Meta{ID: id}, Holder: keys, Until: until})
		case err == nil:
			l.Holder, l.Until = keys, until
			err = s.Locks.Update(ctx, l)
		}
		if err == nil || (!errors.Is(err, store.ErrStale) && !errors.Is(err, store.ErrNotFound)) {
			return mapStore(err)
		}
	}
	return ErrStale
}

// NodeKeys is what a node reported of its master keys.
type NodeKeys struct {
	Active   string   `json:"active_key"`
	Previous []string `json:"previous_keys"`
	// QueueStale counts the items of the node's queues on disk (mail, back-channel logouts) still sealed with a
	// previous key: the previous keys cannot go while any node has one. QueueLost counts those sealed with a key no
	// longer configured: they need none of the configured keys, and the node gives them up once they are 8 days old.
	QueueStale int `json:"queued_items_stale"`
	QueueLost  int `json:"queued_items_lost"`
}

// MasterKeyNodes returns the master keys each live node reported, by node id.
func (s *Service) MasterKeyNodes(ctx context.Context) (map[string]NodeKeys, error) {
	// Only the reports' range of ids, read in id order: other lock records (the admin lock, groups' locks) are not
	// read at all.
	now := time.Now()
	out := map[string]NodeKeys{}
	for after := masterKeyReportPrefix; ; {
		l, _, err := s.Locks.List(ctx, store.ListQuery{After: after, Limit: 100})
		if err != nil {
			return nil, mapStore(err)
		}
		for _, r := range l {
			node, ok := strings.CutPrefix(r.ID, masterKeyReportPrefix)
			if !ok {
				return out, nil // past the reports
			}
			if r.Until.After(now) {
				parts := strings.Split(r.Holder, "|")
				ids := strings.Split(parts[0], ",")
				k := NodeKeys{Active: ids[0], Previous: append([]string{}, ids[1:]...)}
				if len(parts) > 1 {
					k.QueueStale, _ = strconv.Atoi(parts[1])
				}
				if len(parts) > 2 {
					k.QueueLost, _ = strconv.Atoi(parts[2])
				}
				out[node] = k
			}
		}
		if len(l) < 100 {
			return out, nil
		}
		after = l[len(l)-1].ID
	}
}

// MasterKeyAgreed reports whether every live node seals with this service's active master key, and the nodes that do
// not (node id -> key id).
func (s *Service) MasterKeyAgreed(ctx context.Context) (bool, map[string]string, error) {
	nodes, err := s.MasterKeyNodes(ctx)
	if err != nil {
		return false, nil, err
	}
	others := map[string]string{}
	for node, k := range nodes {
		if k.Active != s.Sealer.ActiveKeyID() {
			others[node] = k.Active
		}
	}
	return len(others) == 0, others, nil
}

// MasterKeyStatus is where a master key rotation stands, as any node sees it (GET /api/master-key).
type MasterKeyStatus struct {
	Active   string   `json:"active_key"`    // the key this node seals with
	Previous []string `json:"previous_keys"` // this node's server.previous_master_keys
	// Nodes are the keys every live node reported, by node id; NodesAgree says they all seal with Active.
	Nodes      map[string]NodeKeys `json:"nodes"`
	NodesAgree bool                `json:"nodes_agree"`
	// Stale counts stored secrets sealed with a previous key (the housekeeping leader re-seals them); Unopenable
	// those no configured key opens.
	Stale      int `json:"stale_secrets"`
	Unopenable int `json:"unopenable_secrets"`
	// QueueStale counts the items of the nodes' queues on disk still sealed with a previous key (NodeKeys.QueueStale);
	// QueueLost those sealed with a key no longer configured, which only a warning in Detail mentions
	// (NodeKeys.QueueLost).
	QueueStale int `json:"queued_items_stale"`
	QueueLost  int `json:"queued_items_lost"`
	// Removable says the previous keys can be removed now: every node seals with the active key and nothing stored
	// needs another one. State is one of none (no previous keys), waiting_for_nodes, resealing, unopenable,
	// complete; Detail says what to do.
	Removable bool   `json:"previous_keys_removable"`
	State     string `json:"state"`
	Detail    string `json:"detail"`
}

// RotationStatus reports where a master key rotation stands. It reads every sealed value (without changing any).
func (s *Service) RotationStatus(ctx context.Context) (*MasterKeyStatus, error) {
	ids := s.Sealer.KeyIDs()
	st := &MasterKeyStatus{Active: ids[0], Previous: ids[1:]}
	nodes, err := s.MasterKeyNodes(ctx)
	if err != nil {
		return nil, err
	}
	st.Nodes, st.NodesAgree = nodes, true
	var others, queued, lost []string
	for node, k := range nodes {
		if k.Active != st.Active {
			st.NodesAgree = false
			others = append(others, node+" ("+k.Active+")")
		}
		if k.QueueStale > 0 {
			st.QueueStale += k.QueueStale
			queued = append(queued, node)
		}
		if k.QueueLost > 0 {
			st.QueueLost += k.QueueLost
			lost = append(lost, node)
		}
	}
	r, err := s.resealSecrets(ctx, 0, true)
	if err != nil {
		return nil, err
	}
	st.Stale, st.Unopenable = r.Pending, r.Failed
	switch {
	case !st.NodesAgree:
		st.State = "waiting_for_nodes"
		st.Detail = "Not every node seals with " + st.Active + " yet: " + strings.Join(others, ", ") +
			". Finish the step on every node; the re-seal starts once they all do."
	case st.Unopenable > 0:
		st.State = "unopenable"
		st.Detail = itoa(st.Unopenable) + " stored secrets open with no configured key: put the missing key back in " +
			"server.previous_master_keys."
	case st.Stale > 0:
		st.State = "resealing"
		st.Detail = itoa(st.Stale) + " stored secrets are still sealed with a previous key; the housekeeping leader " +
			"re-seals them within minutes."
	case st.QueueStale > 0:
		st.State = "resealing"
		st.Detail = itoa(st.QueueStale) + " queued messages on " + strings.Join(queued, ", ") + " are still sealed " +
			"with a previous key (their re-seal failed: see that node's log; it is tried again at its next report)."
	case len(st.Previous) == 0:
		st.State = "none"
		st.Detail = "No previous master keys are configured on this node: no rotation in progress."
	default:
		st.State, st.Removable = "complete", true
		st.Detail = "Every node seals with " + st.Active + " and every stored secret is sealed with it: remove " +
			"server.previous_master_keys on every node now (keep the old keys only with backups made before the rotation)."
	}
	for _, k := range nodes { // a node that still lists previous keys is not finished either
		if st.State == "none" && len(k.Previous) > 0 {
			st.State, st.Removable = "complete", true
			st.Detail = "This node has no previous keys, but some nodes still do: remove them there."
		}
	}
	if st.QueueLost > 0 { // a warning: they need no configured key, so they hold the rotation back in nothing
		sort.Strings(lost)
		st.Detail += " Warning: " + itoa(st.QueueLost) + " queued messages on " + strings.Join(lost, ", ") + " are " +
			"sealed with a master key that is not configured: put it back in server.previous_master_keys, or they " +
			"are given up once they are 8 days old."
	}
	return st, nil
}
