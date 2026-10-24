package cluster

// The quorum voter's state that must survive a restart (see the voter in cas.go). Only one thing does: a deletion the
// voter granted but never applied, because its commit did not reach this node (the writer failed mid-commit, or the
// commit failed here). That deletion may be in effect on the nodes that did apply it, and a later live write of the
// record must outrank it (prepare's epoch rule), also after this voter restarts. Such marks are rare, so they are
// written as one small file (voterFile), replaced whole when a mark is added or forgotten. Everything else a voter
// knows lives in memory: a restarted voter is kept safe by the clocks instead (voteAhead, restartPause).

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/paularlott/gossip/hlc"
)

const voterFile = "quorum-voter.json"

// voterState is what voterFile holds.
type voterState struct {
	Deletions map[string]deletedRec `json:"deletions,omitempty"`
}

type deletedRec struct {
	Version uint64 `json:"v"`
	At      int64  `json:"at"` // unix nanoseconds
}

// loadVoterState reads the deletion marks in dir (those older than keep are left out). A file that cannot be read is
// an error: the voter must not grant without what it promised.
func loadVoterState(dir string, keep time.Duration) (map[string]delMark, error) {
	out := map[string]delMark{}
	path := filepath.Join(dir, voterFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var vs voterState
	if err := json.Unmarshal(b, &vs); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cutoff := time.Now().Add(-keep)
	for k, d := range vs.Deletions {
		if at := time.Unix(0, d.At); at.After(cutoff) {
			out[k] = delMark{v: hlc.Timestamp(d.Version), at: at, saved: true}
		}
	}
	return out, nil
}

// saveVoterState replaces the file in dir with the marks that are saved.
func saveVoterState(dir string, marks map[string]delMark) error {
	vs := voterState{Deletions: map[string]deletedRec{}}
	for k, m := range marks {
		if m.saved {
			vs.Deletions[k] = deletedRec{Version: uint64(m.v), At: m.at.UnixNano()}
		}
	}
	b, err := json.Marshal(vs)
	if err != nil {
		return err
	}
	return writeSynced(filepath.Join(dir, voterFile), b)
}

// writeSynced replaces path with b durably: a synced temporary file renamed over it, then the directory synced.
func writeSynced(path string, b []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

// syncDir syncs directory dir, making the names created or renamed in it durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
