package service_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// resealStore counts the records read (the rows its listings return, and its reads by id), and slows each write of a user by writeDelay, as a store that is slower than memory is.
type resealStore struct {
	store.Store
	writeDelay time.Duration
	mu         sync.Mutex
	reads      int // records read, of any kind: the rows of listings and each read by id
	users      int // the rows of listings of users among them
}

func (s *resealStore) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	res, err := s.Store.List(ctx, kind, q)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.reads += len(res.Records)
		if kind == model.KindUser {
			s.users += len(res.Records)
		}
	}
	return res, err
}

func (s *resealStore) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	s.mu.Lock()
	s.reads++
	s.mu.Unlock()
	return s.Store.Get(ctx, kind, id)
}

func (s *resealStore) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if r.Kind == model.KindUser {
		time.Sleep(s.writeDelay)
	}
	return s.Store.CompareAndPut(ctx, r, expect)
}

func (s *resealStore) counts() (reads, users int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads, s.users
}

// resealEnv is a service over a resealStore holding n users whose authenticator secrets are sealed with the previous
// key of the ring the service has now; it returns the old and the new key.
func resealEnv(t *testing.T, n int, writeDelay time.Duration) (e *env, st *resealStore, oldKey, newKey []byte) {
	t.Helper()
	st = &resealStore{Store: memstore.New(), writeDelay: writeDelay}
	t.Cleanup(func() { _ = st.Close() })
	e = newEnvOn(t, st)
	oldKey, newKey = secure.RandomBytes(32), secure.RandomBytes(32)
	old, _ := secure.NewSealer(oldKey)
	e.svc.Sealer.Replace(old)
	for i := range n {
		u := &model.User{OrgID: e.primary.ID, Username: fmt.Sprintf("u%04d", i), Email: fmt.Sprintf("u%04d@example.com", i),
			Active: true, Role: model.RoleUser}
		u.ID = model.NewID()
		u.TOTPSecret = old.SealFor(service.TOTPBinding(u.ID), []byte("totp"))
		if err := e.svc.Users.Create(e.ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	ring, err := secure.NewKeyring(newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.Sealer.Replace(ring)
	return e, st, oldKey, newKey
}

// staleUsers counts the users whose authenticator secret is sealed with a previous key.
func staleUsers(t *testing.T, e *env) (n int) {
	t.Helper()
	us, err := e.svc.Users.All(e.ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range us {
		if e.svc.Sealer.Stale(u.TOTPSecret) {
			n++
		}
	}
	return n
}

// A pass stops once its time is up and the next one goes on where it stopped: no pass reads the records an earlier
// pass finished (the first pass of the old walk read every record of every table, however few it re-sealed, and so did
// every later one), and the passes together end the rotation.
func TestResealPassesResume(t *testing.T) {
	const users = 2000
	e, st, _, _ := resealEnv(t, users, time.Millisecond)

	passes, resealed := 0, 0
	for passes < 500 {
		_, usersBefore := st.counts()
		r, err := e.svc.ResealSecrets(e.ctx, 300*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		passes++
		resealed += r.Resealed
		_, usersAfter := st.counts()
		if r.Resealed == 0 && !r.Done() {
			t.Fatalf("pass %d made no progress: %+v", passes, r)
		}
		if passes == 1 && (r.Resealed == 0 || r.Resealed >= users || r.Done()) {
			t.Fatalf("the first pass did not stop at its time: %+v", r)
		}
		// what it read: the users it re-sealed, and the page it was in the middle of (at most two), never the
		// records an earlier pass was through
		if read := usersAfter - usersBefore; read > r.Resealed+1000 {
			t.Fatalf("pass %d re-sealed %d users and read %d: it did not go on from where the last one stopped", passes, r.Resealed, read)
		}
		if r.Done() {
			break
		}
	}
	if passes < 2 || resealed < users {
		t.Fatalf("%d passes re-sealed %d of %d users", passes, resealed, users)
	}
	if n := staleUsers(t, e); n != 0 {
		t.Fatalf("%d users are still sealed with the previous key", n)
	}
}

// The status is read from the leader's report: however often it is asked it reads no user, grant, identity or other
// stored secret; the report is read from the leader's pass, by any node.
func TestResealStatusReadsNoStoredSecrets(t *testing.T) {
	e, st, _, _ := resealEnv(t, 50, 0)
	if err := e.svc.ReportMasterKey(e.ctx, "n1"); err != nil {
		t.Fatal(err)
	}
	before, _ := st.counts()
	for range 20 {
		if _, err := e.svc.RotationStatus(e.ctx); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := st.counts()
	// per status: the nodes' reports (one) and the leader's report (one), not the 50 users and the rest
	if after-before > 20*2 {
		t.Fatalf("20 status reads read %d records", after-before)
	}
	if _, users := st.counts(); users != 0 {
		t.Fatalf("the status read %d users", users)
	}
	// another node's status shows what the leader reported
	if r, err := e.svc.ResealSecrets(e.ctx, time.Minute); err != nil || !r.Done() || r.Resealed != 50 {
		t.Fatalf("the pass: %+v %v", r, err)
	}
	other := service.New(e.svc.Cfg, e.svc.Store, e.svc.Sealer)
	if s, err := other.RotationStatus(e.ctx); err != nil || s.State != "complete" || s.Resealed != 50 || s.Checked == nil {
		t.Fatalf("another node's status: %+v %v", s, err)
	}
	// a leader that began since (it knows nothing of that walk) voids it when a node seals with another key
	if err := other.ResealRestart(e.ctx); err != nil {
		t.Fatal(err)
	}
	if s, err := e.svc.RotationStatus(e.ctx); err != nil || s.Checked != nil {
		t.Fatalf("the status after the new leader voided the walk: %+v %v", s, err)
	}
}

// Once a walk has found nothing left, no pass reads anything until the keys change (or the leader restarts it
// because a node sealed with another key): the old design walked every record again at every pass, every ten
// minutes, for as long as previous keys stayed configured.
func TestResealStopsWhenDone(t *testing.T) {
	e, st, _, newKey := resealEnv(t, 40, 0)
	if r, err := e.svc.ResealSecrets(e.ctx, time.Minute); err != nil || !r.Done() || r.Resealed != 40 {
		t.Fatalf("the pass: %+v %v", r, err)
	}
	before, _ := st.counts()
	for range 5 {
		if r, err := e.svc.ResealSecrets(e.ctx, time.Minute); err != nil || !r.Done() || r.Resealed != 0 {
			t.Fatalf("a pass after it was done: %+v %v", r, err)
		}
	}
	if after, _ := st.counts(); after != before {
		t.Fatalf("passes after the end read %d records", after-before)
	}

	// a node sealing with another key meanwhile: the leader says its walk is void, and the next pass makes a new one
	if err := e.svc.ResealRestart(e.ctx); err != nil {
		t.Fatal(err)
	}
	if s, _ := e.svc.RotationStatus(e.ctx); s.Checked != nil {
		t.Fatalf("the status still says the walk made before: %+v", s)
	}
	if r, err := e.svc.ResealSecrets(e.ctx, time.Minute); err != nil || !r.Done() || r.Resealed != 0 {
		t.Fatalf("the walk after the restart: %+v %v", r, err)
	}
	if after, _ := st.counts(); after == before {
		t.Fatal("the pass after a restart read nothing")
	}

	// the keys change: what was found says nothing of the new key, in the status or in the passes
	ring, err := secure.NewKeyring(secure.RandomBytes(32), newKey)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.Sealer.Replace(ring)
	if s, _ := e.svc.RotationStatus(e.ctx); s.Checked != nil || s.Resealed != 0 {
		t.Fatalf("the status after the keys changed: %+v", s)
	}
	before, _ = st.counts()
	if r, err := e.svc.ResealSecrets(e.ctx, time.Minute); err != nil || !r.Done() || r.Resealed != 40 {
		t.Fatalf("the pass with the next key: %+v %v", r, err)
	}
	if after, _ := st.counts(); after == before {
		t.Fatal("the pass with the next key read nothing")
	}
}
