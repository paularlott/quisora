package cluster

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

func voterNode(t *testing.T) *Node {
	t.Helper()
	n, err := New(tempConfig(t), memstore.New(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	if !n.votes() {
		t.Fatal("test set-up: the node does not vote anyway")
	}
	return n
}

func mustEncode(t *testing.T, u *model.User) *store.Record {
	t.Helper()
	r, err := store.Encode(u)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A voter grants no version further ahead of its clock than voteAhead: a restart then needs nothing on disk.
func TestVoterRefusesVersionsFarAhead(t *testing.T) {
	v := newVoter(voterNode(t))
	rec := mustEncode(t, newUser("org1", "ahead"))
	rec.Version = hlc.FromTime(time.Now().Add(voteAhead + time.Second))
	if r := v.prepare(bg, "op", rec, modeMatch, store.Rank{}); r.St == stGrant {
		t.Fatal("granted a version further ahead than voteAhead")
	}
	rec.Version = store.Clock.Now()
	if r := v.prepare(bg, "op2", rec, modeMatch, store.Rank{}); r.St != stGrant {
		t.Fatalf("a current version: %d", r.St)
	}
}

// A voter that has just started takes part in no quorum write until restartPause has passed.
func TestVoterPausesAfterStart(t *testing.T) {
	defer func(d time.Duration) { restartPause = d }(restartPause)
	restartPause = 300 * time.Millisecond
	v := newVoter(voterNode(t))
	rec := mustEncode(t, newUser("org1", "paused"))
	if r := v.prepare(bg, "op", rec, modeMatch, store.Rank{}); r.St != stNotReady {
		t.Fatalf("just started: %d, want not ready", r.St)
	}
	time.Sleep(restartPause)
	rec.Version = store.Clock.Now()
	if r := v.prepare(bg, "op", rec, modeMatch, store.Rank{}); r.St != stGrant {
		t.Fatalf("after the pause: %d", r.St)
	}
}

// A deletion's mark lasts from its grant until it is applied here: the normal case leaves nothing behind. One whose
// commit never came is saved past intentTTL, read back after a restart, and forgotten once the deletion arrives.
func TestVoterDeletionMarks(t *testing.T) {
	n := voterNode(t)
	v := newVoter(n)
	u := newUser("org1", "marked")
	live := mustEncode(t, u)
	if _, _, err := n.st.inner.PutReplicated(bg, live); err != nil {
		t.Fatal(err)
	}
	k := recKey(model.KindUser, u.ID)
	del := store.Tombstone(model.KindUser, u.ID)
	if r := v.prepare(bg, "del1", del, modeBlind, store.Rank{}); r.St != stGrant {
		t.Fatalf("deletion prepare: %d", r.St)
	}
	if _, ok := v.deletions[k]; !ok {
		t.Fatal("no mark while the deletion is granted and not applied")
	}
	if st := v.commit(bg, "del1", del, false); st != stGrant {
		t.Fatalf("commit: %d", st)
	}
	if _, ok := v.deletions[k]; ok {
		t.Fatal("the mark outlived its commit")
	}

	// A deletion whose commit never comes.
	u2 := newUser("org1", "partial")
	if _, _, err := n.st.inner.PutReplicated(bg, mustEncode(t, u2)); err != nil {
		t.Fatal(err)
	}
	k2 := recKey(model.KindUser, u2.ID)
	del2 := store.Tombstone(model.KindUser, u2.ID)
	if r := v.prepare(bg, "del2", del2, modeBlind, store.Rank{}); r.St != stGrant {
		t.Fatalf("second deletion prepare: %d", r.St)
	}
	v.mu.Lock()
	v.pruneDeletions(time.Now().Add(intentTTL + time.Second))
	v.mu.Unlock()
	if !v.deletions[k2].saved {
		t.Fatal("an unapplied deletion was not saved past intentTTL")
	}
	again := newVoter(n) // restarted
	if again.broken != "" || again.deletions[k2].v != del2.Version {
		t.Fatalf("after a restart: %q %+v", again.broken, again.deletions)
	}
	// A live write onto that record must take the deletion's generation.
	upd := mustEncode(t, u2)
	upd.Version = store.Clock.Now()
	again.resumeAt = time.Time{}
	if r := again.prepare(bg, "upd", upd, modeBlind, store.Rank{}); r.St != stLow || r.Epoch != uint64(del2.Version) {
		t.Fatalf("live write over a saved partial deletion: %+v", r)
	}
	// The deletion reaches this node: the mark goes, from the file too.
	if _, _, err := n.st.inner.PutReplicated(bg, del2); err != nil {
		t.Fatal(err)
	}
	again.mu.Lock()
	again.pruneDeletions(time.Now())
	again.mu.Unlock()
	if len(again.deletions) != 0 {
		t.Fatalf("marks after the deletion arrived: %+v", again.deletions)
	}
	if b, _ := os.ReadFile(filepath.Join(n.dir, voterFile)); len(b) > 0 && string(b) != `{}` {
		t.Fatalf("file still holds marks: %s", b)
	}
}

// A voter whose saved marks cannot be read takes no part in quorum writes.
func TestVoterUnreadableStateDoesNotVote(t *testing.T) {
	n := voterNode(t)
	os.WriteFile(filepath.Join(n.dir, voterFile), []byte("{nope"), 0o600)
	v := newVoter(n)
	if v.broken == "" {
		t.Fatal("corrupt file accepted")
	}
	if r := v.prepare(bg, "op", mustEncode(t, newUser("org1", "x")), modeMatch, store.Rank{}); r.St != stNotReady {
		t.Fatalf("broken voter answered %d, want not ready", r.St)
	}
}
