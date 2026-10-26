package service

import (
	"context"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// The sweep removes what a failed removal left behind (a deleted user's passkey and sign-in record, a membership a
// stalled group writer made after the user went, a lock whose holder died long ago), and leaves what still has its
// owner, or is too new to tell.
func TestSweepRemovesOrphans(t *testing.T) {
	ctx := context.Background()
	s := newInternalService(t, memstore.New())
	org := &model.Org{Name: "acme"}
	if err := s.Orgs.Create(ctx, org); err != nil {
		t.Fatal(err)
	}
	mk := func(name string) *model.User {
		u := &model.User{OrgID: org.ID, Username: name, Email: name + "@example.com", Role: model.RoleUser, Active: true}
		if err := s.Users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	kept, gone := mk("kept"), mk("gone")
	g := &model.Group{OrgID: org.ID, DisplayName: "staff"}
	_ = s.Groups.Create(ctx, g)
	var pks []*model.Passkey
	for _, u := range []*model.User{kept, gone} {
		pk := &model.Passkey{UserID: u.ID, OrgID: org.ID, Name: "key", CredentialID: []byte(u.ID)}
		if err := s.Passkeys.Create(ctx, pk); err != nil {
			t.Fatal(err)
		}
		pks = append(pks, pk)
		_ = s.SignIns.Create(ctx, &model.SignIn{Meta: model.Meta{ID: u.ID}, OrgID: org.ID})
		_ = s.Members.Create(ctx, &model.Member{Meta: model.Meta{ID: model.MemberID(g.ID, u.ID)}, GroupID: g.ID, UserID: u.ID, OrgID: org.ID, Seq: 1})
	}
	_ = s.Locks.Create(ctx, &model.Lock{Meta: model.Meta{ID: "admins/" + org.ID}, Holder: "dead", Until: time.Now().Add(-48 * time.Hour)})
	if err := s.Users.Delete(ctx, gone.ID); err != nil { // the user alone: their records stay behind
		t.Fatal(err)
	}

	sweepAll := func() int {
		var sw Sweep
		n := 0
		for range 3 * len(sweepKinds) {
			m, err := s.SweepOrphans(ctx, &sw, 2)
			if err != nil {
				t.Fatal(err)
			}
			n += m
		}
		return n
	}
	if n := sweepAll(); n != 1 { // the lock (judged by its lease); the rest are too new to tell
		t.Fatalf("removed %d, want only the lock", n)
	}
	withSweepAge(t)
	if n := sweepAll(); n != 3 { // passkey, sign-in record, membership
		t.Fatalf("removed %d, want 3", n)
	}
	if _, err := s.Passkeys.Get(ctx, pks[0].ID); err != nil {
		t.Fatal("removed the passkey of a user who exists")
	}
	if _, err := s.Passkeys.Get(ctx, pks[1].ID); err == nil {
		t.Fatal("kept the passkey of a deleted user")
	}
	if m, err := s.Members.Get(ctx, model.MemberID(g.ID, gone.ID)); err != nil || m.Active() {
		t.Fatalf("membership of a deleted user: %+v %v", m, err)
	}
	if m, err := s.Members.Get(ctx, model.MemberID(g.ID, kept.ID)); err != nil || !m.Active() {
		t.Fatalf("membership of a user who exists: %+v %v", m, err)
	}
	if _, err := s.Locks.Get(ctx, "admins/"+org.ID); err == nil {
		t.Fatal("kept a lock long past its lease")
	}
	if n := sweepAll(); n != 0 {
		t.Fatalf("a second pass removed %d", n)
	}
}

// The sweep removes the credentials of an epoch the account has moved past (a passkey stored by an invitation
// acceptance that lost, those from before a reset), once old enough, and keeps those of the current epoch.
func TestSweepRemovesCredentialsOfAPassedEpoch(t *testing.T) {
	ctx := context.Background()
	s := newInternalService(t, memstore.New())
	org := &model.Org{Name: "epochs"}
	if err := s.Orgs.Create(ctx, org); err != nil {
		t.Fatal(err)
	}
	u := &model.User{OrgID: org.ID, Username: "e", Email: "e@example.com", Role: model.RoleUser, Active: true, CredEpoch: 7}
	if err := s.Users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	cur := &model.Passkey{UserID: u.ID, OrgID: org.ID, Name: "current", CredentialID: []byte("a"), Epoch: 7}
	lost := &model.Passkey{UserID: u.ID, OrgID: org.ID, Name: "lost", CredentialID: []byte("b"), Epoch: 8}
	for _, pk := range []*model.Passkey{cur, lost} {
		if err := s.Passkeys.Create(ctx, pk); err != nil {
			t.Fatal(err)
		}
	}
	withSweepAge(t)
	var sw Sweep
	for range 2 * len(sweepKinds) {
		if _, err := s.SweepOrphans(ctx, &sw, 100); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Passkeys.Get(ctx, cur.ID); err != nil {
		t.Fatal("removed the passkey of the current epoch")
	}
	if _, err := s.Passkeys.Get(ctx, lost.ID); err == nil {
		t.Fatal("kept a passkey of another epoch")
	}
}

// remoteOwners is a store that does not hold some records its owners do: Fresh reads them from remote, FreshIn only
// those in the partition it is told (an owner of another partition does not have them), as a gossip cluster's
// owners answer.
type remoteOwners struct {
	store.Store
	remote store.Store
	asked  []string // "kind/partition" of every FreshIn
}

func (r *remoteOwners) Fresh(ctx context.Context, kind model.Kind, ids []string) (map[string]*store.Record, error) {
	recs, err := store.GetMany(ctx, r.remote, kind, ids)
	out := map[string]*store.Record{}
	for _, rec := range recs {
		out[rec.ID] = rec
	}
	return out, err
}

func (r *remoteOwners) FreshIn(ctx context.Context, kind model.Kind, part string, ids []string) (map[string]*store.Record, error) {
	r.asked = append(r.asked, string(kind)+"/"+part)
	all, err := r.Fresh(ctx, kind, ids)
	for id, rec := range all {
		if rec.Partition != part {
			delete(all, id)
		}
	}
	return all, err
}

func TestPartOfHintsPartitionZeroForSelfRegisteredClients(t *testing.T) {
	grant := &model.Grant{OrgID: "acme", UserID: "u", ClientID: "c"}
	for id, want := range map[string]string{
		"dyn-AbC123":                           "",
		"https://app.example/client.json":      "",
		"4f3c9a52-0000-7000-8000-000000000000": "acme",
	} {
		if got := (ownerRef{model.KindClient, id}).partOf(grant); got != want {
			t.Errorf("owner client %q: hint %q, want %q", id, got, want)
		}
	}
	if got := (ownerRef{model.KindUser, "u"}).partOf(grant); got != "acme" {
		t.Errorf("owner user: %q", got)
	}
	if got := (ownerRef{model.KindOrg, "acme"}).partOf(grant); got != "" {
		t.Errorf("owner org: %q", got)
	}
}

// A grant of a self-registered application is not removed because the owner of its organization's partition does not
// have the application (it is in partition 0, on another node's copy this one has not received yet): it is not asked
// for it in the grant's partition.
func TestSweepAsksPartitionZeroForSelfRegisteredClients(t *testing.T) {
	ctx := context.Background()
	local := &remoteOwners{Store: memstore.New(), remote: memstore.New()}
	s := newInternalService(t, local)
	org := &model.Org{Name: "acme"}
	if err := s.Orgs.Create(ctx, org); err != nil {
		t.Fatal(err)
	}
	u := &model.User{OrgID: org.ID, Username: "owner", Email: "owner@example.test"}
	if err := s.Users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	app := &model.Client{Meta: model.Meta{ID: "dyn-abc"}, Name: "app", SelfRegistered: true}
	if err := store.NewTable[model.Client](local.remote).Create(ctx, app); err != nil {
		t.Fatal(err)
	}
	g := &model.Grant{UserID: u.ID, OrgID: org.ID, ClientID: app.ID, Expires: time.Now().Add(time.Hour)}
	if err := s.Grants.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	withSweepAge(t)
	n, err := s.SweepOrphans(ctx, sweepStartingAt(model.KindGrant), 100)
	if err != nil || n != 0 {
		t.Fatalf("removed=%d err=%v", n, err)
	}
	if _, err := s.Grants.Get(ctx, g.ID); err != nil {
		t.Fatalf("the grant of a self-registered application was removed: %v", err)
	}
	for _, a := range local.asked {
		if a == string(model.KindClient)+"/"+org.ID {
			t.Fatalf("the application's owner was asked in its grant's partition: %v", local.asked)
		}
	}
}

// quorumReadCounter counts the quorum reads (store.QuorumReader) made through it, answering from the store.
type quorumReadCounter struct {
	store.Store
	calls int
}

func (p *quorumReadCounter) Fresh(ctx context.Context, kind model.Kind, ids []string) (map[string]*store.Record, error) {
	p.calls++
	out := map[string]*store.Record{}
	for _, id := range ids {
		r, err := p.Store.Get(ctx, kind, id)
		if err != nil {
			return nil, err
		}
		out[id] = r
	}
	return out, nil
}

// The sweep reads the owners of a batch of sessions once, from this node; a quorum read only confirms a removal, and
// the owners to confirm are confirmed together, not one session at a time. It keeps a private view of the sweep's
// steps (it starts at the sessions), so it lives with the sweep's internals.
func TestSweepReadsOwnersOncePerBatch(t *testing.T) {
	// setup is an owner at the given session epoch with 100 sessions of epoch 7.
	setup := func(t *testing.T, ownerSessionEpoch, ownerCredEpoch uint64) (*Service, *quorumReadCounter) {
		ctx := context.Background()
		st := &quorumReadCounter{Store: memstore.New()}
		s := newInternalService(t, st)
		org := &model.Org{Name: "sweep"}
		if err := s.Orgs.Create(ctx, org); err != nil {
			t.Fatal(err)
		}
		u := &model.User{OrgID: org.ID, Username: "owner", Email: "owner@example.test", CredEpoch: ownerCredEpoch, SessionEpoch: ownerSessionEpoch}
		if err := s.Users.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		for range 100 {
			sess := &model.Session{UserID: u.ID, OrgID: org.ID, Epoch: 7, Expires: time.Now().Add(time.Hour)}
			if err := s.Sessions.Create(ctx, sess); err != nil {
				t.Fatal(err)
			}
		}
		withSweepAge(t)
		return s, st
	}

	t.Run("current_sessions_need_no_quorum_read", func(t *testing.T) {
		s, st := setup(t, 7, 7)
		n, err := s.SweepOrphans(context.Background(), sweepStartingAt(model.KindSession), 20000)
		if err != nil || n != 0 {
			t.Fatalf("removed=%d err=%v", n, err)
		}
		if st.calls != 0 {
			t.Fatalf("%d quorum reads for a batch of current sessions", st.calls)
		}
	})

	t.Run("obsolete_sessions_confirm_the_owner_once", func(t *testing.T) {
		s, st := setup(t, 8, 0)
		n, err := s.SweepOrphans(context.Background(), sweepStartingAt(model.KindSession), 20000)
		if err != nil || n != 100 {
			t.Fatalf("removed=%d err=%v", n, err)
		}
		if st.calls != 1 {
			t.Fatalf("%d quorum reads to confirm one owner, want 1", st.calls)
		}
	})
}
