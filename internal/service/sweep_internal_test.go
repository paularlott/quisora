package service

import (
	"context"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// The sweep removes what a failed removal left behind (a deleted user's passkey and sign-in record, a membership a
// stalled group writer made after the user went, a lock whose holder died long ago), and leaves what still has its
// owner, or is too new to tell.
func TestSweepOrphans(t *testing.T) {
	ctx := context.Background()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	st := memstore.New()
	defer st.Close()
	s := New(config.Default(), st, sealer)
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
	saved := sweepMinAge
	sweepMinAge = -time.Hour
	defer func() { sweepMinAge = saved }()
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
func TestSweepPassedEpoch(t *testing.T) {
	ctx := context.Background()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	st := memstore.New()
	defer st.Close()
	s := New(config.Default(), st, sealer)
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
	saved := sweepMinAge
	sweepMinAge = -time.Hour
	defer func() { sweepMinAge = saved }()
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
