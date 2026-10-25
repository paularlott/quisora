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

// The tidying after a change of the session epoch removes the sessions of the epoch that change replaced and no
// other: run late (after the user signed in again under the new epoch), it leaves the new session alone.
func TestEndSessionsOfOnlyTheReplacedEpoch(t *testing.T) {
	ctx := context.Background()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	st := memstore.New()
	defer st.Close()
	s := New(config.Default(), st, sealer)
	u := &model.User{OrgID: "org", Username: "s", Email: "s@example.com", Role: model.RoleUser, Active: true, SessionEpoch: 1}
	if err := s.Users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	mk := func(epoch uint64) *model.Session {
		sess := &model.Session{UserID: u.ID, OrgID: "org", Epoch: epoch, Expires: time.Now().Add(time.Hour)}
		if err := s.Sessions.Create(ctx, sess); err != nil {
			t.Fatal(err)
		}
		return sess
	}
	old, later := mk(1), mk(2) // signed in before the reset, and after it (the account's epoch is now 2)
	if err := s.endSessionsOf(ctx, u.ID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sessions.Get(ctx, old.ID); err == nil {
		t.Fatal("the replaced epoch's session stays")
	}
	if _, err := s.Sessions.Get(ctx, later.ID); err != nil {
		t.Fatal("the late tidying ended a session of the new epoch")
	}
}
