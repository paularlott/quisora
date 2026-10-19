package web

import (
	"context"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// A session's last-use stamp is a write made while serving a read. A node that may not change replicated data now
// (catching up, cut off from the majority, out of date) skips it: the session record is not touched at all, so a
// stale copy of a session deleted elsewhere is never written (and could never be sent back). A writable node stamps it.
func TestSessionTouchSkippedWhenNotWritable(t *testing.T) {
	ctx := context.Background()
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svc := service.New(config.Default(), memstore.New(), sealer)
	writable := false
	svc.Writable = func() bool { return writable }
	u := &model.User{OrgID: "org1", Username: "touch", Email: "touch@example.com", Role: model.RoleUser, Active: true}
	if err := svc.Users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute).UTC()
	s := &model.Session{Meta: model.Meta{ID: "sess-touch"}, UserID: u.ID, OrgID: u.OrgID, AuthTime: old, LastSeen: old,
		Expires: time.Now().Add(time.Hour)}
	if err := svc.Sessions.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	m := NewSessions(svc)
	if got, _ := m.Lookup(ctx, s.ID); got == nil {
		t.Fatal("session not found")
	}
	if cur, _ := svc.Sessions.Get(ctx, s.ID); cur.Version != s.Version || !cur.LastSeen.Equal(old) {
		t.Fatal("a node that may not write touched the session")
	}
	writable = true
	if got, _ := m.Lookup(ctx, s.ID); got == nil {
		t.Fatal("session not found")
	}
	if cur, _ := svc.Sessions.Get(ctx, s.ID); cur.Version == s.Version || !cur.LastSeen.After(old) {
		t.Fatal("a writable node did not record the session's use")
	}
}
