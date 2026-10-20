package app

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
)

// "quisora sign-out" signs the server out with the master key while the server is down (a running server holds a
// node-local store: a clear error), and a server started afterwards refuses the sessions it ended.
func TestSignOutCommand(t *testing.T) {
	c := config.Default()
	c.Server.DataDir = t.TempDir()
	c.Server.MasterKey = base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	c.Server.PublicURL = "https://quisora.example.test"
	c.Storage.Backend = "badgerdb"
	c.Limits.PasswordWorkers = 2
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	log := logger.NewNullLogger()
	if _, _, err := Bootstrap(ctx, c, log); err != nil {
		t.Fatal(err)
	}
	a, err := Start(ctx, withListen(t, c), log)
	if err != nil {
		t.Fatal(err)
	}
	primary, _ := a.Svc.PrimaryOrg(ctx)
	admin, _ := a.Svc.FindUserByEmail(ctx, primary.ID, "admin@example.com")
	stamp, _ := a.Svc.SessionStamp(ctx, primary.ID)
	sess := &model.Session{UserID: admin.ID, OrgID: primary.ID, Expires: time.Now().Add(time.Hour), LastSeen: time.Now(), Stamp: stamp}
	if err := a.Svc.Sessions.Create(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SignOut(ctx, c, log, "", "breach", false); !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("a locked store: %v", err)
	}
	a.Close()

	if _, _, err := SignOut(ctx, c, log, "nope", "breach", false); err == nil || !strings.Contains(err.Error(), "no organization") {
		t.Fatalf("unknown organization: %v", err)
	}
	ev, n, err := SignOut(ctx, c, log, "", "breach", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ev.By, "cli:") || ev.Reason != "breach" || n.Sessions != 1 {
		t.Errorf("event %+v, sweep %+v", ev, n)
	}

	a, err = Start(ctx, withListen(t, c), log)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if s, u := a.Server.Sessions.Lookup(ctx, sess.ID); s != nil || u != nil {
		t.Error("the signed-out session still works")
	}
	if p, _ := a.Svc.PrimaryOrg(ctx); p.LastServerSignOut == nil || p.LastServerSignOut.Reason != "breach" {
		t.Errorf("last server sign-out: %+v", p.LastServerSignOut)
	}
}
