package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
)

// "quisora sign-out" while the server runs on its own BadgerDB store: the command asks the server (signed with the
// master key), which pulls the lever and records the command in the audit log; with the server stopped it writes to the
// store itself.
func TestSignOutThroughRunningServer(t *testing.T) {
	a, hc, base := startAppWith(t, "badgerdb", nil)
	ctx := context.Background()
	c, log := a.Cfg, logger.NewNullLogger()
	name := "acme"
	org, err := a.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: &name})
	if err != nil {
		t.Fatal(err)
	}

	ev, _, remote, err := SignOutVia(ctx, c, log, "", "", false, "acme", "suspected theft", true)
	if err != nil || !remote || ev.Reason != "suspected theft" || !ev.APITokens || ev.By != "command:sign-out" {
		t.Fatalf("sign-out of an organization: %+v remote %v %v", ev, remote, err)
	}
	o, err := a.Svc.Orgs.Get(ctx, org.ID)
	if err != nil || o.SignOut.Sessions != 1 || o.SignOut.APITokens != 1 || o.LastSignOut == nil {
		t.Fatalf("the organization's counters: %+v %v", o, err)
	}
	requireCommandActor(t, a, "org.signout", "sign-out")

	if ev, _, remote, err = SignOutVia(ctx, c, log, "", "", false, "", "everyone out", false); err != nil || !remote {
		t.Fatalf("sign-out of every organization: %+v %v", ev, err)
	}
	p, err := a.Svc.PrimaryOrg(ctx)
	if err != nil || p.ServerSignOut.Sessions != 1 || p.LastServerSignOut == nil || p.LastServerSignOut.Reason != "everyone out" {
		t.Fatalf("the server's counters: %+v %v", p, err)
	}
	requireCommandActor(t, a, "server.signout", "sign-out")

	if _, _, _, err := SignOutVia(ctx, c, log, "", "", false, "nope", "x", false); err == nil ||
		!strings.Contains(err.Error(), "no organization") {
		t.Fatalf("unknown organization: %v", err)
	}

	post := func(cs commandSignOut) int {
		b, _ := json.Marshal(cs)
		resp, err := hc.Post(base+commandSignOutPath, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	key, _ := base64.StdEncoding.DecodeString(c.Server.MasterKey)
	mine, _ := newSealer(c, key)
	other, _ := secure.NewSealer(secure.RandomBytes(32))
	req := func(s *secure.Sealer, at time.Time) commandSignOut {
		cs := commandSignOut{Org: "acme", Reason: "r", commandSig: commandSig{At: at.Unix(), Nonce: secure.RandomToken(18)}}
		signCommand(&cs, s)
		return cs
	}
	if got := post(req(other, time.Now())); got != http.StatusUnauthorized {
		t.Errorf("another master key: %d", got)
	}
	if got := post(req(mine, time.Now().Add(-10*time.Minute))); got != http.StatusUnauthorized {
		t.Errorf("stale request: %d", got)
	}
	tampered := req(mine, time.Now())
	tampered.Org, tampered.All = "", true // the organization's sign-out turned into the server's
	if got := post(tampered); got != http.StatusUnauthorized {
		t.Errorf("tampered request: %d", got)
	}
	both := commandSignOut{Org: "acme", All: true, Reason: "r", commandSig: newCommandSig()}
	signCommand(&both, mine)
	if got := post(both); got != http.StatusBadRequest {
		t.Errorf("an organization and every organization: %d", got)
	}
	good := req(mine, time.Now())
	if got := post(good); got != http.StatusOK {
		t.Fatalf("signed request: %d", got)
	}
	if got := post(good); got != http.StatusUnauthorized {
		t.Errorf("replayed request: %d", got)
	}

	// with the server stopped, the command uses the store itself (not a gossip node)
	a.Close()
	if _, _, remote, err := SignOutVia(ctx, c, log, "", "", false, "acme", "server down", false); err != nil || remote {
		t.Fatalf("server stopped: remote %v %v", remote, err)
	}
	// --server names a server: no falling back to the store when it does not answer
	if _, _, _, err := SignOutVia(ctx, c, log, base, "", false, "acme", "x", false); err == nil {
		t.Fatal("--server that does not answer fell back to the store")
	}
}
