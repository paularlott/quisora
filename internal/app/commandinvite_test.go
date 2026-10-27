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
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// "quisora invite" while the server runs on its own BadgerDB store: the command asks the server (signed with the
// master key), and --break-glass recovers a super admin who was locked out.
func TestInviteThroughRunningServer(t *testing.T) {
	a, hc, base := startAppWith(t, "badgerdb", nil)
	ctx := context.Background()
	c, log := a.Cfg, logger.NewNullLogger()
	org, err := a.Svc.OrgByName(ctx, "primary")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := a.Svc.FindUserByEmail(ctx, org.ID, "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	// The only super admin cannot be locked out from the console; an end date that has passed disables them all
	// the same.
	ended := time.Now().Add(-time.Hour)
	admin.ValidUntil = &ended
	if err := a.Svc.Users.Update(ctx, admin); err != nil {
		t.Fatal(err)
	}
	a.OIDC.InvalidateUser(admin.ID)

	// an ordinary invitation is refused for the disabled account, by the running server
	if _, _, how, err := Invite(ctx, c, log, "", "", false, "primary", "admin@example.com", false, false); err == nil ||
		!strings.Contains(err.Error(), "disabled") {
		t.Fatalf("ordinary invitation for a disabled account: %v (%s)", err, how)
	}
	// break-glass works, through the server (its self-signed certificate trusted from the data directory)
	link, expires, how, err := Invite(ctx, c, log, "", "", false, "primary", "admin@example.com", true, false)
	if err != nil || how != "the running server" || !strings.HasPrefix(link, base+"/o/"+org.ID+"/invite?token=") ||
		time.Until(expires) > service.BreakGlassTTL {
		t.Fatalf("break-glass: %q %v %s %v", link, expires, how, err)
	}
	requireCommandActor(t, a, "user.invite.break_glass", "invite")
	tok := link[strings.Index(link, "token=")+6:]
	if _, _, err := a.Svc.PeekLink(ctx, tok, service.LinkInvite); err != nil {
		t.Fatalf("break-glass link does not open for the disabled account: %v", err)
	}
	if _, u, err := a.Svc.UseSignInLink(ctx, tok, service.LinkInvite, "", service.NewCredEpoch()); err != nil || !u.Enabled(time.Now()) {
		t.Fatalf("redeeming did not enable the account: %v", err)
	}

	post := func(ci commandInvite) int {
		b, _ := json.Marshal(ci)
		resp, err := hc.Post(base+commandInvitePath, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	key, _ := base64.StdEncoding.DecodeString(c.Server.MasterKey)
	mine, _ := newSealer(c, key)
	other, _ := secure.NewSealer(secure.RandomBytes(32))
	req := func(s *secure.Sealer, at time.Time) commandInvite {
		ci := commandInvite{Org: "primary", Email: "admin@example.com",
			commandSig: commandSig{At: at.Unix(), Nonce: secure.RandomToken(18)}}
		signCommand(&ci, s)
		return ci
	}
	if got := post(req(other, time.Now())); got != http.StatusUnauthorized {
		t.Errorf("another master key: %d", got)
	}
	if got := post(req(mine, time.Now().Add(-10*time.Minute))); got != http.StatusUnauthorized {
		t.Errorf("stale request: %d", got)
	}
	tampered := req(mine, time.Now())
	tampered.BreakGlass = true
	if got := post(tampered); got != http.StatusUnauthorized {
		t.Errorf("tampered request: %d", got)
	}
	good := req(mine, time.Now())
	if got := post(good); got != http.StatusOK {
		t.Fatalf("signed request: %d", got)
	}
	if got := post(good); got != http.StatusUnauthorized {
		t.Errorf("replayed request: %d", got)
	}

	// with the server stopped, the command uses the store itself
	a.Close()
	link, _, how, err = Invite(ctx, c, log, "", "", false, "primary", "admin@example.com", false, false)
	if err != nil || how != "the store" || link == "" {
		t.Fatalf("server stopped: %v %s", err, how)
	}
	// --server names a server: no falling back to the store when it does not answer
	if _, _, _, err := Invite(ctx, c, log, base, "", false, "primary", "admin@example.com", false, false); err == nil {
		t.Fatal("--server that does not answer fell back to the store")
	}
}

// "quisora invite --break-glass --super-admin" through the running server: the account becomes an enabled super admin
// (audited as the command's action), only for a user of the primary organization, and only with --break-glass.
func TestInviteSuperAdminThroughRunningServer(t *testing.T) {
	a, _, _ := startAppWith(t, "badgerdb", nil)
	ctx := context.Background()
	c, log := a.Cfg, logger.NewNullLogger()
	primary, err := a.Svc.PrimaryOrg(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// the only super admin is gone: demoted and disabled behind the server's back (what two administrators removing
	// each other on two nodes can leave)
	admin, err := a.Svc.FindUserByEmail(ctx, primary.ID, "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	admin.Role, admin.Active = model.RoleUser, false
	if err := a.Svc.Users.Update(ctx, admin); err != nil {
		t.Fatal(err)
	}
	a.OIDC.InvalidateUser(admin.ID)

	if _, _, _, err := Invite(ctx, c, log, "", "", false, "primary", "admin@example.com", false, true); err == nil ||
		!strings.Contains(err.Error(), "--break-glass") {
		t.Fatalf("--super-admin without --break-glass: %v", err)
	}
	if got, _ := a.Svc.Users.Get(ctx, admin.ID); got.Role == model.RoleSuperAdmin || got.Active {
		t.Fatal("a refused command changed the account")
	}
	// a user of another organization cannot become a super admin
	name := "acme"
	org, err := a.Svc.CreateOrg(ctx, service.System, service.OrgInput{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	user, email := "pat", "pat@acme.example"
	pat, err := a.Svc.CreateUser(ctx, service.System, org.ID, service.UserInput{Username: &user, Email: &email, GivenName: &user})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Invite(ctx, c, log, "", "", false, "acme", email, true, true); err == nil ||
		!strings.Contains(err.Error(), "primary organization") {
		t.Fatalf("a user of another organization: %v", err)
	}
	if got, _ := a.Svc.Users.Get(ctx, pat.ID); got.Role == model.RoleSuperAdmin {
		t.Fatal("a user of another organization was made a super admin")
	}

	link, _, how, err := Invite(ctx, c, log, "", "", false, "primary", "admin@example.com", true, true)
	if err != nil || how != "the running server" || link == "" {
		t.Fatalf("break-glass super admin: %q %s %v", link, how, err)
	}
	got, err := a.Svc.Users.Get(ctx, admin.ID)
	if err != nil || got.Role != model.RoleSuperAdmin || !got.Active {
		t.Fatalf("the account after recovery: %+v %v", got, err)
	}
	requireCommandActor(t, a, "user.invite.break_glass", "invite")
	requireCommandActor(t, a, "user.update", "invite")
	if _, _, err := a.Svc.PeekLink(ctx, link[strings.Index(link, "token=")+6:], service.LinkInvite); err != nil {
		t.Fatalf("the invitation does not open: %v", err)
	}
}

// requireCommandActor checks that the audit event of action was recorded as the operator's command, not as the system:
// the command's actor, the address the request came from, and the command and its authentication in the detail.
func requireCommandActor(t *testing.T, a *App, action, command string) {
	t.Helper()
	items, _, err := a.Svc.Audits.List(context.Background(), store.ListQuery{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range items {
		if e.Action != action {
			continue
		}
		found = true
		if e.Actor != "command:"+command || e.IP == "" || e.Detail["command"] != command || !strings.Contains(e.Detail["authenticated"], "master key") {
			t.Fatalf("%s recorded as actor %q ip %q detail %v", action, e.Actor, e.IP, e.Detail)
		}
	}
	if !found {
		t.Fatalf("no %s event was recorded", action)
	}
}
