package service_test

import (
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// A certificate goes with the sign-in it was issued under: ending that session (signed out, or ended from elsewhere),
// a grant of it, or the app's access revokes it for good; certificates of the user's other sign-ins stay good.
func TestSSHCertGoesWithItsSignIn(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	u := w.env.user(w.org.ID, "pat", model.RoleUser)
	now := time.Now().UTC()
	session := func(id string) *model.Session {
		s := &model.Session{Meta: model.Meta{ID: id}, UserID: u.ID, OrgID: u.OrgID, AuthTime: now, LastSeen: now,
			Expires: now.Add(time.Hour), Epoch: u.SessionEpoch, Stamp: w.stamp(u.OrgID)}
		if err := w.svc.Sessions.Create(w.ctx, s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	grant := func(id, sessionID, clientID string) {
		g := &model.Grant{Meta: model.Meta{ID: id}, UserID: u.ID, OrgID: u.OrgID, ClientID: clientID, SessionID: sessionID,
			Scopes: []string{"openid"}, Expires: now.Add(time.Hour)}
		if err := w.svc.Grants.Create(w.ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	from := func(signIn string) func(*service.SSHUserRequest) {
		return func(r *service.SSHUserRequest) { r.SignIn = signIn }
	}

	a, b := session("sess-a"), session("sess-b")
	grant("grant-a", a.ID, "ssh-cli") // a `quisora ssh` sign-in through session a
	grant("grant-app", "", "tool")    // an app's own grant, under no session we end here
	viaA := w.mustSign(u, from(a.ID))
	viaGrantA := w.mustSign(u, from("grant-a"))
	viaB := w.mustSign(u, from(b.ID))
	viaApp := w.mustSign(u, from("grant-app"))
	unbound := w.mustSign(u) // issued before certificates recorded their sign-in

	if _, err := w.svc.EndSession(w.ctx, a); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]*service.SSHIssued{"the session's": viaA, "a grant of the session's": viaGrantA} {
		if got := w.reasonOf(c); got != service.SSHReasonSignInEnded {
			t.Errorf("%s certificate: reason %q, want %s", name, got, service.SSHReasonSignInEnded)
		}
	}
	for name, c := range map[string]*service.SSHIssued{"another session's": viaB, "an app's": viaApp, "an unbound": unbound} {
		if got := w.reasonOf(c); got != "" {
			t.Errorf("%s certificate revoked: %q", name, got)
		}
	}

	if _, err := w.svc.RevokeAppAccess(w.ctx, u.ID, "tool"); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(viaApp); got != service.SSHReasonSignInEnded {
		t.Errorf("the app's certificate after its access was revoked: reason %q", got)
	}

	// for good: a session made again under the same id does not bring it back
	session(a.ID)
	if got := w.reasonOf(viaA); got != service.SSHReasonSignInEnded {
		t.Errorf("revocation undone: %q", got)
	}
	if got := w.reasonOf(viaB); got != "" {
		t.Errorf("session b's certificate revoked: %q", got)
	}
}
