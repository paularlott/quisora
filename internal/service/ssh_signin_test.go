package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
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
	fromSession := func(id string) func(*service.SSHUserRequest) { // the account page's: no client
		return func(r *service.SSHUserRequest) { r.SignIn, r.ClientID = id, "" }
	}

	a, b := session("sess-a"), session("sess-b")
	grant("grant-a", a.ID, "ssh-cli") // a `quisora ssh` sign-in through session a
	grant("grant-app", "", "tool")    // an app's own grant, under no session we end here
	viaA := w.mustSign(u, fromSession(a.ID))
	viaGrantA := w.mustSign(u, from("grant-a"))
	viaB := w.mustSign(u, fromSession(b.ID))
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

// certListing is the store the certificates are read from, noting at each listing of them which of ids are still there
// (as a session or a grant).
type certListing struct {
	store.Store
	svc  *service.Service
	ids  []string
	seen []string
}

func (s *certListing) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if kind == model.KindSSHCert {
		for _, id := range s.ids {
			_, serr := s.svc.Sessions.Get(ctx, id)
			_, gerr := s.svc.Grants.Get(ctx, id)
			if serr == nil || gerr == nil {
				s.seen = append(s.seen, id)
			}
		}
	}
	return s.Store.List(ctx, kind, q)
}

// The certificates of a sign-in are revoked after the sign-in is deleted, never before: a certificate signed between a
// listing made first and the deletion would be missed (its signer finds the sign-in still there). Removing a passkey
// revokes the certificates of the sessions it ends and of their grants.
func TestSSHCertsRevokedAfterTheirSignInEnds(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	u := w.env.user(w.org.ID, "pat", model.RoleUser)
	pk := w.passkey(u, "laptop")
	w.passkey(u, "phone") // not the last way in
	now := time.Now().UTC()
	session := func(id, passkey string) *model.Session {
		s := &model.Session{Meta: model.Meta{ID: id}, UserID: u.ID, OrgID: u.OrgID, AuthTime: now, LastSeen: now, Passkey: passkey,
			Expires: now.Add(time.Hour), Epoch: u.SessionEpoch, Stamp: w.stamp(u.OrgID)}
		if err := w.svc.Sessions.Create(w.ctx, s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	grant := func(id, sessionID, clientID string) {
		g := &model.Grant{Meta: model.Meta{ID: id}, UserID: u.ID, OrgID: u.OrgID, ClientID: clientID, SessionID: sessionID,
			Epoch: u.SessionEpoch, Stamp: w.stamp(u.OrgID), Scopes: []string{"openid"}, Expires: now.Add(time.Hour)}
		if err := w.svc.Grants.Create(w.ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	fromSession := func(id string) func(*service.SSHUserRequest) {
		return func(r *service.SSHUserRequest) { r.SignIn, r.ClientID = id, "" }
	}
	fromGrant := func(id string) func(*service.SSHUserRequest) {
		return func(r *service.SSHUserRequest) { r.SignIn = id }
	}
	watch := &certListing{Store: w.svc.SSHCerts.S, svc: w.svc}
	w.svc.SSHCerts.S = watch
	ended := func(what string, certs ...*service.SSHIssued) {
		t.Helper()
		if len(watch.seen) > 0 {
			t.Errorf("%s: certificates listed while %v were still there", what, watch.seen)
		}
		for i, c := range certs {
			if got := w.reasonOf(c); got != service.SSHReasonSignInEnded {
				t.Errorf("%s: certificate %d: reason %q, want %s", what, i, got, service.SSHReasonSignInEnded)
			}
		}
		watch.ids, watch.seen = nil, nil
	}

	a := session("sess-a", "")
	grant("grant-a", a.ID, "app")
	certs := []*service.SSHIssued{w.mustSign(u, fromSession(a.ID)), w.mustSign(u, fromGrant("grant-a"))}
	watch.ids = []string{a.ID, "grant-a"}
	if _, err := w.svc.EndSession(w.ctx, a); err != nil {
		t.Fatal(err)
	}
	ended("revoking a session", certs...)

	grant("grant-tool", "", "tool")
	cert := w.mustSign(u, fromGrant("grant-tool"))
	watch.ids = []string{"grant-tool"}
	if _, err := w.svc.RevokeAppAccess(w.ctx, u.ID, "tool"); err != nil {
		t.Fatal(err)
	}
	ended("removing an app's access", cert)

	p := session("sess-pk", pk.ID)
	grant("grant-pk", p.ID, "app")
	kept := session("sess-kept", "")
	keptCert := w.mustSign(u, fromSession(kept.ID))
	certs = []*service.SSHIssued{w.mustSign(u, fromSession(p.ID)), w.mustSign(u, fromGrant("grant-pk"))}
	watch.ids = []string{p.ID, "grant-pk"}
	if n, err := w.svc.RemovePasskey(w.ctx, service.System, u.ID, pk.ID, ""); err != nil || n != 1 {
		t.Fatalf("remove the passkey: %d %v", n, err)
	}
	ended("removing the passkey it signed in with", certs...)
	if got := w.reasonOf(keptCert); got != "" {
		t.Errorf("another session's certificate revoked with the passkey: %q", got)
	}
}

// A certificate signed while its sign-in is being ended does not survive it: once its record is stored, the signer reads
// the sign-in again from the store, and finding it gone revokes the certificate and refuses (the revocation's listing,
// made before the record was stored, missed it).
func TestSSHCertOfASignInEndedMeanwhileIsRevoked(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	u := w.env.user(w.org.ID, "pat", model.RoleUser)
	for _, c := range []struct {
		what string
		mut  func(*service.SSHUserRequest)
	}{
		{"a session (the account page)", func(r *service.SSHUserRequest) { r.SignIn, r.ClientID = "sess-gone", "" }},
		{"a grant (the sign endpoint)", func(r *service.SSHUserRequest) { r.SignIn = "grant-gone" }},
	} {
		before := len(w.revokedFor())
		_, err := w.sign(u, c.mut)
		var refusal *service.SSHRefusal
		if !errors.As(err, &refusal) {
			t.Errorf("%s ended meanwhile: %v, want a refusal", c.what, err)
		}
		revoked := w.revokedFor()
		if len(revoked) != before+1 {
			t.Errorf("%s ended meanwhile: the certificate stored is not revoked (%v)", c.what, revoked)
		}
		for _, reason := range revoked {
			if reason != service.SSHReasonSignInEnded {
				t.Errorf("%s ended meanwhile: reason %q", c.what, reason)
			}
		}
	}
}
