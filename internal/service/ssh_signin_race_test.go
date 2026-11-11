package service_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/sshca"
	"github.com/paularlott/quisora/internal/store"
)

// hiddenCerts is the store as a node of a gossip cluster has it before some certificates signed on another node have
// replicated to it: its listings of certificates leave out those of ids.
type hiddenCerts struct {
	store.Store
	ids []string
}

func (s *hiddenCerts) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	res, err := s.Store.List(ctx, kind, q)
	if err != nil || kind != model.KindSSHCert {
		return res, err
	}
	out := *res
	out.Records = slices.DeleteFunc(slices.Clone(res.Records), func(r *store.Record) bool { return slices.Contains(s.ids, r.ID) })
	return &out, nil
}

// onKRL reports whether krl lists certificate c by its serial.
func onKRL(krl *sshca.KRL, c *service.SSHIssued) bool {
	for _, ca := range krl.CAs {
		if slices.Contains(ca.Serials, c.Cert.Serial) {
			return true
		}
	}
	return false
}

// A certificate signed on one node while its sign-in is taken back on another, which the revocation's listing misses
// (the certificate had not replicated to it yet) and whose signer still found the sign-in (the deletion had not
// replicated either), is revoked once both have replicated: the revocation recorded the sign-in as taken back
// (model.SSHRevokedSignIn), and the list revokes every certificate issued under it, and writes that down.
func TestSSHCertMissedByItsSignInsRevocationIsRevoked(t *testing.T) {
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
	hide := &hiddenCerts{Store: w.svc.SSHCerts.S}
	w.svc.SSHCerts.S = hide
	missed := func(what string, revoke func(), certs ...*service.SSHIssued) {
		t.Helper()
		hide.ids = nil
		for _, c := range certs {
			hide.ids = append(hide.ids, c.Cert.ID)
		}
		revoke()
		hide.ids = nil // replicated
		for i, c := range certs {
			got, err := w.svc.SSHCerts.Get(w.ctx, c.Cert.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Revoked {
				t.Fatalf("%s: certificate %d was listed by the revocation: the test misses nothing", what, i)
			}
			if got := w.reasonOf(c); got != service.SSHReasonSignInEnded {
				t.Errorf("%s: certificate %d missed by the revocation: reason %q, want %s", what, i, got, service.SSHReasonSignInEnded)
			}
		}
		krl := w.krlOf() // made afresh: the revocations it finds are written down
		for i, c := range certs {
			if !onKRL(krl, c) {
				t.Errorf("%s: certificate %d is not on the revocation list", what, i)
			}
			got, err := w.svc.SSHCerts.Get(w.ctx, c.Cert.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Revoked || got.RevokedReason != service.SSHReasonSignInEnded {
				t.Errorf("%s: certificate %d not written down as revoked: %v %q", what, i, got.Revoked, got.RevokedReason)
			}
		}
	}

	a := session("sess-a")
	grant("grant-a", a.ID, "ssh-cli")
	missed("revoking a session", func() {
		if _, err := w.svc.EndSession(w.ctx, a); err != nil {
			t.Fatal(err)
		}
	}, w.mustSign(u, fromSession(a.ID)), w.mustSign(u, fromGrant("grant-a")))

	grant("grant-tool", "", "tool")
	missed("removing an app's access", func() {
		if _, err := w.svc.RevokeAppAccess(w.ctx, u.ID, "tool"); err != nil {
			t.Fatal(err)
		}
	}, w.mustSign(u, fromGrant("grant-tool")))

	grant("grant-direct", "", "ssh-cli")
	missed("revoking a grant", func() {
		if err := w.svc.RevokeSSHCertsFrom(w.ctx, u.OrgID, u.ID, map[string]bool{"grant-direct": true}); err != nil {
			t.Fatal(err)
		}
	}, w.mustSign(u, fromGrant("grant-direct")))
}

// The user signing a session out does not take its sign-in back: the certificates issued under it, and under the grants
// that end with it, last to their expiry, and nothing records the sign-in as revoked.
func TestSSHCertOutlivesItsSessionsSignOut(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	u := w.env.user(w.org.ID, "pat", model.RoleUser)
	now := time.Now().UTC()
	s := &model.Session{Meta: model.Meta{ID: "sess-out"}, UserID: u.ID, OrgID: u.OrgID, AuthTime: now, LastSeen: now,
		Expires: now.Add(time.Hour), Epoch: u.SessionEpoch, Stamp: w.stamp(u.OrgID)}
	if err := w.svc.Sessions.Create(w.ctx, s); err != nil {
		t.Fatal(err)
	}
	g := &model.Grant{Meta: model.Meta{ID: "grant-out"}, UserID: u.ID, OrgID: u.OrgID, ClientID: "ssh-cli", SessionID: s.ID,
		Epoch: u.SessionEpoch, Stamp: w.stamp(u.OrgID), Scopes: []string{"openid"}, Expires: now.Add(time.Hour)}
	if err := w.svc.Grants.Create(w.ctx, g); err != nil {
		t.Fatal(err)
	}
	viaSession := w.mustSign(u, func(r *service.SSHUserRequest) { r.SignIn, r.ClientID = s.ID, "" })
	viaGrant := w.mustSign(u, func(r *service.SSHUserRequest) { r.SignIn = g.ID })
	if ended, err := w.svc.SignOutSession(w.ctx, s); err != nil || !ended {
		t.Fatalf("sign out: %v %v", ended, err)
	}
	if _, err := w.svc.Grants.Get(w.ctx, g.ID); err == nil {
		t.Fatal("setup: the grant without offline access outlived its session's sign-out")
	}
	for name, c := range map[string]*service.SSHIssued{"the session's": viaSession, "its grant's": viaGrant} {
		if got := w.reasonOf(c); got != "" {
			t.Errorf("%s certificate revoked by a sign-out: %q", name, got)
		}
		if onKRL(w.krlOf(), c) {
			t.Errorf("%s certificate on the revocation list after a sign-out", name)
		}
	}
	for _, id := range []string{s.ID, g.ID} {
		if _, err := w.svc.SSHRevokedSignIns.Get(w.ctx, id); err == nil {
			t.Errorf("sign-in %s recorded as revoked by a sign-out", id)
		}
	}
}

// The record of a revoked sign-in is kept until every certificate it could have signed has expired, and no longer:
// one past its expiry revokes nothing.
func TestSSHRevokedSignInExpires(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	u := w.env.user(w.org.ID, "pat", model.RoleUser)
	if model.ExpiryOf(model.KindSSHRevokedSignIn) != model.AlwaysExpires {
		t.Error("revoked sign-ins are not a kind that always expires")
	}
	before := time.Now()
	if err := w.svc.RevokeSSHCertsFrom(w.ctx, u.OrgID, u.ID, map[string]bool{"grant-x": true}); err != nil {
		t.Fatal(err)
	}
	r, err := w.svc.SSHRevokedSignIns.Get(w.ctx, "grant-x")
	if err != nil {
		t.Fatalf("the revoked sign-in is not recorded: %v", err)
	}
	if r.OrgID != u.OrgID || r.UserID != u.ID {
		t.Errorf("recorded as %q/%q", r.OrgID, r.UserID)
	}
	// the longest certificate (a day) and its time on the list past its end, and room for replication
	if min, max := before.Add(24*time.Hour+10*time.Minute), time.Now().Add(26*time.Hour); r.Expires.Before(min) || r.Expires.After(max) {
		t.Errorf("expires %v, want between %v and %v", r.Expires, min, max)
	}

	// one that has expired is not found, and revokes nothing
	gone := &model.SSHRevokedSignIn{Meta: model.Meta{ID: "grant-old"}, OrgID: u.OrgID, UserID: u.ID, Expires: time.Now().Add(-time.Second)}
	if err := w.svc.SSHRevokedSignIns.Put(w.ctx, gone); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.SSHRevokedSignIns.Get(w.ctx, gone.ID); err == nil {
		t.Error("an expired revoked sign-in is still found")
	}
	g := &model.Grant{Meta: model.Meta{ID: gone.ID}, UserID: u.ID, OrgID: u.OrgID, ClientID: "ssh-cli", Scopes: []string{"openid"},
		Epoch: u.SessionEpoch, Stamp: w.stamp(u.OrgID), Expires: time.Now().Add(time.Hour)}
	if err := w.svc.Grants.Create(w.ctx, g); err != nil {
		t.Fatal(err)
	}
	c := w.mustSign(u, func(r *service.SSHUserRequest) { r.SignIn = g.ID })
	if got := w.reasonOf(c); got != "" {
		t.Errorf("a certificate revoked by an expired record: %q", got)
	}
}
