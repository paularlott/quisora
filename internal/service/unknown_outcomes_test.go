package service_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// landsThenUnknown makes the next write of a kind land and then report store.ErrUnconfirmed, as a cluster write does
// when the node that decided it was lost before it answered.
type landsThenUnknown struct {
	mu   sync.Mutex
	kind model.Kind
}

func (l *landsThenUnknown) arm(k model.Kind) {
	l.mu.Lock()
	l.kind = k
	l.mu.Unlock()
}

// take reports whether this write is the armed one (once).
func (l *landsThenUnknown) take(k model.Kind) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.kind == "" || l.kind != k {
		return false
	}
	l.kind = ""
	return true
}

func newUnknownEnv(t *testing.T) (*env, *landsThenUnknown) {
	inner := memstore.New()
	t.Cleanup(func() { _ = inner.Close() })
	l := &landsThenUnknown{}
	st := &faultStore{Store: inner}
	st.beforePut = func(r *store.Record) error {
		if l.take(r.Kind) {
			_ = inner.Put(context.Background(), r)
			return store.ErrUnconfirmed
		}
		return nil
	}
	st.beforeCAS = func(r *store.Record, expect hlc.Timestamp) error {
		if l.take(r.Kind) {
			_ = inner.CompareAndPut(context.Background(), r, expect)
			return store.ErrUnconfirmed
		}
		return nil
	}
	// A transaction one of whose writes is of the armed kind lands whole and reports its outcome unknown.
	st.beforeTx = func(ops []store.Op) error {
		for _, op := range ops {
			if l.take(op.Rec.Kind) {
				_ = inner.Tx(context.Background(), ops)
				return store.ErrUnconfirmed
			}
		}
		return nil
	}
	return newEnvOn(t, st), l
}

// Every audited change of the service that ends with its outcome unknown (the write may have landed) records its audit
// event with outcome "unknown", whatever the change: audited is the one way a change is audited (unknown.go). Each case
// arms the next write of one kind to land and report store.ErrUnconfirmed, makes the change and finds its event.
func TestEveryAuditedChangeRecordsAnUnknownOutcome(t *testing.T) {
	type run func() error
	cases := []struct {
		action string
		kind   model.Kind
		setup  func(e *env, org *model.Org) run
	}{
		{"user.create", model.KindUser, func(e *env, org *model.Org) run {
			return func() error {
				_, err := e.svc.CreateUser(e.ctx, service.System, org.ID, service.UserInput{Email: ptr("new@example.com"), GivenName: ptr("New")})
				return err
			}
		}},
		{"user.update", model.KindUser, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "upd", model.RoleUser)
			return func() error {
				_, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{GivenName: ptr("Changed")})
				return err
			}
		}},
		{"user.password", model.KindUser, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "pw", model.RoleUser)
			return func() error {
				_, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Password: ptr("correct horse battery")})
				return err
			}
		}},
		{"user.delete", model.KindUser, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "del", model.RoleUser)
			return func() error { return e.svc.DeleteUser(e.ctx, service.System, u.ID) }
		}},
		{"user.password.remove", model.KindUser, func(e *env, org *model.Org) run {
			u := e.establish(e.user(org.ID, "nopw", model.RoleUser))
			return func() error { return e.svc.RemovePassword(e.ctx, service.System, u.ID) }
		}},
		{"user.invite", model.KindLink, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "inv", model.RoleUser)
			return func() error { _, _, err := e.svc.CreateInvite(e.ctx, service.System, u.ID); return err }
		}},
		{"user.invite.break_glass", model.KindLink, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "bg", model.RoleUser)
			return func() error { _, _, err := e.svc.CreateBreakGlassInvite(e.ctx, u.ID, false); return err }
		}},
		{"user.update", model.KindUser, func(e *env, _ *model.Org) run { // the break-glass promotion
			u := e.user(e.primary.ID, "bgsuper", model.RoleUser)
			return func() error { _, _, err := e.svc.CreateBreakGlassInvite(e.ctx, u.ID, true); return err }
		}},
		{"user.email.add", model.KindUser, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "ea", model.RoleManager)
			return func() error {
				_, err := e.svc.AddLinkedEmail(e.ctx, service.System, u.ID, "other@example.com", false)
				return err
			}
		}},
		{"user.email.remove", model.KindUser, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "er", model.RoleManager)
			if _, err := e.svc.AddLinkedEmail(e.ctx, service.System, u.ID, "other@example.com", false); err != nil {
				t.Fatal(err)
			}
			return func() error {
				_, err := e.svc.RemoveLinkedEmail(e.ctx, service.System, u.ID, "other@example.com")
				return err
			}
		}},
		{"user.email.primary", model.KindUser, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "ep", model.RoleUser)
			if _, err := e.svc.AddLinkedEmail(e.ctx, service.System, u.ID, "other@example.com", true); err != nil {
				t.Fatal(err)
			}
			return func() error {
				_, err := e.svc.MakePrimary(e.ctx, service.System, u.ID, "other@example.com")
				return err
			}
		}},
		{"user.email.verify", model.KindUser, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "ev", model.RoleUser)
			if _, err := e.svc.AddLinkedEmail(e.ctx, service.System, u.ID, "other@example.com", false); err != nil {
				t.Fatal(err)
			}
			return func() error {
				_, err := e.svc.MarkEmailVerified(e.ctx, service.System, u.ID, "other@example.com")
				return err
			}
		}},
		{"account.recovery_codes.create", model.KindUser, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "rc", model.RoleUser)
			if err := e.svc.SetTOTP(e.ctx, e.fresh(u), secure.RandomBytes(20), 1000); err != nil {
				t.Fatal(err)
			}
			return func() error { _, err := e.svc.CreateRecoveryCodes(e.ctx, actor(u), e.fresh(u)); return err }
		}},
		{"user.totp.remove", model.KindUser, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "tr", model.RoleUser)
			if err := e.svc.SetTOTP(e.ctx, e.fresh(u), secure.RandomBytes(20), 1000); err != nil {
				t.Fatal(err)
			}
			return func() error { return e.svc.RemoveTOTP(e.ctx, service.System, u.ID) }
		}},
		{"user.passkey.remove", model.KindUser, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "pk", model.RoleUser)
			pk := e.passkey(u, "key")
			return func() error { _, err := e.svc.RemovePasskey(e.ctx, service.System, u.ID, pk.ID, ""); return err }
		}},
		{"user.app.revoke", model.KindGrant, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "app", model.RoleUser)
			e.grant(u, e.session(u).ID)
			return func() error { _, err := e.svc.RemoveUserApp(e.ctx, service.System, u.ID, "c1"); return err }
		}},
		{"user.expire", model.KindUser, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "exp", model.RoleUser)
			if _, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{ValidUntil: ptr(time.Now().Add(-time.Hour).Format(time.RFC3339))}); err != nil {
				t.Fatal(err)
			}
			return func() error { _, err := e.svc.ExpireUsers(e.ctx); return err }
		}},
		{"identity.unlink", model.KindIdentity, func(e *env, org *model.Org) run { // links made by email go on a promotion
			u := e.user(org.ID, "promo", model.RoleUser)
			p, err := e.svc.CreateProvider(e.ctx, service.System, org.ID, goodProvider("sso-unlink"))
			if err != nil {
				t.Fatal(err)
			}
			i := model.NewIdentity(e.fresh(u), p, "subject", "promo@example.com", "email")
			if err := e.svc.Identities.Create(e.ctx, i); err != nil {
				t.Fatal(err)
			}
			return func() error {
				_, err := e.svc.UpdateUser(e.ctx, service.System, u.ID, service.UserInput{Role: ptr(model.RoleManager)})
				return err
			}
		}},
		{"group.create", model.KindGroup, func(e *env, org *model.Org) run {
			return func() error {
				_, err := e.svc.CreateGroup(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: ptr("crew")})
				return err
			}
		}},
		{"group.member.add", model.KindGroup, func(e *env, org *model.Org) run { // events of the members of a new group
			u := e.user(org.ID, "gm", model.RoleUser)
			return func() error {
				_, err := e.svc.CreateGroupWithMembers(e.ctx, service.System, org.ID, service.GroupInput{DisplayName: ptr("crew2")}, []string{u.ID})
				return err
			}
		}},
		{"group.update", model.KindGroup, func(e *env, org *model.Org) run {
			g := e.group(org.ID, "old")
			return func() error {
				_, err := e.svc.UpdateGroup(e.ctx, service.System, g.ID, service.GroupInput{DisplayName: ptr("new")})
				return err
			}
		}},
		{"group.member.remove", model.KindGroup, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "gr", model.RoleUser)
			g := e.group(org.ID, "members", u)
			return func() error {
				g, err := e.svc.Groups.Get(e.ctx, g.ID)
				if err != nil {
					return err
				}
				_, err = e.svc.ChangeGroup(e.ctx, service.System, g, service.GroupInput{}, nil, []string{u.ID})
				return err
			}
		}},
		{"group.delete", model.KindGroup, func(e *env, org *model.Org) run {
			g := e.group(org.ID, "gone")
			return func() error { return e.svc.DeleteGroup(e.ctx, service.System, g.ID) }
		}},
		{"apitoken.create", model.KindAPIToken, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "tok", model.RoleUser)
			return func() error {
				_, _, err := e.svc.CreateAPIToken(e.ctx, actor(u), service.APITokenInput{Name: "t", Scopes: []string{service.ScopeAPI}})
				return err
			}
		}},
		{"apitoken.update", model.KindAPIToken, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "tok2", model.RoleUser)
			tk, _, err := e.svc.CreateAPIToken(e.ctx, actor(u), service.APITokenInput{Name: "t", Scopes: []string{service.ScopeAPI}})
			if err != nil {
				t.Fatal(err)
			}
			return func() error {
				_, err := e.svc.UpdateAPIToken(e.ctx, actor(u), tk.ID, service.APITokenUpdate{Name: ptr("renamed")})
				return err
			}
		}},
		{"apitoken.regenerate", model.KindAPIToken, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "tok3", model.RoleUser)
			tk, _, err := e.svc.CreateAPIToken(e.ctx, actor(u), service.APITokenInput{Name: "t", Scopes: []string{service.ScopeAPI}})
			if err != nil {
				t.Fatal(err)
			}
			return func() error { _, _, err := e.svc.RegenerateAPIToken(e.ctx, actor(u), tk.ID); return err }
		}},
		{"apitoken.delete", model.KindAPIToken, func(e *env, org *model.Org) run {
			u := e.user(org.ID, "tok4", model.RoleUser)
			tk, _, err := e.svc.CreateAPIToken(e.ctx, actor(u), service.APITokenInput{Name: "t", Scopes: []string{service.ScopeAPI}})
			if err != nil {
				t.Fatal(err)
			}
			return func() error { return e.svc.DeleteAPIToken(e.ctx, actor(u), tk.ID) }
		}},
		{"org.create", model.KindOrg, func(e *env, _ *model.Org) run {
			return func() error {
				_, err := e.svc.CreateOrg(e.ctx, service.System, service.OrgInput{Name: ptr("fresh-org")})
				return err
			}
		}},
		{"org.update", model.KindOrg, func(e *env, org *model.Org) run {
			return func() error {
				_, err := e.svc.UpdateOrg(e.ctx, service.System, org.ID, service.OrgInput{DisplayName: ptr("Renamed")})
				return err
			}
		}},
		{"org.delete", model.KindOrg, func(e *env, _ *model.Org) run {
			o := e.org("doomed")
			return func() error { return e.svc.DeleteOrg(e.ctx, service.System, o.ID, false) }
		}},
		{"org.signout", model.KindOrg, func(e *env, org *model.Org) run {
			return func() error {
				_, err := e.svc.SignOutOrg(e.ctx, service.System, org.ID, service.SignOutOptions{Reason: "test"})
				return err
			}
		}},
		{"tenant.create", model.KindTenant, func(e *env, org *model.Org) run {
			return func() error {
				_, err := e.svc.CreateTenant(e.ctx, service.System, org.ID, service.TenantInput{Name: ptr("t1")})
				return err
			}
		}},
		{"tenant.update", model.KindTenant, func(e *env, org *model.Org) run {
			ten := e.tenant(org.ID, "t2")
			return func() error {
				_, err := e.svc.UpdateTenant(e.ctx, service.System, ten.ID, service.TenantInput{DisplayName: ptr("Two")})
				return err
			}
		}},
		{"tenant.delete", model.KindTenant, func(e *env, org *model.Org) run {
			ten := e.tenant(org.ID, "t3")
			return func() error { return e.svc.DeleteTenant(e.ctx, service.System, ten.ID) }
		}},
		{"tenant.access.add", model.KindAccess, func(e *env, org *model.Org) run {
			ten, u := e.tenant(org.ID, "t4"), e.user(org.ID, "acc", model.RoleUser)
			return func() error {
				_, err := e.svc.AddAccess(e.ctx, service.System, ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: u.ID})
				return err
			}
		}},
		{"tenant.access.update", model.KindAccess, func(e *env, org *model.Org) run {
			ten, u := e.tenant(org.ID, "t5"), e.user(org.ID, "acc2", model.RoleUser)
			ent, err := e.svc.AddAccess(e.ctx, service.System, ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: u.ID})
			if err != nil {
				t.Fatal(err)
			}
			return func() error {
				_, err := e.svc.UpdateAccess(e.ctx, service.System, ten.ID, ent.ID, service.AccessInput{Roles: &[]string{"viewer"}})
				return err
			}
		}},
		{"tenant.access.remove", model.KindAccess, func(e *env, org *model.Org) run {
			ten, u := e.tenant(org.ID, "t6"), e.user(org.ID, "acc3", model.RoleUser)
			ent, err := e.svc.AddAccess(e.ctx, service.System, ten.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: u.ID})
			if err != nil {
				t.Fatal(err)
			}
			return func() error { return e.svc.RemoveAccess(e.ctx, service.System, ten.ID, ent.ID) }
		}},
		{"client.create", model.KindClient, func(e *env, org *model.Org) run {
			return func() error {
				_, _, err := e.svc.CreateClient(e.ctx, service.System, org.ID, e.clientInput("c-new"))
				return err
			}
		}},
		{"client.update", model.KindClient, func(e *env, org *model.Org) run {
			c := e.client(org.ID, "c-upd")
			return func() error {
				_, err := e.svc.UpdateClient(e.ctx, service.System, c.ID, service.ClientInput{Description: ptr("changed")})
				return err
			}
		}},
		{"client.secret.rotate", model.KindClient, func(e *env, org *model.Org) run {
			c := e.client(org.ID, "c-rot")
			return func() error { _, err := e.svc.RotateClientSecret(e.ctx, service.System, c.ID); return err }
		}},
		{"client.delete", model.KindClient, func(e *env, org *model.Org) run {
			c := e.client(org.ID, "c-del")
			return func() error { return e.svc.DeleteClient(e.ctx, service.System, c.ID) }
		}},
		{"client.self_register", model.KindClient, func(e *env, org *model.Org) run {
			e.acceptSelfRegistered(org.ID)
			return func() error {
				_, err := e.svc.RegisterClient(e.ctx, org.ID, service.RegistrationInput{ClientName: "Zed", RedirectURIs: []string{"https://z.example.com/cb"}})
				return err
			}
		}},
		{"client.self_registered.revoke", model.KindClient, func(e *env, org *model.Org) run {
			e.acceptSelfRegistered(org.ID)
			app, err := e.svc.RegisterClient(e.ctx, org.ID, service.RegistrationInput{ClientName: "Zed", RedirectURIs: []string{"https://z.example.com/cb"}})
			if err != nil {
				t.Fatal(err)
			}
			return func() error { return e.svc.RevokeSelfRegisteredApp(e.ctx, service.System, org.ID, app.ID) }
		}},
		{"ssh.settings.update", model.KindTenant, func(e *env, org *model.Org) run {
			ten := e.tenant(org.ID, "ssh1")
			return func() error {
				_, err := e.svc.UpdateTenantSSH(e.ctx, service.System, ten.ID, service.SSHSettingsInput{CertTTL: ptr(3600)})
				return err
			}
		}},
		{"ssh.ca.create", model.KindSSHKey, func(e *env, org *model.Org) run {
			ten := e.tenant(org.ID, "ssh2")
			return func() error {
				_, err := e.svc.UpdateTenantSSH(e.ctx, service.System, ten.ID, service.SSHSettingsInput{Enabled: ptr(true)})
				return err
			}
		}},
		{"ssh.ca.rotate", model.KindSSHKey, func(e *env, org *model.Org) run {
			ten := e.sshTenant(org.ID, "ssh3")
			return func() error {
				_, err := e.svc.RotateSSHKey(e.ctx, service.System, ten.ID, "user", true)
				return err
			}
		}},
		{"ssh.ca.remove", model.KindSSHKey, func(e *env, org *model.Org) run {
			ten := e.sshTenant(org.ID, "ssh4")
			keys, err := e.svc.SSHKeys(e.ctx, ten.ID, "user")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.svc.RotateSSHKey(e.ctx, service.System, ten.ID, "user", true); err != nil {
				t.Fatal(err)
			}
			return func() error { return e.svc.RemoveSSHKey(e.ctx, service.System, ten.ID, keys[0].ID) }
		}},
		{"ssh.cert.issue", model.KindSSHCert, func(e *env, org *model.Org) run {
			ten, u := e.sshTenant(org.ID, "ssh5"), e.user(org.ID, "sshu1", model.RoleUser)
			return func() error { _, err := e.svc.SignUserSSH(e.ctx, e.sshRequest(ten, u)); return err }
		}},
		{"ssh.cert.revoke", model.KindSSHCert, func(e *env, org *model.Org) run {
			ten, u := e.sshTenant(org.ID, "ssh6"), e.user(org.ID, "sshu2", model.RoleUser)
			c, err := e.svc.SignUserSSH(e.ctx, e.sshRequest(ten, u))
			if err != nil {
				t.Fatal(err)
			}
			return func() error { return e.svc.RevokeSSHCert(e.ctx, service.System, org.ID, c.Cert.ID) }
		}},
		{"ssh.host.issue", model.KindSSHCert, func(e *env, org *model.Org) run {
			ten := e.sshTenant(org.ID, "ssh7")
			if _, err := e.svc.UpdateTenantSSH(e.ctx, service.System, ten.ID, service.SSHSettingsInput{HostCerts: ptr(true),
				HostPatterns: &[]string{"*.example.com"}}); err != nil {
				t.Fatal(err)
			}
			return func() error {
				_, err := e.svc.SignHostSSH(e.ctx, service.System, ten.ID, service.SSHHostRequest{PublicKey: newPub(t), Principals: []string{"a.example.com"}})
				return err
			}
		}},
		{"provider.create", model.KindProvider, func(e *env, org *model.Org) run {
			return func() error {
				_, err := e.svc.CreateProvider(e.ctx, service.System, org.ID, goodProvider("sso-new"))
				return err
			}
		}},
		{"provider.update", model.KindProvider, func(e *env, org *model.Org) run {
			p, err := e.svc.CreateProvider(e.ctx, service.System, org.ID, goodProvider("sso-upd"))
			if err != nil {
				t.Fatal(err)
			}
			return func() error {
				_, err := e.svc.UpdateProvider(e.ctx, service.System, p.ID, service.ProviderInput{TrustMFA: ptr(true)})
				return err
			}
		}},
		{"provider.delete", model.KindProvider, func(e *env, org *model.Org) run {
			p, err := e.svc.CreateProvider(e.ctx, service.System, org.ID, goodProvider("sso-del"))
			if err != nil {
				t.Fatal(err)
			}
			return func() error { return e.svc.DeleteProvider(e.ctx, service.System, p.ID) }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			e, lands := newUnknownEnv(t)
			org := e.org("acme")
			do := tc.setup(e, org)
			before := len(e.unknownAudits(tc.action))
			lands.arm(tc.kind)
			err := do()
			// (the expiry pass counts what it ended and a promotion's clean-up is best effort: neither returns the error)
			if !errors.Is(err, service.ErrOutcomeUnknown) && tc.action != "user.expire" && tc.action != "identity.unlink" {
				t.Fatalf("the change did not report its unknown outcome: %v", err)
			}
			if n := len(e.unknownAudits(tc.action)); n <= before {
				t.Fatalf("the change of unknown outcome recorded no %s event with outcome %q (%d events before, %d after)",
					tc.action, service.OutcomeUnknown, before, n)
			}
		})
	}
}

// unknownAudits returns the events of action with outcome "unknown".
func (e *env) unknownAudits(action string) []*model.Audit {
	var out []*model.Audit
	for _, a := range e.audits(action) {
		if a.Outcome == service.OutcomeUnknown {
			out = append(out, a)
		}
	}
	return out
}

func (e *env) tenant(orgID, name string) *model.Tenant {
	e.t.Helper()
	t, err := e.svc.CreateTenant(e.ctx, service.System, orgID, service.TenantInput{Name: &name})
	if err != nil {
		e.t.Fatal(err)
	}
	return t
}

// sshTenant is an open tenant with SSH enabled.
func (e *env) sshTenant(orgID, name string) *model.Tenant {
	e.t.Helper()
	ten := e.tenant(orgID, name)
	open := ten.Settings
	open.MembersOnly = false
	if _, err := e.svc.UpdateTenant(e.ctx, service.System, ten.ID, service.TenantInput{Settings: &open}); err != nil {
		e.t.Fatal(err)
	}
	ten, err := e.svc.UpdateTenantSSH(e.ctx, service.System, ten.ID, service.SSHSettingsInput{Enabled: ptr(true)})
	if err != nil {
		e.t.Fatal(err)
	}
	return ten
}

// sshRequest is a good request for u's certificate of ten (signed in with a second factor a minute ago).
func (e *env) sshRequest(ten *model.Tenant, u *model.User) service.SSHUserRequest {
	stamp, err := e.svc.SessionStamp(e.ctx, u.OrgID)
	if err != nil {
		e.t.Fatal(err)
	}
	return service.SSHUserRequest{User: u, TenantID: ten.ID, ClientID: ten.SSH.ClientID, PublicKey: newPub(e.t),
		AMR: []string{"pwd", "otp"}, AuthTime: time.Now().Add(-time.Minute), Via: "cli", SessionEpoch: u.SessionEpoch, Stamp: stamp}
}

func (e *env) clientInput(name string) service.ClientInput {
	return service.ClientInput{Name: &name, RedirectURIs: &[]string{"https://app.example/cb"},
		GrantTypes: &[]string{"authorization_code"}, Scopes: &[]string{"openid"}}
}

func (e *env) client(orgID, name string) *model.Client {
	e.t.Helper()
	c, _, err := e.svc.CreateClient(e.ctx, service.System, orgID, e.clientInput(name))
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

// A passkey removal whose outcome is unknown ends the sessions the passkey signed in all the same: if it landed, a
// retry finds no passkey to remove, and would never end them.
func TestUnknownPasskeyRemovalEndsItsSessions(t *testing.T) {
	e, l := newUnknownEnv(t)
	u := e.user(e.primary.ID, "pk-unknown", model.RoleUser)
	pk := e.passkey(u, "key")
	now := time.Now().UTC()
	s := &model.Session{Meta: model.Meta{ID: "sess-unknown"}, UserID: u.ID, OrgID: u.OrgID, Passkey: pk.ID, AuthTime: now,
		LastSeen: now, Expires: now.Add(time.Hour), Epoch: e.fresh(u).SessionEpoch}
	if err := e.svc.Sessions.Create(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	l.arm(model.KindUser)
	if _, err := e.svc.RemovePasskey(e.ctx, service.System, u.ID, pk.ID, ""); err == nil {
		t.Fatal("the removal reported success")
	}
	if _, err := e.svc.Sessions.Get(e.ctx, s.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the passkey's session survived its removal: %v", err)
	}
}
