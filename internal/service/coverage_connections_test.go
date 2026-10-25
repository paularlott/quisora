package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
)

// audited returns the audit events of action in org, as a super admin reads them.
func (e *env) audited(orgID, action string) []*model.Audit {
	e.t.Helper()
	page, err := e.svc.ListAudit(e.ctx, actor(e.super), orgID, service.AuditQuery{Action: action})
	if err != nil {
		e.t.Fatal(err)
	}
	return page.Items
}

func (e *env) fresh(u *model.User) *model.User {
	e.t.Helper()
	got, err := e.svc.Users.Get(e.ctx, u.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	return got
}

func (e *env) passkey(u *model.User, name string) *model.Passkey {
	e.t.Helper()
	pk := &model.Passkey{UserID: u.ID, OrgID: u.OrgID, Name: name, CredentialID: []byte(name), UserVerified: true, Epoch: e.fresh(u).CredEpoch}
	if err := e.svc.Passkeys.Create(e.ctx, pk); err != nil {
		e.t.Fatal(err)
	}
	return pk
}

func (e *env) link(u *model.User, p *model.Provider, subject string) *model.Identity {
	e.t.Helper()
	i := model.NewIdentity(e.fresh(u), p, subject, subject+"@example.com", "admin")
	if err := e.svc.Identities.Create(e.ctx, i); err != nil {
		e.t.Fatal(err)
	}
	return i
}

func TestConnectionsAuthorization(t *testing.T) {
	c := newCast(t)
	pk := c.passkey(c.aUser, "yubi")
	for _, tc := range []struct {
		name string
		a    *model.User
		want string
	}{
		{"org admin", c.aAdmin, "ok"},
		{"org manager of a user", c.aManager, "ok"},
		{"other org admin", c.bAdmin, "notfound"},
		{"peer user", c.e2(c.a.ID), "denied"},
	} {
		_, err := c.svc.UserPasskeys(c.ctx, actor(tc.a), c.aUser.ID)
		c.check(t, tc.name+" list passkeys", err, tc.want)
	}
	// A user acts on themselves only through a self-service (re-authenticated) context.
	if _, err := c.svc.UserPasskeys(c.ctx, actor(c.aUser), c.aUser.ID); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("self without re-authentication: %v", err)
	}
	if _, err := c.svc.UserPasskeys(service.SelfService(c.ctx), actor(c.aUser), c.aUser.ID); err != nil {
		t.Errorf("self-service: %v", err)
	}
	if _, err := c.svc.UserPasskeys(c.ctx, nil, c.aUser.ID); err != nil {
		t.Errorf("internal (nil actor): %v", err)
	}
	if _, err := c.svc.UserPasskeys(c.ctx, service.System, "nobody"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
	// Denied removals leave the passkey alone.
	if _, err := c.svc.RemovePasskey(c.ctx, actor(c.bAdmin), c.aUser.ID, pk.ID, ""); err == nil {
		t.Error("cross-org passkey removal allowed")
	}
	if _, err := c.svc.RemovePasskey(c.ctx, actor(c.aUser), c.aUser.ID, pk.ID, ""); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("self removal without re-authentication: %v", err)
	}
	if got, _ := c.svc.CurrentPasskeys(c.ctx, c.fresh(c.aUser)); len(got) != 1 {
		t.Errorf("passkeys after denied removals: %d", len(got))
	}
}

// e2 makes another plain user of org (a peer who may not manage c.aUser).
func (c *cast) e2(orgID string) *model.User { return c.user(orgID, c.next("peer"), model.RoleUser) }

func TestRemovePasskeyByAdmin(t *testing.T) {
	c := newCast(t)
	keep, drop := c.passkey(c.aUser, "keep"), c.passkey(c.aUser, "drop")
	sess := c.session(c.aUser)
	n, err := c.svc.RemovePasskey(c.ctx, actor(c.aAdmin), c.aUser.ID, drop.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if n < 0 {
		t.Errorf("sessions ended %d", n)
	}
	_ = sess
	list, err := c.svc.UserPasskeys(c.ctx, actor(c.aAdmin), c.aUser.ID)
	if err != nil || len(list) != 1 || list[0].ID != keep.ID {
		t.Fatalf("passkeys left: %v %v", list, err)
	}
	if ev := c.audited(c.a.ID, "user.passkey.remove"); len(ev) != 1 {
		t.Errorf("audit events: %d", len(ev))
	}
	if _, err := c.svc.RemovePasskey(c.ctx, actor(c.aAdmin), c.aUser.ID, drop.ID, ""); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("removing it twice: %v", err)
	}
}

func TestRemoveOnlyWayInRefusedForSelf(t *testing.T) {
	c := newCast(t)
	pk := c.passkey(c.aUser, "only")
	ctx := service.SelfService(c.ctx)
	_, err := c.svc.RemovePasskey(ctx, actor(c.aUser), c.aUser.ID, pk.ID, "")
	var fe *service.FieldError
	if !errors.As(err, &fe) || !errors.Is(err, service.ErrConflict) {
		t.Fatalf("only way in removed: %v", err)
	}
	if got, _ := c.svc.CurrentPasskeys(c.ctx, c.fresh(c.aUser)); len(got) != 1 {
		t.Error("passkey gone")
	}
	// With a password as well it may go, and the audit event is the account's own.
	if _, err := c.svc.UpdateUser(c.ctx, service.System, c.aUser.ID, service.UserInput{Password: ptr("correct horse battery")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.RemovePasskey(ctx, actor(c.aUser), c.aUser.ID, pk.ID, ""); err != nil {
		t.Fatal(err)
	}
	if len(c.audited(c.a.ID, "account.passkey.delete")) != 1 {
		t.Error("self removal not audited as account.passkey.delete")
	}
}

func TestTOTPSetAndRemove(t *testing.T) {
	c := newCast(t)
	if err := c.svc.RemoveTOTP(c.ctx, actor(c.aAdmin), c.aUser.ID); !errors.Is(err, service.ErrConflict) {
		t.Errorf("remove with none set: %v", err)
	}
	u, stale := c.fresh(c.aUser), c.fresh(c.aUser)
	if err := c.svc.SetTOTP(c.ctx, u, secure.RandomBytes(20), 1000); err != nil {
		t.Fatal(err)
	}
	got := c.fresh(c.aUser)
	if !got.HasTOTP() || got.MFAEnrolledAt == nil || got.SecurityGen <= c.aUser.SecurityGen {
		t.Fatalf("after SetTOTP: totp %v enrolled %v gen %d", got.HasTOTP(), got.MFAEnrolledAt, got.SecurityGen)
	}
	// a stale copy never overwrites the factor set meanwhile
	if err := c.svc.SetTOTP(c.ctx, stale, secure.RandomBytes(20), 1001); err == nil {
		t.Error("stale SetTOTP applied")
	}
	if err := c.svc.RemoveTOTP(c.ctx, actor(c.bAdmin), c.aUser.ID); err == nil {
		t.Error("cross-org TOTP removal allowed")
	}
	if !c.fresh(c.aUser).HasTOTP() {
		t.Fatal("TOTP removed by a foreign admin")
	}
	if err := c.svc.RemoveTOTP(c.ctx, actor(c.aAdmin), c.aUser.ID); err != nil {
		t.Fatal(err)
	}
	if c.fresh(c.aUser).HasTOTP() {
		t.Error("TOTP still set")
	}
	if len(c.audited(c.a.ID, "user.totp.remove")) != 1 {
		t.Error("removal not audited")
	}
}

func TestRemoveLastSecondFactorWhereRequired(t *testing.T) {
	c := newCast(t)
	// managers need MFA; with a password, a passkey and TOTP the user may drop one factor but not both.
	m := c.aManager
	if _, err := c.svc.UpdateUser(c.ctx, service.System, m.ID, service.UserInput{Password: ptr("correct horse battery")}); err != nil {
		t.Fatal(err)
	}
	pk := c.passkey(m, "k")
	if err := c.svc.SetTOTP(c.ctx, c.fresh(m), secure.RandomBytes(20), 5); err != nil {
		t.Fatal(err)
	}
	ctx := service.SelfService(c.ctx)
	if !c.svc.MFARequired(c.ctx, m) {
		t.Fatal("manager without required MFA")
	}
	if err := c.svc.RemoveTOTP(ctx, actor(m), m.ID); err != nil {
		t.Fatalf("removing one of two factors: %v", err)
	}
	_, err := c.svc.RemovePasskey(ctx, actor(m), m.ID, pk.ID, "")
	if !errors.Is(err, service.ErrConflict) {
		t.Errorf("removing the last second factor: %v", err)
	}
	w, err := c.svc.UserWays(c.ctx, c.fresh(m))
	if err != nil || !w.Password || len(w.Passkeys) != 1 || w.TOTP {
		t.Errorf("ways %+v %v", w, err)
	}
}

func TestMFARequiredByOrgSetting(t *testing.T) {
	c := newCast(t)
	if c.svc.MFARequired(c.ctx, c.aUser) {
		t.Error("plain user requires MFA by default")
	}
	if _, err := c.svc.UpdateOrg(c.ctx, service.System, c.a.ID, service.OrgInput{Settings: &model.OrgSettings{RequireMFA: true}}); err != nil {
		t.Fatal(err)
	}
	if !c.svc.MFARequired(c.ctx, c.aUser) {
		t.Error("org setting ignored")
	}
	ghost := *c.aUser
	ghost.OrgID = "gone"
	if c.svc.MFARequired(c.ctx, &ghost) {
		t.Error("user of a missing org requires MFA")
	}
}

func TestProviderLinksListingAndDisconnect(t *testing.T) {
	c := newCast(t)
	pv, err := c.svc.CreateProvider(c.ctx, service.System, c.a.ID, goodProvider("zeta"))
	if err != nil {
		t.Fatal(err)
	}
	pw, err := c.svc.CreateProvider(c.ctx, service.System, c.a.ID, goodProvider("alpha"))
	if err != nil {
		t.Fatal(err)
	}
	c.link(c.aUser, pv, "s1")
	c.link(c.aUser, pw, "s2")
	ghost := &model.Provider{Meta: model.Meta{ID: "deleted-provider"}}
	c.link(c.aUser, ghost, "s3") // its provider is gone: listed by the placeholder name
	links, err := c.svc.LinkedProviders(c.ctx, c.aUser.ID)
	if err != nil {
		t.Fatal(err)
	}
	// a link to a deleted provider does not count (the sweep removes it), so two are listed, by name
	if len(links) != 2 || links[0].Name != "alpha" || links[1].Name != "zeta" {
		t.Fatalf("links %+v", links)
	}
	if _, err := c.svc.LinkedProviders(c.ctx, "nobody"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
	if _, err := c.svc.DisconnectProvider(c.ctx, actor(c.bAdmin), c.aUser.ID, pv.ID); err == nil {
		t.Error("cross-org disconnect allowed")
	}
	if n, err := c.svc.DisconnectProvider(c.ctx, actor(c.aAdmin), c.aUser.ID, pv.ID); err != nil || n != 1 {
		t.Fatalf("disconnect: %d %v", n, err)
	}
	if _, err := c.svc.DisconnectProvider(c.ctx, actor(c.aAdmin), c.aUser.ID, pv.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("disconnect twice: %v", err)
	}
	ids, _ := c.svc.CurrentIdentities(c.ctx, c.fresh(c.aUser))
	for _, i := range ids {
		if i.ProviderID == pv.ID {
			t.Error("link survived")
		}
	}
	if len(c.audited(c.a.ID, "user.provider.disconnect")) != 1 {
		t.Error("disconnect not audited")
	}
	// the user's only way in: refused for themselves
	if _, err := c.svc.DisconnectProvider(service.SelfService(c.ctx), actor(c.aUser), c.aUser.ID, pw.ID); !errors.Is(err, service.ErrConflict) {
		t.Errorf("last way in: %v", err)
	}
}

func TestConnectedAppsAndRemoveUserApp(t *testing.T) {
	c := newCast(t)
	mk := func(name string) *model.Client {
		cl, _, err := c.svc.CreateClient(c.ctx, service.System, c.a.ID, service.ClientInput{Name: ptr(name),
			RedirectURIs: ptr([]string{"https://app.example.com/cb"})})
		if err != nil {
			t.Fatal(err)
		}
		return cl
	}
	b, a := mk("Bravo"), mk("alpha")
	grant := func(cl *model.Client, clientID string, scopes []string) *model.Grant {
		g := &model.Grant{UserID: c.aUser.ID, OrgID: c.a.ID, ClientID: clientID, Scopes: scopes}
		if err := c.svc.Grants.Create(c.ctx, g); err != nil {
			t.Fatal(err)
		}
		return g
	}
	grant(b, b.ID, []string{"openid", "email"})
	grant(b, b.ID, []string{"openid", "profile"})
	grant(a, a.ID, []string{"openid"})
	grant(nil, "removed-client", nil)
	revoked := grant(nil, "revoked-client", nil)
	revoked.Revoked = true
	if err := c.svc.Grants.Update(c.ctx, revoked); err != nil {
		t.Fatal(err)
	}
	apps, err := c.svc.ConnectedApps(c.ctx, c.aUser.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 3 || apps[0].Name != "alpha" || apps[1].Name != "Bravo" || apps[2].Name != "Removed application" {
		t.Fatalf("apps %+v", apps)
	}
	if apps[1].Grants != 2 || len(apps[1].Scopes) != 3 || apps[1].Scopes[0] != "email" {
		t.Errorf("grouping %+v", apps[1])
	}
	if _, err := c.svc.RemoveUserApp(c.ctx, actor(c.bAdmin), c.aUser.ID, b.ID); err == nil {
		t.Error("cross-org app removal allowed")
	}
	var told []string
	c.svc.OnAppAccessEnding = func(_ context.Context, user, client string) { told = append(told, user+"/"+client) }
	if n, err := c.svc.RemoveUserApp(c.ctx, actor(c.aAdmin), c.aUser.ID, b.ID); err != nil || n != 2 {
		t.Fatalf("remove: %d %v", n, err)
	}
	if len(told) != 1 || told[0] != c.aUser.ID+"/"+b.ID {
		t.Errorf("application told %v", told)
	}
	if n, err := c.svc.RemoveUserApp(c.ctx, actor(c.aAdmin), c.aUser.ID, b.ID); err != nil || n != 0 {
		t.Errorf("second removal: %d %v", n, err)
	}
	if ev := c.audited(c.a.ID, "user.app.revoke"); len(ev) != 1 {
		t.Errorf("audit events %d", len(ev))
	}
	if _, err := c.svc.RemoveUserApp(c.ctx, actor(c.aAdmin), "nobody", b.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
}
