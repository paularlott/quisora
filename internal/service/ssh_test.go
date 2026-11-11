package service_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/sshca"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// sshWorld is an organization with an open tenant, an administrator and SSH ready to enable.
type sshWorld struct {
	*env
	org    *model.Org
	tenant *model.Tenant
	admin  *model.User
}

func newSSHWorld(t *testing.T) *sshWorld {
	t.Helper()
	return sshWorldOn(t, newEnv(t))
}

func sshWorldOn(t *testing.T, e *env) *sshWorld {
	t.Helper()
	org := e.org("acme")
	ten := e.tenant(org.ID, "prod")
	open := ten.Settings
	open.MembersOnly = false
	ten, err := e.svc.UpdateTenant(e.ctx, service.System, ten.ID, service.TenantInput{Settings: &open})
	if err != nil {
		t.Fatal(err)
	}
	return &sshWorld{env: e, org: org, tenant: ten, admin: e.user(org.ID, "boss", model.RoleAdmin)}
}

// set changes the tenant's SSH settings as the organization's administrator.
func (w *sshWorld) set(in service.SSHSettingsInput) *model.Tenant {
	w.t.Helper()
	t, err := w.svc.UpdateTenantSSH(w.ctx, actor(w.admin), w.tenant.ID, in)
	if err != nil {
		w.t.Fatalf("update ssh settings: %v", err)
	}
	w.tenant = t
	return t
}

func (w *sshWorld) enable(in ...service.SSHSettingsInput) *model.Tenant {
	w.t.Helper()
	var s service.SSHSettingsInput
	if len(in) > 0 {
		s = in[0]
	}
	s.Enabled = ptr(true)
	return w.set(s)
}

// reload is the tenant as stored.
func (w *sshWorld) reload() *model.Tenant {
	w.t.Helper()
	t, err := w.svc.Tenants.Get(w.ctx, w.tenant.ID)
	if err != nil {
		w.t.Fatal(err)
	}
	return t
}

func newPub(t testing.TB) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshca.AuthorizedKey(k) + " test@laptop"
}

// req is a good request for u's certificate: signed in with password and a one-time code a minute ago, in the user's
// current session epoch and under the current sign-out stamp.
func (w *sshWorld) req(u *model.User) service.SSHUserRequest {
	clientID := ""
	if t := w.reload(); t.SSH != nil {
		clientID = t.SSH.ClientID
	}
	u = w.fresh(u)
	return service.SSHUserRequest{User: u, TenantID: w.tenant.ID, ClientID: clientID, PublicKey: newPub(w.t),
		AMR: []string{"pwd", "otp"}, AuthTime: time.Now().Add(-time.Minute), Via: "cli", SessionEpoch: u.SessionEpoch, Stamp: w.stamp(u.OrgID)}
}

// stamp is the sign-out stamp of organization orgID now.
func (w *sshWorld) stamp(orgID string) model.SignOutStamp {
	w.t.Helper()
	st, err := w.svc.SessionStamp(w.ctx, orgID)
	if err != nil {
		w.t.Fatal(err)
	}
	return st
}

func (w *sshWorld) sign(u *model.User, mut ...func(*service.SSHUserRequest)) (*service.SSHIssued, error) {
	r := w.req(u)
	for _, m := range mut {
		m(&r)
	}
	return w.svc.SignUserSSH(w.ctx, r)
}

func (w *sshWorld) mustSign(u *model.User, mut ...func(*service.SSHUserRequest)) *service.SSHIssued {
	w.t.Helper()
	got, err := w.sign(u, mut...)
	if err != nil {
		w.t.Fatalf("sign for %s: %v", u.Username, err)
	}
	return got
}

func parseCert(t testing.TB, line string) *ssh.Certificate {
	t.Helper()
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	c, ok := k.(*ssh.Certificate)
	if !ok {
		t.Fatalf("%T is not a certificate", k)
	}
	return c
}

// revokedFor returns the reasons by serial for the tenant's revoked certificates.
func (w *sshWorld) revokedFor() map[uint64]string {
	w.t.Helper()
	list, err := w.svc.SSHRevoked(w.ctx, w.tenant.ID)
	if err != nil {
		w.t.Fatal(err)
	}
	out := map[uint64]string{}
	for _, r := range list {
		out[r.Cert.Serial] = r.Reason
	}
	return out
}

// reasonOf is why cert is revoked ("" when it is not).
func (w *sshWorld) reasonOf(c *service.SSHIssued) string { return w.revokedFor()[c.Cert.Serial] }

func (w *sshWorld) refusedReasons() []string {
	var out []string
	for _, a := range w.audits("ssh.cert.refused") {
		out = append(out, a.Detail["reason"])
	}
	return out
}

func keysOf(t testing.TB, w *sshWorld, purpose string) []*model.SSHKey {
	t.Helper()
	ks, err := w.svc.SSHKeys(w.ctx, w.tenant.ID, purpose)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func sshClientsOf(t testing.TB, w *sshWorld) []*model.Client {
	t.Helper()
	cs, _, err := w.svc.Clients.List(w.ctx, store.ListQuery{Scope: w.org.ID, Filters: []store.Filter{{Field: "tenant_id", Value: w.tenant.ID}}})
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// ---- enabling ----

func TestSSHEnableMakesOneKeyAndOneApplication(t *testing.T) {
	w := newSSHWorld(t)
	if got := w.reload().SSH; got != nil {
		t.Fatalf("a new tenant has SSH settings: %+v", got)
	}
	got := w.enable()
	set := got.SSH
	d := model.DefaultTenantSSH()
	d.Enabled, d.ClientID = true, set.ClientID
	if !equalSSH(*set, d) {
		t.Errorf("enabling did not start from the defaults:\n got %+v\nwant %+v", *set, d)
	}
	if ks := keysOf(t, w, ""); len(ks) != 1 || ks[0].Purpose != "user" || ks[0].Alg != "ssh-ed25519" || !strings.HasPrefix(ks[0].PublicKey, "ssh-ed25519 ") {
		t.Fatalf("keys after enabling: %+v", ks)
	} else if ks[0].NotBefore.After(time.Now()) || ks[0].PrivateKey == "" || strings.Contains(ks[0].PrivateKey, "OPENSSH") {
		t.Errorf("the key must sign from now and be stored sealed: %+v", ks[0])
	}
	cs := sshClientsOf(t, w)
	if len(cs) != 1 {
		t.Fatalf("clients after enabling: %d", len(cs))
	}
	c := cs[0]
	if c.ID != set.ClientID || c.Name != "SSH" || !c.Public() || !c.FirstParty || c.DevicePrivileged || !c.Enabled ||
		!slices.Equal(c.RedirectURIs, []string{"http://127.0.0.1/callback"}) || !slices.Equal(c.Scopes, []string{"openid", "profile"}) ||
		slices.Contains(c.GrantTypes, "refresh_token") || !slices.Contains(c.GrantTypes, service.GrantDeviceCode) || !slices.Contains(c.GrantTypes, "authorization_code") {
		t.Errorf("the SSH application: %+v", c)
	}
	if n := len(w.audits("ssh.ca.create")); n != 1 {
		t.Errorf("%d ssh.ca.create events", n)
	}
	ev := w.lastAudit("ssh.settings.update")
	if ev.Detail["changed.enabled"] != "false → true" || ev.Detail["changed.client_id"] == "" {
		t.Errorf("settings audit: %v", ev.Detail)
	}

	// enabling again, changing something, and turning SSH off and on again make nothing new
	w.enable()
	w.set(service.SSHSettingsInput{CertTTL: ptr(3600)})
	w.set(service.SSHSettingsInput{Enabled: ptr(false)})
	if cs := sshClientsOf(t, w); len(cs) != 1 || cs[0].Enabled {
		t.Errorf("turning SSH off leaves its application enabled: %+v", cs)
	}
	w.set(service.SSHSettingsInput{Enabled: ptr(true)})
	if cs := sshClientsOf(t, w); len(cs) != 1 || !cs[0].Enabled {
		t.Errorf("turning SSH on again leaves its application disabled: %+v", cs)
	}
	if len(keysOf(t, w, "")) != 1 || len(sshClientsOf(t, w)) != 1 || len(w.audits("ssh.ca.create")) != 1 {
		t.Errorf("re-enabling duplicated the key or the application: %d keys, %d clients", len(keysOf(t, w, "")), len(sshClientsOf(t, w)))
	}

	// host certificates add the host key, once
	w.set(service.SSHSettingsInput{HostCerts: ptr(true), HostPatterns: &[]string{"*.example.com"}})
	w.set(service.SSHSettingsInput{HostTTLDays: ptr(30)})
	if ks := keysOf(t, w, "host"); len(ks) != 1 || len(keysOf(t, w, "user")) != 1 {
		t.Errorf("host keys %d, user keys %d", len(ks), len(keysOf(t, w, "user")))
	}

	// a deleted application is made again by enabling again
	if err := w.svc.DeleteClient(w.ctx, service.System, set.ClientID); err != nil {
		t.Fatal(err)
	}
	again := w.enable()
	if again.SSH.ClientID == "" || again.SSH.ClientID == set.ClientID || len(sshClientsOf(t, w)) != 1 {
		t.Errorf("the application was not made again: %q (was %q), %d clients", again.SSH.ClientID, set.ClientID, len(sshClientsOf(t, w)))
	}
}

func equalSSH(a, b model.TenantSSH) bool {
	return a.Enabled == b.Enabled && a.ClientID == b.ClientID && a.CertTTL == b.CertTTL && a.MaxAuthAge == b.MaxAuthAge &&
		a.PrincipalUsername == b.PrincipalUsername && a.PrincipalGroups == b.PrincipalGroups && a.PrincipalRoles == b.PrincipalRoles &&
		a.PermitPTY == b.PermitPTY && a.PermitUserRC == b.PermitUserRC && a.PermitPortForwarding == b.PermitPortForwarding &&
		a.PermitAgentForwarding == b.PermitAgentForwarding && a.PermitX11Forwarding == b.PermitX11Forwarding &&
		slices.Equal(a.SourceAddresses, b.SourceAddresses) && a.AllowPrivileged == b.AllowPrivileged && a.RotationDays == b.RotationDays &&
		a.HostCerts == b.HostCerts && a.HostTTLDays == b.HostTTLDays && slices.Equal(a.HostPatterns, b.HostPatterns)
}

func TestSSHDefaults(t *testing.T) {
	d := model.DefaultTenantSSH()
	if d.CertTTL != 28800 || d.MaxAuthAge != 3600 || !d.PrincipalUsername || !d.PrincipalGroups || d.PrincipalRoles ||
		!d.PermitPTY || !d.PermitUserRC || d.PermitPortForwarding || d.PermitAgentForwarding || d.PermitX11Forwarding ||
		d.AllowPrivileged || d.RotationDays != 0 || d.HostCerts || d.HostTTLDays != 90 || d.Enabled {
		t.Errorf("defaults: %+v", d)
	}
}

func TestSSHSettingsAreValidated(t *testing.T) {
	w := newSSHWorld(t)
	bad := []struct {
		field string
		in    service.SSHSettingsInput
	}{
		{"ssh.cert_ttl", service.SSHSettingsInput{CertTTL: ptr(299)}},
		{"ssh.cert_ttl", service.SSHSettingsInput{CertTTL: ptr(86401)}},
		{"ssh.max_auth_age", service.SSHSettingsInput{MaxAuthAge: ptr(59)}},
		{"ssh.max_auth_age", service.SSHSettingsInput{MaxAuthAge: ptr(86401)}},
		{"ssh.source_addresses", service.SSHSettingsInput{SourceAddresses: &[]string{"not an address"}}},
		{"ssh.rotation_days", service.SSHSettingsInput{RotationDays: ptr(3)}},
		{"ssh.rotation_days", service.SSHSettingsInput{RotationDays: ptr(-1)}},
		{"ssh.host_ttl_days", service.SSHSettingsInput{HostTTLDays: ptr(0)}},
		{"ssh.host_ttl_days", service.SSHSettingsInput{HostTTLDays: ptr(366)}},
		{"ssh.host_patterns", service.SSHSettingsInput{HostPatterns: &[]string{"Bad Pattern!"}}},
		{"ssh.host_patterns", service.SSHSettingsInput{HostCerts: ptr(true)}}, // patterns are required
	}
	for _, c := range bad {
		if _, err := w.svc.UpdateTenantSSH(w.ctx, actor(w.admin), w.tenant.ID, c.in); fieldOf(err) != c.field {
			t.Errorf("%s: %v", c.field, err)
		}
	}
	if w.reload().SSH != nil || len(sshClientsOf(t, w)) != 0 {
		t.Error("a refused change left something behind")
	}
	got := w.set(service.SSHSettingsInput{CertTTL: ptr(300), MaxAuthAge: ptr(86400), RotationDays: ptr(8), HostTTLDays: ptr(365),
		SourceAddresses: &[]string{"10.0.0.0/8", "192.0.2.7/24", "10.0.0.0/8"}, HostPatterns: &[]string{" *.Example.com ", "db1.internal", "*.example.com"}})
	if !slices.Equal(got.SSH.SourceAddresses, []string{"10.0.0.0/8", "192.0.2.0/24"}) || !slices.Equal(got.SSH.HostPatterns, []string{"*.example.com", "db1.internal"}) {
		t.Errorf("normalized: %v %v", got.SSH.SourceAddresses, got.SSH.HostPatterns)
	}
	if got.SSH.Enabled || len(keysOf(t, w, "")) != 0 {
		t.Error("changing settings of a tenant that never enabled SSH enabled it")
	}
	if len(w.audits("ssh.ca.create")) != 0 {
		t.Error("a key was made while SSH is off")
	}
	// nil keeps: a second change leaves the first alone
	got = w.set(service.SSHSettingsInput{PermitPortForwarding: ptr(true)})
	if got.SSH.CertTTL != 300 || !got.SSH.PermitPortForwarding || got.SSH.RotationDays != 8 {
		t.Errorf("omitted settings did not keep their values: %+v", got.SSH)
	}
	ev := w.lastAudit("ssh.settings.update")
	if len(ev.Detail) != 1 || ev.Detail["changed.permit_port_forwarding"] != "false → true" {
		t.Errorf("only the change is audited: %v", ev.Detail)
	}
}

func TestSSHAllowPrivilegedFollowsTheApplication(t *testing.T) {
	w := newSSHWorld(t)
	set := w.enable().SSH
	client := func() *model.Client {
		c, err := w.svc.Clients.Get(w.ctx, set.ClientID)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if client().DevicePrivileged {
		t.Fatal("privileged users may approve the device flow by default")
	}
	w.set(service.SSHSettingsInput{AllowPrivileged: ptr(true)})
	if !client().DevicePrivileged {
		t.Error("allow_privileged did not reach the application")
	}
	w.set(service.SSHSettingsInput{AllowPrivileged: ptr(false)})
	if client().DevicePrivileged {
		t.Error("withdrawing allow_privileged did not reach the application")
	}
}

func TestSSHTenantSettingsSurviveATenantUpdate(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	if _, err := w.svc.UpdateTenant(w.ctx, service.System, w.tenant.ID, service.TenantInput{DisplayName: ptr("Prod")}); err != nil {
		t.Fatal(err)
	}
	if got := w.reload().SSH; got == nil || !got.Enabled {
		t.Errorf("a tenant update dropped the SSH settings: %+v", got)
	}
}

func TestSSHSettingsPermissions(t *testing.T) {
	w := newSSHWorld(t)
	manager := w.user(w.org.ID, "mgr", model.RoleManager)
	plain := w.user(w.org.ID, "plain", model.RoleUser)
	other := w.env.org("globex")
	otherAdmin := w.user(other.ID, "otherboss", model.RoleAdmin)
	sa := func(org string, scopes ...string) *service.Actor {
		return &service.Actor{OrgID: org, Role: model.RoleAdmin, Name: "service:x", ClientID: "c1", Scopes: scopes}
	}
	cases := []struct {
		who  string
		a    *service.Actor
		want string
	}{
		{"admin", actor(w.admin), "ok"},
		{"super admin", actor(w.super), "ok"},
		{"manager", actor(manager), "forbidden"},
		{"user", actor(plain), "forbidden"},
		{"another organization's admin", actor(otherAdmin), "notfound"},
		{"service account with ssh", sa(w.org.ID, service.ScopeSSH), "ok"},
		{"service account without ssh", sa(w.org.ID, service.ScopeTenants, service.ScopeSSHHost), "forbidden"},
		{"service account of another organization", sa(other.ID, service.ScopeSSH), "notfound"},
	}
	for _, c := range cases {
		ctx, a := w.ctx, c.a
		if got := outcome(errOf(w.svc.UpdateTenantSSH(ctx, a, w.tenant.ID, service.SSHSettingsInput{CertTTL: ptr(1800)}))); got != c.want {
			t.Errorf("update by %s: %s, want %s", c.who, got, c.want)
		}
		if got := outcome(errOf(w.svc.GetTenantSSH(ctx, a, w.tenant.ID))); got != c.want {
			t.Errorf("read by %s: %s, want %s", c.who, got, c.want)
		}
		if got := outcome(errOf(w.svc.ListSSHCerts(ctx, a, w.tenant.ID, service.SSHCertFilter{}))); got != c.want {
			t.Errorf("list by %s: %s, want %s", c.who, got, c.want)
		}
		if c.want != "ok" { // (a rotation by someone who may is checked in the rotation tests)
			if got := outcome(errOf(w.svc.RotateSSHKey(ctx, a, w.tenant.ID, "user", false))); got != c.want {
				t.Errorf("rotate by %s: %s, want %s", c.who, got, c.want)
			}
		}
	}
	if _, err := w.svc.GetTenantSSH(w.ctx, actor(w.admin), "nope"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown tenant: %v", err)
	}
}

func errOf[T any](_ T, err error) error { return err }

func TestSSHGetTenantSSHShowsKeys(t *testing.T) {
	w := newSSHWorld(t)
	v, err := w.svc.GetTenantSSH(w.ctx, actor(w.admin), w.tenant.ID)
	if err != nil || v.Settings.Enabled || len(v.Keys) != 0 || v.Settings.CertTTL != 28800 {
		t.Fatalf("before enabling: %+v %v", v, err)
	}
	w.enable(service.SSHSettingsInput{HostCerts: ptr(true), HostPatterns: &[]string{"*.example.com"}})
	v, err = w.svc.GetTenantSSH(w.ctx, actor(w.admin), w.tenant.ID)
	if err != nil || len(v.Keys) != 2 {
		t.Fatalf("keys: %+v %v", v, err)
	}
	for _, k := range v.Keys {
		pub, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(k.PublicKey))
		if perr != nil || k.Fingerprint != ssh.FingerprintSHA256(pub) || k.State != service.SSHKeyActive {
			t.Errorf("key %+v: %v", k, perr)
		}
	}
	if v.Keys[0].Purpose != "user" || v.Keys[1].Purpose != "host" {
		t.Errorf("order %s %s", v.Keys[0].Purpose, v.Keys[1].Purpose)
	}
}

func TestSSHTenantByRef(t *testing.T) {
	w := newSSHWorld(t)
	if _, err := w.svc.SSHTenantByRef(w.ctx, w.org.ID, w.tenant.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("SSH off: %v", err)
	}
	w.enable()
	for _, ref := range []string{w.tenant.ID, "prod", "PROD"} {
		got, err := w.svc.SSHTenantByRef(w.ctx, w.org.ID, ref)
		if err != nil || got.ID != w.tenant.ID {
			t.Errorf("%q: %v", ref, err)
		}
	}
	other := w.env.org("globex")
	for _, c := range []struct{ org, ref string }{{other.ID, w.tenant.ID}, {other.ID, "prod"}, {w.org.ID, "nope"}, {w.org.ID, "0000000000000000000000"}} {
		if _, err := w.svc.SSHTenantByRef(w.ctx, c.org, c.ref); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("%+v: %v", c, err)
		}
	}
	w.set(service.SSHSettingsInput{Enabled: ptr(false)})
	if _, err := w.svc.SSHTenantByRef(w.ctx, w.org.ID, "prod"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("disabled again: %v", err)
	}
}

// ---- user certificates ----

func TestSignUserCertificate(t *testing.T) {
	w := newSSHWorld(t)
	w.enable(service.SSHSettingsInput{SourceAddresses: &[]string{"10.0.0.0/8", "192.0.2.1"}, PermitAgentForwarding: ptr(true)})
	u := w.user(w.org.ID, "paul", model.RoleUser)
	ops := w.group(w.org.ID, "ops", u)
	w.group(w.org.ID, "Not Valid!", u) // a group name that is no principal is skipped
	before := time.Now()
	r := w.req(u)
	got, err := w.svc.SignUserSSH(w.ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	cert := parseCert(t, got.Certificate)
	if cert.CertType != ssh.UserCert || cert.Serial == 0 || cert.Serial != got.Cert.Serial {
		t.Errorf("cert %+v", cert)
	}
	if want := "paul@acme/" + u.ID; cert.KeyId != want || got.Cert.KeyID != want {
		t.Errorf("key id %q, want %q", cert.KeyId, want)
	}
	if !slices.Equal(cert.ValidPrincipals, []string{"group:ops", "paul"}) {
		t.Errorf("principals %v", cert.ValidPrincipals)
	}
	after, until := time.Unix(int64(cert.ValidAfter), 0), time.Unix(int64(cert.ValidBefore), 0)
	if d := before.Add(-5 * time.Minute).Sub(after); d > 2*time.Second || d < -2*time.Second {
		t.Errorf("valid after %v is not five minutes before now", after)
	}
	if d := until.Sub(before); d < 8*time.Hour-2*time.Second || d > 8*time.Hour+2*time.Second {
		t.Errorf("valid for %v, want 8h", d)
	}
	for _, ext := range []string{"permit-pty", "permit-user-rc", "permit-agent-forwarding"} {
		if _, ok := cert.Extensions[ext]; !ok {
			t.Errorf("no %s", ext)
		}
	}
	for _, ext := range []string{"permit-port-forwarding", "permit-X11-forwarding"} {
		if _, ok := cert.Extensions[ext]; ok {
			t.Errorf("%s granted", ext)
		}
	}
	if cert.CriticalOptions["source-address"] != "10.0.0.0/8,192.0.2.1" {
		t.Errorf("critical options %v", cert.CriticalOptions)
	}
	// signed by the tenant's user CA, for the key asked
	keys := keysOf(t, w, "user")
	ca, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(keys[0].PublicKey))
	if !bytes.Equal(cert.SignatureKey.Marshal(), ca.Marshal()) || got.Cert.CAKeyID != keys[0].ID {
		t.Error("signed by another key")
	}
	asked, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(r.PublicKey))
	if !bytes.Equal(cert.Key.Marshal(), asked.Marshal()) || got.Cert.Fingerprint != ssh.FingerprintSHA256(asked) {
		t.Error("certified another key")
	}
	checker := &ssh.CertChecker{SupportedCriticalOptions: []string{"source-address"}, IsUserAuthority: func(a ssh.PublicKey) bool { return bytes.Equal(a.Marshal(), ca.Marshal()) }}
	if err := checker.CheckCert("group:ops", cert); err != nil {
		t.Errorf("CheckCert: %v", err)
	}
	// the record
	rec, err := w.svc.SSHCerts.Get(w.ctx, got.Cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.UserID != u.ID || rec.Host || rec.TenantID != w.tenant.ID || rec.OrgID != w.org.ID || rec.Via != "cli" || rec.Revoked ||
		rec.SessionEpoch != r.SessionEpoch || rec.Stamp != r.Stamp || !slices.Equal(rec.Principals, cert.ValidPrincipals) ||
		!slices.Equal(rec.Extensions, []string{"permit-agent-forwarding", "permit-pty", "permit-user-rc"}) ||
		!slices.Equal(rec.SourceAddresses, []string{"10.0.0.0/8", "192.0.2.1"}) ||
		rec.ValidBefore.Unix() != int64(cert.ValidBefore) || rec.Index().Expires.Unix() != int64(cert.ValidBefore)+3600 {
		t.Errorf("record %+v", rec)
	}
	// the audit event
	ev := w.lastAudit("ssh.cert.issue")
	if ev.Detail["serial"] == "" || ev.Detail["principals"] != "group:ops,paul" || ev.Detail["fingerprint"] != rec.Fingerprint ||
		ev.Detail["via"] != "cli" || ev.Detail["amr"] != "pwd,otp" || ev.Detail["valid_before"] == "" || ev.TargetID != u.ID {
		t.Errorf("issue audit: %+v", ev)
	}
	_ = ops
}

func TestSignUserCertificateRefusals(t *testing.T) {
	w := newSSHWorld(t)
	u := w.user(w.org.ID, "paul", model.RoleUser)
	// 1. SSH not enabled (never set up, then off)
	if _, err := w.sign(u, func(r *service.SSHUserRequest) { r.ClientID = "" }); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("SSH never enabled: %v", err)
	}
	w.enable()
	w.mustSign(u)
	w.set(service.SSHSettingsInput{Enabled: ptr(false)})
	if _, err := w.sign(u, func(r *service.SSHUserRequest) { r.ClientID = "" }); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("SSH off: %v", err)
	}
	w.enable()

	var ref *service.SSHRefusal
	refused := func(name string, mut func(*service.SSHUserRequest)) {
		t.Helper()
		_, err := w.sign(u, mut)
		if !errors.Is(err, service.ErrForbidden) || !errors.As(err, &ref) || ref.Msg == "" {
			t.Errorf("%s: %v, want a refusal", name, err)
		}
	}
	// 2. another client's token
	refused("wrong client", func(r *service.SSHUserRequest) { r.ClientID = "someone-else" })
	// 3. a second factor is always required
	refused("password only", func(r *service.SSHUserRequest) { r.AMR = []string{"pwd"} })
	refused("no amr", func(r *service.SSHUserRequest) { r.AMR = nil })
	// 4. an old sign-in
	refused("old sign-in", func(r *service.SSHUserRequest) { r.AuthTime = time.Now().Add(-61 * time.Minute) })
	refused("no sign-in time", func(r *service.SSHUserRequest) { r.AuthTime = time.Time{} })
	// 4b. the sign-in it stands on (the token's grant, the session) has ended since: its epoch and stamp are those of
	// the request, not the user's current ones
	early := w.req(u)
	if err := w.svc.RevokeSessions(w.ctx, service.System, u.ID); err != nil {
		t.Fatal(err)
	}
	refused("signed out everywhere", func(r *service.SSHUserRequest) { r.SessionEpoch = early.SessionEpoch })
	early = w.req(u)
	if _, err := w.svc.SignOutOrg(w.ctx, service.System, w.org.ID, service.SignOutOptions{Reason: "drill"}); err != nil {
		t.Fatal(err)
	}
	refused("emergency sign-out", func(r *service.SSHUserRequest) { r.Stamp = early.Stamp })
	// accepted: a passkey with user verification, or one-time codes
	w.mustSign(u, func(r *service.SSHUserRequest) { r.AMR = []string{"hwk", "user"} })
	w.mustSign(u, func(r *service.SSHUserRequest) { r.AMR = []string{"mfa"} })
	w.mustSign(u, func(r *service.SSHUserRequest) { r.AuthTime = time.Now().Add(-59 * time.Minute) })
	// 5. a user that cannot be used: disabled
	off := w.user(w.org.ID, "off", model.RoleUser)
	if _, err := w.svc.UpdateUser(w.ctx, service.System, off.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.sign(off); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("disabled user: %v", err)
	}
	// 6. privileged accounts, unless the tenant allows them
	mgr := w.user(w.org.ID, "mgr", model.RoleManager)
	if _, err := w.sign(mgr); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("manager: %v", err)
	}
	if _, err := w.sign(w.admin); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("administrator: %v", err)
	}
	w.set(service.SSHSettingsInput{AllowPrivileged: ptr(true)})
	w.mustSign(mgr)
	w.mustSign(w.admin)
	w.set(service.SSHSettingsInput{AllowPrivileged: ptr(false)})
	// 7. keys
	for name, key := range map[string]string{"empty": "", "junk": "hello", "certificate": mustSignLine(t, w, u),
		"short rsa": rsaLine(t, 1024), "dsa": "ssh-dss AAAAB3NzaC1kc3MAAACBAOmZlKVsMdUt", "two keys": newPub(t) + "\n" + newPub(t)} {
		if _, err := w.sign(u, func(r *service.SSHUserRequest) { r.PublicKey = key }); fieldOf(err) != "public_key" {
			t.Errorf("%s: %v", name, err)
		}
	}
	w.mustSign(u, func(r *service.SSHUserRequest) { r.PublicKey = rsaLine(t, 2048) })
	// 8. principals
	if _, err := w.sign(u, func(r *service.SSHUserRequest) { r.Principals = []string{"root"} }); fieldOf(err) != "principals" {
		t.Errorf("a principal the user may not have: %v", err)
	}
	w.set(service.SSHSettingsInput{PrincipalUsername: ptr(false), PrincipalGroups: ptr(false), PrincipalRoles: ptr(true)}) // roles it has none of
	refused("no principals", func(r *service.SSHUserRequest) {})
	w.set(service.SSHSettingsInput{PrincipalUsername: ptr(true), PrincipalRoles: ptr(false)})
	// the user key gone: nothing to sign with
	for _, k := range keysOf(t, w, "user") {
		if err := w.svc.SSHCAKeys.Delete(w.ctx, k.ID); err != nil {
			t.Fatal(err)
		}
	}
	refused("no CA key", func(r *service.SSHUserRequest) {})

	// every refusal is audited with its reason
	got := w.refusedReasons()
	for _, want := range []string{"not_enabled", "wrong_client", "mfa_required", "auth_too_old", "session_ended", "user_unusable", "privileged",
		"bad_key", "bad_principal", "no_principals", "no_user_key"} {
		if !slices.Contains(got, want) {
			t.Errorf("no ssh.cert.refused event with reason %q (got %v)", want, got)
		}
	}
	for _, a := range w.audits("ssh.cert.refused") {
		if a.Outcome != "failure" || a.Detail["tenant"] != "prod" {
			t.Errorf("refusal audit: %+v", a)
		}
	}
}

func mustSignLine(t testing.TB, w *sshWorld, u *model.User) string {
	t.Helper()
	return w.mustSign(u).Certificate
}

func rsaLine(t testing.TB, bits int) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := ssh.NewPublicKey(&k.PublicKey)
	return sshca.AuthorizedKey(p)
}

func TestSignUserNeedsAccessToTheTenant(t *testing.T) {
	w := newSSHWorld(t)
	closed := w.tenant.Settings
	closed.MembersOnly = true
	if _, err := w.svc.UpdateTenant(w.ctx, service.System, w.tenant.ID, service.TenantInput{Settings: &closed}); err != nil {
		t.Fatal(err)
	}
	w.enable()
	u := w.user(w.org.ID, "paul", model.RoleUser)
	if _, err := w.sign(u); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("a user with no access: %v", err)
	}
	if got := w.refusedReasons(); !slices.Contains(got, "no_access") {
		t.Errorf("refusal reasons %v", got)
	}
	ent, err := w.svc.AddAccess(w.ctx, service.System, w.tenant.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: u.ID})
	if err != nil {
		t.Fatal(err)
	}
	w.mustSign(u)
	// an access that covers other applications only does not cover SSH
	if _, err := w.svc.UpdateAccess(w.ctx, service.System, w.tenant.ID, ent.ID, service.AccessInput{
		AllClients: ptr(false), Clients: &[]string{w.client(w.org.ID, "other").ID}}); err == nil {
		t.Fatal("an access for a client of another tenant was accepted")
	}
	// access through a group, and an end date
	g := w.group(w.org.ID, "eng")
	if err := w.svc.RemoveAccess(w.ctx, service.System, w.tenant.ID, ent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.sign(u); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("after the access was removed: %v", err)
	}
	if _, err := w.svc.AddAccess(w.ctx, service.System, w.tenant.ID, service.AccessInput{SubjectType: model.SubjectGroup, SubjectID: g.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.sign(u); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("not in the group yet: %v", err)
	}
	if err := w.svc.SetMembership(w.ctx, service.System, g.ID, u.ID, true); err != nil {
		t.Fatal(err)
	}
	w.mustSign(u)
	// the user's account is in another organization: never
	other := w.env.org("globex")
	stranger := w.user(other.ID, "paul", model.RoleUser)
	r := w.req(w.user(w.org.ID, "x", model.RoleUser))
	r.User = stranger
	if _, err := w.svc.SignUserSSH(w.ctx, r); err == nil {
		t.Error("a user of another organization got a certificate")
	}
}

func TestSSHPrincipalSources(t *testing.T) {
	w := newSSHWorld(t)
	closed := w.tenant.Settings
	closed.MembersOnly = true
	if _, err := w.svc.UpdateTenant(w.ctx, service.System, w.tenant.ID, service.TenantInput{Settings: &closed}); err != nil {
		t.Fatal(err)
	}
	w.enable()
	u := w.user(w.org.ID, "paul", model.RoleUser)
	ops, dba := w.group(w.org.ID, "ops", u), w.group(w.org.ID, "dba", u)
	w.group(w.org.ID, "has space", u)
	w.group(w.org.ID, strings.Repeat("x", 65), u)
	w.group(w.org.ID, "a.b_c-d@e", u)
	byUser := service.AccessInput{SubjectType: model.SubjectUser, SubjectID: u.ID, Roles: &[]string{"deploy", "root"}}
	if _, err := w.svc.AddAccess(w.ctx, service.System, w.tenant.ID, byUser); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.AddAccess(w.ctx, service.System, w.tenant.ID, service.AccessInput{SubjectType: model.SubjectGroup, SubjectID: ops.ID,
		Roles: &[]string{"on-call", "deploy"}}); err != nil {
		t.Fatal(err)
	}
	_ = dba
	principals := func() []string {
		t.Helper()
		got, err := w.svc.SSHPrincipals(w.ctx, w.reload(), w.fresh(u))
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	// default: username and groups ("group:" and the name); names that cannot be principals are skipped, not refused
	if got, want := principals(), []string{"group:a.b_c-d@e", "group:dba", "group:ops", "paul"}; !slices.Equal(got, want) {
		t.Errorf("default principals %v, want %v", got, want)
	}
	w.set(service.SSHSettingsInput{PrincipalGroups: ptr(false)})
	if got := principals(); !slices.Equal(got, []string{"paul"}) {
		t.Errorf("username only: %v", got)
	}
	w.set(service.SSHSettingsInput{PrincipalUsername: ptr(false), PrincipalGroups: ptr(true)})
	if got := principals(); !slices.Equal(got, []string{"group:a.b_c-d@e", "group:dba", "group:ops"}) {
		t.Errorf("groups only: %v", got)
	}
	w.set(service.SSHSettingsInput{PrincipalUsername: ptr(false), PrincipalGroups: ptr(false), PrincipalRoles: ptr(true)})
	if got := principals(); !slices.Equal(got, []string{"role:deploy", "role:on-call", "role:root"}) {
		t.Errorf("roles only: %v", got)
	}
	w.set(service.SSHSettingsInput{PrincipalUsername: ptr(true), PrincipalGroups: ptr(true)})
	if got := principals(); !slices.Equal(got, []string{"group:a.b_c-d@e", "group:dba", "group:ops", "paul", "role:deploy", "role:on-call", "role:root"}) {
		t.Errorf("all sources: %v", got)
	}
	// a user's name that is no principal is left out, the rest stay
	odd := w.user(w.org.ID, "odd+name", model.RoleUser)
	if _, err := w.svc.AddAccess(w.ctx, service.System, w.tenant.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: odd.ID, Roles: &[]string{"viewer"}}); err != nil {
		t.Fatal(err)
	}
	if got, err := w.svc.SSHPrincipals(w.ctx, w.reload(), w.fresh(odd)); err != nil || !slices.Equal(got, []string{"role:viewer"}) {
		t.Errorf("odd username: %v %v", got, err)
	}
	// no access: none
	nobody := w.user(w.org.ID, "nobody", model.RoleUser)
	if got, err := w.svc.SSHPrincipals(w.ctx, w.reload(), nobody); err != nil || len(got) != 0 {
		t.Errorf("no access: %v %v", got, err)
	}

	// a subset can be asked for; the certificate holds those only, sorted and without repeats
	got := w.mustSign(u, func(r *service.SSHUserRequest) { r.Principals = []string{"group:ops", "paul", "group:ops"} })
	if c := parseCert(t, got.Certificate); !slices.Equal(c.ValidPrincipals, []string{"group:ops", "paul"}) {
		t.Errorf("subset: %v", c.ValidPrincipals)
	}
	if _, err := w.sign(u, func(r *service.SSHUserRequest) { r.Principals = []string{"ops"} }); fieldOf(err) != "principals" {
		t.Errorf("a group's name without its prefix: %v", err)
	}
	if _, err := w.sign(u, func(r *service.SSHUserRequest) { r.Principals = []string{"group:ops", "nope"} }); fieldOf(err) != "principals" {
		t.Errorf("a principal outside the allowed set: %v", err)
	}
	if got := w.mustSign(u); len(parseCert(t, got.Certificate).ValidPrincipals) != 7 {
		t.Errorf("no subset asked: every principal: %v", parseCert(t, got.Certificate).ValidPrincipals)
	}
}

// A user's name, a group's and a role's are principals of their own kinds: a manager, who may create and rename users
// but not change groups, cannot get a group's (or a role's) principal by naming a user after it.
func TestSSHPrincipalNamespaces(t *testing.T) {
	w := newSSHWorld(t)
	closed := w.tenant.Settings
	closed.MembersOnly = true // roles come from the access list
	if _, err := w.svc.UpdateTenant(w.ctx, service.System, w.tenant.ID, service.TenantInput{Settings: &closed}); err != nil {
		t.Fatal(err)
	}
	w.enable(service.SSHSettingsInput{PrincipalRoles: ptr(true)})
	member := w.user(w.org.ID, "alice", model.RoleUser)
	w.group(w.org.ID, "ops", member)
	if _, err := w.svc.AddAccess(w.ctx, service.System, w.tenant.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: member.ID,
		Roles: &[]string{"deploy"}}); err != nil {
		t.Fatal(err)
	}
	mgr := actor(w.user(w.org.ID, "mgr", model.RoleManager))
	for _, name := range []string{"ops", "deploy"} {
		u, err := w.svc.CreateUser(w.ctx, mgr, w.org.ID, service.UserInput{Username: ptr(name), Email: ptr(name + "@example.com"), GivenName: ptr("Imp")})
		if err != nil {
			t.Fatalf("a manager makes a user named %s: %v", name, err)
		}
		if _, err := w.svc.AddAccess(w.ctx, service.System, w.tenant.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: u.ID}); err != nil {
			t.Fatal(err)
		}
		got := parseCert(t, w.mustSign(u).Certificate).ValidPrincipals
		if !slices.Equal(got, []string{name}) {
			t.Errorf("user %s got %v", name, got)
		}
	}
	got := parseCert(t, w.mustSign(member).Certificate).ValidPrincipals
	if !slices.Equal(got, []string{"alice", "group:ops", "role:deploy"}) {
		t.Errorf("the member got %v", got)
	}
	// and no username can be one of the prefixed names
	if _, err := w.svc.CreateUser(w.ctx, mgr, w.org.ID, service.UserInput{Username: ptr("group:ops"), Email: ptr("g@example.com"), GivenName: ptr("Imp")}); err == nil {
		t.Error("a user named group:ops was made")
	}
}

func TestSSHTenantsFor(t *testing.T) {
	w := newSSHWorld(t)
	u := w.user(w.org.ID, "paul", model.RoleUser)
	w.group(w.org.ID, "ops", u)
	if got, err := w.svc.SSHTenantsFor(w.ctx, u, nil); err != nil || len(got) != 0 {
		t.Fatalf("SSH off: %v %v", got, err)
	}
	w.enable()
	got, err := w.svc.SSHTenantsFor(w.ctx, w.fresh(u), nil)
	if err != nil || len(got) != 1 || got[0].Tenant.ID != w.tenant.ID || !slices.Equal(got[0].Principals, []string{"group:ops", "paul"}) {
		t.Fatalf("SSH on: %+v %v", got, err)
	}
	mgr := w.user(w.org.ID, "mgr", model.RoleManager)
	if got, _ := w.svc.SSHTenantsFor(w.ctx, mgr, nil); len(got) != 0 {
		t.Errorf("a manager is offered a tenant that does not allow them: %v", got)
	}
	// the account page says why: the manager has access, the tenant gives managers no certificates
	if uses, blocked, err := w.svc.SSHAccountTenants(w.ctx, mgr, nil); err != nil || len(uses) != 0 || len(blocked) != 1 ||
		blocked[0].Tenant.ID != w.tenant.ID || blocked[0].Reason != service.SSHBlockedRole {
		t.Errorf("a manager's blocked tenants: %v %+v %v", uses, blocked, err)
	}
	if uses, blocked, err := w.svc.SSHAccountTenants(w.ctx, w.fresh(u), nil); err != nil || len(uses) != 1 || len(blocked) != 0 {
		t.Errorf("a user's tenants: %v %+v %v", uses, blocked, err)
	}
	// no principal from the settings: groups only, and a user in none
	loner := w.user(w.org.ID, "loner", model.RoleUser)
	if _, err := w.svc.UpdateTenantSSH(w.ctx, service.System, w.tenant.ID, service.SSHSettingsInput{PrincipalUsername: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if uses, blocked, err := w.svc.SSHAccountTenants(w.ctx, w.fresh(loner), nil); err != nil || len(uses) != 0 || len(blocked) != 1 ||
		blocked[0].Reason != service.SSHBlockedPrincipals {
		t.Errorf("a user with no principal: %v %+v %v", uses, blocked, err)
	}
	if _, err := w.svc.UpdateTenantSSH(w.ctx, service.System, w.tenant.ID, service.SSHSettingsInput{PrincipalUsername: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	closed := w.tenant.Settings
	closed.MembersOnly = true
	if _, err := w.svc.UpdateTenant(w.ctx, service.System, w.tenant.ID, service.TenantInput{Settings: &closed}); err != nil {
		t.Fatal(err)
	}
	if got, _ := w.svc.SSHTenantsFor(w.ctx, w.fresh(u), nil); len(got) != 0 {
		t.Errorf("a user without access is offered a tenant: %v", got)
	}
	// nor is it named to them as one they cannot use
	if uses, blocked, err := w.svc.SSHAccountTenants(w.ctx, w.fresh(u), nil); err != nil || len(uses)+len(blocked) != 0 {
		t.Errorf("a user without access is told about a tenant: %v %+v %v", uses, blocked, err)
	}
}

func TestSSHTTLCaps(t *testing.T) {
	w := newSSHWorld(t)
	w.enable(service.SSHSettingsInput{CertTTL: ptr(3600)})
	u := w.user(w.org.ID, "paul", model.RoleUser)
	validFor := func(c *service.SSHIssued) time.Duration {
		cert := parseCert(t, c.Certificate)
		return time.Unix(int64(cert.ValidBefore), 0).Sub(time.Now()).Round(time.Minute)
	}
	if got := validFor(w.mustSign(u)); got != time.Hour {
		t.Errorf("default ttl %v", got)
	}
	if got := validFor(w.mustSign(u, func(r *service.SSHUserRequest) { r.TTL = 10 * time.Minute })); got != 10*time.Minute {
		t.Errorf("asked 10m, got %v", got)
	}
	for _, ttl := range []time.Duration{3601 * time.Second, 24 * time.Hour, time.Second, -time.Minute} {
		if _, err := w.sign(u, func(r *service.SSHUserRequest) { r.TTL = ttl }); fieldOf(err) != "ttl" {
			t.Errorf("ttl %v: %v", ttl, err)
		}
	}
	// the user's end date caps it
	end := time.Now().Add(20 * time.Minute).UTC().Format(time.RFC3339)
	if _, err := w.svc.UpdateUser(w.ctx, service.System, u.ID, service.UserInput{ValidUntil: &end}); err != nil {
		t.Fatal(err)
	}
	got := w.mustSign(u)
	if d := validFor(got); d != 20*time.Minute {
		t.Errorf("capped by valid_until: %v", d)
	}
	if end2 := got.Cert.ValidBefore.UTC().Format(time.RFC3339); end2 != end {
		t.Errorf("record valid before %s, want the user's end %s", end2, end)
	}
}

// ---- revocation and the KRL ----

// ending a user's access, each way Quisora has, puts their certificates on the list with the reason.
func TestSSHRevocationFollowsAccess(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	issue := func(name string) (*model.User, *service.SSHIssued) {
		u := w.user(w.org.ID, name, model.RoleUser)
		return u, w.mustSign(u)
	}
	fine, fineCert := issue("fine")
	_ = fine
	if got := w.revokedFor(); len(got) != 0 {
		t.Fatalf("a fresh certificate is revoked: %v", got)
	}

	// revoked by hand
	_, hand := issue("hand")
	if err := w.svc.RevokeSSHCert(w.ctx, actor(w.admin), w.org.ID, hand.Cert.ID); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(hand); got != service.SSHReasonRevoked {
		t.Errorf("revoked by hand: %q", got)
	}
	ev := w.lastAudit("ssh.cert.revoke")
	if ev.Detail["serial"] == "" || ev.Actor != "boss" {
		t.Errorf("revoke audit %+v", ev)
	}

	// disabled
	u, c := issue("disabled")
	if _, err := w.svc.UpdateUser(w.ctx, service.System, u.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(c); got != service.SSHReasonUserDisabled {
		t.Errorf("disabled: %q", got)
	}
	// ... and enabled again: disabling ended their sessions, and what they signed in with does not come back
	if _, err := w.svc.UpdateUser(w.ctx, service.System, u.ID, service.UserInput{Active: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(c); got != service.SSHReasonSessionsEnded {
		t.Errorf("enabled again: %q", got)
	}

	// past the end date
	u, c = issue("ending")
	past := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	if _, err := w.svc.UpdateUser(w.ctx, service.System, u.ID, service.UserInput{ValidUntil: &past}); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(c); got != service.SSHReasonUserDisabled {
		t.Errorf("end date passed: %q", got)
	}

	// deleted
	u, c = issue("deleted")
	if err := w.svc.DeleteUser(w.ctx, service.System, u.ID); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(c); got != service.SSHReasonUserDeleted {
		t.Errorf("deleted: %q", got)
	}
	// the sweep does not take a deleted user's certificate off the list while it is valid
	if _, err := w.svc.SweepAll(w.ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(c); got != service.SSHReasonUserDeleted {
		t.Errorf("deleted, after the orphan sweep: %q", got)
	}

	// signed out everywhere
	u, c = issue("signedout")
	if err := w.svc.RevokeSessions(w.ctx, service.System, u.ID); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(c); got != service.SSHReasonSessionsEnded {
		t.Errorf("sign out everywhere: %q", got)
	}
	// a certificate made after it is fine
	w.mustSign(u)

	// locked out
	u, c = issue("lockedout")
	if _, err := w.svc.LockOutUser(w.ctx, actor(w.admin), u.ID, "left the company"); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(c); got != service.SSHReasonUserDisabled && got != service.SSHReasonSessionsEnded {
		t.Errorf("locked out: %q", got)
	}

	// a manager's certificate when the tenant stops allowing managers
	w.set(service.SSHSettingsInput{AllowPrivileged: ptr(true)})
	mgrCert := w.mustSign(w.user(w.org.ID, "mgr", model.RoleManager))
	if got := w.reasonOf(mgrCert); got != "" {
		t.Errorf("a manager's certificate where managers are allowed: %q", got)
	}
	w.set(service.SSHSettingsInput{AllowPrivileged: ptr(false)})
	if got := w.reasonOf(mgrCert); got != service.SSHReasonRoleNotAllowed {
		t.Errorf("managers no longer allowed: %q", got)
	}
	// promoted to manager: ends their sessions too
	u, c = issue("promoted")
	mgr := model.RoleManager
	if _, err := w.svc.UpdateUser(w.ctx, service.System, u.ID, service.UserInput{Role: &mgr}); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(c); got == "" {
		t.Error("promoted: not revoked")
	}

	// the certificate nothing happened to is still not listed
	if _, ok := w.revokedFor()[fineCert.Cert.Serial]; ok {
		t.Error("an untouched certificate is on the list")
	}

	// the emergency sign-out of the organization revokes what was issued before it, and not what comes after
	before := w.mustSign(w.user(w.org.ID, "before", model.RoleUser))
	if _, err := w.svc.SignOutOrg(w.ctx, service.System, w.org.ID, service.SignOutOptions{Reason: "drill"}); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(fineCert); got != service.SSHReasonSignedOut {
		t.Errorf("emergency sign-out: fine user's certificate: %q", got)
	}
	if got := w.reasonOf(before); got != service.SSHReasonSignedOut {
		t.Errorf("emergency sign-out: %q", got)
	}
	after := w.mustSign(w.user(w.org.ID, "after", model.RoleUser))
	if got := w.reasonOf(after); got != "" {
		t.Errorf("a certificate issued after the sign-out: %q", got)
	}
}

func TestSSHRevocationOfTheServerSignOut(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	u := w.user(w.org.ID, "paul", model.RoleUser)
	c := w.mustSign(u)
	if _, err := w.svc.SignOutServer(w.ctx, service.System, service.SignOutOptions{Reason: "drill"}); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(c); got != service.SSHReasonSignedOut {
		t.Errorf("server sign-out: %q", got)
	}
}

func TestSSHRevocationWhenAccessIsRemoved(t *testing.T) {
	w := newSSHWorld(t)
	closed := w.tenant.Settings
	closed.MembersOnly = true
	if _, err := w.svc.UpdateTenant(w.ctx, service.System, w.tenant.ID, service.TenantInput{Settings: &closed}); err != nil {
		t.Fatal(err)
	}
	w.enable()
	u := w.user(w.org.ID, "paul", model.RoleUser)
	ent, err := w.svc.AddAccess(w.ctx, service.System, w.tenant.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: u.ID})
	if err != nil {
		t.Fatal(err)
	}
	c := w.mustSign(u)
	if got := w.reasonOf(c); got != "" {
		t.Fatal(got)
	}
	if err := w.svc.RemoveAccess(w.ctx, service.System, w.tenant.ID, ent.ID); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(c); got != service.SSHReasonAccessRemoved {
		t.Errorf("access removed: %q", got)
	}
	// an access that has ended counts the same
	if _, err := w.svc.AddAccess(w.ctx, service.System, w.tenant.ID, service.AccessInput{SubjectType: model.SubjectUser, SubjectID: u.ID}); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(c); got != "" {
		t.Errorf("access given again: %q", got)
	}
	// the SSH application deleted or disabled: nobody would be issued one, and nobody lost an access of their own, so
	// the revocation is not written down (as turning SSH off): enabling the application again brings it back
	set := w.reload().SSH
	if _, err := w.svc.UpdateClient(w.ctx, service.System, set.ClientID, service.ClientInput{Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(c); got != service.SSHReasonAppUnavailable {
		t.Errorf("application disabled: %q", got)
	}
	w.svc.InvalidateSSHKRL()
	if _, err := w.svc.SSHKRL(w.ctx, w.tenant.ID); err != nil { // a list made meanwhile writes down what is sticky
		t.Fatal(err)
	}
	if _, err := w.svc.UpdateClient(w.ctx, service.System, set.ClientID, service.ClientInput{Enabled: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(c); got != "" {
		t.Errorf("application enabled again: %q", got)
	}
	if rec, err := w.svc.SSHCerts.Get(w.ctx, c.Cert.ID); err != nil || rec.Revoked {
		t.Errorf("the certificate was revoked for good: %+v %v", rec, err)
	}
}

func TestSSHRevocationWhenRemovedFromAGroup(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	u := w.user(w.org.ID, "paul", model.RoleUser)
	ops := w.group(w.org.ID, "ops", u)
	c := w.mustSign(u)
	if !slices.Equal(c.Cert.Principals, []string{"group:ops", "paul"}) {
		t.Fatal(c.Cert.Principals)
	}
	only := w.mustSign(u, func(r *service.SSHUserRequest) { r.Principals = []string{"paul"} })
	if err := w.svc.SetMembership(w.ctx, service.System, ops.ID, u.ID, false); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(c); got != service.SSHReasonPrincipals {
		t.Errorf("removed from a group: %q", got)
	}
	if got := w.reasonOf(only); got != "" {
		t.Errorf("a certificate without that principal: %q", got)
	}
	// a principal source switched off does the same
	w.set(service.SSHSettingsInput{PrincipalUsername: ptr(false)})
	if got := w.reasonOf(only); got != service.SSHReasonPrincipals {
		t.Errorf("username principal switched off: %q", got)
	}
}

func TestSSHKRLContents(t *testing.T) {
	w := newSSHWorld(t)
	w.enable(service.SSHSettingsInput{HostCerts: ptr(true), HostPatterns: &[]string{"*.example.com"}})
	u := w.user(w.org.ID, "paul", model.RoleUser)
	good, gone := w.mustSign(u), w.mustSign(u)
	if err := w.svc.RevokeSSHCert(w.ctx, actor(w.admin), w.org.ID, gone.Cert.ID); err != nil {
		t.Fatal(err)
	}
	host, err := w.svc.SignHostSSH(w.ctx, actor(w.admin), w.tenant.ID, service.SSHHostRequest{PublicKey: newPub(t), Principals: []string{"a.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.svc.RevokeSSHCert(w.ctx, actor(w.admin), w.org.ID, host.Cert.ID); err != nil {
		t.Fatal(err)
	}
	data, err := w.svc.SSHKRL(w.ctx, w.tenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	krl, err := sshca.ParseKRL(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(krl.CAs) != 2 || krl.Version == 0 || time.Since(krl.Generated) > time.Minute || krl.Comment != "quisora acme/prod" {
		t.Fatalf("krl %+v", krl)
	}
	pubOf := func(purpose string) ssh.PublicKey {
		k, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(keysOf(t, w, purpose)[0].PublicKey))
		return k
	}
	if !krl.Revoked(pubOf("user"), gone.Cert.Serial, "") || krl.Revoked(pubOf("user"), good.Cert.Serial, "") {
		t.Error("the user CA's list")
	}
	if !krl.Revoked(pubOf("host"), host.Cert.Serial, "") || krl.Revoked(pubOf("host"), gone.Cert.Serial, "") {
		t.Error("the host CA's list")
	}
	// a node keeps it for a while; a revocation clears it here
	if again, _ := w.svc.SSHKRL(w.ctx, w.tenant.ID); !bytes.Equal(again, data) {
		t.Error("the list changed within the cache window")
	}
	if err := w.svc.RevokeSSHCert(w.ctx, actor(w.admin), w.org.ID, good.Cert.ID); err != nil {
		t.Fatal(err)
	}
	data2, _ := w.svc.SSHKRL(w.ctx, w.tenant.ID)
	if k2, _ := sshca.ParseKRL(data2); !k2.Revoked(pubOf("user"), good.Cert.Serial, "") {
		t.Error("a revocation did not reach the list made after it")
	}

	// nothing revoked: a valid, empty list; SSH off: still there (TestSSHOffRevokesEverything); never on: not found
	w2 := newSSHWorld(t)
	w2.enable()
	empty, err := w2.svc.SSHKRL(w2.ctx, w2.tenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if k, err := sshca.ParseKRL(empty); err != nil || len(k.CAs) != 1 || len(k.CAs[0].Serials) != 0 {
		t.Errorf("empty list: %v %+v", err, k)
	}
	w3 := newSSHWorld(t)
	if _, err := w3.svc.SSHKRL(w3.ctx, w3.tenant.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("SSH never on: %v", err)
	}
}

// OpenSSH itself reads the list we make, and says revoked for the right certificates.
func TestSSHKRLWithSSHKeygen(t *testing.T) {
	kg, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not on PATH")
	}
	w := newSSHWorld(t)
	w.enable()
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var revoked *service.SSHIssued
	var files []string
	for _, name := range []string{"a", "b", "c"} {
		c := w.mustSign(w.user(w.org.ID, name, model.RoleUser))
		if name == "b" {
			revoked = c
		}
		files = append(files, write(name+"-cert.pub", []byte(c.Certificate+"\n")))
	}
	// one revoked by hand: only it is on the list
	if err := w.svc.RevokeSSHCert(w.ctx, actor(w.admin), w.org.ID, revoked.Cert.ID); err != nil {
		t.Fatal(err)
	}
	for i, f := range files {
		data, err := w.svc.SSHKRL(w.ctx, w.tenant.ID)
		if err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(kg, "-Q", "-f", write("krl0", data), f).CombinedOutput()
		if got := err != nil && strings.Contains(string(out), "REVOKED"); got != (i == 1) {
			t.Errorf("certificate %d revoked by hand: revoked=%v (%v %s)", i, got, err, out)
		}
	}
	if _, err := w.svc.SignOutOrg(w.ctx, service.System, w.org.ID, service.SignOutOptions{Reason: "x"}); err != nil {
		t.Fatal(err)
	}
	w.svc.InvalidateSSHKRL()
	data, err := w.svc.SSHKRL(w.ctx, w.tenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	krl := write("krl", data)
	// after the emergency sign-out every one is on the list
	for i, f := range files {
		cmd := exec.Command(kg, "-Q", "-f", krl, f)
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || !strings.Contains(string(out), "REVOKED") {
			t.Errorf("certificate %d after the sign-out: %v %s", i, err, out)
		}
	}
	// and a certificate made after it is not
	fresh := w.mustSign(w.user(w.org.ID, "d", model.RoleUser))
	w.svc.InvalidateSSHKRL()
	data, _ = w.svc.SSHKRL(w.ctx, w.tenant.ID)
	krl = write("krl2", data)
	out, err := exec.Command(kg, "-Q", "-f", krl, write("d-cert.pub", []byte(fresh.Certificate+"\n"))).CombinedOutput()
	if err != nil {
		t.Errorf("a valid certificate reported revoked: %v %s", err, out)
	}
	if out, err := exec.Command(kg, "-Q", "-f", krl, files[1]).CombinedOutput(); err == nil || !strings.Contains(string(out), "REVOKED") {
		t.Errorf("the revoked certificate: %v %s", err, out)
	}
}

func TestSSHRevokePermissions(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	owner := w.user(w.org.ID, "owner", model.RoleUser)
	stranger := w.user(w.org.ID, "stranger", model.RoleUser)
	mgr := w.user(w.org.ID, "mgr", model.RoleManager)
	other := w.env.org("globex")
	otherAdmin := w.user(other.ID, "otherboss", model.RoleAdmin)
	c := w.mustSign(owner)
	cases := []struct {
		who  string
		a    *service.Actor
		org  string
		want string
	}{
		{"a stranger", actor(stranger), w.org.ID, "forbidden"},
		{"a manager", actor(mgr), w.org.ID, "forbidden"},
		{"another organization's admin", actor(otherAdmin), w.org.ID, "forbidden"},
		{"the owner in the wrong organization", actor(owner), other.ID, "notfound"},
		{"a service account without the scope", &service.Actor{OrgID: w.org.ID, Role: model.RoleAdmin, ClientID: "c", Scopes: []string{"users"}}, w.org.ID, "forbidden"},
		{"the owner", actor(owner), w.org.ID, "ok"},
		{"the owner again", actor(owner), w.org.ID, "ok"}, // idempotent
		{"an administrator", actor(w.admin), w.org.ID, "ok"},
		{"a service account with the scope", &service.Actor{OrgID: w.org.ID, Role: model.RoleAdmin, Name: "service:s", ClientID: "c", Scopes: []string{"ssh"}}, w.org.ID, "ok"},
	}
	for _, tc := range cases {
		if got := outcome(w.svc.RevokeSSHCert(w.ctx, tc.a, tc.org, c.Cert.ID)); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.who, got, tc.want)
		}
		if tc.who == "the owner" {
			if got := w.reasonOf(c); got != service.SSHReasonRevoked {
				t.Errorf("revoked by its owner: %q", got)
			}
			rec, _ := w.svc.SSHCerts.Get(w.ctx, c.Cert.ID)
			if rec.RevokedBy != "owner" || rec.RevokedAt.IsZero() {
				t.Errorf("record %+v", rec)
			}
			if n := len(w.audits("ssh.cert.revoke")); n != 1 {
				t.Errorf("%d revoke events", n)
			}
		}
	}
	if n := len(w.audits("ssh.cert.revoke")); n != 1 {
		t.Errorf("revoking a revoked certificate was audited again: %d events", n)
	}
	if err := w.svc.RevokeSSHCert(w.ctx, actor(w.admin), w.org.ID, "nope"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown certificate: %v", err)
	}
}

func TestSSHListCerts(t *testing.T) {
	w := newSSHWorld(t)
	w.enable(service.SSHSettingsInput{HostCerts: ptr(true), HostPatterns: &[]string{"*.example.com"}})
	a, b := w.user(w.org.ID, "alice", model.RoleUser), w.user(w.org.ID, "bob", model.RoleUser)
	ca1, ca2, cb := w.mustSign(a), w.mustSign(a), w.mustSign(b)
	if err := w.svc.RevokeSSHCert(w.ctx, actor(w.admin), w.org.ID, ca2.Cert.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.LockOutUser(w.ctx, actor(w.admin), b.ID, "x"); err != nil {
		t.Fatal(err)
	}
	// an expired certificate (they stay an hour)
	old := *ca1.Cert
	old.ID, old.Serial, old.ValidAfter, old.ValidBefore = "", 4242, time.Now().Add(-9*time.Hour), time.Now().Add(-time.Minute)
	if err := w.svc.SSHCerts.Create(w.ctx, &old); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.SignHostSSH(w.ctx, actor(w.admin), w.tenant.ID, service.SSHHostRequest{PublicKey: newPub(t), Principals: []string{"x.example.com"}}); err != nil {
		t.Fatal(err)
	}
	list := func(f service.SSHCertFilter) map[uint64]*service.SSHCertView {
		t.Helper()
		l, err := w.svc.ListSSHCerts(w.ctx, actor(w.admin), w.tenant.ID, f)
		if err != nil {
			t.Fatal(err)
		}
		m := map[uint64]*service.SSHCertView{}
		for _, v := range l {
			m[v.Serial] = v
		}
		return m
	}
	all := list(service.SSHCertFilter{})
	if len(all) != 5 {
		t.Fatalf("%d certificates listed", len(all))
	}
	for serial, want := range map[uint64][2]string{ca1.Cert.Serial: {"active", ""}, ca2.Cert.Serial: {"revoked", service.SSHReasonRevoked},
		cb.Cert.Serial: {"revoked", service.SSHReasonUserDisabled}, 4242: {"expired", ""}} {
		if v := all[serial]; v == nil || v.Status != want[0] || v.Reason != want[1] {
			t.Errorf("serial %d: %+v, want %v", serial, v, want)
		}
	}
	if all[ca1.Cert.Serial].Username != "alice" {
		t.Errorf("username %q", all[ca1.Cert.Serial].Username)
	}
	check := func(name string, f service.SSHCertFilter, n int) {
		t.Helper()
		if got := list(f); len(got) != n {
			t.Errorf("%s: %d certificates, want %d", name, len(got), n)
		}
	}
	check("active", service.SSHCertFilter{Status: "active"}, 2) // alice's first and the host certificate
	check("revoked", service.SSHCertFilter{Status: "revoked"}, 2)
	check("expired", service.SSHCertFilter{Status: "expired"}, 1)
	check("all", service.SSHCertFilter{Status: "all"}, 5)
	check("alice", service.SSHCertFilter{UserID: a.ID}, 3)
	check("hosts", service.SSHCertFilter{Host: ptr(true)}, 1)
	check("users", service.SSHCertFilter{Host: ptr(false)}, 4)
	check("limit", service.SSHCertFilter{Limit: 2}, 2)
	if _, err := w.svc.ListSSHCerts(w.ctx, actor(w.admin), w.tenant.ID, service.SSHCertFilter{Status: "weird"}); fieldOf(err) != "status" {
		t.Errorf("bad status: %v", err)
	}
	own, err := w.svc.SSHCertsOf(w.ctx, w.fresh(a))
	if err != nil || len(own) != 2 {
		t.Fatalf("alice's own: %d %v", len(own), err)
	}
}

// ---- CA keys ----

func stateOf(t testing.TB, w *sshWorld, id string) string {
	t.Helper()
	v, err := w.svc.GetTenantSSH(w.ctx, actor(w.admin), w.tenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range v.Keys {
		if k.ID == id {
			return k.State
		}
	}
	return "gone"
}

func TestSSHRotateUserKeyAsScheduled(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	u := w.user(w.org.ID, "paul", model.RoleUser)
	first := keysOf(t, w, "user")[0]
	old := w.mustSign(u)
	next, err := w.svc.RotateSSHKey(w.ctx, actor(w.admin), w.tenant.ID, "user", false)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(next.NotBefore); d < 7*24*time.Hour-time.Minute || d > 7*24*time.Hour+time.Minute {
		t.Errorf("the successor signs in %v, want a week", d)
	}
	if got := keysOf(t, w, "user"); len(got) != 2 || got[0].ID != first.ID || got[1].ID != next.ID {
		t.Fatalf("published keys %v", got)
	}
	if stateOf(t, w, first.ID) != "active" || stateOf(t, w, next.ID) != "next" {
		t.Errorf("states %s %s", stateOf(t, w, first.ID), stateOf(t, w, next.ID))
	}
	pred, _ := w.svc.SSHCAKeys.Get(w.ctx, first.ID)
	if !pred.RetireAt.Equal(next.NotBefore) || !pred.Expires.Equal(next.NotBefore.Add(25*time.Hour)) {
		t.Errorf("the predecessor retires at %v and expires %v; the successor starts %v", pred.RetireAt, pred.Expires, next.NotBefore)
	}
	// the old key keeps signing until then
	if got := w.mustSign(u); got.Cert.CAKeyID != first.ID {
		t.Error("the new key signs before its time")
	}
	// a second scheduled rotation while one is under way is refused; an immediate one replaces it
	if _, err := w.svc.RotateSSHKey(w.ctx, actor(w.admin), w.tenant.ID, "user", false); fieldOf(err) != "immediate" {
		t.Errorf("rotating again: %v", err)
	}
	if ev := w.lastAudit("ssh.ca.rotate"); ev.Detail["purpose"] != "user" || ev.Detail["immediate"] != "false" || ev.Detail["key_id"] != next.ID {
		t.Errorf("rotate audit %v", ev.Detail)
	}
	imm, err := w.svc.RotateSSHKey(w.ctx, actor(w.admin), w.tenant.ID, "user", true)
	if err != nil {
		t.Fatal(err)
	}
	if stateOf(t, w, next.ID) != "gone" {
		t.Error("the replaced pending key is still published")
	}
	if stateOf(t, w, imm.ID) != "active" || stateOf(t, w, first.ID) != "retired" {
		t.Errorf("after the immediate rotation: %s, %s", stateOf(t, w, imm.ID), stateOf(t, w, first.ID))
	}
	pred, _ = w.svc.SSHCAKeys.Get(w.ctx, first.ID)
	if d := time.Until(pred.Expires); d < 24*time.Hour+50*time.Minute || d > 25*time.Hour+time.Minute {
		t.Errorf("the predecessor expires in %v", d)
	}
	if got := w.mustSign(u); got.Cert.CAKeyID != imm.ID {
		t.Error("the immediate key does not sign")
	}
	// certificates of the retired key still stand while it is published
	if got := w.reasonOf(old); got != "" {
		t.Errorf("a certificate of a retired CA key: %q", got)
	}
}

func TestSSHRotateImmediately(t *testing.T) {
	w := newSSHWorld(t)
	w.enable(service.SSHSettingsInput{HostCerts: ptr(true), HostPatterns: &[]string{"*.example.com"}})
	for _, purpose := range []string{"user", "host"} {
		was := keysOf(t, w, purpose)[0]
		nk, err := w.svc.RotateSSHKey(w.ctx, actor(w.admin), w.tenant.ID, purpose, true)
		if err != nil {
			t.Fatal(err)
		}
		if nk.Purpose != purpose || nk.NotBefore.After(time.Now()) {
			t.Errorf("%s: %+v", purpose, nk)
		}
		if stateOf(t, w, nk.ID) != "active" || stateOf(t, w, was.ID) != "retired" {
			t.Errorf("%s: states %s %s", purpose, stateOf(t, w, nk.ID), stateOf(t, w, was.ID))
		}
		pred, _ := w.svc.SSHCAKeys.Get(w.ctx, was.ID)
		if purpose == "host" && !pred.Expires.IsZero() {
			t.Errorf("a host key expires: %v", pred.Expires)
		}
		if purpose == "user" && pred.Expires.IsZero() {
			t.Error("a retired user key never expires")
		}
	}
	// a host key rotated as scheduled: signs at once, the old one stays published
	was := keysOf(t, w, "host")
	nk, err := w.svc.RotateSSHKey(w.ctx, actor(w.admin), w.tenant.ID, "host", false)
	if err != nil || nk.NotBefore.After(time.Now()) {
		t.Fatalf("host rotation: %+v %v", nk, err)
	}
	if got := keysOf(t, w, "host"); len(got) != len(was)+1 {
		t.Errorf("host keys %d", len(got))
	}
	if _, err := w.svc.RotateSSHKey(w.ctx, actor(w.admin), w.tenant.ID, "other", false); fieldOf(err) != "purpose" {
		t.Errorf("unknown purpose: %v", err)
	}
	// a tenant that never enabled SSH cannot rotate
	w2 := newSSHWorld(t)
	if _, err := w2.svc.RotateSSHKey(w2.ctx, actor(w2.admin), w2.tenant.ID, "user", true); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("rotating before SSH was set up: %v", err)
	}
	// and host keys need host certificates
	w3 := newSSHWorld(t)
	w3.enable()
	if _, err := w3.svc.RotateSSHKey(w3.ctx, actor(w3.admin), w3.tenant.ID, "host", true); fieldOf(err) != "purpose" {
		t.Errorf("rotating a host key with host certificates off: %v", err)
	}
}

func TestSSHRemoveOnlyRetiredKeys(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	first := keysOf(t, w, "user")[0]
	if err := w.svc.RemoveSSHKey(w.ctx, actor(w.admin), w.tenant.ID, first.ID); fieldOf(err) != "id" {
		t.Errorf("removing the signing key: %v", err)
	}
	next, err := w.svc.RotateSSHKey(w.ctx, actor(w.admin), w.tenant.ID, "user", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.svc.RemoveSSHKey(w.ctx, actor(w.admin), w.tenant.ID, next.ID); fieldOf(err) != "id" {
		t.Errorf("removing a key that has not started: %v", err)
	}
	if err := w.svc.RemoveSSHKey(w.ctx, actor(w.admin), w.tenant.ID, first.ID); fieldOf(err) != "id" {
		t.Errorf("removing a key that still signs (its retirement is a week away): %v", err)
	}
	imm, err := w.svc.RotateSSHKey(w.ctx, actor(w.admin), w.tenant.ID, "user", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.svc.RemoveSSHKey(w.ctx, actor(w.admin), w.tenant.ID, imm.ID); fieldOf(err) != "id" {
		t.Errorf("removing the new signing key: %v", err)
	}
	u := w.user(w.org.ID, "paul", model.RoleUser)
	if err := w.svc.RemoveSSHKey(w.ctx, actor(w.admin), w.tenant.ID, first.ID); err != nil {
		t.Fatalf("removing a retired key: %v", err)
	}
	if got := keysOf(t, w, "user"); len(got) != 1 || got[0].ID != imm.ID {
		t.Errorf("keys after the removal: %v", got)
	}
	if ev := w.lastAudit("ssh.ca.remove"); ev.Detail["key_id"] != first.ID || ev.Detail["purpose"] != "user" {
		t.Errorf("remove audit %v", ev.Detail)
	}
	if err := w.svc.RemoveSSHKey(w.ctx, actor(w.admin), w.tenant.ID, first.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("removing it again: %v", err)
	}
	// a key of another tenant is not found
	other := w.tenant
	w.tenant = w.tenantNamed("staging")
	if err := w.svc.RemoveSSHKey(w.ctx, actor(w.admin), w.tenant.ID, imm.ID); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("another tenant's key: %v", err)
	}
	w.tenant = other
	// permissions
	mgr := w.user(w.org.ID, "mgr", model.RoleManager)
	if err := w.svc.RemoveSSHKey(w.ctx, actor(mgr), w.tenant.ID, imm.ID); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("a manager: %v", err)
	}
	_ = u
}

func (w *sshWorld) tenantNamed(name string) *model.Tenant { return w.env.tenant(w.org.ID, name) }

func TestSSHScheduledRotation(t *testing.T) {
	w := newSSHWorld(t)
	w.enable(service.SSHSettingsInput{RotationDays: ptr(30)})
	first := keysOf(t, w, "user")[0]
	// nothing is due for three weeks: the housekeeping makes nothing, however often it runs
	for range 3 {
		if err := w.svc.EnsureSSHKeys(w.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(keysOf(t, w, "user")) != 1 {
		t.Fatal("a key was made before its time")
	}
	// the newest key is 24 days old (30 - 7 = 23): due
	age(t, w, first, 24*24*time.Hour)
	for range 3 { // and idempotent
		if err := w.svc.EnsureSSHKeys(w.ctx); err != nil {
			t.Fatal(err)
		}
	}
	keys := keysOf(t, w, "user")
	if len(keys) != 2 {
		t.Fatalf("%d keys after the housekeeping", len(keys))
	}
	next := keys[1]
	if d := time.Until(next.NotBefore); d < 7*24*time.Hour-time.Minute || d > 7*24*time.Hour+time.Minute {
		t.Errorf("successor signs in %v", d)
	}
	pred, _ := w.svc.SSHCAKeys.Get(w.ctx, first.ID)
	if !pred.RetireAt.Equal(next.NotBefore) || !pred.Expires.Equal(next.NotBefore.Add(25*time.Hour)) {
		t.Errorf("predecessor %v %v", pred.RetireAt, pred.Expires)
	}
	if ev := w.lastAudit("ssh.ca.rotate"); ev.Detail["scheduled"] != "true" || ev.Actor != "system" {
		t.Errorf("audit %+v", ev)
	}
	// a tenant without a rotation period, or with SSH off, is left alone
	w2 := newSSHWorld(t)
	w2.enable()
	age(t, w2, keysOf(t, w2, "user")[0], 400*24*time.Hour)
	w3 := newSSHWorld(t)
	w3.enable(service.SSHSettingsInput{RotationDays: ptr(30)})
	age(t, w3, keysOf(t, w3, "user")[0], 400*24*time.Hour)
	w3.set(service.SSHSettingsInput{Enabled: ptr(false)})
	if err := w2.svc.EnsureSSHKeys(w2.ctx); err != nil {
		t.Fatal(err)
	}
	if err := w3.svc.EnsureSSHKeys(w3.ctx); err != nil {
		t.Fatal(err)
	}
	if len(keysOf(t, w2, "user")) != 1 || len(keysOf(t, w3, "user")) != 1 {
		t.Error("housekeeping rotated a tenant that does not rotate")
	}
}

// age makes k look d older (it started signing that long ago).
func age(t testing.TB, w *sshWorld, k *model.SSHKey, d time.Duration) {
	t.Helper()
	k, err := w.svc.SSHCAKeys.Get(w.ctx, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	k.NotBefore = k.NotBefore.Add(-d)
	if err := w.svc.SSHCAKeys.Update(w.ctx, k); err != nil {
		t.Fatal(err)
	}
}

func TestSSHKeyIsSealed(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	k := keysOf(t, w, "user")[0]
	if k.PrivateKey == "" || strings.Contains(k.PrivateKey, "PRIVATE") {
		t.Fatalf("stored key: %.30q", k.PrivateKey)
	}
	der, err := w.svc.Sealer.OpenFor(service.SSHKeyBinding(k.ID), k.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	s, err := sshca.ParseCA(der)
	if err != nil || sshca.AuthorizedKey(s.PublicKey()) != k.PublicKey {
		t.Errorf("the sealed key is not the published one: %v", err)
	}
	if _, err := w.svc.Sealer.OpenFor(service.SSHKeyBinding("another"), k.PrivateKey); err == nil {
		t.Error("the sealed key opens for another binding")
	}
}

// ---- host certificates ----

func TestSignHostCertificate(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	host := func(a *service.Actor, in service.SSHHostRequest) (*service.SSHIssued, error) {
		return w.svc.SignHostSSH(w.ctx, a, w.tenant.ID, in)
	}
	req := func(principals ...string) service.SSHHostRequest {
		return service.SSHHostRequest{PublicKey: newPub(t), Principals: principals}
	}
	// host certificates are off
	if _, err := host(actor(w.admin), req("a.example.com")); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("host certificates off: %v", err)
	}
	w.set(service.SSHSettingsInput{HostCerts: ptr(true), HostTTLDays: ptr(30), HostPatterns: &[]string{"*.example.com", "db1.internal"}})
	if len(keysOf(t, w, "host")) != 1 {
		t.Fatal("no host key")
	}
	got, err := host(actor(w.admin), req("Web.Example.com", "db1.internal", "web.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	cert := parseCert(t, got.Certificate)
	if cert.CertType != ssh.HostCert || cert.KeyId != "host:web.example.com@acme" || !slices.Equal(cert.ValidPrincipals, []string{"db1.internal", "web.example.com"}) {
		t.Errorf("cert %+v", cert)
	}
	if d := time.Until(time.Unix(int64(cert.ValidBefore), 0)); d < 30*24*time.Hour-time.Minute || d > 30*24*time.Hour+time.Minute {
		t.Errorf("valid for %v, want the 30 days of the tenant", d)
	}
	hk := keysOf(t, w, "host")[0]
	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(hk.PublicKey))
	if !bytes.Equal(cert.SignatureKey.Marshal(), pub.Marshal()) || got.Cert.CAKeyID != hk.ID {
		t.Error("signed by another key than the host CA")
	}
	if len(cert.Extensions) != 0 || len(cert.CriticalOptions) != 0 {
		t.Errorf("a host certificate carries user options %v %v", cert.Extensions, cert.CriticalOptions)
	}
	checker := &ssh.CertChecker{IsHostAuthority: func(a ssh.PublicKey, _ string) bool { return bytes.Equal(a.Marshal(), pub.Marshal()) }}
	if err := checker.CheckHostKey("web.example.com:22", nil, cert); err != nil {
		t.Errorf("CheckHostKey: %v", err)
	}
	rec, _ := w.svc.SSHCerts.Get(w.ctx, got.Cert.ID)
	if !rec.Host || rec.UserID != "" || rec.IssuedBy != "boss" || rec.Via != "api" || rec.SessionEpoch != 0 {
		t.Errorf("record %+v", rec)
	}
	ev := w.lastAudit("ssh.host.issue")
	if ev.Detail["principals"] != "db1.internal,web.example.com" || ev.Detail["serial"] == "" || ev.Actor != "boss" {
		t.Errorf("audit %+v", ev)
	}
	// a shorter life, but not a longer one
	short, err := host(actor(w.admin), service.SSHHostRequest{PublicKey: newPub(t), Principals: []string{"x.example.com"}, TTL: 48 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(time.Unix(int64(parseCert(t, short.Certificate).ValidBefore), 0)); d > 48*time.Hour+time.Minute || d < 47*time.Hour {
		t.Errorf("ttl 48h: %v", d)
	}
	if _, err := host(actor(w.admin), service.SSHHostRequest{PublicKey: newPub(t), Principals: []string{"x.example.com"}, TTL: 31 * 24 * time.Hour}); fieldOf(err) != "ttl" {
		t.Errorf("a longer life than the tenant allows: %v", err)
	}
	// principals must match a pattern; names, not wildcards or patterns
	pattern := map[string]bool{"a.b.example.com": true, "db1.internal": true, "DB1.Internal": true, "db2.internal": false, "example.com": false,
		"evil.org": false, "*.example.com": false, "*": false, "10.0.0.1": false, "a b.example.com": false}
	for name, ok := range pattern {
		_, err := host(actor(w.admin), req(name))
		if ok != (err == nil) || (!ok && fieldOf(err) != "principals") {
			t.Errorf("principal %q: %v", name, err)
		}
	}
	if _, err := host(actor(w.admin), req()); fieldOf(err) != "principals" {
		t.Errorf("no principals: %v", err)
	}
	many := make([]string, 33)
	for i := range many {
		many[i] = "h" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example.com"
	}
	if _, err := host(actor(w.admin), req(many...)); fieldOf(err) != "principals" {
		t.Errorf("33 principals: %v", err)
	}
	if _, err := host(actor(w.admin), req(many[:32]...)); err != nil {
		t.Errorf("32 principals: %v", err)
	}
	for _, key := range []string{"", "junk", w.mustSign(w.user(w.org.ID, "paul", model.RoleUser)).Certificate} {
		if _, err := host(actor(w.admin), service.SSHHostRequest{PublicKey: key, Principals: []string{"a.example.com"}}); fieldOf(err) != "public_key" {
			t.Errorf("key %.20q: %v", key, err)
		}
	}
	if got := w.audits("ssh.host.refused"); len(got) == 0 || got[0].Detail["reason"] == "" || got[0].Outcome != "failure" {
		t.Errorf("refusals are not audited: %+v", got)
	}
	// SSH off
	w.set(service.SSHSettingsInput{Enabled: ptr(false)})
	if _, err := host(actor(w.admin), req("a.example.com")); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("SSH off: %v", err)
	}
}

func TestSignHostCertificatePermissions(t *testing.T) {
	w := newSSHWorld(t)
	w.enable(service.SSHSettingsInput{HostCerts: ptr(true), HostPatterns: &[]string{"*.example.com"}})
	mgr := w.user(w.org.ID, "mgr", model.RoleManager)
	other := w.env.org("globex")
	otherAdmin := w.user(other.ID, "otherboss", model.RoleAdmin)
	sa := func(org string, scopes ...string) *service.Actor {
		return &service.Actor{OrgID: org, Role: model.RoleAdmin, Name: "service:hosts", ClientID: "c", Scopes: scopes}
	}
	cases := []struct {
		who  string
		a    *service.Actor
		want string
	}{
		{"an administrator", actor(w.admin), "ok"},
		{"a super admin", actor(w.super), "ok"},
		{"a service account with ssh:host", sa(w.org.ID, service.ScopeSSHHost), "ok"},
		{"a service account with only ssh", sa(w.org.ID, service.ScopeSSH), "forbidden"},
		{"a service account with nothing useful", sa(w.org.ID, service.ScopeUsers), "forbidden"},
		{"a manager", actor(mgr), "forbidden"},
		{"another organization's admin", actor(otherAdmin), "notfound"},
		{"a service account of another organization", sa(other.ID, service.ScopeSSHHost), "notfound"},
	}
	for _, c := range cases {
		_, err := w.svc.SignHostSSH(w.ctx, c.a, w.tenant.ID, service.SSHHostRequest{PublicKey: newPub(t), Principals: []string{"a.example.com"}})
		if got := outcome(err); got != c.want {
			t.Errorf("%s: %s, want %s", c.who, got, c.want)
		}
	}
	if _, err := w.svc.SignHostSSH(w.ctx, actor(w.admin), "nope", service.SSHHostRequest{}); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("unknown tenant: %v", err)
	}
	if ev := w.audits("ssh.host.issue"); len(ev) != 3 || ev[2].Actor != "service:hosts" {
		t.Errorf("issue events: %d", len(ev))
	}
}

func TestSSHScopes(t *testing.T) {
	if service.ScopeSSH != "ssh" || service.ScopeSSHHost != "ssh:host" {
		t.Fatal("scope names")
	}
	for _, sc := range []string{service.ScopeSSH, service.ScopeSSHHost} {
		if !slices.Contains(service.ServiceAccountScopes, sc) {
			t.Errorf("%s is not a service account scope", sc)
		}
	}
	// a service account of an organization may be given them
	w := newSSHWorld(t)
	_, _, err := w.svc.CreateServiceAccount(w.ctx, actor(w.admin), w.org.ID, service.ServiceAccountInput{Name: ptr("hosts"),
		Scopes: &[]string{service.ScopeSSHHost}, AuthMethod: ptr("client_secret_post")})
	if err != nil {
		t.Errorf("a service account with ssh:host: %v", err)
	}
	// but nobody gives a scope they do not hold
	limited := &service.Actor{OrgID: w.org.ID, Role: model.RoleAdmin, ClientID: "c", Scopes: []string{service.ScopeServiceAccounts}}
	if _, _, err := w.svc.CreateServiceAccount(w.ctx, limited, w.org.ID, service.ServiceAccountInput{Name: ptr("more"),
		Scopes: &[]string{service.ScopeSSH}, AuthMethod: ptr("client_secret_post")}); !errors.Is(err, service.ErrInvalid) {
		t.Errorf("granting a scope not held: %v", err)
	}
}

// ---- storage ----

func TestSSHRecordsAreSweptWithTheirTenant(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	u := w.user(w.org.ID, "paul", model.RoleUser)
	w.mustSign(u)
	w.set(service.SSHSettingsInput{Enabled: ptr(false)})
	if err := w.svc.DeleteTenant(w.ctx, service.System, w.tenant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.SweepAll(w.ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := w.svc.SSHCAKeys.Count(w.ctx, w.org.ID); n != 0 {
		t.Errorf("%d CA keys left", n)
	}
	if n, _ := w.svc.SSHCerts.Count(w.ctx, w.org.ID); n != 0 {
		t.Errorf("%d certificates left", n)
	}
}

// A tenant with SSH on cannot be deleted, nor an organization with such a tenant: SSH is turned off first, so the
// servers fetch a list that revokes everything. With SSH off the tenant's own SSH application (first party, which an
// organization's administrator could not delete) does not keep it: it is deleted with the tenant, by the system.
func TestSSHTenantDeletion(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	app := w.reload().SSH.ClientID
	if err := w.svc.DeleteTenant(w.ctx, actor(w.admin), w.tenant.ID); !errors.Is(err, service.ErrSSHOn) || !strings.Contains(err.Error(), "turn SSH off") {
		t.Fatalf("SSH on: %v", err)
	}
	if err := w.svc.DeleteOrg(w.ctx, service.System, w.org.ID, true); !errors.Is(err, service.ErrSSHOn) {
		t.Fatalf("the organization, SSH on in a tenant: %v", err)
	}
	if _, err := w.svc.Orgs.Get(w.ctx, w.org.ID); err != nil {
		t.Fatalf("the organization went: %v", err)
	}
	w.set(service.SSHSettingsInput{Enabled: ptr(false)})
	// another application still keeps it
	other := w.client(w.org.ID, "other")
	if _, err := w.svc.UpdateClient(w.ctx, service.System, other.ID, service.ClientInput{TenantID: &w.tenant.ID}); err != nil {
		t.Fatal(err)
	}
	if err := w.svc.DeleteTenant(w.ctx, actor(w.admin), w.tenant.ID); !errors.Is(err, service.ErrTenantInUse) {
		t.Fatalf("another application in it: %v", err)
	}
	if err := w.svc.DeleteClient(w.ctx, actor(w.admin), other.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.svc.DeleteTenant(w.ctx, actor(w.admin), w.tenant.ID); err != nil {
		t.Fatalf("an administrator deletes the tenant with SSH off: %v", err)
	}
	if _, err := w.svc.Clients.Get(w.ctx, app); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the SSH application is left: %v", err)
	}
	found := false
	for _, a := range w.audits("client.delete") {
		found = found || a.Detail["client_id"] == app && a.Actor == "system"
	}
	if !found {
		t.Error("the SSH application's deletion is not audited as the system's")
	}
	// the organization, once no tenant of it has SSH on
	if err := w.svc.DeleteOrg(w.ctx, service.System, w.org.ID, true); err != nil {
		t.Fatalf("the organization: %v", err)
	}
}

// A master key rotation re-seals the CA keys: with only the new key configured, certificates are still signed.
func TestSSHMasterKeyReseal(t *testing.T) {
	w := newSSHWorld(t)
	oldKey, newKey := secure.RandomBytes(32), secure.RandomBytes(32)
	old, _ := secure.NewSealer(oldKey)
	w.svc.Sealer.Replace(old)
	w.enable()
	u := w.user(w.org.ID, "paul", model.RoleUser)
	ring, err := secure.NewKeyring(newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	w.svc.Sealer.Replace(ring)
	k := keysOf(t, w, "user")[0]
	if !w.svc.Sealer.Stale(k.PrivateKey) {
		t.Fatal("the key is not sealed with the previous master key")
	}
	if r, err := w.svc.ResealSecrets(w.ctx, time.Minute); err != nil || r.Resealed == 0 {
		t.Fatalf("reseal: %+v %v", r, err)
	}
	k2, err := w.svc.SSHCAKeys.Get(w.ctx, k.ID)
	if err != nil || w.svc.Sealer.Stale(k2.PrivateKey) {
		t.Fatalf("the CA key was not re-sealed: %v", err)
	}
	only, _ := secure.NewSealer(newKey)
	w.svc.Sealer.Replace(only)
	w.mustSign(u)
}

// ---- review fixes ----

// The tenant's sign-in methods decide which sessions may get a certificate from the account page, as they decide which
// may sign in to the tenant's applications.
func TestSSHSessionMethodsOfTheTenant(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	u := w.user(w.org.ID, "paul", model.RoleUser)
	pwd := &service.SSHSession{AMR: []string{"pwd", "otp", "mfa"}}
	key := &service.SSHSession{AMR: []string{"hwk", "user", "mfa"}}
	signAs := func(ss *service.SSHSession) error {
		_, err := w.sign(u, func(r *service.SSHUserRequest) { r.AMR, r.Session = ss.AMR, ss })
		return err
	}
	if err := signAs(pwd); err != nil {
		t.Fatalf("password session: %v", err)
	}
	if err := signAs(key); err != nil {
		t.Fatalf("passkey session: %v", err)
	}
	if got, err := w.svc.SSHTenantsFor(w.ctx, w.fresh(u), pwd); err != nil || len(got) != 1 {
		t.Fatalf("tenants for a password session: %v %v", got, err)
	}

	set := w.tenant.Settings
	set.PasswordLogin = false
	if _, err := w.svc.UpdateTenant(w.ctx, service.System, w.tenant.ID, service.TenantInput{Settings: &set}); err != nil {
		t.Fatal(err)
	}
	var refusal *service.SSHRefusal
	if err := signAs(pwd); !errors.As(err, &refusal) || !strings.Contains(refusal.Msg, "does not accept the way you signed in") {
		t.Errorf("password session where passwords are off: %v", err)
	}
	if err := signAs(key); err != nil {
		t.Errorf("passkey session: %v", err)
	}
	// without a session (the sign endpoint, whose token was issued under that rule) the method is not asked again
	if _, err := w.sign(u); err != nil {
		t.Errorf("no session: %v", err)
	}
	if !slices.Contains(w.refusedReasons(), "method_not_allowed") {
		t.Errorf("the refusal is not audited: %v", w.refusedReasons())
	}
	if got, err := w.svc.SSHTenantsFor(w.ctx, w.fresh(u), pwd); err != nil || len(got) != 0 {
		t.Errorf("tenants for a password session where passwords are off: %v %v", got, err)
	}
	if _, blocked, err := w.svc.SSHAccountTenants(w.ctx, w.fresh(u), pwd); err != nil || len(blocked) != 1 || blocked[0].Reason != service.SSHBlockedMethod {
		t.Errorf("why not, for a password session where passwords are off: %+v %v", blocked, err)
	}
	if got, err := w.svc.SSHTenantsFor(w.ctx, w.fresh(u), key); err != nil || len(got) != 1 {
		t.Errorf("tenants for a passkey session: %v %v", got, err)
	}
	if got, err := w.svc.SSHTenantsFor(w.ctx, w.fresh(u), nil); err != nil || len(got) != 1 {
		t.Errorf("tenants without a session: %v %v", got, err)
	}
}

func TestSignInMethodsAllowsSession(t *testing.T) {
	m := &service.SignInMethods{Password: true}
	for name, tc := range map[string]struct {
		amr      []string
		provider string
		want     bool
	}{
		"password":                 {[]string{"pwd"}, "", true},
		"password and a passkey":   {[]string{"pwd", "hwk"}, "", true},
		"passkey only":             {[]string{"hwk", "user"}, "", false},
		"provider not allowed":     {[]string{"fed"}, "p1", false},
		"federated without one":    {[]string{"fed"}, "", false},
		"nothing recognised":       {[]string{"mfa"}, "", false},
		"federated and a password": {[]string{"fed", "pwd"}, "p1", false}, // the provider counts
	} {
		if got := m.AllowsSession(tc.amr, tc.provider); got != tc.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

// Turning SSH off cuts the certificates off: the revocation list, which servers go on fetching, lists every one of the
// tenant's certificates that has not expired, host certificates too, and turning it on takes that back.
func TestSSHOffRevokesEverything(t *testing.T) {
	w := newSSHWorld(t)
	w.enable(service.SSHSettingsInput{HostCerts: ptr(true), HostPatterns: &[]string{"*.example.com"}})
	u := w.user(w.org.ID, "paul", model.RoleUser)
	user := w.mustSign(u)
	byHand := w.mustSign(u)
	if err := w.svc.RevokeSSHCert(w.ctx, actor(w.admin), w.org.ID, byHand.Cert.ID); err != nil {
		t.Fatal(err)
	}
	host, err := w.svc.SignHostSSH(w.ctx, actor(w.admin), w.tenant.ID, service.SSHHostRequest{PublicKey: newPub(t), Principals: []string{"a.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	listed := func() map[uint64]string {
		data, err := w.svc.SSHKRL(w.ctx, w.tenant.ID)
		if err != nil {
			t.Fatal(err)
		}
		krl, err := sshca.ParseKRL(data)
		if err != nil {
			t.Fatal(err)
		}
		out := map[uint64]string{}
		for purpose, c := range map[string]*service.SSHIssued{"user": user, "by hand": byHand, "host": host} {
			k, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(keysOf(t, w, map[bool]string{true: "host", false: "user"}[purpose == "host"])[0].PublicKey))
			if krl.Revoked(k, c.Cert.Serial, "") {
				out[c.Cert.Serial] = purpose
			}
		}
		return out
	}
	if got := listed(); len(got) != 1 || got[byHand.Cert.Serial] == "" {
		t.Fatalf("revoked while on: %v", got)
	}

	w.set(service.SSHSettingsInput{Enabled: ptr(false)})
	if got := listed(); len(got) != 3 {
		t.Errorf("revoked while off: %v", got)
	}
	reasons := w.revokedFor()
	if reasons[user.Cert.Serial] != service.SSHReasonOff || reasons[host.Cert.Serial] != service.SSHReasonOff || reasons[byHand.Cert.Serial] != service.SSHReasonRevoked {
		t.Errorf("reasons while off: %v", reasons)
	}
	// signing is refused, the tenant is still published for the servers, and is not found for a sign endpoint
	if _, err := w.sign(u); !errors.As(err, new(*service.SSHRefusal)) {
		t.Errorf("sign while off: %v", err)
	}
	if _, err := w.svc.SSHTenantPublished(w.ctx, w.org.ID, w.tenant.Name); err != nil {
		t.Errorf("published while off: %v", err)
	}
	if _, err := w.svc.SSHTenantByRef(w.ctx, w.org.ID, w.tenant.Name); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("sign endpoint tenant while off: %v", err)
	}
	// the listing says why, and was never written down as a revocation (it ends with turning SSH on)
	views, err := w.svc.ListSSHCerts(w.ctx, actor(w.admin), w.tenant.ID, service.SSHCertFilter{Status: service.SSHCertRevoked})
	if err != nil || len(views) != 3 {
		t.Fatalf("revoked certificates listed: %v %v", views, err)
	}
	if rec, _ := w.svc.SSHCerts.GetIn(w.ctx, w.org.ID, user.Cert.ID); rec.Revoked {
		t.Error("turning SSH off was written to the certificate")
	}

	w.set(service.SSHSettingsInput{Enabled: ptr(true)})
	if got := listed(); len(got) != 1 || got[byHand.Cert.Serial] == "" {
		t.Errorf("revoked after turning SSH on: %v", got)
	}
}

// Many requests for the revocation list of a tenant make it once: the others wait for it and get what it made.
func TestSSHKRLIsMadeOncePerTenantAtATime(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	u := w.user(w.org.ID, "paul", model.RoleUser)
	for range 5 {
		w.mustSign(u)
	}
	w.svc.InvalidateSSHKRL()
	const n = 16
	got := make([][]byte, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], _ = w.svc.SSHKRL(w.ctx, w.tenant.ID)
		}()
	}
	wg.Wait()
	for i := range got {
		if len(got[i]) == 0 || &got[i][0] != &got[0][0] {
			t.Fatalf("request %d did not get the list the first made", i)
		}
	}
}

// A request waiting for a build of the list made by another goes when it hangs up, while the build goes on for the
// others; one that comes after an invalidation does not take a build begun before it.
func TestSSHKRLWaitersCanHangUp(t *testing.T) {
	var mu sync.Mutex
	var block, blocked chan struct{}
	builds := 0
	st := &faultStore{Store: memstore.New()}
	st.beforeList = func(kind model.Kind, q store.ListQuery) error {
		if kind == model.KindSSHCert && len(q.Filters) == 1 && q.Filters[0].Field == "tenant_id" { // a build's user certificates
			mu.Lock()
			builds++
			b, s := block, blocked
			block = nil
			mu.Unlock()
			if b != nil {
				close(s)
				<-b
			}
		}
		return nil
	}
	w := sshWorldOn(t, newEnvOn(t, st))
	w.enable()
	u := w.user(w.org.ID, "paul", model.RoleUser)
	first, second := w.mustSign(u), w.mustSign(u)
	w.svc.InvalidateSSHKRL()
	mu.Lock()
	block, blocked, builds = make(chan struct{}), make(chan struct{}), 0
	release, held := block, blocked
	mu.Unlock()
	type answer struct {
		data []byte
		err  error
	}
	slow := make(chan answer, 1)
	go func() { data, err := w.svc.SSHKRL(w.ctx, w.tenant.ID); slow <- answer{data, err} }()
	select {
	case <-held:
	case <-time.After(5 * time.Second):
		t.Fatal("the build did not begin")
	}
	waiter := make(chan answer, 1)
	go func() { data, err := w.svc.SSHKRL(w.ctx, w.tenant.ID); waiter <- answer{data, err} }()
	ctx, cancel := context.WithCancel(w.ctx)
	gone := make(chan error, 1)
	go func() { _, err := w.svc.SSHKRL(ctx, w.tenant.ID); gone <- err }()
	cancel()
	select {
	case err := <-gone:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("a request that hung up: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a request that hung up waited for the build")
	}

	// a revocation now (its change hook invalidates): a request after it makes the list again, with it
	c, err := w.svc.SSHCerts.Get(w.ctx, second.Cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.Revoked = true
	if err := w.svc.SSHCerts.Update(w.ctx, c); err != nil {
		t.Fatal(err)
	}
	w.svc.InvalidateSSHKRLOf(w.tenant.ID)
	user := pubKeyOf(t, keysOf(t, w, "user")[0])
	data, err := w.svc.SSHKRL(w.ctx, w.tenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if k, err := sshca.ParseKRL(data); err != nil || !k.Revoked(user, second.Cert.Serial, "") {
		t.Errorf("a request after the revocation took the build begun before it: %v", err)
	}

	close(release)
	a, b := <-slow, <-waiter
	if a.err != nil || b.err != nil || len(a.data) == 0 || len(b.data) == 0 { // (b may have come after the revocation)
		t.Fatalf("a request that stayed was not answered: %v %v", a.err, b.err)
	}
	if k, _ := sshca.ParseKRL(a.data); k.Revoked(user, first.Cert.Serial, "") {
		t.Error("the list revokes a certificate that is not")
	}
	mu.Lock()
	defer mu.Unlock()
	if builds != 2 {
		t.Errorf("%d builds, want the held one and the one after the revocation", builds)
	}
}

// What is checked and de-duplicated afterwards must not grow with what was sent: a list over the limit is refused
// first.
func TestSSHListsAreBoundedBeforeAnyLoop(t *testing.T) {
	w := newSSHWorld(t)
	w.enable(service.SSHSettingsInput{HostCerts: ptr(true), HostPatterns: &[]string{"*.example.com"}})
	big := func(format func(int) string) []string {
		l := make([]string, 100_000)
		for i := range l {
			l[i] = format(i)
		}
		return l
	}
	addrs := big(func(i int) string { return fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255) })
	hosts := big(func(i int) string { return fmt.Sprintf("h%d.example.com", i) })
	start := time.Now()
	for field, in := range map[string]service.SSHSettingsInput{
		"ssh.source_addresses": {SourceAddresses: &addrs},
		"ssh.host_patterns":    {HostPatterns: &hosts},
	} {
		if _, err := w.svc.UpdateTenantSSH(w.ctx, actor(w.admin), w.tenant.ID, in); fieldOf(err) != field {
			t.Errorf("%s: %v", field, err)
		}
	}
	if _, err := w.svc.SignHostSSH(w.ctx, actor(w.admin), w.tenant.ID, service.SSHHostRequest{PublicKey: newPub(t), Principals: hosts}); fieldOf(err) != "principals" {
		t.Errorf("host principals: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("refusing the lists took %v", d)
	}
	// 32 is still fine
	if _, err := w.svc.UpdateTenantSSH(w.ctx, actor(w.admin), w.tenant.ID, service.SSHSettingsInput{SourceAddresses: ptr(addrs[:32])}); err != nil {
		t.Errorf("32 addresses: %v", err)
	}
}

// A tenant with SSH on needs a source of principals, as the console says.
func TestSSHNeedsASourceOfPrincipals(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	off := service.SSHSettingsInput{PrincipalUsername: ptr(false), PrincipalGroups: ptr(false), PrincipalRoles: ptr(false)}
	if _, err := w.svc.UpdateTenantSSH(w.ctx, actor(w.admin), w.tenant.ID, off); fieldOf(err) != "ssh.principal_username" {
		t.Fatalf("all sources off while on: %v", err)
	}
	// one is enough, and a tenant that is off may save them all off
	w.set(service.SSHSettingsInput{PrincipalUsername: ptr(false), PrincipalGroups: ptr(false), PrincipalRoles: ptr(true)})
	w.set(service.SSHSettingsInput{Enabled: ptr(false), PrincipalRoles: ptr(false)})
	if _, err := w.svc.UpdateTenantSSH(w.ctx, actor(w.admin), w.tenant.ID, service.SSHSettingsInput{Enabled: ptr(true)}); fieldOf(err) != "ssh.principal_username" {
		t.Errorf("turning on with every source off: %v", err)
	}
}

// At most 100 certificates of a user for a tenant that have not expired, revoked ones included; the refusal says
// revoking does not help, and when the first expires.
func TestSSHLiveCertificateCap(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	u := w.user(w.org.ID, "paul", model.RoleUser)
	var first *service.SSHIssued
	for i := range 100 {
		c := w.mustSign(u)
		if i == 0 {
			first = c
		}
	}
	var refusal *service.SSHRefusal
	if _, err := w.sign(u); !errors.As(err, &refusal) || !strings.Contains(refusal.Msg, "100 certificates for this tenant") ||
		strings.Contains(refusal.Msg, "revoke some") || !strings.Contains(refusal.Msg, "revoked ones count until they expire") ||
		!strings.Contains(refusal.Msg, first.Cert.ValidBefore.UTC().Format(time.RFC3339)) {
		t.Fatalf("the 101st: %v", err)
	}
	if !slices.Contains(w.refusedReasons(), "too_many") {
		t.Errorf("not audited: %v", w.refusedReasons())
	}
	// another user is not held up; a revoked one does not make room (it is on the revocation list until it expires,
	// so signing and revoking cannot grow the list without bound)
	w.mustSign(w.user(w.org.ID, "sam", model.RoleUser))
	if err := w.svc.RevokeSSHCert(w.ctx, actor(w.admin), w.org.ID, first.Cert.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.sign(u); !errors.As(err, &refusal) {
		t.Errorf("after a revocation: %v", err)
	}
	// one that has expired does
	rec, err := w.svc.SSHCerts.Get(w.ctx, first.Cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	rec.ValidBefore = time.Now().Add(-time.Second)
	if err := w.svc.SSHCerts.Update(w.ctx, rec); err != nil {
		t.Fatal(err)
	}
	w.mustSign(u)
	if _, err := w.sign(u); !errors.As(err, &refusal) {
		t.Errorf("full again: %v", err)
	}
}

// A certificate found revoked because its user lost access, a role or a principal stays revoked when they get it back;
// one that is not on the list for a reason of that kind (SSH off, a disabled account) comes back with it.
func TestSSHRevocationIsWrittenDown(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	u := w.user(w.org.ID, "paul", model.RoleUser)
	ops := w.group(w.org.ID, "ops", u)
	c := w.mustSign(u)
	krl := func() {
		w.t.Helper()
		w.svc.InvalidateSSHKRL()
		if _, err := w.svc.SSHKRL(w.ctx, w.tenant.ID); err != nil {
			w.t.Fatal(err)
		}
	}
	stored := func() *model.SSHCert {
		rec, err := w.svc.SSHCerts.GetIn(w.ctx, w.org.ID, c.Cert.ID)
		if err != nil {
			w.t.Fatal(err)
		}
		return rec
	}
	krl()
	if stored().Revoked {
		t.Fatal("revoked while nothing is wrong")
	}
	if err := w.svc.SetMembership(w.ctx, service.System, ops.ID, u.ID, false); err != nil {
		t.Fatal(err)
	}
	krl()
	rec := stored()
	if !rec.Revoked || rec.RevokedBy != "system" || rec.RevokedReason != service.SSHReasonPrincipals || rec.RevokedAt.IsZero() {
		t.Fatalf("not written down: %+v", rec)
	}
	// the group again: the certificate does not come back, and says why it is revoked
	if err := w.svc.SetMembership(w.ctx, service.System, ops.ID, u.ID, true); err != nil {
		t.Fatal(err)
	}
	krl()
	if got := w.reasonOf(c); got != service.SSHReasonPrincipals {
		t.Errorf("after getting the group back: %q", got)
	}
	// only once: the record is not touched again
	if again := stored(); again.Version != rec.Version {
		t.Errorf("written again: %d then %d", rec.Version, again.Version)
	}
	// a lost access counts the same
	d := w.mustSign(w.user(w.org.ID, "sam", model.RoleUser))
	sam, _ := w.svc.Users.Get(w.ctx, d.Cert.UserID)
	open := w.reload().Settings
	closed := open
	closed.MembersOnly = true
	if _, err := w.svc.UpdateTenant(w.ctx, service.System, w.tenant.ID, service.TenantInput{Settings: &closed}); err != nil {
		t.Fatal(err)
	}
	krl()
	if _, err := w.svc.UpdateTenant(w.ctx, service.System, w.tenant.ID, service.TenantInput{Settings: &open}); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(d); got != service.SSHReasonAccessRemoved {
		t.Errorf("access given back: %q (user %s)", got, sam.Username)
	}
	// written down by the system, and audited as its revocation
	var sys *model.Audit
	for _, a := range w.audits("ssh.cert.revoke") {
		if a.Detail["serial"] == strconv.FormatUint(d.Cert.Serial, 10) {
			sys = a
		}
	}
	if sys == nil || sys.Actor != "system" || sys.Detail["reason"] != service.SSHReasonAccessRemoved || sys.Detail["user_id"] != sam.ID {
		t.Errorf("the revocation written down is not audited as the system's: %+v", sys)
	}
	// while SSH is off too: the user's reasons are found first and written down, so turning SSH on again does not
	// bring back a certificate whose user lost a principal meanwhile
	f := w.mustSign(u, func(r *service.SSHUserRequest) { r.Principals = []string{"group:ops"} })
	w.set(service.SSHSettingsInput{Enabled: ptr(false)})
	if err := w.svc.SetMembership(w.ctx, service.System, ops.ID, u.ID, false); err != nil {
		t.Fatal(err)
	}
	krl()
	if err := w.svc.SetMembership(w.ctx, service.System, ops.ID, u.ID, true); err != nil {
		t.Fatal(err)
	}
	w.set(service.SSHSettingsInput{Enabled: ptr(true)})
	if got := w.reasonOf(f); got != service.SSHReasonPrincipals {
		t.Errorf("lost a principal while SSH was off, SSH on again: %q", got)
	}
	// a disabled account is not written down
	e := w.mustSign(w.user(w.org.ID, "kim", model.RoleUser))
	kim, _ := w.svc.Users.Get(w.ctx, e.Cert.UserID)
	disabled := false
	if _, err := w.svc.UpdateUser(w.ctx, service.System, kim.ID, service.UserInput{Active: &disabled}); err != nil {
		t.Fatal(err)
	}
	krl()
	if rec, _ := w.svc.SSHCerts.GetIn(w.ctx, w.org.ID, e.Cert.ID); rec.Revoked {
		t.Error("a disabled account was written down as revoked")
	}
}

// A revoked certificate stays on the list for ten minutes after it expires, for servers whose clocks are slow.
func TestSSHKRLKeepsExpiredCertificatesForAWhile(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	u := w.user(w.org.ID, "paul", model.RoleUser)
	ca := keysOf(t, w, "user")[0]
	mk := func(ago time.Duration) *model.SSHCert {
		c := &model.SSHCert{OrgID: w.org.ID, TenantID: w.tenant.ID, UserID: u.ID, Serial: uint64(ago/time.Second) + 1, KeyID: "k", CAKeyID: ca.ID,
			Principals: []string{"paul"}, Fingerprint: "SHA256:x", ValidAfter: time.Now().Add(-ago - time.Hour), ValidBefore: time.Now().Add(-ago),
			Via: "cli", Revoked: true, RevokedAt: time.Now(), RevokedBy: "x"}
		if err := w.svc.SSHCerts.Create(w.ctx, c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	recent, old := mk(5*time.Minute), mk(11*time.Minute)
	got := w.revokedFor()
	if got[recent.Serial] == "" || got[old.Serial] != "" {
		t.Errorf("revoked: %v (recent %d, old %d)", got, recent.Serial, old.Serial)
	}
}

// A scheduled rotation of a tenant whose keys are gone (removed meanwhile) does nothing; it does not panic.
func TestSSHScheduledRotationWithoutKeys(t *testing.T) {
	w := newSSHWorld(t)
	t1 := w.enable(service.SSHSettingsInput{RotationDays: ptr(30)})
	for _, k := range keysOf(t, w, "") {
		if err := w.svc.SSHCAKeys.Delete(w.ctx, k.ID); err != nil {
			t.Fatal(err)
		}
	}
	if k, err := w.svc.RotateSSHScheduled(w.ctx, t1); k != nil || err != nil {
		t.Errorf("rotation without keys: %v %v", k, err)
	}
}

// krlOf is the tenant's revocation list, made afresh and parsed.
func (w *sshWorld) krlOf() *sshca.KRL {
	w.t.Helper()
	w.svc.InvalidateSSHKRL()
	data, err := w.svc.SSHKRL(w.ctx, w.tenant.ID)
	if err != nil {
		w.t.Fatal(err)
	}
	k, err := sshca.ParseKRL(data)
	if err != nil {
		w.t.Fatal(err)
	}
	return k
}

func pubKeyOf(t testing.TB, k *model.SSHKey) ssh.PublicKey {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// A removed CA key is no longer published, and the revocation list revokes the key itself (a server whose CA file is
// stale still lists it) for as long as a certificate it signed could be valid: its record stays, without the private
// key, as a tombstone. The list has no certificates section for it (the servers publish no such key).
func TestSSHRemovedKeyIsRevoked(t *testing.T) {
	w := newSSHWorld(t)
	w.enable(service.SSHSettingsInput{HostCerts: ptr(true), HostPatterns: &[]string{"*.example.com"}})
	u := w.user(w.org.ID, "paul", model.RoleUser)
	old := keysOf(t, w, "user")[0]
	c := w.mustSign(u)
	imm, err := w.svc.RotateSSHKey(w.ctx, actor(w.admin), w.tenant.ID, "user", true)
	if err != nil {
		t.Fatal(err)
	}
	if k := w.krlOf(); k.KeyRevoked(pubKeyOf(t, old)) || k.Revoked(pubKeyOf(t, old), c.Cert.Serial, "") {
		t.Fatal("a retired key is revoked before it is removed")
	}
	before := time.Now()
	if err := w.svc.RemoveSSHKey(w.ctx, actor(w.admin), w.tenant.ID, old.ID); err != nil {
		t.Fatal(err)
	}
	tomb, err := w.svc.SSHCAKeys.Get(w.ctx, old.ID)
	if err != nil {
		t.Fatalf("no tombstone: %v", err)
	}
	if tomb.PrivateKey != "" || tomb.Removed.IsZero() || tomb.PublicKey != old.PublicKey ||
		tomb.Expires.Before(before.Add(24*time.Hour+10*time.Minute)) || tomb.Expires.After(time.Now().Add(25*time.Hour)) {
		t.Errorf("tombstone %+v", tomb)
	}
	if got := keysOf(t, w, "user"); len(got) != 1 || got[0].ID != imm.ID {
		t.Errorf("published after the removal: %v", got)
	}
	if v, err := w.svc.GetTenantSSH(w.ctx, actor(w.admin), w.tenant.ID); err != nil || slices.ContainsFunc(v.Keys, func(k *service.SSHKeyView) bool { return k.ID == old.ID }) {
		t.Errorf("the console lists the removed key: %v", err)
	}
	k := w.krlOf()
	if !k.KeyRevoked(pubKeyOf(t, old)) || !k.Revoked(pubKeyOf(t, old), c.Cert.Serial, "") || k.KeyRevoked(pubKeyOf(t, imm)) {
		t.Error("the removed key is not revoked, or the new one is")
	}
	for _, ca := range k.CAs {
		if bytes.Equal(ca.Key, pubKeyOf(t, old).Marshal()) {
			t.Error("the list has a certificates section for the removed key")
		}
	}
	if got := w.reasonOf(c); got != service.SSHReasonCAKeyRemoved {
		t.Errorf("its certificate: %q", got)
	}
	// it signs nothing: the new key signs
	if got := w.mustSign(u); got.Cert.CAKeyID != imm.ID {
		t.Errorf("signed by %s", got.Cert.CAKeyID)
	}
	// a host key's tombstone lasts as long as the longest host certificate
	oldHost := keysOf(t, w, "host")[0]
	if _, err := w.svc.RotateSSHKey(w.ctx, actor(w.admin), w.tenant.ID, "host", true); err != nil {
		t.Fatal(err)
	}
	if err := w.svc.RemoveSSHKey(w.ctx, actor(w.admin), w.tenant.ID, oldHost.ID); err != nil {
		t.Fatal(err)
	}
	if tomb, err := w.svc.SSHCAKeys.Get(w.ctx, oldHost.ID); err != nil || tomb.Expires.Before(before.Add(365*24*time.Hour)) {
		t.Errorf("host tombstone: %+v %v", tomb, err)
	}
	if !w.krlOf().KeyRevoked(pubKeyOf(t, oldHost)) {
		t.Error("the removed host key is not revoked")
	}
}

// While SSH is off the list revokes every CA key of the tenant, so a server holding its certificates refuses them
// whatever it fetched before; turning SSH on again takes that back.
func TestSSHOffRevokesTheKeys(t *testing.T) {
	w := newSSHWorld(t)
	w.enable(service.SSHSettingsInput{HostCerts: ptr(true), HostPatterns: &[]string{"*.example.com"}})
	keys := append(keysOf(t, w, "user"), keysOf(t, w, "host")...)
	w.set(service.SSHSettingsInput{Enabled: ptr(false)})
	k := w.krlOf()
	for _, key := range keys {
		if !k.KeyRevoked(pubKeyOf(t, key)) {
			t.Errorf("SSH off: the %s key is not revoked", key.Purpose)
		}
	}
	w.set(service.SSHSettingsInput{Enabled: ptr(true)})
	k = w.krlOf()
	if len(k.Keys) != 0 {
		t.Errorf("SSH on again: %d keys revoked", len(k.Keys))
	}
}

// A certificate that grants more than the tenant's settings now would is on the list (not for good): a lifetime longer
// than CertTTL, an extension turned off, source addresses other than those the tenant now restricts certificates to.
func TestSSHTightenedSettingsRevoke(t *testing.T) {
	w := newSSHWorld(t)
	w.enable(service.SSHSettingsInput{CertTTL: ptr(8 * 3600), PermitAgentForwarding: ptr(true)})
	u := w.user(w.org.ID, "paul", model.RoleUser)
	long := w.mustSign(u)
	short := w.mustSign(u, func(r *service.SSHUserRequest) { r.TTL = time.Hour })
	if got := w.revokedFor(); len(got) != 0 {
		t.Fatalf("revoked at once: %v", got)
	}
	w.set(service.SSHSettingsInput{CertTTL: ptr(2 * 3600)})
	if got := w.reasonOf(long); got != service.SSHReasonSettingsChanged {
		t.Errorf("lifetime lowered: %q", got)
	}
	if got := w.reasonOf(short); got != "" {
		t.Errorf("a certificate within the lower lifetime: %q", got)
	}
	w.set(service.SSHSettingsInput{CertTTL: ptr(8 * 3600)})
	if got := w.reasonOf(long); got != "" {
		t.Errorf("lifetime raised again (not written down): %q", got)
	}
	// an extension no longer permitted; one turned on grants nothing more to those made before
	w.set(service.SSHSettingsInput{PermitAgentForwarding: ptr(false), PermitX11Forwarding: ptr(true)})
	if got := w.reasonOf(long); got != service.SSHReasonSettingsChanged {
		t.Errorf("agent forwarding turned off: %q", got)
	}
	w.set(service.SSHSettingsInput{PermitAgentForwarding: ptr(true)})
	if got := w.reasonOf(long); got != "" {
		t.Errorf("agent forwarding on again: %q", got)
	}
	// source addresses: from anywhere, then restricted
	w.set(service.SSHSettingsInput{SourceAddresses: &[]string{"10.0.0.0/8"}})
	if got := w.reasonOf(long); got != service.SSHReasonSettingsChanged {
		t.Errorf("restricted to addresses: %q", got)
	}
	inNet := w.mustSign(u)
	if got := w.reasonOf(inNet); got != "" {
		t.Errorf("a certificate made under the restriction: %q", got)
	}
	w.set(service.SSHSettingsInput{SourceAddresses: &[]string{"192.0.2.0/24", "10.0.0.0/8"}})
	if got := w.reasonOf(inNet); got != service.SSHReasonSettingsChanged {
		t.Errorf("other addresses: %q", got)
	}
	w.set(service.SSHSettingsInput{SourceAddresses: &[]string{}})
	if got := w.reasonOf(inNet); got != "" {
		t.Errorf("the restriction lifted: %q", got)
	}
	// on the list, and not written down
	w.set(service.SSHSettingsInput{CertTTL: ptr(3600 * 2)})
	if k := w.krlOf(); !k.Revoked(pubKeyOf(t, keysOf(t, w, "user")[0]), long.Cert.Serial, "") {
		t.Error("not on the list")
	}
	if rec, _ := w.svc.SSHCerts.Get(w.ctx, long.Cert.ID); rec.Revoked {
		t.Error("written down")
	}
}

// The list reads the tenant's user certificates and only the host certificates revoked by hand: the others it could
// list only by their CA key (removed, or SSH off), which it revokes whole.
func TestSSHKRLReadsOnlyRevokedHostCertificates(t *testing.T) {
	var mu sync.Mutex
	var queries []store.ListQuery
	st := &faultStore{Store: memstore.New(), beforeList: func(kind model.Kind, q store.ListQuery) error {
		if kind == model.KindSSHCert {
			mu.Lock()
			queries = append(queries, q)
			mu.Unlock()
		}
		return nil
	}}
	w := sshWorldOn(t, newEnvOn(t, st))
	w.enable(service.SSHSettingsInput{HostCerts: ptr(true), HostPatterns: &[]string{"*.example.com"}})
	var hosts []*service.SSHIssued
	for _, name := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		h, err := w.svc.SignHostSSH(w.ctx, actor(w.admin), w.tenant.ID, service.SSHHostRequest{PublicKey: newPub(t), Principals: []string{name}})
		if err != nil {
			t.Fatal(err)
		}
		hosts = append(hosts, h)
	}
	if err := w.svc.RevokeSSHCert(w.ctx, actor(w.admin), w.org.ID, hosts[0].Cert.ID); err != nil {
		t.Fatal(err)
	}
	u := w.mustSign(w.user(w.org.ID, "paul", model.RoleUser))
	mu.Lock()
	queries = nil
	mu.Unlock()
	k := w.krlOf()
	hostKey := pubKeyOf(t, keysOf(t, w, "host")[0])
	if !k.Revoked(hostKey, hosts[0].Cert.Serial, "") || k.Revoked(hostKey, hosts[1].Cert.Serial, "") {
		t.Error("the host certificate revoked by hand is not listed, or another is")
	}
	if k.Revoked(pubKeyOf(t, keysOf(t, w, "user")[0]), u.Cert.Serial, "") {
		t.Error("a good user certificate is listed")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, q := range queries {
		hostOnly := false
		revoked := false
		for _, f := range q.Filters {
			hostOnly = hostOnly || f.Field == "host_tenant_id"
			revoked = revoked || f.Field == "revoked" && f.Value == true
		}
		if len(q.Filters) == 0 || hostOnly && !revoked || len(q.Filters) == 1 && q.Filters[0].Field != "tenant_id" {
			t.Errorf("the list read %+v", q.Filters)
		}
	}
	if len(queries) != 2 {
		t.Errorf("%d reads of the certificates: %+v", len(queries), queries)
	}
}

// A build of the list writes down at most sshPersistPerBuild revocations, each audited as the system's; one whose
// outcome is unknown is audited so, and stops the writing for that build (the list revokes them all the same).
func TestSSHPersistIsBoundedAndAudited(t *testing.T) {
	e, lands := newUnknownEnv(t)
	w := sshWorldOn(t, e)
	w.enable()
	var certs []*service.SSHIssued
	for i := range 60 {
		u := w.user(w.org.ID, fmt.Sprintf("u%02d", i), model.RoleUser)
		certs = append(certs, w.mustSign(u))
	}
	closed := w.reload().Settings
	closed.MembersOnly = true // every one loses access
	if _, err := w.svc.UpdateTenant(w.ctx, service.System, w.tenant.ID, service.TenantInput{Settings: &closed}); err != nil {
		t.Fatal(err)
	}
	written := func() int {
		n := 0
		for _, c := range certs {
			if rec, _ := w.svc.SSHCerts.Get(w.ctx, c.Cert.ID); rec.Revoked {
				n++
			}
		}
		return n
	}
	// the first write lands with its outcome unknown: audited so, and the build writes nothing more
	lands.arm(model.KindSSHCert)
	k := w.krlOf()
	if got := written(); got != 1 {
		t.Errorf("after a write of unknown outcome: %d written", got)
	}
	if n := len(w.unknownAudits("ssh.cert.revoke")); n != 1 {
		t.Errorf("%d revocations audited as of unknown outcome", n)
	}
	userKey := pubKeyOf(t, keysOf(t, w, "user")[0])
	for _, c := range certs {
		if !k.Revoked(userKey, c.Cert.Serial, "") {
			t.Fatal("a certificate not written down is not on the list")
		}
	}
	// the next build writes at most 50, the one after the rest
	w.krlOf()
	if got := written(); got != 51 {
		t.Errorf("after the second build: %d written", got)
	}
	w.krlOf()
	if got := written(); got != 60 {
		t.Errorf("after the third build: %d written", got)
	}
	for _, a := range w.audits("ssh.cert.revoke") {
		if a.Actor != "system" || a.Detail["reason"] != service.SSHReasonAccessRemoved {
			t.Errorf("revocation audit %+v", a)
		}
	}
	if n := len(w.audits("ssh.cert.revoke")); n != 60 {
		t.Errorf("%d revocations audited", n)
	}
}

// Enabling SSH makes the application before the tenant is written: when that write fails for certain the application
// is deleted (as the system, audited); when its outcome is unknown it is kept, as the tenant may name it.
func TestSSHEnableRollsBackOnlyDefiniteFailures(t *testing.T) {
	e, lands := newUnknownEnv(t)
	w := sshWorldOn(t, e)
	lands.arm(model.KindTenant)
	if _, err := w.svc.UpdateTenantSSH(w.ctx, actor(w.admin), w.tenant.ID, service.SSHSettingsInput{Enabled: ptr(true)}); !errors.Is(err, service.ErrOutcomeUnknown) {
		t.Fatalf("enable: %v", err)
	}
	ssh := w.reload().SSH
	if ssh == nil || ssh.ClientID == "" {
		t.Fatal("the write that landed did not")
	}
	if _, err := w.svc.Clients.Get(w.ctx, ssh.ClientID); err != nil {
		t.Errorf("the application of a write of unknown outcome was deleted: %v", err)
	}

	// a definite failure: the tenant changed meanwhile
	st := &faultStore{Store: memstore.New()}
	w2 := sshWorldOn(t, newEnvOn(t, st))
	st.beforeCAS = func(r *store.Record, _ hlc.Timestamp) error {
		if r.Kind == model.KindTenant {
			return store.ErrStale
		}
		return nil
	}
	st.beforePut = func(r *store.Record) error {
		if r.Kind == model.KindTenant {
			return store.ErrStale
		}
		return nil
	}
	if _, err := w2.svc.UpdateTenantSSH(w2.ctx, actor(w2.admin), w2.tenant.ID, service.SSHSettingsInput{Enabled: ptr(true)}); err == nil {
		t.Fatal("the enabling went through")
	}
	st.beforeCAS, st.beforePut = nil, nil
	if left := sshClientsOf(t, w2); len(left) != 0 {
		t.Errorf("the application of a failed enabling is left: %v", left)
	}
	if ev := w2.lastAudit("client.delete"); ev == nil || ev.Actor != "system" {
		t.Errorf("its deletion is not audited as the system's: %+v", ev)
	}
}

// Housekeeping finishes an enabling that failed after the tenant was written: a tenant with SSH on and no CA key (or no
// application) gets them within a run, and signing works again.
func TestSSHHousekeepingRepairs(t *testing.T) {
	w := newSSHWorld(t)
	w.enable(service.SSHSettingsInput{HostCerts: ptr(true), HostPatterns: &[]string{"*.example.com"}})
	u := w.user(w.org.ID, "paul", model.RoleUser)
	for _, k := range append(keysOf(t, w, "user"), keysOf(t, w, "host")...) {
		if err := w.svc.SSHCAKeys.Delete(w.ctx, k.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.sign(u); !errors.As(err, new(*service.SSHRefusal)) {
		t.Fatalf("no key: %v", err)
	}
	// the application gone too
	if err := w.svc.Clients.Delete(w.ctx, w.reload().SSH.ClientID); err != nil {
		t.Fatal(err)
	}
	// a tenant with SSH off is left alone
	off := w.tenantNamed("staging")
	if err := w.svc.EnsureSSHKeys(w.ctx); err != nil {
		t.Fatal(err)
	}
	if len(keysOf(t, w, "user")) != 1 || len(keysOf(t, w, "host")) != 1 {
		t.Errorf("keys after housekeeping: %d user, %d host", len(keysOf(t, w, "user")), len(keysOf(t, w, "host")))
	}
	app := w.reload().SSH.ClientID
	if c, err := w.svc.Clients.Get(w.ctx, app); err != nil || c.TenantID != w.tenant.ID {
		t.Fatalf("the application: %v", err)
	}
	if ev := w.lastAudit("ssh.ca.create"); ev == nil || ev.Actor != "system" {
		t.Errorf("not audited as the system's: %+v", ev)
	}
	w.mustSign(u)
	if ks, _ := w.svc.SSHKeys(w.ctx, off.ID, ""); len(ks) != 0 {
		t.Errorf("a tenant with SSH off got keys: %v", ks)
	}
	// and again: nothing more
	if err := w.svc.EnsureSSHKeys(w.ctx); err != nil {
		t.Fatal(err)
	}
	if len(keysOf(t, w, "user")) != 1 || w.reload().SSH.ClientID != app {
		t.Error("a second run made more")
	}
}

// The listing says how many certificates match, also beyond those it returns.
func TestSSHListCountsEveryMatch(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	u := w.user(w.org.ID, "paul", model.RoleUser)
	for range 5 {
		w.mustSign(u)
	}
	views, total, err := w.svc.ListSSHCertsCounted(w.ctx, actor(w.admin), w.tenant.ID, service.SSHCertFilter{Limit: 2})
	if err != nil || len(views) != 2 || total != 5 {
		t.Errorf("%d listed, total %d: %v", len(views), total, err)
	}
}

// A retired key that expires within the time a node keeps the list has no certificates section in it: ca.pub stops
// publishing it meanwhile, and a list naming a key ca.pub does not is refused by quisora ssh fetch. The certificates it
// signed have all expired by then.
func TestSSHKRLLeavesOutKeysAboutToExpire(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	old := keysOf(t, w, "user")[0]
	next, err := w.svc.RotateSSHKey(w.ctx, actor(w.admin), w.tenant.ID, "user", true)
	if err != nil {
		t.Fatal(err)
	}
	section := func(k *model.SSHKey) bool {
		for _, ca := range w.krlOf().CAs {
			if bytes.Equal(ca.Key, pubKeyOf(t, k).Marshal()) {
				return true
			}
		}
		return false
	}
	if !section(old) || !section(next) {
		t.Fatal("a retired key published for another day has no section")
	}
	rec, err := w.svc.SSHCAKeys.Get(w.ctx, old.ID)
	if err != nil {
		t.Fatal(err)
	}
	rec.Expires = time.Now().Add(10 * time.Second)
	if err := w.svc.SSHCAKeys.Update(w.ctx, rec); err != nil {
		t.Fatal(err)
	}
	if section(old) || !section(next) {
		t.Error("the list names a key that expires before the list does")
	}
}

// A build of the list keeps it before it writes down the sticky revocations it found: a request meanwhile is answered
// from it, not held up nor made to build again, and an invalidation meanwhile (each write fires one, through the change
// hook) counts once the writing ends.
func TestSSHKRLIsKeptWhileItsRevocationsAreWritten(t *testing.T) {
	var mu sync.Mutex
	var block, blocked chan struct{}
	builds := 0
	st := &faultStore{Store: memstore.New()}
	st.beforeCAS = func(r *store.Record, _ hlc.Timestamp) error {
		mu.Lock()
		b, s := block, blocked
		block = nil
		mu.Unlock()
		if r.Kind == model.KindSSHCert && b != nil {
			close(s)
			<-b
		}
		return nil
	}
	st.beforeList = func(kind model.Kind, q store.ListQuery) error {
		if kind == model.KindSSHCert && len(q.Filters) == 1 && q.Filters[0].Field == "tenant_id" { // a build's user certificates
			mu.Lock()
			builds++
			mu.Unlock()
		}
		return nil
	}
	w := sshWorldOn(t, newEnvOn(t, st))
	w.enable()
	c := w.mustSign(w.user(w.org.ID, "paul", model.RoleUser))
	closed := w.reload().Settings
	closed.MembersOnly = true // paul loses access: a revocation to write down
	if _, err := w.svc.UpdateTenant(w.ctx, service.System, w.tenant.ID, service.TenantInput{Settings: &closed}); err != nil {
		t.Fatal(err)
	}
	w.svc.InvalidateSSHKRL()
	mu.Lock()
	block, blocked, builds = make(chan struct{}), make(chan struct{}), 0
	release, held := block, blocked
	mu.Unlock()
	done := make(chan error, 1)
	go func() { _, err := w.svc.SSHKRL(w.ctx, w.tenant.ID); done <- err }()
	select {
	case <-held:
	case <-time.After(5 * time.Second):
		t.Fatal("the build wrote nothing down")
	}
	w.svc.InvalidateSSHKRLOf(w.tenant.ID) // as the write's change hook does
	got := make(chan []byte, 1)
	go func() { data, _ := w.svc.SSHKRL(w.ctx, w.tenant.ID); got <- data }()
	select {
	case data := <-got:
		k, err := sshca.ParseKRL(data)
		if err != nil || !k.Revoked(pubKeyOf(t, keysOf(t, w, "user")[0]), c.Cert.Serial, "") {
			t.Errorf("the list given meanwhile: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a request was held up while the revocations were written down")
	}
	mu.Lock()
	if builds != 1 {
		t.Errorf("%d builds while one was writing down", builds)
	}
	mu.Unlock()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if rec, _ := w.svc.SSHCerts.Get(w.ctx, c.Cert.ID); !rec.Revoked {
		t.Error("not written down")
	}
	// the invalidation held back counts now: the next request makes the list again
	if _, err := w.svc.SSHKRL(w.ctx, w.tenant.ID); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if builds != 2 {
		t.Errorf("%d builds: the invalidation made during the writing was lost", builds)
	}
}

// The deletion of a tenant is made on the tenant as it was read: SSH turned on in between makes it fail.
func TestSSHTenantDeletionRacesAnEnabling(t *testing.T) {
	st := &faultStore{Store: memstore.New()}
	w := sshWorldOn(t, newEnvOn(t, st))
	w.enable()
	w.set(service.SSHSettingsInput{Enabled: ptr(false)})
	var once sync.Once
	st.beforeCAS = func(r *store.Record, _ hlc.Timestamp) error {
		if r.Kind == model.KindTenant && r.Deleted {
			once.Do(func() {
				t2, err := w.svc.Tenants.Get(w.ctx, w.tenant.ID)
				if err != nil {
					t.Error(err)
					return
				}
				t2.SSH.Enabled = true // turned on meanwhile
				if err := w.svc.Tenants.Update(w.ctx, t2); err != nil {
					t.Error(err)
				}
			})
		}
		return nil
	}
	if err := w.svc.DeleteTenant(w.ctx, actor(w.admin), w.tenant.ID); !errors.Is(err, service.ErrStale) {
		t.Fatalf("deleted while SSH was turned on: %v", err)
	}
	if got := w.reload(); !got.SSH.Enabled {
		t.Error("the tenant is not as the enabling left it")
	}
}

// SSH applications of a tenant that it no longer names (an enabling whose tenant write had an unknown outcome, a
// rollback that failed) neither keep the tenant from being deleted nor linger: housekeeping removes them, and the
// deletion of the tenant takes them with it.
func TestSSHLeftoverApplications(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	leftover := func(name string) *model.Client {
		c := w.client(w.org.ID, name)
		c.TenantID, c.SSHApp, c.FirstParty = w.tenant.ID, true, true
		if err := w.svc.Clients.Update(w.ctx, c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	a := leftover("left-a")
	current := w.reload().SSH.ClientID
	if err := w.svc.EnsureSSHKeys(w.ctx); err != nil { // too young to tell from an enabling under way
		t.Fatal(err)
	}
	if _, err := w.svc.Clients.Get(w.ctx, a.ID); err != nil {
		t.Errorf("a young leftover was removed: %v", err)
	}
	if err := w.svc.EnsureSSHKeysNow(w.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Clients.Get(w.ctx, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the leftover is still there: %v", err)
	}
	if _, err := w.svc.Clients.Get(w.ctx, current); err != nil {
		t.Errorf("the tenant's own application was removed: %v", err)
	}
	// the deletion takes the current one and any leftover, as the system
	b := leftover("left-b")
	w.set(service.SSHSettingsInput{Enabled: ptr(false)})
	if err := w.svc.DeleteTenant(w.ctx, actor(w.admin), w.tenant.ID); err != nil {
		t.Fatalf("delete with a leftover SSH application: %v", err)
	}
	for _, id := range []string{current, b.ID} {
		if _, err := w.svc.Clients.Get(w.ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s left: %v", id, err)
		}
	}
}

// An SSH application deleted while SSH is on is made again by housekeeping, with a new client id: its creation is
// audited as the system's, naming the one it replaces and why, and logged as a warning.
func TestSSHApplicationMadeAgainIsAudited(t *testing.T) {
	w := newSSHWorld(t)
	log := newRecLog()
	w.svc.Log = log
	w.enable()
	old := w.reload().SSH.ClientID
	if ev := w.lastAudit("client.create"); ev == nil || ev.Detail["replaces"] != "" || ev.Detail["ssh_tenant"] != w.tenant.ID {
		t.Errorf("the first application's event: %+v", ev)
	}
	if err := w.svc.DeleteClient(w.ctx, service.System, old); err != nil {
		t.Fatal(err)
	}
	if err := w.svc.EnsureSSHKeys(w.ctx); err != nil {
		t.Fatal(err)
	}
	now := w.reload().SSH.ClientID
	if now == "" || now == old {
		t.Fatalf("made again: %q (was %q)", now, old)
	}
	if c, err := w.svc.Clients.Get(w.ctx, now); err != nil || !c.SSHApp {
		t.Errorf("not marked the tenant's SSH application: %+v %v", c, err)
	}
	ev := w.lastAudit("client.create")
	if ev == nil || ev.Actor != "system" || ev.Detail["client_id"] != now || ev.Detail["replaces"] != old || ev.Detail["reason"] == "" {
		t.Errorf("made again, audited: %+v", ev)
	}
	found := false
	for _, e := range *log.entries {
		found = found || strings.HasPrefix(e, "warn ssh: the tenant's SSH application was deleted")
	}
	if !found {
		t.Errorf("not logged: %v", *log.entries)
	}
}

// The certificate list is paged and searched as the users are: the store searches the key id (which starts with the
// username as issued), the fingerprint and the serial by their start and a principal by the whole of it, and the users
// by username and name give the user's certificates, whatever they were issued under.
func TestSSHListSearchAndPaging(t *testing.T) {
	w := newSSHWorld(t)
	w.enable(service.SSHSettingsInput{HostCerts: ptr(true), HostPatterns: &[]string{"*.example.com"}})
	alice, bob, carol := w.user(w.org.ID, "alice", model.RoleUser), w.user(w.org.ID, "bob", model.RoleUser), w.user(w.org.ID, "carol", model.RoleUser)
	if _, err := w.svc.UpdateUser(w.ctx, actor(w.admin), carol.ID, service.UserInput{FamilyName: ptr("Smithers")}); err != nil {
		t.Fatal(err)
	}
	var signed []*service.SSHIssued
	for range 4 {
		signed = append(signed, w.mustSign(alice))
	}
	signed = append(signed, w.mustSign(bob), w.mustSign(bob), w.mustSign(carol))
	hostCert, err := w.svc.SignHostSSH(w.ctx, actor(w.admin), w.tenant.ID, service.SSHHostRequest{PublicKey: newPub(t), Principals: []string{"web1.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.svc.RevokeSSHCert(w.ctx, actor(w.admin), w.org.ID, signed[0].Cert.ID); err != nil {
		t.Fatal(err)
	}

	list := func(f service.SSHCertFilter) ([]*service.SSHCertView, int) {
		t.Helper()
		l, total, err := w.svc.ListSSHCertsCounted(w.ctx, actor(w.admin), w.tenant.ID, f)
		if err != nil {
			t.Fatal(err)
		}
		return l, total
	}
	serials := func(l []*service.SSHCertView) []uint64 {
		var out []uint64
		for _, v := range l {
			out = append(out, v.Serial)
		}
		return out
	}

	// paging: newest first, the offset and limit pick the page, the total counts every match
	all, total := list(service.SSHCertFilter{Status: "all"})
	if total != 8 || len(all) != 8 {
		t.Fatalf("%d listed of %d", len(all), total)
	}
	if all[0].Serial != hostCert.Cert.Serial || all[1].Serial != signed[6].Cert.Serial || all[7].Serial != signed[0].Cert.Serial {
		t.Errorf("not newest first: %v", serials(all))
	}
	page, total := list(service.SSHCertFilter{Status: "all", Offset: 3, Limit: 3})
	if total != 8 || !slices.Equal(serials(page), serials(all[3:6])) {
		t.Errorf("page 2: %v of %d, want %v", serials(page), total, serials(all[3:6]))
	}
	page, total = list(service.SSHCertFilter{Status: "all", Offset: 6, Limit: 3})
	if total != 8 || len(page) != 2 {
		t.Errorf("last page: %d of %d", len(page), total)
	}
	if page, total = list(service.SSHCertFilter{Status: "all", Offset: 50, Limit: 3}); total != 8 || len(page) != 0 {
		t.Errorf("past the end: %d of %d", len(page), total)
	}
	// a page of an evaluated status counts and pages the matches only
	active, total := list(service.SSHCertFilter{Status: "active", Limit: 3})
	if total != 7 || len(active) != 3 {
		t.Errorf("active: %d of %d", len(active), total)
	}
	if rev, total := list(service.SSHCertFilter{Status: "revoked", Offset: 1}); total != 1 || len(rev) != 0 {
		t.Errorf("revoked, second page: %d of %d", len(rev), total)
	}

	check := func(name string, f service.SSHCertFilter, want ...*service.SSHIssued) {
		t.Helper()
		got, total := list(f)
		ws := make([]uint64, len(want))
		for i, c := range want {
			ws[i] = c.Cert.Serial
		}
		slices.Sort(ws)
		gs := serials(got)
		slices.Sort(gs)
		if total != len(want) || !slices.Equal(gs, ws) {
			t.Errorf("%s: %v (%d), want %v", name, gs, total, ws)
		}
	}
	all8 := func(f service.SSHCertFilter) service.SSHCertFilter { f.Status = "all"; return f }
	check("username", all8(service.SSHCertFilter{Search: "ali"}), signed[0], signed[1], signed[2], signed[3])
	check("username, any case", all8(service.SSHCertFilter{Search: "BOB"}), signed[4], signed[5])
	check("name of the user", all8(service.SSHCertFilter{Search: "smith"}), signed[6]) // family name: carol's certificate
	check("a principal", all8(service.SSHCertFilter{Search: "alice"}), signed[0], signed[1], signed[2], signed[3])
	check("a host principal, whole", all8(service.SSHCertFilter{Search: "web1.example.com"}), &service.SSHIssued{Cert: hostCert.Cert})
	check("a host principal, a part", all8(service.SSHCertFilter{Search: "web1.exa"}))
	check("host key ids", all8(service.SSHCertFilter{Search: "host:"}), &service.SSHIssued{Cert: hostCert.Cert})
	check("fingerprint", all8(service.SSHCertFilter{Search: signed[5].Cert.Fingerprint}), signed[5])
	check("fingerprint, the start", all8(service.SSHCertFilter{Search: signed[5].Cert.Fingerprint[:14]}), signed[5])
	check("serial", all8(service.SSHCertFilter{Search: strconv.FormatUint(signed[2].Cert.Serial, 10)}), signed[2])
	check("key id", all8(service.SSHCertFilter{Search: "carol@acme/"}), signed[6])
	check("nothing", all8(service.SSHCertFilter{Search: "nobody"}))
	check("spaces around it", all8(service.SSHCertFilter{Search: "  carol "}), signed[6])
	// with the other filters
	check("search and revoked", service.SSHCertFilter{Search: "alice", Status: "revoked"}, signed[0])
	check("search and active", service.SSHCertFilter{Search: "alice", Status: "active"}, signed[1], signed[2], signed[3])
	check("search of a user, for another user", all8(service.SSHCertFilter{Search: "alice", UserID: bob.ID}))
	check("search of a user, for the user", all8(service.SSHCertFilter{Search: "alice", UserID: alice.ID}), signed[0], signed[1], signed[2], signed[3])
	check("search without hosts", all8(service.SSHCertFilter{Search: "host:", Host: ptr(false)}))
	check("search of hosts only", all8(service.SSHCertFilter{Search: "web1.example.com", Host: ptr(true)}), &service.SSHIssued{Cert: hostCert.Cert})
	if page, total = list(service.SSHCertFilter{Status: "all", Search: "ali", Offset: 1, Limit: 2}); total != 4 || len(page) != 2 {
		t.Errorf("a page of a search: %d of %d", len(page), total)
	}

	// a user renamed since: the new username finds them through the user, the old one through the key id
	if _, err := w.svc.UpdateUser(w.ctx, actor(w.admin), bob.ID, service.UserInput{Username: ptr("robert")}); err != nil {
		t.Fatal(err)
	}
	check("the new username", all8(service.SSHCertFilter{Search: "robert"}), signed[4], signed[5])
	check("the username as issued", all8(service.SSHCertFilter{Search: "bob"}), signed[4], signed[5])
	// another tenant's certificates are not found
	other := w.tenantNamed("other")
	if _, total, err := w.svc.ListSSHCertsCounted(w.ctx, actor(w.admin), other.ID, service.SSHCertFilter{Search: "alice"}); err != nil || total != 0 {
		t.Errorf("another tenant: %d %v", total, err)
	}
}

// A user's certificates, for the user's page in the console: only administrators of the organization (or a service
// account with the ssh scope) may list them.
func TestSSHCertsOfUser(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	alice := w.user(w.org.ID, "alice", model.RoleUser)
	mgr := w.user(w.org.ID, "mgr", model.RoleManager)
	c := w.mustSign(alice)
	got, err := w.svc.SSHCertsOfUser(w.ctx, actor(w.admin), alice)
	if err != nil || len(got) != 1 || got[0].ID != c.Cert.ID || got[0].Status != "active" {
		t.Fatalf("the administrator's list: %v %v", got, err)
	}
	if err := w.svc.RevokeSSHCert(w.ctx, actor(w.admin), w.org.ID, c.Cert.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ = w.svc.SSHCertsOfUser(w.ctx, actor(w.admin), alice); len(got) != 1 || got[0].Status != "revoked" {
		t.Errorf("a revoked certificate stays until it expires: %v", got)
	}
	for _, who := range []*model.User{mgr, alice} {
		if _, err := w.svc.SSHCertsOfUser(w.ctx, actor(who), alice); !errors.Is(err, service.ErrForbidden) {
			t.Errorf("%s: %v", who.Username, err)
		}
	}
	// a service account needs the ssh scope
	sa := &service.Actor{Name: "svc", OrgID: w.org.ID, Role: model.RoleAdmin, ClientID: "c1", Scopes: []string{service.ScopeSSH}}
	if _, err := w.svc.SSHCertsOfUser(w.ctx, sa, alice); err != nil {
		t.Errorf("ssh scope: %v", err)
	}
	sa.Scopes = []string{service.ScopeUsers}
	if _, err := w.svc.SSHCertsOfUser(w.ctx, sa, alice); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("users scope: %v", err)
	}
}

// A guest's certificate stands on the account its sign-in came from (SSHCert.Sources): it is revoked once that
// account's sessions end, and a request under a sign-in whose source has ended is refused, though the guest's own
// account is untouched.
func TestSSHGuestCertificateStandsOnItsSource(t *testing.T) {
	w := newSSHWorld(t)
	w.enable()
	home := w.env.org("home")
	guestOf := func(name string) (*model.User, *model.User, func(*service.SSHUserRequest)) {
		src := w.user(home.ID, name, model.RoleUser)
		g := w.user(w.org.ID, name+"-guest", model.RoleUser)
		sources := []model.GuestSource{{UserID: src.ID, Epoch: w.fresh(src).SessionEpoch}}
		return src, g, func(r *service.SSHUserRequest) { r.Sources = sources }
	}

	src, g, from := guestOf("pat")
	c := w.mustSign(g, from)
	if got := w.reasonOf(c); got != "" {
		t.Fatalf("a guest's certificate while its source stands: %q", got)
	}
	if err := w.svc.RevokeSessions(w.ctx, service.System, src.ID); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(c); got != service.SSHReasonSessionsEnded {
		t.Errorf("its source signed out everywhere: %q", got)
	}
	if _, err := w.sign(g, from); err == nil {
		t.Error("a certificate was signed under a sign-in whose source has ended")
	}

	src, g, from = guestOf("sam")
	c = w.mustSign(g, from)
	if err := w.svc.DeleteUser(w.ctx, service.System, src.ID); err != nil {
		t.Fatal(err)
	}
	if got := w.reasonOf(c); got != service.SSHReasonSessionsEnded {
		t.Errorf("its source deleted: %q", got)
	}
}
