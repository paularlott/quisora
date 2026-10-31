package login_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/passkey/virtualauth"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/sshca"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// sshOrg is the organization "acme" with a tenant "prod" whose SSH is on (and a tenant "lab" whose SSH never was).
func sshOrg(t *testing.T, e *env) (*model.Org, *model.Tenant) {
	t.Helper()
	org := e.org(t, "acme", nil)
	open := model.DefaultTenantSettings()
	open.MembersOnly = false
	prod := e.tenant(t, org, "prod", open)
	e.tenant(t, org, "lab", open)
	on := true
	if _, err := e.Svc.UpdateTenantSSH(context.Background(), service.System, prod.ID, service.SSHSettingsInput{Enabled: &on}); err != nil {
		t.Fatal(err)
	}
	return org, prod
}

func sshPub(t testing.TB) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshca.AuthorizedKey(k) + " pat@laptop"
}

func list(out map[string]any, key string) []map[string]any {
	var r []map[string]any
	raw, _ := out[key].([]any)
	for _, x := range raw {
		r = append(r, x.(map[string]any))
	}
	return r
}

func TestAccountSSHList(t *testing.T) {
	e := newEnv(t, nil)
	org, prod := sshOrg(t, e)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedIn(t, pat)

	res, out := b.api("GET", "/api-internal/account/ssh", nil)
	wantStatus(t, res, out, 200)
	ts := list(out, "tenants")
	if len(ts) != 1 || str(ts[0], "id") != prod.ID {
		t.Fatalf("tenants (lab has no SSH): %v", out["_raw"])
	}
	url := e.Cfg.Server.PublicURL + "/o/" + org.ID + "/ssh/" + prod.ID
	if str(ts[0], "url") != url || str(ts[0], "command") != "quisora ssh login "+url || str(ts[0], "name") == "" {
		t.Errorf("tenant item: %v", ts[0])
	}
	if p, _ := ts[0]["principals"].([]any); len(p) != 1 || p[0] != "pat" {
		t.Errorf("principals: %v", ts[0]["principals"])
	}
	if out["mfa"] != false || len(list(out, "certificates")) != 0 {
		t.Errorf("password session: %v", out["_raw"])
	}
	_, out = e.signedInMFA(t, pat).api("GET", "/api-internal/account/ssh", nil)
	if out["mfa"] != true {
		t.Errorf("mfa session: %v", out["_raw"])
	}

	// a user the tenant is closed to, and a tenant with SSH off again, are not offered
	closed := prod.Settings
	closed.MembersOnly = true
	if _, err := e.Svc.UpdateTenant(context.Background(), service.System, prod.ID, service.TenantInput{Settings: &closed}); err != nil {
		t.Fatal(err)
	}
	_, out = b.api("GET", "/api-internal/account/ssh", nil)
	if len(list(out, "tenants")) != 0 {
		t.Errorf("closed tenant offered: %v", out["_raw"])
	}
	closed.MembersOnly = false
	off := false
	if _, err := e.Svc.UpdateTenant(context.Background(), service.System, prod.ID, service.TenantInput{Settings: &closed}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Svc.UpdateTenantSSH(context.Background(), service.System, prod.ID, service.SSHSettingsInput{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	_, out = b.api("GET", "/api-internal/account/ssh", nil)
	if len(list(out, "tenants")) != 0 {
		t.Errorf("tenant with SSH off offered: %v", out["_raw"])
	}
	// and the session is required
	res, out = e.browser(t).api("GET", "/api-internal/account/ssh", nil)
	if res.StatusCode != 401 {
		t.Errorf("anonymous: %d %v", res.StatusCode, out["_raw"])
	}
}

func TestAccountSSHSign(t *testing.T) {
	e := newEnv(t, nil)
	org, prod := sshOrg(t, e)
	pat := e.user(t, org, "pat", model.RoleUser)
	ops := "ops"
	if _, err := e.Svc.CreateGroupWithMembers(context.Background(), service.System, org.ID, service.GroupInput{DisplayName: &ops}, []string{pat.ID}); err != nil {
		t.Fatal(err)
	}
	body := func() map[string]any { return map[string]any{"tenant_id": prod.ID, "public_key": sshPub(t)} }

	// a session that used only a password is refused, however recently it confirmed
	pw := e.signedIn(t, pat)
	pw.markReauth()
	res, out := pw.api("POST", "/api-internal/account/ssh/sign", body())
	wantStatus(t, res, out, 403)
	if str(out, "field") != "mfa" || !strings.Contains(str(out, "error"), "second factor") {
		t.Errorf("no second factor: %v", out["_raw"])
	}

	// a second factor, signed in an hour ago (the tenant's MaxAuthAge): the account page asks to confirm first, as for
	// an API token ...
	b := e.signedInMFA(t, pat)
	res, out = b.api("POST", "/api-internal/account/ssh/sign", body())
	wantStatus(t, res, out, 403)
	if str(out, "field") != "reauth" {
		t.Errorf("no re-authentication: %v", out["_raw"])
	}
	// ... and the confirmation is the sign-in that counts for how old it may be
	b.markReauth()
	pub := sshPub(t)
	res, out = b.api("POST", "/api-internal/account/ssh/sign", map[string]any{"tenant_id": prod.ID, "public_key": pub})
	wantStatus(t, res, out, 200)
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(str(out, "certificate")))
	cert, ok := k.(*ssh.Certificate)
	if err != nil || !ok {
		t.Fatalf("certificate %q: %v", str(out, "certificate"), err)
	}
	want, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(pub))
	if cert.CertType != ssh.UserCert || string(cert.Key.Marshal()) != string(want.Marshal()) || !slices.Equal(cert.ValidPrincipals, []string{"group:ops", "pat"}) {
		t.Errorf("certificate: type %d principals %v", cert.CertType, cert.ValidPrincipals)
	}
	if p, _ := out["principals"].([]any); len(p) != 2 || str(out, "serial") == "" || str(out, "valid_before") == "" || str(out, "id") == "" {
		t.Errorf("answer: %v", out["_raw"])
	}
	if str(out, "serial") == "0" || strings.Contains(str(out, "_raw"), "session") {
		t.Errorf("answer: %v", out["_raw"])
	}
	rec, err := e.Svc.SSHCerts.GetIn(context.Background(), org.ID, str(out, "id"))
	if err != nil || rec.Via != "account" || rec.UserID != pat.ID || rec.TenantID != prod.ID {
		t.Fatalf("record: %+v %v", rec, err)
	}

	// it is listed, with where it stands
	res, out = b.api("GET", "/api-internal/account/ssh", nil)
	wantStatus(t, res, out, 200)
	cs := list(out, "certificates")
	if len(cs) != 1 || str(cs[0], "id") != rec.ID || str(cs[0], "status") != "active" || str(cs[0], "tenant") == "" {
		t.Fatalf("certificates: %v", out["_raw"])
	}

	// a key that is not one is a field error; so is nothing
	for _, key := range []string{"", "not a key", "ssh-rsa AAAA"} {
		res, out = b.api("POST", "/api-internal/account/ssh/sign", map[string]any{"tenant_id": prod.ID, "public_key": key})
		if res.StatusCode != 422 || str(out, "field") != "public_key" || str(out, "error") == "" {
			t.Errorf("key %q: %d %v", key, res.StatusCode, out["_raw"])
		}
	}
	// a tenant without SSH is refused with the reason; an unknown tenant is not found
	lab, _ := e.Svc.Tenants.GetByUnique(context.Background(), model.TenantNameKey(org.ID, "lab"))
	res, out = b.api("POST", "/api-internal/account/ssh/sign", map[string]any{"tenant_id": lab.ID, "public_key": sshPub(t)})
	wantStatus(t, res, out, 403)
	if str(out, "error") != "SSH certificates are not enabled for this tenant." {
		t.Errorf("tenant without SSH: %v", out["_raw"])
	}
	res, out = b.api("POST", "/api-internal/account/ssh/sign", map[string]any{"tenant_id": "nope", "public_key": sshPub(t)})
	wantStatus(t, res, out, 404)
	// unknown fields are refused
	res, out = b.api("POST", "/api-internal/account/ssh/sign", `{"tenant_id":"`+prod.ID+`","public_key":"x","principals":["root"]}`)
	wantStatus(t, res, out, 400)

	// the confirmation is good for a few minutes only; a sign-in older than the tenant allows without one is refused
	b.e.Mod.ClearReauth(b.sessionID())
	res, out = b.api("POST", "/api-internal/account/ssh/sign", body())
	wantStatus(t, res, out, 403)
	if str(out, "field") != "reauth" {
		t.Errorf("after the window: %v", out["_raw"])
	}
	// a fresh sign-in needs no confirmation
	b.fresh()
	res, out = b.api("POST", "/api-internal/account/ssh/sign", body())
	wantStatus(t, res, out, 200)

	// a sign-in within the confirmation window but older than the tenant's MaxAuthAge is refused by the service ...
	short := 60
	if _, err := e.Svc.UpdateTenantSSH(context.Background(), service.System, prod.ID, service.SSHSettingsInput{MaxAuthAge: &short}); err != nil {
		t.Fatal(err)
	}
	b.signedInAt(time.Now().Add(-2 * time.Minute))
	b.e.Mod.ClearReauth(b.sessionID())
	res, out = b.api("POST", "/api-internal/account/ssh/sign", body())
	wantStatus(t, res, out, 403)
	if str(out, "field") != "" || !strings.Contains(str(out, "error"), "sign-in is too old") {
		t.Errorf("old sign-in: %v", out["_raw"])
	}
	// ... until the session confirms who it is, which is newer than the sign-in
	b.markReauth()
	res, out = b.api("POST", "/api-internal/account/ssh/sign", body())
	wantStatus(t, res, out, 200)
}

func TestAccountSSHRevoke(t *testing.T) {
	e := newEnv(t, nil)
	org, prod := sshOrg(t, e)
	pat := e.user(t, org, "pat", model.RoleUser)
	sam := e.user(t, org, "sam", model.RoleUser)
	sign := func(u *model.User) (*browser, string) {
		b := e.signedInMFA(t, u)
		b.fresh()
		res, out := b.api("POST", "/api-internal/account/ssh/sign", map[string]any{"tenant_id": prod.ID, "public_key": sshPub(t)})
		wantStatus(t, res, out, 200)
		return b, str(out, "id")
	}
	pb, patCert := sign(pat)
	sb, samCert := sign(sam)
	revoked := func(id string) bool {
		c, err := e.Svc.SSHCerts.GetIn(context.Background(), org.ID, id)
		if err != nil {
			t.Fatal(err)
		}
		return c.Revoked
	}

	// not someone else's, even with the id, nor an administrator's through this API; nor one that is not there
	for _, who := range []*browser{pb, e.signedInMFA(t, e.Admin)} {
		res, out := who.api("POST", "/api-internal/account/ssh/certificates/"+samCert+"/revoke", nil)
		wantStatus(t, res, out, 404)
	}
	res, out := pb.api("POST", "/api-internal/account/ssh/certificates/nope/revoke", nil)
	wantStatus(t, res, out, 404)
	if revoked(samCert) {
		t.Fatal("someone else's certificate revoked")
	}

	res, out = pb.api("POST", "/api-internal/account/ssh/certificates/"+patCert+"/revoke", nil)
	wantStatus(t, res, out, 204)
	if !revoked(patCert) || revoked(samCert) {
		t.Fatal("revocation")
	}
	res, out = pb.api("POST", "/api-internal/account/ssh/certificates/"+patCert+"/revoke", nil) // again: nothing more to do
	wantStatus(t, res, out, 204)
	_, out = pb.api("GET", "/api-internal/account/ssh", nil)
	cs := list(out, "certificates")
	if len(cs) != 1 || str(cs[0], "status") != "revoked" || str(cs[0], "reason") != "revoked" {
		t.Errorf("listed: %v", out["_raw"])
	}
	_, out = sb.api("GET", "/api-internal/account/ssh", nil)
	if cs := list(out, "certificates"); len(cs) != 1 || str(cs[0], "status") != "active" || str(cs[0], "id") != samCert {
		t.Errorf("the other user's list: %v", out["_raw"])
	}
}

// signedInWith is a browser whose session signed in an hour ago with amr.
func (e *env) signedInWith(t testing.TB, u *model.User, amr []string) *browser {
	t.Helper()
	c, csrf := e.SessionAMR(u, amr)
	cp := *c
	b := &browser{t: t, e: e, c: &cp, csrf: csrf, auth: virtualauth.New(e.Cfg.Server.PublicURL), base: web.OrgPath(u.OrgID, "")}
	b.signedInAt(time.Now().Add(-time.Hour))
	return b
}

// The tenant's sign-in methods apply to the account page as they do to the sign endpoint: a session that signed in
// with a method the tenant does not allow neither sees the tenant nor gets a certificate from it.
func TestAccountSSHFollowsTheTenantsSignInMethods(t *testing.T) {
	e := newEnv(t, nil)
	org, prod := sshOrg(t, e)
	pat := e.user(t, org, "pat", model.RoleUser)
	body := map[string]any{"tenant_id": prod.ID, "public_key": sshPub(t)}
	pw := e.signedInWith(t, pat, []string{"pwd", "otp", "mfa"})
	pw.fresh()
	key := e.signedInWith(t, pat, []string{"swk", "user", "mfa"})
	key.fresh()
	for name, b := range map[string]*browser{"password": pw, "passkey": key} {
		if _, out := b.api("GET", "/api-internal/account/ssh", nil); len(list(out, "tenants")) != 1 {
			t.Fatalf("%s session, methods allowed: %v", name, out["_raw"])
		}
	}

	set := prod.Settings
	set.PasswordLogin = false
	if _, err := e.Svc.UpdateTenant(context.Background(), service.System, prod.ID, service.TenantInput{Settings: &set}); err != nil {
		t.Fatal(err)
	}
	res, out := pw.api("POST", "/api-internal/account/ssh/sign", body)
	wantStatus(t, res, out, 403)
	if !strings.Contains(str(out, "error"), "does not accept the way you signed in") {
		t.Errorf("password session, passwords off: %v", out["_raw"])
	}
	if _, out := pw.api("GET", "/api-internal/account/ssh", nil); len(list(out, "tenants")) != 0 {
		t.Errorf("tenant offered to a session it does not accept: %v", out["_raw"])
	}
	res, out = key.api("POST", "/api-internal/account/ssh/sign", body)
	wantStatus(t, res, out, 200)
	if _, out := key.api("GET", "/api-internal/account/ssh", nil); len(list(out, "tenants")) != 1 {
		t.Errorf("tenant not offered to a passkey session: %v", out["_raw"])
	}
}

// For an account with no second factor of its own, whose second factor came from its sign-in (a provider trusted for
// it), re-authenticating is the password alone: it does not make the old sign-in count as new when asking for a
// certificate. One with a second factor (a code or a passkey) does.
func TestAccountSSHReauthCountsOnlyWithASecondFactor(t *testing.T) {
	e := newEnv(t, nil)
	org, prod := sshOrg(t, e)
	pat := e.user(t, org, "pat", model.RoleUser)
	body := map[string]any{"tenant_id": prod.ID, "public_key": sshPub(t)}
	b := e.signedInMFA(t, pat) // signed in an hour ago: the tenant's MaxAuthAge
	b.e.Mod.MarkReauthPasswordOnly(b.sessionID())
	res, out := b.api("POST", "/api-internal/account/ssh/sign", body)
	wantStatus(t, res, out, 403)
	if str(out, "field") != "" || !strings.Contains(str(out, "error"), "sign-in is too old") {
		t.Errorf("a password-only re-authentication: %v", out["_raw"])
	}
	b.e.Mod.MarkReauth(b.sessionID())
	res, out = b.api("POST", "/api-internal/account/ssh/sign", body)
	wantStatus(t, res, out, 200)
}

// Requests for certificates from the account page are limited as the sign endpoint's are: 20 a minute for a user.
func TestAccountSSHSignIsRateLimited(t *testing.T) {
	e := newEnv(t, nil)
	org, prod := sshOrg(t, e)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedInMFA(t, pat)
	b.fresh()
	bad := map[string]any{"tenant_id": prod.ID, "public_key": "nope"} // counted all the same
	for i := range web.SSHSignsPerUser {
		if res, out := b.api("POST", "/api-internal/account/ssh/sign", bad); res.StatusCode != 422 {
			t.Fatalf("request %d: %d %v", i, res.StatusCode, out["_raw"])
		}
	}
	res, out := b.api("POST", "/api-internal/account/ssh/sign", bad)
	wantStatus(t, res, out, 429)
	if res.Header.Get("Retry-After") == "" || !strings.Contains(str(out, "error"), "Too many") {
		t.Errorf("over the limit: %v %v", res.Header, out["_raw"])
	}
	// the account page counts in the same place as the sign endpoint (web.Server.SSHSignAllowed): another user's budget is their own
	sam := e.signedInMFA(t, e.user(t, org, "sam", model.RoleUser))
	sam.fresh()
	if res, out := sam.api("POST", "/api-internal/account/ssh/sign", bad); res.StatusCode != 422 {
		t.Errorf("another user: %d %v", res.StatusCode, out["_raw"])
	}
}

// Revoking on the account page is limited per user, as signing is: each revoked certificate stays on the tenant's
// revocation list until it expires.
func TestAccountSSHRevokeIsRateLimited(t *testing.T) {
	e := newEnv(t, nil)
	org, _ := sshOrg(t, e)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedInMFA(t, pat)
	for i := range web.SSHRevokesPerUser { // counted whether or not there is a certificate to revoke
		if res, out := b.api("POST", "/api-internal/account/ssh/certificates/nope/revoke", nil); res.StatusCode != 404 {
			t.Fatalf("request %d: %d %v", i, res.StatusCode, out["_raw"])
		}
	}
	res, out := b.api("POST", "/api-internal/account/ssh/certificates/nope/revoke", nil)
	wantStatus(t, res, out, 429)
	if res.Header.Get("Retry-After") == "" || !strings.Contains(str(out, "error"), "Too many") {
		t.Errorf("over the limit: %v %v", res.Header, out["_raw"])
	}
	sam := e.signedInMFA(t, e.user(t, org, "sam", model.RoleUser))
	if res, out := sam.api("POST", "/api-internal/account/ssh/certificates/nope/revoke", nil); res.StatusCode != 404 {
		t.Errorf("another user: %d %v", res.StatusCode, out["_raw"])
	}
}

// A certificate from the account page stands on the session: it records the session's epoch and sign-out stamp, not
// the current ones.
func TestAccountSSHCertificateStandsOnTheSession(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	org, prod := sshOrg(t, e)
	pat := e.user(t, org, "pat", model.RoleUser)
	b := e.signedInMFA(t, pat)
	b.fresh()
	sessions, _, err := e.Svc.Sessions.List(ctx, store.ListQuery{Scope: pat.ID})
	if err != nil || len(sessions) != 1 {
		t.Fatalf("sessions: %v %v", sessions, err)
	}
	sess := sessions[0]
	sess.Stamp = model.SignOutStamp{Server: 7, Org: 9} // a stamp of the session's own (still current: counters only go up)
	if err := e.Svc.Sessions.Update(ctx, sess); err != nil {
		t.Fatal(err)
	}
	e.Server.Sessions.Evict(sess.ID, "")
	res, out := b.api("POST", "/api-internal/account/ssh/sign", map[string]any{"tenant_id": prod.ID, "public_key": sshPub(t)})
	wantStatus(t, res, out, 200)
	c, err := e.Svc.SSHCerts.GetIn(ctx, org.ID, str(out, "id"))
	if err != nil {
		t.Fatal(err)
	}
	if c.SessionEpoch != sess.Epoch || c.Stamp != sess.Stamp {
		t.Errorf("certificate epoch %d stamp %+v, the session's %d %+v", c.SessionEpoch, c.Stamp, sess.Epoch, sess.Stamp)
	}
}
