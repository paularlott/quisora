package oidc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	logtesting "github.com/paularlott/logger/testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/sshca"
	"github.com/paularlott/quisora/internal/web"
	"golang.org/x/crypto/ssh"
)

var mfaAMR = []string{"pwd", "otp", "mfa"}

// sshEnv is a harness with a tenant that has SSH on, its SSH application, and the endpoints of it.
type sshEnv struct {
	*harness
	tn   *model.Tenant
	cl   *model.Client
	base string // /o/<org id>/ssh/<tenant id>
}

// sshTenant makes tenant name (open to everyone) and turns SSH on, as in.
func (h *harness) sshTenant(name string, in service.SSHSettingsInput) *sshEnv {
	h.t.Helper()
	tn := h.tenant(name, model.TenantSettings{PasswordLogin: true, PasskeyLogin: true, AllProviders: true})
	in.Enabled = ptr(true)
	tn, err := h.env.Svc.UpdateTenantSSH(context.Background(), h.admin, tn.ID, in)
	if err != nil {
		h.t.Fatal(err)
	}
	cl, err := h.env.Svc.Clients.Get(context.Background(), tn.SSH.ClientID)
	if err != nil {
		h.t.Fatal(err)
	}
	return &sshEnv{harness: h, tn: tn, cl: cl, base: h.orgBase + "/ssh/" + tn.ID}
}

// set changes the tenant's SSH settings.
func (e *sshEnv) set(in service.SSHSettingsInput) {
	e.t.Helper()
	tn, err := e.env.Svc.UpdateTenantSSH(context.Background(), e.admin, e.tn.ID, in)
	if err != nil {
		e.t.Fatal(err)
	}
	e.tn = tn
	e.p.InvalidateClient(tn.SSH.ClientID) // the cluster does this in a server: the application follows AllowPrivileged
}

// token signs u in to the SSH application (a browser flow on a loopback port the way the CLI does it, so the
// redirect URI has a port that the registration does not) and returns the token response. extra changes the
// authorization request.
func (e *sshEnv) token(u *model.User, amr []string, authTime time.Time, extra url.Values) tokResp {
	e.t.Helper()
	return e.tokenFor(e.cl, u, amr, authTime, extra)
}

func (e *sshEnv) tokenFor(cl *model.Client, u *model.User, amr []string, authTime time.Time, extra url.Values) tokResp {
	e.t.Helper()
	return e.tokenIn(cl, e.sessionWith(u, amr, authTime), extra)
}

// tokenIn is tokenFor with the browser session c.
func (e *sshEnv) tokenIn(cl *model.Client, c *http.Client, extra url.Values) tokResp {
	e.t.Helper()
	v, ch := pkce()
	port := 20000 + int(binary.BigEndian.Uint16(randBytes(2)))%40000 // the CLI lets the system choose
	redirect := "http://127.0.0.1:" + strconv.Itoa(port) + "/callback"
	q := authzQuery(cl, ch, url.Values{"redirect_uri": {redirect}, "scope": {"openid profile"}})
	for k, v := range extra {
		q[k] = v
	}
	to := e.authorize(c, q)
	code := to.Query().Get("code")
	if code == "" || !strings.HasPrefix(to.String(), redirect+"?") {
		e.t.Fatalf("no code at the loopback redirect: %s", to)
	}
	r := e.post(e.orgBase+"/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {cl.ID},
		"redirect_uri": {redirect}, "code_verifier": {v}}, "", "")
	if r.status != 200 {
		e.t.Fatalf("exchange: %d %v", r.status, r.m)
	}
	return r
}

// mfaToken is a token of u's sign-in with two factors, now.
func (e *sshEnv) mfaToken(u *model.User) string {
	e.t.Helper()
	return e.token(u, mfaAMR, time.Now(), url.Values{"acr_values": {acrMFA}, "max_age": {"3600"}}).str("access_token")
}

// user makes a member of the primary organization.
func (h *harness) sshUser(name string, role model.Role) *model.User {
	h.t.Helper()
	pw := "correct horse battery"
	u, err := h.env.Svc.CreateUser(context.Background(), service.System, h.env.Primary.ID, service.UserInput{
		Username: ptr(name), Email: ptr(name + "@example.com"), Password: &pw, GivenName: ptr(name), FamilyName: ptr("T"),
		Verified: ptr(true), Role: &role})
	if err != nil {
		h.t.Fatal(err)
	}
	return u
}

// sshKey makes a key pair and returns the authorized_keys line of its public key.
func sshKey(t testing.TB) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))), priv
}

// sign posts a sign request with the token (scheme Bearer) and returns the status and the decoded answer.
func (e *sshEnv) sign(tok string, payload any, hdr ...string) (int, map[string]any, http.Header) {
	e.t.Helper()
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, e.env.URL+e.base+"/sign", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := e.http.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	m := map[string]any{}
	_ = json.Unmarshal([]byte(body(resp)), &m)
	return resp.StatusCode, m, resp.Header
}

// userCA is the key that signs user certificates of the tenant now.
func (e *sshEnv) userCA() ssh.PublicKey {
	e.t.Helper()
	keys, err := e.env.Svc.SSHKeys(context.Background(), e.tn.ID, model.SSHPurposeUser)
	if err != nil || len(keys) == 0 {
		e.t.Fatalf("user CA keys: %v %v", keys, err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keys[len(keys)-1].PublicKey))
	if err != nil {
		e.t.Fatal(err)
	}
	return pub
}

func TestSSHDiscovery(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	e := h.sshTenant("prod", service.SSHSettingsInput{HostCerts: ptr(true), HostPatterns: &[]string{"*.example.com"}})

	for name, ref := range map[string]string{"id": e.tn.ID, "name": e.tn.Name} {
		resp := h.get(h.http, h.orgBase+"/ssh/"+ref)
		if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "public, max-age=60" ||
			!strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
			t.Fatalf("by %s: %d %v", name, resp.StatusCode, resp.Header)
		}
		var d map[string]any
		if err := json.Unmarshal([]byte(body(resp)), &d); err != nil {
			t.Fatal(err)
		}
		iss := h.issuer()
		want := map[string]any{
			"issuer": iss, "org": h.env.Primary.Name, "tenant": "prod", "tenant_id": e.tn.ID, "enabled": true, "client_id": e.cl.ID,
			"authorization_endpoint": iss + "/oauth/authorize", "token_endpoint": iss + "/oauth/token",
			"device_authorization_endpoint": iss + "/oauth/device_authorization",
			"sign_endpoint":                 iss + "/ssh/" + e.tn.ID + "/sign", "user_ca_endpoint": iss + "/ssh/" + e.tn.ID + "/ca.pub",
			"known_hosts_endpoint": iss + "/ssh/" + e.tn.ID + "/known_hosts", "krl_endpoint": iss + "/ssh/" + e.tn.ID + "/krl",
			"host_sign_endpoint": h.env.Cfg.Server.PublicURL + "/api/orgs/" + h.env.Primary.ID + "/tenants/" + e.tn.ID + "/ssh/host-certificates",
			"cert_ttl":           float64(28800), "max_auth_age": float64(3600), "host_certs": true,
			"host_patterns": []any{"*.example.com"}, "acr_values": "urn:quisora:acr:mfa",
		}
		if len(d) != len(want) {
			t.Errorf("by %s: %d members, want %d: %v", name, len(d), len(want), d)
		}
		for k, v := range want {
			if got, _ := json.Marshal(d[k]); string(got) != string(mustJSON(v)) {
				t.Errorf("by %s: %s = %s, want %s", name, k, got, mustJSON(v))
			}
		}
	}
	// the organization may be named by its name as well
	if resp := h.get(h.http, "/o/"+h.env.Primary.Name+"/ssh/"+e.tn.ID); resp.StatusCode != 200 {
		t.Errorf("by organization name: %d", resp.StatusCode)
	}

	// no host patterns when host certificates are off: an empty list, not null
	e.set(service.SSHSettingsInput{HostCerts: ptr(false), HostPatterns: &[]string{}})
	var d map[string]any
	_ = json.Unmarshal([]byte(body(h.get(h.http, e.base))), &d)
	if p, ok := d["host_patterns"].([]any); !ok || len(p) != 0 || d["host_certs"] != false {
		t.Errorf("host certificates off: %v", d)
	}
}

// A tenant that is unknown, or never had SSH, is not there, for every endpoint, and the two look alike.
func TestSSHNotFound(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	e := h.sshTenant("prod", service.SSHSettingsInput{})
	plain := h.tenant("plain", model.TenantSettings{PasswordLogin: true})
	// settings saved while SSH is off, before it was ever on: nothing was published, so nothing is there
	saved := h.tenant("saved", model.TenantSettings{PasswordLogin: true})
	if _, err := h.env.Svc.UpdateTenantSSH(context.Background(), h.admin, saved.ID, service.SSHSettingsInput{CertTTL: ptr(600)}); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{plain.ID, plain.Name, saved.ID, saved.Name, "nosuch", "t_" + strings.Repeat("x", 20)} {
		for _, suffix := range []string{"", "/ca.pub", "/known_hosts", "/krl"} {
			if resp := h.get(h.http, h.orgBase+"/ssh/"+ref+suffix); resp.StatusCode != 404 {
				t.Errorf("%s%s: %d", ref, suffix, resp.StatusCode)
			} else {
				body(resp)
			}
		}
		b, _ := json.Marshal(map[string]string{"public_key": "x"})
		resp, err := h.http.Post(h.env.URL+h.orgBase+"/ssh/"+ref+"/sign", "application/json", bytes.NewReader(b))
		if err != nil || resp.StatusCode != 404 {
			t.Errorf("%s sign: %v %v", ref, resp, err)
		}
	}
	// another organization's tenant is not served under this one's path
	if resp := h.get(h.http, "/o/nosuchorg/ssh/"+e.tn.ID); resp.StatusCode != 404 {
		t.Errorf("unknown organization: %d", resp.StatusCode)
	}
}

// With SSH turned off the CA keys, the discovery document and the revocation list are still served (the servers go on
// fetching them, and the list revokes every certificate), while signing is not there.
func TestSSHOffStillPublishes(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	e := h.sshTenant("prod", service.SSHSettingsInput{})
	tok := e.mfaToken(h.user)
	key, _ := sshKey(t)
	st, m, _ := e.sign(tok, map[string]any{"public_key": key})
	if st != 200 {
		t.Fatalf("sign: %d %v", st, m)
	}
	serial, _ := strconv.ParseUint(m["serial"].(string), 10, 64)
	revoked := func() []uint64 {
		resp := h.get(h.http, e.base+"/krl")
		if resp.StatusCode != 200 {
			t.Fatalf("krl: %d", resp.StatusCode)
		}
		k, err := sshca.ParseKRL([]byte(body(resp)))
		if err != nil {
			t.Fatal(err)
		}
		var out []uint64
		for _, ca := range k.CAs {
			out = append(out, ca.Serials...)
		}
		return out
	}
	if got := revoked(); len(got) != 0 {
		t.Fatalf("revoked before: %v", got)
	}

	e.set(service.SSHSettingsInput{Enabled: ptr(false)})
	for _, suffix := range []string{"", "/ca.pub", "/known_hosts", "/krl"} {
		if resp := h.get(h.http, e.base+suffix); resp.StatusCode != 200 {
			t.Errorf("%s while off: %d", suffix, resp.StatusCode)
		} else {
			body(resp)
		}
	}
	var d map[string]any
	_ = json.Unmarshal([]byte(body(h.get(h.http, e.base))), &d)
	if d["enabled"] != false {
		t.Errorf("discovery while off: %v", d)
	}
	if got := revoked(); !slices.Equal(got, []uint64{serial}) {
		t.Errorf("revoked while off: %v, want [%d]", got, serial)
	}
	if st, _, _ := e.sign(tok, map[string]any{"public_key": key}); st != 404 {
		t.Errorf("sign while off: %d", st)
	}

	// on again: the certificate counts again
	e.set(service.SSHSettingsInput{Enabled: ptr(true)})
	if got := revoked(); len(got) != 0 {
		t.Errorf("revoked after turning SSH on: %v", got)
	}
}

func TestSSHCAKeysAndKnownHosts(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	e := h.sshTenant("prod", service.SSHSettingsInput{})
	comment := func(purpose, id string) string {
		return "quisora:" + h.env.Primary.Name + "/prod:" + purpose + ":" + id
	}

	lines := func(path string) []string {
		resp := h.get(h.http, e.base+path)
		if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-cache" || resp.Header.Get("ETag") == "" ||
			!strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
			t.Fatalf("%s: %d %v", path, resp.StatusCode, resp.Header)
		}
		text := body(resp)
		if text == "" {
			return nil
		}
		if !strings.HasSuffix(text, "\n") {
			t.Fatalf("%s: no final newline: %q", path, text)
		}
		return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	}

	keys, _ := h.env.Svc.SSHKeys(ctx, e.tn.ID, model.SSHPurposeUser)
	got := lines("/ca.pub")
	if len(got) != 1 || len(keys) != 1 {
		t.Fatalf("one user CA key: %v %v", got, keys)
	}
	pub, c, _, _, err := ssh.ParseAuthorizedKey([]byte(got[0]))
	if err != nil || c != comment("user", keys[0].ID) || strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) != keys[0].PublicKey {
		t.Fatalf("ca.pub line %q: %v (comment %q)", got[0], err, c)
	}

	// host certificates are off: nothing to trust, whatever the patterns
	if got := lines("/known_hosts"); got != nil {
		t.Errorf("known_hosts with host certificates off: %v", got)
	}

	e.set(service.SSHSettingsInput{HostCerts: ptr(true), HostPatterns: &[]string{"*.example.com", "db1.internal"}})
	hostKeys, _ := h.env.Svc.SSHKeys(ctx, e.tn.ID, model.SSHPurposeHost)
	got = lines("/known_hosts")
	if len(got) != 1 || len(hostKeys) != 1 {
		t.Fatalf("one host CA key: %v %v", got, hostKeys)
	}
	if want := "@cert-authority *.example.com,db1.internal " + hostKeys[0].PublicKey + " " + comment("host", hostKeys[0].ID); got[0] != want {
		t.Errorf("known_hosts line\n got %q\nwant %q", got[0], want)
	}
	if _, _, _, _, _, err := ssh.ParseKnownHosts([]byte(got[0])); err != nil {
		t.Errorf("known_hosts does not parse: %v", err)
	}
	// host keys are not in ca.pub, nor user keys in known_hosts
	if got := lines("/ca.pub"); len(got) != 1 || strings.Contains(got[0], ":host:") {
		t.Errorf("ca.pub with host certificates on: %v", got)
	}

	// a successor is published at once: both keys, oldest first
	if _, err := h.env.Svc.RotateSSHKey(ctx, h.admin, e.tn.ID, model.SSHPurposeUser, false); err != nil {
		t.Fatal(err)
	}
	keys, _ = h.env.Svc.SSHKeys(ctx, e.tn.ID, model.SSHPurposeUser)
	got = lines("/ca.pub")
	if len(got) != 2 || len(keys) != 2 {
		t.Fatalf("after rotation: %v %v", got, keys)
	}
	for i, k := range keys {
		if !strings.HasPrefix(got[i], k.PublicKey+" ") || !strings.HasSuffix(got[i], comment("user", k.ID)) {
			t.Errorf("line %d: %q, want key %s", i, got[i], k.ID)
		}
	}
}

func TestSSHKRL(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	e := h.sshTenant("prod", service.SSHSettingsInput{})
	tok := e.mfaToken(h.user)
	key, _ := sshKey(t)
	signOne := func() uint64 {
		st, m, _ := e.sign(tok, map[string]any{"public_key": key})
		if st != 200 {
			t.Fatalf("sign: %d %v", st, m)
		}
		n, err := strconv.ParseUint(m["serial"].(string), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	revoked, kept := signOne(), signOne()

	fetch := func() *sshca.KRL {
		resp := h.get(h.http, e.base+"/krl")
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/octet-stream" || resp.Header.Get("Cache-Control") != "no-cache" ||
			resp.Header.Get("ETag") == "" {
			t.Fatalf("krl: %d %v", resp.StatusCode, resp.Header)
		}
		k, err := sshca.ParseKRL([]byte(body(resp)))
		if err != nil {
			t.Fatalf("the KRL does not parse: %v", err)
		}
		return k
	}
	listed := func(k *sshca.KRL, serial uint64) bool {
		for _, ca := range k.CAs {
			for _, s := range ca.Serials {
				if s == serial {
					return true
				}
			}
		}
		return false
	}
	k := fetch()
	if listed(k, revoked) || listed(k, kept) || len(k.CAs) == 0 {
		t.Fatalf("before revoking: %+v", k)
	}

	views, err := h.env.Svc.ListSSHCerts(ctx, h.admin, e.tn.ID, service.SSHCertFilter{})
	if err != nil || len(views) != 2 {
		t.Fatalf("certificates: %v %v", views, err)
	}
	for _, v := range views {
		if v.Serial == revoked {
			if err := h.env.Svc.RevokeSSHCert(ctx, h.admin, h.env.Primary.ID, v.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	k = fetch()
	if !listed(k, revoked) || listed(k, kept) {
		t.Fatalf("after revoking: %+v", k)
	}
	// under the CA that signed it
	ca := e.userCA().Marshal()
	found := false
	for _, c := range k.CAs {
		if bytes.Equal(c.Key, ca) {
			found = len(c.Serials) == 1 && c.Serials[0] == revoked
		}
	}
	if !found {
		t.Errorf("the revoked serial is not listed under the user CA: %+v", k)
	}
}

func TestSSHSign(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	if _, err := h.env.Svc.CreateGroupWithMembers(ctx, h.admin, h.env.Primary.ID, service.GroupInput{DisplayName: ptr("ops")}, []string{h.user.ID}); err != nil {
		t.Fatal(err)
	}
	e := h.sshTenant("prod", service.SSHSettingsInput{CertTTL: ptr(3600)})
	tok := e.mfaToken(h.user)
	key, _ := sshKey(t)

	check := func(m map[string]any, principals []string, ttl time.Duration) *ssh.Certificate {
		t.Helper()
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(m["certificate"].(string)))
		if err != nil {
			t.Fatal(err)
		}
		cert, ok := pub.(*ssh.Certificate)
		if !ok {
			t.Fatalf("not a certificate: %T", pub)
		}
		ca := e.userCA()
		checker := ssh.CertChecker{IsUserAuthority: func(auth ssh.PublicKey) bool { return bytes.Equal(auth.Marshal(), ca.Marshal()) }}
		if err := checker.CheckCert(principals[0], cert); err != nil {
			t.Errorf("CheckCert: %v", err)
		}
		if cert.CertType != ssh.UserCert || !equalStrings(cert.ValidPrincipals, principals) {
			t.Errorf("certificate: type %d principals %v, want %v", cert.CertType, cert.ValidPrincipals, principals)
		}
		if want := h.user.Username + "@" + h.env.Primary.Name + "/" + h.user.ID; cert.KeyId != want || m["key_id"] != want {
			t.Errorf("key id %q, %v want %q", cert.KeyId, m["key_id"], want)
		}
		if m["serial"] != strconv.FormatUint(cert.Serial, 10) || cert.Serial == 0 {
			t.Errorf("serial %v, certificate %d", m["serial"], cert.Serial)
		}
		want, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(key))
		if !bytes.Equal(cert.Key.Marshal(), want.Marshal()) {
			t.Error("the certificate is for another key")
		}
		va, _ := time.Parse(time.RFC3339, m["valid_after"].(string))
		vb, _ := time.Parse(time.RFC3339, m["valid_before"].(string))
		if vb.Unix() != int64(cert.ValidBefore) || va.Unix() != int64(cert.ValidAfter) {
			t.Errorf("validity %v..%v, certificate %d..%d", va, vb, cert.ValidAfter, cert.ValidBefore)
		}
		if d := time.Until(vb) - ttl; d > time.Minute || d < -time.Minute {
			t.Errorf("valid for %v, want about %v", time.Until(vb), ttl)
		}
		if p, _ := m["principals"].([]any); len(p) != len(principals) {
			t.Errorf("principals in the answer: %v", m["principals"])
		}
		return cert
	}

	st, m, hdr := e.sign(tok, map[string]any{"public_key": key})
	if st != 200 || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("sign: %d %v %v", st, m, hdr)
	}
	check(m, []string{"alice", "group:ops"}, time.Hour)

	// a subset of the principals and a shorter life
	st, m, _ = e.sign(tok, map[string]any{"public_key": key, "principals": []string{"group:ops"}, "ttl": 600})
	if st != 200 {
		t.Fatalf("subset: %d %v", st, m)
	}
	check(m, []string{"group:ops"}, 10*time.Minute)

	// the tenant may be named by its name too, and the certificate is kept (audited, listed)
	req, _ := http.NewRequest(http.MethodPost, h.env.URL+h.orgBase+"/ssh/prod/sign", strings.NewReader(`{"public_key":`+string(mustJSON(key))+`}`))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+tok)
	if resp, err := h.http.Do(req); err != nil || resp.StatusCode != 200 {
		t.Fatalf("by name: %v %v", resp, err)
	} else {
		body(resp)
	}
	if n := len(h.auditEvents("ssh.cert.issue")); n != 3 {
		t.Errorf("%d ssh.cert.issue events, want 3", n)
	}
	if views, _ := h.env.Svc.ListSSHCerts(ctx, h.admin, e.tn.ID, service.SSHCertFilter{UserID: h.user.ID}); len(views) != 3 {
		t.Errorf("%d certificates listed", len(views))
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestSSHSignRefusals(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	e := h.sshTenant("prod", service.SSHSettingsInput{})
	key, _ := sshKey(t)
	good := map[string]any{"public_key": key}

	// the person did not sign in with a second factor
	pwOnly := e.token(h.user, []string{"pwd"}, time.Now(), nil).str("access_token")
	if st, m, _ := e.sign(pwOnly, good); st != 403 || m["error"] != "access_denied" || !strings.Contains(m["error_description"].(string), "second factor") {
		t.Errorf("password only: %d %v", st, m)
	}
	if n := len(h.auditEvents("ssh.cert.refused")); n != 1 {
		t.Errorf("%d refusals audited", n)
	}

	// a sign-in too old
	stale := e.token(h.user, mfaAMR, time.Now().Add(-2*time.Hour), nil).str("access_token")
	if st, m, _ := e.sign(stale, good); st != 403 || m["error"] != "access_denied" || !strings.Contains(m["error_description"].(string), "too old") {
		t.Errorf("old sign-in: %d %v", st, m)
	}

	// a token of another application, even of the same tenant
	app, _ := h.tenantClient(e.tn, func(in *service.ClientInput) {
		in.AuthMethod = ptr(model.AuthMethodNone)
		in.RedirectURIs = &[]string{"http://127.0.0.1/callback"}
		in.GrantTypes = &[]string{"authorization_code"}
	})
	other := e.tokenFor(app, h.user, mfaAMR, time.Now(), nil).str("access_token")
	if st, m, _ := e.sign(other, good); st != 403 || m["error"] != "access_denied" {
		t.Errorf("another application's token: %d %v", st, m)
	}

	// managers and administrators: not unless the tenant allows it
	mgr := h.sshUser("mallory", model.RoleManager)
	mtok := e.mfaToken(mgr)
	if st, m, _ := e.sign(mtok, good); st != 403 || !strings.Contains(m["error_description"].(string), "managers and administrators") {
		t.Errorf("manager: %d %v", st, m)
	}
	e.set(service.SSHSettingsInput{AllowPrivileged: ptr(true)})
	if st, m, _ := e.sign(mtok, good); st != 200 {
		t.Errorf("manager, allowed: %d %v", st, m)
	}
	e.set(service.SSHSettingsInput{AllowPrivileged: ptr(false)})
	if st, _, _ := e.sign(mtok, good); st != 403 {
		t.Errorf("manager, not allowed again: %d", st)
	}

	// a client's own token (client credentials) is nobody's sign-in
	cc, secret := h.newClient(func(in *service.ClientInput) {
		in.GrantTypes = &[]string{"client_credentials"}
		in.Scopes = &[]string{"api"}
	})
	r := h.token(url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}, cc, secret)
	if r.status != 200 {
		t.Fatalf("client credentials: %d %v", r.status, r.m)
	}
	if st, _, hdr := e.sign(r.str("access_token"), good); st != 401 || !strings.Contains(hdr.Get("WWW-Authenticate"), "invalid_token") {
		t.Errorf("client credentials token: %d %v", st, hdr)
	}

	// no token, a bad one, and a form of the token that is not allowed
	if st, _, hdr := e.sign("", good); st != 401 || !strings.HasPrefix(hdr.Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("no token: %d %v", st, hdr)
	}
	if st, _, hdr := e.sign("not.a.token", good); st != 401 || !strings.Contains(hdr.Get("WWW-Authenticate"), "invalid_token") {
		t.Errorf("bad token: %d %v", st, hdr)
	}
	good_ := e.mfaToken(h.user)
	if st, _, _ := e.sign(good_, good, "Content-Type", "text/plain"); st != 400 {
		t.Errorf("content type: %d", st)
	}
	b, _ := json.Marshal(good)
	req, _ := http.NewRequest(http.MethodPost, h.env.URL+e.base+"/sign?access_token="+good_, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if resp, err := h.http.Do(req); err != nil || resp.StatusCode != 400 {
		t.Errorf("token in the query: %v %v", resp, err)
	}

	// bad requests
	for name, tc := range map[string]struct {
		body  any
		field string
	}{
		"not a key":           {map[string]any{"public_key": "ssh-ed25519 notbase64"}, "public_key"},
		"no key":              {map[string]any{}, "public_key"},
		"a certificate":       {map[string]any{"public_key": certLine(t, e)}, "public_key"},
		"unknown principal":   {map[string]any{"public_key": key, "principals": []string{"root"}}, "principals"},
		"ttl too long":        {map[string]any{"public_key": key, "ttl": 1 << 40}, "ttl"},
		"ttl too short":       {map[string]any{"public_key": key, "ttl": 5}, "ttl"},
		"negative ttl":        {map[string]any{"public_key": key, "ttl": -1}, ""},
		"unknown field":       {map[string]any{"public_key": key, "principal": "alice"}, ""},
		"not an object":       {[]string{"x"}, ""},
		"ttl not a number":    {map[string]any{"public_key": key, "ttl": "600"}, ""},
		"principals a string": {map[string]any{"public_key": key, "principals": "alice"}, ""},
	} {
		st, m, _ := e.sign(good_, tc.body)
		if st != 400 || m["error"] != "invalid_request" || m["error_description"] == "" {
			t.Errorf("%s: %d %v", name, st, m)
		} else if tc.field != "" && !strings.HasPrefix(m["error_description"].(string), tc.field+": ") {
			t.Errorf("%s: %v", name, m["error_description"])
		}
	}
	// a body over the limit
	if st, m, _ := e.sign(good_, map[string]any{"public_key": strings.Repeat("a", maxSSHSignBody)}); st != http.StatusRequestEntityTooLarge {
		t.Errorf("a large body: %d %v", st, m)
	}

	// SSH turned off: no certificates, as though there were no endpoint
	e.set(service.SSHSettingsInput{Enabled: ptr(false)})
	if st, _, _ := e.sign(good_, good); st != 404 {
		t.Errorf("SSH off: %d", st)
	}
}

// certLine is a certificate of the tenant's CA, which is not a key to be certified.
func certLine(t testing.TB, e *sshEnv) string {
	t.Helper()
	key, _ := sshKey(t)
	tok := e.mfaToken(e.user)
	st, m, _ := e.sign(tok, map[string]any{"public_key": key})
	if st != 200 {
		t.Fatalf("sign: %d %v", st, m)
	}
	return m["certificate"].(string)
}

func TestSSHSignDPoP(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	e := h.sshTenant("prod", service.SSHSettingsInput{})
	k := newDPoPKey(t, AlgES256)
	key, _ := sshKey(t)

	// the sign-in: the token endpoint asks for a nonce first
	c := h.sessionWith(h.user, mfaAMR, time.Now())
	v, ch := pkce()
	redirect := "http://127.0.0.1:43211/callback"
	code := h.authorize(c, authzQuery(e.cl, ch, url.Values{"redirect_uri": {redirect}, "scope": {"openid profile"}, "acr_values": {acrMFA}})).Query().Get("code")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {e.cl.ID}, "redirect_uri": {redirect}, "code_verifier": {v}}
	proof := func(nonce string) string {
		return h.proof(k, "POST", h.orgBase+"/oauth/token", func(_, c map[string]any) { c["nonce"] = nonce })
	}
	r := h.post(h.orgBase+"/oauth/token", form, "", "", "DPoP", proof(""))
	if r.status != 400 || r.hdr.Get("DPoP-Nonce") == "" {
		t.Fatalf("no nonce: %d %v", r.status, r.m)
	}
	r = h.post(h.orgBase+"/oauth/token", form, "", "", "DPoP", proof(r.hdr.Get("DPoP-Nonce")))
	if r.status != 200 || r.str("token_type") != "DPoP" {
		t.Fatalf("exchange: %d %v", r.status, r.m)
	}
	at := r.str("access_token")

	signProof := func(edit func(hdr, cl map[string]any)) string {
		return h.proof(k, "POST", e.base+"/sign", func(hdr, c map[string]any) {
			c["ath"], c["nonce"] = ath(at), nil
			if edit != nil {
				edit(hdr, c)
			}
		})
	}
	post := func(scheme, proof string) (int, map[string]any, http.Header) {
		return e.sign(at, map[string]any{"public_key": key}, "Authorization", scheme+" "+at, "DPoP", proof)
	}
	if st, m, _ := post("DPoP", signProof(nil)); st != 200 || m["certificate"] == nil {
		t.Fatalf("DPoP: %d %v", st, m)
	}
	// without the proof, as a bearer, with a proof of another request: refused with a DPoP challenge
	for name, tc := range map[string]struct{ scheme, proof string }{
		"bearer scheme": {"Bearer", signProof(nil)},
		"no proof":      {"DPoP", ""},
		"wrong path":    {"DPoP", h.proof(k, "POST", h.orgBase+"/oauth/userinfo", func(_, c map[string]any) { c["ath"] = ath(at); c["nonce"] = nil })},
		"wrong method":  {"DPoP", h.proof(k, "GET", e.base+"/sign", func(_, c map[string]any) { c["ath"] = ath(at); c["nonce"] = nil })},
	} {
		st, _, hdr := post(tc.scheme, tc.proof)
		if st != 401 {
			t.Errorf("%s: %d", name, st)
		}
		if tc.scheme == "DPoP" && !strings.HasPrefix(hdr.Get("WWW-Authenticate"), "DPoP ") {
			t.Errorf("%s: challenge %q", name, hdr.Get("WWW-Authenticate"))
		}
	}
}

func TestSSHSignRateLimits(t *testing.T) {
	t.Parallel()
	t.Run("per user", func(t *testing.T) {
		h := setup(t, nil)
		e := h.sshTenant("prod", service.SSHSettingsInput{})
		tok := e.mfaToken(h.user)
		bad := map[string]any{"public_key": "nope"} // counted all the same
		for i := range sshSignsPerUser {
			if st, _, _ := e.sign(tok, bad); st != 400 {
				t.Fatalf("request %d: %d", i, st)
			}
		}
		st, m, hdr := e.sign(tok, bad)
		if st != 429 || m["error"] != "slow_down" || hdr.Get("Retry-After") == "" {
			t.Fatalf("over the limit: %d %v %v", st, m, hdr)
		}
		// another user is not held up by it
		other := e.mfaToken(h.sshUser("bob", model.RoleUser))
		if st, _, _ := e.sign(other, bad); st != 400 {
			t.Errorf("another user: %d", st)
		}
	})
	t.Run("per address", func(t *testing.T) {
		h := setup(t, nil)
		e := h.sshTenant("prod", service.SSHSettingsInput{})
		bad := map[string]any{"public_key": "nope"}
		var toks []string
		for i := range 4 {
			toks = append(toks, e.mfaToken(h.sshUser("user"+strconv.Itoa(i), model.RoleUser)))
		}
		for i := range sshSignsPerIP {
			if st, _, _ := e.sign(toks[i%4], bad); st != 400 {
				t.Fatalf("request %d: %d", i, st)
			}
		}
		// every user is under the limit, the address is not
		if st, m, _ := e.sign(toks[0], bad); st != 429 || m["error"] != "slow_down" {
			t.Fatalf("over the address limit: %d %v", st, m)
		}
	})
	t.Run("counter unavailable", func(t *testing.T) {
		h := setup(t, nil)
		e := h.sshTenant("prod", service.SSHSettingsInput{})
		tok := e.mfaToken(h.user)
		key, _ := sshKey(t)
		h.useEph(func(op, ns string) error {
			if op == "incr" && ns == nsRateOIDC {
				return errors.New("counter owner did not answer")
			}
			return nil
		})
		if st, m, hdr := e.sign(tok, map[string]any{"public_key": key}); st != 503 || hdr.Get("Retry-After") == "" || m["error"] != "temporarily_unavailable" {
			t.Errorf("counter failing: %d %v %v", st, m, hdr)
		}
	})
}

// The CLI signs in at a loopback address with a port of its own choosing; the application is registered without one.
func TestSSHApplicationOAuth(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	e := h.sshTenant("prod", service.SSHSettingsInput{})
	c := h.sessionWith(h.user, []string{"pwd"}, time.Now().Add(-2*time.Hour))
	q := func(redirect string, extra url.Values) url.Values {
		_, ch := pkce()
		qq := authzQuery(e.cl, ch, url.Values{"redirect_uri": {redirect}, "scope": {"openid profile"}})
		for k, v := range extra {
			qq[k] = v
		}
		return qq
	}
	if e.cl.RedirectURIs[0] != "http://127.0.0.1/callback" || e.cl.AuthMethod != model.AuthMethodNone || !e.cl.FirstParty {
		t.Fatalf("the application: %+v", e.cl)
	}

	// any port, same path: the stale password sign-in is sent to sign in again (acr_values, max_age), at this endpoint
	for _, port := range []string{"1", "8080", "54321", "65535"} {
		resp := h.get(c, h.orgBase+"/oauth/authorize?"+q("http://127.0.0.1:"+port+"/callback", url.Values{"acr_values": {acrMFA}, "max_age": {"3600"}}).Encode())
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("port %s: %d %s", port, resp.StatusCode, body(resp))
		}
		if u := loc(t, resp); !strings.HasSuffix(u.Path, "/login") {
			t.Errorf("port %s: a stale password sign-in was not asked to sign in again: %s", port, u)
		}
	}
	// a fresh two-factor sign-in goes through to the loopback address with the code and the state
	fresh := h.sessionWith(h.user, mfaAMR, time.Now())
	to := h.authorize(fresh, q("http://127.0.0.1:50123/callback", url.Values{"acr_values": {acrMFA}, "max_age": {"3600"}}))
	if to.Host != "127.0.0.1:50123" || to.Path != "/callback" || to.Query().Get("code") == "" || to.Query().Get("state") != "st1" {
		t.Errorf("fresh sign-in: %s", to)
	}
	// another path, host or scheme is not the registered address
	for _, bad := range []string{"http://127.0.0.1:50123/other", "http://127.0.0.1:50123/callback/x", "http://localhost:50123/callback",
		"https://127.0.0.1:50123/callback", "http://127.0.0.2:50123/callback", "http://evil.example/callback"} {
		resp := h.get(fresh, h.orgBase+"/oauth/authorize?"+q(bad, nil).Encode())
		if resp.StatusCode == http.StatusFound && strings.HasPrefix(resp.Header.Get("Location"), bad) {
			t.Errorf("%s was accepted as a redirect", bad)
		}
		body(resp)
	}
	// no refresh token: a certificate needs a sign-in each time it is asked for after the token's life
	r := e.token(h.user, mfaAMR, time.Now(), nil)
	if r.str("refresh_token") != "" || r.str("access_token") == "" {
		t.Errorf("tokens: %v", r.m)
	}
	if claims := claimsOf(t, r.str("access_token")); claims["client_id"] != e.cl.ID {
		t.Errorf("claims: %v", claims)
	}
}

// The application's device sign-in is for managers and administrators only where the tenant allows certificates for
// them.
func TestSSHApplicationDeviceFlow(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	e := h.sshTenant("prod", service.SSHSettingsInput{})
	mgr := h.sshUser("mallory", model.RoleManager)
	b, csrf := h.session(mgr)

	dc, uc := h.startDevice(e.cl, "openid profile")
	resp := h.get(b, h.orgBase+"/device?user_code="+url.QueryEscape(uc))
	if pg := body(resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(pg, "Managers and administrators cannot sign in on devices") {
		t.Fatalf("manager, not allowed: %d %s", resp.StatusCode, pg)
	}
	if r := h.pollDevice(e.cl, dc); r.str("error") != "access_denied" {
		t.Fatalf("poll after refusal: %v", r.m)
	}

	e.set(service.SSHSettingsInput{AllowPrivileged: ptr(true)})
	cl, err := h.env.Svc.Clients.Get(context.Background(), e.tn.SSH.ClientID)
	if err != nil || !cl.DevicePrivileged {
		t.Fatalf("device_privileged_users after allowing: %v %+v", err, cl)
	}
	dc, uc = h.startDevice(e.cl, "openid profile")
	if status, page := h.consentDevice(b, csrf, uc, true); status != 200 {
		t.Fatalf("manager, allowed: %d %s", status, page)
	}
	if r := h.pollDevice(e.cl, dc); r.status != 200 || r.str("access_token") == "" || r.str("refresh_token") != "" {
		t.Fatalf("tokens: %d %v", r.status, r.m)
	}

	e.set(service.SSHSettingsInput{AllowPrivileged: ptr(false)})
	if cl, _ := h.env.Svc.Clients.Get(context.Background(), e.tn.SSH.ClientID); cl.DevicePrivileged {
		t.Error("device_privileged_users stayed on after the tenant stopped allowing it")
	}
}

// The public documents count against the address and the tenant, a document sent costing more than a 304: past the
// budget they answer 429, while the same address's budget for another tenant is untouched.
func TestSSHPublicEndpointsAreRateLimited(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	e := h.sshTenant("prod", service.SSHSettingsInput{})
	other := h.sshTenant("lab", service.SSHSettingsInput{})
	paths := []string{"", "/ca.pub", "/known_hosts", "/krl"}
	n := web.SSHFetchUnitsPerIP / web.SSHFetchCost
	if n <= 600 {
		t.Fatalf("an address and tenant get %d documents a minute, no more than the old 600", n)
	}
	for i := range n {
		resp := h.get(h.http, e.base+paths[i%len(paths)])
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: %d", i, resp.StatusCode)
		}
		body(resp)
	}
	for _, suffix := range paths {
		resp := h.get(h.http, e.base+suffix)
		if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
			t.Errorf("%s over the limit: %d %v", suffix, resp.StatusCode, resp.Header)
		}
		body(resp)
	}
	// the tenant named by its name is the same budget, by its id
	if resp := h.get(h.http, h.orgBase+"/ssh/prod/krl"); resp.StatusCode != 429 {
		t.Errorf("the tenant by its name: %d", resp.StatusCode)
	} else {
		body(resp)
	}
	if resp := h.get(h.http, other.base+"/krl"); resp.StatusCode != 200 {
		t.Errorf("another tenant from the same address: %d", resp.StatusCode)
	} else {
		body(resp)
	}
	// a tenant that does not exist is 404, counted in the address's one budget for those
	if resp := h.get(h.http, h.orgBase+"/ssh/no-such-tenant/krl"); resp.StatusCode != 404 {
		t.Errorf("an unknown tenant: %d", resp.StatusCode)
	} else {
		body(resp)
	}
}

// The public documents carry an ETag: a request that names it gets 304 and no body until the document changes. The
// revocation list's tag says what it revokes, so a list made again with nothing new is still 304.
func TestSSHPublicDocumentsRevalidate(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	ctx := context.Background()
	e := h.sshTenant("prod", service.SSHSettingsInput{})
	for _, suffix := range []string{"", "/ca.pub", "/known_hosts", "/krl"} {
		resp := h.get(h.http, e.base+suffix)
		tag := resp.Header.Get("ETag")
		body(resp)
		if resp.StatusCode != 200 || tag == "" {
			t.Fatalf("%s: %d, ETag %q", suffix, resp.StatusCode, tag)
		}
		resp = h.get(h.http, e.base+suffix, "If-None-Match", tag)
		if b := body(resp); resp.StatusCode != http.StatusNotModified || b != "" || resp.Header.Get("ETag") != tag {
			t.Errorf("%s revalidated: %d %q, ETag %q", suffix, resp.StatusCode, b, resp.Header.Get("ETag"))
		}
		resp = h.get(h.http, e.base+suffix, "If-None-Match", `"something-else", W/`+tag)
		if body(resp); resp.StatusCode != http.StatusNotModified {
			t.Errorf("%s: a weak tag in a list does not match: %d", suffix, resp.StatusCode)
		}
		resp = h.get(h.http, e.base+suffix, "If-None-Match", `"something-else"`)
		if body(resp); resp.StatusCode != 200 {
			t.Errorf("%s: another tag: %d", suffix, resp.StatusCode)
		}
	}

	resp := h.get(h.http, e.base+"/krl")
	tag := resp.Header.Get("ETag")
	body(resp)
	h.env.Svc.InvalidateSSHKRL() // made again, later: the same revocations, the same tag
	time.Sleep(1100 * time.Millisecond)
	if resp := h.get(h.http, e.base+"/krl", "If-None-Match", tag); resp.StatusCode != http.StatusNotModified {
		t.Errorf("the list made again with nothing new: %d", resp.StatusCode)
	} else {
		body(resp)
	}
	st, m, _ := e.sign(e.mfaToken(h.user), map[string]any{"public_key": func() string { k, _ := sshKey(t); return k }()})
	if st != 200 {
		t.Fatalf("sign: %d %v", st, m)
	}
	views, err := h.env.Svc.ListSSHCerts(ctx, h.admin, e.tn.ID, service.SSHCertFilter{})
	if err != nil || len(views) != 1 {
		t.Fatalf("certificates: %v %v", views, err)
	}
	if err := h.env.Svc.RevokeSSHCert(ctx, h.admin, h.env.Primary.ID, views[0].ID); err != nil {
		t.Fatal(err)
	}
	resp = h.get(h.http, e.base+"/krl", "If-None-Match", tag)
	if body(resp); resp.StatusCode != 200 || resp.Header.Get("ETag") == tag {
		t.Errorf("after a revocation: %d, ETag %q (was %q)", resp.StatusCode, resp.Header.Get("ETag"), tag)
	}
}

// An error of the sign endpoint that is ours (a 500) is logged with the organization and the tenant.
func TestSSHSignLogsServerErrors(t *testing.T) {
	t.Parallel()
	log := logtesting.New()
	h := setupLogged(t, nil, nil, log)
	e := h.sshTenant("prod", service.SSHSettingsInput{})
	tok := e.mfaToken(h.user)
	// the signing key cannot be opened
	for _, k := range mustKeys(t, h, e.tn.ID) {
		k.PrivateKey = "not sealed"
		if err := h.env.Svc.SSHCAKeys.Update(context.Background(), k); err != nil {
			t.Fatal(err)
		}
	}
	key, _ := sshKey(t)
	st, m, _ := e.sign(tok, map[string]any{"public_key": key})
	if st != 500 {
		t.Fatalf("sign: %d %v", st, m)
	}
	var found bool
	for _, en := range log.GetEntries() {
		if en.Level == "error" && strings.Contains(en.Message, "SSH certificate") {
			found = true
			kv := fmt.Sprint(en.KeysAndValues)
			if !strings.Contains(kv, h.env.Primary.ID) || !strings.Contains(kv, e.tn.ID) {
				t.Errorf("the entry names no organization or tenant: %v", en.KeysAndValues)
			}
		}
	}
	if !found {
		t.Errorf("nothing logged: %v", log.GetEntries())
	}
}

func mustKeys(t *testing.T, h *harness, tenantID string) []*model.SSHKey {
	t.Helper()
	ks, err := h.env.Svc.SSHKeys(context.Background(), tenantID, model.SSHPurposeUser)
	if err != nil || len(ks) == 0 {
		t.Fatalf("keys: %v %v", ks, err)
	}
	return ks
}

// A revocation list that cannot be made is a 503 for every server that fetches it: it is logged as an error, with the
// organization and the tenant.
func TestSSHKRLLogsBuildFailures(t *testing.T) {
	t.Parallel()
	log := logtesting.New()
	h := setupLogged(t, nil, nil, log)
	ctx := context.Background()
	e := h.sshTenant("prod", service.SSHSettingsInput{})
	key, _ := sshKey(t)
	if st, m, _ := e.sign(e.mfaToken(h.user), map[string]any{"public_key": key}); st != 200 {
		t.Fatalf("sign: %d %v", st, m)
	}
	// the certificate's user cannot be read
	rec, err := h.env.Store.Get(ctx, model.KindUser, h.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	bad := *rec
	bad.Data, bad.Version, bad.Req = []byte("not a record"), rec.Version+1, ""
	if err := h.env.Store.Put(ctx, &bad); err != nil {
		t.Fatal(err)
	}
	h.env.Svc.InvalidateSSHKRL()
	resp := h.get(h.http, e.base+"/krl")
	body(resp)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("krl: %d", resp.StatusCode)
	}
	var found bool
	for _, en := range log.GetEntries() {
		if en.Level == "error" && strings.Contains(en.Message, "revocation list") {
			found = true
			if kv := fmt.Sprint(en.KeysAndValues); !strings.Contains(kv, h.env.Primary.ID) || !strings.Contains(kv, e.tn.ID) {
				t.Errorf("the entry names no organization or tenant: %v", en.KeysAndValues)
			}
		}
	}
	if !found {
		t.Errorf("nothing logged: %v", log.GetEntries())
	}
}

// A certificate stands on its token's grant, with the grant's session epoch and sign-out stamp: an account whose
// sessions were ended once (a password reset, a disabling), in an organization that pulled the emergency sign-out
// lever once, still gets one after signing in afresh, recorded with what that sign-in holds.
func TestSSHSignAfterSessionsEnded(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	e := h.sshTenant("prod", service.SSHSettingsInput{})
	ctx := context.Background()
	u, err := h.env.Svc.Users.Get(ctx, h.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	u.SessionEpoch = service.NewCredEpoch()
	if err := h.env.Svc.Users.Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := h.env.Svc.SignOutOrg(ctx, service.System, h.env.Primary.ID, service.SignOutOptions{Reason: "drill"}); err != nil {
		t.Fatal(err)
	}
	h.env.Svc.InvalidateOrgs()
	e.p.InvalidateUser(u.ID)
	u, _ = h.env.Svc.Users.Get(ctx, u.ID)
	stamp, err := h.env.Svc.SessionStamp(ctx, u.OrgID)
	if err != nil || stamp.Org == 0 {
		t.Fatalf("test set-up: the sign-out stamp %+v %v", stamp, err)
	}

	key, _ := sshKey(t)
	st, m, _ := e.sign(e.mfaToken(u), map[string]any{"public_key": key})
	if st != 200 {
		t.Fatalf("sign: %d %v", st, m)
	}
	certs, err := h.env.Svc.SSHCertsOf(ctx, u)
	if err != nil || len(certs) != 1 || certs[0].SessionEpoch != u.SessionEpoch || !certs[0].Stamp.Current(stamp) {
		t.Fatalf("the certificate's record: %+v %v (epoch %d, stamp %+v)", certs, err, u.SessionEpoch, stamp)
	}
}

// A certificate goes with the grant of the token that asked for it: revoking the token (RFC 7009) revokes the
// certificate too, for good.
func TestSSHCertRevokedWithItsGrant(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	e := h.sshTenant("prod", service.SSHSettingsInput{CertTTL: ptr(3600)})
	key, _ := sshKey(t)
	other := e.mfaToken(h.user)
	st, kept, _ := e.sign(other, map[string]any{"public_key": key})
	tok := e.mfaToken(h.user)
	st2, m, _ := e.sign(tok, map[string]any{"public_key": key})
	if st != 200 || st2 != 200 {
		t.Fatalf("sign: %d %v / %d %v", st, kept, st2, m)
	}
	reasons := func() map[string]string {
		t.Helper()
		list, err := h.env.Svc.SSHRevoked(context.Background(), e.tn.ID)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, r := range list {
			out[strconv.FormatUint(r.Cert.Serial, 10)] = r.Reason
		}
		return out
	}
	if got := reasons(); len(got) != 0 {
		t.Fatalf("revoked before: %v", got)
	}
	if r := h.post(h.orgBase+"/oauth/revoke", url.Values{"token": {tok}, "client_id": {e.cl.ID}}, "", ""); r.status != 200 {
		t.Fatalf("revoke: %d %v", r.status, r)
	}
	got := reasons()
	if got[m["serial"].(string)] != service.SSHReasonSignInEnded {
		t.Errorf("the revoked token's certificate: %v", got)
	}
	if reason, ok := got[kept["serial"].(string)]; ok {
		t.Errorf("another sign-in's certificate revoked: %s", reason)
	}
}
