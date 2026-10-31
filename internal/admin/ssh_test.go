package admin_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	logtesting "github.com/paularlott/logger/testing"
	"golang.org/x/crypto/ssh"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/sshca"
	"github.com/paularlott/quisora/internal/web"
)

func newSSHPub(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshca.AuthorizedKey(k) + " host@example"
}

// sshKeys returns the keys of an SSH response by id, and their ids in order.
func sshKeys(t *testing.T, r resp) (map[string]map[string]any, []string) {
	t.Helper()
	by := map[string]map[string]any{}
	var ids []string
	keys, _ := r.JSON["keys"].([]any)
	for _, k := range keys {
		km := k.(map[string]any)
		id := km["id"].(string)
		by[id] = km
		ids = append(ids, id)
	}
	return by, ids
}

func keyOf(t *testing.T, r resp, purpose, state string) map[string]any {
	t.Helper()
	by, _ := sshKeys(t, r)
	for _, k := range by {
		if k["purpose"] == purpose && k["state"] == state {
			return k
		}
	}
	t.Fatalf("no %s key in state %s: %s", purpose, state, r.Raw)
	return nil
}

// The SSH settings of a tenant: off until enabled (which makes the CA key and the SSH application), changed by PATCH
// (omitted settings keep their values), refused with the field when invalid.
func TestSSHSettings(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	tn := ad.get(A + "/tenants").items()[0].(map[string]any)
	S := A + "/tenants/" + tn["id"].(string) + "/ssh"

	r := ad.get(S)
	want(t, r, 200)
	disc := w.env.Server.Cfg.OrgIssuer(w.acme.ID) + "/ssh/" + tn["id"].(string)
	ep, _ := r.JSON["endpoints"].(map[string]any)
	if r.JSON["enabled"] != false || r.JSON["cert_ttl"] != float64(28800) || r.JSON["principal_username"] != true || len(r.JSON["keys"].([]any)) != 0 ||
		ep["discovery"] != disc || ep["ca_pub"] != disc+"/ca.pub" || ep["known_hosts"] != disc+"/known_hosts" || ep["krl"] != disc+"/krl" ||
		ep["host_sign"] != w.env.Server.Cfg.Server.PublicURL+"/api/orgs/"+w.acme.ID+"/tenants/"+tn["id"].(string)+"/ssh/host-certificates" {
		t.Fatalf("not enabled: %s", r.Raw)
	}
	// the tenant is found by its name too
	want(t, ad.get(A+"/tenants/default/ssh"), 200)

	// enabling makes the user CA key and the application
	r = ad.patch(S, map[string]any{"enabled": true})
	want(t, r, 200)
	k := keyOf(t, r, "user", "active")
	if r.JSON["enabled"] != true || r.str("client_id") == "" || k["alg"] != "ssh-ed25519" || !strings.HasPrefix(k["public_key"].(string), "ssh-ed25519 ") ||
		!strings.HasPrefix(k["fingerprint"].(string), "SHA256:") || k["not_before"] == "" {
		t.Fatalf("enable: %s", r.Raw)
	}
	if _, ids := sshKeys(t, r); len(ids) != 1 {
		t.Fatalf("keys after enabling: %s", r.Raw)
	}
	app := ad.get(A + "/clients/" + r.str("client_id"))
	want(t, app, 200)
	if app.str("name") != "SSH" {
		t.Fatalf("the SSH application: %s", app.Raw)
	}
	clientID := r.str("client_id")

	// a change keeps what it does not name, and makes nothing twice
	r = ad.patch(S, map[string]any{"cert_ttl": 7200, "principal_roles": true, "source_addresses": []string{"10.0.0.0/8"}, "allow_privileged": true})
	want(t, r, 200)
	if r.JSON["cert_ttl"] != float64(7200) || r.JSON["principal_roles"] != true || r.JSON["principal_groups"] != true || r.JSON["enabled"] != true ||
		r.str("client_id") != clientID || len(r.JSON["keys"].([]any)) != 1 || len(r.JSON["source_addresses"].([]any)) != 1 {
		t.Fatalf("change: %s", r.Raw)
	}
	if got := ad.get(S); got.JSON["max_auth_age"] != float64(3600) || got.JSON["allow_privileged"] != true {
		t.Fatalf("get after change: %s", got.Raw)
	}
	if a := ad.get(A + "/clients/" + clientID); a.JSON["device_privileged_users"] != true {
		t.Fatalf("the application follows allow_privileged: %s", a.Raw)
	}
	if n := len(auditActions(t, w, "ssh.settings.update")); n != 2 {
		t.Fatalf("%d ssh.settings.update events, want 2", n)
	}
	if len(auditActions(t, w, "ssh.ca.create")) != 1 {
		t.Fatal("no ssh.ca.create event")
	}

	// each refusal names its field
	wantField(t, ad.patch(S, map[string]any{"cert_ttl": 10}), 422, "ssh.cert_ttl")
	wantField(t, ad.patch(S, map[string]any{"max_auth_age": 5}), 422, "ssh.max_auth_age")
	wantField(t, ad.patch(S, map[string]any{"rotation_days": 3}), 422, "ssh.rotation_days")
	wantField(t, ad.patch(S, map[string]any{"source_addresses": []string{"not an address"}}), 422, "ssh.source_addresses")
	wantField(t, ad.patch(S, map[string]any{"host_ttl_days": 999}), 422, "ssh.host_ttl_days")
	wantField(t, ad.patch(S, map[string]any{"host_certs": true}), 422, "ssh.host_patterns")
	wantField(t, ad.patch(S, map[string]any{"host_patterns": []string{"Bad Host!"}}), 422, "ssh.host_patterns")
	want(t, ad.patch(S, map[string]any{"bogus": 1}), 400)
	if got := ad.get(S); got.JSON["cert_ttl"] != float64(7200) {
		t.Fatalf("a refused change was applied: %s", got.Raw)
	}

	// off: the keys are kept
	r = ad.patch(S, map[string]any{"enabled": false})
	want(t, r, 200)
	if r.JSON["enabled"] != false || len(r.JSON["keys"].([]any)) != 1 {
		t.Fatalf("disable: %s", r.Raw)
	}

	// another organization's tenant is not seen; a tenant that is not there is not found
	want(t, w.as("other").get(A+"/tenants/"+tn["id"].(string)+"/ssh"), 404)
	want(t, w.as("other").get(G+"/tenants/"+tn["id"].(string)+"/ssh"), 404)
	want(t, ad.get(A+"/tenants/nope/ssh"), 404)
}

// Rotating and removing CA keys need a recent re-authentication, as the signing keys do: a console session without
// one gets the re-authentication answer, a personal API token is refused, a service account goes ahead.
func TestSSHKeysStepUp(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	S := A + "/tenants/default/ssh"
	want(t, ad.patch(S, map[string]any{"enabled": true}), 200)
	key := keyOf(t, ad.get(S), "user", "active")["id"].(string)

	w.env.Server.Reauthed = func(*http.Request) bool { return false }
	wantField(t, ad.post(S+"/rotate", map[string]any{"purpose": "user"}), 403, "reauth")
	wantField(t, ad.delete(S+"/keys/"+key), 403, "reauth")
	tok := w.withBearer("admin", "admin")
	wantField(t, tok.post(S+"/rotate", map[string]any{"purpose": "user"}), 403, "reauth")
	want(t, w.asServiceAccount(w.acme, service.ScopeSSH).post(S+"/rotate", map[string]any{"purpose": "user"}), 201)
}

// CA keys: a user key's rotation is published first and signs a week later, an immediate one signs at once; only a
// key that no longer signs can be removed; host keys exist once host certificates are on.
func TestSSHKeys(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	S := A + "/tenants/default/ssh"

	wantField(t, ad.post(S+"/rotate", map[string]any{"purpose": "user"}), 422, "ssh")
	want(t, ad.patch(S, map[string]any{"enabled": true}), 200)
	first := keyOf(t, ad.get(S), "user", "active")["id"].(string)
	wantField(t, ad.post(S+"/rotate", map[string]any{"purpose": "other"}), 422, "purpose")
	wantField(t, ad.post(S+"/rotate", map[string]any{"purpose": "host"}), 422, "purpose") // host certificates are off
	want(t, ad.post(S+"/rotate", map[string]any{"purpose": "user", "bogus": true}), 400)

	// as scheduled: the successor is published now and signs in a week
	r := ad.post(S+"/rotate", map[string]any{"purpose": "user"})
	want(t, r, 201)
	next := r.str("id")
	if r.str("state") != "next" || r.str("purpose") != "user" || r.str("public_key") == "" {
		t.Fatalf("rotate: %s", r.Raw)
	}
	got := ad.get(S)
	by, ids := sshKeys(t, got)
	if len(ids) != 2 || by[next]["state"] != "next" || by[first]["state"] != "active" || by[first]["retire_at"] == nil {
		t.Fatalf("keys after rotating: %s", got.Raw)
	}
	wantField(t, ad.post(S+"/rotate", map[string]any{"purpose": "user"}), 422, "immediate") // one is under way
	wantField(t, ad.delete(S+"/keys/"+next), 422, "id")                                     // not signing yet

	// immediately: signs at once and retires the others
	r = ad.post(S+"/rotate", map[string]any{"purpose": "user", "immediate": true})
	want(t, r, 201)
	now := r.str("id")
	got = ad.get(S)
	by, _ = sshKeys(t, got)
	if r.str("state") != "active" || by[now]["state"] != "active" || by[first]["state"] != "retired" || by[next] != nil {
		t.Fatalf("immediate rotation: %s", got.Raw)
	}
	wantField(t, ad.delete(S+"/keys/"+now), 422, "id") // signs now
	want(t, ad.delete(S+"/keys/"+first), 200)
	want(t, ad.delete(S+"/keys/"+first), 404)
	if _, ids := sshKeys(t, ad.get(S)); len(ids) != 1 {
		t.Fatal("the removed key is still listed")
	}
	want(t, ad.delete(S+"/keys/nope"), 404)

	// host keys
	want(t, ad.patch(S, map[string]any{"host_certs": true, "host_patterns": []string{"*.example.com"}}), 200)
	host := keyOf(t, ad.get(S), "host", "active")["id"].(string)
	r = ad.post(S+"/rotate", map[string]any{"purpose": "host"})
	want(t, r, 201)
	if r.str("state") != "active" || r.str("id") == host {
		t.Fatalf("host rotation signs at once: %s", r.Raw)
	}
	if keyOf(t, ad.get(S), "host", "retired")["id"] != host {
		t.Fatal("the old host key is not retired")
	}
	for _, a := range []string{"ssh.ca.rotate", "ssh.ca.remove"} {
		if len(auditActions(t, w, a)) == 0 {
			t.Errorf("no %s event", a)
		}
	}
}

// Host certificates are signed for names that match the tenant's patterns, by administrators and by service accounts
// with ssh:host, and they are listed and revoked with the others.
func TestSSHHostCertificates(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	S := A + "/tenants/default/ssh"
	H := S + "/host-certificates"
	pub := newSSHPub(t)

	// refused while off
	r := ad.post(H, map[string]any{"public_key": pub, "principals": []string{"web1.example.com"}})
	want(t, r, 403)
	if !strings.Contains(r.str("error"), "not enabled") {
		t.Fatalf("the refusal says why: %s", r.Raw)
	}
	want(t, ad.patch(S, map[string]any{"enabled": true, "host_certs": true, "host_patterns": []string{"*.example.com"}, "host_ttl_days": 30}), 200)

	r = ad.post(H, map[string]any{"public_key": pub, "principals": []string{"Web1.example.com"}})
	want(t, r, 200)
	serial := r.str("serial")
	until, _ := time.Parse(time.RFC3339, r.str("valid_before"))
	if !strings.HasPrefix(r.str("certificate"), "ssh-ed25519-cert-v01@openssh.com ") || serial == "" || serial == "0" ||
		r.str("key_id") != "host:web1.example.com@acme" || len(r.JSON["principals"].([]any)) != 1 ||
		until.Before(time.Now().Add(29*24*time.Hour)) || until.After(time.Now().Add(31*24*time.Hour)) {
		t.Fatalf("host certificate: %s", r.Raw)
	}
	cert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(r.str("certificate")))
	if err != nil || cert.(*ssh.Certificate).CertType != ssh.HostCert {
		t.Fatalf("the certificate does not parse as a host certificate: %v", err)
	}

	// a shorter life
	r = ad.post(H, map[string]any{"public_key": pub, "principals": []string{"web2.example.com"}, "ttl_days": 2})
	want(t, r, 200)
	if until, _ = time.Parse(time.RFC3339, r.str("valid_before")); until.After(time.Now().Add(3 * 24 * time.Hour)) {
		t.Fatalf("ttl_days: %s", r.Raw)
	}
	wantField(t, ad.post(H, map[string]any{"public_key": pub, "principals": []string{"web2.example.com"}, "ttl_days": 31}), 422, "ttl_days")
	wantField(t, ad.post(H, map[string]any{"public_key": pub, "principals": []string{"web2.example.com"}, "ttl_days": -1}), 422, "ttl_days")

	// a name outside the patterns, a bad key, no names
	wantField(t, ad.post(H, map[string]any{"public_key": pub, "principals": []string{"db.internal"}}), 422, "principals")
	wantField(t, ad.post(H, map[string]any{"public_key": pub, "principals": []string{}}), 422, "principals")
	wantField(t, ad.post(H, map[string]any{"public_key": "not a key", "principals": []string{"web1.example.com"}}), 422, "public_key")
	if len(auditActions(t, w, "ssh.host.refused")) == 0 || len(auditActions(t, w, "ssh.host.issue")) != 2 {
		t.Fatalf("audit: %d refused, %d issued", len(auditActions(t, w, "ssh.host.refused")), len(auditActions(t, w, "ssh.host.issue")))
	}

	// service accounts: ssh:host signs, ssh alone does not
	sa := w.asServiceAccount(w.acme, service.ScopeSSHHost)
	want(t, sa.post(H, map[string]any{"public_key": pub, "principals": []string{"web3.example.com"}}), 200)
	if r = sa.get(S); !guardRefused(r) {
		t.Fatalf("ssh:host reads the settings: %d %s", r.Status, r.Raw)
	}
	if r = w.asServiceAccount(w.acme, service.ScopeSSH).post(H, map[string]any{"public_key": pub, "principals": []string{"web3.example.com"}}); !guardRefused(r) {
		t.Fatalf("ssh signs host certificates: %d %s", r.Status, r.Raw)
	}
	if r = w.asServiceAccount(w.acme, service.ScopeUsers).post(H, map[string]any{}); !guardRefused(r) {
		t.Fatalf("a service account with neither: %d %s", r.Status, r.Raw)
	}
	// a service account of another organization does not see the tenant
	want(t, w.asServiceAccount(w.other, service.ScopeSSHHost).post(H, map[string]any{"public_key": pub, "principals": []string{"web3.example.com"}}), 404)

	// listed with who issued it, then revoked
	hosts := ad.get(S + "/certificates?host=true")
	want(t, hosts, 200)
	if hosts.total() != 3 {
		t.Fatalf("host certificates: %s", hosts.Raw)
	}
	var id string
	for _, it := range hosts.items() {
		c := it.(map[string]any)
		if c["serial"] == serial {
			id = c["id"].(string)
			if c["host"] != true || c["status"] != "active" || c["via"] != "api" || c["issued_by"] == "" || c["key_id"] != "host:web1.example.com@acme" {
				t.Fatalf("listed host certificate: %s", hosts.Raw)
			}
		}
	}
	if id == "" || ad.get(S+"/certificates?host=false").total() != 0 {
		t.Fatalf("listing: %s", hosts.Raw)
	}
	want(t, ad.post(S+"/certificates/"+id+"/revoke", nil), 200)
	want(t, ad.post(S+"/certificates/"+id+"/revoke", nil), 200) // again: nothing changes
	rev := ad.get(S + "/certificates?status=revoked")
	if rev.total() != 1 || rev.items()[0].(map[string]any)["reason"] != "revoked" || ad.get(S+"/certificates?status=active").total() != 2 {
		t.Fatalf("after revoking: %s", rev.Raw)
	}
	if len(auditActions(t, w, "ssh.cert.revoke")) != 1 {
		t.Fatal("no ssh.cert.revoke event")
	}
}

// User certificates are listed for the console (user, principals, status) and revoked by id; a certificate of another
// tenant is not found under this one.
func TestSSHCertificates(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	S := A + "/tenants/default/ssh"
	want(t, ad.patch(S, map[string]any{"enabled": true}), 200)
	tenantID := ad.get(A + "/tenants/default").str("id")
	clientID := ad.get(S).str("client_id")

	u := w.users["user"]
	stamp, err := w.env.Svc.SessionStamp(context.Background(), u.OrgID)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := w.env.Svc.SignUserSSH(context.Background(), service.SSHUserRequest{User: u, TenantID: tenantID, ClientID: clientID,
		PublicKey: newSSHPub(t), AMR: []string{"pwd", "otp", "mfa"}, AuthTime: time.Now().Add(-time.Minute), Via: "cli",
		SessionEpoch: u.SessionEpoch, Stamp: stamp})
	if err != nil {
		t.Fatal(err)
	}
	id := issued.Cert.ID

	r := ad.get(S + "/certificates")
	want(t, r, 200)
	c, _ := r.items()[0].(map[string]any)
	if r.total() != 1 || c["id"] != id || c["username"] != "alan" || c["status"] != "active" || c["user_id"] != u.ID || c["via"] != "cli" ||
		c["serial"] == nil || len(c["principals"].([]any)) == 0 {
		t.Fatalf("list: %s", r.Raw)
	}
	if ad.get(S+"/certificates?user="+u.ID).total() != 1 || ad.get(S+"/certificates?user="+w.users["admin"].ID).total() != 0 ||
		ad.get(S+"/certificates?status=expired").total() != 0 || ad.get(S+"/certificates?status=all").total() != 1 ||
		ad.get(S+"/certificates?host=false").total() != 1 {
		t.Fatal("filters")
	}
	wantField(t, ad.get(S+"/certificates?status=nope"), 422, "status")
	wantField(t, ad.get(S+"/certificates?host=maybe"), 422, "host")

	// a certificate of another tenant is not found under this one
	other := ad.post(A+"/tenants", map[string]any{"name": "staff", "display_name": "Staff"})
	want(t, other, 201)
	want(t, ad.patch(A+"/tenants/staff/ssh", map[string]any{"enabled": true}), 200)
	want(t, ad.post(A+"/tenants/staff/ssh/certificates/"+id+"/revoke", nil), 404)
	want(t, ad.post(S+"/certificates/nope/revoke", nil), 404)
	if ad.get(S+"/certificates?status=active").total() != 1 {
		t.Fatal("the certificate was revoked")
	}

	want(t, ad.post(S+"/certificates/"+id+"/revoke", nil), 200)
	r = ad.get(S + "/certificates?status=revoked")
	if r.total() != 1 || r.items()[0].(map[string]any)["reason"] != "revoked" || r.items()[0].(map[string]any)["revoked_by"] == "" {
		t.Fatalf("revoked: %s", r.Raw)
	}
	if ad.get(S+"/certificates?status=active").total() != 0 {
		t.Fatal("still active")
	}
}

// The tenants list says whether each tenant has SSH on (the SSH column of the console): the tenant's ssh settings, absent
// until SSH was first turned on.
func TestTenantListShowsSSH(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	want(t, ad.post(A+"/tenants", map[string]any{"name": "staff", "display_name": "Staff"}), 201)
	enabled := func() map[string]any { // tenant name -> its ssh.enabled, absent when the list has no ssh for it
		out := map[string]any{}
		for _, it := range ad.get(A + "/tenants").items() {
			m := it.(map[string]any)
			if ssh, ok := m["ssh"].(map[string]any); ok {
				out[m["name"].(string)] = ssh["enabled"]
			}
		}
		return out
	}
	if got := enabled(); len(got) != 0 {
		t.Fatalf("SSH never turned on: %v", got)
	}
	want(t, ad.patch(A+"/tenants/staff/ssh", map[string]any{"enabled": true}), 200)
	if got := enabled(); len(got) != 1 || got["staff"] != true {
		t.Fatalf("SSH on: %v", got)
	}
	want(t, ad.patch(A+"/tenants/staff/ssh", map[string]any{"enabled": false}), 200)
	if got := enabled(); len(got) != 1 || got["staff"] != false {
		t.Fatalf("SSH off again: %v", got)
	}
}

// The tenant's certificates are paged and searched as the users are (q, offset, limit; the same {items, total}).
func TestSSHCertificatesPagedAndSearched(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	S := A + "/tenants/default/ssh"
	want(t, ad.patch(S, map[string]any{"enabled": true, "allow_privileged": true, "host_certs": true, "host_patterns": []string{"*.example.com"}}), 200)
	tenantID := ad.get(A + "/tenants/default").str("id")
	clientID := ad.get(S).str("client_id")
	sign := func(u *model.User) string {
		t.Helper()
		stamp, err := w.env.Svc.SessionStamp(context.Background(), u.OrgID)
		if err != nil {
			t.Fatal(err)
		}
		got, err := w.env.Svc.SignUserSSH(context.Background(), service.SSHUserRequest{User: u, TenantID: tenantID, ClientID: clientID,
			PublicKey: newSSHPub(t), AMR: []string{"pwd", "otp", "mfa"}, AuthTime: time.Now().Add(-time.Minute), Via: "cli",
			SessionEpoch: u.SessionEpoch, Stamp: stamp})
		if err != nil {
			t.Fatal(err)
		}
		return got.Cert.ID
	}
	alan, boss := w.users["user"], w.users["admin"]
	var alans []string
	for range 4 {
		alans = append(alans, sign(alan))
	}
	bossCert := sign(boss)
	want(t, ad.post(S+"/host-certificates", map[string]any{"public_key": newSSHPub(t), "principals": []string{"web1.example.com"}}), 200)

	idsOf := func(r resp) []string {
		var out []string
		for _, it := range r.items() {
			out = append(out, it.(map[string]any)["id"].(string))
		}
		return out
	}
	// the page: 25 by default, newest first, the total counts every certificate
	r := ad.get(S + "/certificates?status=all")
	want(t, r, 200)
	if r.total() != 6 || len(r.items()) != 6 || r.items()[1].(map[string]any)["id"] != bossCert {
		t.Fatalf("list: %s", r.Raw)
	}
	r = ad.get(S + "/certificates?status=all&limit=2&offset=1")
	if got := idsOf(r); r.total() != 6 || len(got) != 2 || got[0] != bossCert || got[1] != alans[3] {
		t.Fatalf("page: %s", r.Raw)
	}
	if r = ad.get(S + "/certificates?status=all&limit=2&offset=5"); r.total() != 6 || len(r.items()) != 1 {
		t.Fatalf("last page: %s", r.Raw)
	}
	if r = ad.get(S + "/certificates?status=all&limit=500"); len(r.items()) != 6 { // the most a page holds is capped
		t.Fatalf("a large limit: %s", r.Raw)
	}
	// the search: username, principal, fingerprint (a prefix), serial, key id; it pages too
	r = ad.get(S + "/certificates?q=alan")
	if r.total() != 4 || len(r.items()) != 4 {
		t.Fatalf("search by username: %s", r.Raw)
	}
	if r = ad.get(S + "/certificates?q=alan&limit=3&offset=3"); r.total() != 4 || len(r.items()) != 1 {
		t.Fatalf("a page of the search: %s", r.Raw)
	}
	one := ad.get(S + "/certificates?q=alan&limit=1").items()[0].(map[string]any)
	for name, q := range map[string]string{"serial": one["serial"].(string), "fingerprint": one["fingerprint"].(string)[:16], "key id": one["key_id"].(string)} {
		if r = ad.get(S + "/certificates?status=all&q=" + url.QueryEscape(q)); r.total() < 1 || idsOf(r)[len(idsOf(r))-1] == "" {
			t.Errorf("search by %s: %s", name, r.Raw)
		}
	}
	if r = ad.get(S + "/certificates?status=all&q=" + url.QueryEscape(one["serial"].(string))); r.total() != 1 || r.items()[0].(map[string]any)["id"] != one["id"] {
		t.Errorf("search by serial: %s", r.Raw)
	}
	if r = ad.get(S + "/certificates?status=all&q=web1.example.com"); r.total() != 1 || r.items()[0].(map[string]any)["host"] != true {
		t.Errorf("search by host principal: %s", r.Raw)
	}
	if r = ad.get(S + "/certificates?q=nobody"); r.total() != 0 || len(r.items()) != 0 {
		t.Errorf("no match: %s", r.Raw)
	}
	// with the filters
	want(t, ad.post(S+"/certificates/"+alans[0]+"/revoke", nil), 200)
	if r = ad.get(S + "/certificates?q=alan&status=revoked"); r.total() != 1 || r.items()[0].(map[string]any)["id"] != alans[0] {
		t.Errorf("search and status: %s", r.Raw)
	}
	if r = ad.get(S + "/certificates?q=alan&status=active"); r.total() != 3 {
		t.Errorf("search and active: %s", r.Raw)
	}
	if r = ad.get(S + "/certificates?q=alan&user=" + boss.ID + "&status=all"); r.total() != 0 {
		t.Errorf("search and user: %s", r.Raw)
	}
}

// A user's certificates, for the user's page: administrators of the organization only.
func TestUserSSHCertificates(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	S := A + "/tenants/default/ssh"
	want(t, ad.patch(S, map[string]any{"enabled": true}), 200)
	tenantID := ad.get(A + "/tenants/default").str("id")
	clientID := ad.get(S).str("client_id")
	alan := w.users["user"]
	sign := func() string {
		t.Helper()
		stamp, err := w.env.Svc.SessionStamp(context.Background(), alan.OrgID)
		if err != nil {
			t.Fatal(err)
		}
		got, err := w.env.Svc.SignUserSSH(context.Background(), service.SSHUserRequest{User: alan, TenantID: tenantID, ClientID: clientID,
			PublicKey: newSSHPub(t), AMR: []string{"pwd", "otp", "mfa"}, AuthTime: time.Now().Add(-time.Minute), Via: "cli",
			SessionEpoch: alan.SessionEpoch, Stamp: stamp})
		if err != nil {
			t.Fatal(err)
		}
		return got.Cert.ID
	}
	U := A + "/users/" + alan.ID + "/ssh-certificates"

	// none yet: an empty list
	r := ad.get(U)
	want(t, r, 200)
	if r.total() != 0 || len(r.items()) != 0 {
		t.Fatalf("no certificates: %s", r.Raw)
	}
	first, second := sign(), sign()
	// a certificate that has expired is not listed
	old := *w.certOf(t, first)
	old.ID, old.Serial, old.ValidAfter, old.ValidBefore = "", 4242, time.Now().Add(-9*time.Hour), time.Now().Add(-time.Minute)
	if err := w.env.Svc.SSHCerts.Create(context.Background(), &old); err != nil {
		t.Fatal(err)
	}
	r = ad.get(U)
	want(t, r, 200)
	if r.total() != 2 || len(r.items()) != 2 {
		t.Fatalf("list: %s", r.Raw)
	}
	c := r.items()[0].(map[string]any)
	if c["id"] != second || c["tenant_id"] != tenantID || c["tenant"] != "Default" || c["tenant_name"] != "default" || c["status"] != "active" ||
		c["user_id"] != alan.ID || c["serial"] == nil || len(c["principals"].([]any)) == 0 || c["valid_before"] == nil {
		t.Fatalf("a certificate: %s", r.Raw)
	}
	// revoked through the tenant's revoke operation: listed (until it expires) with its reason
	want(t, ad.post(A+"/tenants/"+tenantID+"/ssh/certificates/"+first+"/revoke", nil), 200)
	r = ad.get(U)
	var revoked map[string]any
	for _, it := range r.items() {
		if m := it.(map[string]any); m["id"] == first {
			revoked = m
		}
	}
	if revoked == nil || revoked["status"] != "revoked" || revoked["reason"] != "revoked" || revoked["revoked_by"] == "" {
		t.Fatalf("revoked: %s", r.Raw)
	}
	// the super admin may, as may a service account with the ssh scope; managers, users and others may not
	want(t, w.as("super").get(U), 200)
	want(t, w.asServiceAccount(w.acme, service.ScopeSSH).get(U), 200)
	if r := w.asServiceAccount(w.acme, service.ScopeUsers).get(U); !guardRefused(r) {
		t.Errorf("users scope: %d %s", r.Status, r.Raw)
	}
	want(t, w.as("manager").get(U), 403)
	want(t, w.as("user").get(U), 403)
	want(t, w.as("other").get(U), 404)
	want(t, w.anon().get(U), 401)
	want(t, ad.get(A+"/users/nope/ssh-certificates"), 404)
}

// Only administrators of the organization manage SSH: managers and users do not see the tenant, nor does another
// organization's administrator, and service accounts need the scope.
func TestSSHAccess(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	S := A + "/tenants/default/ssh"
	want(t, ad.patch(S, map[string]any{"enabled": true, "host_certs": true, "host_patterns": []string{"*.example.com"}}), 200)
	key := keyOf(t, ad.get(S), "user", "active")["id"].(string)
	pub := newSSHPub(t)

	calls := func(c *caller) map[string]resp {
		return map[string]resp{
			"get":     c.get(S),
			"patch":   c.patch(S, map[string]any{"cert_ttl": 3600}),
			"rotate":  c.post(S+"/rotate", map[string]any{"purpose": "user"}),
			"remove":  c.delete(S + "/keys/" + key),
			"certs":   c.get(S + "/certificates"),
			"revoke":  c.post(S+"/certificates/nope/revoke", nil),
			"hostsig": c.post(S+"/host-certificates", map[string]any{"public_key": pub, "principals": []string{"a.example.com"}}),
		}
	}
	for _, who := range []string{"manager", "user"} {
		for name, r := range calls(w.as(who)) {
			if r.Status != 404 { // as for the tenant itself: it is not theirs to see
				t.Errorf("%s %s: %d %s", who, name, r.Status, r.Raw)
			}
		}
	}
	for name, r := range calls(w.as("other")) {
		if r.Status != 404 {
			t.Errorf("other organization's administrator %s: %d %s", name, r.Status, r.Raw)
		}
	}
	for name, r := range calls(w.anon()) {
		if r.Status != 401 {
			t.Errorf("anonymous %s: %d %s", name, r.Status, r.Raw)
		}
	}
	// a personal API token follows its user: administrators need the admin scope
	if r := w.withBearer("admin", "admin").get(S); r.Status != 200 {
		t.Errorf("admin token: %d %s", r.Status, r.Raw)
	}
	if r := w.withBearer("manager", "admin").get(S); r.Status != 404 {
		t.Errorf("manager's token: %d %s", r.Status, r.Raw)
	}

	// service accounts: the ssh scope reaches everything but host signing, ssh:host only that
	sshOnly := w.asServiceAccount(w.acme, service.ScopeSSH)
	for name, r := range calls(sshOnly) {
		if name == "hostsig" {
			if !guardRefused(r) {
				t.Errorf("ssh scope signs host certificates: %d %s", r.Status, r.Raw)
			}
		} else if guardRefused(r) || r.Status == 401 {
			t.Errorf("ssh scope, %s: %d %s", name, r.Status, r.Raw)
		}
	}
	for name, r := range calls(w.asServiceAccount(w.acme, service.ScopeSSHHost)) {
		if name == "hostsig" {
			if r.Status != 200 {
				t.Errorf("ssh:host signs: %d %s", r.Status, r.Raw)
			}
		} else if !guardRefused(r) {
			t.Errorf("ssh:host scope, %s: %d %s", name, r.Status, r.Raw)
		}
	}
	for name, r := range calls(w.asServiceAccount(w.acme, service.ScopeTenants)) {
		if !guardRefused(r) {
			t.Errorf("neither scope, %s: %d %s", name, r.Status, r.Raw)
		}
	}
}

// The answer to a rotation names the new key's fingerprint, as the key listing does.
func TestSSHRotateShowsTheFingerprint(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	S := A + "/tenants/default/ssh"
	want(t, ad.patch(S, map[string]any{"enabled": true}), 200)
	r := ad.post(S+"/rotate", map[string]any{"purpose": "user"})
	want(t, r, 201)
	fp := r.str("fingerprint")
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("rotate: %s", r.Raw)
	}
	if listed := keyOf(t, ad.get(S), "user", "next")["fingerprint"]; listed != fp {
		t.Errorf("fingerprint %q in the answer, %v in the listing", fp, listed)
	}
}

// An administrator or service account may ask for 120 host certificates a minute; each has its own budget.
func TestSSHHostCertificatesAreRateLimited(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	S := A + "/tenants/default/ssh"
	H := S + "/host-certificates"
	want(t, ad.patch(S, map[string]any{"enabled": true, "host_certs": true, "host_patterns": []string{"*.example.com"}}), 200)
	pub := newSSHPub(t)
	bad := map[string]any{"public_key": pub, "principals": []string{"elsewhere.test"}} // refused, but counted
	for i := range web.SSHHostSignsPerActor {
		if r := ad.post(H, bad); r.Status != 422 {
			t.Fatalf("request %d: %d %s", i, r.Status, r.Raw)
		}
	}
	r := ad.post(H, bad)
	want(t, r, 429)
	if r.Header.Get("Retry-After") == "" || !strings.Contains(r.str("error"), "Too many") {
		t.Errorf("over the limit: %v %s", r.Header, r.Raw)
	}
	// the administrator's budget is theirs: a service account's is its own
	sa := w.asServiceAccount(w.acme, service.ScopeSSHHost)
	want(t, sa.post(H, map[string]any{"public_key": pub, "principals": []string{"web1.example.com"}}), 200)
}

// A host certificate that fails for a reason of ours answers 500 and is logged with the organization and tenant.
func TestSSHHostSignLogsServerErrors(t *testing.T) {
	log := logtesting.New()
	w := newWorldLogged(t, nil, log)
	ad := w.as("admin")
	S := A + "/tenants/default/ssh"
	want(t, ad.patch(S, map[string]any{"enabled": true, "host_certs": true, "host_patterns": []string{"*.example.com"}}), 200)
	tn, err := w.env.Svc.Tenants.GetByUnique(context.Background(), model.TenantNameKey(w.acme.ID, "default"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := w.env.Svc.SSHKeys(context.Background(), tn.ID, model.SSHPurposeHost)
	if err != nil || len(keys) == 0 {
		t.Fatalf("host keys: %v %v", keys, err)
	}
	for _, k := range keys {
		k.PrivateKey = "not sealed" // the signing key cannot be opened
		if err := w.env.Svc.SSHCAKeys.Update(context.Background(), k); err != nil {
			t.Fatal(err)
		}
	}
	want(t, ad.post(S+"/host-certificates", map[string]any{"public_key": newSSHPub(t), "principals": []string{"web1.example.com"}}), 500)
	found := false
	for _, e := range log.GetEntries() {
		if e.Level == "error" && strings.Contains(e.Message, "SSH host certificate") {
			kv := fmt.Sprint(e.KeysAndValues)
			found = strings.Contains(kv, w.acme.ID) && strings.Contains(kv, tn.ID)
		}
	}
	if !found {
		t.Errorf("not logged with the organization and tenant: %v", log.GetEntries())
	}
}

// A tenant with SSH on cannot be deleted (409, saying to turn SSH off first); with SSH off its own SSH application,
// which an administrator could not delete, goes with it.
func TestSSHTenantDeletion(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	want(t, ad.post(A+"/tenants", map[string]any{"name": "lab"}), 201)
	S := A + "/tenants/lab/ssh"
	want(t, ad.patch(S, map[string]any{"enabled": true}), 200)
	r := ad.delete(A + "/tenants/lab")
	want(t, r, 409)
	if msg := r.str("error"); !strings.Contains(msg, "turn SSH off first") {
		t.Errorf("the refusal says %q", msg)
	}
	want(t, ad.patch(S, map[string]any{"enabled": false}), 200)
	want(t, ad.delete(A+"/tenants/lab"), 200)
	want(t, ad.get(A+"/tenants/lab"), 404)
}

// certOf is the stored certificate id.
func (w *world) certOf(t *testing.T, id string) *model.SSHCert {
	t.Helper()
	c, err := w.env.Svc.SSHCerts.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
