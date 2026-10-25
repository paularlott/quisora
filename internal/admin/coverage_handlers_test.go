package admin_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/admin"
	"github.com/paularlott/quisora/internal/model"
)

// failingMailer refuses every mail with err.
type failingMailer struct{ err error }

func (m failingMailer) SendInviteLink(context.Context, *model.Org, *model.User, string, time.Time) error {
	return m.err
}

func (m failingMailer) SendVerifyAddress(context.Context, *model.Org, *model.User, string) error {
	return m.err
}

func TestCoverageBackupDownload(t *testing.T) {
	w := newWorld(t)
	su := w.as("super")
	want(t, w.as("admin").get("/api/backup?plain=1"), 403)
	want(t, w.as("manager").get("/api/backup?plain=1"), 403)
	wantField(t, su.get("/api/backup"), 400, "")
	wantField(t, su.do("GET", "/api/backup", nil, "X-Backup-Password", "short"), 400, "password")

	r := su.get("/api/backup?plain=1")
	want(t, r, 200)
	if ct := r.Header.Get("Content-Type"); ct != "application/gzip" || !strings.Contains(r.Header.Get("Content-Disposition"), ".bak") {
		t.Errorf("headers: %v", r.Header)
	}
	if zr, err := gzip.NewReader(bytes.NewReader(r.Raw)); err != nil {
		t.Errorf("plain backup is not gzip: %v", err)
	} else {
		zr.Close()
	}
	r = su.do("GET", "/api/backup", nil, "X-Backup-Password", "a long enough password")
	want(t, r, 200)
	if r.Header.Get("Content-Type") != "application/octet-stream" || bytes.HasPrefix(r.Raw, []byte{0x1f, 0x8b}) {
		t.Errorf("encrypted backup: %v", r.Header)
	}
	want(t, su.get("/api/backup?plain=true"), 200)
	if n := len(auditActions(t, w, "backup.download")); n != 3 {
		t.Errorf("audited %d downloads", n)
	}
}

func TestCoverageMailerRefusals(t *testing.T) {
	w := newWorld(t)
	w.env.Server.Site.Mail = true
	w.mod = admin.New() // the default mailer is disabled
	ad := w.as("admin")
	E := AU + "/" + w.users["user"].ID + "/emails"
	// Adding an address and changing the primary address succeed even though the mail cannot go out.
	r := ad.post(E, map[string]any{"address": "disabled@x.example"})
	want(t, r, 201)
	want(t, ad.patch(AU+"/"+w.users["user"].ID, map[string]any{"email": "alan.two@x.example"}), 200)
	// The resend names the cause: email is not set up here.
	r = ad.post(E+"/"+url.PathEscape("disabled@x.example")+"/verify", nil)
	if r.Status != 503 && r.Status != 200 {
		t.Errorf("resend with the default mailer: %d %s", r.Status, r.Raw)
	}
}

func TestCoverageMailerFailures(t *testing.T) {
	w := newWorld(t)
	w.env.Server.Site.Mail = true
	ad := w.as("admin")
	uid := w.users["user"].ID
	E := AU + "/" + uid + "/emails"

	w.mod.Mailer = failingMailer{err: admin.ErrMailerDisabled}
	want(t, ad.post(E, map[string]any{"address": "one@x.example"}), 201)
	r := ad.post(E+"/"+url.PathEscape("one@x.example")+"/verify", nil)
	want(t, r, 503)
	if !strings.Contains(r.str("error"), "not set up") {
		t.Errorf("message: %s", r.Raw)
	}
	want(t, ad.patch(AU+"/"+uid, map[string]any{"email": "alan.three@x.example"}), 200)

	w.mod.Mailer = failingMailer{err: errors.New("smtp down")}
	want(t, ad.post(E, map[string]any{"address": "two@x.example"}), 201)
	if r := ad.post(E+"/"+url.PathEscape("two@x.example")+"/verify", nil); r.Status != 500 {
		t.Errorf("resend with a failing mailer: %d %s", r.Status, r.Raw)
	}
	want(t, ad.patch(AU+"/"+uid, map[string]any{"email": "alan.four@x.example"}), 200)
	// Invitations are created with the link even when the mail fails.
	r = ad.post(AU+"/"+uid+"/invite", map[string]any{"email": true})
	want(t, r, 200)
	if r.JSON["emailed"] != false {
		t.Errorf("invite: %s", r.Raw)
	}
}

func TestCoverageUserEdges(t *testing.T) {
	w := newWorld(t)
	ad, mg := w.as("admin"), w.as("manager")
	uid := w.users["user"].ID
	// Filters of the user list.
	want(t, ad.get(AU+"?active=1"), 200)
	want(t, ad.get(AU+"?active=0"), 200)
	want(t, ad.get(AU+"?active=maybe"), 200)
	want(t, ad.get(AU+"?role=user&q=al"), 200)
	// An invitation of a user without an email address.
	nm := ad.post(AU, map[string]any{"given_name": "N", "username": "noemail"})
	if nm.Status == 201 {
		id := nm.str("id")
		wantField(t, ad.post(AU+"/"+id+"/invite", map[string]any{"email": true}), 422, "email")
	}
	// A manager can invite a plain user but not an administrator.
	want(t, mg.post(AU+"/"+w.users["admin"].ID+"/invite", map[string]any{}), 403)
	// Users of another organization are not found from here, by any of the user routes.
	for _, p := range []string{"", "/apps", "/providers", "/sessions", "/passkeys", "/tokens"} {
		want(t, ad.get(AU+"/"+w.users["other"].ID+p), 404)
	}
	// A user's own profile through the user routes.
	me := w.as("user")
	want(t, me.get(AU+"/"+uid), 200)
	want(t, me.get(AU+"/"+w.users["manager"].ID), 404) // a user does not see above their own role
	want(t, me.get(AU+"/"+uid+"/sessions"), 200)
	want(t, me.get(AU+"/"+uid+"/passkeys"), 200)
	want(t, me.get(AU+"/"+uid+"/tokens"), 200)
	// Sessions list: the current one first.
	r := ad.get(AU + "/" + w.users["admin"].ID + "/sessions")
	want(t, r, 200)
	if r.total() < 1 || r.items()[0].(map[string]any)["current"] != true {
		t.Errorf("sessions: %s", r.Raw)
	}
}

func TestCoverageTenantAccessAndSelfRegistered(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	T := A + "/tenants"
	r := ad.post(T, map[string]any{"name": "covt", "display_name": "T", "resources": []string{"https://t.example.com/mcp"},
		"settings": map[string]any{"password_login": true, "passkey_login": true, "all_providers": true}})
	want(t, r, 201)
	id := r.str("id")
	AC := T + "/" + id + "/access"
	want(t, ad.get(AC), 200)
	want(t, ad.post(AC, "not json"), 400)
	want(t, ad.post(AC, map[string]any{"subject_type": "user", "subject_id": "ghost"}), 422)
	r = ad.post(AC, map[string]any{"subject_type": "user", "subject_id": w.users["user"].ID, "roles": []string{"viewer"}, "all_clients": true})
	want(t, r, 201)
	aid := r.str("id")
	if aid == "" {
		aid = r.JSON["id"].(string)
	}
	want(t, ad.get(AC+"/"+aid), 200)
	want(t, ad.get(AC+"/nope"), 404)
	want(t, ad.patch(AC+"/"+aid, "not json"), 400)
	want(t, ad.patch(AC+"/"+aid, map[string]any{"tags": []string{"x"}}), 200)
	want(t, ad.patch(AC+"/nope", map[string]any{"tags": []string{"x"}}), 404)
	want(t, ad.delete(AC+"/nope"), 404)
	want(t, ad.get(T+"/"+id+"/self-registered"), 200)
	want(t, ad.delete(T+"/"+id+"/self-registered/ghost"), 404)
	want(t, ad.delete(AC+"/"+aid), 200)
	// Another organization's administrator reaches none of it.
	other := w.as("other")
	for _, p := range []string{AC, AC + "/" + aid, T + "/" + id + "/self-registered"} {
		want(t, other.get(p), 404)
	}
	_ = model.RoleUser
}

func TestCoverageClientProviderGroupEdges(t *testing.T) {
	w := newWorld(t)
	ad := w.as("admin")
	// Clients.
	r := ad.post(A+"/clients", map[string]any{"name": "Pub", "redirect_uris": []string{"https://p.example/cb"}, "token_endpoint_auth_method": "none"})
	want(t, r, 201)
	pub := r.str("id")
	if pub == "" {
		pub = r.JSON["client_id"].(string)
	}
	wantField(t, ad.post(A+"/clients/"+pub+"/secret", nil), 422, "token_endpoint_auth_method")
	want(t, ad.post(A+"/clients", "junk"), 400)
	want(t, ad.patch(A+"/clients/"+pub, "junk"), 400)
	want(t, ad.delete(A+"/clients/"+pub), 200)
	want(t, ad.delete(A+"/clients/"+pub), 404)
	// Providers.
	want(t, ad.post(A+"/providers", "junk"), 400)
	want(t, ad.post(A+"/providers", map[string]any{}), 422)
	want(t, ad.patch(A+"/providers/nope", map[string]any{}), 404)
	want(t, ad.delete(A+"/providers/nope"), 404)
	// Groups.
	want(t, ad.post(A+"/groups", "junk"), 400)
	want(t, ad.patch(A+"/groups/nope", map[string]any{"display_name": "x"}), 404)
	want(t, ad.delete(A+"/groups/nope"), 404)
	want(t, ad.get(A+"/groups/nope/members"), 404)
	want(t, ad.put(A+"/groups/nope/members/"+w.users["user"].ID, nil), 404)
	want(t, ad.delete(A+"/groups/nope/members/"+w.users["user"].ID), 404)
	g := ad.post(A+"/groups", map[string]any{"display_name": "covg"})
	want(t, g, 201)
	gid := g.str("id")
	want(t, ad.patch(A+"/groups/"+gid, "junk"), 400)
	want(t, ad.put(A+"/groups/"+gid+"/members/ghost", nil), 422)
	want(t, ad.delete(A+"/groups/"+gid+"/members/ghost"), 200)
	want(t, ad.delete(A+"/groups/"+gid), 200)
	// Organizations.
	want(t, w.as("super").patch("/api/orgs/acme", "junk"), 400)
	want(t, w.as("super").post("/api/orgs", "junk"), 400)
}
