package admin_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/backup"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// GET /api/backup streams a complete backup of the live store; super admins only. It is encrypted with the
// password in X-Backup-Password, or unencrypted with ?plain=1; one or the other must be asked for.
func TestBackupDownload(t *testing.T) {
	w := newWorld(t)
	wantField(t, w.as("super").get("/api/backup"), 400, "")
	wantField(t, w.as("super").do("GET", "/api/backup", nil, "X-Backup-Password", "short"), 400, "password")
	enc := w.as("super").do("GET", "/api/backup", nil, "X-Backup-Password", "correct horse battery")
	want(t, enc, 200)
	if !backup.PasswordProtected(enc.Raw) || enc.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("encrypted download: %v", enc.Header)
	}
	if _, err := backup.Verify(bytes.NewReader(enc.Raw), w.env.Svc.Sealer, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	r := w.as("super").get("/api/backup?plain=1")
	want(t, r, 200)
	if cd := r.Header.Get("Content-Disposition"); r.Header.Get("Content-Type") != "application/gzip" || !strings.Contains(cd, "attachment") ||
		!strings.Contains(cd, ".bak") {
		t.Fatalf("headers %v", r.Header)
	}
	stats, err := backup.Verify(bytes.NewReader(r.Raw), w.env.Svc.Sealer, "")
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := w.env.Svc.Users.Count(context.Background(), ""); stats[model.KindUser] != n {
		t.Fatalf("backup has %d users, the store %d", stats[model.KindUser], n)
	}
	want(t, w.as("admin").get("/api/backup"), 403)
	want(t, w.as("manager").get("/api/backup?plain=1"), 403)
	// a token needs the backup scope (admin is not enough); only super admins get it, and it expires within 30 days
	want(t, w.withBearer("super", "admin").get("/api/backup"), 403)
	want(t, w.withBearer("super", "api").get("/api/backup"), 403)
	_, tok, err := w.env.Svc.CreateAPIToken(context.Background(), service.ActorForUser(w.env.Admin, ""),
		service.APITokenInput{Name: "b", Scopes: []string{"backup"}, Expires: 7})
	if err != nil {
		t.Fatal(err)
	}
	c := w.withBearer("super", "api")
	c.bearer = tok
	want(t, c.get("/api/backup?plain=1"), 200)
	for name, in := range map[string]service.APITokenInput{
		"no expiry": {Name: "b", Scopes: []string{"backup"}},
		"too long":  {Name: "b", Scopes: []string{"backup"}, Expires: 31},
	} {
		if _, _, err := w.env.Svc.CreateAPIToken(context.Background(), service.ActorForUser(w.env.Admin, ""), in); err == nil {
			t.Errorf("backup token %s: accepted", name)
		}
	}
	if _, _, err := w.env.Svc.CreateAPIToken(context.Background(), service.ActorForUser(w.users["admin"], ""),
		service.APITokenInput{Name: "b", Scopes: []string{"backup"}, Expires: 7}); err == nil {
		t.Error("an organization admin got a backup token")
	}
	// a node that is not ready (catching up, cut off) refuses rather than back up a partial store
	w.env.Server.Health = notReady{}
	want(t, w.as("super").get("/api/backup?plain=1"), 503)
	w.env.Server.Health = nil
	want(t, w.as("super").get("/api/backup?plain=true"), 200)
	// every download is audited: encrypted, plain, by token, plain=true
	if n := len(auditActions(t, w, "backup.download")); n != 4 {
		t.Fatalf("backup downloads audited: %d", n)
	}
}
