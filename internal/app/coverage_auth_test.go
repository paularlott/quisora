package app

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// The management API takes personal API tokens only: anything else, and unknown tokens, are rejected.
func TestBearerRejections(t *testing.T) {
	a, _, _ := startApp(t, "sqlite")
	f := bearer(a.Svc)
	r := httptest.NewRequest("GET", "/api/me", nil)
	for _, tok := range []string{"", "plain-oauth-access-token", "eyJhbGciOiJFUzI1NiJ9.e30.sig"} {
		if _, err := f(context.Background(), r, tok); !errors.Is(err, service.ErrBadToken) {
			t.Fatalf("token %q: %v", tok, err)
		}
	}
	// well formed but unknown: refused (never an actor)
	tok := "qsr_pat_" + strings.Repeat("a", 40)
	if !service.IsAPIToken(tok) {
		t.Skip("API token prefix changed; adjust the test")
	}
	if act, err := f(context.Background(), r, tok); err == nil || act != nil {
		t.Fatalf("unknown API token accepted: %v %v", act, err)
	}
}

// SCIM takes OAuth client_credentials tokens only; garbage is refused.
func TestSCIMVerifierRejectsGarbage(t *testing.T) {
	a, _, _ := startApp(t, "sqlite")
	v := scimVerifier(a)
	r := httptest.NewRequest("GET", "/scim/v2/acme/Users", nil)
	for _, tok := range []string{"", "garbage", "a.b.c"} {
		if act, err := v(r, "Bearer", tok); err == nil || act != nil {
			t.Fatalf("token %q accepted: %v %v", tok, act, err)
		}
	}
	if act, err := v(r, "DPoP", "garbage"); err == nil || act != nil {
		t.Fatalf("DPoP garbage accepted: %v %v", act, err)
	}
}

// A restore note that cannot be read is dropped; a missing one is ignored.
func TestAuditRestoreNotes(t *testing.T) {
	a, _, _ := startApp(t, "sqlite")
	ctx := context.Background()
	a.auditRestore(ctx) // no note
	path := filepath.Join(a.Cfg.Server.DataDir, restoreAuditFile)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.auditRestore(ctx)
	if _, err := os.Stat(path); err == nil {
		t.Fatal("corrupt note kept")
	}
	// a valid note is written to the audit log and removed
	noteRestore(a.Cfg, "x.bak", 7, true, "restore")
	a.auditRestore(ctx)
	if _, err := os.Stat(path); err == nil {
		t.Fatal("note kept after it was audited")
	}
	org, err := a.Svc.PrimaryOrg(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found *model.Audit
	for deadline := time.Now().Add(10 * time.Second); found == nil && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		l, _, _ := a.Svc.Audits.List(ctx, store.ListQuery{Scope: org.ID})
		for _, e := range l {
			if e.Action == "backup.restore" {
				found = e
			}
		}
	}
	if found == nil || found.Detail["file"] != "x.bak" || found.Detail["records"] != "7" || found.Detail["forced"] != "true" {
		t.Fatalf("backup.restore event: %+v", found)
	}
}

// cliAudit is a no-op without VictoriaLogs, and with a bad address; with one it queues to it.
func TestCLIAudit(t *testing.T) {
	log := logger.NewNullLogger()
	c := config.Default()
	cleanup := cliAudit(c, nil, log)
	cleanup()
	c.Audit.VictoriaLogs = "://bad url"
	cliAudit(c, nil, log)()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	c.Audit.VictoriaLogs = srv.URL
	svc := service.New(c, nil, nil)
	cliAudit(c, svc, log)()
	if svc.AuditWriter == nil {
		t.Fatal("audit writer not set")
	}
}

// set-primary refusals: no key, unknown organization.
func TestSetPrimaryRefusals(t *testing.T) {
	ctx := context.Background()
	log := logger.NewNullLogger()
	c := sqliteNode(t, "")
	if _, _, err := SetPrimary(ctx, c, log, "x", "a@b.test"); err == nil || !strings.Contains(err.Error(), "master_key") {
		t.Fatalf("no key: %v", err)
	}
	c.Server.MasterKey = base64.StdEncoding.EncodeToString(secure.RandomBytes(32))
	c.Server.PreviousMasterKeys = []string{"!"}
	if _, _, err := SetPrimary(ctx, c, log, "x", "a@b.test"); err == nil {
		t.Fatal("bad previous key accepted")
	}
	c.Server.PreviousMasterKeys = nil
	if _, _, err := SetPrimary(ctx, c, log, "nope", "a@b.test"); err == nil || !strings.Contains(err.Error(), "no organization") {
		t.Fatalf("unknown org: %v", err)
	}
	_ = model.PrimaryOrgID
}
