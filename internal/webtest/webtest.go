// Package webtest starts a complete in-process HTTPS server over an in-memory store for end-to-end tests.
package webtest

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
	"github.com/paularlott/quisora/internal/web"
)

// Env is a running test server.
type Env struct {
	T        testing.TB
	Cfg      *config.Config
	Store    store.Store
	Svc      *service.Service
	Server   *web.Server
	HTTP     *httptest.Server
	URL      string
	Admin    *model.User // bootstrap super admin of the primary org
	Password string      // its password
	Primary  *model.Org
}

// Options tweak the environment before modules are registered.
type Options struct {
	Store     store.Store          // default: memstore
	Configure func(*config.Config) // edit config before start
	Modules   func(*web.Server) []web.Module
	MasterKey []byte // default: a random one
}

// New starts a server. The TLS server's certificate is trusted by Client().
func New(t testing.TB, o Options) *Env {
	t.Helper()
	ctx := context.Background()
	st := o.Store
	if st == nil {
		st = memstore.New()
	}
	// Start the listener first so the issuer URL is known.
	hs := httptest.NewUnstartedServer(nil)
	hs.StartTLS()
	cfg := config.Default()
	cfg.Server.PublicURL = hs.URL
	cfg.Server.DataDir = t.TempDir()
	cfg.Limits.PasswordWorkers = 4
	if o.Configure != nil {
		o.Configure(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	key := o.MasterKey
	if key == nil {
		key = secure.RandomBytes(32)
	}
	sealer, _ := secure.NewSealer(key)
	svc := service.New(cfg, st, sealer)
	admin, _, err := svc.Bootstrap(ctx, "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Tests sign the bootstrap admin in with a password, and keep the primary org's MFA requirement off unless a
	// test turns it on (production bootstraps with RequireMFA and an invitation link instead of a password).
	pw := "bootstrap-test-password"
	if admin, err = svc.UpdateUser(ctx, service.System, admin.ID, service.UserInput{Password: &pw}); err != nil {
		t.Fatal(err)
	}
	if p, err := svc.PrimaryOrg(ctx); err == nil {
		p.Settings.RequireMFA = false
		if err := svc.Orgs.Update(ctx, p); err != nil {
			t.Fatal(err)
		}
		NoTenantMFA(t, svc, p.ID)
	}
	eph := ephemeral.NewLocal("n1")
	srv, err := web.New(cfg, svc, eph, logger.NewNullLogger())
	if err != nil {
		t.Fatal(err)
	}
	if o.Modules != nil {
		srv.Use(o.Modules(srv)...)
	}
	hs.Config.Handler = srv.Handler()
	primary, _ := svc.PrimaryOrg(ctx)
	t.Cleanup(func() { hs.Close(); svc.WaitBackground(); eph.Close(); st.Close() })
	return &Env{T: t, Cfg: cfg, Store: st, Svc: svc, Server: srv, HTTP: hs, URL: hs.URL, Admin: admin, Password: pw,
		Primary: primary}
}

// Client returns a new HTTPS client trusting the test certificate, with its own cookie jar and no automatic
// redirects.
func (e *Env) Client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Transport: e.HTTP.Client().Transport, Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// Session signs u in directly (bypassing the login UI) and returns a client carrying the session cookie and the
// CSRF token to send as X-CSRF-Token.
func (e *Env) Session(u *model.User) (*http.Client, string) {
	e.T.Helper()
	return e.SessionAMR(u, []string{"pwd"})
}

// SessionAMR is Session with the given sign-in methods (amr), e.g. pwd+otp+mfa for an administration console session.
func (e *Env) SessionAMR(u *model.User, amr []string) (*http.Client, string) {
	e.T.Helper()
	if cur, err := e.Svc.Users.Get(context.Background(), u.ID); err == nil {
		u = cur // as a sign-in does: the account as it is now (its session epoch)
	}
	org, _ := e.Svc.Orgs.Get(context.Background(), u.OrgID)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, e.URL+"/", nil)
	sess, err := e.Server.Sessions.Create(context.Background(), rec, req, u, org, amr)
	if err != nil {
		e.T.Fatal(err)
	}
	c := e.Client()
	req2, _ := http.NewRequest(http.MethodGet, e.URL+"/", nil)
	c.Jar.SetCookies(req2.URL, rec.Result().Cookies())
	return c, sess.CSRF
}

// ConsoleSession is Session with a second factor, as the administration console requires of managers and above.
func (e *Env) ConsoleSession(u *model.User) (*http.Client, string) {
	e.T.Helper()
	return e.SessionAMR(u, []string{"pwd", "otp", "mfa"})
}

// NoTenantMFA turns off the second-factor requirement of an organization's default tenant (on when it is created),
// for tests that sign in with a password alone.
func NoTenantMFA(t testing.TB, svc *service.Service, orgID string) {
	t.Helper()
	ctx := context.Background()
	d, err := svc.DefaultTenant(ctx, orgID)
	if err != nil {
		t.Fatal(err)
	}
	d.Settings.RequireMFA = false
	if err := svc.Tenants.Update(ctx, d); err != nil {
		t.Fatal(err)
	}
}
