package login_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/login"
	"github.com/paularlott/quisora/internal/mail"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/passkey/virtualauth"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

const userPassword = "correct-horse-battery"

type env struct {
	*webtest.Env
	Mod    *login.Module
	Mailer *mail.Mailer
	mu     sync.Mutex
	mails  []mail.Message
	mailCh chan mail.Message
}

// newEnv starts a test server with the login module and a capturing mailer. The public URL host is "localhost"
// (WebAuthn forbids IP addresses as RP ids).
func newEnv(t testing.TB, mut func(*config.Config)) *env { return newEnvWith(t, mut, false) }

// newEnvWith can keep webtest's default 127.0.0.1 public URL (keepIP), which cannot be a WebAuthn relying party.
func newEnvWith(t testing.TB, mut func(*config.Config), keepIP bool) *env {
	t.Helper()
	e := &env{mailCh: make(chan mail.Message, 64)}
	e.Env = webtest.New(t, webtest.Options{
		Configure: func(c *config.Config) {
			if !keepIP {
				u, _ := url.Parse(c.Server.PublicURL)
				c.Server.PublicURL = "https://localhost:" + u.Port()
			}
			if mut != nil {
				mut(c)
			}
		},
		Modules: func(s *web.Server) []web.Module {
			m, err := mail.New(s.Cfg, logger.NewNullLogger(), s.Svc.Sealer)
			if err != nil {
				t.Fatal(err)
			}
			e.Mailer = m
			e.Mailer.Transport = mail.TransportFunc(func(_ context.Context, m mail.Message) error {
				e.mu.Lock()
				e.mails = append(e.mails, m)
				e.mu.Unlock()
				e.mailCh <- m
				return nil
			})
			// "/step-up" stands for an authorization request that asked for a second factor (acr_values).
			e.Mod = login.New(s, login.Options{Mail: e.Mailer, StepUp: func(_ context.Context, next string) bool { return next == "/step-up" }})
			return []web.Module{e.Mod}
		},
	})
	t.Cleanup(e.Mailer.Close)
	return e
}

// client returns an independent cookie-jar client (webtest's Client() mutates one shared http.Client).
func (e *env) client() *http.Client {
	c := *e.HTTP.Client()
	jar, _ := cookiejar.New(nil)
	c.Jar = jar
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

func (e *env) mailCount() int { e.mu.Lock(); defer e.mu.Unlock(); return len(e.mails) }

func (e *env) nextMail(t testing.TB) mail.Message {
	t.Helper()
	select {
	case m := <-e.mailCh:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no mail sent")
	}
	return mail.Message{}
}

func (e *env) noMail(t testing.TB) {
	t.Helper()
	select {
	case m := <-e.mailCh:
		t.Fatalf("unexpected mail to %s: %s", m.To, m.Subject)
	case <-time.After(150 * time.Millisecond):
	}
}

var linkRe = regexp.MustCompile(`https://localhost:\d+(/[a-z-]+\?token=[A-Za-z0-9._%-]+)`)

// linkPath returns the path+query of the link in a message.
func linkPath(t testing.TB, m mail.Message) string {
	t.Helper()
	g := linkRe.FindStringSubmatch(m.Text)
	if g == nil {
		t.Fatalf("no link in mail: %s", m.Text)
	}
	return g[1]
}

func (e *env) user(t testing.TB, org *model.Org, name string, role model.Role) *model.User {
	t.Helper()
	pw := userPassword
	email := name + "@example.com"
	u, err := e.Svc.CreateUser(context.Background(), service.System, org.ID, service.UserInput{Username: &name, Email: &email,
		Role: &role, GivenName: &name})
	if err != nil {
		t.Fatal(err)
	}
	// Passwords are never set when a user is created; fixtures set one as the system, like an accepted invitation.
	if u, err = e.Svc.UpdateUser(context.Background(), service.System, u.ID, service.UserInput{Password: &pw}); err != nil {
		t.Fatal(err)
	}
	return u
}

func (e *env) org(t testing.TB, name string, mut func(*model.OrgSettings)) *model.Org {
	t.Helper()
	in := service.OrgInput{Name: &name}
	if mut != nil {
		s := model.DefaultOrgSettings()
		mut(&s)
		in.Settings = &s
	}
	o, err := e.Svc.CreateOrg(context.Background(), service.System, in)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func (e *env) setSettings(t testing.TB, o *model.Org, mut func(*model.OrgSettings)) {
	t.Helper()
	s := o.Settings
	mut(&s)
	if _, err := e.Svc.UpdateOrg(context.Background(), service.System, o.ID, service.OrgInput{Settings: &s}); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------------------------------------------
// A scripted "browser"

type browser struct {
	t    testing.TB
	e    *env
	c    *http.Client
	csrf string
	auth *virtualauth.Authenticator
}

var metaRe = regexp.MustCompile(`<meta name="csrf-token" content="([^"]*)"`)

// browser returns a fresh browser (own cookie jar) that has loaded the sign-in page, so it holds the anonymous
// CSRF cookie and token.
func (e *env) browser(t testing.TB) *browser {
	t.Helper()
	b := &browser{t: t, e: e, c: e.client(), auth: virtualauth.New(e.Cfg.Server.PublicURL)}
	b.refresh()
	return b
}

func (b *browser) refresh() {
	b.t.Helper()
	_, body := b.get("/login/primary")
	m := metaRe.FindStringSubmatch(body)
	if m == nil {
		b.t.Fatalf("no csrf meta in page: %.300s", body)
	}
	b.csrf = m[1]
}

func (b *browser) get(path string) (*http.Response, string) {
	b.t.Helper()
	res, err := b.c.Get(b.e.URL + path)
	if err != nil {
		b.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res, string(body)
}

type hdrs map[string]string

func (b *browser) do(method, path string, body any, h hdrs) (*http.Response, map[string]any) {
	b.t.Helper()
	var rd io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			rd = strings.NewReader(v)
		default:
			j, _ := json.Marshal(v)
			rd = bytes.NewReader(j)
		}
	}
	req, _ := http.NewRequest(method, b.e.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if _, skip := h["X-CSRF-Token"]; !skip {
		req.Header.Set("X-CSRF-Token", b.csrf)
	}
	for k, v := range h {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	res, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	out["_raw"] = string(raw)
	return res, out
}

func (b *browser) post(path string, body any) (*http.Response, map[string]any) {
	return b.do(http.MethodPost, path, body, nil)
}

// login posts the password form. A bare name stands for the fixture address <name>@example.com (see env.user and the
// bootstrap admin); anything containing "@" is sent as given.
func (b *browser) login(org, who, password string) (*http.Response, map[string]any) {
	if who != "" && !strings.Contains(who, "@") {
		who += "@example.com"
	}
	return b.post("/api-internal/login/password", map[string]any{"org": org, "email": who, "password": password})
}

// signedIn returns a browser holding a session for u (created directly) and its CSRF token.
func (e *env) signedIn(t testing.TB, u *model.User) *browser {
	t.Helper()
	c, csrf := e.Session(u)
	cp := *c // webtest hands out one shared *http.Client; keep this jar
	b := &browser{t: t, e: e, c: &cp, csrf: csrf, auth: virtualauth.New(e.Cfg.Server.PublicURL)}
	b.signedInAt(time.Now().Add(-time.Hour)) // an older sign-in: sensitive changes ask to confirm (b.fresh() undoes it)
	return b
}

// signedInMFA is signedIn with a session that used a second factor (pwd, otp), as managers and above always have.
func (e *env) signedInMFA(t testing.TB, u *model.User) *browser {
	t.Helper()
	c, csrf := e.SessionAMR(u, []string{"pwd", "otp", "mfa"})
	cp := *c
	b := &browser{t: t, e: e, c: &cp, csrf: csrf, auth: virtualauth.New(e.Cfg.Server.PublicURL)}
	b.signedInAt(time.Now().Add(-time.Hour))
	return b
}

// signedInAt sets when the browser's session signed in.
func (b *browser) signedInAt(at time.Time) {
	b.t.Helper()
	id := b.sessionID()
	s, err := b.e.Svc.Sessions.Get(context.Background(), id)
	if err != nil {
		b.t.Fatal(err)
	}
	s.AuthTime = at
	if err := b.e.Svc.Sessions.Update(context.Background(), s); err != nil {
		b.t.Fatal(err)
	}
	b.e.Server.Sessions.Evict(id, "")
}

// fresh makes the browser's sign-in a moment ago.
func (b *browser) fresh() { b.signedInAt(time.Now()) }

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func wantStatus(t testing.TB, res *http.Response, body map[string]any, want int) {
	t.Helper()
	if res.StatusCode != want {
		t.Fatalf("status %d, want %d: %v", res.StatusCode, want, body["_raw"])
	}
}

// sessionCookie reports whether the browser holds a session cookie.
func (b *browser) hasSession() bool {
	u, _ := url.Parse(b.e.URL)
	for _, c := range b.c.Jar.Cookies(u) {
		if c.Name == web.SessionCookie {
			return true
		}
	}
	return false
}

func (b *browser) sessionID() string {
	u, _ := url.Parse(b.e.URL)
	for _, c := range b.c.Jar.Cookies(u) {
		if c.Name == web.SessionCookie {
			return web.SessionID(c.Value) // stored id = hash of the cookie
		}
	}
	return ""
}

// ---------------------------------------------------------------------------------------------------------------
// TOTP

func totpAt(secret string, t time.Time) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/30))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}

func (e *env) giveTOTP(t testing.TB, u *model.User) string {
	t.Helper()
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	fresh, err := e.Svc.Users.Get(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	fresh.TOTPSecret = e.Svc.Sealer.SealFor(service.TOTPBinding(fresh.ID), []byte(secret))
	if err := e.Svc.Users.Update(context.Background(), fresh); err != nil {
		t.Fatal(err)
	}
	return secret
}

// audits returns every audit event with the action.
func (e *env) audits(t testing.TB, action string) []*model.Audit {
	t.Helper()
	l, _, err := e.Svc.Audits.List(context.Background(), store.ListQuery{})
	if err != nil {
		t.Fatal(err)
	}
	var out []*model.Audit
	for _, a := range l {
		if a.Action == action {
			out = append(out, a)
		}
	}
	return out
}

// markReauth gives the browser's session a fresh re-authentication without going through the dialog.
func (b *browser) markReauth() { b.e.Mod.MarkReauth(b.sessionID()) }

// member creates a plain user "member" in the primary organization (password userPassword): the bootstrap admin is a
// super admin, who never signs in with a password alone.
func (e *env) member(t testing.TB) *model.User {
	t.Helper()
	org, err := e.Svc.PrimaryOrg(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return e.user(t, org, "member", model.RoleUser)
}
