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
	"maps"
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
	// last is the organization most recently made by env.org: the one a new browser's relative paths are in, as most
	// tests are about the organization they make (the primary one otherwise).
	last   *model.Org
	mu     sync.Mutex
	mails  []mail.Message
	mailCh chan mail.Message
}

// newEnv starts a test server with the login module and a capturing mailer. The public URL host is "localhost"
// (WebAuthn forbids IP addresses as RP ids).
func newEnv(t testing.TB, mut ...func(*config.Config)) *env { return newEnvWith(t, false, mut...) }

// Configuration mutators for newEnv.
var (
	// noIPLimit lifts the per-address sign-in limit, for tests that sign in many times.
	noIPLimit = func(c *config.Config) { c.Limits.LoginPerIPMin = 0 }
	// auditLogins records successful sign-ins too.
	auditLogins = func(c *config.Config) { c.Audit.Logins = true }
	// withSMTP makes the server send mail (the capturing transport takes it).
	withSMTP = func(c *config.Config) { c.Mail.SMTPHost = "smtp.example.com" }
)

// lockoutAfter locks an account after n failed sign-ins (0: never).
func lockoutAfter(n int) func(*config.Config) {
	return func(c *config.Config) { c.Limits.LockoutAttempts = n }
}

// newEnvWith can keep webtest's default 127.0.0.1 public URL (keepIP), which cannot be a WebAuthn relying party.
func newEnvWith(t testing.TB, keepIP bool, mut ...func(*config.Config)) *env {
	return newEnvModules(t, keepIP, nil, mut...)
}

// newEnvModules is newEnvWith with more modules registered after the login module (extra may be nil): tests of what
// the login module does with another module of the server, such as the OAuth endpoints of an organization.
func newEnvModules(t testing.TB, keepIP bool, extra func(*web.Server) []web.Module, mut ...func(*config.Config)) *env {
	t.Helper()
	e := &env{mailCh: make(chan mail.Message, 64)}
	e.Env = webtest.New(t, webtest.Options{
		Configure: func(c *config.Config) {
			if !keepIP {
				u, _ := url.Parse(c.Server.PublicURL)
				c.Server.PublicURL = "https://localhost:" + u.Port()
			}
			for _, m := range mut {
				if m != nil {
					m(c)
				}
			}
		},
		Modules: func(s *web.Server) []web.Module {
			m := mail.New(s.Cfg, logger.NewNullLogger(), s.Svc.Store, "node-1", s.Svc.Sealer, mail.TransportFunc(func(_ context.Context, m mail.Message) error {
				e.mu.Lock()
				e.mails = append(e.mails, m)
				e.mu.Unlock()
				e.mailCh <- m
				return nil
			}))
			m.SetService(s.Svc)
			e.Mailer = m
			// "/step-up" stands for an authorization request that asked for a second factor (acr_values).
			e.Mod = login.New(s, login.Options{Mail: e.Mailer, StepUp: func(_ context.Context, next string) bool { return next == "/step-up" }})
			mods := []web.Module{e.Mod}
			if extra != nil {
				mods = append(mods, extra(s)...)
			}
			return mods
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

// mailInvite issues an invitation for u and emails it, as an administrator's "send invitation" does.
func (e *env) mailInvite(t testing.TB, u *model.User, org *model.Org) {
	t.Helper()
	link, exp, err := e.Svc.CreateInvite(context.Background(), service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Mailer.SendInviteLink(context.Background(), u, org, link, exp); err != nil {
		t.Fatal(err)
	}
}

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

// mailSettle is how long noMail and drainMails wait for a mail still on its way: the sign-in handlers send theirs in the
// background, after the response.
const mailSettle = 150 * time.Millisecond

// drainMails returns how many mails arrive: it waits for the first, then until none has for mailSettle.
func (e *env) drainMails(t testing.TB) int {
	t.Helper()
	e.nextMail(t)
	n := 1
	for {
		select {
		case <-e.mailCh:
			n++
		case <-time.After(mailSettle):
			return n
		}
	}
}

func (e *env) noMail(t testing.TB) {
	t.Helper()
	select {
	case m := <-e.mailCh:
		t.Fatalf("unexpected mail to %s: %s", m.To, m.Subject)
	case <-time.After(mailSettle):
	}
}

var linkRe = regexp.MustCompile(`https://localhost:\d+(/o/[0-9A-Za-z]{22}/[a-z-]+\?token=[A-Za-z0-9._%-]+)`)

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

// allowAPITokens is an org mutation that lets everyone make api tokens (an organization starts with nobody allowed).
func allowAPITokens(s *model.OrgSettings) { s.APITokens = model.APITokensEveryone }

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
	e.last = o
	return o
}

func (e *env) setSettings(t testing.TB, o *model.Org, mut func(*model.OrgSettings)) {
	t.Helper()
	s := o.Settings
	mut(&s)
	if _, err := e.Svc.UpdateOrg(context.Background(), service.System, o.ID, service.OrgInput{Settings: &s}); err != nil {
		t.Fatal(err)
	}
	e.Svc.InvalidateOrgs() // as the change feed does
}

// ---------------------------------------------------------------------------------------------------------------
// A scripted "browser"

type browser struct {
	t    testing.TB
	e    *env
	c    *http.Client
	csrf string
	auth *virtualauth.Authenticator
	// base is the address space (/o/<org id or name>) the browser's relative paths are in, as the page a person is on
	// decides where its links lead: "/login" is that organization's sign-in page. A path that starts with /o/ is taken
	// as it is, and is the new base.
	base string
}

// primaryBase is the primary organization's address space.
func (e *env) primaryBase() string { return web.OrgPath(e.Primary.ID, "") }

// at returns the browser's path for p: p itself when it names an organization (which the browser is then in), else p
// in the one it is in.
func (b *browser) at(p string) string {
	if rest, ok := strings.CutPrefix(p, "/o/"); ok {
		org, _, _ := strings.Cut(rest, "/")
		if o, err := b.e.Svc.OrgByRef(context.Background(), org); err == nil {
			org = o.ID
		}
		b.base = "/o/" + org
		return p
	}
	return b.base + p
}

var metaRe = regexp.MustCompile(`<meta name="csrf-token" content="([^"]*)"`)

// browser returns a fresh browser (own cookie jar) that has loaded the sign-in page, so it holds the anonymous
// CSRF cookie and token. Its relative paths are in the organization most recently made (env.org), the primary one
// before any.
func (e *env) browser(t testing.TB) *browser {
	t.Helper()
	b := &browser{t: t, e: e, c: e.client(), auth: virtualauth.New(e.Cfg.Server.PublicURL), base: e.primaryBase()}
	if e.last != nil {
		b.base = web.OrgPath(e.last.ID, "")
	}
	b.refresh()
	return b
}

// browserAt is a fresh browser in org's address space.
func (e *env) browserAt(t testing.TB, org *model.Org) *browser {
	t.Helper()
	b := e.browser(t)
	b.base = web.OrgPath(org.ID, "")
	b.refresh()
	return b
}

func (b *browser) refresh() {
	b.t.Helper()
	_, body := b.get("/login")
	m := metaRe.FindStringSubmatch(body)
	if m == nil {
		b.t.Fatalf("no csrf meta in page: %.300s", body)
	}
	b.csrf = m[1]
}

func (b *browser) get(path string) (*http.Response, string) {
	b.t.Helper()
	return b.getAt(b.at(path))
}

// getAbs is get of a path as it is, outside any organization's address space.
func (b *browser) getAbs(path string) (*http.Response, string) {
	b.t.Helper()
	return b.getAt(path)
}

func (b *browser) getAt(path string) (*http.Response, string) {
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

// do sends a request, failing the test when it cannot be sent.
func (b *browser) do(method, path string, body any, h hdrs) (*http.Response, map[string]any) {
	b.t.Helper()
	res, out, err := b.send(method, path, body, h)
	if err != nil {
		b.t.Fatal(err)
	}
	return res, out
}

// send is do for goroutines other than the test's: the error is returned.
func (b *browser) send(method, path string, body any, h hdrs) (*http.Response, map[string]any, error) {
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
	req, _ := http.NewRequest(method, b.e.URL+b.at(path), rd)
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
		return nil, nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	out["_raw"] = string(raw)
	return res, out, nil
}

func (b *browser) post(path string, body any) (*http.Response, map[string]any) {
	return b.do(http.MethodPost, path, body, nil)
}

// login posts the password form of the organization called org (its name or id). A bare name stands for the fixture
// address <name>@example.com (see env.user and the bootstrap admin); anything containing "@" is sent as given.
func (b *browser) login(org, who, password string) (*http.Response, map[string]any) {
	if who != "" && !strings.Contains(who, "@") {
		who += "@example.com"
	}
	return b.post("/o/"+org+"/api-internal/login/password", map[string]any{"email": who, "password": password})
}

// signedIn returns a browser holding a session for u (created directly) and its CSRF token.
func (e *env) signedIn(t testing.TB, u *model.User) *browser {
	t.Helper()
	c, csrf := e.Session(u)
	cp := *c // webtest hands out one shared *http.Client; keep this jar
	b := &browser{t: t, e: e, c: &cp, csrf: csrf, auth: virtualauth.New(e.Cfg.Server.PublicURL), base: web.OrgPath(u.OrgID, "")}
	b.signedInAt(time.Now().Add(-time.Hour)) // an older sign-in: sensitive changes ask to confirm (b.fresh() undoes it)
	return b
}

// signedInMFA is signedIn with a session that used a second factor (pwd, otp), as managers and above always have.
func (e *env) signedInMFA(t testing.TB, u *model.User) *browser {
	t.Helper()
	c, csrf := e.SessionAMR(u, []string{"pwd", "otp", "mfa"})
	cp := *c
	b := &browser{t: t, e: e, c: &cp, csrf: csrf, auth: virtualauth.New(e.Cfg.Server.PublicURL), base: web.OrgPath(u.OrgID, "")}
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

// hasSession reports whether the browser holds a session cookie (of any organization).
func (b *browser) hasSession() bool { return b.sessionID() != "" }

// sessionID is the id of the browser's session (of the first organization it holds one of), "" when it has none.
func (b *browser) sessionID() string {
	u, _ := url.Parse(b.e.URL)
	for _, c := range b.c.Jar.Cookies(u) {
		if strings.HasPrefix(c.Name, web.SessionCookieFor("")) {
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

func ptr[T any](v T) *T { return &v }

func (b *browser) api(method, path string, body any) (*http.Response, map[string]any) {
	return b.do(method, path, body, nil)
}

func items(t testing.TB, out map[string]any) []map[string]any {
	t.Helper()
	raw, _ := out["items"].([]any)
	var r []map[string]any
	for _, x := range raw {
		r = append(r, x.(map[string]any))
	}
	return r
}

func sessionsOf(t testing.TB, e *env, u *model.User) []*model.Session {
	t.Helper()
	s, err := e.Svc.Sessions.All(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var mailCodeRe = regexp.MustCompile(`\b(\d{6})\b`)

// emailEnv is a server that sends mail, with an organization whose settings mut sets.
func emailEnv(t *testing.T, mut func(*model.OrgSettings)) (*env, *model.Org) {
	e := newEnv(t, func(c *config.Config) { c.Mail.SMTPHost = "smtp.example.com"; c.Audit.Logins = true })
	return e, e.org(t, "acme", mut)
}

// verifiedUser creates a user whose address is verified.
func (e *env) verifiedUser(t *testing.T, org *model.Org, name string, role model.Role) *model.User {
	t.Helper()
	u := e.user(t, org, name, role)
	yes := true
	u, err := e.Svc.UpdateUser(context.Background(), service.System, u.ID, service.UserInput{Verified: &yes})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func codeFrom(t *testing.T, e *env) string {
	t.Helper()
	m := e.nextMail(t)
	if !strings.Contains(m.Subject, "sign-in code") {
		t.Fatalf("not a code: %q", m.Subject)
	}
	g := mailCodeRe.FindStringSubmatch(m.Text)
	if g == nil {
		t.Fatalf("no code in %q", m.Text)
	}
	if strings.Contains(m.Subject, g[1]) {
		t.Fatalf("the code is in the subject (shown in notification previews): %q", m.Subject)
	}
	return g[1]
}

// invitee creates a user without a password and returns it with the path+query of a fresh invitation.
func (e *env) invitee(t testing.TB, org *model.Org, name string) (*model.User, string) {
	t.Helper()
	email := name + "@example.com"
	u, err := e.Svc.CreateUser(context.Background(), service.System, org.ID, service.UserInput{Username: &name, Email: &email, GivenName: &name})
	if err != nil {
		t.Fatal(err)
	}
	return u, e.invite(t, u)
}

// invite issues an invitation for u and returns its path+query: the page of the user's organization the link opens
// (the token is the service's; where the page is is the module's, whatever address the service builds).
func (e *env) invite(t testing.TB, u *model.User) string {
	t.Helper()
	link, _, err := e.Svc.CreateInvite(context.Background(), service.System, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	return web.OrgPath(u.OrgID, "/invite?token="+tokenOf(link))
}

func tokenOf(link string) string { return link[strings.Index(link, "token=")+len("token="):] }

// invitePasskey runs the passkey ceremony of an invitation and returns the completion request body.
func (b *browser) invitePasskeyBody(token string, extra map[string]any) (map[string]any, int, map[string]any) {
	b.t.Helper()
	res, begin := b.post("/api-internal/invite/passkey/begin", map[string]any{"token": token})
	if res.StatusCode != 200 {
		return nil, res.StatusCode, begin
	}
	opts, _ := json.Marshal(begin["options"])
	cred, _, err := b.auth.Create(opts)
	if err != nil {
		b.t.Fatal(err)
	}
	body := map[string]any{"token": token, "challenge": begin["challenge"], "name": "Key", "credential": json.RawMessage(cred)}
	for k, v := range extra {
		body[k] = v
	}
	return body, 200, nil
}

// registerPasskey enrols a passkey for the signed-in browser's user through the account API.
func (b *browser) registerPasskey(name string) *virtualauth.Credential {
	b.t.Helper()
	b.markReauth() // registering a passkey needs a recent re-authentication
	res, out := b.post("/api-internal/account/passkeys/register/begin", nil)
	wantStatus(b.t, res, out, 200)
	opts, _ := json.Marshal(out["options"])
	cred, c, err := b.auth.Create(opts)
	if err != nil {
		b.t.Fatal(err)
	}
	res, out = b.post("/api-internal/account/passkeys/register/finish", map[string]any{"challenge": out["challenge"], "name": name,
		"credential": json.RawMessage(cred)})
	wantStatus(b.t, res, out, 201)
	return c
}

// passkeyLogin runs begin+finish on an anonymous browser and returns the finish response. begin's "org" (a name or
// id) is the organization whose page the ceremony runs on, by default the browser's own.
func (b *browser) passkeyLogin(begin map[string]any) (int, map[string]any) {
	b.t.Helper()
	base := b.base
	if org, ok := begin["org"].(string); ok {
		base = "/o/" + org
		begin = maps.Clone(begin)
		delete(begin, "org")
	}
	res, out := b.post(base+"/api-internal/login/passkey/begin", begin)
	if res.StatusCode != 200 {
		return res.StatusCode, out
	}
	opts, _ := json.Marshal(out["options"])
	cred, _, err := b.auth.Get(opts)
	if err != nil {
		b.t.Fatal(err)
	}
	res, out2 := b.post(base+"/api-internal/login/passkey/finish", map[string]any{"challenge": out["challenge"], "credential": json.RawMessage(cred)})
	return res.StatusCode, out2
}

// refused is the answer of a step whose ticket, link or confirmation no longer binds to the account.
func refused(t *testing.T, res *http.Response, body map[string]any) {
	t.Helper()
	switch res.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict, http.StatusGone:
	default:
		t.Fatalf("status %d, want a refusal: %v", res.StatusCode, body["_raw"])
	}
}

func (e *env) securityGen(t *testing.T, id string) uint64 {
	t.Helper()
	u, err := e.Svc.Users.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return u.SecurityGen
}

var formField = regexp.MustCompile(`name="(csrf|token)" value="([^"]*)"`)

// verifyLink follows an emailed verification link as a person does: opens it (a page that uses nothing up), then
// presses its button. It returns the answer to the press.
func (b *browser) verifyLink(path string) (*http.Response, string) {
	b.t.Helper()
	res, page := b.get(path)
	if res.StatusCode != http.StatusOK {
		return res, page
	}
	form := url.Values{}
	for _, m := range formField.FindAllStringSubmatch(page, -1) {
		form.Set(m[1], strings.ReplaceAll(m[2], "&amp;", "&"))
	}
	res, err := b.c.PostForm(b.e.URL+b.at("/verify-email"), form)
	if err != nil {
		b.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res, string(body)
}

func (e *env) tenant(t testing.TB, org *model.Org, name string, set model.TenantSettings) *model.Tenant {
	t.Helper()
	tn, err := e.Svc.CreateTenant(context.Background(), service.System, org.ID,
		service.TenantInput{Name: ptr(name), Settings: &set})
	if err != nil {
		t.Fatal(err)
	}
	return tn
}

// accountEnv is a server that audits sign-ins, does not limit them per address and locks an account after the given
// number of failures (0: never), with the organization "acme".
func accountEnv(t *testing.T, attempts int) (*env, *model.Org) {
	e := newEnv(t, noIPLimit, auditLogins, lockoutAfter(attempts))
	return e, e.org(t, "acme", allowAPITokens)
}

// mfaEnv is accountEnv without a lockout, for the organization "acme" that requires a second factor.
func mfaEnv(t *testing.T) (*env, *model.Org) {
	e := newEnv(t, noIPLimit, auditLogins, lockoutAfter(0))
	return e, e.org(t, "acme", func(s *model.OrgSettings) { s.RequireMFA = true })
}

func (e *env) passkeyCount(t *testing.T, u *model.User) int {
	t.Helper()
	l, err := e.Svc.Passkeys.All(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	return len(l)
}

// passkeyEnv is a server with a user "pat" in "acme" who has registered a passkey, and his signed-in browser.
func passkeyEnv(t *testing.T) (*env, *model.User, *browser) {
	e := newEnv(t, noIPLimit, auditLogins)
	org := e.org(t, "acme", nil)
	pat := e.user(t, org, "pat", model.RoleUser)
	signed := e.signedIn(t, pat)
	signed.registerPasskey("Laptop")
	return e, pat, signed
}

// lockEnv is a server that sends mail, locks an account after 3 failures and does not limit sign-ins per address,
// with the organization "acme" using e-mailed codes.
func lockEnv(t *testing.T) (*env, *model.Org) {
	e := newEnv(t, withSMTP, noIPLimit, auditLogins, lockoutAfter(3))
	return e, e.org(t, "acme", func(s *model.OrgSettings) { s.EmailCodes = true })
}

// lockedReasons counts the sign-in failures audited as "locked".
func (e *env) lockedReasons(t *testing.T) int {
	t.Helper()
	n := 0
	for _, a := range e.audits(t, "login.failure") {
		if a.Detail["reason"] == "locked" {
			n++
		}
	}
	return n
}

// deviceCookie returns the known-device cookie the browser holds.
func (b *browser) deviceCookie() *http.Cookie {
	b.t.Helper()
	u, _ := url.Parse(b.e.URL)
	for _, ck := range b.c.Jar.Cookies(u) {
		if ck.Name == "__Host-quisora_dev" {
			return ck
		}
	}
	b.t.Fatal("no device cookie")
	return nil
}

// browserWithDevice is a fresh browser that holds only the given known-device cookie value.
func (e *env) browserWithDevice(t testing.TB, value string) *browser {
	t.Helper()
	b := e.browser(t)
	u, _ := url.Parse(e.URL)
	b.c.Jar.SetCookies(u, []*http.Cookie{{Name: "__Host-quisora_dev", Value: value, Path: "/", Secure: true}})
	return b
}
