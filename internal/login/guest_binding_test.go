package login_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// clientListFails refuses the listings of the clients of one organization while armed: once (left > 0, counting down),
// or every one (always). The guest accounts of that organization's users are found through those clients
// (service.guestsOf), so the tidying that removes their records misses them.
type clientListFails struct {
	store.Store
	org    string
	mu     sync.Mutex
	left   int
	always bool
	failed int
}

func (s *clientListFails) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if kind == model.KindClient && q.Scope == s.org {
		s.mu.Lock()
		fail := s.always || s.left > 0
		if fail {
			s.left--
			s.failed++
		}
		s.mu.Unlock()
		if fail {
			return nil, store.ErrUnavailable
		}
	}
	return s.Store.List(ctx, kind, q)
}

// userReads counts the reads of one user's record.
type userReads struct {
	store.Store
	id string
	mu sync.Mutex
	n  int
}

func (s *userReads) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == model.KindUser && id == s.id {
		s.mu.Lock()
		s.n++
		s.mu.Unlock()
	}
	return s.Store.Get(ctx, kind, id)
}

func (s *userReads) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.n }

// appTenants numbers the tenants signInToApp makes.
var appTenants atomic.Int64

// guestApp is what a guest signed in to an application of acme holds: its access and refresh tokens.
type guestApp struct {
	g       *guestEnv
	b       *browser
	client  *model.Client
	issuer  string // acme's issuer, as a path of the server
	access  string
	refresh string
}

// signInToApp signs the guest browser b in to an application of acme (one asking no second factor, with refresh
// tokens and offline access: a grant that does not end with the browser session), and returns its tokens.
func (g *guestEnv) signInToApp(t *testing.T, b *browser) *guestApp {
	t.Helper()
	ctx := context.Background()
	open := model.DefaultTenantSettings()
	open.RequireMFA = false
	tn, err := g.Svc.CreateTenant(ctx, service.System, g.acme.ID, service.TenantInput{Name: ptr("apps-" + strconv.Itoa(int(appTenants.Add(1)))),
		DisplayName: ptr("Apps"), Settings: &open})
	if err != nil {
		t.Fatal(err)
	}
	g.setSettings(t, g.acme, func(s *model.OrgSettings) { s.RequireMFA = false })
	redirect := "https://app.example/cb"
	c, _, err := g.Svc.CreateClient(ctx, service.System, g.acme.ID, service.ClientInput{Name: ptr("App"),
		AuthMethod: ptr(model.AuthMethodNone), GrantTypes: &[]string{"authorization_code", "refresh_token"},
		RedirectURIs: &[]string{redirect}, Scopes: &[]string{"openid", "offline_access"}, FirstParty: ptr(true), TenantID: &tn.ID})
	if err != nil {
		t.Fatal(err)
	}
	iu, err := url.Parse(g.Cfg.OrgIssuer(g.acme.ID))
	if err != nil {
		t.Fatal(err)
	}
	a := &guestApp{g: g, b: b, client: c, issuer: iu.Path}
	verifier := secure.RandomToken(32)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {c.ID}, "redirect_uri": {redirect}, "scope": {"openid offline_access"},
		"state": {"s"}, "nonce": {"n"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	res, _ := b.getAbs(a.issuer + "/oauth/authorize?" + q.Encode())
	to, err := url.Parse(res.Header.Get("Location"))
	if err != nil || res.StatusCode != 302 || to.Query().Get("code") == "" {
		t.Fatalf("authorize: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	st, tok := a.token(url.Values{"grant_type": {"authorization_code"}, "code": {to.Query().Get("code")},
		"redirect_uri": {redirect}, "code_verifier": {verifier}})
	if st != 200 || tok["access_token"] == "" || tok["refresh_token"] == "" {
		t.Fatalf("code exchange: %d %v", st, tok)
	}
	a.access, a.refresh = tok["access_token"], tok["refresh_token"]
	return a
}

// token posts to acme's token endpoint as the application.
func (a *guestApp) token(form url.Values) (int, map[string]string) {
	a.b.t.Helper()
	form.Set("client_id", a.client.ID)
	res, err := a.b.c.PostForm(a.g.URL+a.issuer+"/oauth/token", form)
	if err != nil {
		a.b.t.Fatal(err)
	}
	defer res.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(res.Body).Decode(&out)
	str := map[string]string{}
	for k, v := range out {
		if s, ok := v.(string); ok {
			str[k] = s
		}
	}
	return res.StatusCode, str
}

// refreshes reports whether the refresh token still refreshes (keeping the rotated one), and the error it got.
func (a *guestApp) refreshes() (bool, string) {
	st, tok := a.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {a.refresh}})
	if st == 200 && tok["refresh_token"] != "" {
		a.refresh = tok["refresh_token"]
	}
	return st == 200, tok["error"]
}

// userinfo is the status of acme's userinfo endpoint for the access token.
func (a *guestApp) userinfo() int {
	a.b.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, a.g.URL+a.issuer+"/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+a.access)
	res, err := a.b.c.Do(req)
	if err != nil {
		a.b.t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

// signedInToAcme reports whether the browser's acme session still signs it in.
func signedInToAcme(b *browser) bool {
	res, body := b.get("/account")
	return res.StatusCode == 200 && strings.Contains(body, "Your account")
}

// heard does what every node does when it hears that user u's record changed (app.App evict): the cached sessions
// standing on it, and the OAuth endpoints' cached copy of it, are dropped. The tests' server is not wired to the
// store's change feed.
func (g *guestEnv) heard(u *model.User) {
	g.Server.Sessions.Evict("", u.ID)
	g.op.InvalidateUser(u.ID)
}

// The finding: disabling a source user succeeds even when their guest accounts could not be found (one listing of the
// source organization's clients failed), and nothing retries the tidying. The guest's session, refresh grant (offline
// access) and access token must end anyway: they stand on the source account, and every check of their use reads it.
func TestGuestSignInEndsWithItsSourceWhenTheGuestIsMissed(t *testing.T) {
	g := newGuestEnv(t, func(in *service.ProviderInput) { in.LinkByEmail = ptr(true) })
	ctx := context.Background()
	pat := g.person(t, g.Primary, "pat", "pat@example.com")
	patGuest := g.person(t, g.acme, "pat-guest", "pat@example.com")
	b, _ := g.continueAs(t, pat)
	app := g.signInToApp(t, b)
	if !signedInToAcme(b) {
		t.Fatal("the guest is not signed in")
	}
	if ok, e := app.refreshes(); !ok || app.userinfo() != 200 {
		t.Fatalf("the guest's application before: refresh %v %q, userinfo %d", ok, e, app.userinfo())
	}

	good := g.Svc.Clients.S
	fails := &clientListFails{Store: good, org: g.Primary.ID, left: 1}
	g.Svc.Clients.S = fails
	if _, err := g.Svc.UpdateUser(ctx, service.System, pat.ID, service.UserInput{Active: ptr(false)}); err != nil {
		t.Fatalf("disabling the source user: %v", err)
	}
	g.Svc.Clients.S = good
	if fails.failed != 1 {
		t.Fatalf("the listing failed %d times, want once", fails.failed)
	}
	g.Svc.WaitBackground()
	g.heard(pat)
	if len(sessionsOf(t, g.env, patGuest)) != 1 {
		t.Fatal("the tidying reached the guest: the test does not exercise a missed guest")
	}

	if signedInToAcme(b) {
		t.Fatal("the guest's session still signs in after its source user was disabled")
	}
	if ok, e := app.refreshes(); ok || e != "invalid_grant" {
		t.Fatalf("the guest's refresh token after its source user was disabled: %v %q", ok, e)
	}
	if st := app.userinfo(); st != http.StatusUnauthorized {
		t.Fatalf("the guest's access token after its source user was disabled: %d", st)
	}
}

// A guest of a guest stands on the whole chain: pat of the primary organization signs in to acme as a guest, and from
// there to beta as acme's guest's guest. When pat is disabled and neither guest is found, beta's session ends too,
// though the account it is beta's guest of, in acme, is untouched.
func TestGuestOfAGuestStandsOnTheChain(t *testing.T) {
	g := newGuestEnv(t, func(in *service.ProviderInput) { in.LinkByEmail = ptr(true) })
	ctx := context.Background()
	pat := g.person(t, g.Primary, "pat", "pat@example.com")
	g.person(t, g.acme, "pat-guest", "pat@example.com")
	b, _ := g.continueAs(t, pat)
	// acme's default tenant, which holds the sign-in client of beta's provider, asks no second factor
	def, err := g.Svc.DefaultTenant(ctx, g.acme.ID)
	if err != nil {
		t.Fatal(err)
	}
	open := def.Settings
	open.RequireMFA = false
	if _, err := g.Svc.UpdateTenant(ctx, service.System, def.ID, service.TenantInput{Settings: &open}); err != nil {
		t.Fatal(err)
	}
	beta := g.org(t, "beta", nil)
	pb, err := g.Svc.CreateProvider(ctx, service.System, beta.ID, service.ProviderInput{Type: ptr(model.ProviderOrganization),
		SourceOrg: &g.acme.ID, LinkByEmail: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	betaGuest := g.person(t, beta, "pat-guest-2", "pat@example.com")
	if _, done := g.continueAsVia(t, b, beta, pb); done != web.OrgPath(beta.ID, "/account") {
		t.Fatalf("signing in to beta from acme: %q", done)
	}
	s := sessionsOf(t, g.env, betaGuest)
	if len(s) != 1 || len(s[0].Sources) != 2 || s[0].Sources[1].UserID != pat.ID {
		t.Fatalf("beta's session: %+v", s)
	}
	inBeta := func() bool {
		b.base = web.OrgPath(beta.ID, "")
		return signedInToAcme(b) // (the account page of the browser's organization)
	}
	if !inBeta() {
		t.Fatal("not signed in to beta")
	}

	good := g.Svc.Clients.S
	g.Svc.Clients.S = &clientListFails{Store: good, org: g.Primary.ID, always: true}
	_, err = g.Svc.UpdateUser(ctx, service.System, pat.ID, service.UserInput{Active: ptr(false)})
	g.Svc.WaitBackground()
	g.Svc.Clients.S = good
	if err != nil {
		t.Fatal(err)
	}
	g.heard(pat)
	if inBeta() {
		t.Fatal("beta's session still signs in after the person it came from was disabled")
	}
}

// Whatever ends the source user's sessions ends their guest's sign-in, with no help from the tidying (every listing of
// the source organization's clients fails meanwhile): locked out, signed out everywhere, their other sessions signed
// out, a credential reset, deleted. Another source user's guest goes on.
func TestGuestSignInStandsOnItsSource(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(g *guestEnv, id string) error
	}{
		{"locked out", func(g *guestEnv, id string) error {
			_, err := g.Svc.LockOutUser(context.Background(), service.System, id, "compromised")
			return err
		}},
		{"signed out everywhere", func(g *guestEnv, id string) error {
			return g.Svc.RevokeSessions(context.Background(), service.System, id)
		}},
		{"other sessions signed out", func(g *guestEnv, id string) error {
			_, err := g.Svc.RevokeOtherSessions(context.Background(), id, "")
			return err
		}},
		{"credentials reset", func(g *guestEnv, id string) error {
			return g.Svc.ResetCredentials(context.Background(), id)
		}},
		{"deleted", func(g *guestEnv, id string) error {
			return g.Svc.DeleteUser(context.Background(), service.System, id)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newGuestEnv(t, func(in *service.ProviderInput) { in.LinkByEmail = ptr(true) })
			pat := g.person(t, g.Primary, "pat", "pat@example.com")
			g.person(t, g.acme, "pat-guest", "pat@example.com")
			sam := g.person(t, g.Primary, "sam", "sam@example.com")
			g.person(t, g.acme, "sam-guest", "sam@example.com")
			pb, _ := g.continueAs(t, pat)
			sb, _ := g.continueAs(t, sam)
			patApp, samApp := g.signInToApp(t, pb), g.signInToApp(t, sb)
			if !signedInToAcme(pb) || !signedInToAcme(sb) {
				t.Fatal("the guests are not signed in")
			}

			good := g.Svc.Clients.S
			g.Svc.Clients.S = &clientListFails{Store: good, org: g.Primary.ID, always: true}
			err := tc.end(g, pat.ID)
			g.Svc.WaitBackground()
			g.Svc.Clients.S = good
			if err != nil {
				t.Fatal(err)
			}
			g.heard(pat)

			if signedInToAcme(pb) {
				t.Fatal("pat's guest session still signs in")
			}
			if ok, e := patApp.refreshes(); ok || e != "invalid_grant" {
				t.Fatalf("pat's guest's refresh token: %v %q", ok, e)
			}
			if st := patApp.userinfo(); st != http.StatusUnauthorized {
				t.Fatalf("pat's guest's access token: %d", st)
			}
			if !signedInToAcme(sb) {
				t.Fatal("sam's guest session ended too")
			}
			if ok, e := samApp.refreshes(); !ok || samApp.userinfo() != 200 {
				t.Fatalf("sam's guest's application: refresh %v %q", ok, e)
			}
		})
	}
}

// A guest's session check costs no more reads than another session's while it is cached: the source user is read with
// the session, kept with it, and read again only once the cache drops it (its time is up, or the source user changed:
// heard). The OAuth endpoints read it through their user cache too.
func TestGuestSessionCheckReadsItsSourceOnce(t *testing.T) {
	g := newGuestEnv(t, func(in *service.ProviderInput) { in.LinkByEmail = ptr(true) })
	pat := g.person(t, g.Primary, "pat", "pat@example.com")
	g.person(t, g.acme, "pat-guest", "pat@example.com")
	b, _ := g.continueAs(t, pat)
	app := g.signInToApp(t, b)

	reads := &userReads{Store: g.Svc.Users.S, id: pat.ID}
	g.Svc.Users.S = reads
	g.heard(pat) // nothing cached: the next check reads the source user
	for i := range 5 {
		if !signedInToAcme(b) {
			t.Fatalf("request %d: the guest is not signed in", i)
		}
	}
	if n := reads.count(); n != 1 {
		t.Fatalf("the source user was read %d times for 5 requests, want once", n)
	}
	g.heard(pat)
	if !signedInToAcme(b) || reads.count() != 2 {
		t.Fatalf("after the source user changed: read %d times, want once more", reads.count()-1)
	}

	if app.userinfo() != 200 {
		t.Fatal("userinfo")
	}
	before := reads.count()
	for range 3 {
		if app.userinfo() != 200 {
			t.Fatal("userinfo")
		}
	}
	if n := reads.count() - before; n != 0 {
		t.Fatalf("the OAuth endpoints read the source user %d times for 3 cached checks", n)
	}
}
