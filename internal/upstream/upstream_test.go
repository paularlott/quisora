package upstream_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/store/memstore"
	"github.com/paularlott/quisora/internal/upstream"
	ut "github.com/paularlott/quisora/internal/upstream/upstreamtest"
)

var b64 = base64.RawURLEncoding

type env struct {
	ctx  context.Context
	svc  *service.Service
	up   *upstream.Service
	org  *model.Org
	oidc *ut.FakeOIDC
	gh   *ut.FakeGitHub
	now  time.Time
	mu   sync.Mutex
}

func setup(t *testing.T) *env { return setupOn(t, memstore.New()) }

func setupOn(t *testing.T, st store.Store) *env {
	t.Helper()
	ctx := context.Background()
	cfg := config.Default()
	cfg.Server.PublicURL = "https://quisora.example.test"
	cfg.Limits.PasswordWorkers = 2
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svc := service.New(cfg, st, sealer)
	if _, _, err := svc.Bootstrap(ctx, "admin@example.com"); err != nil {
		t.Fatal(err)
	}
	org, err := svc.CreateOrg(ctx, service.System, service.OrgInput{Name: ptr("acme")})
	if err != nil {
		t.Fatal(err)
	}
	eph := ephemeral.NewLocal("n1")
	t.Cleanup(eph.Close)
	e := &env{ctx: ctx, svc: svc, org: org, oidc: ut.NewFakeOIDC(t), gh: ut.NewFakeGitHub(t), now: time.Now()}
	e.up = upstream.New(svc, eph, cfg.Server.PublicURL, &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }})
	e.up.HTTP = ut.HTTPClient()
	e.up.GitHubAuthURL, e.up.GitHubTokenURL, e.up.GitHubAPIURL = e.gh.Srv.URL+"/authorize", e.gh.Srv.URL+"/token", e.gh.Srv.URL
	e.up.Now = func() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.now }
	return e
}

func (e *env) advance(d time.Duration) { e.mu.Lock(); e.now = e.now.Add(d); e.mu.Unlock() }

func ptr[T any](v T) *T { return &v }

func (e *env) oidcProvider(t *testing.T, mut func(*service.ProviderInput)) *model.Provider {
	t.Helper()
	in := service.ProviderInput{Type: ptr(model.ProviderOIDC), Name: ptr("Corp SSO"), Issuer: ptr(e.oidc.Srv.URL),
		ClientID: ptr("cid"), ClientSecret: ptr("s3cret"), AutoProvision: ptr(true)}
	if mut != nil {
		mut(&in)
	}
	p, err := e.svc.CreateProvider(e.ctx, service.System, e.org.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (e *env) githubProvider(t *testing.T, mut func(*service.ProviderInput)) *model.Provider {
	t.Helper()
	in := service.ProviderInput{Type: ptr(model.ProviderGitHub), Name: ptr("GitHub"), ClientID: ptr("gh-cid"),
		ClientSecret: ptr("gh-secret"), AutoProvision: ptr(true)}
	if mut != nil {
		mut(&in)
	}
	p, err := e.svc.CreateProvider(e.ctx, service.System, e.org.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// signIn runs Begin, the fake provider and Finish.
func (e *env) signIn(p *model.Provider, claims map[string]any) (*upstream.Result, error) {
	authURL, state, err := e.up.BeginTenant(e.ctx, e.org, p, "/next", "")
	if err != nil {
		return nil, err
	}
	var code string
	if p.Type == model.ProviderGitHub {
		code = e.gh.Authorize(authURL)
	} else {
		code = e.oidc.Authorize(authURL, claims)
	}
	return e.up.Finish(e.ctx, e.org.ID, p.ID, state, state, code)
}

func std(sub, email string) map[string]any {
	return map[string]any{"sub": sub, "email": email, "email_verified": true, "name": "Pat Doe", "given_name": "Pat",
		"family_name": "Doe"}
}

func TestOIDCAutoProvisionAndRelink(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)

	res, err := e.signIn(p, std("sub-1", "Pat@Example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Provisioned || res.Next != "/next" || res.User.OrgID != e.org.ID || !res.User.EmailVerified ||
		res.User.Email != "Pat@Example.com" || res.User.Role != model.RoleUser || res.User.FullName() != "Pat Doe" ||
		res.User.PasswordHash != "" {
		t.Fatalf("provisioned user %+v", res.User)
	}
	id, err := e.svc.Identities.GetByUnique(e.ctx, model.IdentityKey(p.ID, "sub-1"))
	if err != nil || id.UserID != res.User.ID {
		t.Fatalf("identity not linked: %v %+v", err, id)
	}

	// Same subject again: the linked user, even though the provider now reports another email.
	res2, err := e.signIn(p, std("sub-1", "other@example.com"))
	if err != nil || res2.Provisioned || res2.User.ID != res.User.ID {
		t.Fatalf("relink: %v %+v", err, res2)
	}
	if n, _ := e.svc.Users.Count(e.ctx, e.org.ID); n != 1 {
		t.Fatalf("users %d", n)
	}
}

func TestProvisionRules(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, func(in *service.ProviderInput) { in.AllowedDomains = &[]string{"Corp.Example", "@partner.example"} })

	unverified := std("u1", "a@corp.example")
	unverified["email_verified"] = false
	if _, err := e.signIn(p, unverified); !errors.Is(err, upstream.ErrUnverifiedEmail) {
		t.Fatalf("unverified: %v", err)
	}
	asString := std("u1", "a@corp.example")
	asString["email_verified"] = "false"
	if _, err := e.signIn(p, asString); !errors.Is(err, upstream.ErrUnverifiedEmail) {
		t.Fatalf("string false: %v", err)
	}
	noEmail := std("u1", "")
	delete(noEmail, "email")
	if _, err := e.signIn(p, noEmail); !errors.Is(err, upstream.ErrUnverifiedEmail) {
		t.Fatalf("no email: %v", err)
	}
	if _, err := e.signIn(p, std("u2", "a@evil.example")); !errors.Is(err, upstream.ErrDomain) {
		t.Fatalf("domain: %v", err)
	}
	if _, err := e.signIn(p, std("u2", "a@corp.example.evil.example")); !errors.Is(err, upstream.ErrDomain) {
		t.Fatalf("suffix domain: %v", err)
	}
	if _, err := e.signIn(p, std("u3", "a@CORP.example")); err != nil {
		t.Fatalf("allowed domain: %v", err)
	}
	if _, err := e.signIn(p, std("u4", "b@partner.example")); err != nil {
		t.Fatalf("second allowed domain: %v", err)
	}
	// string "true" is accepted (some providers send it that way)
	s := std("u5", "c@corp.example")
	s["email_verified"] = "true"
	if _, err := e.signIn(p, s); err != nil {
		t.Fatalf("string true: %v", err)
	}
}

func TestDisabledStates(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)
	res, err := e.signIn(p, std("d1", "d1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	res.User.Active = false
	if err := e.svc.Users.Update(e.ctx, res.User); err != nil {
		t.Fatal(err)
	}
	if _, err := e.signIn(p, std("d1", "d1@example.com")); !errors.Is(err, upstream.ErrDisabled) {
		t.Fatalf("inactive user: %v", err)
	}
}

func TestOrphanedIdentityIsReplaced(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)
	res, _ := e.signIn(p, std("o1", "o1@example.com"))
	if err := e.svc.Users.Delete(e.ctx, res.User.ID); err != nil {
		t.Fatal(err)
	}
	res2, err := e.signIn(p, std("o1", "o1@example.com"))
	if err != nil || !res2.Provisioned || res2.User.ID == res.User.ID {
		t.Fatalf("orphan: %v %+v", err, res2)
	}
}

// ID tokens that fail any check, or are signed with an algorithm or key that does not fit, never sign anybody in.
func TestIDTokenValidation(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)
	cases := map[string]map[string]any{
		"wrong nonce":              {"nonce": "other"},
		"missing nonce":            {"nonce": nil},
		"wrong audience":           {"aud": "someone-else"},
		"audience list without us": {"aud": []string{"a", "b"}},
		"wrong issuer":             {"iss": "https://evil.example"},
		"expired":                  {"exp": time.Now().Add(-time.Hour).Unix()},
		"no exp":                   {"exp": nil},
		"future iat":               {"iat": time.Now().Add(time.Hour).Unix()},
		"not valid yet (nbf)":      {"nbf": time.Now().Add(10 * time.Minute).Unix()},
		"no subject":               {"sub": ""},
		"alg none":                 {"_alg": "none"},
		"alg HS256":                {"_alg": "HS256"},
		"foreign key":              {"_alg": "RS256-other"},
		"unknown kid":              {"_kid": "nope"},
		"azp mismatch":             {"aud": []string{"cid", "other"}, "azp": "other"},
		"alg RS512":                {"_alg": "RS512"},
		"alg RS384":                {"_alg": "RS384"},
		"alg PS256":                {"_alg": "PS256"},
		"alg ES384":                {"_alg": "ES384"},
		"alg PS512":                {"_alg": "PS512"},
		"alg EdDSA":                {"_alg": "EdDSA"},
		"alg RS1":                  {"_alg": "RS1"},
		"EC key used for RS256":    {"_kid": "k1-ec"},
		"RSA key used for ES256":   {"_alg": "ES256", "_kid": "k1"},
	}
	for name, over := range cases {
		c := std("v1", "v@example.com")
		for k, v := range over {
			c[k] = v
		}
		if name == "no subject" {
			delete(c, "sub")
		}
		if _, err := e.signIn(p, c); !errors.Is(err, upstream.ErrUpstream) {
			t.Errorf("%s: want ErrUpstream, got %v", name, err)
		}
	}
	// Multiple audiences are fine when azp is us.
	c := std("v2", "v2@example.com")
	c["aud"], c["azp"] = []string{"cid", "other"}, "cid"
	if _, err := e.signIn(p, c); err != nil {
		t.Fatalf("aud list with azp: %v", err)
	}
	if n, _ := e.svc.Users.Count(e.ctx, e.org.ID); n != 1 {
		t.Fatalf("a rejected token provisioned a user: %d", n)
	}
	// An ES256 token signed with the EC key is accepted.
	c = std("es-1", "es@example.com")
	c["_alg"] = "ES256"
	if _, err := e.signIn(p, c); err != nil {
		t.Fatalf("ES256 id token rejected: %v", err)
	}
}

func TestJWKSRotation(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)
	if _, err := e.signIn(p, std("r1", "r1@example.com")); err != nil {
		t.Fatal(err)
	}
	fetches := e.oidc.JWKSFetches
	if _, err := e.signIn(p, std("r1", "r1@example.com")); err != nil || e.oidc.JWKSFetches != fetches {
		t.Fatalf("keys not cached: %v fetches %d -> %d", err, fetches, e.oidc.JWKSFetches)
	}

	// Provider rotates to a new key id: an unknown kid refetches, at most once every 5 seconds.
	e.oidc.Mu.Lock()
	e.oidc.RSAKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	e.oidc.KID = "k2"
	e.oidc.Mu.Unlock()
	if _, err := e.signIn(p, std("r1", "r1@example.com")); !errors.Is(err, upstream.ErrUpstream) {
		t.Fatalf("rotation inside the refetch window should fail: %v", err)
	}
	e.advance(5 * time.Second) // seconds, not a minute: a provider's rotation stalls its sign-ins that long at most
	if _, err := e.signIn(p, std("r1", "r1@example.com")); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
}

func TestUserinfoFallbackAndBasicAuth(t *testing.T) {
	e := setup(t)
	e.oidc.BasicOnly = true
	e.oidc.UserInfo = map[string]any{"sub": "ui-1", "email": "ui@example.com", "email_verified": true, "name": "From Userinfo"}
	p := e.oidcProvider(t, nil)
	c := std("ui-1", "")
	c["email"], c["email_verified"], c["name"], c["given_name"], c["family_name"] = nil, nil, nil, nil, nil
	res, err := e.signIn(p, c)
	if err != nil {
		t.Fatal(err)
	}
	if !e.oidc.GotBasic {
		t.Fatal("client_secret_basic not used although it is the only advertised method")
	}
	if res.User.Email != "ui@example.com" || res.User.FullName() != "From Userinfo" {
		t.Fatalf("userinfo not used: %+v", res.User)
	}
	// Userinfo for a different subject is ignored.
	e.oidc.UserInfo["sub"] = "someone-else"
	c2 := std("ui-2", "")
	c2["email"], c2["email_verified"] = nil, nil
	if _, err := e.signIn(p, c2); !errors.Is(err, upstream.ErrUnverifiedEmail) {
		t.Fatalf("foreign userinfo accepted: %v", err)
	}
}

func TestDiscoveryChecks(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)
	e.oidc.IssuerOver = "https://evil.example"
	if _, _, err := e.up.BeginTenant(e.ctx, e.org, p, "", ""); !errors.Is(err, upstream.ErrUpstream) {
		t.Fatalf("issuer mismatch accepted: %v", err)
	}
}

// A provider whose discovery hangs or fails costs one outbound request per retry interval, not one per sign-in:
// concurrent sign-ins share one fetch, callers that give up return at once, and a failure is remembered.
func TestDiscoveryFailureIsShared(t *testing.T) {
	e := setup(t)
	var hits atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release
		http.Error(w, "down", http.StatusBadGateway)
	}))
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() { unblock(); srv.Close() })
	p := e.oidcProvider(t, func(in *service.ProviderInput) { in.Issuer = ptr(srv.URL) })

	var wg sync.WaitGroup
	start := time.Now()
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(e.ctx, 100*time.Millisecond)
			defer cancel()
			if _, _, err := e.up.BeginTenant(ctx, e.org, p, "", ""); !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("abandoned sign-in: %v", err)
			}
		}()
	}
	wg.Wait()
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("abandoned sign-ins waited for the upstream: %v", d)
	}
	// The one shared fetch outlives the abandoned sign-ins; on a loaded machine it may reach the server only after
	// they gave up, so wait for it rather than look at once.
	for deadline := time.Now().Add(2 * time.Second); hits.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("concurrent sign-ins fetched discovery %d times", n)
	}

	unblock()
	for range 3 {
		if _, _, err := e.up.BeginTenant(e.ctx, e.org, p, "", ""); err == nil {
			t.Fatal("failed discovery accepted")
		}
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("a failed discovery was fetched again within the retry interval: %d", n)
	}
	e.advance(31 * time.Second)
	if _, _, err := e.up.BeginTenant(e.ctx, e.org, p, "", ""); err == nil {
		t.Fatal("failed discovery accepted")
	}
	if n := hits.Load(); n != 2 {
		t.Fatalf("discovery not retried after the interval: %d", n)
	}
}

// An issuer that ends with a slash (Auth0's does) matches its stored form.
func TestIssuerTrailingSlash(t *testing.T) {
	e := setup(t)
	e.oidc.IssuerOver = e.oidc.Srv.URL + "/"
	p := e.oidcProvider(t, nil)
	if _, err := e.signIn(p, map[string]any{"iss": e.oidc.Srv.URL + "/", "sub": "s9", "email": "s9@example.com", "email_verified": true}); err != nil {
		t.Fatal(err)
	}
}

func TestWrongClientSecretFailsWithoutLeakingIt(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, func(in *service.ProviderInput) { in.ClientSecret = ptr("wrong") })
	res, err := e.signIn(p, std("s", "s@example.com"))
	if !errors.Is(err, upstream.ErrUpstream) || res == nil || res.Provider == nil {
		t.Fatalf("wrong client secret: %+v %v", res, err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Fatalf("secret leaked into the error: %v", err)
	}
}

func TestNewDefaultsAndCallbackURL(t *testing.T) {
	client := &http.Client{}
	s := upstream.New(nil, nil, "https://idp.example/", client)
	if s.PublicURL != "https://idp.example" || s.Now == nil || s.HTTP != client || s.GitHubAPIURL == "" || s.MicrosoftAuthority == "" {
		t.Fatalf("%+v", s)
	}
	// Each provider's callback is in its organization's address space: two organizations never share one.
	if got := s.CallbackURL("o1", "p"); got != "https://idp.example/o/o1/login/callback/p" {
		t.Fatal(got)
	}
	if got := s.CallbackURL("o1", "p 1"); got != "https://idp.example/o/o1/login/callback/p%201" {
		t.Fatalf("callback url %q", got)
	}
	if s.CallbackURL("o1", "p") == s.CallbackURL("o2", "p") {
		t.Fatal("two organizations share a callback url")
	}
	if upstream.CallbackPath("o1", "abc") != "/o/o1/login/callback/abc" {
		t.Fatal("callback path")
	}
}
