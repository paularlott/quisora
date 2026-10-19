package upstream_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	"github.com/paularlott/quisora/internal/store/memstore"
	"github.com/paularlott/quisora/internal/upstream"
	ut "github.com/paularlott/quisora/internal/upstream/upstreamtest"
)

var b64 = base64.RawURLEncoding

// ---------------------------------------------------------------------------------------------------------------
// Environment

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

func setup(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	cfg := config.Default()
	cfg.Server.PublicURL = "https://quisora.example.test"
	cfg.Limits.PasswordWorkers = 2
	sealer, _ := secure.NewSealer(secure.RandomBytes(32))
	svc := service.New(cfg, memstore.New(), sealer)
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
	e.up = upstream.New(svc, eph, cfg.Server.PublicURL)
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
	authURL, state, err := e.up.Begin(e.ctx, e.org, p, "/next")
	if err != nil {
		return nil, err
	}
	var code string
	if p.Type == model.ProviderGitHub {
		code = e.gh.Authorize(authURL)
	} else {
		code = e.oidc.Authorize(authURL, claims)
	}
	return e.up.Finish(e.ctx, p.ID, state, state, code)
}

func std(sub, email string) map[string]any {
	return map[string]any{"sub": sub, "email": email, "email_verified": true, "name": "Pat Doe", "given_name": "Pat",
		"family_name": "Doe"}
}

// ---------------------------------------------------------------------------------------------------------------
// Tests

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

func TestOIDCES256(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)
	c := std("es-1", "es@example.com")
	c["_alg"] = "ES256"
	if _, err := e.signIn(p, c); err != nil {
		t.Fatalf("ES256 id token rejected: %v", err)
	}
}

// An address that is not VERIFIED on our side never links (see email_link_test.go for the verified cases).
func TestNeverLinksByEmail(t *testing.T) {
	e := setup(t)
	victim, err := e.svc.CreateUser(e.ctx, service.System, e.org.ID, service.UserInput{GivenName: gn("T"),
		Username: ptr("victim"), Email: ptr("victim@example.com"), Password: ptr("a-long-password-1")})
	if err != nil {
		t.Fatal(err)
	}

	// Auto-provision on: an upstream account claiming the same (verified) email is refused, not linked.
	p := e.oidcProvider(t, nil)
	if _, err := e.signIn(p, std("attacker", "victim@example.com")); !errors.Is(err, upstream.ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}
	if _, err := e.svc.Identities.GetByUnique(e.ctx, model.IdentityKey(p.ID, "attacker")); err == nil {
		t.Fatal("identity created for an email clash")
	}

	// Auto-provision off: no link, no sign-in.
	p2 := e.oidcProvider(t, func(in *service.ProviderInput) { in.Name = ptr("Closed"); in.AutoProvision = ptr(false) })
	if _, err := e.signIn(p2, std("attacker", "victim@example.com")); !errors.Is(err, upstream.ErrNotLinked) {
		t.Fatalf("want ErrNotLinked, got %v", err)
	}
	// ...unless an identity was linked deliberately.
	if err := e.svc.Identities.Create(e.ctx, model.NewIdentity(victim, p2, "legit", "", "admin")); err != nil {
		t.Fatal(err)
	}
	res, err := e.signIn(p2, std("legit", "anything@else.example"))
	if err != nil || res.User.ID != victim.ID {
		t.Fatalf("linked identity sign-in: %v %+v", err, res)
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
	off := false
	p, err = e.svc.UpdateProvider(e.ctx, service.System, p.ID, service.ProviderInput{Enabled: &off})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.up.Begin(e.ctx, e.org, p, ""); !errors.Is(err, upstream.ErrDisabled) {
		t.Fatalf("disabled provider Begin: %v", err)
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
		"no subject":               {"sub": ""},
		"alg none":                 {"_alg": "none"},
		"alg HS256":                {"_alg": "HS256"},
		"foreign key":              {"_alg": "RS256-other"},
		"unknown kid":              {"_kid": "nope"},
		"azp mismatch":             {"aud": []string{"cid", "other"}, "azp": "other"},
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
}

func TestStateHandling(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)

	authURL, state, err := e.up.Begin(e.ctx, e.org, p, "/n")
	if err != nil {
		t.Fatal(err)
	}
	code := e.oidc.Authorize(authURL, std("s1", "s1@example.com"))
	// Cookie that does not match the state: login CSRF.
	if _, err := e.up.Finish(e.ctx, p.ID, state, "other", code); !errors.Is(err, upstream.ErrState) {
		t.Fatalf("cookie mismatch: %v", err)
	}
	// ...and the state is burnt, so the right cookie cannot rescue it.
	if _, err := e.up.Finish(e.ctx, p.ID, state, state, code); !errors.Is(err, upstream.ErrState) {
		t.Fatalf("burnt state: %v", err)
	}

	authURL, state, _ = e.up.Begin(e.ctx, e.org, p, "/n")
	code = e.oidc.Authorize(authURL, std("s1", "s1@example.com"))
	if _, err := e.up.Finish(e.ctx, p.ID, state, state, code); err != nil {
		t.Fatal(err)
	}
	if _, err := e.up.Finish(e.ctx, p.ID, state, state, code); !errors.Is(err, upstream.ErrState) {
		t.Fatalf("replay: %v", err)
	}
	if _, err := e.up.Finish(e.ctx, p.ID, "n1.unknown", "n1.unknown", "x"); !errors.Is(err, upstream.ErrState) {
		t.Fatalf("unknown state: %v", err)
	}
	if _, err := e.up.Finish(e.ctx, p.ID, "", "", ""); !errors.Is(err, upstream.ErrState) {
		t.Fatalf("empty state: %v", err)
	}
	// A response arriving at another provider's callback address is refused (IdP mix-up), and the state is burnt.
	other := e.oidcProvider(t, func(in *service.ProviderInput) { in.Name = ptr("Other SSO") })
	authURL, state, _ = e.up.Begin(e.ctx, e.org, p, "/n")
	code = e.oidc.Authorize(authURL, std("s1", "s1@example.com"))
	if _, err := e.up.Finish(e.ctx, other.ID, state, state, code); !errors.Is(err, upstream.ErrState) {
		t.Fatalf("other provider's callback: %v", err)
	}
	if _, err := e.up.Finish(e.ctx, p.ID, state, state, code); !errors.Is(err, upstream.ErrState) {
		t.Fatalf("state reused after a mix-up: %v", err)
	}
}

func TestPKCEIsEnforcedByProvider(t *testing.T) {
	e := setup(t)
	p := e.oidcProvider(t, nil)
	authURL, state, _ := e.up.Begin(e.ctx, e.org, p, "")
	u, _ := url.Parse(authURL)
	if u.Query().Get("redirect_uri") != "https://quisora.example.test/login/callback/"+p.ID || u.Query().Get("state") != state {
		t.Fatalf("authorization url %s", authURL)
	}
	// The fake provider checks the verifier against the challenge; a normal sign-in passing proves the verifier is sent.
	if _, err := e.signIn(p, std("p1", "p1@example.com")); err != nil {
		t.Fatal(err)
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

	// Provider rotates to a new key id: an unknown kid refetches, but only once a minute.
	e.oidc.Mu.Lock()
	e.oidc.RSAKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	e.oidc.KID = "k2"
	e.oidc.Mu.Unlock()
	if _, err := e.signIn(p, std("r1", "r1@example.com")); !errors.Is(err, upstream.ErrUpstream) {
		t.Fatalf("rotation inside the refetch window should fail: %v", err)
	}
	e.advance(2 * time.Minute)
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
	if _, _, err := e.up.Begin(e.ctx, e.org, p, ""); !errors.Is(err, upstream.ErrUpstream) {
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
			if _, _, err := e.up.Begin(ctx, e.org, p, ""); !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("abandoned sign-in: %v", err)
			}
		}()
	}
	wg.Wait()
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("abandoned sign-ins waited for the upstream: %v", d)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("concurrent sign-ins fetched discovery %d times", n)
	}

	unblock()
	for range 3 {
		if _, _, err := e.up.Begin(e.ctx, e.org, p, ""); err == nil {
			t.Fatal("failed discovery accepted")
		}
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("a failed discovery was fetched again within the retry interval: %d", n)
	}
	e.advance(31 * time.Second)
	if _, _, err := e.up.Begin(e.ctx, e.org, p, ""); err == nil {
		t.Fatal("failed discovery accepted")
	}
	if n := hits.Load(); n != 2 {
		t.Fatalf("discovery not retried after the interval: %d", n)
	}
}

func TestGitHub(t *testing.T) {
	e := setup(t)
	p := e.githubProvider(t, nil)
	authURL, _, err := e.up.Begin(e.ctx, e.org, p, "/gh")
	if err != nil || !strings.HasPrefix(authURL, e.gh.Srv.URL+"/authorize?") {
		t.Fatalf("auth url %q %v", authURL, err)
	}
	if !strings.Contains(authURL, "scope=read%3Auser+user%3Aemail") || strings.Contains(authURL, "nonce") {
		t.Fatalf("github scopes/params: %s", authURL)
	}
	res, err := e.signIn(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Provisioned || res.User.Email != "octo@example.com" || res.User.FullName() != "The Octocat" || !res.User.EmailVerified {
		t.Fatalf("github user %+v", res.User)
	}
	if _, err := e.svc.Identities.GetByUnique(e.ctx, model.IdentityKey(p.ID, "583231")); err != nil {
		t.Fatalf("identity by numeric id: %v", err)
	}
	// A renamed account (new login, new primary email) is still the same user: subject is the numeric id.
	e.gh.Login = "renamed"
	e.gh.Emails = []map[string]any{{"email": "new@example.com", "primary": true, "verified": true}}
	res2, err := e.signIn(p, nil)
	if err != nil || res2.Provisioned || res2.User.ID != res.User.ID {
		t.Fatalf("renamed account: %v %+v", err, res2)
	}
}

func TestGitHubEmailRules(t *testing.T) {
	e := setup(t)
	p := e.githubProvider(t, func(in *service.ProviderInput) { in.AllowedDomains = &[]string{"example.com"} })
	for name, emails := range map[string][]map[string]any{
		"primary unverified":       {{"email": "a@example.com", "primary": true, "verified": false}},
		"verified but not primary": {{"email": "a@example.com", "primary": false, "verified": true}},
		"none":                     {},
		"verified secondary + unverified primary": {{"email": "x@example.com", "primary": true, "verified": false},
			{"email": "y@example.com", "primary": false, "verified": true}},
	} {
		e.gh.Emails = emails
		if _, err := e.signIn(p, nil); !errors.Is(err, upstream.ErrUnverifiedEmail) {
			t.Errorf("%s: want ErrUnverifiedEmail, got %v", name, err)
		}
	}
	e.gh.Emails = []map[string]any{{"email": "a@other.org", "primary": true, "verified": true}}
	if _, err := e.signIn(p, nil); !errors.Is(err, upstream.ErrDomain) {
		t.Fatalf("domain: %v", err)
	}
}

func TestGitHubTokenFailure(t *testing.T) {
	e := setup(t)
	p := e.githubProvider(t, nil)
	authURL, state, _ := e.up.Begin(e.ctx, e.org, p, "")
	_ = e.gh.Authorize(authURL)
	if _, err := e.up.Finish(e.ctx, p.ID, state, state, "wrong-code"); !errors.Is(err, upstream.ErrUpstream) {
		t.Fatalf("want ErrUpstream, got %v", err)
	}
	_ = fmt.Sprint()
}

// Microsoft: each tenant issues its own tokens; only the allowed tenants sign in; the user is tenant:object ID; the
// email address is verified only when Microsoft vouches for its domain (xms_edov).
func TestMicrosoftProvider(t *testing.T) {
	e := setup(t)
	e.up.MicrosoftAuthority = e.oidc.Srv.URL
	tidA, tidB := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	p, err := e.svc.CreateProvider(e.ctx, service.System, e.org.ID, service.ProviderInput{Type: ptr(model.ProviderMicrosoft),
		Tenant: ptr("organizations"), AllowedTenants: &[]string{tidA}, ClientID: ptr("cid"), ClientSecret: ptr("s3cret"),
		AutoProvision: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	ms := func(tid, issTid, oid string, extra map[string]any) map[string]any {
		c := map[string]any{"iss": e.oidc.Srv.URL + "/" + issTid + "/v2.0", "tid": tid, "oid": oid, "sub": "pairwise-" + oid,
			"email": oid + "@contoso.example", "name": "Ms User"}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
	// the authorization request goes to the "organizations" directory
	authURL, _, err := e.up.Begin(e.ctx, e.org, p, "")
	if err != nil || !strings.HasPrefix(authURL, e.oidc.Srv.URL+"/authorize") {
		t.Fatalf("begin: %v %s", err, authURL)
	}
	res, err := e.signIn(p, ms(tidA, tidA, "obj-1", map[string]any{"xms_edov": true}))
	if err != nil || res.Claims.Subject != tidA+":obj-1" || !res.Claims.EmailVerified || res.User == nil {
		t.Fatalf("allowed tenant: %v %+v", err, res)
	}
	if _, err := e.signIn(p, ms(tidB, tidB, "obj-2", map[string]any{"xms_edov": true})); !errors.Is(err, upstream.ErrUpstream) {
		t.Errorf("a tenant that is not allowed: %v", err)
	}
	if _, err := e.signIn(p, ms(tidA, tidB, "obj-3", map[string]any{"xms_edov": true})); !errors.Is(err, upstream.ErrUpstream) {
		t.Errorf("issuer of another tenant: %v", err)
	}
	if _, err := e.signIn(p, ms(tidA, tidA, "", nil)); !errors.Is(err, upstream.ErrUpstream) {
		t.Errorf("no object id: %v", err)
	}
	// without xms_edov the address is not verified, so nobody is created for it (auto-provisioning needs a verified one)
	if res, err := e.signIn(p, ms(tidA, tidA, "obj-4", nil)); err == nil || (res != nil && res.User != nil) {
		t.Errorf("unverified email provisioned a user: %v %+v", err, res)
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
