package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store/kvstore"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
)

// The token endpoint benchmarks call the full handler chain (middleware, form parsing, client authentication, store
// reads/writes, signing, response) in-process through httptest, so they measure the server's work without TLS or
// the network.

type benchEnv struct {
	*harness
	handler http.Handler
	cl      *model.Client
	secret  string
}

func newBenchEnv(b *testing.B, edit func(*service.ClientInput)) *benchEnv {
	h := setup(b, nil)
	cl, secret := h.newClient(edit)
	return &benchEnv{harness: h, handler: h.env.Server.Handler(), cl: cl, secret: secret}
}

func (e *benchEnv) call(path string, form url.Values, basic bool) (int, []byte) {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		req.SetBasicAuth(e.cl.ID, e.secret)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (e *benchEnv) newGrant(b *testing.B, rotate bool) string {
	ctx := context.Background()
	g := &model.Grant{ClientID: e.cl.ID, UserID: e.user.ID, OrgID: e.user.OrgID, SessionID: "bench", Scopes: []string{"openid", "profile", "email", "offline_access"},
		AMR: []string{"pwd"}, AuthTime: time.Now(), Expires: time.Now().Add(time.Hour)}
	g.ID = model.NewID()
	e.env.Svc.NewGrantKey(g)
	if err := e.env.Svc.Grants.Create(ctx, g); err != nil {
		b.Fatal(err)
	}
	rt, err := e.p.refreshToken(g, rotate)
	if err != nil {
		b.Fatal(err)
	}
	return rt
}

func BenchmarkTokenRefreshStatic(b *testing.B) {
	e := newBenchEnv(b, nil)
	rt := e.newGrant(b, false)
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {e.cl.ID}, "client_secret": {e.secret}}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if code, _ := e.call(e.orgBase+"/oauth/token", form, false); code != 200 {
				b.Fatal(code)
			}
		}
	})
}

func BenchmarkTokenRefreshStaticBasicAuth(b *testing.B) {
	e := newBenchEnv(b, func(in *service.ClientInput) { in.AuthMethod = ptr(model.AuthMethodSecretBasic) })
	rt := e.newGrant(b, false)
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if code, _ := e.call(e.orgBase+"/oauth/token", form, true); code != 200 {
				b.Fatal(code)
			}
		}
	})
}

func BenchmarkTokenRefreshRotating(b *testing.B) {
	e := newBenchEnv(b, func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		rt := e.newGrant(b, true) // one token chain per goroutine: a chain is inherently serial
		for pb.Next() {
			code, body := e.call(e.orgBase+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt},
				"client_id": {e.cl.ID}, "client_secret": {e.secret}}, false)
			if code != 200 {
				b.Fatal(code, string(body))
			}
			var r struct {
				Refresh string `json:"refresh_token"`
			}
			_ = json.Unmarshal(body, &r)
			rt = r.Refresh
		}
	})
}

func BenchmarkTokenClientCredentials(b *testing.B) {
	e := newBenchEnv(b, nil)
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {e.cl.ID}, "client_secret": {e.secret}}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if code, _ := e.call(e.orgBase+"/oauth/token", form, false); code != 200 {
				b.Fatal(code)
			}
		}
	})
}

func BenchmarkTokenCodeExchange(b *testing.B) {
	e := newBenchEnv(b, nil)
	pu, _ := url.Parse(e.env.URL)
	verifier, challenge := pkce()
	ctx := context.Background()
	// codeFor is the code data of a sign-in in a session of its own: each parallel worker exchanges the codes of its
	// own browser session, as separate users do (one session's exchanges take turns: see grantAttempts).
	codeFor := func() []byte {
		c, _ := e.session(e.user)
		var sid string
		for _, ck := range c.Jar.Cookies(pu) {
			if ck.Name == web.SessionCookieFor(e.env.Primary.ID) {
				sid = web.SessionID(ck.Value) // stored sessions are keyed by the cookie's hash
			}
		}
		cd, _ := json.Marshal(codeData{ClientID: e.cl.ID, RedirectURI: rpCallback, Challenge: challenge, Nonce: "n", SessionID: sid,
			UserID: e.user.ID, OrgID: e.user.OrgID, AuthTime: time.Now().Unix(), AMR: []string{"pwd"},
			Scopes: []string{"openid", "profile", "email", "offline_access"}})
		return cd
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		cd := codeFor()
		for pb.Next() {
			code, _ := e.p.s.Eph.New(ctx, nsCode, cd, time.Minute)
			status, body := e.call(e.orgBase+"/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code},
				"redirect_uri": {rpCallback}, "code_verifier": {verifier}, "client_id": {e.cl.ID}, "client_secret": {e.secret}}, false)
			if status != 200 {
				b.Fatal(status, string(body))
			}
		}
	})
}

func BenchmarkIntrospection(b *testing.B) {
	e := newBenchEnv(b, nil)
	r := e.token(url.Values{"grant_type": {"client_credentials"}}, e.cl, e.secret)
	jwtTok := r.str("access_token")
	_, plain, err := e.env.Svc.CreateAPIToken(context.Background(), service.ActorForUser(e.user, ""), service.APITokenInput{Name: "b", Scopes: []string{"api"}})
	if err != nil {
		b.Fatal(err)
	}
	rt := e.newGrant(b, false)
	// a user access token carries a grant id: exercises the grant-alive cache as well
	user := e.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, e.cl, e.secret).str("access_token")
	for name, tok := range map[string]string{"AccessTokenClient": jwtTok, "AccessTokenUser": user, "RefreshToken": rt, "APIToken": plain} {
		b.Run(name, func(b *testing.B) {
			form := url.Values{"token": {tok}, "client_id": {e.cl.ID}, "client_secret": {e.secret}}
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if code, body := e.call(e.orgBase+"/oauth/introspect", form, false); code != 200 || !strings.Contains(string(body), `"active":true`) {
						b.Fatal(code, string(body))
					}
				}
			})
		})
	}
}

func BenchmarkVerifyAccessToken(b *testing.B) {
	e := newBenchEnv(b, nil)
	tok := e.token(url.Values{"grant_type": {"client_credentials"}}, e.cl, e.secret).str("access_token")
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := e.p.verifyAccessToken(ctx, tok); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkTokenRefreshWithGroups(b *testing.B) {
	e := newBenchEnv(b, nil)
	ctx := context.Background()
	for i := range 5 {
		g, err := e.env.Svc.CreateGroup(ctx, e.admin, e.env.Primary.ID, service.GroupInput{DisplayName: ptr("group-" + string(rune('a'+i)))})
		if err != nil {
			b.Fatal(err)
		}
		if err := e.env.Svc.SetMembership(ctx, e.admin, g.ID, e.user.ID, true); err != nil {
			b.Fatal(err)
		}
	}
	rt := e.newGrant(b, false)
	e.cl.Scopes = append(e.cl.Scopes, "groups")
	e.env.Svc.UpdateClient(ctx, e.admin, e.cl.ID, service.ClientInput{Scopes: &e.cl.Scopes})
	e.p.InvalidateClient(e.cl.ID)
	g, _ := e.env.Svc.Grants.All(ctx, e.user.ID)
	g[0].Scopes = []string{"openid", "profile", "groups", "offline_access"}
	if err := e.env.Svc.Grants.Update(ctx, g[0]); err != nil {
		b.Fatal(err)
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {e.cl.ID}, "client_secret": {e.secret}}
	if code, body := e.call(e.orgBase+"/oauth/token", form, false); code != 200 {
		b.Fatal(code, string(body))
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if code, _ := e.call(e.orgBase+"/oauth/token", form, false); code != 200 {
				b.Fatal(code)
			}
		}
	})
}

// BenchmarkTokenEndpointDiskBadger runs the token and introspection endpoints against a disk-backed Badger store with
// its production fsync, with ES256 and Basic authentication.
func BenchmarkTokenEndpointDiskBadger(b *testing.B) {
	ctx := context.Background()
	st, err := kvstore.OpenBadger(ctx, b.TempDir(), kvstore.BadgerOptions{})
	if err != nil {
		b.Fatal(err)
	}
	var p *Provider
	e := webtest.New(b, webtest.Options{Store: st, Modules: func(s *web.Server) []web.Module { p = New(s); return []web.Module{p} }})
	if err := p.EnsureKeys(ctx); err != nil {
		b.Fatal(err)
	}
	c, secret, err := e.Svc.CreateClient(ctx, service.ActorForUser(e.Admin, ""), e.Primary.ID, service.ClientInput{Name: ptr("App"), AuthMethod: ptr(model.AuthMethodSecretBasic), GrantTypes: &[]string{"client_credentials", "refresh_token"}, Scopes: &[]string{"api", "openid", "offline_access"}, RotateRefresh: ptr(false)})
	if err != nil {
		b.Fatal(err)
	}
	h, base := e.Server.Handler(), web.OrgPath(e.Primary.ID, "")
	call := func(path string, form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(c.ID, secret)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	first := call(base+"/oauth/token", form)
	if first.Code != 200 {
		b.Fatalf("%d %s", first.Code, first.Body)
	}
	var tok struct {
		Access string `json:"access_token"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &tok); err != nil || tok.Access == "" {
		b.Fatal("missing access token", err)
	}
	u, err := e.Svc.CreateUser(ctx, service.System, e.Primary.ID, service.UserInput{Email: ptr("user@example.com"), Username: ptr("user"), GivenName: ptr("User")})
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	g := &model.Grant{ClientID: c.ID, UserID: u.ID, OrgID: u.OrgID, SessionID: "session", Scopes: []string{"openid", "offline_access"}, AMR: []string{"pwd"}, AuthTime: now, Expires: now.Add(time.Hour)}
	g.ID = model.NewID()
	e.Svc.NewGrantKey(g)
	if err := e.Svc.Grants.Create(ctx, g); err != nil {
		b.Fatal(err)
	}
	rt, err := p.refreshToken(g, false)
	if err != nil {
		b.Fatal(err)
	}
	for _, name := range []string{"ClientCredentials", "Introspection", "RefreshStatic"} {
		b.Run(name, func(b *testing.B) {
			path, values := base+"/oauth/token", form
			if name == "Introspection" {
				path, values = base+"/oauth/introspect", url.Values{"token": {tok.Access}}
			}
			if name == "RefreshStatic" {
				values = url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
			}
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					rec := call(path, values)
					if rec.Code != 200 {
						b.Fatalf("%d %s", rec.Code, rec.Body)
					}
					if name == "Introspection" && !strings.Contains(rec.Body.String(), `"active":true`) {
						b.Fatal(rec.Body.String())
					}
				}
			})
		})
	}
}
