package oidc

// Matches Fortix Identity's review harness: full handler, ES256, Basic auth,
// disk-backed Badger with production fsync. No network or TLS is timed.
import (
	"context"
	"encoding/json"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store/kvstore"
	"github.com/paularlott/quisora/internal/web"
	"github.com/paularlott/quisora/internal/webtest"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func BenchmarkComparison(b *testing.B) {
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
	h := e.Server.Handler()
	call := func(path string, form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(c.ID, secret)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	first := call("/oauth/token", form)
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
			path, values := "/oauth/token", form
			if name == "Introspection" {
				path, values = "/oauth/introspect", url.Values{"token": {tok.Access}}
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
