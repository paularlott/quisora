package login_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	ut "github.com/paularlott/quisora/internal/upstream/upstreamtest"
	"github.com/paularlott/quisora/internal/web"
)

type upEnv struct {
	*env
	org  *model.Org
	oidc *ut.FakeOIDC
	gh   *ut.FakeGitHub
}

func newUpEnv(t *testing.T, mut ...func(*config.Config)) *upEnv {
	e := newEnv(t, mut...)
	u := &upEnv{env: e, org: e.org(t, "acme", nil), oidc: ut.NewFakeOIDC(t), gh: ut.NewFakeGitHub(t)}
	e.Mod.Upstream.HTTP = ut.HTTPClient()
	e.Mod.Upstream.GitHubAuthURL, e.Mod.Upstream.GitHubTokenURL, e.Mod.Upstream.GitHubAPIURL =
		u.gh.Srv.URL+"/authorize", u.gh.Srv.URL+"/token", u.gh.Srv.URL
	return u
}

func (u *upEnv) oidcProvider(t *testing.T, mut func(*service.ProviderInput)) *model.Provider {
	in := service.ProviderInput{Type: ptr(model.ProviderOIDC), Name: ptr("Corp SSO"), Issuer: ptr(u.oidc.Srv.URL), ClientID: ptr("cid"),
		ClientSecret: ptr("s3cret"), AutoProvision: ptr(true)}
	if mut != nil {
		mut(&in)
	}
	p, err := u.Svc.CreateProvider(context.Background(), service.System, u.org.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func claims(sub, email string) map[string]any {
	return map[string]any{"sub": sub, "email": email, "email_verified": true, "name": "Pat Doe"}
}

// at is a path of the test organization's address space.
func (u *upEnv) at(rest string) string { return web.OrgPath(u.org.ID, rest) }

// nextOf is the next a test means: a path of the organization's space, except one that is not a local path at all
// (a hostile one), which is sent as it is.
func (u *upEnv) nextOf(next string) string {
	if strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") {
		return u.at(next)
	}
	return next
}

// via runs the provider round trip and returns the callback response. next is a path in the organization's space
// (u.at), given without its /o/<id> prefix.
func (b *browser) via(t *testing.T, u *upEnv, p *model.Provider, org, next string, c map[string]any) *http.Response {
	t.Helper()
	path := "/o/" + org + "/login/provider/" + p.ID
	if next != "" {
		path += "?next=" + url.QueryEscape(u.nextOf(next))
	}
	res, _ := b.get(path)
	if res.StatusCode != 302 {
		t.Fatalf("provider start: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	loc := res.Header.Get("Location")
	state := ""
	if lu, err := url.Parse(loc); err == nil {
		state = lu.Query().Get("state")
	}
	var code string
	if p.Type == model.ProviderGitHub {
		code = u.gh.Authorize(loc)
	} else {
		code = u.oidc.Authorize(loc, c)
	}
	res2, _ := b.get("/login/callback/" + p.ID + "?state=" + url.QueryEscape(state) + "&code=" + url.QueryEscape(code))
	return res2
}

// viaTenant is via for a sign-in made on behalf of a tenant.
func (b *browser) viaTenant(t *testing.T, u *upEnv, p *model.Provider, org, tenant, next string, c map[string]any) *http.Response {
	t.Helper()
	res, _ := b.get("/o/" + org + "/login/provider/" + p.ID + "?tenant=" + tenant + "&next=" + url.QueryEscape(u.nextOf(next)))
	if res.StatusCode != 302 {
		t.Fatalf("provider start: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	loc := res.Header.Get("Location")
	lu, _ := url.Parse(loc)
	code := u.oidc.Authorize(loc, c)
	res2, _ := b.get("/login/callback/" + p.ID + "?state=" + url.QueryEscape(lu.Query().Get("state")) + "&code=" + url.QueryEscape(code))
	return res2
}

func (u *upEnv) org2(t *testing.T) *model.Org { return u.env.org(t, "other", nil) }

func attr(body, name string) string {
	i := strings.Index(body, name+`="`)
	if i < 0 {
		return ""
	}
	rest := body[i+len(name)+2:]
	return rest[:strings.IndexByte(rest, '"')]
}

// sessionCSRF loads the account page into b's CSRF token (refresh is for signed-out pages).
func sessionCSRF(t *testing.T, b *browser) {
	t.Helper()
	_, body := b.get("/account")
	m := metaRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf meta on the account page: %.300s", body)
	}
	b.csrf = m[1]
}

func (u *upEnv) connectURL(t *testing.T, b *browser, p *model.Provider) string {
	t.Helper()
	b.markReauth()
	res, out := b.post("/api-internal/account/providers/"+p.ID+"/connect", nil)
	wantStatus(t, res, out, 200)
	return str(out, "url")
}

func (u *upEnv) connectCallback(t *testing.T, b *browser, p *model.Provider, authURL string, c map[string]any) string {
	t.Helper()
	code := u.oidc.Authorize(authURL, c)
	lu, _ := url.Parse(authURL)
	res, _ := b.get("/login/callback/" + p.ID + "?state=" + url.QueryEscape(lu.Query().Get("state")) + "&code=" + url.QueryEscape(code))
	return res.Header.Get("Location")
}
