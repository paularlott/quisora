package login_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

// A provider trusted to ask for a second factor (TrustMFA) never stands in for a manager's or administrator's own
// second factor, and only a super admin can mark a provider as trusted.
func TestTrustedProviderStillAsksPrivilegedUsers(t *testing.T) {
	u := newUpEnv(t, nil)
	ctx := context.Background()
	admin := u.user(t, u.org, "orgadmin", model.RoleAdmin)
	if _, err := u.Svc.CreateProvider(ctx, service.ActorForUser(admin, ""), u.org.ID, service.ProviderInput{
		Type: ptr(model.ProviderOIDC), Name: ptr("Mine"), Issuer: ptr(u.oidc.Srv.URL), ClientID: ptr("cid"),
		ClientSecret: ptr("s3cret"), TrustMFA: ptr(true)}); err == nil {
		t.Fatal("an organization admin created a trusted provider")
	}
	p, err := u.Svc.CreateProvider(ctx, service.ActorForUser(admin, ""), u.org.ID, service.ProviderInput{
		Type: ptr(model.ProviderOIDC), Name: ptr("Mine"), Issuer: ptr(u.oidc.Srv.URL), ClientID: ptr("cid"), ClientSecret: ptr("s3cret")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Svc.UpdateProvider(ctx, service.ActorForUser(admin, ""), p.ID, service.ProviderInput{TrustMFA: ptr(true)}); err == nil {
		t.Fatal("an organization admin turned on TrustMFA")
	}
	// Unchanged, the flag may be sent along with other edits.
	if _, err := u.Svc.UpdateProvider(ctx, service.ActorForUser(admin, ""), p.ID, service.ProviderInput{TrustMFA: ptr(false), Name: ptr("Mine 2")}); err != nil {
		t.Fatalf("edit with the flag unchanged: %v", err)
	}
	if p, err = u.Svc.UpdateProvider(ctx, service.System, p.ID, service.ProviderInput{TrustMFA: ptr(true)}); err != nil || !p.TrustMFA {
		t.Fatalf("super admin turns on TrustMFA: %v", err)
	}

	mgr := u.user(t, u.org, "boss", model.RoleManager)
	u.giveTOTP(t, mgr)
	if err := u.Svc.Identities.Create(ctx, model.NewIdentity(mgr, p, "boss-sub", "", "admin")); err != nil {
		t.Fatal(err)
	}
	b := u.browser(t)
	res := b.via(t, u, p, "acme", "/x", claims("boss-sub", "boss@example.com"))
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "step=1") || b.hasSession() {
		t.Fatalf("manager through a trusted provider: %d %q session=%v", res.StatusCode, loc, b.hasSession())
	}
}

// Re-authentication asks for the account's second factor when it has one: the password alone confirms only an
// account that signs in with nothing else.
func TestReauthRequiresSecondFactor(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil)

	plain := e.signedIn(t, e.user(t, org, "plain", model.RoleUser))
	res, out := plain.api("POST", "/api/account/reauth", map[string]any{"password": userPassword})
	wantStatus(t, res, out, 200)

	totpUser := e.user(t, org, "coder", model.RoleUser)
	secret := e.giveTOTP(t, totpUser)
	b := e.signedIn(t, totpUser)
	res, out = b.api("POST", "/api/account/reauth", map[string]any{"password": userPassword})
	wantStatus(t, res, out, 422)
	if str(out, "field") != "code" {
		t.Fatalf("password alone with the app: %v", out)
	}
	if _, v := b.api("GET", "/api/account/reauth", nil); v["valid"] != false {
		t.Fatalf("re-authenticated by the password alone: %v", v)
	}
	res, out = b.api("POST", "/api/account/reauth", map[string]any{"password": userPassword, "code": totpAt(secret, time.Now())})
	wantStatus(t, res, out, 200)

	keyUser := e.user(t, org, "keyed", model.RoleUser)
	k := e.signedIn(t, keyUser)
	k.registerPasskey("Key")
	k2 := e.signedIn(t, keyUser)
	res, out = k2.api("POST", "/api/account/reauth", map[string]any{"password": userPassword})
	wantStatus(t, res, out, 422)
	if str(out, "field") != "passkey" {
		t.Fatalf("password alone with a passkey: %v", out)
	}
	if _, v := k2.api("GET", "/api/account/reauth", nil); v["valid"] != false {
		t.Fatalf("re-authenticated by the password alone: %v", v)
	}
}

// Signing in again as the same user upgrades the browser's session: same id (the refresh grants made in it, and
// the sid applications know, stay), a new sign-in time and a new cookie value (the old one stops working). Signing
// in as someone else replaces the session and ends its grants.
func TestSameUserSignInUpgradesSession(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	b := e.browser(t)
	m := e.member(t)
	res, out := b.login("primary", "member", userPassword)
	wantStatus(t, res, out, 200)
	sid := b.sessionID()
	first, _ := e.Svc.Sessions.Get(ctx, sid)
	oldCookie := b.cookie()
	g := &model.Grant{ClientID: "other-rp", UserID: m.ID, OrgID: m.OrgID, SessionID: sid, Scopes: []string{"openid"},
		Expires: time.Now().Add(time.Hour)}
	if err := e.Svc.Grants.Create(ctx, g); err != nil {
		t.Fatal(err)
	}

	time.Sleep(10 * time.Millisecond)
	res, out = b.do("POST", "/api/login/password", map[string]any{"org": "primary", "email": "member@example.com",
		"password": userPassword, "next": "/account"}, nil)
	wantStatus(t, res, out, 200)
	if b.sessionID() != sid {
		t.Fatalf("re-authentication made a new session: %s -> %s", sid, b.sessionID())
	}
	if b.cookie() == oldCookie {
		t.Fatal("the cookie value was not rotated")
	}
	up, err := e.Svc.Sessions.Get(ctx, sid)
	if err != nil || !up.AuthTime.After(first.AuthTime) {
		t.Fatalf("auth time not renewed: %v %v -> %v", err, first.AuthTime, up)
	}
	if _, err := e.Svc.Grants.Get(ctx, g.ID); err != nil {
		t.Fatalf("the other application's grant ended: %v", err)
	}
	if res, _ := b.get("/account"); res.StatusCode != 200 {
		t.Fatalf("upgraded session: %d", res.StatusCode)
	}
	// The cookie from before the upgrade no longer signs anyone in.
	stale := e.browser(t)
	stale.setCookie(oldCookie)
	if res, _ := stale.get("/account"); res.StatusCode == 200 {
		t.Fatal("the pre-upgrade cookie still works")
	}

	// Another user signing in on this browser: the old session and its grants end.
	e.user(t, mustPrimary(t, e), "someone", model.RoleUser)
	res, out = b.do("POST", "/api/login/password", map[string]any{"org": "primary", "email": "someone@example.com",
		"password": userPassword, "next": "/account"}, nil)
	wantStatus(t, res, out, 200)
	if b.sessionID() == sid {
		t.Fatal("a different user took over the session")
	}
	if _, err := e.Svc.Sessions.Get(ctx, sid); err == nil {
		t.Fatal("the previous user's session survived")
	}
	if _, err := e.Svc.Grants.Get(ctx, g.ID); err == nil {
		t.Fatal("the previous user's grant survived")
	}
}

func mustPrimary(t *testing.T, e *env) *model.Org {
	o, err := e.Svc.PrimaryOrg(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func (b *browser) cookie() string {
	u, _ := url.Parse(b.e.URL)
	for _, c := range b.c.Jar.Cookies(u) {
		if c.Name == web.SessionCookie {
			return c.Value
		}
	}
	return ""
}

func (b *browser) setCookie(v string) {
	u, _ := url.Parse(b.e.URL)
	b.c.Jar.SetCookies(u, []*http.Cookie{{Name: web.SessionCookie, Value: v, Path: "/", Secure: true}})
}

// Leaver detection: the provider's refresh token, kept from the sign-in, is replayed; a rotated one replaces it, a
// transient failure changes nothing, and invalid_grant ends the user's sessions and refresh grants.
func TestUpstreamLeaverDetection(t *testing.T) {
	u := newUpEnv(t, nil)
	ctx := context.Background()
	u.oidc.IssueRefresh, u.oidc.RotateRefresh = true, true
	p := u.oidcProvider(t, nil)
	b := u.browser(t)
	if res := b.via(t, u, p, "acme", "/x", claims("leaver-sub", "lee@corp.example")); res.StatusCode != 303 || !b.hasSession() {
		t.Fatalf("sign-in: %d", res.StatusCode)
	}
	lee, err := u.Svc.FindUserByEmail(ctx, u.org.ID, "lee@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	ident, err := u.Svc.Identities.GetByUnique(ctx, model.IdentityKey(p.ID, "leaver-sub"))
	if err != nil || ident.Refresh == "" || strings.Contains(ident.Refresh, "rt-") {
		t.Fatalf("refresh token not kept (sealed): %+v %v", ident, err)
	}
	sid := b.sessionID()
	g := &model.Grant{ClientID: "rp", UserID: lee.ID, OrgID: lee.OrgID, SessionID: sid, Scopes: []string{"openid"},
		Expires: time.Now().Add(time.Hour)}
	if err := u.Svc.Grants.Create(ctx, g); err != nil {
		t.Fatal(err)
	}

	// Nothing is due within the interval.
	if r, err := u.Mod.Upstream.CheckSessions(ctx, time.Hour); err != nil || r.Checked != 0 {
		t.Fatalf("check within the interval: %+v %v", r, err)
	}
	// Accepted, and rotated: the new token replaces the old one.
	before := u.oidc.LiveRefresh()
	if r, err := u.Mod.Upstream.CheckSessions(ctx, 0); err != nil || r.Checked != 1 || r.Ended != 0 {
		t.Fatalf("first check: %+v %v", r, err)
	}
	after := u.oidc.LiveRefresh()
	if len(before) != 1 || len(after) != 1 || before[0] == after[0] {
		t.Fatalf("rotation: %v -> %v", before, after)
	}
	if r, err := u.Mod.Upstream.CheckSessions(ctx, 0); err != nil || r.Checked != 1 || r.Ended != 0 {
		t.Fatalf("check with the rotated token: %+v %v", r, err)
	}
	// A transient failure ends nothing.
	u.oidc.Mu.Lock()
	u.oidc.RefreshFail = 503
	u.oidc.Mu.Unlock()
	if r, err := u.Mod.Upstream.CheckSessions(ctx, 0); err != nil || r.Failed != 1 || r.Ended != 0 {
		t.Fatalf("transient failure: %+v %v", r, err)
	}
	if _, err := u.Svc.Sessions.Get(ctx, sid); err != nil {
		t.Fatal("a transient failure ended the session")
	}
	u.oidc.Mu.Lock()
	u.oidc.RefreshFail = 0
	u.oidc.Mu.Unlock()

	// The account is gone at the provider: its sessions and grants end here.
	u.oidc.RevokeRefresh()
	if r, err := u.Mod.Upstream.CheckSessions(ctx, 0); err != nil || r.Ended != 1 {
		t.Fatalf("leaver: %+v %v", r, err)
	}
	if _, err := u.Svc.Sessions.Get(ctx, sid); err == nil {
		t.Fatal("the leaver's session survived")
	}
	if _, err := u.Svc.Grants.Get(ctx, g.ID); err == nil {
		t.Fatal("the leaver's refresh grant survived")
	}
	if res, _ := b.get("/account"); res.StatusCode == 200 {
		t.Fatal("the browser is still signed in")
	}
	if id, _ := u.Svc.Identities.Get(ctx, ident.ID); id == nil || id.Refresh != "" {
		t.Fatalf("the refused token was kept: %+v", id)
	}
	if len(u.audits(t, "identity.refresh.refused")) != 1 {
		t.Fatal("not audited")
	}
	// With no session through the provider, nothing is replayed.
	refreshCalls := func() int { u.oidc.Mu.Lock(); defer u.oidc.Mu.Unlock(); return u.oidc.RefreshCalls }
	calls := refreshCalls()
	if r, _ := u.Mod.Upstream.CheckSessions(ctx, 0); r.Checked != 0 || refreshCalls() != calls {
		t.Fatalf("replayed without a session: %+v", r)
	}
}
