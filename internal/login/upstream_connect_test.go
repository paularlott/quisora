package login_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// An administrator (never linked by email) connects a provider from the account page, after re-authenticating; the
// identity then signs them in (with their second factor). An identity already linked to someone else is refused, and
// the last way to sign in cannot be disconnected.
func TestConnectProviderToAccount(t *testing.T) {
	u := newUpEnv(t, nil)
	p := u.oidcProvider(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(false) })
	admin := u.user(t, u.org, "ada", model.RoleAdmin)
	b := u.signedIn(t, admin)

	// by email: refused for an administrator
	if br := u.browser(t); !strings.Contains(br.via(t, u, p, "acme", "", claims("ada-sub", admin.Email)).Header.Get("Location"), "error=") || br.hasSession() {
		t.Fatal("an admin was signed in through an unconnected provider")
	}
	// connecting needs a recent re-authentication
	res, out := b.post("/api-internal/account/providers/"+p.ID+"/connect", nil)
	wantStatus(t, res, out, 403)
	authURL := u.connectURL(t, b, p)
	if loc := u.connectCallback(t, b, p, authURL, claims("ada-sub", "ada@elsewhere.example")); loc != u.at("/account?provider=connected#providers") {
		t.Fatalf("connect callback: %q", loc)
	}
	res, out = b.api("GET", "/api-internal/account/providers", nil)
	if it := items(t, out); len(it) != 1 || it[0]["connected"] != true {
		t.Fatalf("providers: %v", out["_raw"])
	}
	if len(u.audits(t, "account.provider.connect")) != 1 {
		t.Error("connect not audited")
	}
	// the identity now signs Ada in, and as an administrator she continues with a second factor (she has none yet,
	// so the sign-in page asks her to set one up) even though the organization does not require one
	if res := u.browser(t).via(t, u, p, "acme", "/x", claims("ada-sub", "whatever@x.example")); !strings.Contains(res.Header.Get("Location"), "step=1") {
		t.Fatalf("sign-in with the connected identity: %q", res.Header.Get("Location"))
	}

	// someone else cannot take that identity
	bob := u.user(t, u.org, "bob", model.RoleUser)
	bb := u.signedIn(t, bob)
	authURL = u.connectURL(t, bb, p)
	if loc := u.connectCallback(t, bb, p, authURL, claims("ada-sub", "bob@corp.example")); loc != u.at("/account?provider=taken#providers") {
		t.Fatalf("taken identity: %q", loc)
	}

	// disconnect: needs reauth; refused when it is the last way in
	b.markReauth() // (Ada has a password: the test helper sets one)
	res, out = b.api("DELETE", "/api-internal/account/providers/"+p.ID, nil)
	wantStatus(t, res, out, 204)
	solo := u.user(t, u.org, "solo", model.RoleUser)
	fresh, _ := u.Svc.Users.Get(context.Background(), solo.ID)
	fresh.PasswordHash = ""
	_ = u.Svc.Users.Update(context.Background(), fresh)
	_ = u.Svc.Identities.Create(context.Background(), model.NewIdentity(solo, p, "solo-sub", "", "admin"))
	sb := u.signedIn(t, solo)
	sb.markReauth()
	res, out = sb.api("DELETE", "/api-internal/account/providers/"+p.ID, nil)
	wantStatus(t, res, out, 409)
}

// A tenant that requires a second factor asks for one after a provider sign-in, unless the provider is marked as
// counting as one (TrustMFA): then the user's own code is not asked for either, and the session carries "mfa".
func TestUpstreamTrustedProviderCountsAsSecondFactor(t *testing.T) {
	u := newUpEnv(t, nil)
	ctx := context.Background()
	if d, err := u.Svc.DefaultTenant(ctx, u.org.ID); err != nil || !d.Settings.RequireMFA {
		t.Fatalf("a new organization's default tenant should require a second factor: %+v %v", d, err)
	}

	// Not trusted: the tenant's requirement holds after the provider, whatever the provider says it did.
	plain := u.oidcProvider(t, func(in *service.ProviderInput) { in.Name = ptr("Plain SSO") })
	b := u.browser(t)
	said := claims("sub-p", "lee@corp.example")
	said["amr"] = []string{"pwd", "mfa"}
	res := b.viaTenant(t, u, plain, "acme", "default", "/x", said)
	if loc := res.Header.Get("Location"); res.StatusCode != 303 || !strings.Contains(loc, "step=1") || b.hasSession() {
		t.Fatalf("untrusted provider: %d %q session=%v", res.StatusCode, loc, b.hasSession())
	}

	// Trusted: straight in, even for a user with a code of their own, and the session satisfies the requirement.
	trusted := u.oidcProvider(t, func(in *service.ProviderInput) { in.TrustMFA = ptr(true) })
	if res := u.browser(t).via(t, u, trusted, "acme", "/x", claims("sub-t", "kim@corp.example")); res.StatusCode != 303 {
		t.Fatalf("first sign-in: %d", res.StatusCode)
	}
	kim, _ := u.Svc.FindUserByEmail(ctx, u.org.ID, "kim@corp.example")
	u.giveTOTP(t, kim)
	b2 := u.browser(t)
	said = claims("sub-t", "kim@corp.example")
	said["amr"] = []string{"pwd", "mfa"}
	res = b2.viaTenant(t, u, trusted, "acme", "default", "/x", said)
	if res.StatusCode != 303 || res.Header.Get("Location") != u.at("/x") || !b2.hasSession() {
		t.Fatalf("trusted provider: %d %q session=%v", res.StatusCode, res.Header.Get("Location"), b2.hasSession())
	}
	ok := false
	for _, s := range sessionsOf(t, u.env, kim) {
		ok = ok || (slices.Equal(s.AMR, []string{"fed", "mfa"}) && model.MFA(s.AMR) && s.Provider == trusted.ID &&
			slices.Equal(s.UpstreamAMR, []string{"pwd", "mfa"}))
	}
	if !ok {
		t.Fatalf("sessions: %+v", sessionsOf(t, u.env, kim))
	}

	// Trusted, but its ID token says no second factor was used (amr without "mfa"): the trust does not apply, and the
	// user's own code is asked for, as after an untrusted provider. (One that sends no amr at all, as above, is
	// taken at its trust.)
	b3 := u.browser(t)
	said = claims("sub-t", "kim@corp.example")
	said["amr"] = []string{"pwd"}
	res = b3.viaTenant(t, u, trusted, "acme", "default", "/x", said)
	if loc := res.Header.Get("Location"); res.StatusCode != 303 || !strings.Contains(loc, "step=1") || b3.hasSession() {
		t.Fatalf("trusted provider without mfa in its amr: %d %q session=%v", res.StatusCode, loc, b3.hasSession())
	}
}

// A sign-in through a provider trusted as a second factor (TrustMFA) skips the user's own code, so it does not count
// as the recent re-authentication that connecting another provider needs: that would let it add further ways in that
// skip the code too. A re-authentication (which asks for the code) does; and an account with no second factor of its
// own connects straight after any sign-in, as before.
func TestConnectNeedsOwnSecondFactor(t *testing.T) {
	u := newUpEnv(t, nil)
	ctx := context.Background()
	trusted := u.oidcProvider(t, func(in *service.ProviderInput) { in.TrustMFA = ptr(true) })
	other := u.oidcProvider(t, func(in *service.ProviderInput) { in.Name = ptr("Other SSO"); in.AutoProvision = ptr(false) })
	if res := u.browser(t).via(t, u, trusted, "acme", "/x", claims("sub-k", "kim@corp.example")); res.StatusCode != 303 {
		t.Fatalf("first sign-in: %d", res.StatusCode)
	}
	kim, _ := u.Svc.FindUserByEmail(ctx, u.org.ID, "kim@corp.example")

	// no second factor of her own yet: a fresh provider sign-in is enough
	b := u.browser(t)
	if res := b.via(t, u, trusted, "acme", "/x", claims("sub-k", "kim@corp.example")); !b.hasSession() {
		t.Fatalf("sign-in: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	sessionCSRF(t, b)
	res, out := b.post("/api-internal/account/providers/"+other.ID+"/connect", nil)
	wantStatus(t, res, out, 200)

	// with an authenticator, the trusted provider's sign-in no longer is
	u.giveTOTP(t, kim)
	b = u.browser(t)
	if res := b.via(t, u, trusted, "acme", "/x", claims("sub-k", "kim@corp.example")); !b.hasSession() {
		t.Fatalf("sign-in: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	sessionCSRF(t, b)
	res, out = b.post("/api-internal/account/providers/"+other.ID+"/connect", nil)
	wantStatus(t, res, out, 403)
	if str(out, "field") != "reauth" {
		t.Fatalf("refusal: %v", out["_raw"])
	}
	// nor does it let that sign-in add another way in that skips the code (a passkey), or replace the code
	for _, path := range []string{"/api-internal/account/passkeys/register/begin", "/api-internal/account/totp/begin"} {
		res, out = b.post(path, map[string]any{})
		if res.StatusCode != 403 || str(out, "field") != "reauth" {
			t.Fatalf("%s after a trusted provider sign-in: %d %v", path, res.StatusCode, out["_raw"])
		}
	}
	b.markReauth()
	res, out = b.post("/api-internal/account/providers/"+other.ID+"/connect", nil)
	wantStatus(t, res, out, 200)
}

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

// Reconnecting a provider whose link is left from before the account's sign-in was reset (a passed credential epoch)
// makes a link that counts: "connected" is said only when the account has one.
func TestReconnectReplacesPassedEpochLink(t *testing.T) {
	ctx := context.Background()
	u := newUpEnv(t, nil)
	p := u.oidcProvider(t, func(in *service.ProviderInput) { in.AutoProvision = ptr(false) })
	kim := u.user(t, u.org, "kim", model.RoleUser)
	if err := u.Svc.Identities.Create(ctx, model.NewIdentity(kim, p, "kim-sub", "", "admin")); err != nil {
		t.Fatal(err)
	}
	fresh, err := u.Svc.Users.Get(ctx, kim.ID)
	if err != nil {
		t.Fatal(err)
	}
	fresh.CredEpoch = service.NewCredEpoch() // the sign-in was reset: the link counts no more
	if err := u.Svc.Users.Update(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	b := u.signedIn(t, fresh)
	authURL := u.connectURL(t, b, p)
	if loc := u.connectCallback(t, b, p, authURL, claims("kim-sub", kim.Email)); loc != u.at("/account?provider=connected#providers") {
		t.Fatalf("reconnect callback: %q", loc)
	}
	now, err := u.Svc.Users.Get(ctx, kim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ids, err := u.Svc.CurrentIdentities(ctx, now); err != nil || len(ids) != 1 {
		t.Fatalf("no link that counts after reconnecting: %v %v", ids, err)
	}
}

// Connecting a provider to an account: the browser that finishes must be the one signed in as the account that
// began, the e-mail domain rule applies, connecting again is idempotent and an unknown or switched-off provider is
// not found.
func TestConnectProviderRefusals(t *testing.T) {
	u := newUpEnv(t, func(c *config.Config) { c.Audit.Logins = true })
	p := u.oidcProvider(t, func(in *service.ProviderInput) {
		in.AutoProvision = ptr(false)
		in.AllowedDomains = &[]string{"corp.example"}
	})
	off := u.oidcProvider(t, func(in *service.ProviderInput) { in.Name = ptr("Off"); in.Enabled = ptr(false) })
	pat := u.user(t, u.org, "pat", model.RoleUser)
	b := u.signedIn(t, pat)

	b.markReauth()
	for _, id := range []string{"nope", off.ID} {
		res, out := b.post("/api-internal/account/providers/"+id+"/connect", nil)
		wantStatus(t, res, out, 404)
	}

	// finished by a browser that did not start it (no state cookie: anonymous, or signed in as someone else): nothing is linked
	authURL := u.connectURL(t, b, p)
	if loc := u.connectCallback(t, u.browserAt(t, u.org), p, authURL, claims("pat-sub", "pat@corp.example")); loc != u.at("/login?error=failed") {
		t.Fatalf("anonymous finish: %q", loc)
	}
	sam := u.user(t, u.org, "sam", model.RoleUser)
	sb := u.signedIn(t, sam)
	authURL = u.connectURL(t, b, p)
	if loc := u.connectCallback(t, sb, p, authURL, claims("pat-sub", "pat@corp.example")); loc != u.at("/login?error=failed") {
		t.Fatalf("another user's finish: %q", loc)
	}
	if ids, _ := u.Svc.Identities.All(context.Background(), ""); len(ids) != 0 {
		t.Fatalf("identities linked by refused finishes: %d", len(ids))
	}

	// an address outside the provider's allowed domains
	authURL = u.connectURL(t, b, p)
	if loc := u.connectCallback(t, b, p, authURL, claims("pat-sub", "pat@evil.example")); loc != u.at("/account?provider=domain#providers") {
		t.Fatalf("domain: %q", loc)
	}
	if len(u.audits(t, "account.provider.connect_refused")) != 1 {
		t.Fatal("refusal not audited")
	}

	// success, and again with the same identity
	authURL = u.connectURL(t, b, p)
	if loc := u.connectCallback(t, b, p, authURL, claims("pat-sub", "pat@corp.example")); loc != u.at("/account?provider=connected#providers") {
		t.Fatalf("connect: %q", loc)
	}
	authURL = u.connectURL(t, b, p)
	if loc := u.connectCallback(t, b, p, authURL, claims("pat-sub", "pat@corp.example")); loc != u.at("/account?provider=connected#providers") {
		t.Fatalf("connect again: %q", loc)
	}
	if ids, _ := u.Svc.Identities.All(context.Background(), pat.ID); len(ids) != 1 {
		t.Fatalf("identities: %d", len(ids))
	}
	// sam cannot take pat's identity
	authURL = u.connectURL(t, sb, p)
	if loc := u.connectCallback(t, sb, p, authURL, claims("pat-sub", "sam@corp.example")); loc != u.at("/account?provider=taken#providers") {
		t.Fatalf("taken: %q", loc)
	}

	// disconnecting something not connected
	b.markReauth()
	res, out := b.api("DELETE", "/api-internal/account/providers/nope", nil)
	wantStatus(t, res, out, 404)
}
