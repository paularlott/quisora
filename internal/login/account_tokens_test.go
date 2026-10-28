package login_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func TestAccountTokens(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", allowAPITokens)
	pat := e.user(t, org, "pat", model.RoleUser)
	mgr := e.user(t, org, "mia", model.RoleManager)
	b := e.signedIn(t, pat)
	m := e.signedInMFA(t, mgr)

	res, out := b.api("GET", "/api-internal/account/tokens", nil)
	wantStatus(t, res, out, 200)
	if sc, _ := out["scopes"].([]any); len(sc) != 1 || sc[0] != "api" {
		t.Fatalf("user scopes %v", out["scopes"])
	}
	res, out = m.api("GET", "/api-internal/account/tokens", nil)
	if sc, _ := out["scopes"].([]any); len(sc) != 3 {
		t.Fatalf("manager scopes %v", out["scopes"])
	}

	b.markReauth()
	res, out = b.api("POST", "/api-internal/account/tokens", map[string]any{"name": "ci", "scopes": []string{"api"}, "expires_days": 30})
	wantStatus(t, res, out, 201)
	token := str(out, "token")
	item := out["item"].(map[string]any)
	if !strings.HasPrefix(token, "qsr_"+str(item, "id")+"_") {
		t.Fatalf("token %q", token)
	}
	exp, _ := time.Parse(time.RFC3339, str(item, "expires"))
	if d := time.Until(exp); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Fatalf("expiry %v", exp)
	}
	// the secret is shown once
	res, out = b.api("GET", "/api-internal/account/tokens", nil)
	if strings.Contains(str(out, "_raw"), token) || strings.Contains(str(out, "_raw"), "secret") || len(items(t, out)) != 1 {
		t.Fatalf("list: %v", out["_raw"])
	}
	// and works with the service
	if _, u, err := e.Svc.ValidateAPIToken(context.Background(), token); err != nil || u.ID != pat.ID {
		t.Fatalf("token invalid: %v", err)
	}

	// validation and role limits
	for name, body := range map[string]map[string]any{
		"no name": {"name": "", "scopes": []string{"api"}}, "no scopes": {"name": "x", "scopes": []string{}},
		"unknown scope": {"name": "x", "scopes": []string{"root"}}, "scim as user": {"name": "x", "scopes": []string{"scim"}},
		"admin as user": {"name": "x", "scopes": []string{"admin"}}, "too long": {"name": "x", "scopes": []string{"api"}, "expires_days": 100000},
		"negative": {"name": "x", "scopes": []string{"api"}, "expires_days": -1},
	} {
		res, out = b.api("POST", "/api-internal/account/tokens", body)
		if res.StatusCode != 422 {
			t.Errorf("%s: %d %v", name, res.StatusCode, out["_raw"])
		}
	}
	res, out = b.api("POST", "/api-internal/account/tokens", `{"name":"x","scopes":["api"],"user_id":"someone"}`)
	wantStatus(t, res, out, 400)
	m.markReauth()
	res, out = m.api("POST", "/api-internal/account/tokens", map[string]any{"name": "provisioning", "scopes": []string{"scim"}})
	wantStatus(t, res, out, 201)
	mgrTokenID := str(out["item"].(map[string]any), "id")

	// delete: own token only, even an administrator cannot delete someone else's through the account API
	admin := e.signedIn(t, e.Admin)
	res, out = admin.api("DELETE", "/api-internal/account/tokens/"+mgrTokenID, nil)
	wantStatus(t, res, out, 404)
	res, out = b.api("DELETE", "/api-internal/account/tokens/"+mgrTokenID, nil)
	wantStatus(t, res, out, 404)
	res, out = b.api("DELETE", "/api-internal/account/tokens/nope", nil)
	wantStatus(t, res, out, 404)
	if _, err := e.Svc.APITokens.Get(context.Background(), mgrTokenID); err != nil {
		t.Fatal("someone else's token deleted")
	}
	res, out = b.api("GET", "/api-internal/account/tokens", nil)
	id := str(items(t, out)[0], "id")
	res, out = b.api("DELETE", "/api-internal/account/tokens/"+id, nil)
	wantStatus(t, res, out, 204)
	if _, _, err := e.Svc.ValidateAPIToken(context.Background(), token); err == nil {
		t.Fatal("deleted token still valid")
	}
}

// A token's secret can be replaced: the new one works at once and the old one stops; the name, access and expiry stay.
// The same conditions as making a token (a recent re-authentication), and only for your own tokens.
func TestAccountTokenRegenerate(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", allowAPITokens)
	pat := e.user(t, org, "pat", model.RoleUser)
	sam := e.user(t, org, "sam", model.RoleUser)
	b := e.signedIn(t, pat)
	b.markReauth()
	res, out := b.api("POST", "/api-internal/account/tokens", map[string]any{"name": "ci", "scopes": []string{"api"}, "expires_days": 30})
	wantStatus(t, res, out, 201)
	old := str(out, "token")
	id := str(out["item"].(map[string]any), "id")
	exp := str(out["item"].(map[string]any), "expires")

	// someone else's token is not found, even with a fresh re-authentication
	other := e.signedIn(t, sam)
	other.markReauth()
	res, out = other.api("POST", "/api-internal/account/tokens/"+id+"/regenerate", nil)
	wantStatus(t, res, out, 404)

	res, out = b.api("POST", "/api-internal/account/tokens/"+id+"/regenerate", nil)
	wantStatus(t, res, out, 200)
	fresh := str(out, "token")
	item := out["item"].(map[string]any)
	if fresh == old || !strings.HasPrefix(fresh, "qsr_"+id+"_") || str(item, "name") != "ci" || !sameSecond(str(item, "expires"), exp) {
		t.Fatalf("regenerated: %q %v", fresh, item)
	}
	if _, _, err := e.Svc.ValidateAPIToken(context.Background(), old); err == nil {
		t.Fatal("the old secret still works")
	}
	if _, _, err := e.Svc.ValidateAPIToken(context.Background(), fresh); err != nil {
		t.Fatalf("the new secret: %v", err)
	}
	if len(e.audits(t, "apitoken.regenerate")) == 0 {
		t.Error("no audit entry")
	}
}

func sameSecond(a, b string) bool {
	ta, errA := time.Parse(time.RFC3339Nano, a)
	tb, errB := time.Parse(time.RFC3339Nano, b)
	return errA == nil && errB == nil && ta.Truncate(time.Second).Equal(tb.Truncate(time.Second))
}

// The token list offers the applications a token can be for, with their own scopes; editing a token changes its
// name, applications and scopes (checked as when it was made), and only for its owner.
func TestAccountTokenEdit(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", allowAPITokens)
	pat := e.user(t, org, "pat", model.RoleUser)
	sam := e.user(t, org, "sam", model.RoleUser)
	app, _, err := e.Svc.CreateClient(context.Background(), service.System, org.ID, service.ClientInput{Name: ptr("Orders"),
		GrantTypes: ptr([]string{"client_credentials"}), Scopes: ptr([]string{"orders:read", "orders:write"}), AcceptsAPITokens: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	b := e.signedIn(t, pat)
	b.markReauth()
	res, out := b.api("GET", "/api-internal/account/tokens", nil)
	wantStatus(t, res, out, 200)
	apps, _ := out["apps"].([]any)
	if len(apps) != 1 || str(apps[0].(map[string]any), "id") != app.ID {
		t.Fatalf("apps: %v", out["apps"])
	}
	res, out = b.api("POST", "/api-internal/account/tokens", map[string]any{"name": "ci", "scopes": []string{"api"},
		"audience": []string{app.ID}, "app_scopes": []string{"orders:read"}})
	wantStatus(t, res, out, 201)
	id := str(out["item"].(map[string]any), "id")

	res, out = b.api("PATCH", "/api-internal/account/tokens/"+id, map[string]any{"app_scopes": []string{"billing:read"}})
	wantStatus(t, res, out, 422)
	if str(out, "field") != "app_scopes" {
		t.Fatalf("field %v", out)
	}
	res, out = b.api("PATCH", "/api-internal/account/tokens/"+id, map[string]any{"name": "ci (read/write)", "app_scopes": []string{"orders:read", "orders:write"}})
	wantStatus(t, res, out, 200)
	if it := out["item"].(map[string]any); str(it, "name") != "ci (read/write)" || len(it["app_scopes"].([]any)) != 2 {
		t.Fatalf("edited %v", it)
	}
	other := e.signedIn(t, sam)
	other.markReauth()
	res, out = other.api("PATCH", "/api-internal/account/tokens/"+id, map[string]any{"name": "mine"})
	wantStatus(t, res, out, 404)
}

// API tokens of managers and above need a second-factor session to be made or changed.
func TestAccountTokenChangesNeedMFAForManagers(t *testing.T) {
	e, org := accountEnv(t, 0)
	mgr := e.user(t, org, "mia", model.RoleManager)
	mfa := e.signedInMFA(t, mgr)
	mfa.markReauth()
	res, out := mfa.api("POST", "/api-internal/account/tokens", map[string]any{"name": "ci", "scopes": []string{"api"}})
	wantStatus(t, res, out, 201)
	id := str(out["item"].(map[string]any), "id")

	single := e.signedIn(t, mgr)
	single.markReauth()
	// it would act as the manager and skip the console's second-factor check
	res, out = single.api("POST", "/api-internal/account/tokens", map[string]any{"name": "x", "scopes": []string{"api"}})
	wantStatus(t, res, out, 403)
	if str(out, "field") != "mfa" {
		t.Fatalf("create: %v", out["_raw"])
	}
	res, out = single.api("PATCH", "/api-internal/account/tokens/"+id, map[string]any{"name": "renamed"})
	wantStatus(t, res, out, 403)
	if str(out, "field") != "mfa" {
		t.Fatalf("update: %v", out["_raw"])
	}
	res, out = single.api("POST", "/api-internal/account/tokens/"+id+"/regenerate", nil)
	wantStatus(t, res, out, 403)
	if str(out, "field") != "mfa" {
		t.Fatalf("regenerate: %v", out["_raw"])
	}
	// removing access needs neither: any session of the owner may delete the token
	e.Mod.ClearReauth(single.sessionID())
	res, out = single.api("DELETE", "/api-internal/account/tokens/"+id, nil)
	wantStatus(t, res, out, 204)
}

// The api scope is offered, and accepted, only to those the organization lets make api tokens; the others still get
// the scopes their role allows, and no application that has not chosen to accept api tokens is offered for one.
func TestAccountTokensFollowTheOrganizationSetting(t *testing.T) {
	e := newEnv(t, nil)
	org := e.org(t, "acme", nil) // as a new organization is: nobody
	pat := e.user(t, org, "pat", model.RoleUser)
	mia := e.user(t, org, "mia", model.RoleManager)
	closed, _, err := e.Svc.CreateClient(context.Background(), service.System, org.ID, service.ClientInput{Name: ptr("Closed"),
		GrantTypes: ptr([]string{"client_credentials"})})
	if err != nil {
		t.Fatal(err)
	}
	b, m := e.signedIn(t, pat), e.signedInMFA(t, mia)
	b.markReauth()
	m.markReauth()
	scopes := func(c *browser) []any {
		t.Helper()
		res, out := c.api("GET", "/api-internal/account/tokens", nil)
		wantStatus(t, res, out, 200)
		sc, _ := out["scopes"].([]any)
		if apps, _ := out["apps"].([]any); len(apps) != 0 {
			t.Fatalf("an application that does not accept api tokens is offered: %v (%s)", apps, closed.ID)
		}
		return sc
	}
	if sc := scopes(b); len(sc) != 0 {
		t.Fatalf("nobody allowed, user scopes %v", sc)
	}
	if sc := scopes(m); len(sc) != 2 || sc[0] != "scim" || sc[1] != "admin" {
		t.Fatalf("nobody allowed, manager scopes %v", sc)
	}
	res, out := b.api("POST", "/api-internal/account/tokens", map[string]any{"name": "ci", "scopes": []string{"api"}})
	wantStatus(t, res, out, 422)
	if str(out, "field") != "scopes" {
		t.Fatalf("refusal: %v", out["_raw"])
	}
	res, out = m.api("POST", "/api-internal/account/tokens", map[string]any{"name": "provisioning", "scopes": []string{"scim"}})
	wantStatus(t, res, out, 201)

	e.setSettings(t, org, allowAPITokens)
	if sc := scopes(b); len(sc) != 1 || sc[0] != "api" {
		t.Fatalf("everyone allowed, user scopes %v", sc)
	}
	res, out = b.api("POST", "/api-internal/account/tokens", map[string]any{"name": "ci", "scopes": []string{"api"}})
	wantStatus(t, res, out, 201)
}
