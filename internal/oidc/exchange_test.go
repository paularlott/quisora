package oidc

import (
	"context"
	"net/url"
	"slices"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func (h *harness) exchange(c *model.Client, secret, subject string, extra url.Values) tokResp {
	h.t.Helper()
	f := url.Values{"grant_type": {service.GrantTokenExchange}, "subject_token": {subject},
		"subject_token_type": {tokenTypeAccess}}
	for k, v := range extra {
		if len(v) == 1 && v[0] == "" {
			f.Del(k)
		} else {
			f[k] = v
		}
	}
	return h.token(f, c, secret)
}

func withExchange(in *service.ClientInput) {
	in.GrantTypes = &[]string{"authorization_code", "refresh_token", "client_credentials", service.GrantTokenExchange}
}

func TestTokenExchangeByResourceServer(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	app, asecret := h.newClient(nil)
	r, _ := h.login(app, asecret, url.Values{"scope": {"openid profile email api offline_access"}})
	at, rt := r.str("access_token"), r.str("refresh_token")
	subject := claimsOf(t, at)

	// an API of the organization that may see every token (introspect_org) passes the user on to another API
	api, apiSecret := h.newClient(func(in *service.ClientInput) {
		withExchange(in)
		in.IntrospectOrg = ptr(true)
		in.Scopes = &[]string{"openid", "api", "email"}
		in.Resources = &[]string{"https://api.example/b"}
	})
	x := h.exchange(api, apiSecret, at, url.Values{"resource": {"https://api.example/b"}})
	if x.status != 200 || x.str("issued_token_type") != tokenTypeAccess || x.str("token_type") != "Bearer" ||
		x.str("refresh_token") != "" || x.str("id_token") != "" || x.str("scope") != "openid email api" {
		t.Fatalf("exchange: %d %v", x.status, x.m)
	}
	xc := claimsOf(t, x.str("access_token"))
	act, _ := xc["act"].(map[string]any)
	aud, _ := xc["aud"].([]any)
	if xc["sub"] != h.user.ID || xc["client_id"] != api.ID || act["sub"] != api.ID || act["act"] != nil ||
		!slices.Equal(aud, []any{api.ID, "https://api.example/b"}) || xc["gid"] != subject["gid"] || xc["sid"] != subject["sid"] ||
		xc["exp"].(float64) > subject["exp"].(float64) {
		t.Fatalf("exchanged claims: %v", xc)
	}
	// introspection shows the actor
	if m := h.introspect(api, apiSecret, x.str("access_token")); m["active"] != true || m["act"].(map[string]any)["sub"] != api.ID {
		t.Fatalf("introspect: %v", m)
	}
	// a further exchange nests the actors
	next, nsecret := h.newClient(func(in *service.ClientInput) { withExchange(in); in.IntrospectOrg = ptr(true) })
	x2 := h.exchange(next, nsecret, x.str("access_token"), nil)
	if x2.status != 200 {
		t.Fatalf("second exchange: %d %v", x2.status, x2.m)
	}
	act2 := claimsOf(t, x2.str("access_token"))["act"].(map[string]any)
	if act2["sub"] != next.ID || act2["act"].(map[string]any)["sub"] != api.ID {
		t.Fatalf("nested act: %v", act2)
	}
	// revoking the exchanged token does not end the user's grant at the application
	if rr := h.clientPost(orgBase+"/oauth/revoke", url.Values{"token": {x.str("access_token")}}, api, apiSecret); rr.status != 200 {
		t.Fatalf("revoke: %d", rr.status)
	}
	if rf := h.refreshWith(app, asecret, rt); rf.status != 200 {
		t.Fatalf("grant ended by revoking an exchanged token: %v", rf.m)
	}
	// ending the grant ends the exchanged token
	if rr := h.clientPost(orgBase+"/oauth/revoke", url.Values{"token": {rt}}, app, asecret); rr.status != 200 {
		t.Fatal("revoke refresh")
	}
	h.p.InvalidateGrant(subject["gid"].(string))
	if _, err := h.p.VerifyAccessToken(context.Background(), x.str("access_token")); err == nil {
		t.Fatal("exchanged token outlived its grant")
	}
}

func TestTokenExchangeRules(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	app, asecret := h.newClient(withExchange)
	r, _ := h.login(app, asecret, url.Values{"scope": {"openid profile email api offline_access"}})
	at := r.str("access_token")

	// the application narrows its own token: no actor, a resource of its own
	x := h.exchange(app, asecret, at, url.Values{"scope": {"api"}, "audience": {"https://api.example/a"}})
	if x.status != 200 || x.str("scope") != "api" {
		t.Fatalf("self exchange: %d %v", x.status, x.m)
	}
	if xc := claimsOf(t, x.str("access_token")); xc["act"] != nil || xc["client_id"] != app.ID {
		t.Fatalf("self exchange claims: %v", xc)
	}
	// offline_access is not carried over
	if x := h.exchange(app, asecret, at, nil); x.str("scope") != "openid profile email api" {
		t.Fatalf("default scopes: %v", x.m)
	}

	bystander, bsecret := h.newClient(withExchange) // same organization, not an audience, no introspect_org
	plain, psecret := h.newClient(func(in *service.ClientInput) { in.IntrospectOrg = ptr(true) })
	cc := h.token(url.Values{"grant_type": {"client_credentials"}}, app, asecret).str("access_token")
	for name, tc := range map[string]struct {
		c      *model.Client
		secret string
		tok    string
		extra  url.Values
		code   string
	}{
		"not an audience":     {bystander, bsecret, at, nil, "invalid_grant"},
		"grant not enabled":   {plain, psecret, at, nil, "unauthorized_client"},
		"more scope":          {app, asecret, at, url.Values{"scope": {"api admin"}}, "invalid_scope"},
		"foreign resource":    {app, asecret, at, url.Values{"resource": {"https://other.example"}}, "invalid_target"},
		"client token":        {app, asecret, cc, nil, "invalid_grant"},
		"garbage":             {app, asecret, "garbage", nil, "invalid_grant"},
		"id token":            {app, asecret, r.str("id_token"), nil, "invalid_grant"},
		"refresh token":       {app, asecret, r.str("refresh_token"), nil, "invalid_grant"},
		"no subject":          {app, asecret, "", nil, "invalid_request"},
		"subject type":        {app, asecret, at, url.Values{"subject_token_type": {"urn:ietf:params:oauth:token-type:id_token"}}, "invalid_request"},
		"actor token":         {app, asecret, at, url.Values{"actor_token": {at}, "actor_token_type": {tokenTypeAccess}}, "invalid_request"},
		"requested refresh":   {app, asecret, at, url.Values{"requested_token_type": {"urn:ietf:params:oauth:token-type:refresh_token"}}, "invalid_request"},
		"wrong client secret": {app, "nope", at, nil, "invalid_client"},
	} {
		if x := h.exchange(tc.c, tc.secret, tc.tok, tc.extra); x.m["error"] != tc.code {
			t.Errorf("%s: %d %v", name, x.status, x.m)
		}
	}

	// another organization's resource server cannot exchange our users' tokens
	ctx := context.Background()
	org2, err := h.env.Svc.CreateOrg(ctx, h.admin, service.OrgInput{Name: ptr("acme"), DisplayName: ptr("Acme")})
	if err != nil {
		t.Fatal(err)
	}
	foreign, fsecret, err := h.env.Svc.CreateClient(ctx, h.admin, org2.ID, service.ClientInput{Name: ptr("foreign"),
		GrantTypes: &[]string{service.GrantTokenExchange}, IntrospectOrg: ptr(true), Scopes: &[]string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	if x := h.exchange(foreign, fsecret, at, nil); x.m["error"] != "invalid_grant" {
		t.Fatalf("foreign org: %v", x.m)
	}

	// a public client cannot have the grant
	if _, _, err := h.env.Svc.CreateClient(ctx, h.admin, h.env.Primary.ID, service.ClientInput{Name: ptr("spa"),
		AuthMethod: ptr(model.AuthMethodNone), RedirectURIs: &[]string{"https://spa.example/cb"},
		GrantTypes: &[]string{"authorization_code", service.GrantTokenExchange}}); err == nil {
		t.Fatal("public client with token exchange")
	}

	// the user must have access to the exchanging client
	h.env.Svc.UpdateUser(ctx, h.admin, h.user.ID, service.UserInput{Active: ptr(false)})
	h.p.users.clear()
	if x := h.exchange(app, asecret, at, nil); x.m["error"] != "invalid_grant" {
		t.Fatalf("disabled user: %v", x.m)
	}
}

func TestActDepthLimit(t *testing.T) {
	t.Parallel()
	c := &model.Client{Meta: model.Meta{ID: "c"}}
	act := ""
	for i := range maxActDepth {
		a, oe := exchangeActor(c, &Claims{ClientID: "other", Act: []byte(act)})
		if oe != nil {
			t.Fatalf("depth %d: %v", i, oe)
		}
		act = a
	}
	if _, oe := exchangeActor(c, &Claims{ClientID: "other", Act: []byte(act)}); oe == nil {
		t.Fatal("chain longer than the limit")
	}
	if _, oe := exchangeActor(c, &Claims{ClientID: "c", Act: []byte(act)}); oe != nil {
		t.Fatal("narrowing a token at the limit")
	}
	if actDepth([]byte(`"x"`)) != -1 {
		t.Fatal("non-object act")
	}
}
