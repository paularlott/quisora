package oidc

import (
	"context"
	"net/url"
	"slices"
	"strings"
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
	if rr := h.clientPost(h.orgBase+"/oauth/revoke", url.Values{"token": {x.str("access_token")}}, api, apiSecret); rr.status != 200 {
		t.Fatalf("revoke: %d", rr.status)
	}
	if rf := h.refreshWith(app, asecret, rt); rf.status != 200 {
		t.Fatalf("grant ended by revoking an exchanged token: %v", rf.m)
	}
	// ending the grant ends the exchanged token
	if rr := h.clientPost(h.orgBase+"/oauth/revoke", url.Values{"token": {rt}}, app, asecret); rr.status != 200 {
		t.Fatal("revoke refresh")
	}
	h.p.InvalidateGrant(subject["gid"].(string))
	if _, err := h.p.verifyAccessToken(context.Background(), x.str("access_token")); err == nil {
		t.Fatal("exchanged token outlived its grant")
	}
}

func TestTokenExchangeRules(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	app, asecret := h.newClient(withExchange)
	r, _ := h.login(app, asecret, url.Values{"scope": {"openid profile email api offline_access"}, "resource": {"https://api.example/a"}})
	at := r.str("access_token")

	// the application narrows its own token: no actor, a resource the user authorized
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
	h.p.users.Clear()
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

// A DPoP-bound subject token keeps its constraint: it is exchanged only with a proof of its own key, and the new token
// is bound to that key. Without this, an API that was sent the token (in its audience, or able to introspect the
// organization) could trade it for a bearer token.
func TestTokenExchangeKeepsDPoPBinding(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	app, secret := h.newClient(withExchange)
	k := newDPoPKey(t, AlgES256)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, app, ch, nil)
	tokenProof := func(k dpopKey) string { return h.proof(k, "POST", h.orgBase+"/oauth/token", nil) }
	r := h.tokenDPoP(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback},
		"code_verifier": {v}}, app, secret, tokenProof(k))
	if r.status != 200 || r.str("token_type") != "DPoP" {
		t.Fatalf("bound sign-in: %d %v", r.status, r.m)
	}
	at := r.str("access_token")
	form := url.Values{"grant_type": {service.GrantTokenExchange}, "subject_token": {at}, "subject_token_type": {tokenTypeAccess}}

	// a bearer request, or a proof of another key, does not get a token
	for name, proof := range map[string]string{"no proof": "", "other key": tokenProof(newDPoPKey(t, AlgEdDSA))} {
		if x := h.tokenDPoP(form, app, secret, proof); x.status != 400 || x.m["error"] != "invalid_grant" || x.str("access_token") != "" {
			t.Errorf("%s: %d %v", name, x.status, x.m)
		}
	}
	// a proof of its key does, and the new token is bound to that key
	x := h.tokenDPoP(form, app, secret, tokenProof(k))
	if x.status != 200 || x.str("token_type") != "DPoP" {
		t.Fatalf("exchange with the key: %d %v", x.status, x.m)
	}
	if cnf, _ := claimsOf(t, x.str("access_token"))["cnf"].(map[string]any); cnf["jkt"] != k.jkt {
		t.Fatalf("exchanged token's cnf: %v", claimsOf(t, x.str("access_token")))
	}
}

// adExchangeSetup is adSetup with the token exchange grant on its client.
func adExchangeSetup(t *testing.T) (*harness, *model.Client, string) {
	h, cl, secret := adSetup(t)
	if _, err := h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{
		GrantTypes: &[]string{"authorization_code", "refresh_token", service.GrantTokenExchange}}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	return h, cl, secret
}

// A token exchange never carries more authorization details than the subject token: the types the subject token
// carries bound the new token's, a request may narrow them further but not widen them, and the calling client's
// current access and types still apply.
func TestTokenExchangeKeepsAuthorizationDetails(t *testing.T) {
	t.Parallel()
	h, cl, secret := adExchangeSetup(t)
	topics := `{"actions":["subscribe"],"topics":[{"match":"https://chat.example/users/` + h.user.ID + `"}],"type":"` + topicsType + `"}`
	other := `{"identifier":"` + cl.TenantID + `","type":"` + otherType + `"}`
	adOf := func(types ...string) url.Values {
		var b strings.Builder
		for i, ty := range types {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`{"type":"` + ty + `"}`)
		}
		return url.Values{"authorization_details": {"[" + b.String() + "]"}}
	}

	// The authorization asked for one type (the client may have both): a self exchange that names none keeps to it.
	narrowed, _ := h.login(cl, secret, adOf(otherType))
	if got := detailsOf(t, claimsOf(t, narrowed.str("access_token"))); got != "["+other+"]" {
		t.Fatalf("subject token: %s", got)
	}
	x := h.exchange(cl, secret, narrowed.str("access_token"), nil)
	if x.status != 200 || detailsOf(t, claimsOf(t, x.str("access_token"))) != "["+other+"]" || detailsOf(t, x.m) != "["+other+"]" {
		t.Fatalf("self exchange of a narrowed token: %d %v", x.status, x.m)
	}
	// ... and one that names a type the subject token does not carry is refused, alone or with one it does
	for _, ad := range []url.Values{adOf(topicsType), adOf(otherType, topicsType)} {
		tokenErr(t, h.exchange(cl, secret, narrowed.str("access_token"), ad), 400, "invalid_authorization_details")
	}

	// A subject token with both types: a request narrows to one, and the narrowed token cannot be widened again.
	full, _ := h.login(cl, secret, nil)
	x = h.exchange(cl, secret, full.str("access_token"), adOf(topicsType))
	if x.status != 200 || detailsOf(t, claimsOf(t, x.str("access_token"))) != "["+topics+"]" || detailsOf(t, x.m) != "["+topics+"]" {
		t.Fatalf("narrowing exchange: %d %v", x.status, x.m)
	}
	again := h.exchange(cl, secret, x.str("access_token"), nil)
	if again.status != 200 || detailsOf(t, claimsOf(t, again.str("access_token"))) != "["+topics+"]" {
		t.Fatalf("exchange of an exchanged token: %d %v", again.status, again.m)
	}
	tokenErr(t, h.exchange(cl, secret, x.str("access_token"), adOf(otherType)), 400, "invalid_authorization_details")

	// The client lost a type since: the new token drops it, and naming it is refused (the client is no longer
	// registered for it), as at any token request.
	if _, err := h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{AuthorizationDetailsTypes: &[]string{topicsType}}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	x = h.exchange(cl, secret, full.str("access_token"), nil)
	if x.status != 200 || detailsOf(t, claimsOf(t, x.str("access_token"))) != "["+topics+"]" {
		t.Fatalf("type lost since: %d %v", x.status, x.m)
	}
	tokenErr(t, h.exchange(cl, secret, full.str("access_token"), adOf(otherType)), 400, "invalid_authorization_details")
	x = h.exchange(cl, secret, narrowed.str("access_token"), nil) // its only type is gone: none left
	if x.status != 200 || detailsOf(t, claimsOf(t, x.str("access_token"))) != "" {
		t.Fatalf("only type lost since: %d %v", x.status, x.m)
	}

	// A subject token with no details (the client had no types then) gets none, though the client has types now; the
	// response says nothing of details the request did not ask for.
	if _, err := h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{AuthorizationDetailsTypes: &[]string{}}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	bare, _ := h.login(cl, secret, nil)
	if _, err := h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{AuthorizationDetailsTypes: &[]string{topicsType, otherType}}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	x = h.exchange(cl, secret, bare.str("access_token"), nil)
	if _, stated := x.m["authorization_details"]; x.status != 200 || stated || detailsOf(t, claimsOf(t, x.str("access_token"))) != "" {
		t.Fatalf("subject without details: %d %v", x.status, x.m)
	}
	tokenErr(t, h.exchange(cl, secret, bare.str("access_token"), adOf(topicsType)), 400, "invalid_authorization_details")
}

// Another client exchanging a narrowed token is bound by it too: its own access gives no type the subject token lacks.
func TestTokenExchangeByOtherClientKeepsAuthorizationDetails(t *testing.T) {
	t.Parallel()
	h, cl, secret := adSetup(t)
	api, apiSecret := h.tenantClient(&model.Tenant{Meta: model.Meta{ID: cl.TenantID}}, func(in *service.ClientInput) {
		withExchange(in)
		in.IntrospectOrg = ptr(true)
		in.AuthorizationDetailsTypes = &[]string{topicsType, otherType}
	})
	narrowed, _ := h.login(cl, secret, url.Values{"authorization_details": {`[{"type":"` + otherType + `"}]`}})
	x := h.exchange(api, apiSecret, narrowed.str("access_token"), nil)
	if got := detailsOf(t, claimsOf(t, x.str("access_token"))); x.status != 200 || !strings.Contains(got, otherType) || strings.Contains(got, topicsType) {
		t.Fatalf("exchange by another client: %d %v", x.status, x.m)
	}
	tokenErr(t, h.exchange(api, apiSecret, narrowed.str("access_token"), url.Values{"authorization_details": {`[{"type":"` + topicsType + `"}]`}}),
		400, "invalid_authorization_details")
}

// A client exchanging its own token cannot add an API the user did not authorize (RFC 8707 §2.2, as for a refresh), nor
// regain scopes an earlier exchange dropped.
func TestSelfExchangeNeverWidens(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	app, asecret := h.newClient(withExchange)
	r, _ := h.login(app, asecret, url.Values{"scope": {"openid profile api"}, "resource": {"https://api.example/a"}})
	at := r.str("access_token")
	tokenErr(t, h.exchange(app, asecret, at, url.Values{"resource": {"https://api.example/b"}}), 400, "invalid_target")
	tokenErr(t, h.exchange(app, asecret, at, url.Values{"resource": {"https://api.example/a"}, "audience": {"https://api.example/b"}}), 400, "invalid_target")
	x := h.exchange(app, asecret, at, url.Values{"resource": {"https://api.example/a"}, "scope": {"api"}})
	if aud, _ := claimsOf(t, x.str("access_token"))["aud"].([]any); x.status != 200 || !slices.Equal(aud, []any{app.ID, "https://api.example/a"}) {
		t.Fatalf("self exchange for the authorized API: %d %v", x.status, x.m)
	}
	// the exchanged token names one API and one scope: exchanging it again cannot bring back the others
	tokenErr(t, h.exchange(app, asecret, x.str("access_token"), url.Values{"scope": {"openid api"}}), 400, "invalid_scope")
	y := h.exchange(app, asecret, x.str("access_token"), nil)
	if y.status != 200 || y.str("scope") != "api" {
		t.Fatalf("exchange of an exchanged token: %d %v", y.status, y.m)
	}
	// without a resource the new token is for the client alone, so it cannot be widened back to the API either
	tokenErr(t, h.exchange(app, asecret, y.str("access_token"), url.Values{"resource": {"https://api.example/a"}}), 400, "invalid_target")
}
