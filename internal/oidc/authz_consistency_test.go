package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// Authorization consistency: every decision that depends on a store read fails closed when the read fails (503
// temporarily_unavailable, never "allowed" and never "revoked"), the same checks apply wherever a token is
// presented, and a revocation that did not persist is reported as such and never audited as done.

// Introspection and userinfo make the same access decision, and an access entry that cannot be read is answered as 503,
// not as active (the resource would serve a token whose access may be gone) nor as inactive (it would refuse a user
// whose access is fine, who would then sign in again for a store hiccup).
func TestIntrospectionAndUserinfoFailClosedOnAccessReadFailure(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret, tokens := h.membersOnlyLogin("introspect-access-read")
	at, rt := tokens.str("access_token"), tokens.str("refresh_token")
	good := h.env.Svc.Access.S
	h.env.Svc.Access.S = failReads(good, model.KindAccess)
	for _, tok := range []string{at, rt} {
		r := h.post("/oauth/introspect", url.Values{"token": {tok}, "client_id": {cl.ID}, "client_secret": {secret}}, "", "")
		expectUnavailable(t, "introspect with unreadable access", r)
	}
	ui := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+at)
	if text := body(ui); ui.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("userinfo with unreadable access: %d %s", ui.StatusCode, text)
	}
	h.env.Svc.Access.S = good
	for _, tok := range []string{at, rt} {
		if m := h.introspect(cl, secret, tok); m["active"] != true {
			t.Fatalf("token inactive once the store answers again: %v", m)
		}
	}
	if ui := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+at); ui.StatusCode != http.StatusOK {
		t.Fatalf("userinfo once the store answers again: %d %s", ui.StatusCode, body(ui))
	}
}

// A refresh token whose grant cannot be read is not "invalid, expired or revoked" (which makes the client throw it
// away and sign the user in again): the token endpoint says it cannot decide now, and the token works afterwards.
func TestRefreshFailsClosedOnStoreReadFailures(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret, tokens := h.membersOnlyLogin("refresh-read-failures")
	rt := tokens.str("refresh_token")
	grants, access := h.env.Svc.Grants.S, h.env.Svc.Access.S

	h.env.Svc.Grants.S = failReads(grants, model.KindGrant)
	expectUnavailable(t, "refresh with unreadable grant", h.refreshWith(cl, secret, rt))
	h.env.Svc.Grants.S = grants

	h.env.Svc.Access.S = failReads(access, model.KindAccess)
	expectUnavailable(t, "refresh with unreadable access", h.refreshWith(cl, secret, rt))
	h.env.Svc.Access.S = access

	// Refresh-token introspection reads the same grant: the same answer.
	h.env.Svc.Grants.S = failReads(grants, model.KindGrant)
	r := h.post("/oauth/introspect", url.Values{"token": {rt}, "client_id": {cl.ID}, "client_secret": {secret}}, "", "")
	expectUnavailable(t, "introspect refresh token with unreadable grant", r)
	h.env.Svc.Grants.S = grants

	users := h.env.Svc.Users.S
	h.env.Svc.Users.S = failReads(users, model.KindUser)
	h.p.users.clear()
	expectUnavailable(t, "refresh with unreadable user", h.refreshWith(cl, secret, rt))
	h.env.Svc.Users.S = users
	h.p.users.clear()

	if r := h.refreshWith(cl, secret, rt); r.status != 200 {
		t.Fatalf("refresh once the store answers again: %d %v", r.status, r.m)
	}

	// a grant without offline_access lives with its session: one that cannot be read is not an answer
	plain, plainSecret := h.newClient(nil)
	short, _ := h.login(plain, plainSecret, url.Values{"scope": {"openid"}})
	srt := short.str("refresh_token")
	sessions := h.env.Svc.Sessions.S
	h.env.Svc.Sessions.S = failReads(sessions, model.KindSession)
	h.p.InvalidateGrant(strings.SplitN(srt, ".", 2)[0])
	expectUnavailable(t, "refresh with unreadable session", h.refreshWith(plain, plainSecret, srt))
	h.env.Svc.Sessions.S = sessions
	if r := h.refreshWith(plain, plainSecret, srt); r.status != 200 {
		t.Fatalf("session-bound refresh once the store answers again: %d %v", r.status, r.m)
	}
}

// The groups an access decision depends on (a user allowed through a group) that cannot be read: userinfo waits
// (503) rather than deciding from no groups and telling the user their access was taken away.
func TestUserinfoFailsClosedWhenGroupsCannotBeRead(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret, tokens := h.membersOnlyLogin("userinfo-groups-read")
	at := tokens.str("access_token")
	members := h.env.Svc.Members.S
	h.env.Svc.Members.S = failLists(members, model.KindMember)
	h.p.InvalidateMembership(h.env.Primary.ID) // the sign-in cached the groups; a change makes them be read again
	ui := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+at)
	if text := body(ui); ui.StatusCode != http.StatusServiceUnavailable || ui.Header.Get("WWW-Authenticate") != "" {
		t.Fatalf("userinfo with unreadable groups: %d %q %s", ui.StatusCode, ui.Header.Get("WWW-Authenticate"), text)
	}
	r := h.post("/oauth/introspect", url.Values{"token": {at}, "client_id": {cl.ID}, "client_secret": {secret}}, "", "")
	expectUnavailable(t, "introspect with unreadable groups", r)
	h.env.Svc.Members.S = members
	if ui := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+at); ui.StatusCode != 200 {
		t.Fatalf("userinfo once the store answers again: %d %s", ui.StatusCode, body(ui))
	}
}

// A token exchange checks the user's access to the calling client as a sign-in would, and an access that cannot be
// read issues nothing (503) instead of a refusal the caller would take as final.
func TestTokenExchangeFailsClosedOnAccessReadFailure(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	app, asecret := h.newClient(nil)
	r, _ := h.login(app, asecret, url.Values{"scope": {"openid profile email api offline_access"}})
	at := r.str("access_token")
	tn := h.tenant("exchange-access-read", membersOnly())
	api, apiSecret := h.tenantClient(tn, func(in *service.ClientInput) {
		withExchange(in)
		in.IntrospectOrg = ptr(true)
		in.Scopes = &[]string{"openid", "api", "email"}
		in.Resources = &[]string{"https://api.example/b"}
	})
	h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{})
	if x := h.exchange(api, apiSecret, at, url.Values{"resource": {"https://api.example/b"}}); x.status != 200 {
		t.Fatalf("control: exchange %d %v", x.status, x.m)
	}
	good := h.env.Svc.Access.S
	h.env.Svc.Access.S = failReads(good, model.KindAccess)
	expectUnavailable(t, "exchange with unreadable access", h.exchange(api, apiSecret, at, url.Values{"resource": {"https://api.example/b"}}))
}

// Revoking an access token ends its grant; when the deletion fails the client is told so (503, RFC 7009 §2.2.1), no
// revocation is audited, and the retry (once the store answers) really ends the grant, rather than answering 200 to a
// cached "nothing to revoke".
func TestRevocationFailureIsReportedAndNotAudited(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	tokens, _ := h.login(cl, secret, nil)
	at, rt := tokens.str("access_token"), tokens.str("refresh_token")
	good := h.env.Svc.Grants.S
	h.env.Svc.Grants.S = failDeletes(good, model.KindGrant)
	r := h.post("/oauth/revoke", url.Values{"token": {at}, "client_id": {cl.ID}, "client_secret": {secret}}, "", "")
	expectUnavailable(t, "revoke with failing deletion", r)
	if n := len(h.auditEvents("oauth.revoke")); n != 0 {
		t.Fatalf("a revocation that did not happen was audited (%d events)", n)
	}
	if h.refreshWith(cl, secret, rt).status != 200 {
		t.Fatal("control: the grant should still work, the deletion failed")
	}
	h.env.Svc.Grants.S = good
	if r := h.post("/oauth/revoke", url.Values{"token": {at}, "client_id": {cl.ID}, "client_secret": {secret}}, "", ""); r.status != 200 {
		t.Fatalf("retry: %d %v", r.status, r.m)
	}
	if n := len(h.auditEvents("oauth.revoke")); n != 1 {
		t.Fatalf("revocation audited %d times, want 1", n)
	}
	if h.refreshWith(cl, secret, rt).status == 200 {
		t.Fatal("the grant survived a revocation that answered 200")
	}

	// revoking the refresh token itself is the handler's other branch
	again, _ := h.login(cl, secret, nil)
	rt = again.str("refresh_token")
	h.env.Svc.Grants.S = failDeletes(good, model.KindGrant)
	r = h.post("/oauth/revoke", url.Values{"token": {rt}, "client_id": {cl.ID}, "client_secret": {secret}}, "", "")
	expectUnavailable(t, "revoke refresh token with failing deletion", r)
	if h.refreshWith(cl, secret, rt).status != 200 {
		t.Fatal("control: the grant should still work, the deletion failed")
	}
	h.env.Svc.Grants.S = good
	if r := h.post("/oauth/revoke", url.Values{"token": {rt}, "client_id": {cl.ID}, "client_secret": {secret}}, "", ""); r.status != 200 {
		t.Fatalf("retry: %d %v", r.status, r.m)
	}
	if h.refreshWith(cl, secret, rt).status == 200 {
		t.Fatal("the grant survived a refresh token revocation that answered 200")
	}
}

// A code exchange that cannot read what it depends on (the user's session, the sign-out counters) or write the grant
// it creates answers 503, not "the user's session has ended" or a refusal the client takes as final.
func TestCodeExchangeFailsClosedOnStoreFailures(t *testing.T) {
	t.Parallel()
	for name, fault := range map[string]func(h *harness){
		"session unreadable": func(h *harness) { h.env.Svc.Sessions.S = failReads(h.env.Svc.Sessions.S, model.KindSession) },
		"sign-out counters unreadable": func(h *harness) {
			h.env.Svc.InvalidateSignOut()
			h.env.Svc.Orgs.S = failReads(h.env.Svc.Orgs.S, model.KindOrg)
		},
		"grant not writable": func(h *harness) {
			h.env.Svc.Grants.S = failCAS(h.env.Svc.Grants.S, model.KindGrant, func() error { return store.ErrNotWritable })
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := setup(t, nil)
			cl, secret := h.newClient(nil)
			c, _ := h.session(h.user)
			v, ch := pkce()
			code := h.getCode(c, cl, ch, nil)
			fault(h)
			r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
				"code_verifier": {v}}, cl, secret)
			expectUnavailable(t, name, r)
		})
	}
}

// RP-initiated logout whose session deletion fails tells the user so (503) instead of sending the browser to the
// relying party's signed-out page: the session is still in the store, and a refresh grant of it still works.
func TestLogoutReportsFailureWhenSessionCannotBeEnded(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.PostLogoutURIs = &[]string{"https://rp.example/bye"} })
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}, cl, secret)
	idt := r.str("id_token")
	sid, _ := claimsOf(t, idt)["sid"].(string)
	if sid == "" {
		t.Fatalf("no sid: %v", r.m)
	}
	good := h.env.Svc.Sessions.S
	h.env.Svc.Sessions.S = failDeletes(good, model.KindSession)
	q := url.Values{"id_token_hint": {idt}, "post_logout_redirect_uri": {"https://rp.example/bye"}, "state": {"s"}}
	resp := h.get(c, "/oauth/logout?"+q.Encode())
	if text := body(resp); resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Location") != "" {
		t.Fatalf("logout with failing deletion: %d %q %s", resp.StatusCode, resp.Header.Get("Location"), text)
	}
	if _, err := h.env.Svc.Sessions.Get(context.Background(), sid); err != nil {
		t.Fatalf("control: the session should still exist: %v", err)
	}
	h.env.Svc.Sessions.S = good
}

// A sign-in flow or a code that cannot be stored, an organization that cannot be read and an access entry that cannot be
// read all end the request without issuing a code.
func TestAuthorizeFailsClosedOnStoreFailures(t *testing.T) {
	t.Parallel()
	boom := errors.New("ephemeral down")
	t.Run("flow store", func(t *testing.T) {
		h := setup(t, nil)
		cl, _ := h.newClient(nil)
		_, ch := pkce()
		h.useEph(func(op, ns string) error {
			if op == "new" && ns == nsFlow {
				return boom
			}
			return nil
		})
		if u := h.authorize(h.anon(), authzQuery(cl, ch, nil)); u.Query().Get("error") != "server_error" {
			t.Fatalf("flow: %s", u)
		}
	})
	t.Run("code store", func(t *testing.T) {
		h := setup(t, nil)
		cl, _ := h.newClient(nil)
		c, _ := h.session(h.user)
		_, ch := pkce()
		h.useEph(func(op, ns string) error {
			if op == "new" && ns == nsCode {
				return boom
			}
			return nil
		})
		if u := h.authorize(c, authzQuery(cl, ch, nil)); u.Query().Get("error") != "server_error" {
			t.Fatalf("code: %s", u)
		}
	})
	// the application cannot be resolved without its organization: try again later, no redirect and no code
	t.Run("organization unreadable", func(t *testing.T) {
		h := setup(t, nil)
		cl, _ := h.newClient(nil)
		c, _ := h.session(h.user)
		_, ch := pkce()
		h.env.Svc.Orgs.S = failReads(h.env.Svc.Orgs.S, model.KindOrg)
		h.p.orgs.clear()
		h.p.clients.clear()
		resp := h.get(c, "/oauth/authorize?"+authzQuery(cl, ch, nil).Encode())
		if body(resp); resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Location") != "" {
			t.Fatalf("unreadable organization: %d %q", resp.StatusCode, resp.Header.Get("Location"))
		}
	})
	t.Run("access entry unreadable", func(t *testing.T) {
		h := setup(t, nil)
		tn := h.tenant("cov-access-read", membersOnly())
		cl, _ := h.tenantClient(tn, nil)
		h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{})
		c, _ := h.session(h.user)
		_, ch := pkce()
		h.env.Svc.Access.S = failReads(h.env.Svc.Access.S, model.KindAccess)
		if u := h.authorize(c, authzQuery(cl, ch, nil)); u.Query().Get("error") != "server_error" {
			t.Fatalf("%s", u)
		}
	})
}

// A code store that fails when the code is taken, and signing keys that cannot be read when tokens are made, answer
// 500; a refresh that failed at signing is served again when retried (it is the lost-response retry).
func TestTokenEndpointFailsClosedOnEphemeralAndKeyFailures(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	c, _ := h.session(h.user)
	v, ch := pkce()
	exch := func(code, verifier string) tokResp {
		return h.exchangeCode(cl, secret, code, verifier)
	}
	// the code store fails when the code is taken
	code := h.getCode(c, cl, ch, nil)
	h.useEph(func(op, ns string) error {
		if op == "take" && ns == nsCode {
			return errors.New("ephemeral down")
		}
		return nil
	})
	if r := exch(code, v); r.status != 500 {
		t.Fatalf("take: %d %v", r.status, r.m)
	}
	h.useEph(nil)

	// the signing keys cannot be read when the tokens are made
	code = h.getCode(c, cl, ch, nil)
	r, _ := h.login(cl, secret, nil)
	keys := h.env.Svc.Keys.S
	h.env.Svc.Keys.S = failLists(keys, model.KindKey)
	h.p.Invalidate()
	if x := exch(code, v); x.status != 500 {
		t.Fatalf("exchange: %d %v", x.status, x.m)
	}
	if x := h.refreshWith(cl, secret, r.str("refresh_token")); x.status != 500 {
		t.Fatalf("refresh: %d %v", x.status, x.m)
	}
	h.env.Svc.Keys.S = keys
	h.p.Invalidate()
	if x := h.refreshWith(cl, secret, r.str("refresh_token")); x.status != 200 {
		t.Fatalf("retry of the refresh that failed at signing: %d %v", x.status, x.m)
	}
}

func TestLogoutConfirmationFailsClosed(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) { in.PostLogoutURIs = &[]string{"https://rp.example/bye"} })
	c, _ := h.session(h.user)
	// no hint: the confirmation page needs a place to keep the request
	h.useEph(func(op, ns string) error {
		if op == "new" && ns == nsLogout {
			return errors.New("ephemeral down")
		}
		return nil
	})
	resp := h.get(c, "/oauth/logout?client_id="+cl.ID)
	if body(resp); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("confirmation: %d", resp.StatusCode)
	}
	h.useEph(func(string, string) error { return nil })
	// a hint signed by a key the server does not publish under that algorithm
	ks, _ := h.p.keys(context.Background())
	var other assertionKey
	for _, k := range newAssertionKeys(t) {
		if k.alg != ks.list[0].alg {
			other = k
		}
	}
	tok, err := signJWT(other.alg, other.priv, mkHeader(other.alg, ks.list[0].kid, typJWT), mustJSON(map[string]any{"iss": h.p.issuer, "aud": cl.ID, "sub": h.user.ID}))
	if err != nil {
		t.Fatal(err)
	}
	resp = h.get(c, "/oauth/logout?id_token_hint="+tok)
	if body(resp); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("hint with the wrong algorithm: %d", resp.StatusCode)
	}
	// the confirmed sign-out cannot end the session
	resp = h.get(c, "/oauth/logout")
	page := body(resp)
	id, pageCSRF := regexpValue(page, "id"), regexpValue(page, "csrf")
	sessions := h.env.Svc.Sessions.S
	h.env.Svc.Sessions.S = failDeletes(sessions, model.KindSession)
	confirm := func() *http.Response {
		return h.confirmLogout(c, url.Values{"id": {id}, "csrf": {pageCSRF}}.Encode())
	}
	if resp := confirm(); body(resp) == "" || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("confirm with a failing deletion: %d", resp.StatusCode)
	}
	h.env.Svc.Sessions.S = sessions
	// the request was used up: ask again, and this time it ends with the plain page (no address to return to)
	page = body(h.get(c, "/oauth/logout"))
	id, pageCSRF = regexpValue(page, "id"), regexpValue(page, "csrf")
	resp = confirm()
	if pg := body(resp); resp.StatusCode != 200 || !strings.Contains(pg, "signed out") {
		t.Fatalf("confirm: %d %s", resp.StatusCode, pg)
	}
}

// An access token, its revocation and its introspection each depend on stored state (the application, the user, the
// grant, the organization); one that cannot be read is "cannot decide now", never "invalid".
func TestAccessTokenChecksFailClosedOnUnreadableStores(t *testing.T) {
	t.Parallel()
	// each subtest has its own provider, so one failing store cannot leak into the next
	login := func(t *testing.T) (h *harness, cl *model.Client, secret string, r tokResp) {
		h = setup(t, nil)
		cl, secret = h.newClient(nil)
		r, _ = h.login(cl, secret, nil)
		return
	}
	t.Run("client", func(t *testing.T) {
		h, cl, _, _ := login(t)
		h.env.Svc.Clients.S = failReads(h.env.Svc.Clients.S, model.KindClient)
		h.p.InvalidateClient(cl.ID)
		if _, err := h.p.VerifyAccessToken(t.Context(), h.forgeAccess(cl, nil)); !isUnavailable(err) {
			t.Fatalf("client read: %v", err)
		}
	})
	t.Run("user", func(t *testing.T) {
		h, _, _, r := login(t)
		at := r.str("access_token")
		h.env.Svc.Users.S = failReads(h.env.Svc.Users.S, model.KindUser)
		h.p.users.clear()
		if _, err := h.p.VerifyAccessToken(t.Context(), at); !isUnavailable(err) {
			t.Fatalf("user read: %v", err)
		}
		ui := h.get(h.http, "/oauth/userinfo", "Authorization", "Bearer "+at)
		if body(ui); ui.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("userinfo with unreadable user: %d", ui.StatusCode)
		}
	})
	t.Run("grant", func(t *testing.T) {
		h, cl, secret, r := login(t)
		at := r.str("access_token")
		h.env.Svc.Grants.S = failReads(h.env.Svc.Grants.S, model.KindGrant)
		h.p.InvalidateGrant(claimsOf(t, at)["gid"].(string))
		if _, err := h.p.VerifyAccessToken(t.Context(), at); !isUnavailable(err) {
			t.Fatalf("grant read: %v", err)
		}
		// revocation and introspection cannot decide either
		f := url.Values{"token": {at}, "client_id": {cl.ID}, "client_secret": {secret}}
		expectUnavailable(t, "revoke", h.post("/oauth/revoke", f, "", ""))
		expectUnavailable(t, "introspect", h.post("/oauth/introspect", f, "", ""))
		f.Set("token", r.str("refresh_token"))
		expectUnavailable(t, "revoke refresh", h.post("/oauth/revoke", f, "", ""))
	})
	t.Run("organization", func(t *testing.T) {
		h, _, _, r := login(t)
		h.env.Svc.Orgs.S = failReads(h.env.Svc.Orgs.S, model.KindOrg)
		h.p.orgs.clear()
		h.p.users.clear()
		if _, err := h.p.VerifyAccessToken(t.Context(), r.str("access_token")); !isUnavailable(err) {
			t.Fatalf("org read: %v", err)
		}
	})
	t.Run("token exchange subject", func(t *testing.T) {
		h := setup(t, nil)
		app, secret := h.newClient(withExchange)
		r, _ := h.login(app, secret, url.Values{"scope": {"openid profile email api"}})
		h.env.Svc.Users.S = failReads(h.env.Svc.Users.S, model.KindUser)
		h.p.users.clear()
		expectUnavailable(t, "exchange", h.exchange(app, secret, r.str("access_token"), nil))
	})
}

// Authorization approved by a session that has since ended (a credentials reset moved the epoch, an emergency sign-out
// invalidated its stamp) issues nothing, even when the physical deletion of the session failed or has not run yet:
// deletion is only housekeeping.
func TestOutstandingAuthorizationEndsWithSessionEpoch(t *testing.T) {
	t.Parallel()
	t.Run("credentials reset with failing session cleanup", func(t *testing.T) {
		h := setup(t, nil)
		ctx := context.Background()
		cl, secret := h.newClient(nil)
		browser, _ := h.session(h.user)
		verifier, challenge := pkce()
		code := h.getCode(browser, cl, challenge, nil)
		h.resetCredentialsWithFailingCleanup()
		r := h.exchangeCode(cl, secret, code, verifier)
		if r.status == 200 {
			_, verifyErr := h.p.VerifyAccessToken(ctx, r.str("access_token"))
			refreshed := h.refreshWith(cl, secret, r.str("refresh_token"))
			t.Fatalf("authorization from a passed session epoch issued new tokens: access verification=%v refresh status=%d", verifyErr, refreshed.status)
		}
		tokenErr(t, r, 400, "invalid_grant")
	})
	t.Run("organization sign-out", func(t *testing.T) {
		h := setup(t, nil)
		ctx := context.Background()
		cl, secret := h.newClient(nil)
		browser, _ := h.session(h.user)
		verifier, challenge := pkce()
		code := h.getCode(browser, cl, challenge, nil)
		if _, err := h.env.Svc.SignOutOrg(ctx, service.System, h.user.OrgID, service.SignOutOptions{Reason: "outstanding code"}); err != nil {
			t.Fatal(err)
		}
		r := h.exchangeCode(cl, secret, code, verifier)
		if r.status == 200 {
			_, verifyErr := h.p.VerifyAccessToken(ctx, r.str("access_token"))
			t.Fatalf("authorization from a signed-out session issued tokens with current counters: access verification=%v", verifyErr)
		}
		tokenErr(t, r, 400, "invalid_grant")
	})
	t.Run("approved device grant", func(t *testing.T) {
		h := setup(t, nil)
		cl := h.deviceClient(nil)
		dc, uc := h.startDevice(cl, "openid profile offline_access")
		browser, csrf := h.session(h.user)
		if status, page := h.consentDevice(browser, csrf, uc, true); status != 200 {
			t.Fatalf("approval: %d %s", status, page)
		}
		h.resetCredentialsWithFailingCleanup()
		if r := h.pollDevice(cl, dc); r.status != 400 || r.str("error") != "invalid_grant" {
			t.Fatalf("approved device authorization outlived session epoch: %d %v", r.status, r.m)
		}
	})
}

// resetCredentialsWithFailingCleanup resets the user's credentials (moving the session epoch) while the deletion of
// their sessions fails, as the production user-change notification then reaches the provider.
func (h *harness) resetCredentialsWithFailingCleanup() {
	h.t.Helper()
	base := h.env.Svc.Store
	h.env.Svc.Store = failDeletes(base, model.KindSession)
	err := h.env.Svc.ResetCredentials(context.Background(), h.user.ID)
	h.env.Svc.Store = base
	if err == nil {
		h.t.Fatal("setup: expected the injected cleanup error")
	}
	current, err := h.env.Svc.Users.Get(context.Background(), h.user.ID)
	if err != nil {
		h.t.Fatal(err)
	}
	if current.CredEpoch == h.user.CredEpoch {
		h.t.Fatal("reset did not commit a new epoch")
	}
	h.p.InvalidateUser(h.user.ID)
}

// landsUnconfirmed stores a grant and then answers that its outcome is unknown (the cluster lost contact before it
// confirmed the write).
type landsUnconfirmed struct{ store.Store }

func (s landsUnconfirmed) CompareAndPut(ctx context.Context, r *store.Record, expect hlc.Timestamp) error {
	if err := s.Store.CompareAndPut(ctx, r, expect); err != nil || r.Kind != model.KindGrant {
		return err
	}
	return store.ErrUnconfirmed
}

// A code exchange that failed on our side once its grant may be stored puts the code back for the retry; the retry
// that succeeds removes that grant (nobody holds its tokens), so only the grant it hands out is left.
func TestCodeExchangeRetryRemovesTheGrantItAbandoned(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	good := h.env.Svc.Grants.S
	h.env.Svc.Grants.S = landsUnconfirmed{good}
	expectUnavailable(t, "unconfirmed grant", h.exchangeCode(cl, secret, code, v))
	h.env.Svc.Grants.S = good
	if r := h.exchangeCode(cl, secret, code, v); r.status != 200 {
		t.Fatalf("retry: %d %v", r.status, r.m)
	}
	h.env.Svc.WaitBackground()
	grants, err := h.env.Svc.Store.List(context.Background(), model.KindGrant, store.ListQuery{})
	if err != nil || len(grants.Records) != 1 {
		t.Fatalf("grants left: %v %v", grants, err)
	}
}
