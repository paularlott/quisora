package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

// Authorization consistency: every decision that depends on a store read fails closed when the read fails (503
// temporarily_unavailable, never "allowed" and never "revoked"), the same checks apply wherever a token is
// presented, and a revocation that did not persist is reported as such and never audited as done.

// failReads fails every Get of one kind (an access entry, a grant, a session, an organization ...).
type failReads struct {
	store.Store
	kind model.Kind
}

func (s failReads) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == s.kind {
		return nil, errors.New("consistency: read failed")
	}
	return s.Store.Get(ctx, kind, id)
}

// failLists fails every List of one kind (a user's memberships).
type failLists struct {
	store.Store
	kind model.Kind
}

func (s failLists) List(ctx context.Context, kind model.Kind, q store.ListQuery) (*store.ListResult, error) {
	if kind == s.kind {
		return nil, errors.New("consistency: list failed")
	}
	return s.Store.List(ctx, kind, q)
}

// failDeletes fails every deletion (tombstone) of one kind.
type failDeletes struct {
	store.Store
	kind model.Kind
}

func (s failDeletes) Put(ctx context.Context, r *store.Record) error {
	if r.Kind == s.kind && r.Deleted {
		return errors.New("consistency: deletion failed")
	}
	return s.Store.Put(ctx, r)
}

func expectUnavailable(t testing.TB, what string, r tokResp) {
	t.Helper()
	if r.status != http.StatusServiceUnavailable || r.str("error") != "temporarily_unavailable" {
		t.Fatalf("%s: %d %v, want 503 temporarily_unavailable", what, r.status, r.m)
	}
}

// membersOnlyLogin signs the user in to a client of a members-only tenant they have access to.
func (h *harness) membersOnlyLogin(name string) (*model.Client, string, tokResp) {
	h.t.Helper()
	tn := h.tenant(name, membersOnly())
	cl, secret := h.tenantClient(tn, nil)
	h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{})
	tokens, _ := h.login(cl, secret, orgScope)
	if tokens.status != 200 || tokens.str("access_token") == "" || tokens.str("refresh_token") == "" {
		h.t.Fatalf("login: %d %v", tokens.status, tokens.m)
	}
	return cl, secret, tokens
}

// Introspection makes the same access decision as userinfo, and an access entry that cannot be read is answered as
// 503, not as active (the resource would serve a token whose access may be gone) nor as inactive (it would refuse a
// user whose access is fine, who would then sign in again for a store hiccup).
func TestIntrospectionFailsClosedOnAccessReadFailure(t *testing.T) {
	h := setup(t, nil)
	cl, secret, tokens := h.membersOnlyLogin("introspect-access-read")
	at, rt := tokens.str("access_token"), tokens.str("refresh_token")
	good := h.env.Svc.Access.S
	h.env.Svc.Access.S = failReads{Store: good, kind: model.KindAccess}
	for _, tok := range []string{at, rt} {
		r := h.post("/oauth/introspect", url.Values{"token": {tok}, "client_id": {cl.ID}, "client_secret": {secret}}, "", "")
		expectUnavailable(t, "introspect with unreadable access", r)
	}
	h.env.Svc.Access.S = good
	for _, tok := range []string{at, rt} {
		if m := h.introspect(cl, secret, tok); m["active"] != true {
			t.Fatalf("token inactive once the store answers again: %v", m)
		}
	}
}

// A refresh token whose grant cannot be read is not "invalid, expired or revoked" (which makes the client throw it
// away and sign the user in again): the token endpoint says it cannot decide now, and the token works afterwards.
func TestRefreshFailsClosedOnStoreReadFailures(t *testing.T) {
	h := setup(t, nil)
	cl, secret, tokens := h.membersOnlyLogin("refresh-read-failures")
	rt := tokens.str("refresh_token")
	grants, access := h.env.Svc.Grants.S, h.env.Svc.Access.S

	h.env.Svc.Grants.S = failReads{Store: grants, kind: model.KindGrant}
	expectUnavailable(t, "refresh with unreadable grant", h.refreshWith(cl, secret, rt))
	h.env.Svc.Grants.S = grants

	h.env.Svc.Access.S = failReads{Store: access, kind: model.KindAccess}
	expectUnavailable(t, "refresh with unreadable access", h.refreshWith(cl, secret, rt))
	h.env.Svc.Access.S = access

	// Refresh-token introspection reads the same grant: the same answer.
	h.env.Svc.Grants.S = failReads{Store: grants, kind: model.KindGrant}
	r := h.post("/oauth/introspect", url.Values{"token": {rt}, "client_id": {cl.ID}, "client_secret": {secret}}, "", "")
	expectUnavailable(t, "introspect refresh token with unreadable grant", r)
	h.env.Svc.Grants.S = grants

	if r := h.refreshWith(cl, secret, rt); r.status != 200 {
		t.Fatalf("refresh once the store answers again: %d %v", r.status, r.m)
	}
}

// The groups an access decision depends on (a user allowed through a group) that cannot be read: userinfo waits
// (503) rather than deciding from no groups and telling the user their access was taken away.
func TestUserinfoFailsClosedWhenGroupsCannotBeRead(t *testing.T) {
	h := setup(t, nil)
	cl, secret, tokens := h.membersOnlyLogin("userinfo-groups-read")
	at := tokens.str("access_token")
	members := h.env.Svc.Members.S
	h.env.Svc.Members.S = failLists{Store: members, kind: model.KindMember}
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
	h.env.Svc.Access.S = failReads{Store: good, kind: model.KindAccess}
	expectUnavailable(t, "exchange with unreadable access", h.exchange(api, apiSecret, at, url.Values{"resource": {"https://api.example/b"}}))
}

// Revoking an access token ends its grant; when the deletion fails the client is told so (503, RFC 7009 §2.2.1), no
// revocation is audited, and the retry (once the store answers) really ends the grant, rather than answering 200 to a
// cached "nothing to revoke".
func TestRevocationFailureIsReportedAndNotAudited(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	tokens, _ := h.login(cl, secret, nil)
	at, rt := tokens.str("access_token"), tokens.str("refresh_token")
	good := h.env.Svc.Grants.S
	h.env.Svc.Grants.S = failDeletes{Store: good, kind: model.KindGrant}
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
}

// The user's session, read when a code is exchanged, that cannot be read: 503, not "the user's session has ended".
func TestCodeExchangeFailsClosedWhenSessionCannotBeRead(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	good := h.env.Svc.Sessions.S
	h.env.Svc.Sessions.S = failReads{Store: good, kind: model.KindSession}
	defer func() { h.env.Svc.Sessions.S = good }()
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}, cl, secret)
	expectUnavailable(t, "code exchange with unreadable session", r)
}

// RP-initiated logout whose session deletion fails tells the user so (503) instead of sending the browser to the
// relying party's signed-out page: the session is still in the store, and a refresh grant of it still works.
func TestLogoutReportsFailureWhenSessionCannotBeEnded(t *testing.T) {
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
	h.env.Svc.Sessions.S = failDeletes{Store: good, kind: model.KindSession}
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
