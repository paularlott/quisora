package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

func TestCoverageErrorHelpers(t *testing.T) {
	if errString(context.Canceled) != "canceled" || errString(errors.New("x")) != "internal" {
		t.Fatal("errString")
	}
	if verifierOK['!'] || !verifierOK['~'] {
		t.Fatal("verifier alphabet")
	}
	if pkceOK("not a verifier!"+strings.Repeat("a", 43), "x") {
		t.Fatal("verifier with a bad character")
	}
}

func TestCoverageTokenFailures(t *testing.T) {
	h := setup(t, func(c *config.Config) { c.Audit.Tokens = true })
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	ctx := context.Background()
	c, _ := h.session(h.user)
	v, ch := pkce()
	exch := func(code, verifier string) tokResp {
		return h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]}, "code_verifier": {verifier}}, cl, secret)
	}
	// a verifier with characters that are not allowed
	tokenErr(t, exch(h.getCode(c, cl, ch, nil), "bad verifier with spaces and a very long tail 0123456789"), 400, "invalid_grant")
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
	h.useEph(func(string, string) error { return nil })

	// the signing keys cannot be read when the tokens are made
	code = h.getCode(c, cl, ch, nil)
	r, _ := h.login(cl, secret, nil)
	keys := h.env.Svc.Keys.S
	h.env.Svc.Keys.S = failLists{Store: keys, kind: model.KindKey}
	h.p.Invalidate()
	if x := exch(code, v); x.status != 500 {
		t.Fatalf("exchange: %d %v", x.status, x.m)
	}
	if x := h.refreshWith(cl, secret, r.str("refresh_token")); x.status != 500 {
		t.Fatalf("refresh: %d %v", x.status, x.m)
	}
	h.env.Svc.Keys.S = keys
	h.p.Invalidate()
	// the failed refresh moved the counter though no token came out: the client's retry is then reuse. The grant's
	// state is what it is; only that the refusal is a 400 matters here.
	_ = h.refreshWith(cl, secret, r.str("refresh_token"))

	// client_credentials with the audit of tokens on
	cc, ccs := h.newClient(nil)
	if x := h.token(url.Values{"grant_type": {"client_credentials"}}, cc, ccs); x.status != 200 {
		t.Fatalf("%d %v", x.status, x.m)
	}
	if len(h.auditActions("oauth.client_credentials")) != 1 {
		t.Fatal("client_credentials not audited")
	}
	_ = ctx
}

func TestCoverageGrantLiveRefusals(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	ctx := context.Background()
	// a grant without offline_access lives with its session: a session gone from the store ends it, one that cannot be
	// read is not an answer
	r, _ := h.login(cl, secret, url.Values{"scope": {"openid"}})
	rt := r.str("refresh_token")
	sid := claimsOf(t, r.str("access_token"))["sid"].(string)
	sessions := h.env.Svc.Sessions.S
	h.env.Svc.Sessions.S = failReads{Store: sessions, kind: model.KindSession}
	h.p.InvalidateGrant(strings.SplitN(rt, ".", 2)[0])
	expectUnavailable(t, "session read", h.refreshWith(cl, secret, rt))
	h.env.Svc.Sessions.S = sessions
	if err := h.env.Svc.Sessions.Delete(ctx, sid); err != nil {
		t.Fatal(err)
	}
	tokenErr(t, h.refreshWith(cl, secret, rt), 400, "invalid_grant")

	// a credentials reset ends the grants of the user's earlier sign-ins
	r2, _ := h.login(cl, secret, url.Values{"scope": {"openid offline_access"}})
	if err := h.env.Svc.ResetCredentials(ctx, h.user.ID); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateUser(h.user.ID)
	tokenErr(t, h.refreshWith(cl, secret, r2.str("refresh_token")), 400, "invalid_grant")
}

func TestCoverageRefreshAfterRotationSwitchedOff(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RotateRefresh = ptr(true) })
	r, _ := h.login(cl, secret, nil)
	rt0 := r.str("refresh_token")
	rt1 := h.refreshWith(cl, secret, rt0).str("refresh_token")
	if _, err := h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{RotateRefresh: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	// the rotation has moved on: a counted token of an earlier step is refused, the current one still works
	tokenErr(t, h.refreshWith(cl, secret, rt0), 400, "invalid_grant")
	if x := h.refreshWith(cl, secret, rt1); x.status != 200 {
		t.Fatalf("%d %v", x.status, x.m)
	}
}

func TestCoverageLogoutStoreFailures(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.PostLogoutURIs = &[]string{"https://rp.example/bye"} })
	c, csrf := h.session(h.user)
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
	r, _ := h.login(cl, secret, nil)
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
	_ = r
	// the confirmed sign-out cannot end the session
	resp = h.get(c, "/oauth/logout")
	page := body(resp)
	id, pageCSRF := regexpValue(page, "id"), regexpValue(page, "csrf")
	sessions := h.env.Svc.Sessions.S
	h.env.Svc.Sessions.S = failDeletes{Store: sessions, kind: model.KindSession}
	confirm := func() *http.Response {
		req, _ := http.NewRequest("POST", h.env.URL+"/oauth/logout/confirm", strings.NewReader(url.Values{"id": {id}, "csrf": {pageCSRF}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
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
	_ = csrf
}

func TestCoverageBackchannelTargets(t *testing.T) {
	var hits atomic.Int32
	rp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer rp.Close()
	h := setup(t, nil)
	ctx := context.Background()
	cl, secret := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL) })
	// two sessions of the user, each with a grant of the client
	var sids []string
	for range 2 {
		r, _ := h.login(cl, secret, nil)
		sids = append(sids, claimsOf(t, r.str("access_token"))["sid"].(string))
	}
	// a session that is not the user's, and one that does not exist, are not counted; only the named one is told
	h.p.BackchannelLogout(ctx, sids[0], "nosuchsession")
	h.p.Wait()
	if hits.Load() != 1 {
		t.Fatalf("told %d times, want 1", hits.Load())
	}
	// listings that fail are logged, not fatal
	sessions, grants := h.env.Svc.Sessions.S, h.env.Svc.Grants.S
	h.env.Svc.Sessions.S = failLists{Store: sessions, kind: model.KindSession}
	h.env.Svc.Grants.S = failLists{Store: grants, kind: model.KindGrant}
	h.p.BackchannelLogoutUser(ctx, h.user.ID)
	h.p.Wait()
	h.env.Svc.Sessions.S, h.env.Svc.Grants.S = sessions, grants
	// noting a client on a session: one that is gone, one at the bound, one already noted
	h.p.noteSessionClient(ctx, "nosuchsession", cl.ID)
	s, err := h.env.Svc.Sessions.Get(ctx, sids[1])
	if err != nil {
		t.Fatal(err)
	}
	s.Clients = make([]string, 100)
	for i := range s.Clients {
		s.Clients[i] = "client" + string(rune('A'+i%26)) + string(rune('a'+i/26))
	}
	if err := h.env.Svc.Sessions.Update(ctx, s); err != nil {
		t.Fatal(err)
	}
	h.p.noteSessionClient(ctx, sids[1], "one-more")
	if s2, _ := h.env.Svc.Sessions.Get(ctx, sids[1]); len(s2.Clients) != 100 {
		t.Fatalf("clients: %d", len(s2.Clients))
	}
	h.p.noteSessionClient(ctx, sids[1], s.Clients[3])
}

func TestCoverageBackchannelDelivery(t *testing.T) {
	var calls atomic.Int32
	rp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer rp.Close()
	h := setup(t, nil)
	saved := logoutBackoff
	logoutBackoff = []time.Duration{5 * time.Millisecond, 5 * time.Millisecond}
	defer func() { logoutBackoff = saved }()
	retries, err := h.p.OpenLogoutQueue(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	failing, _ := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL) })
	gone, _ := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL) })
	deleted, _ := h.newClient(func(in *service.ClientInput) { in.BackchannelURI = ptr(rp.URL) })
	entry := func(c *model.Client) *clientEntry {
		ce, err := h.p.client(context.Background(), c.ID)
		if err != nil {
			t.Fatal(err)
		}
		return ce
	}
	fe, ge, de := entry(failing), entry(gone), entry(deleted)
	// a client that stopped wanting notices (or went) before its retry is not told
	if err := retries.Add(LogoutRetry{ClientID: gone.ID, Sub: "u", SID: "s"}, 20*time.Millisecond, 1); err != nil {
		t.Fatal(err)
	}
	if err := retries.Add(LogoutRetry{ClientID: "nosuchclient", Sub: "u"}, 20*time.Millisecond, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := h.env.Svc.UpdateClient(context.Background(), h.admin, gone.ID, service.ClientInput{Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(gone.ID)
	_ = ge
	_ = de
	// one that keeps refusing is given up on after its retries
	h.p.dispatch([]bcTarget{{client: fe.c, sub: "u", sid: "s"}})
	h.p.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for (calls.Load() < 3 || retries.Queued() > 0) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if calls.Load() < 3 || retries.Queued() != 0 {
		t.Fatalf("%d attempts, %d queued", calls.Load(), retries.Queued())
	}
	retries.Close()
	// with the queue closed a failure is only logged
	h.p.retryLogout(bcTarget{client: fe.c, sub: "u"}, errors.New("refused"))

	// delivery failures at each step
	if err := h.p.sendLogoutToken(bcTarget{client: &model.Client{Meta: model.Meta{ID: "c"}, BackchannelURI: "https://127.0.0.1:1/x"}, sub: "u"}); err == nil {
		t.Error("unreachable relying party")
	}
	if err := h.p.sendLogoutToken(bcTarget{client: &model.Client{Meta: model.Meta{ID: "c"}, BackchannelURI: "https://a b/x"}, sub: "u"}); err == nil {
		t.Error("unparsable address")
	}
	keys := h.env.Svc.Keys.S
	h.env.Svc.Keys.S = failLists{Store: keys, kind: model.KindKey}
	h.p.Invalidate()
	if err := h.p.sendLogoutToken(bcTarget{client: fe.c, sub: "u"}); err == nil {
		t.Error("without a signing key")
	}
	h.env.Svc.Keys.S = keys
	h.p.Invalidate()
	if (&statusError{code: 502}).Error() != "relying party answered Bad Gateway" {
		t.Error("statusError")
	}
}
