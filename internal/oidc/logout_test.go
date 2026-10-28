package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

func TestLogoutWithBackchannel(t *testing.T) {
	t.Parallel()
	rp := newRP()
	defer rp.Close()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) {
		in.BackchannelURI = ptr(rp.URL + "/logout")
		in.PostLogoutURIs = &[]string{"https://rp.example/bye"}
	})
	silent, ssecret := h.newClient(nil) // no back-channel URI: must not be contacted, must not break anything
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	r := h.exchangeCode(cl, secret, code, v)
	v2, ch2 := pkce()
	code2 := h.getCode(c, silent, ch2, nil)
	r2 := h.exchangeCode(silent, ssecret, code2, v2)
	idt, rt := r.str("id_token"), r.str("refresh_token")
	sid := claimsOf(t, idt)["sid"].(string)

	// unregistered post-logout redirect is refused and nothing happens
	bad := h.orgBase + "/oauth/logout?" + url.Values{"id_token_hint": {idt}, "post_logout_redirect_uri": {"https://evil.example/"}}.Encode()
	if resp := h.get(c, bad); resp.StatusCode != 400 {
		t.Fatalf("bad redirect: %d", resp.StatusCode)
	}
	if resp := h.get(c, h.orgBase+"/oauth/logout?id_token_hint="+idt+"x"); resp.StatusCode != 400 {
		t.Fatal("forged hint accepted")
	}
	if h.refreshWith(cl, secret, rt).status != 200 {
		t.Fatal("rejected logout had effects")
	}

	q := url.Values{"id_token_hint": {idt}, "post_logout_redirect_uri": {"https://rp.example/bye"}, "state": {"xyz"}}
	resp := h.get(c, h.orgBase+"/oauth/logout?"+q.Encode())
	u := loc(t, resp)
	if resp.StatusCode != 302 || u.Scheme+"://"+u.Host+u.Path != "https://rp.example/bye" || u.Query().Get("state") != "xyz" {
		t.Fatalf("logout redirect: %d %s", resp.StatusCode, u)
	}
	select {
	case lt := <-rp.got:
		pj, err := ParseJWT(lt)
		if err != nil || pj.Header.Typ != "logout+jwt" {
			t.Fatalf("logout token header %v %v", pj, err)
		}
		key := h.p.keyByKID(context.Background(), pj.Header.Kid)
		if key == nil || pj.Verify(key.pub) != nil {
			t.Fatal("logout token signature")
		}
		lc := claimsOf(t, lt)
		ev, _ := lc["events"].(map[string]any)
		if _, ok := ev[backchannelEvent]; !ok || lc["sid"] != sid || lc["sub"] != h.user.ID || lc["aud"] != cl.ID ||
			lc["iss"] != h.issuer() || lc["jti"] == "" || lc["iat"] == nil || lc["exp"] == nil || lc["nonce"] != nil {
			t.Fatalf("logout claims %v", lc)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no back-channel logout received")
	}
	h.p.Wait()
	select {
	case <-rp.got:
		t.Fatal("more than one logout token delivered")
	default:
	}
	// session and grants are gone
	if resp := h.get(c, h.orgBase+"/oauth/authorize?"+authzQuery(cl, ch, nil).Encode()); resp.StatusCode != 302 || loc(t, resp).Path != h.orgBase+"/login" {
		t.Fatal("session survived logout")
	}
	if h.refreshWith(cl, secret, rt).status != 400 || h.refreshWith(silent, ssecret, r2.str("refresh_token")).status != 400 {
		t.Fatal("grants survived logout")
	}
}

func TestLogoutConfirmationWithoutHint(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) { in.PostLogoutURIs = &[]string{"https://rp.example/bye"} })
	c, csrf := h.session(h.user)
	// GET without hint must not log out
	resp := h.get(c, h.orgBase+"/oauth/logout?"+url.Values{"client_id": {cl.ID}, "post_logout_redirect_uri": {"https://rp.example/bye"}, "state": {"s"}}.Encode())
	page := body(resp)
	if resp.StatusCode != 200 || !strings.Contains(page, `action="`+h.orgBase+`/oauth/logout/confirm"`) {
		t.Fatalf("expected confirmation page: %d", resp.StatusCode)
	}
	// an over-long state is dropped, not a reason to sign the user out without asking
	resp = h.get(c, h.orgBase+"/oauth/logout?"+url.Values{"client_id": {cl.ID}, "state": {strings.Repeat("s", 3000)},
		"post_logout_redirect_uri": {"https://rp.example/bye"}}.Encode())
	if long := body(resp); resp.StatusCode != 200 || !strings.Contains(long, `action="`+h.orgBase+`/oauth/logout/confirm"`) {
		t.Fatalf("confirmation with a long state: %d", resp.StatusCode)
	}
	id, pageCSRF := regexpValue(page, "id"), regexpValue(page, "csrf")
	if pageCSRF != csrf {
		t.Fatalf("the page's form carries %q, not the session's token", pageCSRF)
	}
	if _, sess := h.env.Server.Sessions.Current(reqWithCookies(h, c)); sess == nil {
		t.Fatal("logged out without confirmation")
	}
	// a plain form post (no JavaScript needed); a wrong CSRF token is refused and keeps the request
	post := func(token string) *http.Response {
		return h.confirmLogout(c, url.Values{"id": {id}, "csrf": {token}}.Encode())
	}
	if r := post("wrong"); r.StatusCode != 400 {
		t.Fatalf("bad csrf: %d", r.StatusCode)
	}
	r := post(csrf)
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "https://rp.example/bye?state=s" {
		t.Fatalf("confirm: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	if _, sess := h.env.Server.Sessions.Current(reqWithCookies(h, c)); sess != nil {
		t.Fatal("session survived")
	}
	// no session at all: straight to the redirect
	anon := h.anon()
	resp = h.get(anon, h.orgBase+"/oauth/logout?"+url.Values{"client_id": {cl.ID}, "post_logout_redirect_uri": {"https://rp.example/bye"}}.Encode())
	if resp.StatusCode != 302 {
		t.Fatalf("anon logout: %d", resp.StatusCode)
	}
	// no redirect: plain message
	resp = h.get(anon, h.orgBase+"/oauth/logout")
	if resp.StatusCode != 200 || !strings.Contains(body(resp), "signed out") {
		t.Fatal("signed out page")
	}
}

// An ID token hint signed by a key that has since been retired and deleted (relying parties keep ID tokens for as long
// as their own sessions last) is treated as absent: the user is asked to confirm, and the redirect is still checked
// against the client the hint names. A tampered hint, or one in an algorithm we never use, is still refused.
func TestLogoutHintWithRetiredKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.PostLogoutURIs = &[]string{"https://rp.example/bye"} })
	r, _ := h.login(cl, secret, nil)
	old := r.str("id_token")
	kid, _ := headerOf(t, old)["kid"].(string)
	if err := h.env.Svc.Keys.Delete(ctx, kid); err != nil {
		t.Fatal(err)
	}
	h.p.Invalidate()
	if err := h.p.EnsureKeys(ctx); err != nil {
		t.Fatal(err)
	}
	c, _ := h.session(h.user)
	q := url.Values{"id_token_hint": {old}, "post_logout_redirect_uri": {"https://rp.example/bye"}}
	resp := h.get(c, h.orgBase+"/oauth/logout?"+q.Encode())
	if page := body(resp); resp.StatusCode != 200 || !strings.Contains(page, `action="`+h.orgBase+`/oauth/logout/confirm"`) {
		t.Fatalf("retired-key hint: %d", resp.StatusCode)
	}
	// an address the client did not register is still refused
	q.Set("post_logout_redirect_uri", "https://evil.example/")
	if resp := h.get(c, h.orgBase+"/oauth/logout?"+q.Encode()); resp.StatusCode != 400 {
		t.Fatalf("unregistered address with a retired-key hint: %d", resp.StatusCode)
	}
	// a current key with a broken signature, and an algorithm Quisora never signs with, are refused
	r2, _ := h.login(cl, secret, nil)
	fresh := r2.str("id_token")
	tampered := fresh[:len(fresh)-4] + "AAAA"
	hs := strings.Replace(fresh, strings.Split(fresh, ".")[0], b64.EncodeToString([]byte(`{"alg":"HS256","kid":"gone","typ":"JWT"}`)), 1)
	for name, tok := range map[string]string{"tampered": tampered, "HS256": hs} {
		if resp := h.get(c, h.orgBase+"/oauth/logout?"+url.Values{"id_token_hint": {tok}}.Encode()); resp.StatusCode != 400 {
			t.Errorf("%s hint: %d", name, resp.StatusCode)
		}
	}
}

// A relying party's cross-site POST to the logout endpoint carries no SameSite=Lax cookie: it is turned into a GET
// (a top-level navigation, which does carry it), so the session really ends.
func TestCrossSitePostLogout(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.PostLogoutURIs = &[]string{"https://rp.example/bye"} })
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}, cl, secret)
	form := url.Values{"id_token_hint": {r.str("id_token")}, "post_logout_redirect_uri": {"https://rp.example/bye"}, "state": {"s1"}}
	// without the cookie (as the browser sends it cross-site)
	resp := h.post(h.orgBase+"/oauth/logout", form, "", "")
	if resp.status != http.StatusSeeOther {
		t.Fatalf("cookieless POST: %d", resp.status)
	}
	loc, _ := url.Parse(resp.hdr.Get("Location"))
	if loc.Path != h.orgBase+"/oauth/logout" || loc.Query().Get("id_token_hint") != r.str("id_token") || loc.Query().Get("state") != "s1" {
		t.Fatalf("redirect: %s", loc)
	}
	// the GET, with the session cookie, ends the session and returns to the client
	get := h.get(c, loc.String())
	if get.StatusCode != http.StatusFound || get.Header.Get("Location") != "https://rp.example/bye?state=s1" {
		t.Fatalf("GET logout: %d %q", get.StatusCode, get.Header.Get("Location"))
	}
	if _, sess := h.env.Server.Sessions.Current(reqWithCookies(h, c)); sess != nil {
		t.Fatal("the session survived the logout")
	}
}

func TestLogoutRequestRefusals(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.PostLogoutURIs = &[]string{"https://rp.example/bye"} })
	other, _ := h.newClient(nil)
	r, _ := h.login(cl, secret, nil)
	idt := r.str("id_token")
	c, csrf := h.session(h.user)
	status := func(q url.Values) int {
		resp := h.get(c, h.orgBase+"/oauth/logout?"+q.Encode())
		body(resp)
		return resp.StatusCode
	}
	// a token of the wrong kind as hint
	if st := status(url.Values{"id_token_hint": {r.str("access_token")}}); st != 400 {
		t.Errorf("access token hint: %d", st)
	}
	if st := status(url.Values{"id_token_hint": {h.forge(typLogout, mustJSON(map[string]any{"iss": h.issuer(), "aud": cl.ID, "sub": "x"}))}}); st != 400 {
		t.Errorf("logout token hint: %d", st)
	}
	// an ID token hint of claims that make no sense (signed by us)
	if st := status(url.Values{"id_token_hint": {h.forge(typJWT, mustJSON(map[string]any{"iss": "https://x"}))}}); st != 400 {
		t.Errorf("hint claims: %d", st)
	}
	// a client_id that is not the hint's audience; an unknown client; a disabled one
	if st := status(url.Values{"id_token_hint": {idt}, "client_id": {other.ID}}); st != 400 {
		t.Errorf("client_id vs audience: %d", st)
	}
	if st := status(url.Values{"client_id": {"nosuchclient"}}); st != 400 {
		t.Errorf("unknown client: %d", st)
	}
	// a redirect with no client to check it against
	if st := status(url.Values{"post_logout_redirect_uri": {"https://rp.example/bye"}}); st != 400 {
		t.Errorf("redirect without client: %d", st)
	}
	// confirm: an unknown request, an unreadable body
	post := func(form string) *http.Response { return h.confirmLogout(c, form) }
	if resp := post("id=nosuch&csrf=" + url.QueryEscape(csrf)); resp.StatusCode != 400 {
		t.Errorf("expired request: %d", resp.StatusCode)
	}
	if resp := post("%zz"); resp.StatusCode != 400 {
		t.Errorf("unreadable: %d", resp.StatusCode)
	}
	// unreadable logout query
	resp := h.get(c, h.orgBase+"/oauth/logout?%zz")
	if body(resp); resp.StatusCode != 400 {
		t.Errorf("unreadable query: %d", resp.StatusCode)
	}
	// a disabled client cannot name a redirect
	if _, err := h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	if st := status(url.Values{"client_id": {cl.ID}, "post_logout_redirect_uri": {"https://rp.example/bye"}}); st != 400 {
		t.Errorf("disabled client: %d", st)
	}
}

// sessionReadsRefused refuses every session read, as a node that cannot vouch for the session partition does.
type sessionReadsRefused struct{ store.Store }

func (s sessionReadsRefused) Get(ctx context.Context, kind model.Kind, id string) (*store.Record, error) {
	if kind == model.KindSession {
		return nil, store.ErrUnavailable
	}
	return s.Store.Get(ctx, kind, id)
}

// A sign-out of a session the store cannot check is answered 503, not sent on to the relying party's signed-out page
// as though there were nothing to end (the session may be alive), and the confirmation's request is kept for the
// retry.
func TestLogoutWhenTheSessionCannotBeCheckedAsksToRetry(t *testing.T) {
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) { in.PostLogoutURIs = &[]string{"https://rp.example/bye"} })
	c, csrf := h.session(h.user)
	logoutURL := h.orgBase + "/oauth/logout?" + url.Values{"client_id": {cl.ID}, "post_logout_redirect_uri": {"https://rp.example/bye"}}.Encode()
	page := body(h.get(c, logoutURL)) // the confirmation page, with its request
	id := regexpValue(page, "id")
	if id == "" {
		t.Fatalf("no confirmation page: %.200s", page)
	}
	pu, _ := url.Parse(h.env.URL)
	for _, ck := range c.Jar.Cookies(pu) {
		if strings.HasPrefix(ck.Name, web.SessionCookieFor("")) {
			h.env.Server.Sessions.Evict(web.SessionID(ck.Value), "") // the cached copy would answer without the store
		}
	}
	good := h.env.Svc.Sessions.S
	h.env.Svc.Sessions.S = sessionReadsRefused{good}
	if resp := h.get(c, logoutURL); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("sign-out with an unreadable session: %d, want 503", resp.StatusCode)
	}
	form := url.Values{"id": {id}, "csrf": {csrf}}.Encode()
	if resp := h.confirmLogout(c, form); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("confirmed sign-out with an unreadable session: %d, want 503", resp.StatusCode)
	}
	h.env.Svc.Sessions.S = good
	if resp := h.confirmLogout(c, form); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "https://rp.example/bye" {
		t.Fatalf("confirmed sign-out once the store answers: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, sess := h.env.Server.Sessions.Current(reqWithCookies(h, c)); sess != nil {
		t.Fatal("session survived")
	}
}
