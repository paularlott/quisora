package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// push posts an authorization request to the PAR endpoint as client c (secret "" for a public client).
func (h *harness) push(c *model.Client, secret string, q url.Values) tokResp {
	h.t.Helper()
	f := url.Values{}
	for k, v := range q {
		if k != "client_id" {
			f[k] = v
		}
	}
	if secret == "" {
		f.Set("client_id", c.ID)
		return h.post(h.orgBase+"/oauth/par", f, "", "")
	}
	return h.clientPost(h.orgBase+"/oauth/par", f, c, secret)
}

func pushedQuery(c *model.Client, requestURI string) url.Values {
	return url.Values{"client_id": {c.ID}, "request_uri": {requestURI}}
}

func TestPushedAuthorizationRequest(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	v, ch := pkce()
	r := h.push(cl, secret, authzQuery(cl, ch, url.Values{"state": {"pushed"}}))
	uri := r.str("request_uri")
	if r.status != 201 || !strings.HasPrefix(uri, parURNPrefix) || r.m["expires_in"] != float64(60) ||
		r.hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("push: %d %v", r.status, r.m)
	}
	// Only the pushed parameters count: whatever else the URL carries is ignored.
	c, _ := h.session(h.user)
	q := pushedQuery(cl, uri)
	q.Set("state", "from-url")
	q.Set("scope", "openid admin")
	q.Set("redirect_uri", "https://evil.example/cb")
	u := h.authorize(c, q)
	code := u.Query().Get("code")
	if u.Scheme+"://"+u.Host+u.Path != rpCallback || code == "" || u.Query().Get("state") != "pushed" {
		t.Fatalf("authorize: %s", u)
	}
	tr := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpCallback},
		"code_verifier": {v}}, cl, secret)
	if tr.status != 200 || tr.str("id_token") == "" || tr.str("scope") != "openid profile email offline_access" {
		t.Fatalf("exchange: %d %v", tr.status, tr.m)
	}
	// single use: presented again after the code, it is sent back to the client as invalid_request_uri
	u = h.authorize(c, pushedQuery(cl, uri))
	if u.Scheme+"://"+u.Host+u.Path != rpCallback || u.Query().Get("error") != "invalid_request_uri" || u.Query().Get("state") != "pushed" {
		t.Fatalf("reused request_uri: %s", u)
	}
	// only by the client that pushed it
	other, _ := h.newClient(nil)
	r = h.push(cl, secret, authzQuery(cl, ch, nil))
	resp := h.get(c, h.orgBase+"/oauth/authorize?"+pushedQuery(other, r.str("request_uri")).Encode())
	if b := body(resp); resp.StatusCode != 400 || resp.Header.Get("Location") != "" || !strings.Contains(b, "This sign-in request is not valid") {
		t.Fatalf("another client's request_uri: %d", resp.StatusCode)
	}
	// an unknown one
	resp = h.get(c, h.orgBase+"/oauth/authorize?"+pushedQuery(cl, parURNPrefix+"nope").Encode())
	if b := body(resp); resp.StatusCode != 400 || !strings.Contains(b, "This sign-in request is not valid") {
		t.Fatalf("unknown request_uri: %d", resp.StatusCode)
	}
	// a request_uri that is not a pushed one is still not supported
	u = h.authorize(c, authzQuery(cl, ch, url.Values{"request_uri": {"https://rp.example/req.jwt"}}))
	if u.Query().Get("error") != "request_uri_not_supported" {
		t.Fatalf("foreign request_uri: %s", u)
	}
}

func TestPushedAuthorizationRequestValidation(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	_, ch := pkce()
	for name, tc := range map[string]struct {
		extra  url.Values
		status int
		code   string
	}{
		"wrong redirect": {url.Values{"redirect_uri": {"https://evil.example/cb"}}, 400, "invalid_request"},
		"no redirect":    {url.Values{"redirect_uri": {""}}, 400, "invalid_request"},
		"no pkce":        {url.Values{"code_challenge": {""}, "code_challenge_method": {""}}, 400, "invalid_request"},
		"scope":          {url.Values{"scope": {"openid admin"}}, 400, "invalid_scope"},
		"token type":     {url.Values{"response_type": {"token"}}, 400, "unsupported_response_type"},
		"request object": {url.Values{"request": {"x"}}, 400, "request_not_supported"},
		"request_uri":    {url.Values{"request_uri": {parURNPrefix + "x"}}, 400, "invalid_request"},
		"resource":       {url.Values{"resource": {"https://other.example"}}, 400, "invalid_target"},
		"repeated":       {url.Values{"scope": {"openid", "email"}}, 400, "invalid_request"},
		"long state":     {url.Values{"state": {strings.Repeat("s", 2049)}}, 400, "invalid_request"},
	} {
		if r := h.push(cl, secret, authzQuery(cl, ch, tc.extra)); r.status != tc.status || r.m["error"] != tc.code {
			t.Errorf("%s: %d %v", name, r.status, r.m)
		}
	}
	// client authentication is required, and must be right
	if r := h.push(cl, "wrong", authzQuery(cl, ch, nil)); r.status != 401 || r.m["error"] != "invalid_client" {
		t.Errorf("wrong secret: %d %v", r.status, r.m)
	}
	if r := h.push(cl, "", authzQuery(cl, ch, nil)); r.status != 401 {
		t.Errorf("confidential client without a secret: %d %v", r.status, r.m)
	}
	// the request_uri holds no client credentials
	r := h.push(cl, secret, authzQuery(cl, ch, nil))
	q, _, _, err := h.p.loadPushed(context.Background(), cl.OrgID, cl.ID, r.str("request_uri"))
	if err != nil || q.Get("client_id") != cl.ID || q.Has("client_secret") || strings.Contains(q.Encode(), secret) ||
		strings.Contains(r.str("request_uri"), secret) {
		t.Fatalf("pushed: %v %v", q, err)
	}
}

func TestPushedAuthorizationRequestPublicAndBasic(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	// a public client pushes with its client_id alone
	pub := h.publicClient(func(in *service.ClientInput) { in.FirstParty = ptr(true) })
	_, ch := pkce()
	r := h.push(pub, "", authzQuery(pub, ch, nil))
	if r.status != 201 {
		t.Fatalf("public push: %d %v", r.status, r.m)
	}
	c, _ := h.session(h.user)
	if u := h.authorize(c, pushedQuery(pub, r.str("request_uri"))); u.Query().Get("code") == "" {
		t.Fatalf("public authorize: %s", u)
	}
	// client_secret_basic: the client_id need not be in the body
	basic, bsecret := h.newClient(func(in *service.ClientInput) { in.AuthMethod = ptr(model.AuthMethodSecretBasic) })
	r = h.push(basic, bsecret, authzQuery(basic, ch, nil))
	if r.status != 201 {
		t.Fatalf("basic push: %d %v", r.status, r.m)
	}
	if u := h.authorize(c, pushedQuery(basic, r.str("request_uri"))); u.Query().Get("code") == "" {
		t.Fatalf("basic authorize: %s", u)
	}
}

func TestRequirePushedAuthorizationRequests(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RequirePAR = ptr(true) })
	if !cl.RequirePAR {
		t.Fatal("flag not stored")
	}
	c, _ := h.session(h.user)
	_, ch := pkce()
	u := h.authorize(c, authzQuery(cl, ch, nil))
	if u.Query().Get("error") != "invalid_request" || u.Query().Get("state") != "st1" ||
		!strings.Contains(u.Query().Get("error_description"), "RFC 9126") {
		t.Fatalf("unpushed request: %s", u)
	}
	r := h.push(cl, secret, authzQuery(cl, ch, nil))
	if u := h.authorize(c, pushedQuery(cl, r.str("request_uri"))); u.Query().Get("code") == "" {
		t.Fatalf("pushed request: %s", u)
	}
}

// A request_uri is used up when the request is decided, not when the browser first opens it (FAPI 2.0 §5.3.2.2): the
// sign-in page can be reloaded, and only one of two flows of the same request_uri gets a code.
func TestPushedRequestUsedWhenDecided(t *testing.T) {
	t.Parallel()
	t.Run("first party", func(t *testing.T) {
		h := setup(t, nil)
		cl, secret := h.newClient(nil)
		_, ch := pkce()
		uri := h.push(cl, secret, authzQuery(cl, ch, nil)).str("request_uri")
		anon := h.anon()
		for i := 0; i < 2; i++ { // not signed in: sent to the sign-in page, twice
			if u := h.authorize(anon, pushedQuery(cl, uri)); !strings.HasSuffix(u.Path, "/login") {
				t.Fatalf("visit %d: %s", i, u)
			}
		}
		// two signed-in browsers start flows from it; the first to be decided gets the code
		b1, _ := h.session(h.user)
		b2, _ := h.session(h.user)
		u1 := h.authorize(b1, pushedQuery(cl, uri))
		u2 := h.authorize(b2, pushedQuery(cl, uri))
		if u1.Query().Get("code") == "" || u2.Query().Get("error") != "invalid_request_uri" {
			t.Fatalf("decided twice: %s / %s", u1, u2)
		}
	})

	t.Run("consent screen", func(t *testing.T) {
		h := setup(t, nil)
		cl, secret := h.newClient(func(in *service.ClientInput) { in.FirstParty = ptr(false) })
		_, ch := pkce()
		uri := h.push(cl, secret, authzQuery(cl, ch, nil)).str("request_uri")
		b1, csrf1 := h.session(h.user)
		b2, csrf2 := h.session(h.user)
		flowOf := func(b *http.Client) string {
			u := h.authorize(b, pushedQuery(cl, uri))
			if u.Path != h.orgBase+"/oauth/consent" {
				t.Fatalf("expected consent: %s", u)
			}
			return u.Query().Get("flow")
		}
		f1, f2 := flowOf(b1), flowOf(b2)
		decide := func(b *http.Client, csrf, flow string) *url.URL {
			_, redirect := h.decideConsent(b, csrf, flow, true)
			return loc(t, h.get(b, redirect))
		}
		if u := decide(b1, csrf1, f1); u.Query().Get("code") == "" {
			t.Fatalf("first: %s", u)
		}
		if u := decide(b2, csrf2, f2); u.Query().Get("error") != "invalid_request_uri" {
			t.Fatalf("second: %s", u)
		}
	})

	// the refusal for a request pushed with form_post is the page that mode renders, not a redirect
	t.Run("form_post", func(t *testing.T) {
		h := setup(t, nil)
		cl, secret := h.newClient(nil)
		c, _ := h.session(h.user)
		_, ch := pkce()
		uri := h.push(cl, secret, authzQuery(cl, ch, url.Values{"response_mode": {"form_post"}})).str("request_uri")
		body(h.get(c, h.orgBase+"/oauth/authorize?"+pushedQuery(cl, uri).Encode()))
		resp := h.get(c, h.orgBase+"/oauth/authorize?"+pushedQuery(cl, uri).Encode())
		if pg := body(resp); resp.StatusCode != 200 || !strings.Contains(pg, "invalid_request_uri") {
			t.Fatalf("reuse: %d %s", resp.StatusCode, pg)
		}
	})
}

func TestCancelSignIn(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	_, ch := pkce()
	for name, q := range map[string]url.Values{"plain": authzQuery(cl, ch, nil),
		"pushed": pushedQuery(cl, h.push(cl, secret, authzQuery(cl, ch, nil)).str("request_uri"))} {
		b := h.anon()
		login := h.authorize(b, q)
		next := login.Query().Get("next") // the sign-in page's Cancel link (login.cancelURL) is built from it
		cancel := h.orgBase + "/oauth/authorize/cancel?" + strings.TrimPrefix(next, h.orgBase+"/oauth/authorize/resume?")
		if !strings.HasPrefix(next, h.orgBase+"/oauth/authorize/resume?flow=") {
			t.Fatalf("%s: next %q", name, next)
		}
		// another browser cannot cancel it
		if resp := h.get(h.anon(), cancel); resp.StatusCode != 403 {
			t.Errorf("%s: cancel from another browser: %d", name, resp.StatusCode)
		}
		u := loc(t, h.get(b, cancel))
		if u.Scheme+"://"+u.Host+u.Path != rpCallback || u.Query().Get("error") != "access_denied" || u.Query().Get("state") != "st1" {
			t.Fatalf("%s: cancel: %s", name, u)
		}
		if name == "pushed" {
			if u := h.authorize(b, q); u.Query().Get("error") != "invalid_request_uri" {
				t.Fatalf("cancelled request_uri reused: %s", u)
			}
		}
	}
}

// A pushed request of more than parMaxParams (form-encoded) is refused; one of exactly that size is accepted, and the
// authorization URL that carries its request_uri fits the 8 KiB request line nginx allows by default, whether the
// request is one large value or many small parameters (whose "&" JSON would escape to six characters each).
func TestPushedRequestSizeLimit(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	_, ch := pkce()
	// the form the server encodes: the request with client_id, padded to size by one parameter ("x=" and its "&")
	sized := func(size int, many bool) url.Values {
		q := authzQuery(cl, ch, nil)
		if many { // as many parameters as will fit
			for i := 0; len(q.Encode()) < size-12; i++ {
				q.Set("p"+strconv.Itoa(i), "")
			}
		}
		q.Set("x", "")
		q.Set("x", strings.Repeat("x", size-len(q.Encode())))
		return q
	}
	for name, many := range map[string]bool{"one large value": false, "many parameters": true} {
		q := sized(parMaxParams, many)
		if len(q.Encode()) != parMaxParams {
			t.Fatalf("%s: test request of %d bytes", name, len(q.Encode()))
		}
		r := h.push(cl, secret, q)
		if r.status != 201 {
			t.Fatalf("%s: a push of the largest size: %d %v", name, r.status, r.m)
		}
		if u := h.orgBase + "/oauth/authorize?" + pushedQuery(cl, r.str("request_uri")).Encode(); len(u) >= 8<<10 {
			t.Errorf("%s: the authorization URL of the largest push is %d bytes", name, len(u))
		}
		if r := h.push(cl, secret, sized(parMaxParams+1, many)); r.status != 400 || r.m["error"] != "invalid_request" {
			t.Errorf("%s: a push of one byte more: %d %v", name, r.status, r.m)
		}
	}
}

// A request_uri whose use cannot be looked up is not answered as an invalid one: the store failed, and the page says to
// try again. When its use cannot be recorded at the decision, no code is issued.
func TestPushedRequestStoreFailures(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	_, ch := pkce()
	c, _ := h.session(h.user)
	uri := h.push(cl, secret, authzQuery(cl, ch, nil)).str("request_uri")
	good := h.env.Svc.Replays.S
	h.env.Svc.Replays.S = failReads(good, model.KindReplay)
	resp := h.get(c, h.orgBase+"/oauth/authorize?"+pushedQuery(cl, uri).Encode())
	if pg := body(resp); resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(pg, "Please try again") {
		t.Fatalf("use not readable: %d %.80s", resp.StatusCode, pg)
	}
	h.env.Svc.Replays.S = failCAS(good, model.KindReplay, func() error { return errFault })
	if u := h.authorize(c, pushedQuery(cl, uri)); u.Query().Get("code") != "" {
		t.Fatalf("a code was issued although its request_uri could not be recorded as used: %s", u)
	}
	h.env.Svc.Replays.S = good
	if u := h.authorize(c, pushedQuery(cl, uri)); u.Query().Get("code") == "" {
		t.Fatalf("the request_uri after the store recovered: %s", u)
	}
}

// A request_uri that is not one of ours for that client (no client, nothing after the prefix, not encoded, sealed
// for another client or organization, tampered with, expired, or holding parameters that cannot be read) is answered
// with the error page, never a redirect.
func TestPushedRequestURIRefusals(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	_, ch := pkce()
	uri := h.push(cl, secret, authzQuery(cl, ch, nil)).str("request_uri")
	seal := func(binding string, pr pushedRequest) string {
		b, _ := json.Marshal(pr)
		return parURNPrefix + base64.RawURLEncoding.EncodeToString([]byte(h.env.Svc.Sealer.SealFor(binding, b)))
	}
	own := parBinding(cl.OrgID, cl.ID)
	live := time.Now().Add(time.Minute).UnixMilli()
	for name, tc := range map[string]struct{ client, requestURI string }{
		"no client":      {"", uri},
		"no id":          {cl.ID, parURNPrefix},
		"not encoded":    {cl.ID, parURNPrefix + "!!!"},
		"not sealed":     {cl.ID, parURNPrefix + base64.RawURLEncoding.EncodeToString([]byte("v3:x:y"))},
		"tampered":       {cl.ID, uri[:len(uri)-2] + "AA"},
		"another client": {cl.ID, seal(parBinding(cl.OrgID, "other"), pushedRequest{ID: "a", Expires: live, Params: "client_id=" + cl.ID})},
		"another org":    {cl.ID, seal(parBinding("another-org", cl.ID), pushedRequest{ID: "a", Expires: live, Params: "client_id=" + cl.ID})},
		"expired":        {cl.ID, seal(own, pushedRequest{ID: "a", Expires: time.Now().Add(-time.Second).UnixMilli(), Params: "client_id=" + cl.ID})},
		// expires_in is a promise to the millisecond: not a moment's grace after it (the conformance suite visits at once)
		"expired just now": {cl.ID, seal(own, pushedRequest{ID: "a", Expires: time.Now().Add(-20 * time.Millisecond).UnixMilli(), Params: "client_id=" + cl.ID})},
		"sealed in seconds": {cl.ID, parURNPrefix + base64.RawURLEncoding.EncodeToString([]byte(h.env.Svc.Sealer.SealFor(own,
			[]byte(`{"j":"a","e":`+strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10)+`,"q":"client_id=`+cl.ID+`"}`))))},
		"no id inside":      {cl.ID, seal(own, pushedRequest{Expires: live, Params: "client_id=" + cl.ID})},
		"unparsable params": {cl.ID, seal(own, pushedRequest{ID: "a", Expires: live, Params: "a=%zz"})},
	} {
		resp := h.get(c, h.orgBase+"/oauth/authorize?"+url.Values{"client_id": {tc.client}, "request_uri": {tc.requestURI}}.Encode())
		if pg := body(resp); resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" ||
			!strings.Contains(pg, "This sign-in request is not valid") {
			t.Errorf("%s: %d %.80s", name, resp.StatusCode, pg)
		}
	}
	// the one that was pushed still works
	if u := h.authorize(c, pushedQuery(cl, uri)); u.Query().Get("code") == "" {
		t.Fatalf("control: %s", u)
	}
}

// A push stores nothing, so what anyone may push cannot use up the node's short-lived state or an organization's
// share of it: a flood of public pushes from many addresses leaves the ephemeral store as it was (but for the
// per-address counters), all of them are answered, and another public client's sign-in is not held back.
func TestPublicPushesHoldNothing(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	pub := h.publicClient(func(in *service.ClientInput) { in.FirstParty = ptr(true) })
	victim := h.publicClient(func(in *service.ClientInput) { in.FirstParty = ptr(true) })
	local, ok := h.env.Server.Eph.(*ephemeral.Local)
	if !ok {
		t.Fatalf("the test server's ephemeral store is %T", h.env.Server.Eph)
	}
	_, ch := pkce()
	pad := strings.Repeat("x", 3000) // a push of about 3.5 KB: a public client's largest before pushes held nothing was 4 KB
	pushFrom := func(c *model.Client, ip string) (int, string) {
		f := authzQuery(c, ch, url.Values{"x_padding": {pad}})
		req := httptest.NewRequest(http.MethodPost, h.orgBase+"/oauth/par", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = ip + ":4000"
		rec := httptest.NewRecorder()
		h.env.Server.Handler().ServeHTTP(rec, req)
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		uri, _ := m["request_uri"].(string)
		return rec.Code, uri
	}
	const pushes = 1500 // more than an organization's former budget of 600 a minute
	before := local.Used()
	for i := range pushes {
		if code, _ := pushFrom(pub, "10."+strconv.Itoa(i/250)+"."+strconv.Itoa(i%250)+".1"); code != http.StatusCreated {
			t.Fatalf("push %d: %d", i, code)
		}
	}
	// what remains is a counter per address; a stored push would be the size of its parameters or more
	if grown := local.Used() - before; grown > pushes*512 {
		t.Fatalf("%d pushes grew the ephemeral store by %d bytes: a push holds something", pushes, grown)
	}
	// the organization's other public client signs in as ever
	code, uri := pushFrom(victim, "192.0.2.9")
	if code != http.StatusCreated {
		t.Fatalf("another public client's push after the flood: %d", code)
	}
	c, _ := h.session(h.user)
	if u := h.authorize(c, pushedQuery(victim, uri)); u.Query().Get("code") == "" {
		t.Fatalf("another public client's sign-in after the flood: %s", u)
	}
}

// A request_uri is used up once, on every node: a request decided from it records its id (nothing before).
func TestPushedRequestIsRecordedOnlyWhenDecided(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	_, ch := pkce()
	uri := h.push(cl, secret, authzQuery(cl, ch, nil)).str("request_uri")
	ctx := context.Background()
	_, id, used, err := h.p.loadPushed(ctx, cl.OrgID, cl.ID, uri)
	if err != nil || used {
		t.Fatalf("before: used=%v err=%v", used, err)
	}
	if !h.p.usePushed(ctx, id) || h.p.usePushed(ctx, id) {
		t.Fatal("a request_uri is used once")
	}
	if _, _, used, err := h.p.loadPushed(ctx, cl.OrgID, cl.ID, uri); err != nil || !used {
		t.Fatalf("after: used=%v err=%v", used, err)
	}
}
