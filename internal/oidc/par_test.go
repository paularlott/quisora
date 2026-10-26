package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
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
		return h.post("/oauth/par", f, "", "")
	}
	return h.clientPost("/oauth/par", f, c, secret)
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
	resp := h.get(c, "/oauth/authorize?"+pushedQuery(other, r.str("request_uri")).Encode())
	if b := body(resp); resp.StatusCode != 400 || resp.Header.Get("Location") != "" || !strings.Contains(b, "This sign-in request is not valid") {
		t.Fatalf("another client's request_uri: %d", resp.StatusCode)
	}
	// an unknown one
	resp = h.get(c, "/oauth/authorize?"+pushedQuery(cl, parURNPrefix+"nope").Encode())
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
	// the stored request holds no client credentials
	r := h.push(cl, secret, authzQuery(cl, ch, nil))
	raw, err := h.env.Server.Eph.Get(context.Background(), nsPAR, strings.TrimPrefix(r.str("request_uri"), parURNPrefix))
	if err != nil {
		t.Fatal(err)
	}
	var pr pushedRequest
	_ = json.Unmarshal(raw, &pr)
	if pr.ClientID != cl.ID || strings.Contains(pr.Params, "client_secret") || strings.Contains(pr.Params, secret) {
		t.Fatalf("stored: %+v", pr)
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
			if u := h.authorize(anon, pushedQuery(cl, uri)); !strings.HasPrefix(u.Path, "/login/") {
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
			if u.Path != "/oauth/consent" {
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
		body(h.get(c, "/oauth/authorize?"+pushedQuery(cl, uri).Encode()))
		resp := h.get(c, "/oauth/authorize?"+pushedQuery(cl, uri).Encode())
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
		cancel := "/oauth/authorize/cancel?" + strings.TrimPrefix(next, "/oauth/authorize/resume?")
		if !strings.HasPrefix(next, "/oauth/authorize/resume?flow=") {
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

// A pushed request is kept in memory until it is used: one larger than parMaxParams is refused, not kept.
func TestPushedRequestTooLarge(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	_, ch := pkce()
	q := authzQuery(cl, ch, url.Values{"x_padding": {strings.Repeat("x", parMaxParams)}})
	if r := h.push(cl, secret, q); r.status != 400 || r.m["error"] != "invalid_request" {
		t.Fatalf("oversized push: %d %v", r.status, r.m)
	}
}

func TestPushedRequestStoreFailures(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	_, ch := pkce()
	// a push that cannot be stored
	h.useEph(func(op, ns string) error {
		if op == "new" && ns == nsPAR {
			return ephemeral.ErrFull
		}
		return nil
	})
	expectUnavailable(t, "par full", h.push(cl, secret, authzQuery(cl, ch, nil)))
	h.useEph(func(op, ns string) error {
		if op == "new" && ns == nsPAR {
			return errors.New("boom")
		}
		return nil
	})
	if r := h.push(cl, secret, authzQuery(cl, ch, nil)); r.status != 500 {
		t.Fatalf("%d %v", r.status, r.m)
	}
}

// A request_uri that names nothing usable (no client or id, an id too long, a record that is not a pushed request, one
// whose parameters cannot be read) is answered with the error page, never a redirect.
func TestPushedRequestURIRefusals(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	c, _ := h.session(h.user)
	ctx := context.Background()
	put := func(v []byte) string {
		id, err := h.env.Server.Eph.New(ctx, nsPAR, v, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	unparsable, _ := json.Marshal(pushedRequest{ClientID: cl.ID, Params: "a=%zz"})
	for name, tc := range map[string]struct{ client, requestURI string }{
		"no client":         {"", parURNPrefix + "x"},
		"no id":             {cl.ID, parURNPrefix},
		"long id":           {cl.ID, parURNPrefix + strings.Repeat("i", 201)},
		"not json":          {cl.ID, parURNPrefix + put([]byte("not json"))},
		"unparsable params": {cl.ID, parURNPrefix + put(unparsable)},
	} {
		resp := h.get(c, "/oauth/authorize?"+url.Values{"client_id": {tc.client}, "request_uri": {tc.requestURI}}.Encode())
		if pg := body(resp); resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" ||
			!strings.Contains(pg, "This sign-in request is not valid") {
			t.Errorf("%s: %d %.80s", name, resp.StatusCode, pg)
		}
	}
	// what is gone or unreadable counts as used up: the first visit and the decision both treat it so
	if !h.p.startPushed(ctx, "gone") || !h.p.startPushed(ctx, put([]byte("not json"))) {
		t.Fatal("startPushed of a missing or unreadable request is not used")
	}
	if h.p.usePushed(ctx, "gone") || h.p.usePushed(ctx, put([]byte("not json"))) {
		t.Fatal("usePushed of a missing or unreadable request")
	}
}

// Two browsers reach the consent screen with one pushed request; the second to decide finds it used.

func TestPushedRequestNotResurrectedByDelayedFirstVisit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	local := ephemeral.NewLocal("pushed-request")
	defer local.Close()
	// the first read of the request holds after it has its snapshot, while another browser starts and finishes the
	// authorization
	g := newGate(t)
	p := &Provider{s: &web.Server{Eph: faultEph{Store: local, after: func(op, ns string) {
		if op == "get" && ns == nsPAR {
			g.hold()
		}
	}}}}
	raw, _ := json.Marshal(pushedRequest{ClientID: "client", Params: "client_id=client&response_type=code"})
	id, err := local.New(ctx, nsPAR, raw, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	loaded := make(chan error, 1)
	go func() { _, _, _, err := p.loadPushed(ctx, "client", parURNPrefix+id); loaded <- err }()
	g.waitHeld(t)
	if _, _, used, err := p.loadPushed(ctx, "client", parURNPrefix+id); err != nil || used {
		t.Fatalf("second visit: used=%v err=%v", used, err)
	}
	if !p.usePushed(ctx, id) {
		t.Fatal("first completion refused")
	}
	g.open()
	if err := <-loaded; err != nil {
		t.Fatal(err)
	}
	if p.usePushed(ctx, id) {
		t.Fatal("consumed PAR request resurrected by delayed first-visit write; another authorization code can be issued")
	}
}
