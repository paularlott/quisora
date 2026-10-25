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
)

func TestCoverageAuthorizeRefusals(t *testing.T) {
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	noCode, _ := h.newClient(func(in *service.ClientInput) { in.GrantTypes = &[]string{"client_credentials"} })
	c, _ := h.session(h.user)
	_, ch := pkce()
	errOf := func(cli *model.Client, extra url.Values) string {
		t.Helper()
		resp := h.get(c, "/oauth/authorize?"+authzQuery(cli, ch, extra).Encode())
		if resp.StatusCode != http.StatusFound {
			body(resp)
			return "page"
		}
		return loc(t, resp).Query().Get("error")
	}
	many := make([]string, 11)
	for i := range many {
		many[i] = "https://api.example/r" + string(rune('a'+i))
	}
	for name, tc := range map[string]struct {
		cl    *model.Client
		extra url.Values
		want  string
	}{
		"state twice":        {cl, url.Values{"state": {"a", "b"}}, "invalid_request"},
		"long state":         {cl, url.Values{"state": {strings.Repeat("s", 2049)}}, "invalid_request"},
		"parameter twice":    {cl, url.Values{"nonce": {"a", "b"}}, "invalid_request"},
		"no code grant":      {noCode, nil, "unauthorized_client"},
		"challenge alphabet": {cl, url.Values{"code_challenge": {strings.Repeat("+", 43)}}, "invalid_request"},
		"long nonce":         {cl, url.Values{"nonce": {strings.Repeat("n", 1025)}}, "invalid_request"},
		"too many resources": {cl, url.Values{"resource": many}, "invalid_target"},
		"bad prompt":         {cl, url.Values{"prompt": {"nope"}}, "invalid_request"},
		"prompt none+login":  {cl, url.Values{"prompt": {"none login"}}, "invalid_request"},
		"bad max_age":        {cl, url.Values{"max_age": {"-1"}}, "invalid_request"},
		"bad response mode":  {cl, url.Values{"response_mode": {"fragment"}}, "invalid_request"},
		"bad claims":         {cl, url.Values{"claims": {"[]"}}, "invalid_request"},
		"unmet acr":          {cl, url.Values{"claims": {`{"id_token":{"acr":{"essential":true,"value":"urn:nope"}}}`}}, "unmet_authentication_requirements"},
		"bad dpop_jkt":       {cl, url.Values{"dpop_jkt": {"short"}}, "invalid_request"},
	} {
		if got := errOf(tc.cl, tc.extra); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
	// no scope asked: the client's own
	if u := h.authorize(c, authzQuery(cl, ch, url.Values{"scope": {""}})); u.Query().Get("code") == "" {
		t.Fatalf("default scope: %s", u)
	}
	// an unreadable query
	resp := h.get(c, "/oauth/authorize?%zz")
	if body(resp); resp.StatusCode != 400 {
		t.Fatalf("unreadable: %d", resp.StatusCode)
	}
	// a metadata document id with no resource, and one with a resource no tenant owns
	for _, q := range []url.Values{
		{"client_id": {"https://client.example/metadata.json"}, "redirect_uri": {rpCallback}},
		{"client_id": {"https://client.example/metadata.json"}, "redirect_uri": {rpCallback}, "resource": {"https://nobody.example"}},
	} {
		resp := h.get(c, "/oauth/authorize?"+q.Encode())
		if pg := body(resp); resp.StatusCode != 400 || !strings.Contains(pg, "not recognised") {
			t.Errorf("metadata id: %d", resp.StatusCode)
		}
	}
	// the sign-in page is told the login hint
	anon := h.anon()
	u := h.authorize(anon, authzQuery(cl, ch, url.Values{"login_hint": {"alice@example.com"}}))
	if u.Query().Get("login_hint") != "alice@example.com" {
		t.Fatalf("login hint: %s", u)
	}
	// a pushed request that asked for form_post, used a second time
	cl2, secret2 := h.newClient(nil)
	uri := h.push(cl2, secret2, authzQuery(cl2, ch, url.Values{"response_mode": {"form_post"}})).str("request_uri")
	body(h.get(c, "/oauth/authorize?"+pushedQuery(cl2, uri).Encode()))
	resp = h.get(c, "/oauth/authorize?"+pushedQuery(cl2, uri).Encode())
	if pg := body(resp); resp.StatusCode != 200 || !strings.Contains(pg, "invalid_request_uri") {
		t.Fatalf("form_post reuse: %d %s", resp.StatusCode, pg)
	}
}

func TestCoverageAuthorizeStoreFailures(t *testing.T) {
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	c, _ := h.session(h.user)
	_, ch := pkce()
	boom := errors.New("ephemeral down")
	h.useEph(func(op, ns string) error {
		if op == "new" && ns == nsFlow {
			return boom
		}
		return nil
	})
	if u := h.authorize(h.anon(), authzQuery(cl, ch, nil)); u.Query().Get("error") != "server_error" {
		t.Fatalf("flow: %s", u)
	}
	h.useEph(func(op, ns string) error {
		if op == "new" && ns == nsCode {
			return boom
		}
		return nil
	})
	if u := h.authorize(c, authzQuery(cl, ch, nil)); u.Query().Get("error") != "server_error" {
		t.Fatalf("code: %s", u)
	}
	// the user's organization cannot be read
	h.useEph(func(string, string) error { return nil })
	orgs := h.env.Svc.Orgs.S
	h.env.Svc.Orgs.S = failReads{Store: orgs, kind: model.KindOrg}
	h.p.orgs.clear()
	h.p.clients.clear()
	resp := h.get(c, "/oauth/authorize?"+authzQuery(cl, ch, nil).Encode())
	body(resp)
	h.env.Svc.Orgs.S = orgs
	h.p.orgs.clear()
	if resp.StatusCode == http.StatusFound && loc(t, resp).Query().Get("code") != "" {
		t.Fatal("a code was issued with an unreadable organization")
	}
}

func TestCoverageAuthorizeAccessUnreadable(t *testing.T) {
	h := setup(t, nil)
	tn := h.tenant("cov-access-read", membersOnly())
	cl, _ := h.tenantClient(tn, nil)
	h.grant(tn, model.SubjectUser, h.user.ID, service.AccessInput{})
	c, _ := h.session(h.user)
	_, ch := pkce()
	access := h.env.Svc.Access.S
	h.env.Svc.Access.S = failReads{Store: access, kind: model.KindAccess}
	if u := h.authorize(c, authzQuery(cl, ch, nil)); u.Query().Get("error") != "server_error" {
		t.Fatalf("%s", u)
	}
	h.env.Svc.Access.S = access
}

// Two browsers reach the consent screen with one pushed request; the second to decide finds it used.
func TestCoverageParDecidedTwice(t *testing.T) {
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
		req, _ := http.NewRequest(http.MethodPost, h.env.URL+"/api-internal/oauth/consent", strings.NewReader(`{"flow":"`+flow+`","approve":true}`))
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Content-Type", "application/json")
		r, err := b.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]string
		_ = json.Unmarshal([]byte(body(r)), &out)
		return loc(t, h.get(b, out["redirect"]))
	}
	if u := decide(b1, csrf1, f1); u.Query().Get("code") == "" {
		t.Fatalf("first: %s", u)
	}
	if u := decide(b2, csrf2, f2); u.Query().Get("error") != "invalid_request_uri" {
		t.Fatalf("second: %s", u)
	}
}

func TestCoverageFlowEndpointsRefuseBadFlows(t *testing.T) {
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) { in.FirstParty = ptr(false) })
	other, _ := h.newClient(nil)
	c, csrf := h.session(h.user)
	ctx := context.Background()
	status := func(path string) int {
		resp := h.get(c, path)
		body(resp)
		return resp.StatusCode
	}
	put := func(v []byte) string {
		id, err := h.env.Server.Eph.New(ctx, nsFlow, v, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	garbage := put([]byte("not json"))
	for _, path := range []string{"/oauth/authorize/resume?flow=" + garbage, "/oauth/authorize/cancel?flow=" + garbage,
		"/oauth/authorize/resume?flow=unknown", "/oauth/consent?flow=" + garbage, "/oauth/consent?flow=unknown"} {
		if st := status(path); st != 400 && st != 404 {
			t.Errorf("%s: %d", path, st)
		}
	}
	// a flow whose client is disabled or gone before it resumes
	_, ch := pkce()
	u := h.authorize(c, authzQuery(cl, ch, nil))
	id := u.Query().Get("flow")
	if _, err := h.env.Svc.UpdateClient(ctx, h.admin, cl.ID, service.ClientInput{Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	for _, path := range []string{"/oauth/authorize/resume?flow=" + id, "/oauth/consent?flow=" + id} {
		if st := status(path); st != 400 && st != 404 {
			t.Errorf("disabled client %s: %d", path, st)
		}
	}
	post := func(body, token string) int {
		req, _ := http.NewRequest(http.MethodPost, h.env.URL+"/api-internal/oauth/consent", strings.NewReader(body))
		req.Header.Set("X-CSRF-Token", token)
		req.Header.Set("Content-Type", "application/json")
		r, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return r.StatusCode
	}
	if st := post(`{"flow":"`+id+`","approve":true}`, csrf); st != http.StatusNotFound {
		t.Errorf("consent for a disabled client: %d", st)
	}
	if st := post(`not json`, csrf); st != http.StatusBadRequest {
		t.Errorf("consent with a broken body: %d", st)
	}
	// a flow of a client that is enabled, started in this browser and given a scope with no description
	_ = other
	bare, err := h.env.Svc.CreateUser(ctx, service.System, h.env.Primary.ID, service.UserInput{Username: ptr("bare"), Email: ptr("bare@example.com"), GivenName: ptr("Bare"), FamilyName: ptr("B"), Verified: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	cl2, _ := h.newClient(func(in *service.ClientInput) { in.FirstParty = ptr(false) })
	bc, _ := h.session(bare)
	u = h.authorize(bc, authzQuery(cl2, ch, url.Values{"scope": {"openid api"}}))
	if u.Path != "/oauth/consent" {
		t.Fatalf("consent: %s", u)
	}
	page := body(h.get(bc, u.RequestURI()))
	if !strings.Contains(page, "Access: api") {
		t.Fatalf("consent page: %s", page)
	}
	_ = ephemeral.ErrNotFound
}
