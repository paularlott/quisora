package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/service"
)

// covEph fails the operations of the ephemeral store for which fail answers an error.
type covEph struct {
	ephemeral.Store
	fail func(op, ns string) error
}

func (e covEph) New(ctx context.Context, ns string, v []byte, ttl time.Duration) (string, error) {
	if err := e.fail("new", ns); err != nil {
		return "", err
	}
	return e.Store.New(ctx, ns, v, ttl)
}

func (e covEph) Get(ctx context.Context, ns, id string) ([]byte, error) {
	if err := e.fail("get", ns); err != nil {
		return nil, err
	}
	return e.Store.Get(ctx, ns, id)
}

func (e covEph) Take(ctx context.Context, ns, id string) ([]byte, error) {
	if err := e.fail("take", ns); err != nil {
		return nil, err
	}
	return e.Store.Take(ctx, ns, id)
}

func (e covEph) Set(ctx context.Context, ns, id string, v []byte, ttl time.Duration) error {
	if err := e.fail("set", ns); err != nil {
		return err
	}
	return e.Store.Set(ctx, ns, id, v, ttl)
}

// useEph swaps the provider's ephemeral store for the failing one and restores it when the test ends.
func (h *harness) useEph(fail func(op, ns string) error) {
	h.t.Helper()
	good := h.env.Server.Eph
	if c, ok := good.(covEph); ok {
		good = c.Store
	}
	orig := h.env.Server.Eph
	h.env.Server.Eph = covEph{Store: good, fail: fail}
	h.t.Cleanup(func() { h.env.Server.Eph = orig })
}

// rawPost posts a body as is (not necessarily a valid form).
func (h *harness) rawPost(path, payload string) tokResp {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.env.URL+path, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.http.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return tokResp{status: resp.StatusCode, m: map[string]any{"body": body(resp)}, hdr: resp.Header}
}

func TestCoverageUnreadableBodies(t *testing.T) {
	h := setup(t, nil)
	for _, path := range []string{"/oauth/token", "/oauth/par", "/oauth/device_authorization", "/oauth/revoke", "/oauth/introspect"} {
		r := h.rawPost(path, "a=%zz")
		if r.status != 400 && r.status != 401 {
			t.Errorf("%s: %d %v", path, r.status, r.m)
		}
	}
}

func TestCoverageDeviceAuthorizationRefusals(t *testing.T) {
	h := setup(t, func(c *config.Config) { c.Audit.Tokens = true })
	cl := h.deviceClient(nil)
	post := func(f url.Values) tokResp { return h.post("/oauth/device_authorization", f, "", "") }

	tokenErr(t, post(url.Values{"client_id": {cl.ID, cl.ID}}), 400, "invalid_request")
	if r := post(url.Values{"client_id": {"nosuchclient"}}); r.status != 401 || r.str("error") != "invalid_client" {
		t.Fatalf("%d %v", r.status, r.m)
	}
	tokenErr(t, post(url.Values{"client_id": {cl.ID}, "resource": {"https://other.example"}}), 400, "invalid_target")
	tokenErr(t, post(url.Values{"client_id": {cl.ID}, "resource": {"nope"}}), 400, "invalid_target")

	h.startDevice(cl, "openid")
	if len(h.auditActions("oauth.device.start")) != 1 {
		t.Fatal("start not audited")
	}

	// the start of a device sign-in is limited per address
	limited := false
	for range deviceStartsPerIP + 1 {
		if r := post(url.Values{"client_id": {cl.ID}}); r.status == http.StatusTooManyRequests {
			limited = r.str("error") == "slow_down"
			break
		}
	}
	if !limited {
		t.Fatal("device starts were not limited")
	}
}

func TestCoverageDeviceStoreFailures(t *testing.T) {
	h := setup(t, nil)
	cl := h.deviceClient(nil)
	start := func() tokResp {
		return h.post("/oauth/device_authorization", url.Values{"client_id": {cl.ID}, "scope": {"openid"}}, "", "")
	}
	boom := errors.New("ephemeral down")

	h.useEph(func(op, ns string) error {
		if op == "new" && ns == nsDevice {
			return boom
		}
		return nil
	})
	if r := start(); r.status != 500 || r.str("error") != "server_error" {
		t.Fatalf("new: %d %v", r.status, r.m)
	}
	h.useEph(func(op, ns string) error {
		if op == "set" && ns == nsDeviceUser {
			return boom
		}
		return nil
	})
	if r := start(); r.status != 500 {
		t.Fatalf("set: %d %v", r.status, r.m)
	}
	// every user code looks taken
	h.useEph(func(op, ns string) error { return nil })
	good := h.env.Server.Eph.(covEph).Store
	h.env.Server.Eph = takenCodes{Store: good}
	if r := start(); r.status != 500 {
		t.Fatalf("no free code: %d %v", r.status, r.m)
	}
	h.env.Server.Eph = good

	dc, uc := h.startDevice(cl, "openid")
	// polling: the sign-in cannot be read; no device code at all, or an absurd one
	h.useEph(func(op, ns string) error {
		if op == "get" && ns == nsDevice {
			return boom
		}
		return nil
	})
	if r := h.pollDevice(cl, dc); r.status != 500 {
		t.Fatalf("poll: %d %v", r.status, r.m)
	}
	h.env.Server.Eph = good
	tokenErr(t, h.pollDevice(cl, ""), 400, "invalid_request")
	tokenErr(t, h.pollDevice(cl, strings.Repeat("d", 201)), 400, "invalid_request")

	// the verification page cannot start its flow
	h.useEph(func(op, ns string) error {
		if op == "new" && ns == nsFlow {
			return boom
		}
		return nil
	})
	b, _ := h.session(h.user)
	resp := h.get(b, "/device?user_code="+url.QueryEscape(uc))
	if pg := body(resp); resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(pg, "Something went wrong") {
		t.Fatalf("page: %d %s", resp.StatusCode, pg)
	}
}

// takenCodes answers every user code lookup with a waiting sign-in.
type takenCodes struct{ ephemeral.Store }

func (s takenCodes) Get(ctx context.Context, ns, id string) ([]byte, error) {
	if ns == nsDeviceUser {
		return []byte("x"), nil
	}
	return s.Store.Get(ctx, ns, id)
}

func TestCoverageDeviceUserCodeHelpers(t *testing.T) {
	if formatUserCode("ABC") != "ABC" || formatUserCode("WDJBMJHT") != "WDJB-MJHT" {
		t.Fatal("formatUserCode")
	}
	if normUserCode(strings.Repeat("B", 33)) != "" || normUserCode("WDJB-MJH1") != "" || normUserCode("bcdf ghjk") != "BCDFGHJK" {
		t.Fatal("normUserCode")
	}
}

func TestCoverageDevicePageStates(t *testing.T) {
	h := setup(t, nil)
	cl := h.deviceClient(nil)
	b, csrf := h.session(h.user)
	page := func(uc string) (int, string) {
		resp := h.get(b, "/device?user_code="+url.QueryEscape(uc))
		return resp.StatusCode, body(resp)
	}
	if st, pg := page("BCDF-GHJK"); st != 400 || !strings.Contains(pg, "not valid") {
		t.Fatalf("unknown: %d", st)
	}
	// a sign-in whose device code vanished
	dc, uc := h.startDevice(cl, "openid")
	_ = h.env.Server.Eph.Delete(context.Background(), nsDevice, dc)
	if st, _ := page(uc); st != 400 {
		t.Fatalf("expired: %d", st)
	}
	// a client that lost the grant, or was disabled, since
	dc, uc = h.startDevice(cl, "openid")
	if _, err := h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	if st, _ := page(uc); st != 400 {
		t.Fatalf("disabled client: %d", st)
	}
	if _, err := h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{Enabled: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	// denied already: the code is spent
	dc, uc = h.startDevice(cl, "openid")
	if st, _ := h.consentDevice(b, csrf, uc, false); st != 200 {
		t.Fatalf("deny: %d", st)
	}
	if st, _ := page(uc); st != 400 {
		t.Fatalf("decided: %d", st)
	}
	tokenErr(t, h.pollDevice(cl, dc), 400, "access_denied")
	// the sign-in is gone: nothing more to poll
	tokenErr(t, h.pollDevice(cl, dc), 400, "expired_token")
}

// Two browsers hold the same code; the first decision wins and the second finds the sign-in decided.
func TestCoverageDeviceSecondDecisionRefused(t *testing.T) {
	h := setup(t, nil)
	cl := h.deviceClient(nil)
	dc, uc := h.startDevice(cl, "openid")
	b1, csrf1 := h.session(h.user)
	b2, csrf2 := h.session(h.user)
	flowOf := func(b *http.Client) string {
		resp := h.get(b, "/device?user_code="+url.QueryEscape(uc))
		u := loc(t, resp)
		if u.Path != "/oauth/consent" {
			t.Fatalf("expected consent: %s", u)
		}
		return u.Query().Get("flow")
	}
	f1, f2 := flowOf(b1), flowOf(b2)
	decide := func(b *http.Client, csrf, flow string) (int, string) {
		req, _ := http.NewRequest(http.MethodPost, h.env.URL+"/api-internal/oauth/consent",
			strings.NewReader(fmt.Sprintf(`{"flow":%q,"approve":true}`, flow)))
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Content-Type", "application/json")
		r, err := b.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		text := body(r)
		if r.StatusCode == 200 {
			var out map[string]string
			_ = json.Unmarshal([]byte(text), &out)
			resp := h.get(b, out["redirect"]) // the decision is taken where the flow resumes
			return resp.StatusCode, body(resp)
		}
		return r.StatusCode, text
	}
	if st, bd := decide(b1, csrf1, f1); st != 200 {
		t.Fatalf("first: %d %s", st, bd)
	}
	st, bd := decide(b2, csrf2, f2)
	if st != http.StatusBadRequest && st != http.StatusOK {
		t.Fatalf("second: %d %s", st, bd)
	}
	if r := h.pollDevice(cl, dc); r.status != 200 {
		t.Fatalf("the first decision stands: %d %v (second answered %d %s)", r.status, r.m, st, bd)
	}
}

func TestCoverageDevicePrivilegedAtPoll(t *testing.T) {
	h := setup(t, nil)
	c, csrf := h.env.SessionAMR(h.env.Admin, []string{"pwd", "otp", "mfa"})
	pu, _ := url.Parse(h.env.URL)
	jar := h.anon().Jar
	jar.SetCookies(pu, c.Jar.Cookies(pu))
	admin := *c
	admin.Jar = jar
	cl := h.deviceClient(func(in *service.ClientInput) { in.DevicePrivileged = ptr(true) })
	dc, uc := h.startDevice(cl, "openid")
	if st, pg := h.consentDevice(&admin, csrf, uc, true); st != 200 {
		t.Fatalf("approve: %d %s", st, pg)
	}
	// the client stops accepting managers' approvals before the device collects its tokens
	if _, err := h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{DevicePrivileged: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	tokenErr(t, h.pollDevice(cl, dc), 400, "access_denied")
}
