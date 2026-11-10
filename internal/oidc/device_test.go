package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/web"
)

var userCodeRe = regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`)

// deviceClient is a public client with the device grant (and refresh tokens).
func (h *harness) deviceClient(edit func(*service.ClientInput)) *model.Client {
	return h.publicClient(func(in *service.ClientInput) {
		in.GrantTypes = &[]string{"authorization_code", "refresh_token", service.GrantDeviceCode}
		in.Name = ptr("TV App")
		if edit != nil {
			edit(in)
		}
	})
}

// startDevice asks for a device sign-in and returns the device and user codes.
func (h *harness) startDevice(c *model.Client, scope string) (deviceCode, userCode string) {
	h.t.Helper()
	r := h.post(h.orgBase+"/oauth/device_authorization", url.Values{"client_id": {c.ID}, "scope": {scope}}, "", "")
	if r.status != 200 {
		h.t.Fatalf("device authorization: %d %v", r.status, r.m)
	}
	if !userCodeRe.MatchString(r.str("user_code")) || r.str("verification_uri") != h.issuer()+"/device" ||
		r.str("verification_uri_complete") != h.issuer()+"/device?user_code="+url.QueryEscape(r.str("user_code")) ||
		r.m["expires_in"] != float64(600) || r.m["interval"] != float64(5) || r.str("device_code") == "" {
		h.t.Fatalf("device authorization response: %v", r.m)
	}
	return r.str("device_code"), r.str("user_code")
}

func (h *harness) pollDevice(c *model.Client, deviceCode string) tokResp {
	return h.token(url.Values{"grant_type": {service.GrantDeviceCode}, "device_code": {deviceCode}}, c, "")
}

// consentDevice enters the user code in browser b (signed in, with its CSRF token) and decides on the consent screen.
// It returns the final page.
func (h *harness) consentDevice(b *http.Client, csrf, userCode string, approve bool) (int, string) {
	h.t.Helper()
	resp := h.get(b, h.orgBase+"/device?user_code="+url.QueryEscape(userCode))
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("device page: %d %s", resp.StatusCode, body(resp))
	}
	u := loc(h.t, resp)
	if u.Path != h.orgBase+"/oauth/consent" {
		h.t.Fatalf("expected the consent screen: %s", u)
	}
	page := body(h.get(b, u.RequestURI()))
	if !strings.Contains(page, "Signing in a device") || !strings.Contains(page, `class="mono">`+formatUserCode(normUserCode(userCode))+`<`) {
		h.t.Fatalf("consent page has no device warning: %s", page)
	}
	st, redirect := h.decideConsent(b, csrf, u.Query().Get("flow"), approve)
	if st != 200 {
		h.t.Fatalf("consent: %d", st)
	}
	resp = h.get(b, redirect)
	return resp.StatusCode, body(resp)
}

// The device polls while the user signs in elsewhere, approves on the consent screen (always shown, with a warning
// and the code), and the device then gets its tokens once.
func TestDeviceGrant(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.deviceClient(nil)
	dc, uc := h.startDevice(cl, "openid profile offline_access")

	if r := h.pollDevice(cl, dc); r.status != 400 || r.str("error") != "authorization_pending" {
		t.Fatalf("first poll: %d %v", r.status, r.m)
	}
	if r := h.pollDevice(cl, dc); r.str("error") != "slow_down" {
		t.Fatalf("a poll too soon: %v", r.m)
	}

	// signed out: the code leads to the sign-in page of the client's organization
	resp := h.get(h.anon(), h.orgBase+"/device?user_code="+url.QueryEscape(uc))
	if u := loc(t, resp); !strings.HasSuffix(u.Path, "/login") || !strings.Contains(u.Query().Get("next"), h.orgBase+"/oauth/authorize/resume") {
		t.Fatalf("signed out: %s", u)
	}

	b, csrf := h.session(h.user)
	// typed loosely: lower case, without the dash
	status, page := h.consentDevice(b, csrf, strings.ToLower(strings.ReplaceAll(uc, "-", "")), true)
	if status != 200 || !strings.Contains(page, "Your device is signed in to TV App") {
		t.Fatalf("after approving: %d %s", status, page)
	}

	r := h.pollDevice(cl, dc)
	if r.status != 200 || r.str("access_token") == "" || r.str("id_token") == "" || r.str("refresh_token") == "" {
		t.Fatalf("tokens: %d %v", r.status, r.m)
	}
	if claimsOf(t, r.str("id_token"))["sub"] != h.user.ID {
		t.Fatal("wrong subject")
	}
	if rr := h.refreshWith(cl, "", r.str("refresh_token")); rr.status != 200 {
		t.Fatalf("refresh: %v", rr.m)
	}
	// once only
	if r := h.pollDevice(cl, dc); r.str("error") != "expired_token" {
		t.Fatalf("second redemption: %v", r.m)
	}
	// the code no longer works on the page
	resp = h.get(b, h.orgBase+"/device?user_code="+url.QueryEscape(uc))
	if pg := body(resp); resp.StatusCode != 400 || !strings.Contains(pg, "That code is not valid") {
		t.Fatalf("used code: %d", resp.StatusCode)
	}
	if len(h.auditEvents("oauth.device.approve")) != 1 {
		t.Fatal("approval not audited")
	}
	found := false
	for _, a := range h.auditEvents("oauth.grant") {
		found = found || a.Detail["grant_type"] == "device_code"
	}
	if !found {
		t.Fatal("grant not audited as a device grant")
	}
}

// Deny on the consent screen tells the device: access_denied.
func TestDeviceGrantDenied(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.deviceClient(nil)
	dc, uc := h.startDevice(cl, "openid")
	b, csrf := h.session(h.user)
	status, page := h.consentDevice(b, csrf, uc, false)
	if status != 200 || !strings.Contains(page, "Your device was not signed in") {
		t.Fatalf("after denying: %d %s", status, page)
	}
	if r := h.pollDevice(cl, dc); r.str("error") != "access_denied" {
		t.Fatalf("poll after deny: %v", r.m)
	}
	if r := h.pollDevice(cl, dc); r.str("error") != "expired_token" {
		t.Fatalf("poll after the answer: %v", r.m)
	}
	// the code is spent: the page refuses it
	if resp := h.get(b, h.orgBase+"/device?user_code="+url.QueryEscape(uc)); body(resp) == "" || resp.StatusCode != 400 {
		t.Fatalf("page after the decision: %d", resp.StatusCode)
	}
}

// Only clients with the grant may start a device sign-in; a FAPI 2.0 client may not have it; another client cannot
// redeem a device code; unknown device codes have expired.
func TestDeviceGrantClients(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	plain := h.publicClient(nil)
	if r := h.post(h.orgBase+"/oauth/device_authorization", url.Values{"client_id": {plain.ID}}, "", ""); r.str("error") != "unauthorized_client" {
		t.Fatalf("client without the grant: %v", r.m)
	}
	if r := h.token(url.Values{"grant_type": {service.GrantDeviceCode}, "device_code": {"x"}}, plain, ""); r.str("error") != "unauthorized_client" {
		t.Fatalf("token without the grant: %v", r.m)
	}
	cl := h.deviceClient(nil)
	if r := h.post(h.orgBase+"/oauth/device_authorization", url.Values{"client_id": {cl.ID}, "scope": {"openid nope"}}, "", ""); r.str("error") != "invalid_scope" {
		t.Fatalf("scope: %v", r.m)
	}
	dc, _ := h.startDevice(cl, "")
	other := h.deviceClient(nil)
	if r := h.pollDevice(other, dc); r.str("error") != "invalid_grant" {
		t.Fatalf("another client's device code: %v", r.m)
	}
	if r := h.pollDevice(cl, "n1.unknown"); r.str("error") != "expired_token" {
		t.Fatalf("unknown device code: %v", r.m)
	}
	_, _, err := h.env.Svc.CreateClient(context.Background(), h.admin, h.env.Primary.ID, service.ClientInput{Name: ptr("fapi"),
		RedirectURIs: &[]string{rpCallback}, GrantTypes: &[]string{"authorization_code", service.GrantDeviceCode},
		AuthMethod: ptr(model.AuthMethodPrivateJWT), JWKSURI: ptr("https://rp.example/jwks"), FAPI: ptr(true)})
	if err == nil || !strings.Contains(err.Error(), "device") {
		t.Fatalf("FAPI client with the device grant: %v", err)
	}
}

// Managers and above approve device sign-ins only where the client allows it.
func TestDeviceGrantPrivileged(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	admin, csrf := h.adminBrowser()
	cl := h.deviceClient(nil)
	dc, uc := h.startDevice(cl, "openid")
	resp := h.get(admin, h.orgBase+"/device?user_code="+url.QueryEscape(uc))
	if pg := body(resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(pg, "Managers and administrators cannot sign in on devices") {
		t.Fatalf("administrator: %d %s", resp.StatusCode, pg)
	}
	if r := h.pollDevice(cl, dc); r.str("error") != "access_denied" {
		t.Fatalf("poll after refusal: %v", r.m)
	}

	allowed := h.deviceClient(func(in *service.ClientInput) { in.DevicePrivileged = ptr(true) })
	dc, uc = h.startDevice(allowed, "openid")
	if status, page := h.consentDevice(admin, csrf, uc, true); status != 200 || !strings.Contains(page, "Your device is signed in") {
		t.Fatalf("allowed administrator: %d %s", status, page)
	}
	if r := h.pollDevice(allowed, dc); r.status != 200 {
		t.Fatalf("tokens: %v", r.m)
	}
}

// Wrong codes are limited per address; a malformed one says what a code looks like.
func TestDeviceCodeGuessing(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	b := h.anon()
	resp := h.get(b, h.orgBase+"/device?user_code=12")
	if pg := body(resp); resp.StatusCode != 400 || !strings.Contains(pg, "8-letter code") {
		t.Fatalf("malformed: %d", resp.StatusCode)
	}
	for i := range deviceGuessesPerIP {
		if resp := h.get(b, h.orgBase+"/device?user_code=BBBB-BBBB"); resp.StatusCode != 400 {
			t.Fatalf("guess %d: %d", i, resp.StatusCode)
		}
	}
	if resp := h.get(b, h.orgBase+"/device?user_code=BBBB-BBBB"); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("over the limit: %d", resp.StatusCode)
	}
	// the page itself, and its form
	resp = h.get(b, h.orgBase+"/device")
	if pg := body(resp); resp.StatusCode != 200 || !strings.Contains(pg, `name="user_code"`) || !strings.Contains(pg, "Never enter a code someone sent you") {
		t.Fatalf("device page: %d", resp.StatusCode)
	}
}

func TestUserCodes(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"wdjb-mjht": "WDJBMJHT", " WDJB MJHT ": "WDJBMJHT", "WDJBMJH": "", "WDJA-MJHT": "", "WDJB-MJHT-X": "",
		strings.Repeat("B", 33): ""} {
		if got := normUserCode(in); got != want {
			t.Errorf("normUserCode(%q) = %q, want %q", in, got, want)
		}
	}
	if formatUserCode("ABC") != "ABC" || formatUserCode("WDJBMJHT") != "WDJB-MJHT" {
		t.Error("formatUserCode")
	}
	c, err := newUserCode()
	if err != nil || !userCodeRe.MatchString(formatUserCode(c)) {
		t.Fatalf("newUserCode: %q %v", c, err)
	}
}

func TestDeviceAuthorizationRefusals(t *testing.T) {
	t.Parallel()
	h := setup(t, func(c *config.Config) { c.Audit.Tokens = true })
	cl := h.deviceClient(nil)
	post := func(f url.Values) tokResp { return h.post(h.orgBase+"/oauth/device_authorization", f, "", "") }

	tokenErr(t, post(url.Values{"client_id": {cl.ID, cl.ID}}), 400, "invalid_request")
	if r := post(url.Values{"client_id": {"nosuchclient"}}); r.status != 401 || r.str("error") != "invalid_client" {
		t.Fatalf("%d %v", r.status, r.m)
	}
	tokenErr(t, post(url.Values{"client_id": {cl.ID}, "resource": {"https://other.example"}}), 400, "invalid_target")
	tokenErr(t, post(url.Values{"client_id": {cl.ID}, "resource": {"nope"}}), 400, "invalid_target")

	h.startDevice(cl, "openid")
	if len(h.auditEvents("oauth.device.start")) != 1 {
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

func TestDeviceFailsClosedOnStoreFailures(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.deviceClient(nil)
	start := func() tokResp {
		return h.post(h.orgBase+"/oauth/device_authorization", url.Values{"client_id": {cl.ID}, "scope": {"openid"}}, "", "")
	}
	boom := errors.New("ephemeral down")
	good := h.env.Server.Eph

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
	h.useEphFaults(faultEph{answer: func(ns, id string) []byte {
		if ns == nsDeviceUser {
			return []byte("x")
		}
		return nil
	}})
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
	resp := h.get(b, h.orgBase+"/device?user_code="+url.QueryEscape(uc))
	if pg := body(resp); resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(pg, "Something went wrong") {
		t.Fatalf("page: %d %s", resp.StatusCode, pg)
	}
}

func TestDevicePageRefusesStaleCodes(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.deviceClient(nil)
	b, _ := h.session(h.user)
	page := func(uc string) (int, string) {
		resp := h.get(b, h.orgBase+"/device?user_code="+url.QueryEscape(uc))
		return resp.StatusCode, body(resp)
	}
	// a sign-in whose device code vanished
	dc, uc := h.startDevice(cl, "openid")
	_ = h.env.Server.Eph.Delete(context.Background(), nsDevice, dc)
	if st, _ := page(uc); st != 400 {
		t.Fatalf("expired: %d", st)
	}
	// a client disabled since
	_, uc = h.startDevice(cl, "openid")
	if _, err := h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	if st, _ := page(uc); st != 400 {
		t.Fatalf("disabled client: %d", st)
	}
}

// Two browsers hold the same code; the first decision wins and the second finds the sign-in decided.
func TestDeviceSecondApprovalRefused(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.deviceClient(nil)
	dc, uc := h.startDevice(cl, "openid")
	b1, csrf1 := h.session(h.user)
	b2, csrf2 := h.session(h.user)
	flowOf := func(b *http.Client) string {
		resp := h.get(b, h.orgBase+"/device?user_code="+url.QueryEscape(uc))
		u := loc(t, resp)
		if u.Path != h.orgBase+"/oauth/consent" {
			t.Fatalf("expected consent: %s", u)
		}
		return u.Query().Get("flow")
	}
	f1, f2 := flowOf(b1), flowOf(b2)
	decide := func(b *http.Client, csrf, flow string) (int, string) {
		st, redirect := h.decideConsent(b, csrf, flow, true)
		if st == 200 {
			resp := h.get(b, redirect) // the decision is taken where the flow resumes
			return resp.StatusCode, body(resp)
		}
		return st, ""
	}
	if st, bd := decide(b1, csrf1, f1); st != 200 {
		t.Fatalf("first: %d %s", st, bd)
	}
	if st, bd := decide(b2, csrf2, f2); st != http.StatusBadRequest || !strings.Contains(bd, "This code can no longer be used") {
		t.Fatalf("second: %d %s", st, bd)
	}
	if r := h.pollDevice(cl, dc); r.status != 200 {
		t.Fatalf("the first decision stands: %d %v", r.status, r.m)
	}
}

func TestDevicePrivilegedRevokedBeforePoll(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	admin, csrf := h.adminBrowser()
	cl := h.deviceClient(func(in *service.ClientInput) { in.DevicePrivileged = ptr(true) })
	dc, uc := h.startDevice(cl, "openid")
	if st, pg := h.consentDevice(admin, csrf, uc, true); st != 200 {
		t.Fatalf("approve: %d %s", st, pg)
	}
	// the client stops accepting managers' approvals before the device collects its tokens
	if _, err := h.env.Svc.UpdateClient(context.Background(), h.admin, cl.ID, service.ClientInput{DevicePrivileged: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	h.p.InvalidateClient(cl.ID)
	tokenErr(t, h.pollDevice(cl, dc), 400, "access_denied")
}

func TestDevicePollDuringApprovalStaysPending(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	local := ephemeral.NewLocal("device-poll")
	defer local.Close()
	// the approval pauses just before it records the decision: the window in which a poll must not see the sign-in gone
	g := newGate(t)
	p := &Provider{s: &web.Server{Eph: faultEph{Store: local, before: func(op, ns string) error {
		if op == "set" && ns == nsDevice {
			g.hold()
		}
		return nil
	}}}}
	raw, _ := json.Marshal(deviceGrant{ClientID: "client", UserCode: "BCDFGHJK", Expires: time.Now().Add(time.Minute).Unix()})
	id, _ := local.New(ctx, nsDevice, raw, time.Minute)
	_ = local.Set(ctx, nsDeviceTurn, id, []byte{1}, time.Minute)
	done := make(chan bool, 1)
	go func() {
		done <- p.decideDevice(ctx, &flow{Device: id}, true, &model.Session{AuthTime: time.Now()}, &model.User{}, "", 0)
	}()
	g.waitHeld(t)
	_, oe := p.deviceToken(ctx, &model.Client{Meta: model.Meta{ID: "client"}}, id, nil, "")
	g.open()
	if !<-done {
		t.Fatal("approval failed")
	}
	if oe == nil || oe.code != "authorization_pending" {
		t.Fatalf("live device grant returned terminal expiry during approval: %v", oe)
	}
}

// An approved device sign-in whose tokens cannot be made on our side (503) stays approved: the next poll gets them,
// and the user does not have to approve again.
func TestDeviceApprovalKeptWhenIssueFails(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.deviceClient(nil)
	deviceCode, userCode := h.startDevice(cl, "openid")
	b, csrf := h.session(h.user)
	if status, _ := h.consentDevice(b, csrf, userCode, true); status != 200 {
		t.Fatalf("approve: %d", status)
	}
	users := h.env.Svc.Users.S
	h.env.Svc.Users.S = failReads(users, model.KindUser)
	h.p.users.Clear()
	if r := h.pollDevice(cl, deviceCode); r.status != 503 {
		t.Fatalf("with the user unreadable: %d %v", r.status, r.m)
	}
	h.env.Svc.Users.S = users
	h.p.users.Clear()
	if r := h.pollDevice(cl, deviceCode); r.status != 200 || r.str("access_token") == "" {
		t.Fatalf("the next poll: %d %v", r.status, r.m)
	}
}

// adminBrowser is a browser of its own signed in as the administrator with a second factor, with its CSRF token.
func (h *harness) adminBrowser() (*http.Client, string) {
	h.t.Helper()
	c, csrf := h.env.SessionAMR(h.env.Admin, []string{"pwd", "otp", "mfa"})
	pu, _ := url.Parse(h.env.URL)
	browser := h.anon()
	browser.Jar.SetCookies(pu, c.Jar.Cookies(pu))
	return browser, csrf
}

// startDeviceWith is startDevice with more parameters of the device authorization request.
func (h *harness) startDeviceWith(c *model.Client, extra url.Values) (deviceCode, userCode string) {
	h.t.Helper()
	form := url.Values{"client_id": {c.ID}, "scope": {"openid profile"}}
	for k, v := range extra {
		form[k] = v
	}
	r := h.post(h.orgBase+"/oauth/device_authorization", form, "", "")
	if r.status != 200 {
		h.t.Fatalf("device authorization: %d %v", r.status, r.m)
	}
	return r.str("device_code"), r.str("user_code")
}

// The sign-in that approves a device meets the acr_values and max_age the device asked for, as an authorization
// request's does: a password-only session is sent to step up (a second factor) and an older one to sign in again,
// where without them the session goes straight to the consent screen.
func TestDeviceGrantAcrValuesAndMaxAge(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl := h.deviceClient(nil)
	toLogin := func(c *http.Client, extra url.Values) *url.URL {
		t.Helper()
		_, uc := h.startDeviceWith(cl, extra)
		resp := h.get(c, h.orgBase+"/device?user_code="+url.QueryEscape(uc))
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("device page: %d %s", resp.StatusCode, body(resp))
		}
		return loc(t, resp)
	}
	wantConsent := func(what string, u *url.URL) {
		t.Helper()
		if u.Path != h.orgBase+"/oauth/consent" {
			t.Errorf("%s: expected the consent screen: %s", what, u)
		}
	}
	wantSignIn := func(what string, u *url.URL) {
		t.Helper()
		if !strings.HasSuffix(u.Path, "/login") || u.Query().Get("reauth") != "1" ||
			!strings.Contains(u.Query().Get("next"), h.orgBase+"/oauth/authorize/resume") {
			t.Errorf("%s: expected a new sign-in: %s", what, u)
		}
	}

	pwd := h.sessionWith(h.user, []string{"pwd"}, time.Now())
	mfa := h.sessionWith(h.user, mfaAMR, time.Now())
	wantConsent("password session, nothing asked", toLogin(pwd, nil))
	wantSignIn("password session, acr_values mfa", toLogin(pwd, url.Values{"acr_values": {acrMFA}}))
	wantConsent("password session, acr_values basic", toLogin(pwd, url.Values{"acr_values": {acrBasic}}))
	wantConsent("mfa session, acr_values mfa", toLogin(mfa, url.Values{"acr_values": {acrMFA}}))

	old := h.sessionWith(h.user, mfaAMR, time.Now().Add(-2*time.Hour))
	wantConsent("old session, nothing asked", toLogin(old, nil))
	wantSignIn("old session, max_age 3600", toLogin(old, url.Values{"max_age": {"3600"}}))
	wantConsent("old session, max_age 86400", toLogin(old, url.Values{"max_age": {"86400"}}))
	wantSignIn("fresh session, max_age 0", toLogin(h.sessionWith(h.user, mfaAMR, time.Now().Add(-time.Second)), url.Values{"max_age": {"0"}}))

	// a max_age that is not a number of seconds is refused
	for _, bad := range []string{"-1", "soon", "1.5"} {
		r := h.post(h.orgBase+"/oauth/device_authorization", url.Values{"client_id": {cl.ID}, "scope": {"openid"}, "max_age": {bad}}, "", "")
		if r.status != 400 || r.str("error") != "invalid_request" {
			t.Errorf("max_age %q: %d %v", bad, r.status, r.m)
		}
	}
}
