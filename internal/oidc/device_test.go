package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
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
	r := h.post("/oauth/device_authorization", url.Values{"client_id": {c.ID}, "scope": {scope}}, "", "")
	if r.status != 200 {
		h.t.Fatalf("device authorization: %d %v", r.status, r.m)
	}
	if !userCodeRe.MatchString(r.str("user_code")) || r.str("verification_uri") != h.env.Cfg.Issuer()+"/device" ||
		r.str("verification_uri_complete") != h.env.Cfg.Issuer()+"/device?user_code="+url.QueryEscape(r.str("user_code")) ||
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
	resp := h.get(b, "/device?user_code="+url.QueryEscape(userCode))
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("device page: %d %s", resp.StatusCode, body(resp))
	}
	u := loc(h.t, resp)
	if u.Path != "/oauth/consent" {
		h.t.Fatalf("expected the consent screen: %s", u)
	}
	page := body(h.get(b, u.RequestURI()))
	if !strings.Contains(page, "Signing in a device") || !strings.Contains(page, `class="mono">`+formatUserCode(normUserCode(userCode))+`<`) {
		h.t.Fatalf("consent page has no device warning: %s", page)
	}
	bb, _ := json.Marshal(map[string]any{"flow": u.Query().Get("flow"), "approve": approve})
	req, _ := http.NewRequest(http.MethodPost, h.env.URL+"/api-internal/oauth/consent", strings.NewReader(string(bb)))
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Content-Type", "application/json")
	r, err := b.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	var out map[string]string
	_ = json.Unmarshal([]byte(body(r)), &out)
	if r.StatusCode != 200 {
		h.t.Fatalf("consent: %d", r.StatusCode)
	}
	resp = h.get(b, out["redirect"])
	return resp.StatusCode, body(resp)
}

func (h *harness) auditActions(action string) []*model.Audit {
	h.t.Helper()
	l, _, err := h.env.Svc.Audits.List(context.Background(), store.ListQuery{})
	if err != nil {
		h.t.Fatal(err)
	}
	var out []*model.Audit
	for _, a := range l {
		if a.Action == action {
			out = append(out, a)
		}
	}
	return out
}

// The device polls while the user signs in elsewhere, approves on the consent screen (always shown, with a warning
// and the code), and the device then gets its tokens once.
func TestDeviceGrant(t *testing.T) {
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
	resp := h.get(h.anon(), "/device?user_code="+url.QueryEscape(uc))
	if u := loc(t, resp); !strings.HasPrefix(u.Path, "/login/") || !strings.Contains(u.Query().Get("next"), "/oauth/authorize/resume") {
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
	resp = h.get(b, "/device?user_code="+url.QueryEscape(uc))
	if pg := body(resp); resp.StatusCode != 400 || !strings.Contains(pg, "That code is not valid") {
		t.Fatalf("used code: %d", resp.StatusCode)
	}
	if len(h.auditActions("oauth.device.approve")) != 1 {
		t.Fatal("approval not audited")
	}
	found := false
	for _, a := range h.auditActions("oauth.grant") {
		found = found || a.Detail["grant_type"] == "device_code"
	}
	if !found {
		t.Fatal("grant not audited as a device grant")
	}
}

// Deny on the consent screen tells the device: access_denied.
func TestDeviceGrantDenied(t *testing.T) {
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
}

// Only clients with the grant may start a device sign-in; a FAPI 2.0 client may not have it; another client cannot
// redeem a device code; unknown device codes have expired.
func TestDeviceGrantClients(t *testing.T) {
	h := setup(t, nil)
	plain := h.publicClient(nil)
	if r := h.post("/oauth/device_authorization", url.Values{"client_id": {plain.ID}}, "", ""); r.str("error") != "unauthorized_client" {
		t.Fatalf("client without the grant: %v", r.m)
	}
	if r := h.token(url.Values{"grant_type": {service.GrantDeviceCode}, "device_code": {"x"}}, plain, ""); r.str("error") != "unauthorized_client" {
		t.Fatalf("token without the grant: %v", r.m)
	}
	cl := h.deviceClient(nil)
	if r := h.post("/oauth/device_authorization", url.Values{"client_id": {cl.ID}, "scope": {"openid nope"}}, "", ""); r.str("error") != "invalid_scope" {
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
	var disc map[string]any
	_ = json.Unmarshal([]byte(body(h.get(h.anon(), "/.well-known/openid-configuration"))), &disc)
	if disc["device_authorization_endpoint"] != h.env.Cfg.Issuer()+"/oauth/device_authorization" ||
		!strings.Contains(strings.Join(toStrings(disc["grant_types_supported"]), " "), service.GrantDeviceCode) {
		t.Fatalf("discovery: %v %v", disc["device_authorization_endpoint"], disc["grant_types_supported"])
	}
}

func toStrings(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// Managers and above approve device sign-ins only where the client allows it.
func TestDeviceGrantPrivileged(t *testing.T) {
	h := setup(t, nil)
	c, csrf := h.env.SessionAMR(h.env.Admin, []string{"pwd", "otp", "mfa"})
	pu, _ := url.Parse(h.env.URL)
	jar, _ := cookiejar.New(nil)
	jar.SetCookies(pu, c.Jar.Cookies(pu))
	admin := *c
	admin.Jar = jar

	cl := h.deviceClient(nil)
	dc, uc := h.startDevice(cl, "openid")
	resp := h.get(&admin, "/device?user_code="+url.QueryEscape(uc))
	if pg := body(resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(pg, "Managers and administrators cannot sign in on devices") {
		t.Fatalf("administrator: %d %s", resp.StatusCode, pg)
	}
	if r := h.pollDevice(cl, dc); r.str("error") != "access_denied" {
		t.Fatalf("poll after refusal: %v", r.m)
	}

	allowed := h.deviceClient(func(in *service.ClientInput) { in.DevicePrivileged = ptr(true) })
	dc, uc = h.startDevice(allowed, "openid")
	if status, page := h.consentDevice(&admin, csrf, uc, true); status != 200 || !strings.Contains(page, "Your device is signed in") {
		t.Fatalf("allowed administrator: %d %s", status, page)
	}
	if r := h.pollDevice(allowed, dc); r.status != 200 {
		t.Fatalf("tokens: %v", r.m)
	}
}

// Wrong codes are limited per address; a malformed one says what a code looks like.
func TestDeviceCodeGuessing(t *testing.T) {
	h := setup(t, nil)
	b := h.anon()
	resp := h.get(b, "/device?user_code=12")
	if pg := body(resp); resp.StatusCode != 400 || !strings.Contains(pg, "8-letter code") {
		t.Fatalf("malformed: %d", resp.StatusCode)
	}
	for i := range deviceGuessesPerIP {
		if resp := h.get(b, "/device?user_code=BBBB-BBBB"); resp.StatusCode != 400 {
			t.Fatalf("guess %d: %d", i, resp.StatusCode)
		}
	}
	if resp := h.get(b, "/device?user_code=BBBB-BBBB"); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("over the limit: %d", resp.StatusCode)
	}
	// the page itself, and its form
	resp = h.get(b, "/device")
	if pg := body(resp); resp.StatusCode != 200 || !strings.Contains(pg, `name="user_code"`) || !strings.Contains(pg, "Never enter a code someone sent you") {
		t.Fatalf("device page: %d", resp.StatusCode)
	}
}

func TestUserCodes(t *testing.T) {
	for in, want := range map[string]string{"wdjb-mjht": "WDJBMJHT", " WDJB MJHT ": "WDJBMJHT", "WDJBMJH": "", "WDJA-MJHT": "", "WDJB-MJHT-X": ""} {
		if got := normUserCode(in); got != want {
			t.Errorf("normUserCode(%q) = %q, want %q", in, got, want)
		}
	}
	c, err := newUserCode()
	if err != nil || !userCodeRe.MatchString(formatUserCode(c)) {
		t.Fatalf("newUserCode: %q %v", c, err)
	}
}
