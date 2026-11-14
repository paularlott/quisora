package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/metrics"
)

// startFrom sends an authorization request for q from address ip (cookies added) straight to the server's handler.
func (h *harness) startFrom(ip string, q url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, h.orgBase+"/oauth/authorize?"+q.Encode(), nil)
	return h.serveFrom(ip, req, cookies...)
}

func (h *harness) serveFrom(ip string, req *http.Request, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	h.t.Helper()
	req.RemoteAddr = withPort(ip)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.env.Server.Handler().ServeHTTP(rec, req)
	return rec
}

// withPort is ip with a port, as RemoteAddr carries it.
func withPort(ip string) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]:4000"
	}
	return ip + ":4000"
}

// startedFlow is the id of the flow a started sign-in holds (in the sign-in page's next) and its binding cookie.
func startedFlow(t *testing.T, rec *httptest.ResponseRecorder) (string, *http.Cookie) {
	t.Helper()
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != http.StatusFound {
		t.Fatalf("not a started sign-in: %d %s", rec.Code, rec.Body)
	}
	next, _ := url.Parse(u.Query().Get("next"))
	id := next.Query().Get("flow")
	for _, c := range rec.Result().Cookies() {
		if c.Name == flowCookieName(id) {
			return id, c
		}
	}
	t.Fatalf("no flow cookie for %q", id)
	return "", nil
}

// A node whose short-lived state is full answers a new sign-in with the "try again" page (503, Retry-After), and the
// device authorization endpoint with temporarily_unavailable: never a server_error sent back to the application. The
// refusals are counted; the address's flow slot is given back.
func TestFullEphemeralStoreAnswers503(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	dev := h.deviceClient(nil)
	local, ok := h.env.Server.Eph.(*ephemeral.Local)
	if !ok {
		t.Fatalf("the test server's ephemeral store is %T", h.env.Server.Eph)
	}
	local.Budget = 1 // nothing more fits; counters are still kept
	before := metrics.EphemeralRefused.Value("full")
	_, ch := pkce()
	rec := h.startFrom("198.51.100.20", authzQuery(cl, ch, nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" || rec.Header().Get("Location") != "" ||
		!strings.Contains(rec.Body.String(), "Please try again") {
		t.Fatalf("a sign-in on a full node: %d %q %q", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	if n, _ := ephemeral.Holding(context.Background(), h.env.Server.Eph, nsHeld, "198.51.100.20", flowTTL); n != 0 {
		t.Fatalf("the refused flow still holds a slot: %d", n)
	}
	if n, _ := ephemeral.Holding(context.Background(), h.env.Server.Eph, ephemeral.HeldNS, "ip|198.51.100.20", flowTTL); n != 0 {
		t.Fatalf("the refused flow's bytes are still charged to its address: %d", n)
	}
	r := h.post(h.orgBase+"/oauth/device_authorization", url.Values{"client_id": {dev.ID}, "scope": {"openid"}}, "", "")
	if r.status != http.StatusServiceUnavailable || r.str("error") != "temporarily_unavailable" || r.hdr.Get("Retry-After") == "" {
		t.Fatalf("a device sign-in on a full node: %d %v", r.status, r.m)
	}
	if got := metrics.EphemeralRefused.Value("full") - before; got < 2 {
		t.Fatalf("%d refusals counted", got)
	}
	local.Budget = 0 // the default again: sign-ins start
	if rec := h.startFrom("198.51.100.20", authzQuery(cl, ch, nil)); rec.Code != http.StatusFound {
		t.Fatalf("after room was made: %d", rec.Code)
	}
}

// One address holds at most limits.flows_per_ip sign-ins in progress (an IPv6 /64 counts as one address); past it
// new ones get 429. Ending one (cancelled, or finished with a code) gives its slot back, once however often it is
// ended, and other addresses are not held back.
func TestFlowsPerIPCap(t *testing.T) {
	t.Parallel()
	h := setup(t, func(c *config.Config) { c.Limits.FlowsPerIP = 3 })
	cl, _ := h.newClient(nil)
	_, ch := pkce()
	q := authzQuery(cl, ch, nil)
	before := metrics.EphemeralRefused.Value("flows_per_ip")

	var ids []string
	var cookies []*http.Cookie
	for range 3 {
		id, ck := startedFlow(t, h.startFrom("198.51.100.30", q))
		ids, cookies = append(ids, id), append(cookies, ck)
	}
	rec := h.startFrom("198.51.100.30", q)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" ||
		!strings.Contains(rec.Body.String(), "Too many sign-ins in progress") {
		t.Fatalf("a fourth sign-in from one address: %d %s", rec.Code, rec.Body)
	}
	if got := metrics.EphemeralRefused.Value("flows_per_ip") - before; got != 1 {
		t.Fatalf("%d refusals counted, want 1", got)
	}
	startedFlow(t, h.startFrom("198.51.100.31", q)) // another address is not held back

	// IPv6: the addresses of one /64 share their slots, another /64 has its own
	for _, ip := range []string{"2001:db8::1", "2001:db8::2", "2001:db8::3"} {
		startedFlow(t, h.startFrom(ip, q))
	}
	if rec := h.startFrom("2001:db8::4", q); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a fourth sign-in from one /64: %d", rec.Code)
	}
	startedFlow(t, h.startFrom("2001:db8:0:1::1", q))

	// a cancelled sign-in gives its slot back, once: cancelling it again frees nothing more
	cancel := func() int {
		req := httptest.NewRequest(http.MethodGet, h.orgBase+"/oauth/authorize/cancel?flow="+url.QueryEscape(ids[0]), nil)
		return h.serveFrom("198.51.100.30", req, cookies[0]).Code
	}
	if code := cancel(); code != http.StatusFound {
		t.Fatalf("cancel: %d", code)
	}
	_ = cancel()
	startedFlow(t, h.startFrom("198.51.100.30", q))
	if rec := h.startFrom("198.51.100.30", q); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a slot was given back twice: %d", rec.Code)
	}

	// sign-ins that finish with a code give theirs back: one browser signs in again and again from one address
	c, _ := h.session(h.user)
	for i := range 6 {
		if code := h.getCode(c, cl, ch, nil); code == "" {
			t.Fatalf("sign-in %d", i)
		}
	}
	if n, _ := h.env.Server.Eph.Incr(context.Background(), nsHeld, "127.0.0.1", 0, time.Minute); n != 0 {
		t.Fatalf("finished sign-ins still hold %d slots", n)
	}
}
