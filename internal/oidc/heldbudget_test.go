package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/metrics"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// localEph is the test server's own short-lived state.
func (h *harness) localEph() *ephemeral.Local {
	h.t.Helper()
	local, ok := h.env.Server.Eph.(*ephemeral.Local)
	if !ok {
		h.t.Fatalf("the test server's ephemeral store is %T", h.env.Server.Eph)
	}
	return local
}

// One address holds at most limits.held_kb of sign-in flows, whatever their number and however large it makes them:
// past it new ones get 429 (counted), other addresses are not held back, and a flow that ends gives its bytes back.
func TestFlowBytesHeldPerAddress(t *testing.T) {
	t.Parallel()
	h := setup(t, func(c *config.Config) { c.Limits.FlowsPerIP, c.Limits.HeldKB = 1000, 64 })
	cl, _ := h.newClient(nil)
	_, ch := pkce()
	q := authzQuery(cl, ch, url.Values{"state": {strings.Repeat("s", 2000)}, "nonce": {strings.Repeat("n", 1000)}})
	local := h.localEph()
	used, refused := local.Used(), metrics.EphemeralRefused.Value("held_bytes")
	var ids []string
	var cookies []*http.Cookie
	var rec *httptest.ResponseRecorder
	for range 200 {
		if rec = h.startFrom("198.51.100.60", q); rec.Code != http.StatusFound {
			break
		}
		id, ck := startedFlow(t, rec)
		ids, cookies = append(ids, id), append(cookies, ck)
	}
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" ||
		!strings.Contains(rec.Body.String(), "Too many sign-ins in progress") {
		t.Fatalf("after %d flows of 3 KB from one address: %d %.200s", len(ids), rec.Code, rec.Body)
	}
	if len(ids) < 5 || len(ids) > 22 {
		t.Fatalf("%d flows of about 3.5 KB held within 64 KiB", len(ids))
	}
	if grew := local.Used() - used; grew > 64<<10 {
		t.Fatalf("one address holds %d bytes of flows, past its 64 KiB", grew)
	}
	if got := metrics.EphemeralRefused.Value("held_bytes") - refused; got != 1 {
		t.Fatalf("%d refusals counted, want 1", got)
	}
	startedFlow(t, h.startFrom("198.51.100.61", q)) // another address has its own
	// a cancelled sign-in gives its bytes back, once
	cancel := func() {
		req := httptest.NewRequest(http.MethodGet, h.orgBase+"/oauth/authorize/cancel?flow="+url.QueryEscape(ids[0]), nil)
		h.serveFrom("198.51.100.60", req, cookies[0])
	}
	cancel()
	cancel()
	startedFlow(t, h.startFrom("198.51.100.60", q))
	if rec := h.startFrom("198.51.100.60", q); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a cancelled flow gave its bytes back twice: %d", rec.Code)
	}
}

// setEph records how long the last value set in namespace ns was to be kept, and how many were set.
type setEph struct {
	ephemeral.Store
	ns   string
	ttl  *time.Duration
	sets *int
}

func (e setEph) Set(ctx context.Context, ns, id string, v []byte, ttl time.Duration) error {
	if ns == e.ns {
		*e.ttl = ttl
		*e.sets++
	}
	return e.Store.Set(ctx, ns, id, v, ttl)
}

// A flow stored again by a later step (sent to sign in, a decision made) ends when it was to end as it started, not
// twenty minutes after the step: its address was charged for it for that long, and a flow each visit kept alive
// would be held long after its slot and bytes were forgotten. It is replaced where it is, with the expiry it has
// (ephemeral.Store.Replace keeps it: TestReplaceKeepsExpiry), never set for a time of the step's choosing.
func TestFlowStoredAgainKeepsItsExpiry(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(nil)
	_, ch := pkce()
	id, _ := startedFlow(t, h.startFrom("198.51.100.62", authzQuery(cl, ch, nil)))
	ctx := context.Background()
	raw, err := h.env.Server.Eph.Get(ctx, nsFlow, id)
	if err != nil {
		t.Fatal(err)
	}
	var f flow
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	var ttl time.Duration
	var sets int
	orig := h.env.Server.Eph
	h.env.Server.Eph = setEph{Store: orig, ns: nsFlow, ttl: &ttl, sets: &sets}
	t.Cleanup(func() { h.env.Server.Eph = orig })
	f.Logins = 3
	if err := h.p.saveFlow(ctx, id, &f); err != nil {
		t.Fatal(err)
	}
	if sets != 0 {
		t.Fatalf("a flow was stored again with a time of its own (%s), not replaced with the expiry it had", ttl)
	}
	raw, _ = orig.Get(ctx, nsFlow, id)
	var saved flow
	if json.Unmarshal(raw, &saved) != nil || saved.Logins != 3 {
		t.Fatalf("the flow was not saved: %s", raw)
	}
	// one that has gone is not made again
	if _, err := orig.Take(ctx, nsFlow, id); err != nil {
		t.Fatal(err)
	}
	if err := h.p.saveFlow(ctx, id, &f); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("saving a flow that has gone: %v", err)
	}
	if _, err := orig.Get(ctx, nsFlow, id); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("a flow that had gone was made again by saving it: %v", err)
	}
}

// A string presented as a code that this client never began to redeem leaves nothing behind: anyone can present
// any string, and a mark for each would be state of the presenter's choosing.
func TestUnknownCodeKeepsNothing(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	pub := h.publicClient(nil)
	local := h.localEph()
	used, guarded, entries := local.Used(), local.Guarded(), local.Len()
	for i := range 20 {
		r := h.token(url.Values{"grant_type": {"authorization_code"}, "code": {strings.Repeat("x", 190) + strconv.Itoa(i)},
			"redirect_uri": {pub.RedirectURIs[0]}, "code_verifier": {strings.Repeat("v", 43)}}, pub, "")
		if r.status != 400 || r.str("error") != "invalid_grant" {
			t.Fatalf("an unknown code: %d %v", r.status, r.m)
		}
	}
	if local.Used() != used || local.Guarded() != guarded {
		t.Fatalf("20 unknown codes left %d bytes of sign-in state and %d of guard records", local.Used()-used, local.Guarded()-guarded)
	}
	if grew := local.Len() - entries; grew > 4 { // the request counters only
		t.Fatalf("20 unknown codes left %d entries", grew)
	}
}

// Replay detection does not lapse when sign-in state fills the node: the record of a code's use has room of its
// own, so a code redeemed on a full node and presented again still ends what was issued from it.
func TestCodeReplayEndsGrantOnFullNode(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	local := h.localEph()
	local.Budget = 1 // nothing more fits among the sign-in state
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]}, "code_verifier": {v}}
	r := h.token(form, cl, secret)
	if r.status != 200 {
		t.Fatalf("redeeming a code on a full node: %d %v", r.status, r.m)
	}
	if r := h.token(form, cl, secret); r.status != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("replay: %d %v", r.status, r.m)
	}
	if x := h.refreshWith(cl, secret, r.str("refresh_token")); x.status != 400 {
		t.Fatalf("the grant survived its code's replay on a full node: %d %v", x.status, x.m)
	}
}

// A code is not redeemed when the record of its use cannot be kept (the guard records' room is full): nothing could
// then notice its replay. The code is still there once there is room.
func TestCodeNotRedeemedWithoutItsRecord(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	local := h.localEph()
	local.GuardBudget = 1
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]}, "code_verifier": {v}}
	if r := h.token(form, cl, secret); r.status != http.StatusServiceUnavailable || r.str("error") != "temporarily_unavailable" {
		t.Fatalf("a redemption whose record cannot be kept: %d %v", r.status, r.m)
	}
	local.GuardBudget = 0
	if r := h.token(form, cl, secret); r.status != 200 {
		t.Fatalf("the code after room was made: %d %v", r.status, r.m)
	}
}

// slow_down does not lapse when sign-in state fills the node: a device that polls again at once is told to slow down.
func TestDevicePollSlowsDownOnFullNode(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	dev := h.deviceClient(nil)
	dc, _ := h.startDevice(dev, "openid")
	dc2, _ := h.startDevice(dev, "openid")
	local := h.localEph()
	local.Budget = 1
	if r := h.pollDevice(dev, dc); r.str("error") != "authorization_pending" {
		t.Fatalf("first poll: %d %v", r.status, r.m)
	}
	if r := h.pollDevice(dev, dc); r.str("error") != "slow_down" {
		t.Fatalf("a poll at once after another, on a full node: %d %v", r.status, r.m)
	}
	// and with no room for its record at all, a poll is told to slow down rather than left unlimited
	local.GuardBudget = 1
	if r := h.pollDevice(dev, dc2); r.str("error") != "slow_down" {
		t.Fatalf("a poll whose time cannot be kept: %d %v", r.status, r.m)
	}
}

// The device sign-ins an address has waiting are charged to it in bytes: past limits.held_kb the next is refused
// (429 slow_down), well within the thirty a minute it may start. A public client's starts are audited once per
// client and address a minute, not once each.
func TestDeviceStartsHeldAndAuditedOnce(t *testing.T) {
	t.Parallel()
	h := setup(t, func(c *config.Config) { c.Audit.Tokens, c.Limits.HeldKB = true, 64 })
	// a sign-in for ten resources with long names: what it holds is the request's to choose, within the client's
	var resources []string
	for i := range 10 {
		resources = append(resources, "https://api.example/"+strings.Repeat("r", 480)+strconv.Itoa(i))
	}
	dev := h.deviceClient(func(in *service.ClientInput) { in.Resources = &resources })
	started := 0
	var r tokResp
	for range 25 { // fewer than an address may start in a minute
		r = h.post(h.orgBase+"/oauth/device_authorization", url.Values{"client_id": {dev.ID}, "scope": {"openid"}, "resource": resources}, "", "")
		if r.status != 200 {
			break
		}
		started++
	}
	if r.status != http.StatusTooManyRequests || r.str("error") != "slow_down" || r.hdr.Get("Retry-After") == "" ||
		!strings.Contains(r.str("error_description"), "waiting") {
		t.Fatalf("after %d device sign-ins from one address: %d %v", started, r.status, r.m)
	}
	if started < 4 || started > 12 {
		t.Fatalf("%d device sign-ins of about 6 KB held within 64 KiB", started)
	}
	if ev := h.auditEvents("oauth.device.start"); len(ev) != 1 {
		t.Fatalf("%d oauth.device.start events for %d starts of a public client from one address", len(ev), started)
	}
}

// A session has one sign-out waiting for its confirmation, however often the sign-out endpoint is asked: an account
// (or a page that sends its browser there) cannot have a record kept for each request.
func TestLogoutConfirmationOnePerSession(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) { in.PostLogoutURIs = &[]string{"https://rp.example/bye"} })
	c, _ := h.session(h.user)
	local := h.localEph()
	q := url.Values{"client_id": {cl.ID}, "post_logout_redirect_uri": {"https://rp.example/bye"}, "state": {strings.Repeat("<", 2000)}}
	body(h.get(c, h.orgBase+"/oauth/logout?"+q.Encode()))
	used, entries := local.Used(), local.Len()
	for range 30 {
		if resp := h.get(c, h.orgBase+"/oauth/logout?"+q.Encode()); resp.StatusCode != 200 {
			t.Fatalf("confirmation page: %d", resp.StatusCode)
		} else {
			body(resp)
		}
	}
	if local.Used() != used || local.Len() != entries {
		t.Fatalf("30 more sign-out requests of one session left %d bytes in %d entries", local.Used()-used, local.Len()-entries)
	}
}

// The codes a signed-in user is issued and does not redeem are charged to the user: past limits.held_kb the next
// request gets 429 and its flow is kept.
func TestCodesHeldPerUser(t *testing.T) {
	t.Parallel()
	h := setup(t, func(c *config.Config) { c.Limits.HeldKB = 64 })
	cl, _ := h.newClient(nil)
	c, _ := h.session(h.user)
	_, ch := pkce()
	q := authzQuery(cl, ch, url.Values{"nonce": {strings.Repeat("n", 1000)}}) // the code carries the nonce
	issued := 0
	var resp *http.Response
	for range 100 {
		resp = h.get(c, h.orgBase+"/oauth/authorize?"+q.Encode())
		body(resp)
		if resp.StatusCode != http.StatusFound {
			break
		}
		issued++
	}
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("after %d codes issued to one user and not redeemed: %d", issued, resp.StatusCode)
	}
	if issued < 10 || issued > 45 {
		t.Fatalf("%d codes of about 1.7 KB held within 64 KiB", issued)
	}
	// another user is not held back
	other := h.sshUser("heldother", model.RoleUser)
	oc, _ := h.session(other)
	h.getCode(oc, cl, ch, nil)
}

// A sign-in to an application not stored yet keeps what its metadata document said, encoded again, not the document:
// padding and escapes in a document of the largest size do not come to rest in every flow that names it. And each
// such sign-in counts against its address's metadata budget whether the document was read for it or found shared, so
// one read a minute of one document does not serve flows without number.
func TestMetadataFlowKeepsSummaryAndCountsSharedReads(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	const redirect = "http://127.0.0.1:44021/callback"
	srv, hits := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		id := "https://" + r.Host + r.URL.Path
		_, _ = w.Write([]byte(`{"client_id":"` + id + `","client_name":"Gen","redirect_uris":["` + redirect +
			`"],"padding":"` + strings.Repeat("<", 4800) + `"}`))
	})
	h.p.HTTP = srv.Client()
	local := h.localEph()
	_, ch := pkce()
	cl := &model.Client{Meta: model.Meta{ID: srv.URL + "/app"}, RedirectURIs: []string{redirect}}
	q := authzQuery(cl, ch, url.Values{"resource": {mcpResource}, "scope": {"openid"}})
	used := local.Used()
	id, _ := startedFlow(t, h.startFrom("198.51.100.64", q))
	if grew := local.Used() - used; grew > 2<<10 {
		t.Fatalf("a flow of an application with a 5 KiB document takes %d bytes", grew)
	}
	raw, _ := h.env.Server.Eph.Get(context.Background(), nsFlow, id)
	if strings.Contains(string(raw), "padding") || strings.Contains(string(raw), "u003c") {
		t.Fatalf("the flow keeps the document as it was written: %.300s", raw)
	}
	// the same document, shared for a minute: an address's sign-ins to it stop at its budget all the same
	started := 1
	for range 2 * metadataPerIPMin {
		if rec := h.startFrom("198.51.100.64", q); rec.Code == http.StatusFound {
			started++
		}
	}
	if started != metadataPerIPMin {
		t.Fatalf("%d sign-ins to an application not stored started from one address in a minute, want %d", started, metadataPerIPMin)
	}
	if hits.Load() != 1 {
		t.Fatalf("%d reads of the document", hits.Load())
	}
	startedFlow(t, h.startFrom("198.51.100.65", q)) // another address has its own, and the shared copy
}
