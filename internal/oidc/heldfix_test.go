package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/service"
)

// hookEph runs hook once, just before the entry ns/id is written back (set, or replaced where it is): the moment
// between a request's read of an entry and its save, in which another request ends the entry.
type hookEph struct {
	ephemeral.Store
	ns, id string
	hook   func()
}

func (e *hookEph) run(ns, id string) {
	if ns == e.ns && id == e.id && e.hook != nil {
		h := e.hook
		e.hook = nil
		h()
	}
}

func (e *hookEph) Set(ctx context.Context, ns, id string, v []byte, ttl time.Duration) error {
	e.run(ns, id)
	return e.Store.Set(ctx, ns, id, v, ttl)
}

func (e *hookEph) Replace(ctx context.Context, ns, id string, v []byte) error {
	e.run(ns, id)
	return e.Store.(interface {
		Replace(context.Context, string, string, []byte) error
	}).Replace(ctx, ns, id, v)
}

// heldWindow is the window of the held budgets now: a test that compares counts taken at two moments skips itself
// when the window turned between them (once in twenty minutes), since the counts are then of different windows.
func heldWindow() int64 { return time.Now().UnixNano() / int64(ephemeral.HeldWindow) }

// A flow that was cancelled while another request of its browser was between reading it and saving it is not made
// again by the save. It came back with the stamps of the slot and the bytes its cancel had given back, and each
// later cancel gave them back again, off the count of the address's other flows: one flow, revived up to six times,
// let its address hold flows past limits.flows_per_ip and limits.held_kb, and a cancelled sign-in went on.
func TestFlowEndedIsNotSavedAgain(t *testing.T) {
	h := setup(t, func(c *config.Config) { c.Limits.FlowsPerIP, c.Limits.HeldKB = 4, 64 })
	cl, _ := h.newClient(nil)
	_, ch := pkce()
	const ip = "198.51.100.70"
	q := authzQuery(cl, ch, url.Values{"state": {strings.Repeat("s", 2000)}, "nonce": {strings.Repeat("n", 1000)}})
	ctx := context.Background()
	orig := h.env.Server.Eph
	holding := func() (bytes, slots int64) {
		bytes, _ = ephemeral.Holding(ctx, orig, ephemeral.HeldNS, "ip|"+ip, ephemeral.HeldWindow)
		slots, _ = ephemeral.Holding(ctx, orig, nsHeld, ip, flowTTL)
		return bytes, slots
	}
	window := heldWindow()
	var ids []string
	var cks []*http.Cookie
	for range 4 {
		id, ck := startedFlow(t, h.startFrom(ip, q))
		ids, cks = append(ids, id), append(cks, ck)
	}
	if rec := h.startFrom(ip, q); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a fifth flow within a limit of four: %d", rec.Code)
	}
	b0, s0 := holding()
	he := &hookEph{Store: orig, ns: nsFlow, id: ids[0]}
	h.env.Server.Eph = he
	t.Cleanup(func() { h.env.Server.Eph = orig })
	cancel := func() {
		req := httptest.NewRequest(http.MethodGet, h.orgBase+"/oauth/authorize/cancel?flow="+url.QueryEscape(ids[0]), nil)
		h.serveFrom(ip, req, cks[0])
	}
	for round := range 4 {
		he.hook = cancel // the cancel lands between the resume's read of the flow and its save
		req := httptest.NewRequest(http.MethodGet, h.orgBase+"/oauth/authorize/resume?flow="+url.QueryEscape(ids[0]), nil)
		rec := h.serveFrom(ip, req, cks[0])
		if round == 0 && rec.Code != http.StatusBadRequest {
			t.Fatalf("a resume whose flow was cancelled under it: %d %s (want the page for an expired request)", rec.Code, rec.Header().Get("Location"))
		}
		if _, err := orig.Get(ctx, nsFlow, ids[0]); !errors.Is(err, ephemeral.ErrNotFound) {
			t.Fatalf("round %d: the cancelled flow is there again: %v", round, err)
		}
	}
	if heldWindow() != window {
		t.Skip("the held window turned during the test")
	}
	b1, s1 := holding()
	if s1 != s0-1 || b1 >= b0 || b1 < b0*5/8 {
		t.Fatalf("one of four flows ended: %d slots and %d bytes counted, from %d and %d", s1, b1, s0, b0)
	}
	live := 0
	for _, id := range ids {
		if _, err := orig.Get(ctx, nsFlow, id); err == nil {
			live++
		}
	}
	extra := 0
	for range 20 {
		if rec := h.startFrom(ip, q); rec.Code != http.StatusFound {
			break
		}
		extra++
	}
	if live != 3 || extra != 1 {
		t.Fatalf("the address holds %d flows and started %d more, within a limit of four", live, extra)
	}
}

// The same with nothing arranged: a flow's cancel and resume sent together, over and over. No flow's charge is given
// back more than once, whichever order they land in.
func TestFlowCancelAndResumeTogetherRefundOnce(t *testing.T) {
	h := setup(t, func(c *config.Config) { c.Limits.FlowsPerIP, c.Limits.HeldKB = 0, 2048 })
	cl, _ := h.newClient(nil)
	_, ch := pkce()
	const ip = "198.51.100.71"
	q := authzQuery(cl, ch, url.Values{"state": {strings.Repeat("s", 2000)}, "nonce": {strings.Repeat("n", 1000)}})
	ctx := context.Background()
	st := h.env.Server.Eph
	window := heldWindow()
	for range 3 { // flows kept to the end: their charge is what a second refund would eat
		startedFlow(t, h.startFrom(ip, q))
	}
	base, _ := ephemeral.Holding(ctx, st, ephemeral.HeldNS, "ip|"+ip, ephemeral.HeldWindow)
	do := func(what, id string, ck *http.Cookie) {
		req := httptest.NewRequest(http.MethodGet, h.orgBase+"/oauth/authorize/"+what+"?flow="+url.QueryEscape(id), nil)
		h.serveFrom(ip, req, ck)
	}
	twice := 0
	for range 60 {
		id, ck := startedFlow(t, h.startFrom(ip, q))
		var wg sync.WaitGroup
		for range 4 {
			wg.Add(2)
			go func() { defer wg.Done(); do("resume", id, ck) }()
			go func() { defer wg.Done(); do("cancel", id, ck) }()
		}
		wg.Wait()
		for range 3 { // end whatever is left of it
			do("cancel", id, ck)
		}
		if _, err := st.Get(ctx, nsFlow, id); !errors.Is(err, ephemeral.ErrNotFound) {
			t.Fatalf("a flow cancelled eleven times is still there: %v", err)
		}
		if now, _ := ephemeral.Holding(ctx, st, ephemeral.HeldNS, "ip|"+ip, ephemeral.HeldWindow); now < base {
			twice++
			base = now
		}
	}
	if heldWindow() != window {
		t.Skip("the held window turned during the test")
	}
	if twice > 0 {
		t.Fatalf("a flow's charge was given back more than once in %d of 60 races of its cancel and resume", twice)
	}
}

// A decision on the consent screen is not recorded on a flow that was cancelled while it was being made: the flow is
// not made again by saving the decision, and the page is told the request has expired.
func TestConsentOnEndedFlowIsRefused(t *testing.T) {
	h := setup(t, nil)
	cl := h.publicClient(nil)
	c, csrf := h.session(h.user)
	_, ch := pkce()
	_, id := h.consentPage(c, cl, ch, nil)
	ctx := context.Background()
	orig := h.env.Server.Eph
	window := heldWindow()
	before, _ := ephemeral.Holding(ctx, orig, ephemeral.HeldNS, "ip|127.0.0.1", ephemeral.HeldWindow)
	if before == 0 {
		t.Fatal("the flow is not charged to 127.0.0.1")
	}
	he := &hookEph{Store: orig, ns: nsFlow, id: id}
	he.hook = func() { body(h.get(c, h.orgBase+"/oauth/authorize/cancel?flow="+url.QueryEscape(id))) }
	h.env.Server.Eph = he
	t.Cleanup(func() { h.env.Server.Eph = orig })
	if st, _ := h.decideConsent(c, csrf, id, true); st != http.StatusNotFound {
		t.Fatalf("a decision on a flow cancelled under it: %d, want 404", st)
	}
	if _, err := orig.Get(ctx, nsFlow, id); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("the cancelled flow is there again, with its decision: %v", err)
	}
	if heldWindow() != window {
		t.Skip("the held window turned during the test")
	}
	if after, _ := ephemeral.Holding(ctx, orig, ephemeral.HeldNS, "ip|127.0.0.1", ephemeral.HeldWindow); after != 0 {
		t.Fatalf("the address is still charged %d bytes for a flow that ended", after)
	}
	if ev := h.auditEvents("oauth.consent"); len(ev) != 0 {
		t.Fatalf("a decision on a flow that had ended was recorded: %+v", ev[0].Detail)
	}
}

// A code's charge to its user is given back when the code is redeemed: an account that signs in to applications
// again and again, redeeming each code, is not refused for the codes it no longer holds.
func TestCodeChargeGivenBackWhenRedeemed(t *testing.T) {
	h := setup(t, func(c *config.Config) { c.Limits.HeldKB = 64 })
	redirect := "https://rp.example/cb/" + strings.Repeat("p", 900)
	cl, secret := h.newClient(func(in *service.ClientInput) { in.RedirectURIs = &[]string{redirect} })
	c, _ := h.session(h.user)
	v, ch := pkce()
	q := authzQuery(cl, ch, url.Values{"nonce": {strings.Repeat("n", 1000)}}) // the code carries the nonce
	for i := range 36 {                                                       // 36 codes of 2.5 KB are more than 64 KiB
		resp := h.get(c, h.orgBase+"/oauth/authorize?"+q.Encode())
		body(resp)
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("code %d, each one before it redeemed: %d", i+1, resp.StatusCode)
		}
		code := loc(t, resp).Query().Get("code")
		if r := h.exchangeCode(cl, secret, code, v); r.status != 200 {
			t.Fatalf("redeeming code %d: %d %v", i+1, r.status, r.m)
		}
	}
}

// What one user's redeemed codes keep among the guard records (the records of their use, which replay detection
// rests on) is bounded far below the user's budget for the rest: past it a code is not redeemed (429), so that a
// few dozen accounts redeeming codes as fast as they can do not fill the room every tenant's redemptions need.
func TestGuardRecordsBoundedPerUser(t *testing.T) {
	h := setup(t, func(c *config.Config) { c.Limits.HeldKB = 512 })
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	local := h.localEph()
	guarded := local.Guarded()
	limit := ephemeral.GuardLimit(512 << 10)
	redeemed := 0
	var r tokResp
	var code string
	for range 100 {
		code = h.getCode(c, cl, ch, nil)
		if r = h.exchangeCode(cl, secret, code, v); r.status != 200 {
			break
		}
		redeemed++
	}
	if r.status != http.StatusTooManyRequests || r.str("error") != "temporarily_unavailable" || r.hdr.Get("Retry-After") == "" {
		t.Fatalf("after %d codes redeemed for one user: %d %v", redeemed, r.status, r.m)
	}
	if redeemed < 20 || redeemed > 60 {
		t.Fatalf("%d codes redeemed within a guard budget of %d bytes", redeemed, limit)
	}
	if grew := local.Guarded() - guarded; grew > limit {
		t.Fatalf("one user's codes keep %d bytes of guard records, past its %d", grew, limit)
	}
	// the code that was not redeemed is still there, and nothing was recorded for it
	if _, err := h.env.Server.Eph.Get(context.Background(), nsCode, code); err != nil {
		t.Fatalf("the code that was refused: %v", err)
	}
	if _, err := h.env.Server.Eph.Get(context.Background(), nsReplayed, replayKey(cl, code)); !errors.Is(err, ephemeral.ErrNotFound) {
		t.Fatalf("a mark was kept for a redemption that was refused: %v", err)
	}
	// another user's codes are redeemed
	other := h.sshUser("guardother", model.RoleUser)
	oc, _ := h.session(other)
	if r := h.exchangeCode(cl, secret, h.getCode(oc, cl, ch, nil), v); r.status != 200 {
		t.Fatalf("another user's code: %d %v", r.status, r.m)
	}
}

// A code put back after a redemption that failed on our side lasts until the moment it was to expire at, not for
// another whole lifetime; and the retry does not erase the mark of a replay made while the code was away: it ends
// as a replayed code's redemption does.
func TestCodePutBackKeepsItsExpiryAndReplayMark(t *testing.T) {
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	v, ch := pkce()
	code := h.getCode(c, cl, ch, nil)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cl.RedirectURIs[0]},
		"code_verifier": {v}}
	ctx := context.Background()
	orig := h.env.Server.Eph
	var ttl time.Duration
	var sets int
	h.env.Server.Eph = setEph{Store: &hookEph{Store: orig, ns: nsCode, id: code, hook: func() {
		// a second presentation, made while the first has the code: it leaves its mark over the redemption's
		_ = orig.Set(ctx, nsReplayed, replayKey(cl, code), markReplayed, usedTTL)
	}}, ns: nsCode, ttl: &ttl, sets: &sets}
	t.Cleanup(func() { h.env.Server.Eph = orig })
	users := h.env.Svc.Users.S
	h.env.Svc.Users.S = failReads(users, model.KindUser)
	h.p.users.Clear()
	time.Sleep(20 * time.Millisecond)
	if r := h.token(form, cl, secret); r.status != 503 {
		t.Fatalf("with the user unreadable: %d %v", r.status, r.m)
	}
	if sets != 1 || ttl <= 0 || ttl >= h.env.Cfg.Tokens.Code() {
		t.Fatalf("the code was put back %d times, for %s: want once, for what was left of its %s", sets, ttl, h.env.Cfg.Tokens.Code())
	}
	h.env.Svc.Users.S = users
	h.p.users.Clear()
	if r := h.token(form, cl, secret); r.status != 400 || r.str("error") != "invalid_grant" {
		t.Fatalf("the retry of a code that was replayed meanwhile: %d %v", r.status, r.m)
	}
	if m, err := orig.Get(ctx, nsReplayed, replayKey(cl, code)); err != nil || string(m) != string(markReplayed) {
		t.Fatalf("the replay's mark after the retry: %v %v", m, err)
	}
}

// The records of a code's use are kept where the code is: their key begins with the code's owner, so with gossip
// they are routed to the node that issued the code, not by hash among the nodes that serve. Routed by hash, a node
// starting or stopping while a code was redeemed moved them, and the redemption, finding no mark where it had just
// left one, took that for a replay and ended its own grant.
func TestReplayRecordsAreKeptWithTheirCode(t *testing.T) {
	cl := &model.Client{Meta: model.Meta{ID: model.NewID()}}
	code := "n7c2k4q1." + strings.Repeat("r", 32)
	if got := ephemeral.Owner(replayKey(cl, code)); got != ephemeral.Owner(code) {
		t.Fatalf("the records of a code owned by %q are routed as owned by %q", ephemeral.Owner(code), got)
	}
	other := &model.Client{Meta: model.Meta{ID: model.NewID()}}
	if replayKey(cl, code) == replayKey(other, code) {
		t.Fatal("two clients' records of one code share a key")
	}
}

// A device sign-in's charge to the address that started it is given back when the sign-in ends: its tokens
// collected, or its refusal. Devices signing in one after another from an address are bounded by how many wait at
// once, not by how many there were in twenty minutes.
func TestDeviceChargeGivenBackWhenCollected(t *testing.T) {
	h := setup(t, func(c *config.Config) { c.Limits.HeldKB = 64 })
	dev := h.deviceClient(func(in *service.ClientInput) { in.DevicePrivileged = ptr(true) })
	b, csrf := h.adminBrowser()
	ctx := context.Background()
	st := h.env.Server.Eph
	holding := func() (bytes, guard int64) {
		bytes, _ = ephemeral.Holding(ctx, st, ephemeral.HeldNS, "ip|127.0.0.1", ephemeral.HeldWindow)
		guard, _ = ephemeral.Holding(ctx, st, ephemeral.HeldNS, "guard|ip|127.0.0.1", ephemeral.HeldWindow)
		return bytes, guard
	}
	window := heldWindow()
	for _, approve := range []bool{true, false} {
		dc, uc := h.startDevice(dev, "openid")
		waiting, polls := holding()
		if waiting == 0 {
			t.Fatal("a device sign-in waiting is not charged to its address")
		}
		if status, pg := h.consentDevice(b, csrf, uc, approve); status != 200 {
			t.Fatalf("deciding (approve %v): %d %s", approve, status, pg)
		}
		r := h.pollDevice(dev, dc)
		if approve && r.status != 200 || !approve && r.str("error") != "access_denied" {
			t.Fatalf("the poll after the decision (approve %v): %d %v", approve, r.status, r.m)
		}
		if heldWindow() != window {
			t.Skip("the held window turned during the test")
		}
		if n, g := holding(); n != 0 || g != 0 {
			t.Fatalf("after the sign-in ended (approve %v) its address is still charged %d bytes and %d of guard records", approve, n, g)
		}
		if polls == 0 { // the record of its polls is charged apart, against the address's share of guard records
			t.Fatal("a device sign-in waiting has no guard record charged to its address")
		}
	}
}

// A sign-out waiting for its confirmation is charged to its user, like everything else kept for a signed-in
// account; asking again replaces the session's request and its charge, and confirming gives it back.
func TestLogoutRequestChargedToItsUser(t *testing.T) {
	h := setup(t, nil)
	cl, _ := h.newClient(func(in *service.ClientInput) { in.PostLogoutURIs = &[]string{"https://rp.example/bye"} })
	c, csrf := h.session(h.user)
	ctx := context.Background()
	holding := func() int64 {
		n, _ := ephemeral.Holding(ctx, h.env.Server.Eph, ephemeral.HeldNS, "user|"+h.user.ID, ephemeral.HeldWindow)
		return n
	}
	window := heldWindow()
	q := url.Values{"client_id": {cl.ID}, "post_logout_redirect_uri": {"https://rp.example/bye"}, "state": {strings.Repeat("s", 2000)}}
	page := body(h.get(c, h.orgBase+"/oauth/logout?"+q.Encode()))
	first := holding()
	if first < 2000 {
		t.Fatalf("a sign-out request with a state of 2 KB is charged %d bytes to its user", first)
	}
	for range 30 {
		page = body(h.get(c, h.orgBase+"/oauth/logout?"+q.Encode()))
	}
	if heldWindow() != window {
		t.Skip("the held window turned during the test")
	}
	if n := holding(); n != first {
		t.Fatalf("30 more requests of one session: %d bytes charged, want the one request's %d", n, first)
	}
	r := h.confirmLogout(c, url.Values{"id": {regexpValue(page, "id")}, "csrf": {csrf}}.Encode())
	if r.StatusCode != http.StatusSeeOther {
		t.Fatalf("confirming: %d", r.StatusCode)
	}
	if n := holding(); n != 0 {
		t.Fatalf("a confirmed sign-out is still charged %d bytes", n)
	}
}

// The flows an IPv6 network holds are bounded as its bytes are: a /48 sixteen times limits.flows_per_ip, a /32
// sixty-four times, so that one allocation's /64s do not each bring their own.
func TestFlowSlotsBoundedForTheWiderNetwork(t *testing.T) {
	h := setup(t, func(c *config.Config) { c.Limits.FlowsPerIP = 2 })
	cl, _ := h.newClient(nil)
	_, ch := pkce()
	q := authzQuery(cl, ch, nil)
	start := func(format string, a ...any) int { return h.startFrom(fmt.Sprintf(format, a...), q).Code }
	for site := range 4 { // four /48s of one /32, each to its sixteen times two
		for subnet := range 16 {
			for i := range 2 {
				if code := start("2001:db8:%x:%x::%x", site, subnet, i+1); code != http.StatusFound {
					t.Fatalf("flow %d of /64 %d of /48 %d: %d", i+1, subnet, site, code)
				}
			}
		}
		if code := start("2001:db8:%x:ffff::1", site); code != http.StatusTooManyRequests {
			t.Fatalf("a 33rd flow from /48 %d, from a /64 of its own: %d", site, code)
		}
	}
	if code := start("2001:db8:aaaa:1::1"); code != http.StatusTooManyRequests {
		t.Fatalf("a 129th flow from the /32, from a /48 of its own: %d", code)
	}
	if code := start("2001:db9::1"); code != http.StatusFound {
		t.Fatalf("another /32: %d", code)
	}
	if code := start("198.51.100.72"); code != http.StatusFound {
		t.Fatalf("an IPv4 address: %d", code)
	}
}
