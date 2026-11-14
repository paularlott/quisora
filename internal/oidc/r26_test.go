package oidc

import (
	"context"
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
	"github.com/paularlott/quisora/internal/store"
	"github.com/paularlott/quisora/internal/web"
)

// contendedEph is a store whose counters of namespace ns are too contended to update (or past the counters' cap):
// Incr reports Contended, as the store does.
type contendedEph struct {
	ephemeral.Store
	ns string
}

func (e contendedEph) Incr(ctx context.Context, ns, key string, delta int64, window time.Duration) (int64, error) {
	if ns == e.ns {
		return ephemeral.Contended, nil
	}
	return e.Store.Incr(ctx, ns, key, delta, window)
}

// A held budget whose counter could not be updated says nothing of what the address holds: the sign-in is answered
// 503 with a short Retry-After (the server cannot count it now), not 429 "you hold too much from your network", and
// it is not counted as held_bytes (nor flows_per_ip), which would blame the client and hide the cause.
func TestHeldContendedIs503(t *testing.T) {
	h := setup(t, func(c *config.Config) { c.Limits.FlowsPerIP, c.Limits.HeldKB = 4, 64 })
	cl, _ := h.newClient(nil)
	_, ch := pkce()
	orig := h.env.Server.Eph
	t.Cleanup(func() { h.env.Server.Eph = orig })
	for _, ns := range []string{ephemeral.HeldNS, nsHeld} { // the bytes' budget, then the flows' slots
		h.env.Server.Eph = contendedEph{Store: orig, ns: ns}
		held, flows := metrics.EphemeralRefused.Value("held_bytes"), metrics.EphemeralRefused.Value("flows_per_ip")
		rec := h.startFrom("198.51.100.81", authzQuery(cl, ch, nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: a charge whose counter is contended: %d, want 503", ns, rec.Code)
		}
		if ra, _ := strconv.Atoi(rec.Header().Get("Retry-After")); ra < 1 || ra > 10 {
			t.Fatalf("%s: Retry-After %q, want a short one", ns, rec.Header().Get("Retry-After"))
		}
		if metrics.EphemeralRefused.Value("held_bytes") != held || metrics.EphemeralRefused.Value("flows_per_ip") != flows {
			t.Fatalf("%s: a contended counter was counted as the address holding too much", ns)
		}
	}
}

// A sign-in refused for what its address holds is told to come back when the window that refused it ends, which is
// when the address may hold more again: not a constant minute, after which a compliant client is refused again for
// up to twenty minutes.
func TestHeldRetryAfterIsWhenTheWindowEnds(t *testing.T) {
	for name, limits := range map[string][2]int{"held_bytes": {1000, 64}, "flows_per_ip": {1, 1024}} {
		t.Run(name, func(t *testing.T) {
			h := setup(t, func(c *config.Config) { c.Limits.FlowsPerIP, c.Limits.HeldKB = limits[0], limits[1] })
			cl, _ := h.newClient(nil)
			_, ch := pkce()
			q := authzQuery(cl, ch, url.Values{"state": {strings.Repeat("s", 2000)}, "nonce": {strings.Repeat("n", 1000)}})
			var rec interface {
				Header() http.Header
			}
			code := 0
			for range 50 {
				r := h.startFrom("198.51.100.82", q)
				if rec, code = r, r.Code; code != http.StatusFound {
					break
				}
			}
			window := ephemeral.HeldWindow
			if name == "flows_per_ip" {
				window = flowTTL
			}
			n := time.Now().UnixNano()
			want := int((time.Duration((n/int64(window)+1)*int64(window)-n) + time.Second - 1) / time.Second)
			if code != http.StatusTooManyRequests {
				t.Fatalf("no refusal: %d", code)
			}
			got, _ := strconv.Atoi(rec.Header().Get("Retry-After"))
			if want >= 55 && want <= 65 {
				t.Skip("the window ends about a minute from now: a constant would pass")
			}
			if got < want-2 || got > want+1 {
				t.Fatalf("Retry-After %d s, want %d (the end of the window that refused)", got, want)
			}
		})
	}
}

// The pre-auth limits an address is counted by (its /64) count its IPv6 /48 as well, so one allocation's 65,536 /64s
// do not each bring a share of their own: once the /48 has made its factor of the limit, a /64 of it that has made
// nothing is refused. An IPv4 address, and another /48, are not.
func TestPerAddressLimitsCountTheNet(t *testing.T) {
	ctx := context.Background()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	pub := h.deviceClient(nil)
	const redirect = "http://127.0.0.1:44022/callback"
	srv, hits := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		id := "https://" + r.Host + r.URL.Path
		_, _ = w.Write([]byte(`{"client_id":"` + id + `","client_name":"Gen","redirect_uris":["` + redirect + `"]}`))
	})
	h.p.HTTP = srv.Client()
	_, ch := pkce()
	doc := &model.Client{Meta: model.Meta{ID: srv.URL + "/app"}, RedirectURIs: []string{redirect}}
	cases := []struct {
		name   string
		net    string // the /48 counted, and its window
		window time.Duration
		limit  int64
		send   func(ip string) *http.Response
		ok     func(res *http.Response) bool // the request was not refused for its address
	}{
		{"authorize", "authorize", time.Minute, authorizePerIPMin * web.NetBusyFactor,
			func(ip string) *http.Response {
				return h.startFrom(ip, authzQuery(pub, ch, nil)).Result()
			}, func(res *http.Response) bool { return res.StatusCode != http.StatusTooManyRequests }},
		{"device start", "device-start", time.Minute, deviceStartsPerIP * web.NetShareFactor,
			func(ip string) *http.Response {
				req := httptest.NewRequest(http.MethodPost, h.orgBase+"/oauth/device_authorization",
					strings.NewReader(url.Values{"client_id": {pub.ID}, "scope": {"openid"}}.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return h.serveFrom(ip, req).Result()
			}, func(res *http.Response) bool { return res.StatusCode == http.StatusOK }},
		{"device code", "device-code", deviceGuessWindow, deviceGuessesPerIP * web.NetShareFactor,
			func(ip string) *http.Response {
				return h.serveFrom(ip, httptest.NewRequest(http.MethodGet, h.orgBase+"/device?user_code=BCDF-GHJK", nil)).Result()
			}, func(res *http.Response) bool { return res.StatusCode != http.StatusTooManyRequests }},
		{"par", "par-ip", time.Minute, parPublicPerIPMin * web.NetShareFactor,
			func(ip string) *http.Response {
				req := httptest.NewRequest(http.MethodPost, h.orgBase+"/oauth/par",
					strings.NewReader(url.Values{"client_id": {pub.ID}}.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return h.serveFrom(ip, req).Result()
			}, func(res *http.Response) bool { return res.StatusCode != http.StatusTooManyRequests }},
		{"failures", failNet, time.Minute, failuresPerIPMax * web.NetBusyFactor,
			func(ip string) *http.Response {
				req := httptest.NewRequest(http.MethodPost, h.orgBase+"/oauth/token",
					strings.NewReader(url.Values{"client_id": {pub.ID}, "grant_type": {"refresh_token"}, "refresh_token": {"x"}}.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return h.serveFrom(ip, req).Result()
			}, func(res *http.Response) bool { return res.StatusCode != http.StatusTooManyRequests }},
		{"metadata documents", "cimd-ip", time.Minute, metadataPerIPMin * web.NetShareFactor,
			func(ip string) *http.Response {
				before := hits.Load()
				res := h.startFrom(ip, authzQuery(doc, ch, url.Values{"resource": {mcpResource}, "scope": {"openid"}})).Result()
				if hits.Load() != before || res.StatusCode == http.StatusFound {
					res.StatusCode = http.StatusFound // read for it: not refused
				}
				return res
			}, func(res *http.Response) bool { return res.StatusCode == http.StatusFound }},
	}
	for i, c := range cases {
		net := "2001:db8:" + strconv.Itoa(100+i)
		if _, err := h.p.s.Eph.Incr(ctx, nsRateOIDC, c.net+"-net|"+net+"::/48", c.limit, c.window); err != nil {
			t.Fatal(err)
		}
		if res := c.send(net + ":99::1"); c.ok(res) {
			t.Fatalf("%s: a /64 of a /48 past its share was not refused: %d", c.name, res.StatusCode)
		}
		if res := c.send("2001:db8:" + strconv.Itoa(200+i) + ":1::1"); !c.ok(res) {
			t.Fatalf("%s: another /48 was refused: %d", c.name, res.StatusCode)
		}
		if res := c.send("198.51.100." + strconv.Itoa(150+i)); !c.ok(res) {
			t.Fatalf("%s: an IPv4 address was refused: %d", c.name, res.StatusCode)
		}
	}
}

// shiftGoneMark moves every time in the note of a gone document back by d, whatever its form: as if the answers it
// records had come d earlier.
func (h *harness) shiftGoneMark(key string, d time.Duration) {
	h.t.Helper()
	ctx := context.Background()
	b, err := h.env.Server.Eph.Get(ctx, nsCIMDGone, key)
	if err != nil {
		h.t.Fatalf("no note: %v", err)
	}
	parts := strings.Split(string(b), ",")
	for i, s := range parts {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			h.t.Fatalf("note %q", b)
		}
		parts[i] = strconv.FormatInt(n-int64(d), 10)
	}
	if err := h.env.Server.Eph.Set(ctx, nsCIMDGone, key, []byte(strings.Join(parts, ",")), time.Hour); err != nil {
		h.t.Fatal(err)
	}
}

// The grace before a gone document ends its application is a run of gone answers without a break longer than the
// grace, not the time between two of them: two blips twenty minutes apart, with nothing seen in between, are not a
// document taken down, and start the grace again. Answers that keep coming within the grace of each other end it
// once the first is a grace ago.
func TestMetadataGoneGraceIsContinuity(t *testing.T) {
	ctx := context.Background()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	redirect := "http://127.0.0.1:44198/callback"
	srv, _, _ := statusDocServer(t, redirect)
	h.p.HTTP = srv.Client()
	cl, rid := h.storedDocApp(srv.URL, redirect, time.Hour)
	org := h.env.Primary.ID
	key := metadataGoneKey(org, cl.ID)
	stored := func() bool {
		_, err := h.env.Svc.Clients.Get(ctx, rid)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		return err == nil
	}
	h.p.endGoneMetadataApp(ctx, org, cl.ID, errFetchGone) // a blip
	h.shiftGoneMark(key, 20*time.Minute)                  // nothing seen for twenty minutes
	h.p.endGoneMetadataApp(ctx, org, cl.ID, errFetchGone) // another blip
	if !stored() {
		t.Fatal("two gone answers twenty minutes apart, nothing seen between, ended the application")
	}
	h.shiftGoneMark(key, 6*time.Minute)
	h.p.endGoneMetadataApp(ctx, org, cl.ID, errFetchGone) // six minutes later: gone six minutes in all
	if !stored() {
		t.Fatal("a run of gone answers shorter than the grace ended the application")
	}
	h.shiftGoneMark(key, 6*time.Minute)
	h.p.endGoneMetadataApp(ctx, org, cl.ID, errFetchGone) // six minutes later again: gone twelve minutes, no break
	if stored() {
		t.Fatal("a document gone for longer than the grace, read within the grace each time, did not end its application")
	}
}

// An application that could not be ended (the store refusing) keeps the note of its gone document: the next read
// that finds it still gone ends it, rather than starting the grace over.
func TestMetadataGoneFailedEndKeepsTheGrace(t *testing.T) {
	ctx := context.Background()
	h := setup(t, nil)
	h.mcpTenant("mcp", true)
	redirect := "http://127.0.0.1:44199/callback"
	srv, _, _ := statusDocServer(t, redirect)
	h.p.HTTP = srv.Client()
	cl, rid := h.storedDocApp(srv.URL, redirect, time.Hour)
	org := h.env.Primary.ID
	key := metadataGoneKey(org, cl.ID)
	h.p.endGoneMetadataApp(ctx, org, cl.ID, errFetchGone)
	h.shiftGoneMark(key, 6*time.Minute)
	h.p.endGoneMetadataApp(ctx, org, cl.ID, errFetchGone)
	h.shiftGoneMark(key, 6*time.Minute) // gone twelve minutes, no break: the next gone answer ends it
	good := h.env.Svc.Clients.S
	h.env.Svc.Clients.S = failDeletes(good, model.KindClient)
	h.p.endGoneMetadataApp(ctx, org, cl.ID, errFetchGone)
	h.env.Svc.Clients.S = good
	if _, err := h.env.Svc.Clients.Get(ctx, rid); err != nil {
		t.Fatalf("the application was ended by a store that refused: %v", err)
	}
	if _, err := h.env.Server.Eph.Get(ctx, nsCIMDGone, key); err != nil {
		t.Fatalf("an application that could not be ended lost the note of its gone document: %v", err)
	}
	h.p.endGoneMetadataApp(ctx, org, cl.ID, errFetchGone)
	if _, err := h.env.Svc.Clients.Get(ctx, rid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the next gone answer did not end it: %v", err)
	}
}
