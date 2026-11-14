package login_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/ephemeral"
	"github.com/paularlott/quisora/internal/metrics"
	"github.com/paularlott/quisora/internal/model"
)

// heldKB sets what one requester may have the server hold, and lifts the per-address request limit, so that what
// stops a flood in these tests is what it holds, not how fast it comes.
func heldKB(kb int) func(*config.Config) {
	return func(c *config.Config) { c.Limits.HeldKB, c.Limits.LoginPerIPMin = kb, 0 }
}

func localEph(t *testing.T, e *env) *ephemeral.Local {
	t.Helper()
	local, ok := e.Server.Eph.(*ephemeral.Local)
	if !ok {
		t.Fatalf("the test server's ephemeral store is %T", e.Server.Eph)
	}
	return local
}

// Starting a sign-in at a provider keeps its state for ten minutes, and anyone can: an address holds at most
// limits.held_kb of them (429 past it, counted), each costs what it carries and not six times that, and one that
// comes back from the provider gives its bytes back.
func TestProviderSignInStateHeldPerAddress(t *testing.T) {
	u := newUpEnv(t, heldKB(64))
	p := u.oidcProvider(t, nil)
	local := localEph(t, u.env)
	next := u.at("/x?" + strings.Repeat("&", 1900)) // a path this organization's sign-in may end at
	start := "/o/acme/login/provider/" + p.ID + "?next=" + url.QueryEscape(next)
	b := u.browser(t)
	used, refused := local.Used(), metrics.EphemeralRefused.Value("held_bytes")
	res, _ := b.get(start)
	if res.StatusCode != http.StatusFound || !strings.Contains(res.Header.Get("Location"), "state=") {
		t.Fatalf("start: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if one := local.Used() - used; one > 3<<10 {
		t.Fatalf("the state of a sign-in with a 2 KB path to return to takes %d bytes", one)
	}
	first, _ := url.Parse(res.Header.Get("Location"))
	started := 1
	for range 60 {
		if res, _ = b.get(start); res.StatusCode != http.StatusFound {
			break
		}
		started++
	}
	if res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Retry-After") == "" {
		t.Fatalf("after %d sign-ins begun from one address: %d", started, res.StatusCode)
	}
	if grew := local.Used() - used; grew > 64<<10 {
		t.Fatalf("one address holds %d bytes of provider sign-ins, past its 64 KiB", grew)
	}
	if got := metrics.EphemeralRefused.Value("held_bytes") - refused; got != 1 {
		t.Fatalf("%d refusals counted, want 1", got)
	}
	// the provider sends the first one back (declined): its state is taken, and its bytes given back
	if res, _ = b.get("/login/callback/" + p.ID + "?error=access_denied&state=" + url.QueryEscape(first.Query().Get("state"))); res.StatusCode != http.StatusFound {
		t.Fatalf("callback: %d", res.StatusCode)
	}
	if res, _ = b.get(start); res.StatusCode != http.StatusFound {
		t.Fatalf("after one came back: %d", res.StatusCode)
	}
}

// A passkey sign-in challenge is anyone's to ask for, and carries the path the sign-in is to end at: an address
// holds at most limits.held_kb of them.
func TestPasskeyChallengesHeldPerAddress(t *testing.T) {
	e := newEnv(t, heldKB(64))
	local := localEph(t, e)
	b := e.browser(t)
	next := "/o/primary/x?" + strings.Repeat("&", 1900)
	used := local.Used()
	res, out := b.post("/o/primary/api-internal/login/passkey/begin", map[string]any{"next": next})
	wantStatus(t, res, out, 200)
	if one := local.Used() - used; one > 3<<10 {
		t.Fatalf("a challenge with a 2 KB path to return to takes %d bytes", one)
	}
	begun := 1
	for range 60 {
		if res, out = b.post("/o/primary/api-internal/login/passkey/begin", map[string]any{"next": next}); res.StatusCode != 200 {
			break
		}
		begun++
	}
	wantStatus(t, res, out, 429)
	if res.Header.Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
	if grew := local.Used() - used; grew > 64<<10 {
		t.Fatalf("one address holds %d bytes of passkey challenges (%d of them), past its 64 KiB", grew, begun)
	}
}

// The ticket of a sign-in's second step is kept for the address the first factor came from: whoever holds an
// account's password cannot have more than limits.held_kb of them kept.
func TestSignInTicketsHeldPerAddress(t *testing.T) {
	e := newEnv(t, heldKB(64))
	e.giveTOTP(t, e.member(t))
	local := localEph(t, e)
	b := e.browser(t)
	next := "/o/primary/x?" + strings.Repeat("&", 1900) // the ticket carries the path the sign-in is to end at
	used := local.Used()
	var res *http.Response
	var out map[string]any
	made := 0
	for range 60 {
		res, out = b.post("/o/primary/api-internal/login/password", map[string]any{"email": "member@example.com",
			"password": userPassword, "next": next})
		if res.StatusCode != 200 {
			break
		}
		made++
	}
	wantStatus(t, res, out, 429)
	if made < 5 || local.Used()-used > 64<<10 {
		t.Fatalf("%d tickets made, holding %d bytes, within 64 KiB", made, local.Used()-used)
	}
}

// What a signed-in account has kept is charged to the account: connecting a provider over and over holds at most
// limits.held_kb of sign-in states.
func TestProviderConnectStateHeldPerUser(t *testing.T) {
	u := newUpEnv(t, heldKB(64))
	p := u.oidcProvider(t, nil)
	b := u.signedIn(t, u.user(t, u.org, "pat", model.RoleUser))
	b.markReauth()
	var res *http.Response
	var out map[string]any
	begun := 0
	for range 300 {
		if res, out = b.post("/api-internal/account/providers/"+p.ID+"/connect", nil); res.StatusCode != 200 {
			break
		}
		begun++
	}
	wantStatus(t, res, out, 429)
	if begun < 20 || begun > 150 {
		t.Fatalf("%d connections begun within 64 KiB", begun)
	}
	// another account is not held back
	b2 := u.signedIn(t, u.user(t, u.org, "kim", model.RoleUser))
	b2.markReauth()
	res, out = b2.post("/api-internal/account/providers/"+p.ID+"/connect", nil)
	wantStatus(t, res, out, 200)
}

// The spray limit does not lapse when sign-in state fills the node: the record that an organization is under spray
// has room of its own, so a spray that starts on a full node is recorded, and limits addresses as on any other.
func TestSprayRecordedOnFullNode(t *testing.T) {
	e := newEnv(t, sprayConfig(5))
	org := e.org(t, "acme", nil)
	e.user(t, org, "pat", model.RoleUser)
	localEph(t, e).Budget = 1 // nothing more fits among the sign-in state
	for i := range 6 {
		b := e.browser(t)
		b.fromAddress("192.0.2.1")
		res, out := b.login("acme", fmt.Sprintf("nobody%d", i), "x")
		wantStatus(t, res, out, 401)
	}
	if _, err := e.Server.Eph.Get(context.Background(), ephemeral.GuardPrefix+"spray", org.ID); err != nil {
		t.Fatalf("the spray was not recorded on a full node: %v", err)
	}
	checked := 0
	for i := range 30 {
		b := e.browser(t)
		b.fromAddress(fmt.Sprintf("203.0.113.%d", i+1))
		if res, _ := b.login("acme", "pat", fmt.Sprintf("guess-%d", i)); res.StatusCode == http.StatusUnauthorized {
			checked++
		}
	}
	if checked != 10 {
		t.Fatalf("30 addresses had %d guesses at one account checked under a spray on a full node, want 10", checked)
	}
}
