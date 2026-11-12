package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	logpkg "github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/app"
	"github.com/paularlott/quisora/internal/config"
)

// A reload (SIGHUP) applies the limits and server.deny_networks of the edited config file to the running node: the
// next request is denied or limited by them, and nothing counted so far is reset. The limits that size the node at
// start-up are reported as needing a restart and keep their value. A file that does not parse, or names a bad
// network or limit, fails the reload and leaves everything as it was.
func TestReloadLimitsAndDenyNetworks(t *testing.T) {
	e := newEnv(t, "")
	base, err := os.ReadFile(e.conf)
	if err != nil {
		t.Fatal(err)
	}
	// write sets server.deny_networks to deny (a TOML array, "" for none) and appends the limits table limits.
	write := func(deny, limits string) {
		t.Helper()
		if deny != "" {
			deny = "deny_networks = " + deny + "\n"
		}
		body := strings.Replace(string(base), "[server]\n", "[server]\n"+deny, 1) + limits
		if err := os.WriteFile(e.conf, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("", "[limits]\nlogin_per_ip_min = 100\n")
	cfg := config.Default()
	c := parsed(t, cfg, "--config", e.conf, "serve")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := prepare(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	a, err := app.Start(ctx, cfg, logpkg.NewNullLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	reload := reloader(c, a, logpkg.NewNullLogger())
	h := a.Server.Handler()
	denied := func(ip string) bool {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = ip + ":1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code == http.StatusForbidden
	}
	count := func() int64 { // a sign-in counter of the kind the limits are checked against
		n, err := a.Eph.Incr(ctx, "test", "login|x|203.0.113.7", 1, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if denied("203.0.113.7") || a.Cfg.LiveLimits().LoginPerIPMin != 100 || count() != 1 {
		t.Fatal("start-up")
	}

	write(`["203.0.113.0/24"]`, "[limits]\nlogin_per_ip_min = 5\nmax_in_flight = 64\nephemeral_mb = 2048\n")
	r := reload(ctx, true, 0)
	if r.Error != "" {
		t.Fatalf("reload: %+v", r)
	}
	l := a.Cfg.LiveLimits()
	if !denied("203.0.113.7") || denied("198.51.100.1") || l.LoginPerIPMin != 5 || l.MaxInFlight != 64 ||
		l.EphemeralMB != 1024 || count() != 2 {
		t.Fatalf("after the reload: %+v %v", l, a.Server.DenyNetworks())
	}
	for _, want := range []string{"limits.login_per_ip_min 100 to 5", "limits.max_in_flight 4096 to 64",
		"limits.ephemeral_mb changed: applies after a restart", "server.deny_networks [203.0.113.0/24]"} {
		if !slices.Contains(r.Changes, want) {
			t.Errorf("changes %q lack %q", r.Changes, want)
		}
	}

	for name, bad := range map[string][3]string{ // deny_networks, the limits table, the error's start
		"syntax":  {`["198.51.100.0/24"`, "", "configuration: "},
		"network": {`["not-an-address"]`, "", "server.deny_networks: "},
		"every":   {`["0.0.0.0/0"]`, "", "server.deny_networks: "},
		"limit":   {`["198.51.100.0/24"]`, "[limits]\nmax_in_flight = 0\n", "limits: limits.max_in_flight"},
	} {
		write(bad[0], bad[1])
		if r := reload(ctx, true, 0); !strings.HasPrefix(r.Error, bad[2]) || len(r.Changes) != 0 {
			t.Errorf("%s: reload of a bad file: %+v", name, r)
		}
		l := a.Cfg.LiveLimits()
		if !denied("203.0.113.7") || denied("198.51.100.1") || l.LoginPerIPMin != 5 || l.MaxInFlight != 64 {
			t.Errorf("%s: a bad file changed the node: %+v %v", name, l, a.Server.DenyNetworks())
		}
	}
	if !slices.Equal(a.Server.DenyNetworks(), []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}) {
		t.Fatalf("deny list: %v", a.Server.DenyNetworks())
	}

	write("", "") // back to the defaults: the list emptied
	if r := reload(ctx, true, 0); r.Error != "" || !slices.Contains(r.Changes, "server.deny_networks []") {
		t.Fatalf("reload to defaults: %+v", r)
	}
	if denied("203.0.113.7") || a.Cfg.LiveLimits().LoginPerIPMin != 300 || count() != 3 {
		t.Fatalf("after the reload to defaults: %+v", a.Cfg.LiveLimits())
	}
}
