package config

import (
	"testing"

	"github.com/paularlott/cli"
)

func TestSettingValueAndConfigFile(t *testing.T) {
	c := Default()
	c.Cluster.Peers = []string{"a:1", "b:2"}
	got := map[string]string{}
	for _, s := range Settings(c) {
		got[s.Path] = s.Value()
	}
	if got["cluster.peers"] != "a:1,b:2" || got["server.listen"] != ":8443" || got["storage.badgerdb.sync_writes"] != "true" ||
		got["tokens.access_ttl"] != "600" {
		t.Fatalf("values: %q", got)
	}
	src, flag := NewConfigFile(c)
	if src == nil || flag == nil || c.ConfigFile != src {
		t.Fatal("NewConfigFile did not record the source")
	}
}

// Every setting has a unique flag and environment variable, help text, and a config path.
func TestSettingsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range Settings(Default()) {
		if seen[s.Flag] {
			t.Errorf("duplicate flag %s", s.Flag)
		}
		seen[s.Flag] = true
		if s.Usage == "" || s.Path == "" || s.Env == "" {
			t.Errorf("%s: missing usage, path or env", s.Flag)
		}
	}
	if len(seen) < 50 {
		t.Errorf("only %d settings found", len(seen))
	}
}

// A command offers the flags of the settings it reads; the others it binds hidden (read from the config file and the
// environment), and the log level and format are global.
func TestCommandFlags(t *testing.T) {
	fs := Flags(Default())
	shown := func(flags []cli.Flag, name string) (found, visible bool) {
		for _, f := range flags {
			if s, ok := f.(*cli.StringFlag); ok && s.Name == name {
				return true, !s.Hidden
			}
		}
		return false, false
	}
	for _, c := range []struct {
		cmd, flag      string
		found, visible bool
	}{
		{"bootstrap", "bootstrap-admin", true, true}, {"serve", "bootstrap-admin", true, false},
		{"serve", "site-name", true, true}, {"backup", "site-name", true, false}, {"backup", "master-key", true, true},
		{"healthcheck", "listen", true, true}, {"healthcheck", "master-key", true, false},
		{"serve", "log-level", false, false}, {"backup", "log-level", false, false},
	} {
		if found, visible := shown(fs.For(c.cmd), c.flag); found != c.found || visible != c.visible {
			t.Errorf("%s --%s: bound %v, offered %v", c.cmd, c.flag, found, visible)
		}
	}
	if found, _ := shown(fs.Global, "log-level"); !found {
		t.Error("log-level is not global")
	}
}
