package config

import (
	"slices"
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

// A setting only one command reads is offered there alone.
func TestCommandOnlyFlags(t *testing.T) {
	fs := Flags(Default())
	has := func(flags []cli.Flag, name string) bool {
		return slices.ContainsFunc(flags, func(f cli.Flag) bool { s, ok := f.(*cli.StringFlag); return ok && s.Name == name })
	}
	if has(fs.Server, "bootstrap-admin") || !has(fs.For("bootstrap"), "bootstrap-admin") || !has(fs.For("bootstrap"), "listen") {
		t.Fatal("bootstrap-admin placement")
	}
}
