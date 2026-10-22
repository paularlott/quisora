package config

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/paularlott/cli"
	cli_toml "github.com/paularlott/cli/toml"
)

// parse runs a "serve" command built from Flags with the config file path ("" for none) and args after "serve", the
// way the quisora command does, and returns the configuration it filled (not validated).
func parse(t *testing.T, path string, args ...string) (*Config, error) {
	t.Helper()
	cfg := Default()
	fs := Flags(cfg)
	ran := false
	cmd := &cli.Command{Name: "quisora", Flags: fs.Global,
		Commands: []*cli.Command{{Name: "serve", Flags: fs.Server, Run: func(context.Context, *cli.Command) error {
			ran = true
			return nil
		}}}}
	if path != "" {
		cmd.ConfigFile = cli_toml.NewConfigFile(&path, func() []string { return nil })
		cfg.ConfigFile = cmd.ConfigFile
	}
	old := os.Args
	defer func() { os.Args = old }()
	os.Args = append([]string{"quisora", "serve"}, args...)
	if err := cmd.Execute(context.Background()); err != nil {
		return nil, err
	}
	if !ran {
		t.Fatal("command did not run")
	}
	return cfg, nil
}

// Every setting can come from a flag, an QUISORA_* environment variable or the config file; a flag beats the
// environment, which beats the file, which beats the default.
func TestFlagsEnvAndConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "quisora.toml")
	if err := os.WriteFile(path, []byte(`
[server]
listen = ":1111"
public_url = "https://file.example.com"
data_dir = "/from/file"
[storage]
backend = "sqlite"
[storage.postgres]
dsn = "postgres://file"
[cluster]
peers = ["a:1", "b:2"]
[log]
level = "warn"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUISORA_PUBLIC_URL", "https://env.example.com")
	t.Setenv("QUISORA_LISTEN", ":2222")
	t.Setenv("QUISORA_SESSION_IDLE", "42")

	cfg, err := parse(t, path, "--listen", ":3333", "--badgerdb-sync-writes=false")
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct{ name, got, want string }{
		{"flag beats env and file", cfg.Server.Listen, ":3333"},
		{"env beats file", cfg.Server.PublicURL, "https://env.example.com"},
		{"file beats default", cfg.Server.DataDir, "/from/file"},
		{"nested file value", cfg.Storage.Postgres.DSN, "postgres://file"},
		{"backend from file", cfg.Storage.Backend, "sqlite"},
		{"global log level from file", cfg.Log.Level, "warn"},
		{"default kept", cfg.Tokens.SigningAlg, "ES256"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %q want %q", c.name, c.got, c.want)
		}
	}
	if cfg.Session.Idle != 42 || len(cfg.Cluster.Peers) != 2 || cfg.Storage.BadgerDB.SyncWrites {
		t.Errorf("int/slice/bool settings: idle=%d peers=%v sync=%v", cfg.Session.Idle, cfg.Cluster.Peers, cfg.Storage.BadgerDB.SyncWrites)
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

func TestListenAndTrustProxyValidation(t *testing.T) {
	for _, l := range []string{"8443", "localhost", ":99999", ""} {
		c := Default()
		c.Server.Listen = l
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "server.listen") {
			t.Errorf("listen %q: %v", l, err)
		}
	}
	c := Default()
	c.Server.Listen = "0.0.0.0:8443"
	c.Server.TrustProxy = []string{"10.0.0.0/8", "192.168.1.5", "::1", "10.0.0.300", "proxy.example"}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), `"10.0.0.300"`) || !strings.Contains(err.Error(), `"proxy.example"`) || strings.Contains(err.Error(), `"10.0.0.0/8"`) {
		t.Errorf("trust_proxy: %v", err)
	}
	if p, err := ParseProxy("2001:db8::1"); err != nil || p.Bits() != 128 {
		t.Errorf("v6 address: %v %v", p, err)
	}
}

// A value that does not parse, from the environment or the config file, fails rather than falling back to the default.
func TestBadValuesFail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quisora.toml")
	if err := os.WriteFile(path, []byte("[session]\nidle = \"soon\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parse(t, path); err == nil || !strings.Contains(err.Error(), "session.idle") {
		t.Errorf("config file: %v", err)
	}
	t.Setenv("QUISORA_CLUSTER_SIZE", "three")
	if _, err := parse(t, ""); err == nil || !strings.Contains(err.Error(), "QUISORA_CLUSTER_SIZE") {
		t.Errorf("environment: %v", err)
	}
}

// Keys of the config file that are not settings are refused by Validate, named by their dotted paths; settings,
// their sections and empty sections are not.
func TestUnknownKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quisora.toml")
	if err := os.WriteFile(path, []byte(`
colour = "red"
[server]
listen = ":1111"
lisen = ":2222"
[storage.postgres]
dsn = "postgres://x"
tls = true
[cluster.notify]
[nosuch]
a = 1
[server.listen_extra]
b = 2
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := parse(t, path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"colour", "nosuch", "server.lisen", "server.listen_extra", "storage.postgres.tls"}
	if got := cfg.UnknownKeys(); !slices.Equal(got, want) {
		t.Fatalf("unknown keys %v, want %v", got, want)
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "unknown settings: colour, nosuch") {
		t.Fatalf("validate: %v", err)
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
