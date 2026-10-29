package cmd

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/paularlott/cli"
	"github.com/paularlott/quisora/internal/config"
)

// parsed parses args (after the program name) into cfg through the command tree, without running anything, and
// returns the root command (FlagSource and the rest answer for the matched command; the global ones too).
func parsed(t *testing.T, cfg *config.Config, args ...string) *cli.Command {
	t.Helper()
	old := os.Args
	t.Cleanup(func() { os.Args = old })
	os.Args = append([]string{"quisora"}, args...)
	root := newRoot(cfg)
	if err := root.ReloadFlags(); err != nil {
		t.Fatal(err)
	}
	for _, c := range root.Commands {
		if slices.Contains(args, c.Name) {
			return c
		}
	}
	return root
}

// A reload reads the master keys the way start-up does: the command line, then the environment, then the config file
// (read again), with bad values refused.
func TestReloadReadsMasterKeys(t *testing.T) {
	k0 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	k1 := base64.StdEncoding.EncodeToString(append(make([]byte, 31), 1))
	k2 := base64.StdEncoding.EncodeToString(append(make([]byte, 31), 2))
	f := filepath.Join(t.TempDir(), "q.toml")
	write := func(master string) {
		if err := os.WriteFile(f, []byte("[server]\nmaster_key = \""+master+"\"\nprevious_master_keys = [\""+k0+"\"]\nlisten = \"bad\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(k1)
	cfg := config.Default()
	c := parsed(t, cfg, "--config", f, "serve")
	if m, prev, err := cfg.MasterKeys(); err != nil || m != k1 || len(prev) != 1 || prev[0] != k0 {
		t.Fatalf("from the file (other settings not checked): %q %v %v", m, prev, err)
	}
	if c.FlagSource("master-key") != cli.SourceConfigFile {
		t.Fatalf("source %v", c.FlagSource("master-key"))
	}
	write(k2) // the file is read again
	cfg = config.Default()
	parsed(t, cfg, "--config", f, "serve")
	if m, _, _ := cfg.MasterKeys(); m != k2 {
		t.Fatalf("changed file not read again: %q", m)
	}
	t.Setenv(config.EnvPrefix+"MASTER_KEY", k1)
	cfg = config.Default()
	parsed(t, cfg, "--config", f, "serve")
	if m, _, _ := cfg.MasterKeys(); m != k1 {
		t.Fatalf("the environment over the file: %q", m)
	}
	t.Setenv(config.EnvPrefix+"MASTER_KEY", "short")
	cfg = config.Default()
	parsed(t, cfg, "--config", f, "serve")
	if _, _, err := cfg.MasterKeys(); err == nil {
		t.Fatal("an invalid key was accepted")
	}
	// a value that does not parse fails the reload itself
	t.Setenv(config.EnvPrefix+"CLUSTER_SIZE", "three")
	old := os.Args
	defer func() { os.Args = old }()
	os.Args = []string{"quisora", "--config", f, "serve"}
	if err := newRoot(config.Default()).ReloadFlags(); err == nil {
		t.Fatal("QUISORA_CLUSTER_SIZE=three was accepted")
	}
}

func TestFlagSourceOnCommandLine(t *testing.T) {
	c := parsed(t, config.Default(), "serve", "--master-key=x", "--data-dir", "d")
	if c.FlagSource("master-key") != cli.SourceCommandLine || c.FlagSource("previous-master-keys") == cli.SourceCommandLine {
		t.Fatal("master-key source")
	}
}

func TestGenkey(t *testing.T) {
	e := newEnv(t, "")
	out, _, err := e.run(t, "", "genkey")
	if err != nil {
		t.Fatal(err)
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	if err != nil || len(k) != 32 {
		t.Fatalf("genkey %q: %v", out, err)
	}
}

func TestRootHelpAndUnknown(t *testing.T) {
	e := newEnv(t, "")
	if out, _, err := e.run(t, "", "--version"); err != nil || !strings.Contains(out, "quisora") {
		t.Fatalf("version: %v %q", err, out)
	}
	if _, _, err := e.run(t, "", "bogus"); err == nil {
		t.Fatal("unknown command accepted")
	}
	if c := Root(); c == nil || c.Name != "quisora" {
		t.Fatal("Root")
	}
}

// A command's own flags work beside the settings' flags it offers, and do not leak into another command.
func TestCommandFlagsDoNotClobberEachOther(t *testing.T) {
	e := newEnv(t, "")
	// one command with a flag of its own that works through
	if _, errOut, err := e.run(t, "", "bootstrap", "--bootstrap-admin", "boss@example.com"); err != nil || !strings.Contains(errOut, "boss@example.com") {
		t.Fatalf("bootstrap with its own flag: %v %q", err, errOut)
	}
	for _, args := range [][]string{{"invite", "--break-glass", "primary", "a@example.com"}, {"backup", "--plain", "--server", "x", "-"},
		{"restore", "--force", "-"}, {"healthcheck", "--ready"}} {
		if _, _, err := e.run(t, "", args...); err != nil && strings.Contains(err.Error(), "unknown flag") {
			t.Errorf("%v: %v", args, err)
		}
	}
}

func TestPrepareRejectsInvalidConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Cluster.Size = 3 // size without bind
	if err := prepare(context.Background(), cfg); err == nil {
		t.Fatal("invalid configuration prepared")
	}
}

// Each command offers as flags the settings it reads, and the log settings and --config are global. The rest are read
// from the config file and the environment, which every command shares with serve (validated whole), and refused on
// the command line.
func TestCommandFlagsAreItsOwn(t *testing.T) {
	e := newEnv(t, "[ui]\nsite_name = \"Acme\"\n")
	t.Setenv(config.EnvPrefix+"FOOTER", "Acme Inc")
	help := func(args ...string) string {
		t.Helper()
		out, errOut, err := e.run(t, "", append(args, "--help")...)
		if err != nil {
			t.Fatal(err)
		}
		return out + errOut
	}
	for _, c := range []struct {
		cmd       string
		has, hasn []string
	}{
		{"serve", []string{"--site-name", "--listen", "--master-key", "--log-access", "--log-level", "--config"}, []string{"--bootstrap-admin"}},
		{"backup", []string{"--master-key", "--storage", "--data-dir", "--log-level", "--config"}, []string{"--site-name", "--logo-light", "--listen", "--log-access", "--access-ttl", "--cluster-bind"}},
		{"healthcheck", []string{"--listen", "--log-level"}, []string{"--master-key", "--storage", "--site-name"}},
		{"bootstrap", []string{"--bootstrap-admin", "--public-url", "--cluster-bind"}, []string{"--site-name", "--listen"}},
	} {
		h := help(c.cmd)
		for _, f := range c.has {
			if !strings.Contains(h, f+" ") && !strings.Contains(h, f+",") && !strings.Contains(h, f+"=") {
				t.Errorf("%s does not offer %s", c.cmd, f)
			}
		}
		for _, f := range c.hasn {
			if strings.Contains(h, f+" ") || strings.Contains(h, f+",") || strings.Contains(h, f+"=") {
				t.Errorf("%s offers %s", c.cmd, f)
			}
		}
	}
	out := filepath.Join(e.dir, "b")
	if _, _, err := e.run(t, "", "backup", "--plain", "--site-name", "x", out); err == nil || !strings.Contains(err.Error(), "--site-name") {
		t.Fatalf("a serve setting on backup's command line: %v", err)
	}
	// The same settings from the config file and the environment are read as ever.
	if _, errOut, err := e.run(t, "", "backup", "--plain", out); err != nil {
		t.Fatalf("backup with serve's settings in the file and environment: %v %s", err, errOut)
	}
}
