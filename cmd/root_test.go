package cmd

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
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
