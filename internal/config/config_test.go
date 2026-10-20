package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestExampleParses(t *testing.T) {
	c, err := Load("../../quisora.toml.example")
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.PublicURL != "https://id.example.com" || c.UI.DefaultTheme != "system" || c.Tokens.AccessTTL != 600 ||
		c.Tokens.APITokenMaxDays != 0 { // personal API tokens: no lifetime limit unless the operator sets one
		t.Fatalf("unexpected values: %+v", c.Server)
	}
}

func TestDefaultsValidate(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Server.PublicURL != "https://localhost:8443" {
		t.Fatal(c.Server.PublicURL)
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("QUISORA_STORAGE", "sqlite")
	t.Setenv("QUISORA_CLUSTER_PEERS", "a:1, b:2")
	t.Setenv("QUISORA_DEFAULT_THEME", "dark")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Storage.Backend != "sqlite" || len(c.Cluster.Peers) != 2 || c.UI.DefaultTheme != "dark" {
		t.Fatalf("env not applied: %+v %+v", c.Storage, c.Cluster)
	}
}

func TestInvalid(t *testing.T) {
	for name, mut := range map[string]func(*Config){
		"http url":       func(c *Config) { c.Server.PublicURL = "http://x" },
		"bad theme":      func(c *Config) { c.UI.DefaultTheme = "blue" },
		"bad backend":    func(c *Config) { c.Storage.Backend = "mongo" },
		"cluster no key": func(c *Config) { c.Cluster.Bind = ":7946"; c.Cluster.Peers = []string{"b:7946"}; c.Cluster.Size = 2 },
		"cluster no size": func(c *Config) {
			c.Cluster.Bind, c.Cluster.Key, c.Server.MasterKey = "10.0.0.1:7946", "k", "m"
			c.Cluster.Peers = []string{"10.0.0.2:7946", "10.0.0.3:7946"}
		},
		"cluster size above peers": func(c *Config) {
			c.Cluster.Bind, c.Cluster.Key, c.Server.MasterKey = "10.0.0.1:7946", "k", "m"
			c.Cluster.Peers, c.Cluster.Size = []string{"10.0.0.2:7946"}, 3
		},
		"size without cluster": func(c *Config) { c.Cluster.Size = 3 },
		"cluster no peers": func(c *Config) {
			c.Cluster.Bind, c.Cluster.Key, c.Server.MasterKey = "10.0.0.1:7946", "k", "m"
		},
		"cluster only itself": func(c *Config) {
			c.Cluster.Bind, c.Cluster.Key, c.Server.MasterKey, c.Cluster.Peers = "10.0.0.1:7946", "k", "m", []string{"10.0.0.1:7946"}
		},
		"half tls": func(c *Config) { c.Server.TLSCert = "x" },
		"bad alg":  func(c *Config) { c.Tokens.SigningAlg = "HS256" },
	} {
		c := Default()
		mut(c)
		if c.Validate() == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

// A reload (SIGHUP) reads the master keys from the config file and the environment, as at start-up, and nothing else.
func TestLoadMasterKeys(t *testing.T) {
	k0 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	k1 := base64.StdEncoding.EncodeToString(append(make([]byte, 31), 1))
	f := filepath.Join(t.TempDir(), "q.toml")
	if err := os.WriteFile(f, []byte("[server]\nmaster_key = \""+k1+"\"\nprevious_master_keys = [\""+k0+"\"]\nlisten = \"bad\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, prev, err := LoadMasterKeys(f)
	if err != nil || m != k1 || len(prev) != 1 || prev[0] != k0 {
		t.Fatalf("from the file (other settings not checked): %q %v %v", m, prev, err)
	}
	t.Setenv(EnvPrefix+"PREVIOUS_MASTER_KEYS", "")
	if m, prev, err = LoadMasterKeys(f); err != nil || m != k1 || len(prev) != 0 {
		t.Fatalf("the environment over the file: %q %v %v", m, prev, err)
	}
	t.Setenv(EnvPrefix+"MASTER_KEY", "short")
	if _, _, err = LoadMasterKeys(f); err == nil {
		t.Fatal("an invalid key was accepted")
	}
}
