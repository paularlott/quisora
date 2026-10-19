package config

import (
	"testing"
)

func TestExampleParses(t *testing.T) {
	c, err := Load("../../quisora.toml.example")
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.PublicURL != "https://id.example.com" || c.UI.DefaultTheme != "system" || c.Tokens.AccessTTL != 600 {
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
