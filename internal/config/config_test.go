package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestExampleParses(t *testing.T) {
	c, err := parse(t, "../../quisora.toml.example")
	if err == nil {
		err = c.Validate()
	}
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.PublicURL != "https://id.example.com" || c.UI.DefaultTheme != "system" || c.Tokens.AccessTTL != 600 ||
		c.Tokens.APITokenMaxDays != 365 { // personal API tokens: a year at most unless the operator says otherwise
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
	c, err := parse(t, "")
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
		"notify on a local database": func(c *Config) {
			c.Cluster.Notify = Notify{Bind: "10.0.0.1:7947", Peers: []string{"10.0.0.2:7947"}, Key: base64.StdEncoding.EncodeToString(make([]byte, 32))}
		},
		"notify without a key": func(c *Config) {
			c.Storage.Backend = "postgres"
			c.Cluster.Notify = Notify{Bind: "10.0.0.1:7947", Peers: []string{"10.0.0.2:7947"}}
		},
		"notify with a bad key": func(c *Config) {
			c.Storage.Backend = "postgres"
			c.Cluster.Notify = Notify{Bind: "10.0.0.1:7947", Peers: []string{"10.0.0.2:7947"}, Key: "short"}
		},
		"notify without peers": func(c *Config) {
			c.Storage.Backend = "postgres"
			c.Cluster.Notify = Notify{Bind: "10.0.0.1:7947", Peers: []string{"10.0.0.1:7947"}, Key: base64.StdEncoding.EncodeToString(make([]byte, 32))}
		},
		"notify on a wildcard without advertise": func(c *Config) {
			c.Storage.Backend = "postgres"
			c.Cluster.Notify = Notify{Bind: "0.0.0.0:7947", Peers: []string{"10.0.0.2:7947"}, Key: base64.StdEncoding.EncodeToString(make([]byte, 32))}
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

// Logos are the built-in one, an https URL or an absolute path to a regular file; anything else fails at load.
func TestLogo(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "logo.svg")
	if err := os.WriteFile(file, []byte("<svg/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	for v, ok := range map[string]bool{
		"":                                true,
		"https://cdn.example.com/l.svg":   true,
		file:                              true,
		"http://cdn.example.com/l.svg":    false,
		"https://":                        false,
		"https://u:p@cdn.example.com/l":   false,
		"logo.svg":                        false,
		"../logo.svg":                     false,
		dir:                               false,
		filepath.Join(dir, "missing.svg"): false,
	} {
		for _, dark := range []bool{false, true} {
			c := Default()
			if dark {
				c.UI.LogoDark = v
			} else {
				c.UI.LogoLight = v
			}
			if err := c.Validate(); (err == nil) != ok {
				t.Errorf("logo %q (dark %v): err = %v, want ok %v", v, dark, err, ok)
			}
		}
	}
}

// ui.skin is a built-in skin's name or the path of a folder holding skin.css (named like a skin); a relative path is
// made absolute against the working directory.
func TestSkinSetting(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	good, bare := filepath.Join(root, "acme"), filepath.Join(root, "empty")
	for _, d := range []string{good, bare, filepath.Join(root, "Bad_Name")} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{good, filepath.Join(root, "Bad_Name")} {
		if err := os.WriteFile(filepath.Join(d, "skin.css"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for v, want := range map[string]string{
		"":                              "",
		"corporate":                     "corporate",
		good:                            good,
		"./acme":                        good,
		"./acme/":                       good,
		"empty/../acme":                 good,
		"Corporate":                     "error",
		"acme_1":                        "error",
		"./corporate":                   "error",
		"../acme":                       "error",
		bare:                            "error",
		filepath.Join(root, "Bad_Name"): "error",
		filepath.Join(root, "missing"):  "error",
	} {
		c := Default()
		c.UI.Skin = v
		err := c.Validate()
		got := c.UI.Skin
		if err != nil {
			got = "error"
		}
		if got != want {
			t.Errorf("skin %q: got %q (err %v), want %q", v, got, err, want)
		}
	}
}

// A shared database with the notice gossip is valid; with cluster.bind too the notice settings are not checked (the
// node ignores them, with a warning).
func TestNotifyConfig(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	c := Default()
	c.Storage.Backend = "postgres"
	c.Storage.Postgres.DSN = "postgres://u:p@db/quisora"
	c.Cluster.Notify = Notify{Bind: "10.0.0.1:7947", Peers: []string{"10.0.0.1:7947", "10.0.0.2:7947"}, Key: key}
	if err := c.Validate(); err != nil {
		t.Fatalf("shared database with notify: %v", err)
	}
	for _, s := range settings(c) {
		if s.Path == "cluster.notify.bind" && s.Env != EnvPrefix+"CLUSTER_NOTIFY_BIND" {
			t.Errorf("env name %s", s.Env)
		}
	}
}
