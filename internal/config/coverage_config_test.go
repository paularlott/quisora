package config

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func key(b byte) string { return base64.StdEncoding.EncodeToString(slices.Repeat([]byte{b}, 32)) }

// Each invalid setting is refused with a message naming it.
func TestValidateMessages(t *testing.T) {
	good := key(1)
	for name, tc := range map[string]struct {
		mut  func(*Config)
		want string
	}{
		"listen":            {func(c *Config) { c.Server.Listen = "nope" }, "server.listen"},
		"trust proxy":       {func(c *Config) { c.Server.TrustProxy = []string{"x"} }, "trust_proxy"},
		"public url path":   {func(c *Config) { c.Server.PublicURL = "https://x/path" }, "server.public_url"},
		"extra ca":          {func(c *Config) { c.Server.ExtraCAFile = "/nonexistent/ca.pem" }, "ca.pem"},
		"master key":        {func(c *Config) { c.Server.MasterKey = "short" }, "server.master_key"},
		"previous no key":   {func(c *Config) { c.Server.PreviousMasterKeys = []string{good} }, "needs server.master_key"},
		"previous is key":   {func(c *Config) { c.Server.MasterKey, c.Server.PreviousMasterKeys = good, []string{good} }, "itself"},
		"previous bad":      {func(c *Config) { c.Server.MasterKey, c.Server.PreviousMasterKeys = good, []string{"x"} }, "previous_master_keys[0]"},
		"badger key":        {func(c *Config) { c.Storage.BadgerDB.EncryptionKey = "x" }, "encryption_key"},
		"cluster key bad":   {func(c *Config) { c.Cluster.Key = "x" }, "cluster.key"},
		"cluster prev":      {func(c *Config) { c.Cluster.PreviousKeys = []string{good} }, "needs cluster.key"},
		"cluster prev same": {func(c *Config) { c.Cluster.Key, c.Cluster.PreviousKeys = good, []string{good} }, "itself"},
		"cluster prev bad":  {func(c *Config) { c.Cluster.Key, c.Cluster.PreviousKeys = good, []string{"x"} }, "previous_keys[0]"},
		"advertise": {func(c *Config) {
			c.Cluster.Bind, c.Cluster.Peers, c.Cluster.Size = ":7946", []string{"a:1"}, 2
		}, "cluster.advertise"},
		"node id":        {func(c *Config) { c.Cluster.NodeID = "x" }, "node_id"},
		"grace":          {func(c *Config) { c.Cluster.MinorityGrace = -1 }, "minority_grace"},
		"bad bind":       {func(c *Config) { c.Cluster.Bind = "x" }, "cluster.bind"},
		"bad peer":       {func(c *Config) { c.Cluster.Peers = []string{"x"} }, "cluster.peers"},
		"master missing": {func(c *Config) { c.Cluster.Bind, c.Cluster.Key = "10.0.0.1:1", good }, "server.master_key is required"},
		"data dir":       {func(c *Config) { c.Server.DataDir = " " }, "server.data_dir"},
		"postgres":       {func(c *Config) { c.Storage.Backend = "postgres" }, "storage.postgres.dsn"},
		"mysql":          {func(c *Config) { c.Storage.Backend = "mysql" }, "storage.mysql.dsn"},
		"mariadb":        {func(c *Config) { c.Storage.Backend = "mariadb" }, "storage.mariadb.dsn"},
		"drain":          {func(c *Config) { c.Server.ShutdownDrain = -1 }, "shutdown_drain"},
		"eph mb":         {func(c *Config) { c.Limits.EphemeralMB = 0 }, "limits.ephemeral_mb"},
		"pw min low":     {func(c *Config) { c.Limits.PasswordMinLength = 7 }, "limits.password_min_length"},
		"pw min high":    {func(c *Config) { c.Limits.PasswordMinLength = 65 }, "limits.password_min_length"},
		"trust all v4":   {func(c *Config) { c.Server.TrustProxy = []string{"0.0.0.0/0"} }, "trusts every address"},
		"trust all v6":   {func(c *Config) { c.Server.TrustProxy = []string{"::/0"} }, "trusts every address"},
		"allowed bad":    {func(c *Config) { c.Server.AllowedNetworks = []string{"172.16.0.0/33"} }, "server.allowed_networks"},
		"allowed all":    {func(c *Config) { c.Server.AllowedNetworks = []string{"0.0.0.0/0"} }, "is every address"},
		"timeout":        {func(c *Config) { c.Server.ShutdownTimeout = 0 }, "shutdown_timeout"},
		"access ttl":     {func(c *Config) { c.Tokens.AccessTTL = 0 }, "tokens.access_ttl"},
		"code ttl":       {func(c *Config) { c.Tokens.CodeTTL = 601 }, "at most 600"},
		"session idle":   {func(c *Config) { c.Session.Idle = -1 }, "session.idle"},
		"retention":      {func(c *Config) { c.Audit.RetentionDays = 0 }, "audit.retention_days"},
		"victoria":       {func(c *Config) { c.Audit.VictoriaLogs = "ftp://x" }, "victorialogs_url"},
		"spool":          {func(c *Config) { c.Audit.SpoolMaxMB = 0 }, "spool_max_mb"},
		"in flight":      {func(c *Config) { c.Limits.MaxInFlight = 0 }, "max_in_flight"},
		"lockout":        {func(c *Config) { c.Limits.LockoutMinutes = 0 }, "lockout_minutes"},
		"workers":        {func(c *Config) { c.Limits.PasswordWorkers = -1 }, "password_workers"},
		"smtp port":      {func(c *Config) { c.Mail.SMTPHost, c.Mail.SMTPPort = "smtp", 70000 }, "mail.smtp_port"},
		"mail tls":       {func(c *Config) { c.Mail.SMTPHost, c.Mail.TLS = "smtp", "weird" }, "mail.tls"},
		"mail from":      {func(c *Config) { c.Mail.SMTPHost, c.Mail.From = "smtp", "not an address" }, "mail.from"},
		"log level":      {func(c *Config) { c.Log.Level = "loud" }, "log.level"},
		"log format":     {func(c *Config) { c.Log.Format = "xml" }, "log.format"},
		"logo":           {func(c *Config) { c.UI.LogoLight = "relative.png" }, "ui.logo_light"},
		"skin":           {func(c *Config) { c.UI.Skin = "Bad Name" }, "ui.skin"},
	} {
		c := Default()
		tc.mut(c)
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want an error naming %q, got %v", name, tc.want, err)
		}
	}
	// several problems are all reported
	c := Default()
	c.Log.Level, c.Log.Format = "loud", "xml"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "log.level") || !strings.Contains(err.Error(), "log.format") {
		t.Fatalf("joined errors: %v", err)
	}
}

func TestValidateAcceptsAndDerives(t *testing.T) {
	c := Default()
	c.Server.Listen = ":443"
	if err := c.Validate(); err != nil || c.Server.PublicURL != "https://localhost" {
		t.Fatalf("%v %q", err, c.Server.PublicURL)
	}
	c = Default()
	c.Server.PublicURL = "https://id.example.com/"
	c.Storage.Backend, c.Storage.Postgres.DSN = "postgres", "postgres://db.example.com/quisora?sslmode=verify-full"
	c.Mail.SMTPHost, c.Mail.From = "smtp", "Identity <no-reply@example.com>"
	c.Audit.VictoriaLogs = "http://vl:9428"
	c.Server.TrustProxy = []string{"10.0.0.0/8", "::1"}
	if err := c.Validate(); err != nil || c.Server.PublicURL != "https://id.example.com" || c.Issuer() != "https://id.example.com" {
		t.Fatalf("%v %q", err, c.Server.PublicURL)
	}
	dir := filepath.Join(t.TempDir(), "acme")
	_ = os.Mkdir(dir, 0o700)
	_ = os.WriteFile(filepath.Join(dir, "skin.css"), []byte("a{}"), 0o600)
	c = Default()
	c.UI.Skin = dir
	if err := c.Validate(); err != nil || c.UI.Skin != dir {
		t.Fatalf("skin folder: %v %q", err, c.UI.Skin)
	}
	c.UI.Skin = "midnight"
	if err := c.Validate(); err != nil || c.UI.Skin != "midnight" {
		t.Fatalf("skin name: %v", err)
	}
	// a skin folder without skin.css, or named badly
	c.UI.Skin = filepath.Join(t.TempDir(), "empty")
	_ = os.Mkdir(c.UI.Skin, 0o700)
	if c.Validate() == nil {
		t.Fatal("skin folder without skin.css accepted")
	}
	c.UI.Skin = filepath.Join(t.TempDir(), "Bad_Name")
	if c.Validate() == nil {
		t.Fatal("badly named skin folder accepted")
	}
	d := filepath.Join(t.TempDir(), "skin")
	_ = os.MkdirAll(filepath.Join(d, "skin.css"), 0o700) // a directory called skin.css
	c.UI.Skin = d
	if c.Validate() == nil {
		t.Fatal("skin.css directory accepted")
	}
}

func TestAccessors(t *testing.T) {
	c := Default()
	c.Server.DataDir = "/d"
	if c.DataPath() != "/d" || c.DataPath("a", "b") != filepath.Join("/d", "a", "b") {
		t.Fatal("DataPath")
	}
	if !c.LocalStorage() || c.SharedStorage() || c.Replicate() {
		t.Fatal("badgerdb is local, no gossip")
	}
	c.Storage.Backend, c.Cluster.Bind = "postgres", ":1"
	if c.LocalStorage() || !c.SharedStorage() || !c.Replicate() {
		t.Fatal("postgres is shared, gossip replicates")
	}
	if tk := (Tokens{AccessTTL: 1, IDTokenTTL: 2, RefreshTTL: 3, CodeTTL: 4}); tk.Access() != time.Second || tk.IDToken() != 2*time.Second ||
		tk.Refresh() != 3*time.Second || tk.Code() != 4*time.Second {
		t.Fatal("token durations")
	}
}

func TestKeyReaders(t *testing.T) {
	c := Default()
	if m, p, err := c.MasterKeys(); err != nil || m != "" || len(p) != 0 {
		t.Fatalf("no key: %q %v %v", m, p, err)
	}
	c.Server.MasterKey, c.Server.PreviousMasterKeys = key(1), []string{key(2)}
	if m, p, err := c.MasterKeys(); err != nil || m != key(1) || len(p) != 1 {
		t.Fatalf("%v", err)
	}
	c.Server.PreviousMasterKeys = []string{"bad", key(1)}
	if _, _, err := c.MasterKeys(); err == nil || !strings.Contains(err.Error(), "[0]") || !strings.Contains(err.Error(), "[1]") {
		t.Fatalf("both previous keys named: %v", err)
	}

	if _, _, err := c.ClusterKeys(); err == nil || !strings.Contains(err.Error(), "not set") {
		t.Fatalf("no cluster key: %v", err)
	}
	c.Cluster.Key, c.Cluster.PreviousKeys = key(3), []string{key(4)}
	if k, p, err := c.ClusterKeys(); err != nil || k != key(3) || len(p) != 1 {
		t.Fatal(err)
	}
	c.Cluster.PreviousKeys = []string{key(3)}
	if _, _, err := c.ClusterKeys(); err == nil {
		t.Fatal("previous equal to current accepted")
	}

	c.Cluster.Size, c.Cluster.Peers = 3, []string{"a:1", "b:2"}
	if n, p, err := c.ClusterSize(); err != nil || n != 3 || len(p) != 2 {
		t.Fatal(err)
	}
	c.Cluster.Peers = []string{"a:1", "b"}
	if _, _, err := c.ClusterSize(); err == nil || !strings.Contains(err.Error(), `"b"`) {
		t.Fatalf("%v", err)
	}
}

func TestParseProxyForms(t *testing.T) {
	for in, want := range map[string]string{"10.1.2.3": "10.1.2.3/32", " ::1 ": "::1/128", "10.1.2.3/8": "10.0.0.0/8"} {
		if p, err := ParseProxy(in); err != nil || p.String() != want {
			t.Errorf("%q: %v %v", in, p, err)
		}
	}
	for _, in := range []string{"", "host", "10.0.0.0/33", "x/8"} {
		if _, err := ParseProxy(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestSecretRefs(t *testing.T) {
	for v, want := range map[string]bool{"op://v/i/f": true, "vault://p#f": true, "plain": false, "": false, " op://x": false} {
		if IsSecretRef(v) != want {
			t.Errorf("IsSecretRef(%q)", v)
		}
	}
	c := Default()
	if c.HasSecretRefs() {
		t.Fatal("defaults hold no references")
	}
	c.Server.MasterKey = "vault://secret/data/q#master"
	c.Server.PreviousMasterKeys = []string{"vault://secret/data/q#prev1", "op://v/i/prev2", "literal"}
	c.Cluster.Key = "op://v/i/cluster"
	c.Secrets.Vault.Token = "vault://not/resolved#here" // the stores' own credentials are never resolved
	if !c.HasSecretRefs() {
		t.Fatal("references not found")
	}
	values := map[string]string{"vault://secret/data/q#master": key(1), "vault://secret/data/q#prev1": "", "op://v/i/prev2": key(2),
		"op://v/i/cluster": key(3)}
	var asked []string
	resolve := func(_ context.Context, ref string) (string, error) {
		asked = append(asked, ref)
		return values[ref], nil
	}
	// only the named setting
	if err := c.ResolveSecrets(context.Background(), resolve, "cluster.key"); err != nil || c.Cluster.Key != key(3) ||
		c.Server.MasterKey != "vault://secret/data/q#master" || len(asked) != 1 {
		t.Fatalf("selective: %v %v %q", err, asked, c.Server.MasterKey)
	}
	// all of them; empty list entries drop out, literals stay
	if err := c.ResolveSecrets(context.Background(), resolve); err != nil {
		t.Fatal(err)
	}
	if c.Server.MasterKey != key(1) || !slices.Equal(c.Server.PreviousMasterKeys, []string{key(2), "literal"}) ||
		c.Secrets.Vault.Token != "vault://not/resolved#here" {
		t.Fatalf("resolved: %q %q %q", c.Server.MasterKey, c.Server.PreviousMasterKeys, c.Secrets.Vault.Token)
	}
	// an error names the setting
	c.Server.MasterKey = "op://bad"
	boom := errors.New("boom")
	err := c.ResolveSecrets(context.Background(), func(context.Context, string) (string, error) { return "", boom })
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "server.master_key") {
		t.Fatalf("%v", err)
	}
	c.Server.MasterKey = key(1)
	c.Server.PreviousMasterKeys = []string{"vault://x#y"}
	err = c.ResolveSecrets(context.Background(), func(context.Context, string) (string, error) { return "", boom })
	if !errors.Is(err, boom) {
		t.Fatalf("list entry error: %v", err)
	}
}

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

// server.allowed_networks takes IP addresses and CIDR ranges; OutboundReach gives them, with allow_private_networks,
// to the outbound guard.
func TestOutboundReach(t *testing.T) {
	c := Default()
	c.Server.AllowedNetworks = []string{"172.16.0.0/12", " 10.1.2.3 ", "::ffff:192.168.5.9", "fd00:1::/32"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	r := c.OutboundReach()
	want := []string{"172.16.0.0/12", "10.1.2.3/32", "192.168.5.9/32", "fd00:1::/32"}
	if r.Private || len(r.Networks) != len(want) {
		t.Fatalf("%+v", r)
	}
	for i, p := range r.Networks {
		if p.String() != want[i] {
			t.Errorf("network %d: %s, want %s", i, p, want[i])
		}
	}
	c.Server.AllowPrivateNetworks = true
	if !c.OutboundReach().Private {
		t.Fatal("allow_private_networks not carried")
	}
}
