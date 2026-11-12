package config

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"
)

func key(b byte) string { return base64.StdEncoding.EncodeToString(slices.Repeat([]byte{b}, 32)) }

// Each invalid setting is refused with a message naming it.
func TestValidateMessages(t *testing.T) {
	good := key(1)
	// a two node cluster that is valid until a row spoils one thing
	cluster := func(mut func(*Config)) func(*Config) {
		return func(c *Config) {
			c.Server.MasterKey, c.Cluster.Key = key(2), good
			c.Cluster.Bind, c.Cluster.Advertise = "10.0.0.1:7946", "10.0.0.1:7946"
			c.Cluster.Peers, c.Cluster.Size = []string{"10.0.0.2:7946"}, 2
			mut(c)
		}
	}
	notify := func(backend string, n Notify) func(*Config) {
		return func(c *Config) { c.Storage.Backend, c.Cluster.Notify = backend, n }
	}
	for name, tc := range map[string]struct {
		mut  func(*Config)
		want string
	}{
		"public url scheme":                      {func(c *Config) { c.Server.PublicURL = "http://x" }, "server.public_url"},
		"grants per user low":                    {func(c *Config) { c.Limits.GrantsPerUser = 9 }, "limits.grants_per_user"},
		"grants per user high":                   {func(c *Config) { c.Limits.GrantsPerUser = 100001 }, "limits.grants_per_user"},
		"theme":                                  {func(c *Config) { c.UI.DefaultTheme = "blue" }, "ui.default_theme"},
		"backend":                                {func(c *Config) { c.Storage.Backend = "mongo" }, "storage.backend"},
		"half tls":                               {func(c *Config) { c.Server.TLSCert = "x" }, "tls_cert and server.tls_key"},
		"signing alg":                            {func(c *Config) { c.Tokens.SigningAlg = "HS256" }, "tokens.signing_alg"},
		"cluster no key":                         {cluster(func(c *Config) { c.Cluster.Key = "" }), "cluster.key"},
		"cluster no size":                        {cluster(func(c *Config) { c.Cluster.Size = 0 }), "cluster.size is required"},
		"size above peers":                       {cluster(func(c *Config) { c.Cluster.Size = 3 }), "cluster.size is 3"},
		"size without cluster":                   {func(c *Config) { c.Cluster.Size = 3 }, "applies only with cluster.bind"},
		"cluster no peers":                       {cluster(func(c *Config) { c.Cluster.Peers = nil }), "cluster.peers"},
		"cluster only itself":                    {cluster(func(c *Config) { c.Cluster.Peers = []string{"10.0.0.1:7946"} }), "cluster.peers"},
		"notify on a local database":             {notify("badgerdb", Notify{Bind: "10.0.0.1:7947", Peers: []string{"10.0.0.2:7947"}, Key: key(3)}), "cluster.notify is for nodes that share one database"},
		"notify without a key":                   {notify("postgres", Notify{Bind: "10.0.0.1:7947", Peers: []string{"10.0.0.2:7947"}}), "cluster.notify.key is required"},
		"notify with a bad key":                  {notify("postgres", Notify{Bind: "10.0.0.1:7947", Peers: []string{"10.0.0.2:7947"}, Key: "short"}), "cluster.notify.key must be 32 bytes"},
		"notify without peers":                   {notify("postgres", Notify{Bind: "10.0.0.1:7947", Peers: []string{"10.0.0.1:7947"}, Key: key(3)}), "cluster.notify.peers"},
		"notify on a wildcard without advertise": {notify("postgres", Notify{Bind: "0.0.0.0:7947", Peers: []string{"10.0.0.2:7947"}, Key: key(3)}), "cluster.notify.advertise is required"},
		"listen":                                 {func(c *Config) { c.Server.Listen = "nope" }, "server.listen"},
		"trust proxy":                            {func(c *Config) { c.Server.TrustProxy = []string{"x"} }, "trust_proxy"},
		"deny network":                           {func(c *Config) { c.Server.DenyNetworks = []string{"10.0.0.0/8", "x"} }, "server.deny_networks \"x\""},
		"deny every address":                     {func(c *Config) { c.Server.DenyNetworks = []string{"::/0"} }, "is every address"},
		"public url path":                        {func(c *Config) { c.Server.PublicURL = "https://x/path" }, "server.public_url"},
		"extra ca":                               {func(c *Config) { c.Server.ExtraCAFile = "/nonexistent/ca.pem" }, "ca.pem"},
		"master key":                             {func(c *Config) { c.Server.MasterKey = "short" }, "server.master_key"},
		"previous no key":                        {func(c *Config) { c.Server.PreviousMasterKeys = []string{good} }, "needs server.master_key"},
		"previous is key":                        {func(c *Config) { c.Server.MasterKey, c.Server.PreviousMasterKeys = good, []string{good} }, "itself"},
		"previous bad":                           {func(c *Config) { c.Server.MasterKey, c.Server.PreviousMasterKeys = good, []string{"x"} }, "previous_master_keys[0]"},
		"badger key":                             {func(c *Config) { c.Storage.BadgerDB.EncryptionKey = "x" }, "encryption_key"},
		"cluster key bad":                        {func(c *Config) { c.Cluster.Key = "x" }, "cluster.key"},
		"cluster prev":                           {func(c *Config) { c.Cluster.PreviousKeys = []string{good} }, "needs cluster.key"},
		"cluster prev same":                      {func(c *Config) { c.Cluster.Key, c.Cluster.PreviousKeys = good, []string{good} }, "itself"},
		"cluster prev bad":                       {func(c *Config) { c.Cluster.Key, c.Cluster.PreviousKeys = good, []string{"x"} }, "previous_keys[0]"},
		"advertise": {func(c *Config) {
			c.Cluster.Bind, c.Cluster.Peers, c.Cluster.Size = ":7946", []string{"a:1"}, 2
		}, "cluster.advertise"},
		"node id":        {func(c *Config) { c.Cluster.NodeID = "x" }, "node_id"},
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
	if err := c.Validate(); err != nil || c.Server.PublicURL != "https://localhost:8443" {
		t.Fatalf("defaults: %v %q", err, c.Server.PublicURL)
	}
	c = Default()
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
	if err := c.Validate(); err != nil || c.Server.PublicURL != "https://id.example.com" {
		t.Fatalf("%v %q", err, c.Server.PublicURL)
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
}

func TestParseProxyForms(t *testing.T) {
	for in, want := range map[string]string{"10.1.2.3": "10.1.2.3/32", " ::1 ": "::1/128", "10.1.2.3/8": "10.0.0.0/8", "2001:db8::1": "2001:db8::1/128"} {
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
