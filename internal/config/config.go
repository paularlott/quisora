// Package config holds the server configuration, loaded from a TOML file with QUISORA_* environment overrides.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/google/uuid"
	"github.com/paularlott/quisora/internal/secure"
)

// Config is every setting. Each one can be given as a command-line flag (`flag` tag, with the prefixes of the
// structs it sits in), an QUISORA_<FLAG> environment variable or a key in the TOML config file (`toml` path); see
// Flags. Precedence: flag, then environment, then config file, then the default.
type Config struct {
	// FileUsed names the configuration file that was read ("" for none); Validate refuses keys in it that are not
	// settings (a misspelt key would otherwise be ignored silently). Set by the command line.
	FileUsed func() string `toml:"-"`

	Server  Server  `toml:"server"`
	UI      UI      `toml:"ui"`
	Storage Storage `toml:"storage"`
	Cluster Cluster `toml:"cluster" flag:"cluster"`
	Tokens  Tokens  `toml:"tokens"`
	Session Session `toml:"session" flag:"session"`
	Mail    Mail    `toml:"mail"`
	Audit   Audit   `toml:"audit" flag:"audit"`
	Limits  Limits  `toml:"limits"`
	Log     Log     `toml:"log" flag:"log"`
}

type Server struct {
	Listen               string   `toml:"listen" flag:"listen" usage:"HTTPS listen address (there is no plain-HTTP listener)"`
	PublicURL            string   `toml:"public_url" flag:"public-url" usage:"Public base URL and OIDC issuer, https://host[:port], identical on every node (default https://localhost:<port>)"`
	DataDir              string   `toml:"data_dir" flag:"data-dir" usage:"Data directory (keys, self-signed certificate, embedded databases)"`
	TLSCert              string   `toml:"tls_cert" flag:"tls-cert" usage:"TLS certificate (PEM); without it a self-signed certificate is generated in <data-dir>/tls"`
	TLSKey               string   `toml:"tls_key" flag:"tls-key" usage:"TLS private key (PEM)"`
	MasterKey            string   `toml:"master_key" flag:"master-key" usage:"Base64 32-byte key sealing secrets at rest (quisora genkey); required and identical on every node in a cluster"`
	TrustProxy           []string `toml:"trust_proxy" flag:"trust-proxy" usage:"Proxies (CIDRs or IPs) whose X-Forwarded-For is honoured"`
	BootstrapAdmin       string   `toml:"bootstrap_admin" flag:"bootstrap-admin" usage:"Email of the first super admin, created by the bootstrap command with the primary organization"`
	AllowPrivateNetworks bool     `toml:"allow_private_networks" flag:"allow-private-networks" usage:"Let outbound calls to admin-supplied URLs (back-channel logout, jwks_uri, providers) reach private addresses"`
	RestoreFrom          string   `toml:"restore_from" flag:"restore-from" usage:"Backup file (quisora backup) loaded at start-up when the store is empty; ignored once it holds data, so it can stay set"`
	ExtraCAFile          string   `toml:"extra_ca_file" flag:"extra-ca-file" usage:"PEM file of extra CA certificates trusted for outbound HTTPS (sign-in providers, client JWKS, back-channel logout), e.g. an internal CA"`
}

type UI struct {
	SiteName     string `toml:"site_name" flag:"site-name" usage:"Product name shown in the UI"`
	DefaultTheme string `toml:"default_theme" flag:"default-theme" usage:"Default theme: light, dark or system"`
	LogoLight    string `toml:"logo_light" flag:"logo-light" usage:"Logo file path or https URL (default: built-in)"`
	LogoDark     string `toml:"logo_dark" flag:"logo-dark" usage:"Dark-theme logo (default: logo-light)"`
	Footer       string `toml:"footer" flag:"footer" usage:"Footer line"`
}

type Storage struct {
	Backend  string   `toml:"backend" flag:"storage" usage:"Storage backend: badgerdb, sqlite, postgres, mysql, mariadb or valkey"`
	BadgerDB BadgerDB `toml:"badgerdb" flag:"badgerdb"`
	SQLite   SQLite   `toml:"sqlite" flag:"sqlite"`
	Postgres SQLDSN   `toml:"postgres" flag:"postgres"`
	MySQL    SQLDSN   `toml:"mysql" flag:"mysql"`
	MariaDB  SQLDSN   `toml:"mariadb" flag:"mariadb"`
	Valkey   Valkey   `toml:"valkey" flag:"valkey"`
}

type BadgerDB struct {
	Path       string `toml:"path" flag:"path" usage:"BadgerDB directory (default <data-dir>/badgerdb)"`
	SyncWrites bool   `toml:"sync_writes" flag:"sync-writes" usage:"Sync every BadgerDB write to disk"`
}

type SQLite struct {
	Path string `toml:"path" flag:"path" usage:"SQLite database file (default <data-dir>/quisora.db)"`
}

type SQLDSN struct {
	DSN          string `toml:"dsn" flag:"dsn" usage:"Database connection string"`
	MaxOpenConns int    `toml:"max_open_conns" flag:"max-open-conns" usage:"Maximum open connections (0 = default)"`
	MaxIdleConns int    `toml:"max_idle_conns" flag:"max-idle-conns" usage:"Maximum idle connections (0 = default)"`
}

type Valkey struct {
	Addrs     []string `toml:"addrs" flag:"addrs" usage:"Valkey server addresses (host:port)"`
	Username  string   `toml:"username" flag:"username" usage:"Valkey username"`
	Password  string   `toml:"password" flag:"password" usage:"Valkey password"`
	DB        int      `toml:"db" flag:"db" usage:"Valkey database number"`
	KeyPrefix string   `toml:"key_prefix" flag:"key-prefix" usage:"Prefix for every Valkey key"`
	TLS       bool     `toml:"tls" flag:"tls" usage:"Connect to Valkey with TLS"`
}

type Cluster struct {
	NodeID    string   `toml:"node_id" flag:"node-id" usage:"Node UUID (default: generated and kept in the data directory)"`
	Bind      string   `toml:"bind" flag:"bind" usage:"Gossip bind address (empty = standalone)"`
	Advertise string   `toml:"advertise" flag:"advertise" usage:"Gossip address advertised to peers"`
	Peers     []string `toml:"peers" flag:"peers" usage:"Gossip addresses of the other nodes"`
	Key       string   `toml:"key" flag:"key" usage:"Base64 32-byte cluster encryption key (quisora genkey), identical on every node"`
	// Size is the number of nodes the cluster is made of, required with cluster.bind. The quorum (size/2+1) is
	// computed from it and never changes while the cluster runs: not when a node leaves, stops or restarts. Changing
	// it is a planned change of the whole cluster (see docs/REPLICATION.md, "Scaling").
	Size int `toml:"size" flag:"size" usage:"With cluster.bind: the number of nodes in the cluster (required; identical on every node; the quorum is size/2+1)"`
	// MinorityGrace bounds how long a node cut off from the majority keeps serving tokens.
	MinorityGrace int `toml:"minority_grace" flag:"minority-grace" usage:"Seconds a node cut off from the majority keeps serving the token, userinfo and introspection endpoints (0: refuse at once)"`
	// StrictDurability makes a durable write of a kind that is not quorum-committed (sessions, refresh grants, links,
	// identities, groups, keys) fail when a majority does not confirm it (undone where possible) instead of standing
	// on this node and reaching the others later. Security-sensitive kinds (users, credentials, clients, providers,
	// organizations, tenants, access, memberships) are always quorum compare-and-swaps.
	StrictDurability bool `toml:"strict_durability" flag:"strict-durability" usage:"With cluster.bind: a durable write of a kind that is not quorum-committed fails when a majority does not confirm it (undone where possible), instead of standing here and replicating later"`
}

type Tokens struct {
	SigningAlg      string `toml:"signing_alg" flag:"signing-alg" usage:"Token signing algorithm: ES256 or EdDSA"`
	AccessTTL       int    `toml:"access_ttl" flag:"access-ttl" usage:"Access token lifetime, seconds"`
	IDTokenTTL      int    `toml:"id_token_ttl" flag:"id-token-ttl" usage:"ID token lifetime, seconds"`
	RefreshTTL      int    `toml:"refresh_ttl" flag:"refresh-ttl" usage:"Refresh token lifetime, seconds"`
	CodeTTL         int    `toml:"code_ttl" flag:"code-ttl" usage:"Authorization code lifetime, seconds"`
	KeyRotationDays int    `toml:"key_rotation_days" flag:"key-rotation-days" usage:"Rotate the signing key this often, days (0 = by hand)"`
	APITokenMaxDays int    `toml:"api_token_max_days" flag:"api-token-max-days" usage:"Longest personal API token lifetime, days (default 365; 0 = may never expire)"`
}

type Session struct {
	TTL  int `toml:"ttl" flag:"ttl" usage:"Browser session lifetime from sign-in, seconds"`
	Idle int `toml:"idle" flag:"idle" usage:"Browser session ends after this long unused, seconds (0 = never)"`
	// UpstreamCheckMinutes is how often the refresh token of an upstream provider is replayed for users with sessions
	// signed in through it (leaver detection: a refusal ends their sessions).
	UpstreamCheckMinutes int `toml:"upstream_check_minutes" flag:"upstream-check-minutes" usage:"Replay upstream providers' refresh tokens this often, minutes, ending the sessions of users the provider no longer accepts (0 = never)"`
}

// Enabled reports whether an SMTP server is configured. Without one nothing is emailed and nothing offers to email:
// administrators share invitation links themselves, and self-service flows that need a mailed link are hidden.
func (m Mail) Enabled() bool { return strings.TrimSpace(m.SMTPHost) != "" }

type Mail struct {
	SMTPHost string `toml:"smtp_host" flag:"smtp-host" usage:"SMTP server host name or IP address (without it, nothing is emailed: administrators share invitation links themselves)"`
	SMTPPort int    `toml:"smtp_port" flag:"smtp-port" usage:"SMTP port"`
	Username string `toml:"username" flag:"smtp-username" usage:"SMTP username"`
	Password string `toml:"password" flag:"smtp-password" usage:"SMTP password"`
	From     string `toml:"from" flag:"smtp-from" usage:"From address, e.g. Identity <no-reply@example.com>"`
	TLS      string `toml:"tls" flag:"smtp-tls" usage:"SMTP TLS: starttls, tls or none"`
}

type Audit struct {
	RetentionDays int  `toml:"retention_days" flag:"retention-days" usage:"Keep audit events this many days (in the database; with gossip, on each node)"`
	Logins        bool `toml:"logins" flag:"logins" usage:"Also audit successful sign-ins"`
	// VictoriaLogs sends audit events to VictoriaLogs instead of the database, and the audit pages read them from
	// there (any node). The base URL; user:password in it is sent as basic authentication.
	VictoriaLogs string `toml:"victorialogs_url" flag:"victorialogs-url" usage:"VictoriaLogs base URL (http://host:9428): audit events go there instead of the database, and the audit pages read them from there"`
}

type Limits struct {
	MaxInFlight     int `toml:"max_in_flight" flag:"max-in-flight" usage:"Concurrent requests per node before 503"`
	LoginPerIPMin   int `toml:"login_per_ip_min" flag:"login-per-ip-min" usage:"Sign-in attempts per organization and IP per minute (0 = no limit)"`
	LockoutAttempts int `toml:"lockout_attempts" flag:"lockout-attempts" usage:"Failed passwords before an account is locked (0 = never locked)"`
	LockoutMinutes  int `toml:"lockout_minutes" flag:"lockout-minutes" usage:"Account lockout duration, minutes"`
	PasswordWorkers int `toml:"password_workers" flag:"password-workers" usage:"Concurrent password hashes (0 = number of CPUs)"`
}

type Log struct {
	Level  string `toml:"level" flag:"level" usage:"Log level: trace, debug, info, warn or error"`
	Format string `toml:"format" flag:"format" usage:"Log format: console or json"`
}

// Default returns the configuration used when nothing is set.
func Default() *Config {
	return &Config{
		Server:  Server{Listen: ":8443", DataDir: "data"},
		Cluster: Cluster{MinorityGrace: 300},
		UI:      UI{SiteName: "Quisora", DefaultTheme: "system"},
		Storage: Storage{Backend: "badgerdb", BadgerDB: BadgerDB{SyncWrites: true}},
		Tokens: Tokens{SigningAlg: "ES256", AccessTTL: 600, IDTokenTTL: 600, RefreshTTL: 30 * 86400, CodeTTL: 60,
			KeyRotationDays: 30, APITokenMaxDays: 365},
		Session: Session{TTL: 7 * 86400, Idle: 86400, UpstreamCheckMinutes: 60},
		Mail:    Mail{SMTPPort: 587, TLS: "starttls"},
		Audit:   Audit{RetentionDays: 7},
		Limits:  Limits{MaxInFlight: 4096, LoginPerIPMin: 300, LockoutAttempts: 10, LockoutMinutes: 15},
		Log:     Log{Level: "info", Format: "console"},
	}
}

// Load reads path (if non-empty) over the defaults, then applies the QUISORA_* environment variables, then validates.
// The command line uses Flags instead (flags, environment and config file, through the cli package); Load serves
// programmatic callers and tests with the same names.
func Load(path string) (*Config, error) {
	c := Default()
	if path != "" {
		if _, err := toml.DecodeFile(path, c); err != nil {
			return nil, fmt.Errorf("config %s: %w", path, err)
		}
	}
	for _, s := range settings(c) {
		val, ok := os.LookupEnv(s.Env)
		if !ok {
			continue
		}
		if err := s.set(val); err != nil {
			return nil, fmt.Errorf("%s: %w", s.Env, err)
		}
	}
	return c, c.Validate()
}

// Validate checks the configuration and fills derived defaults.
func (c *Config) Validate() error {
	var errs []error
	if c.FileUsed != nil {
		if f := c.FileUsed(); f != "" {
			if err := CheckFile(f); err != nil {
				errs = append(errs, err)
			}
		}
	}
	_, port, lerr := net.SplitHostPort(c.Server.Listen)
	if n, err := strconv.Atoi(port); lerr != nil || err != nil || n < 0 || n > 65535 {
		errs = append(errs, fmt.Errorf("server.listen %q must be host:port, such as :8443 or 0.0.0.0:8443", c.Server.Listen))
		port = ""
	}
	if c.Server.PublicURL == "" {
		c.Server.PublicURL = "https://localhost"
		if port != "443" && port != "" {
			c.Server.PublicURL += ":" + port
		}
	}
	for _, p := range c.Server.TrustProxy {
		if _, err := ParseProxy(p); err != nil {
			errs = append(errs, err)
		}
	}
	u, err := url.Parse(c.Server.PublicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") {
		errs = append(errs, errors.New("server.public_url must be https://host[:port] with no path"))
	}
	c.Server.PublicURL = strings.TrimSuffix(c.Server.PublicURL, "/")
	if c.Server.ExtraCAFile != "" {
		if _, err := secure.RootPool(c.Server.ExtraCAFile); err != nil {
			errs = append(errs, err)
		}
	}
	if (c.Server.TLSCert == "") != (c.Server.TLSKey == "") {
		errs = append(errs, errors.New("server.tls_cert and server.tls_key must be set together"))
	}
	if c.Server.MasterKey != "" {
		if k, err := base64.StdEncoding.DecodeString(c.Server.MasterKey); err != nil || len(k) != 32 {
			errs = append(errs, errors.New("server.master_key must be 32 bytes, base64 encoded (quisora genkey)"))
		}
	}
	if c.Cluster.Key != "" {
		if k, err := base64.StdEncoding.DecodeString(c.Cluster.Key); err != nil || len(k) != 32 {
			errs = append(errs, errors.New("cluster.key must be 32 bytes, base64 encoded (quisora genkey)"))
		}
	}
	if c.Cluster.Bind != "" && c.Cluster.Advertise == "" {
		if host, _, err := net.SplitHostPort(c.Cluster.Bind); err == nil && (host == "" || host == "0.0.0.0" || host == "::") {
			errs = append(errs, errors.New("cluster.advertise is required when cluster.bind is a wildcard address"))
		}
	}
	if c.Cluster.NodeID != "" {
		if _, err := uuid.Parse(c.Cluster.NodeID); err != nil {
			errs = append(errs, errors.New("cluster.node_id must be a UUID"))
		}
	}
	if c.Cluster.MinorityGrace < 0 {
		errs = append(errs, errors.New("cluster.minority_grace must be 0 or more seconds"))
	}
	if c.Cluster.Bind != "" && c.Cluster.Size < 2 {
		errs = append(errs, errors.New("cluster.size is required with cluster.bind: the number of nodes in the cluster "+
			"(at least 2, identical on every node)"))
	}
	if c.Cluster.Bind == "" && c.Cluster.Size != 0 {
		errs = append(errs, errors.New("cluster.size applies only with cluster.bind"))
	}
	if c.Cluster.Bind != "" && c.Cluster.Key == "" {
		errs = append(errs, errors.New("cluster.key is required when clustering"))
	}
	if c.Cluster.Bind != "" && c.Server.MasterKey == "" {
		errs = append(errs, errors.New("server.master_key is required when clustering (identical on every node)"))
	}
	switch c.UI.DefaultTheme {
	case "light", "dark", "system":
	default:
		errs = append(errs, errors.New("ui.default_theme must be light, dark or system"))
	}
	switch c.Tokens.SigningAlg {
	case "ES256", "EdDSA":
	default:
		errs = append(errs, errors.New("tokens.signing_alg must be ES256 or EdDSA"))
	}
	switch c.Storage.Backend {
	case "badgerdb":
		if c.Storage.BadgerDB.Path == "" {
			c.Storage.BadgerDB.Path = filepath.Join(c.Server.DataDir, "badgerdb")
		}
	case "sqlite":
		if c.Storage.SQLite.Path == "" {
			c.Storage.SQLite.Path = filepath.Join(c.Server.DataDir, "quisora.db")
		}
	case "postgres":
		if c.Storage.Postgres.DSN == "" {
			errs = append(errs, errors.New("storage.postgres.dsn is required"))
		}
	case "mysql":
		if c.Storage.MySQL.DSN == "" {
			errs = append(errs, errors.New("storage.mysql.dsn is required"))
		}
	case "mariadb":
		if c.Storage.MariaDB.DSN == "" {
			errs = append(errs, errors.New("storage.mariadb.dsn is required"))
		}
	case "valkey":
		if len(c.Storage.Valkey.Addrs) == 0 {
			errs = append(errs, errors.New("storage.valkey.addrs is required"))
		}
	default:
		errs = append(errs, fmt.Errorf("storage.backend %q: must be badgerdb, sqlite, postgres, mysql, mariadb or valkey",
			c.Storage.Backend))
	}
	positive := func(name string, v int) {
		if v <= 0 {
			errs = append(errs, fmt.Errorf("%s must be greater than 0", name))
		}
	}
	nonNegative := func(name string, v int) {
		if v < 0 {
			errs = append(errs, fmt.Errorf("%s must be 0 or more", name))
		}
	}
	positive("tokens.access_ttl", c.Tokens.AccessTTL)
	positive("tokens.id_token_ttl", c.Tokens.IDTokenTTL)
	positive("tokens.refresh_ttl", c.Tokens.RefreshTTL)
	positive("tokens.code_ttl", c.Tokens.CodeTTL)
	positive("session.ttl", c.Session.TTL)
	nonNegative("session.idle", c.Session.Idle)
	nonNegative("session.upstream_check_minutes", c.Session.UpstreamCheckMinutes)
	nonNegative("tokens.key_rotation_days", c.Tokens.KeyRotationDays)
	nonNegative("tokens.api_token_max_days", c.Tokens.APITokenMaxDays)
	positive("audit.retention_days", c.Audit.RetentionDays)
	if v := c.Audit.VictoriaLogs; v != "" {
		if u, err := url.Parse(v); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, fmt.Errorf("audit.victorialogs_url %q must be an http(s) URL such as http://victorialogs:9428", v))
		}
	}
	positive("limits.max_in_flight", c.Limits.MaxInFlight)
	nonNegative("limits.login_per_ip_min", c.Limits.LoginPerIPMin)
	nonNegative("limits.lockout_attempts", c.Limits.LockoutAttempts)
	nonNegative("limits.password_workers", c.Limits.PasswordWorkers)
	if c.Limits.LockoutAttempts > 0 {
		positive("limits.lockout_minutes", c.Limits.LockoutMinutes)
	}
	if c.Tokens.CodeTTL > 600 {
		errs = append(errs, errors.New("tokens.code_ttl must be at most 600 seconds (RFC 6749 §4.1.2)"))
	}
	if c.Mail.Enabled() {
		if c.Mail.SMTPPort <= 0 || c.Mail.SMTPPort > 65535 {
			errs = append(errs, errors.New("mail.smtp_port must be a port number"))
		}
		switch c.Mail.TLS {
		case "starttls", "tls", "none":
		default:
			errs = append(errs, errors.New("mail.tls must be starttls, tls or none"))
		}
		if _, err := mail.ParseAddress(c.Mail.From); c.Mail.From != "" && err != nil { // empty: quisora@<smtp host>
			errs = append(errs, fmt.Errorf("mail.from %q must be an email address, such as Identity <no-reply@example.com>", c.Mail.From))
		}
	}
	switch strings.ToLower(c.Log.Level) {
	case "trace", "debug", "info", "warn", "error":
	default:
		errs = append(errs, errors.New("log.level must be trace, debug, info, warn or error"))
	}
	switch c.Log.Format {
	case "console", "json":
	default:
		errs = append(errs, errors.New("log.format must be console or json"))
	}
	for _, peer := range c.Cluster.Peers {
		if _, _, err := net.SplitHostPort(peer); err != nil {
			errs = append(errs, fmt.Errorf("cluster.peers: %q must be host:port", peer))
		}
	}
	if c.Cluster.Bind != "" {
		if _, _, err := net.SplitHostPort(c.Cluster.Bind); err != nil {
			errs = append(errs, fmt.Errorf("cluster.bind %q must be host:port", c.Cluster.Bind))
		}
		// A gossip node with no peers would be a cluster of one after every restart: ready, writable and leader on
		// its own while the others carry on without it. Every node lists the others (listing itself too is fine).
		others := 0
		for _, p := range c.Cluster.Peers {
			if p != c.Cluster.Bind && p != c.Cluster.Advertise {
				others++
			}
		}
		if others == 0 {
			errs = append(errs, errors.New("cluster.peers must list the other nodes of the cluster (every node lists every other); "+
				"a single node runs without cluster.bind"))
		}
		if c.Cluster.Size >= 2 && others+1 < c.Cluster.Size {
			errs = append(errs, fmt.Errorf("cluster.size is %d but cluster.peers lists only %d other nodes: every node "+
				"lists every other node", c.Cluster.Size, others))
		}
	}
	for _, a := range c.Storage.Valkey.Addrs {
		if _, _, err := net.SplitHostPort(a); err != nil {
			errs = append(errs, fmt.Errorf("storage.valkey.addrs: %q must be host:port", a))
		}
	}
	return errors.Join(errs...)
}

// LocalStorage reports whether the backend lives on this node only (so cluster data replication is needed).
func (c *Config) LocalStorage() bool {
	return c.Storage.Backend == "badgerdb" || c.Storage.Backend == "sqlite"
}

// SharedStorage reports whether the backend is a database server that several nodes can share (PostgreSQL, MySQL,
// MariaDB, Valkey).
func (c *Config) SharedStorage() bool { return !c.LocalStorage() }

// Replicate reports whether nodes replicate their data to each other. Gossip (cluster.bind) means every node has its
// own database, of any backend, and the nodes keep them in step; without gossip, nodes that should form a cluster
// share one database server and nothing is replicated.
func (c *Config) Replicate() bool { return c.Cluster.Bind != "" }

// Issuer returns the OIDC issuer identifier.
func (c *Config) Issuer() string { return c.Server.PublicURL }

func (t Tokens) Access() time.Duration  { return time.Duration(t.AccessTTL) * time.Second }
func (t Tokens) IDToken() time.Duration { return time.Duration(t.IDTokenTTL) * time.Second }
func (t Tokens) Refresh() time.Duration { return time.Duration(t.RefreshTTL) * time.Second }
func (t Tokens) Code() time.Duration    { return time.Duration(t.CodeTTL) * time.Second }

// ParseProxy reads a trust_proxy entry: an IP address or a CIDR range.
func ParseProxy(s string) (netip.Prefix, error) {
	v := strings.TrimSpace(s)
	if !strings.Contains(v, "/") {
		a, err := netip.ParseAddr(v)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("server.trust_proxy %q is not an IP address or CIDR range", s)
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(v)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("server.trust_proxy %q is not an IP address or CIDR range", s)
	}
	return p.Masked(), nil
}

// CheckFile reports keys in the TOML configuration file that are not settings.
func CheckFile(path string) error {
	var c Config
	md, err := toml.DecodeFile(path, &c)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if u := md.Undecoded(); len(u) > 0 {
		keys := make([]string, len(u))
		for i, k := range u {
			keys[i] = k.String()
		}
		return fmt.Errorf("%s: unknown settings: %s", path, strings.Join(keys, ", "))
	}
	return nil
}
