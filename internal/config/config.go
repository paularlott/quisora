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
	"slices"
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
	Metrics Metrics `toml:"metrics" flag:"metrics"`
}

// Metrics configures GET /metrics (Prometheus). It is served only with a token: the counters say how the server is
// used and attacked, which is not for everyone.
type Metrics struct {
	Token string `toml:"token" flag:"token" secret:"true" usage:"Bearer token Prometheus sends to GET /metrics; empty = no metrics endpoint"`
}

type Server struct {
	Listen               string   `toml:"listen" flag:"listen" usage:"HTTPS listen address (there is no plain-HTTP listener)"`
	PublicURL            string   `toml:"public_url" flag:"public-url" usage:"Public base URL and OIDC issuer, https://host[:port], identical on every node (default https://localhost:<port>)"`
	DataDir              string   `toml:"data_dir" flag:"data-dir" usage:"Data directory (keys, self-signed certificate, embedded databases)"`
	TLSCert              string   `toml:"tls_cert" flag:"tls-cert" usage:"TLS certificate (PEM); without it a self-signed certificate is generated in <data-dir>/tls"`
	TLSKey               string   `toml:"tls_key" flag:"tls-key" usage:"TLS private key (PEM)"`
	MasterKey            string   `toml:"master_key" flag:"master-key" secret:"true" usage:"Base64 32-byte key sealing secrets at rest (quisora genkey); required and identical on every node in a cluster"`
	PreviousMasterKeys   []string `toml:"previous_master_keys" flag:"previous-master-keys" secret:"true" usage:"Earlier master keys (base64), during a master key rotation: they only open what they sealed until it is re-sealed with master_key; identical on every node"`
	TrustProxy           []string `toml:"trust_proxy" flag:"trust-proxy" usage:"Proxies (CIDRs or IPs) whose X-Forwarded-For is honoured"`
	BootstrapAdmin       string   `toml:"bootstrap_admin" flag:"bootstrap-admin" usage:"Email of the first super admin, created by the bootstrap command with the primary organization"`
	AllowPrivateNetworks bool     `toml:"allow_private_networks" flag:"allow-private-networks" usage:"Let outbound calls to admin-supplied URLs (back-channel logout, jwks_uri, providers) reach private addresses"`
	RestorePassword      string   `toml:"restore_password" flag:"restore-password" secret:"true" usage:"Password of the server.restore_from backup, when it is encrypted"`
	RestoreFrom          string   `toml:"restore_from" flag:"restore-from" usage:"Backup file (quisora backup) loaded at start-up when the store is empty; ignored once it holds data, so it can stay set"`
	ExtraCAFile          string   `toml:"extra_ca_file" flag:"extra-ca-file" usage:"PEM file of extra CA certificates trusted for outbound HTTPS (sign-in providers, client JWKS, back-channel logout), e.g. an internal CA"`
}

type UI struct {
	SiteName     string `toml:"site_name" flag:"site-name" usage:"Product name shown in the UI"`
	DefaultTheme string `toml:"default_theme" flag:"default-theme" usage:"Default theme: light, dark or system"`
	LogoLight    string `toml:"logo_light" flag:"logo-light" usage:"Logo absolute file path or https URL (default: built-in)"`
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
	// EncryptionKey encrypts the BadgerDB files at rest (AES-256). It is not the master key, and a store is created
	// encrypted or not: an existing store cannot be switched (back up, then restore into a new encrypted one).
	EncryptionKey string `toml:"encryption_key" flag:"encryption-key" secret:"true" usage:"Base64 32-byte key (quisora genkey) encrypting the BadgerDB files at rest; set when the store is created (empty = not encrypted)"`
}

type SQLite struct {
	Path string `toml:"path" flag:"path" usage:"SQLite database file (default <data-dir>/quisora.db)"`
}

type SQLDSN struct {
	DSN          string `toml:"dsn" flag:"dsn" secret:"true" usage:"Database connection string"`
	MaxOpenConns int    `toml:"max_open_conns" flag:"max-open-conns" usage:"Maximum open connections (0 = default)"`
	MaxIdleConns int    `toml:"max_idle_conns" flag:"max-idle-conns" usage:"Maximum idle connections (0 = default)"`
	CAFile       string `toml:"ca_file" flag:"ca-file" usage:"PEM CA certificates the database server's TLS certificate is verified against (a private CA; MySQL/MariaDB: also turns TLS on)"`
}

type Valkey struct {
	Addrs      []string `toml:"addrs" flag:"addrs" usage:"Valkey server addresses (host:port)"`
	Username   string   `toml:"username" flag:"username" usage:"Valkey username"`
	Password   string   `toml:"password" flag:"password" secret:"true" usage:"Valkey password"`
	DB         int      `toml:"db" flag:"db" usage:"Valkey database number"`
	KeyPrefix  string   `toml:"key_prefix" flag:"key-prefix" usage:"Prefix for every Valkey key"`
	TLS        bool     `toml:"tls" flag:"tls" usage:"Connect to Valkey with TLS"`
	CAFile     string   `toml:"ca_file" flag:"ca-file" usage:"PEM CA certificates Valkey's TLS certificate is verified against (a private CA)"`
	ServerName string   `toml:"server_name" flag:"server-name" usage:"Name Valkey's TLS certificate is verified for (default: the address's host)"`
	CertFile   string   `toml:"cert_file" flag:"cert-file" usage:"Client certificate (PEM) for Valkey mutual TLS"`
	KeyFile    string   `toml:"key_file" flag:"key-file" usage:"Client private key (PEM) for Valkey mutual TLS"`
}

type Cluster struct {
	NodeID    string   `toml:"node_id" flag:"node-id" usage:"Node UUID (default: generated and kept in the data directory)"`
	Bind      string   `toml:"bind" flag:"bind" usage:"Gossip bind address (empty = standalone)"`
	Advertise string   `toml:"advertise" flag:"advertise" usage:"Gossip address advertised to peers"`
	Peers     []string `toml:"peers" flag:"peers" usage:"Gossip addresses of the other nodes"`
	Key       string   `toml:"key" flag:"key" secret:"true" usage:"Base64 32-byte cluster encryption key (quisora genkey), identical on every node"`
	// PreviousKeys still decrypt gossip, never encrypt: a cluster key rotation (docs/RUNNING.md). SIGHUP reloads
	// both settings.
	PreviousKeys []string `toml:"previous_keys" flag:"previous-keys" secret:"true" usage:"Earlier cluster keys (base64), during a cluster key rotation: they still decrypt gossip, never encrypt"`
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
	// Notify links nodes that share one database server by a gossip network of their own that carries only change
	// notices (no data): each node's caches and live admin pages then follow the others' changes within moments.
	// Ignored, with a warning, when cluster.bind is set (replication delivers the changes already).
	Notify Notify `toml:"notify" flag:"notify"`
}

// Notify is the change-notice gossip of nodes sharing one database (cluster.notify).
type Notify struct {
	Bind      string   `toml:"bind" flag:"bind" usage:"Shared database: gossip bind address for change notices between the nodes (empty: none; caches then follow other nodes' changes within 5 seconds)"`
	Advertise string   `toml:"advertise" flag:"advertise" usage:"Shared database: notice gossip address advertised to the other nodes"`
	Peers     []string `toml:"peers" flag:"peers" usage:"Shared database: notice gossip addresses of the other nodes"`
	Key       string   `toml:"key" flag:"key" secret:"true" usage:"Shared database: base64 32-byte key for the notice gossip (quisora genkey), identical on every node"`
}

type Tokens struct {
	SigningAlg      string `toml:"signing_alg" flag:"signing-alg" usage:"Token signing algorithm: ES256 or EdDSA"`
	AccessTTL       int    `toml:"access_ttl" flag:"access-ttl" usage:"Access token lifetime, seconds"`
	IDTokenTTL      int    `toml:"id_token_ttl" flag:"id-token-ttl" usage:"ID token lifetime, seconds"`
	RefreshTTL      int    `toml:"refresh_ttl" flag:"refresh-ttl" usage:"Refresh token lifetime, seconds"`
	CodeTTL         int    `toml:"code_ttl" flag:"code-ttl" usage:"Authorization code lifetime, seconds"`
	KeyRotationDays int    `toml:"key_rotation_days" flag:"key-rotation-days" usage:"Rotate the signing key this often, days (0 = by hand)"`
	APITokenMaxDays int    `toml:"api_token_max_days" flag:"api-token-max-days" usage:"Longest personal API token lifetime, days (default 0: no limit, a token may never expire)"`
}

type Session struct {
	TTL  int `toml:"ttl" flag:"ttl" usage:"Browser session lifetime from sign-in, seconds"`
	Idle int `toml:"idle" flag:"idle" usage:"Browser session ends after this long unused, seconds (0 = never)"`
	// TTL and Idle are also the most an organization may set. Managers and above (who can change other people's
	// access) get shorter sessions still: PrivilegedTTL and PrivilegedIdle, when shorter.
	PrivilegedTTL  int `toml:"privileged_ttl" flag:"privileged-ttl" usage:"Browser session lifetime for managers and above, seconds (0 = as everyone)"`
	PrivilegedIdle int `toml:"privileged_idle" flag:"privileged-idle" usage:"Idle timeout for managers and above, seconds (0 = as everyone)"`
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
	Password string `toml:"password" flag:"smtp-password" secret:"true" usage:"SMTP password"`
	From     string `toml:"from" flag:"smtp-from" usage:"From address, e.g. Identity <no-reply@example.com>"`
	TLS      string `toml:"tls" flag:"smtp-tls" usage:"SMTP TLS: starttls, tls or none"`
}

type Audit struct {
	RetentionDays int  `toml:"retention_days" flag:"retention-days" usage:"Keep audit events this many days (in the database; with gossip, on each node)"`
	Logins        bool `toml:"logins" flag:"logins" usage:"Also audit successful sign-ins (default on; failures are always audited)"`
	Tokens        bool `toml:"tokens" flag:"tokens" usage:"Also audit every refresh and client_credentials token issued (new grants, revocations and token reuse are always audited)"`
	// VictoriaLogs sends audit events to VictoriaLogs instead of the database, and the audit pages read them from
	// there (any node). The base URL; user:password in it is sent as basic authentication.
	VictoriaLogs string `toml:"victorialogs_url" flag:"victorialogs-url" secret:"true" usage:"VictoriaLogs base URL (http://host:9428): audit events go there instead of the database, and the audit pages read them from there"`
	// SpoolDir keeps audit events VictoriaLogs does not take (unreachable, refusing) on disk until it does, at most
	// SpoolMaxMB; without it they are retried briefly and then dropped. One directory per node.
	SpoolDir   string `toml:"victorialogs_spool_dir" flag:"victorialogs-spool-dir" usage:"Directory that keeps audit events VictoriaLogs does not take until it does (one per node; empty = no spool: they are retried briefly, then dropped)"`
	SpoolMaxMB int    `toml:"victorialogs_spool_max_mb" flag:"victorialogs-spool-max-mb" usage:"Most disk space the VictoriaLogs spool may use, in megabytes; past it the oldest events are dropped"`
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
	// Access logs every HTTP request (method, path without its query string, status, duration, size, client address,
	// request id). Query strings are never logged: they carry codes, states and link tokens.
	Access bool `toml:"access" flag:"access" usage:"Log every HTTP request (never its query string)"`
}

// Default returns the configuration used when nothing is set.
func Default() *Config {
	return &Config{
		Server:  Server{Listen: ":8443", DataDir: "data"},
		Cluster: Cluster{MinorityGrace: 300},
		UI:      UI{SiteName: "Quisora", DefaultTheme: "system"},
		Storage: Storage{Backend: "badgerdb", BadgerDB: BadgerDB{SyncWrites: true}},
		Tokens: Tokens{SigningAlg: "ES256", AccessTTL: 600, IDTokenTTL: 600, RefreshTTL: 30 * 86400, CodeTTL: 60,
			KeyRotationDays: 30, APITokenMaxDays: 0},
		Session: Session{TTL: 7 * 86400, Idle: 86400, PrivilegedTTL: 12 * 3600, PrivilegedIdle: 3600, UpstreamCheckMinutes: 60},
		Mail:    Mail{SMTPPort: 587, TLS: "starttls"},
		Audit:   Audit{RetentionDays: 7, Logins: true, SpoolMaxMB: 256},
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

// masterKeyErrors checks server.master_key and server.previous_master_keys.
func masterKeyErrors(master string, previous []string) []error {
	var errs []error
	if master != "" {
		if k, err := base64.StdEncoding.DecodeString(master); err != nil || len(k) != 32 {
			errs = append(errs, errors.New("server.master_key must be 32 bytes, base64 encoded (quisora genkey)"))
		}
	}
	for i, v := range previous {
		if k, err := base64.StdEncoding.DecodeString(v); err != nil || len(k) != 32 {
			errs = append(errs, fmt.Errorf("server.previous_master_keys[%d] must be 32 bytes, base64 encoded", i))
		} else if v == master {
			errs = append(errs, fmt.Errorf("server.previous_master_keys[%d] is server.master_key itself", i))
		}
	}
	if len(previous) > 0 && master == "" {
		errs = append(errs, errors.New("server.previous_master_keys needs server.master_key (rotating the generated "+
			"data_dir/master.key: set its value as a previous key and a new one as server.master_key)"))
	}
	return errs
}

// LoadMasterKeys reads server.master_key and server.previous_master_keys again, for a running server reloading its
// master keys (SIGHUP): from the config file path (if non-empty), then the QUISORA_* environment variables, as at
// start-up; nothing else is read or checked. (Values given on the command line cannot change while it runs.)
func LoadMasterKeys(path string) (master string, previous []string, err error) {
	c, err := reload(path, "server.master_key", "server.previous_master_keys")
	if err != nil {
		return "", nil, err
	}
	if errs := masterKeyErrors(c.Server.MasterKey, c.Server.PreviousMasterKeys); len(errs) > 0 {
		return "", nil, errors.Join(errs...)
	}
	return c.Server.MasterKey, c.Server.PreviousMasterKeys, nil
}

// LoadClusterKeys reads cluster.key and cluster.previous_keys again (SIGHUP), as LoadMasterKeys does the master keys.
func LoadClusterKeys(path string) (key string, previous []string, err error) {
	c, err := reload(path, "cluster.key", "cluster.previous_keys")
	if err != nil {
		return "", nil, err
	}
	if c.Cluster.Key == "" {
		return "", nil, errors.New("cluster.key is not set")
	}
	if errs := clusterKeyErrors(c.Cluster.Key, c.Cluster.PreviousKeys); len(errs) > 0 {
		return "", nil, errors.Join(errs...)
	}
	return c.Cluster.Key, c.Cluster.PreviousKeys, nil
}

// reload reads the settings at paths from the config file path (if non-empty), then the QUISORA_* environment
// variables, over the defaults; nothing else is read or checked.
func reload(path string, paths ...string) (*Config, error) {
	c := Default()
	if path != "" {
		if _, err := toml.DecodeFile(path, c); err != nil {
			return nil, fmt.Errorf("config %s: %w", path, err)
		}
	}
	for _, st := range settings(c) {
		if !slices.Contains(paths, st.Path) {
			continue
		}
		if val, ok := os.LookupEnv(st.Env); ok {
			if err := st.set(val); err != nil {
				return nil, fmt.Errorf("%s: %w", st.Env, err)
			}
		}
	}
	return c, nil
}

func clusterKeyErrors(key string, previous []string) []error {
	var errs []error
	if key != "" {
		if k, err := base64.StdEncoding.DecodeString(key); err != nil || len(k) != 32 {
			errs = append(errs, errors.New("cluster.key must be 32 bytes, base64 encoded (quisora genkey)"))
		}
	}
	for i, v := range previous {
		if k, err := base64.StdEncoding.DecodeString(v); err != nil || len(k) != 32 {
			errs = append(errs, fmt.Errorf("cluster.previous_keys[%d] must be 32 bytes, base64 encoded", i))
		} else if v == key {
			errs = append(errs, fmt.Errorf("cluster.previous_keys[%d] is cluster.key itself", i))
		}
	}
	if len(previous) > 0 && key == "" {
		errs = append(errs, errors.New("cluster.previous_keys needs cluster.key"))
	}
	return errs
}

// keyErrors checks a 32-byte base64 key setting.
func keyErrors(name, key string) []error {
	if k, err := base64.StdEncoding.DecodeString(key); err != nil || len(k) != 32 {
		return []error{errors.New(name + " must be 32 bytes, base64 encoded (quisora genkey)")}
	}
	return nil
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
	errs = append(errs, masterKeyErrors(c.Server.MasterKey, c.Server.PreviousMasterKeys)...)
	if v := c.Storage.BadgerDB.EncryptionKey; v != "" {
		if k, err := base64.StdEncoding.DecodeString(v); err != nil || len(k) != 32 {
			errs = append(errs, errors.New("storage.badgerdb.encryption_key must be 32 bytes, base64 encoded (quisora genkey)"))
		}
	}
	errs = append(errs, clusterKeyErrors(c.Cluster.Key, c.Cluster.PreviousKeys)...)
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
	if n := c.Cluster.Notify; n.Bind != "" && c.Cluster.Bind == "" {
		if c.LocalStorage() {
			errs = append(errs, errors.New("cluster.notify is for nodes that share one database server: "+c.Storage.Backend+
				" is this node's own (several nodes with their own databases use cluster.bind)"))
		}
		if n.Key == "" {
			errs = append(errs, errors.New("cluster.notify.key is required with cluster.notify.bind"))
		} else {
			errs = append(errs, keyErrors("cluster.notify.key", n.Key)...)
		}
		if _, _, err := net.SplitHostPort(n.Bind); err != nil {
			errs = append(errs, fmt.Errorf("cluster.notify.bind %q must be host:port", n.Bind))
		} else if host, _, _ := net.SplitHostPort(n.Bind); n.Advertise == "" && (host == "" || host == "0.0.0.0" || host == "::") {
			errs = append(errs, errors.New("cluster.notify.advertise is required when cluster.notify.bind is a wildcard address"))
		}
		others := 0
		for _, p := range n.Peers {
			if _, _, err := net.SplitHostPort(p); err != nil {
				errs = append(errs, fmt.Errorf("cluster.notify.peers: %q must be host:port", p))
			} else if p != n.Bind && p != n.Advertise {
				others++
			}
		}
		if others == 0 {
			errs = append(errs, errors.New("cluster.notify.peers must list the other nodes sharing the database"))
		}
	}
	if c.Cluster.Bind != "" && c.Server.MasterKey == "" {
		errs = append(errs, errors.New("server.master_key is required when clustering (identical on every node)"))
	}
	switch c.UI.DefaultTheme {
	case "light", "dark", "system":
	default:
		errs = append(errs, errors.New("ui.default_theme must be light, dark or system"))
	}
	for _, l := range [][2]string{{"ui.logo_light", c.UI.LogoLight}, {"ui.logo_dark", c.UI.LogoDark}} {
		if err := logoError(l[0], l[1]); err != nil {
			errs = append(errs, err)
		}
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
		if v := c.Storage.Valkey; !v.TLS && (v.CAFile != "" || v.ServerName != "" || v.CertFile != "" || v.KeyFile != "") {
			errs = append(errs, errors.New("storage.valkey: ca_file, server_name, cert_file and key_file apply to TLS "+
				"connections only: set storage.valkey.tls = true (without it the connection is not encrypted)"))
		}
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
	nonNegative("session.privileged_ttl", c.Session.PrivilegedTTL)
	nonNegative("session.privileged_idle", c.Session.PrivilegedIdle)
	nonNegative("session.upstream_check_minutes", c.Session.UpstreamCheckMinutes)
	nonNegative("tokens.key_rotation_days", c.Tokens.KeyRotationDays)
	nonNegative("tokens.api_token_max_days", c.Tokens.APITokenMaxDays)
	positive("audit.retention_days", c.Audit.RetentionDays)
	if v := c.Audit.VictoriaLogs; v != "" {
		if u, err := url.Parse(v); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, fmt.Errorf("audit.victorialogs_url %q must be an http(s) URL such as http://victorialogs:9428", v))
		}
	}
	if c.Audit.SpoolDir != "" && c.Audit.VictoriaLogs == "" {
		errs = append(errs, fmt.Errorf("audit.victorialogs_spool_dir needs audit.victorialogs_url"))
	}
	positive("audit.victorialogs_spool_max_mb", c.Audit.SpoolMaxMB)
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

// logoError checks a logo setting: empty (the built-in logo), an https URL, or an absolute path to a regular file.
// The branding handler serves the file as is, so a directory (which http.ServeFile would list) or a relative path
// (resolved against whatever the working directory is) is refused here rather than at the first request.
func logoError(name, v string) error {
	if v == "" {
		return nil
	}
	if strings.HasPrefix(v, "https://") {
		if u, err := url.Parse(v); err != nil || u.Host == "" || u.User != nil {
			return fmt.Errorf("%s %q must be an https URL such as https://example.com/logo.svg", name, v)
		}
		return nil
	}
	if !filepath.IsAbs(v) {
		return fmt.Errorf("%s %q must be an https URL or an absolute file path", name, v)
	}
	if fi, err := os.Stat(v); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	} else if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s %q is not a regular file", name, v)
	}
	return nil
}

// LocalStoragereports whether the backend lives on this node only (so cluster data replication is needed).
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
