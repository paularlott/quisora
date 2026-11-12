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

	"github.com/google/uuid"
	"github.com/paularlott/cli"
	"github.com/paularlott/quisora/internal/secure"
)

// Config is every setting. Each one can be given as a command-line flag (`flag` tag, with the prefixes of the
// structs it sits in), an QUISORA_<FLAG> environment variable or a key in the TOML config file (`toml` path); see
// Flags. Precedence: flag, then environment, then config file, then the default. The `cmd` tag names the commands that
// offer the flag (serve's alone when there is none; on a struct, for the settings inside it; "*" is every command).
type Config struct {
	// ConfigFile is the configuration file the command line read (nil or no file used: none); Validate refuses keys
	// in it that are not settings (a misspelt key would otherwise be ignored silently). Set by NewConfigFile's caller.
	ConfigFile cli.ConfigFileSource `toml:"-"`

	Server  Server  `toml:"server"`
	UI      UI      `toml:"ui"`
	Storage Storage `toml:"storage" cmd:"serve bootstrap invite sign-out backup restore"`
	Cluster Cluster `toml:"cluster" flag:"cluster" cmd:"serve bootstrap invite sign-out restore force-start"`
	Tokens  Tokens  `toml:"tokens"`
	Session Session `toml:"session" flag:"session"`
	Mail    Mail    `toml:"mail"`
	Audit   Audit   `toml:"audit" flag:"audit"`
	Limits  Limits  `toml:"limits"`
	Log     Log     `toml:"log" flag:"log"`
	Metrics Metrics `toml:"metrics" flag:"metrics"`
	Secrets Secrets `toml:"secrets" cmd:"serve bootstrap invite sign-out backup restore force-start"`
}

// Metrics configures GET /metrics (Prometheus). It is served only with a token: the counters say how the server is
// used and attacked, which is not for everyone.
type Metrics struct {
	Token string `toml:"token" flag:"token" secret:"true" usage:"Bearer token Prometheus sends to GET /metrics; empty = no metrics endpoint"`
}

type Server struct {
	Listen               string   `toml:"listen" flag:"listen" cmd:"serve healthcheck" usage:"HTTPS listen address (there is no plain-HTTP listener)"`
	PublicURL            string   `toml:"public_url" flag:"public-url" cmd:"serve bootstrap invite sign-out" usage:"Public base URL and OIDC issuer, https://host[:port], identical on every node (default https://localhost:<port>)"`
	DataDir              string   `toml:"data_dir" flag:"data-dir" cmd:"serve bootstrap invite sign-out backup restore force-start" usage:"Data directory: everything this node keeps on disk (embedded database, self-signed certificate, audit spool, node id, cluster state)"`
	TLSCert              string   `toml:"tls_cert" flag:"tls-cert" usage:"TLS certificate (PEM); without it a self-signed certificate is generated in <data-dir>/tls"`
	TLSKey               string   `toml:"tls_key" flag:"tls-key" usage:"TLS private key (PEM)"`
	MasterKey            string   `toml:"master_key" flag:"master-key" secret:"true" cmd:"serve bootstrap invite sign-out backup restore" usage:"Base64 32-byte key sealing secrets at rest (quisora genkey); required and identical on every node in a cluster"`
	PreviousMasterKeys   []string `toml:"previous_master_keys" flag:"previous-master-keys" secret:"true" cmd:"serve bootstrap invite sign-out backup restore" usage:"Earlier master keys (base64), during a master key rotation: they only open what they sealed until it is re-sealed with master_key; identical on every node"`
	TrustProxy           []string `toml:"trust_proxy" flag:"trust-proxy" usage:"Proxies (CIDRs or IPs) whose X-Forwarded-For is honoured"`
	BootstrapAdmin       string   `toml:"bootstrap_admin" flag:"bootstrap-admin" cmd:"bootstrap" usage:"Email of the first super admin, created by the bootstrap command with the primary organization"`
	AllowPrivateNetworks bool     `toml:"allow_private_networks" flag:"allow-private-networks" usage:"Let outbound calls to admin-supplied URLs (back-channel logout, jwks_uri, providers) reach every private address (a home lab)"`
	AllowedNetworks      []string `toml:"allowed_networks" flag:"allowed-networks" usage:"Networks (CIDRs or IPs) outbound calls to admin-supplied URLs may reach although private: the internal providers and applications"`
	RestorePassword      string   `toml:"restore_password" flag:"restore-password" secret:"true" usage:"Password of the server.restore_from backup, when it is encrypted"`
	RestoreFrom          string   `toml:"restore_from" flag:"restore-from" usage:"Backup file (quisora backup) loaded at start-up when the store is empty; ignored once it holds data, so it can stay set"`
	ExtraCAFile          string   `toml:"extra_ca_file" flag:"extra-ca-file" cmd:"serve invite sign-out" usage:"PEM file of extra CA certificates trusted for outbound HTTPS (sign-in providers, client JWKS, back-channel logout), e.g. an internal CA"`
	ShutdownDrain        int      `toml:"shutdown_drain" flag:"shutdown-drain" usage:"Seconds /readyz answers 503 before shutting down, when a load balancer has been polling it, so traffic moves to other nodes first (0 = none)"`
	ShutdownTimeout      int      `toml:"shutdown_timeout" flag:"shutdown-timeout" usage:"Seconds requests in flight get to finish at shutdown"`
	DisablePictures      bool     `toml:"disable_pictures" flag:"disable-pictures" usage:"Turn off users' profile pictures in every organization (none stored, served or sent), and the setting that chooses who sets them"`
	DisableMCP           bool     `toml:"disable_mcp" flag:"disable-mcp" usage:"Turn off every organization's own MCP server (AI clients managing users and groups), and the option to switch it on"`
}

type UI struct {
	SiteName     string `toml:"site_name" flag:"site-name" usage:"Product name shown in the UI"`
	DefaultTheme string `toml:"default_theme" flag:"default-theme" usage:"Default theme: light, dark or system"`
	LogoLight    string `toml:"logo_light" flag:"logo-light" usage:"Logo absolute file path or https URL (default: built-in)"`
	LogoDark     string `toml:"logo_dark" flag:"logo-dark" usage:"Dark-theme logo (default: logo-light)"`
	Footer       string `toml:"footer" flag:"footer" usage:"Footer line; may hold links (<a href>) and <strong>, <em>, <small>, <span>, <br>"`
}

type Storage struct {
	Backend  string   `toml:"backend" flag:"storage" usage:"Storage backend: badgerdb, sqlite, postgres, mysql or mariadb"`
	BadgerDB BadgerDB `toml:"badgerdb" flag:"badgerdb"`
	Postgres SQLDSN   `toml:"postgres" flag:"postgres"`
	MySQL    SQLDSN   `toml:"mysql" flag:"mysql"`
	MariaDB  SQLDSN   `toml:"mariadb" flag:"mariadb"`
}

type BadgerDB struct {
	SyncWrites bool `toml:"sync_writes" flag:"sync-writes" usage:"Sync every BadgerDB write to disk"`
	// SyncIntervalMs, with sync_writes off, syncs BadgerDB to disk this often: writes are acknowledged from memory, and a
	// power cut (not a crash of the process) loses up to this long of them. For a single node on a disk whose sync is
	// slow; never for a gossip node, whose acknowledged writes must survive a power cut.
	SyncIntervalMs int `toml:"sync_interval_ms" flag:"sync-interval-ms" usage:"With sync_writes = false, sync BadgerDB to disk this often, in milliseconds (0 = leave it to the operating system); a power cut loses up to this long of acknowledged writes"`
	// EncryptionKey encrypts the BadgerDB files at rest (AES-256). It is not the master key, and a store is created
	// encrypted or not: an existing store cannot be switched (back up, then restore into a new encrypted one).
	EncryptionKey string `toml:"encryption_key" flag:"encryption-key" secret:"true" usage:"Base64 32-byte key (quisora genkey) encrypting the BadgerDB files at rest; set when the store is created (empty = not encrypted)"`
}

type SQLDSN struct {
	DSN          string `toml:"dsn" flag:"dsn" secret:"true" usage:"Database connection string"`
	MaxOpenConns int    `toml:"max_open_conns" flag:"max-open-conns" usage:"Maximum open connections (0 = default)"`
	MaxIdleConns int    `toml:"max_idle_conns" flag:"max-idle-conns" usage:"Maximum idle connections (0 = default)"`
	CAFile       string `toml:"ca_file" flag:"ca-file" usage:"PEM CA certificates the database server's TLS certificate is verified against (a private CA; MySQL/MariaDB: also turns TLS on)"`
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
	// Size is the number of nodes the cluster is made of, required with cluster.bind. The majority (size/2+1) that
	// commits every write is computed from it and does not change when a node leaves, stops or restarts: only when
	// every node's size is changed by one and the configuration reloaded (see docs/REPLICATION.md, "Cluster size").
	Size int `toml:"size" flag:"size" usage:"With cluster.bind: the number of nodes in the cluster (required; identical on every node; the quorum is size/2+1)"`
	// Notify links nodes that share one database server by a gossip network of their own that carries only change
	// notices (no data): each node's caches and live admin pages then follow the others' changes within moments.
	// Ignored, with a warning, when cluster.bind is set (replication delivers the changes already).
	Notify Notify `toml:"notify" flag:"notify" cmd:"serve"`
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
	APITokenMaxDays int    `toml:"api_token_max_days" flag:"api-token-max-days" usage:"Longest personal API token lifetime, days; a token made without a lifetime gets it (0: no limit, a token may never expire)"`
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
	RetentionDays int  `toml:"retention_days" flag:"retention-days" cmd:"serve bootstrap invite sign-out" usage:"Keep audit events this many days (in the database; with gossip, on each node)"`
	Logins        bool `toml:"logins" flag:"logins" usage:"Also audit successful sign-ins (default on; failures are always audited)"`
	Tokens        bool `toml:"tokens" flag:"tokens" usage:"Also audit every refresh and client_credentials token issued (new grants, revocations and token reuse are always audited)"`
	// VictoriaLogs sends audit events to VictoriaLogs instead of the database, and the audit pages read them from
	// there (any node). The base URL; user:password in it is sent as basic authentication.
	VictoriaLogs string `toml:"victorialogs_url" flag:"victorialogs-url" secret:"true" cmd:"serve bootstrap invite sign-out" usage:"VictoriaLogs base URL (http://host:9428): audit events go there instead of the database, and the audit pages read them from there"`
	// Audit events VictoriaLogs does not take (unreachable, refusing) wait in <data-dir>/auditspool until it does, at
	// most SpoolMaxMB.
	SpoolMaxMB int `toml:"victorialogs_spool_max_mb" flag:"victorialogs-spool-max-mb" usage:"Most disk space the VictoriaLogs spool may use, in megabytes; past it the oldest events are dropped"`
}

// Bounds of limits.grants_per_user, and of an organization's own (model.OrgSettings.GrantsPerUser).
const (
	MinGrantsPerUser = 10
	MaxGrantsPerUser = 100000
)

type Limits struct {
	MaxInFlight     int `toml:"max_in_flight" flag:"max-in-flight" usage:"Concurrent requests per node before 503"`
	LoginPerIPMin   int `toml:"login_per_ip_min" flag:"login-per-ip-min" usage:"Sign-in attempts per organization and IP per minute (0 = no limit)"`
	LockoutAttempts int `toml:"lockout_attempts" flag:"lockout-attempts" usage:"Failed passwords before an account is locked (0 = never locked)"`
	LockoutMinutes  int `toml:"lockout_minutes" flag:"lockout-minutes" usage:"Account lockout duration, minutes"`
	PasswordWorkers int `toml:"password_workers" flag:"password-workers" usage:"Concurrent password hashes (0 = number of CPUs); sign-ins waiting for one are served by organization in turn"`
	// PasswordMinLength is the shortest password accepted, in characters. NIST SP 800-63B rev 4 asks for 15 where a
	// password may be the only factor (as here, unless the organization requires a second one), and 8 at least.
	PasswordMinLength int `toml:"password_min_length" flag:"password-min-length" usage:"Shortest password accepted, characters (8 to 64; NIST SP 800-63B: 15 where a password may be the only factor)"`
	// GrantsPerUser is how many refresh grants one user may hold at once (each sign-in of an application makes one);
	// past it the least likely to be missed are ended. An organization may set its own (model.OrgSettings).
	GrantsPerUser int `toml:"grants_per_user" flag:"grants-per-user" usage:"Refresh grants one user may hold, 10 to 100000; past it the oldest unused are ended (an organization may set its own)"`
	EphemeralMB   int `toml:"ephemeral_mb" flag:"ephemeral-mb" usage:"Memory per node for short-lived sign-in state (flows, codes, pushed requests), MiB; past it such requests get 503"`
}

type Log struct {
	Level  string `toml:"level" flag:"level" cmd:"*" usage:"Log level: trace, debug, info, warn or error"`
	Format string `toml:"format" flag:"format" cmd:"*" usage:"Log format: console or json"`
	// Access logs every HTTP request (method, path without its query string, status, duration, size, client address,
	// request id). Query strings are never logged: they carry codes, states and link tokens.
	Access bool `toml:"access" flag:"access" usage:"Log every HTTP request (never its query string)"`
}

// The layout of server.data_dir: everything a node keeps on disk lives under it, so one setting (one volume, one
// backup exclusion, one permission check) covers it all. Each node of a cluster has its own.
const (
	DirBadgerDB   = "badgerdb"   // storage.backend badgerdb
	FileSQLite    = "quisora.db" // storage.backend sqlite
	DirTLS        = "tls"        // the self-signed certificate, when no tls_cert is configured
	DirAuditSpool = "auditspool" // audit events VictoriaLogs has not taken yet
)

// DataPath is name inside server.data_dir.
func (c *Config) DataPath(name ...string) string {
	return filepath.Join(append([]string{c.Server.DataDir}, name...)...)
}

// Default returns the configuration used when nothing is set.
func Default() *Config {
	return &Config{
		Server:  Server{Listen: ":8443", DataDir: "data", ShutdownDrain: 10, ShutdownTimeout: 30},
		UI:      UI{SiteName: "Quisora", DefaultTheme: "system"},
		Storage: Storage{Backend: "badgerdb", BadgerDB: BadgerDB{SyncWrites: true}},
		Tokens: Tokens{SigningAlg: "ES256", AccessTTL: 600, IDTokenTTL: 600, RefreshTTL: 30 * 86400, CodeTTL: 60,
			KeyRotationDays: 30, APITokenMaxDays: 365},
		Session: Session{TTL: 7 * 86400, Idle: 86400, PrivilegedTTL: 12 * 3600, PrivilegedIdle: 3600, UpstreamCheckMinutes: 60},
		Mail:    Mail{SMTPPort: 587, TLS: "starttls"},
		Audit:   Audit{RetentionDays: 90, Logins: true, SpoolMaxMB: 256},
		Limits:  Limits{MaxInFlight: 4096, LoginPerIPMin: 300, LockoutAttempts: 10, LockoutMinutes: 15, EphemeralMB: 1024, PasswordMinLength: 15, GrantsPerUser: 1000},
		Log:     Log{Level: "info", Format: "console", Access: true},
	}
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
		errs = append(errs, errors.New("server.previous_master_keys needs server.master_key (during a rotation the new "+
			"key is server.master_key and the old one a previous key)"))
	}
	return errs
}

// MasterKeys returns server.master_key and server.previous_master_keys, checked, for a running server reloading its
// master keys (SIGHUP): c is a configuration read again for the reload (the command line, the environment and the
// config file, as at start-up); nothing else of it is checked.
func (c *Config) MasterKeys() (master string, previous []string, err error) {
	if errs := masterKeyErrors(c.Server.MasterKey, c.Server.PreviousMasterKeys); len(errs) > 0 {
		return "", nil, errors.Join(errs...)
	}
	return c.Server.MasterKey, c.Server.PreviousMasterKeys, nil
}

// ClusterKeys returns cluster.key and cluster.previous_keys, checked, for a reload, as MasterKeys does the master keys.
func (c *Config) ClusterKeys() (key string, previous []string, err error) {
	if c.Cluster.Key == "" {
		return "", nil, errors.New("cluster.key is not set")
	}
	if errs := clusterKeyErrors(c.Cluster.Key, c.Cluster.PreviousKeys); len(errs) > 0 {
		return "", nil, errors.Join(errs...)
	}
	return c.Cluster.Key, c.Cluster.PreviousKeys, nil
}

// ClusterSize returns cluster.size and cluster.peers for a reload, as MasterKeys does the master keys. Whether the
// running node can change to them is cluster.Node.CheckResize's to say.
func (c *Config) ClusterSize() (size int, peers []string, err error) {
	for _, p := range c.Cluster.Peers {
		if _, _, err := net.SplitHostPort(p); err != nil {
			return 0, nil, fmt.Errorf("cluster.peers: %q must be host:port", p)
		}
	}
	return c.Cluster.Size, c.Cluster.Peers, nil
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
	if c.ConfigFile != nil && c.ConfigFile.FileUsed() != "" {
		if u := c.UnknownKeys(); len(u) > 0 {
			errs = append(errs, fmt.Errorf("%s: unknown settings: %s", c.ConfigFile.FileUsed(), strings.Join(u, ", ")))
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
		if pr, err := ParseProxy(p); err != nil {
			errs = append(errs, err)
		} else if pr.Bits() == 0 {
			// Every client could then name any address in X-Forwarded-For: the per-address limits (sign-in,
			// client authentication, bearer tokens) and the audit log's addresses would be the caller's to choose.
			errs = append(errs, fmt.Errorf("server.trust_proxy %q trusts every address: list your proxies' "+
				"addresses or their network", p))
		}
	}
	for _, s := range c.Server.AllowedNetworks {
		if p, err := parseNetwork("server.allowed_networks", s); err != nil {
			errs = append(errs, err)
		} else if p.Bits() == 0 {
			errs = append(errs, fmt.Errorf("server.allowed_networks %q is every address: list the networks of the "+
				"internal services (server.allow_private_networks allows every private address)", s))
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
	if strings.TrimSpace(c.Server.DataDir) == "" {
		errs = append(errs, errors.New("server.data_dir is required: the directory this node keeps everything on disk in"))
	}
	switch c.Storage.Backend {
	case "badgerdb", "sqlite": // in the data directory (DataPath)
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
	default:
		errs = append(errs, fmt.Errorf("storage.backend %q: must be badgerdb, sqlite, postgres, mysql or mariadb",
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
	if c.Server.ShutdownDrain < 0 {
		errs = append(errs, errors.New("server.shutdown_drain must not be negative"))
	}
	positive("server.shutdown_timeout", c.Server.ShutdownTimeout)
	positive("tokens.access_ttl", c.Tokens.AccessTTL)
	positive("limits.ephemeral_mb", c.Limits.EphemeralMB)
	if n := c.Limits.PasswordMinLength; n < 8 || n > 64 {
		errs = append(errs, fmt.Errorf("limits.password_min_length must be between 8 and 64 (NIST SP 800-63B: at least 8, "+
			"and 15 where a password may be the only factor), not %d", n))
	}
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
	if b := c.Storage.BadgerDB; b.SyncIntervalMs < 0 || b.SyncIntervalMs > 0 && b.SyncWrites {
		errs = append(errs, errors.New("storage.badgerdb.sync_interval_ms must be 0 or more, and is only for sync_writes = false "+
			"(with sync_writes every write is synced)"))
	}
	if v := c.Audit.VictoriaLogs; v != "" {
		if u, err := url.Parse(v); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, fmt.Errorf("audit.victorialogs_url %q must be an http(s) URL such as http://victorialogs:9428", v))
		}
	}
	positive("audit.victorialogs_spool_max_mb", c.Audit.SpoolMaxMB)
	positive("limits.max_in_flight", c.Limits.MaxInFlight)
	nonNegative("limits.login_per_ip_min", c.Limits.LoginPerIPMin)
	nonNegative("limits.lockout_attempts", c.Limits.LockoutAttempts)
	nonNegative("limits.password_workers", c.Limits.PasswordWorkers)
	if c.Limits.GrantsPerUser < MinGrantsPerUser || c.Limits.GrantsPerUser > MaxGrantsPerUser {
		errs = append(errs, fmt.Errorf("limits.grants_per_user must be between %d and %d", MinGrantsPerUser, MaxGrantsPerUser))
	}
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
		if c.Storage.Backend == "badgerdb" && !c.Storage.BadgerDB.SyncWrites {
			// A node's promises and the writes it acknowledges must survive a power cut (docs/REPLICATION.md). (So does
			// sync_interval_ms, which needs sync_writes off.)
			errs = append(errs, errors.New("storage.badgerdb.sync_writes must be true with cluster.bind: a gossip node's "+
				"promises and the writes it acknowledges are lost in a power cut otherwise"))
		}
		if c.Cluster.Size >= 2 && others+1 < c.Cluster.Size {
			errs = append(errs, fmt.Errorf("cluster.size is %d but cluster.peers lists only %d other nodes: every node "+
				"lists every other node", c.Cluster.Size, others))
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
// MariaDB).
func (c *Config) SharedStorage() bool { return !c.LocalStorage() }

// Replicate reports whether nodes replicate their data to each other. Gossip (cluster.bind) means every node has its
// own database, of any backend, and the nodes keep them in step; without gossip, nodes that should form a cluster
// share one database server and nothing is replicated.
func (c *Config) Replicate() bool { return c.Cluster.Bind != "" }

// Issuer returns the OIDC issuer identifier.
// OrgIssuer is the OAuth issuer of an organization: its own, under /o/<id>, so a token of one organization is never
// taken for another's (an API checks the issuer and its audience), and every endpoint of it is the organization's.
func (c *Config) OrgIssuer(orgID string) string { return c.Server.PublicURL + "/o/" + orgID }

// OrgMCP is the address of organization orgID's own MCP server (internal/mcpapi), its resource identifier (RFC 8707):
// what a tenant lists to turn it on, and what AI clients ask tokens for.
func (c *Config) OrgMCP(orgID string) string { return c.OrgIssuer(orgID) + "/mcp" }

// MCPServer reports whether an organization whose settings say on (model.OrgSettings.MCPServer) serves its own MCP
// server: unless server.disable_mcp turns them all off.
func (c *Config) MCPServer(on bool) bool { return on && !c.Server.DisableMCP }

// Endpoints are an organization's OAuth and OpenID Connect addresses: the one list the discovery document publishes
// and the console shows for applications to be configured with.
type Endpoints struct {
	Issuer              string
	Discovery           string // OpenID Connect discovery (issuer + /.well-known/openid-configuration)
	Metadata            string // OAuth authorization server metadata at its RFC 8414 address (MCP clients look there)
	Authorization       string
	Token               string
	PAR                 string // pushed authorization requests (RFC 9126)
	UserInfo            string
	JWKS                string
	Introspection       string
	Revocation          string
	EndSession          string
	DeviceAuthorization string
	DeviceVerification  string // the page a device sign-in's user code is entered on
	Registration        string // dynamic client registration (RFC 7591)
}

// OrgEndpoints returns the endpoints of organization orgID.
func (c *Config) OrgEndpoints(orgID string) Endpoints {
	iss := c.OrgIssuer(orgID)
	return Endpoints{
		Issuer:              iss,
		Discovery:           iss + "/.well-known/openid-configuration",
		Metadata:            c.Server.PublicURL + "/.well-known/oauth-authorization-server/o/" + orgID,
		Authorization:       iss + "/oauth/authorize",
		Token:               iss + "/oauth/token",
		PAR:                 iss + "/oauth/par",
		UserInfo:            iss + "/oauth/userinfo",
		JWKS:                iss + "/oauth/jwks",
		Introspection:       iss + "/oauth/introspect",
		Revocation:          iss + "/oauth/revoke",
		EndSession:          iss + "/oauth/logout",
		DeviceAuthorization: iss + "/oauth/device_authorization",
		DeviceVerification:  iss + "/device",
		Registration:        iss + "/oauth/register",
	}
}

func (t Tokens) Access() time.Duration  { return time.Duration(t.AccessTTL) * time.Second }
func (t Tokens) IDToken() time.Duration { return time.Duration(t.IDTokenTTL) * time.Second }
func (t Tokens) Refresh() time.Duration { return time.Duration(t.RefreshTTL) * time.Second }
func (t Tokens) Code() time.Duration    { return time.Duration(t.CodeTTL) * time.Second }

// ParseProxy reads a trust_proxy entry: an IP address or a CIDR range.
func ParseProxy(s string) (netip.Prefix, error) { return parseNetwork("server.trust_proxy", s) }

// parseNetwork reads an IP address (a network of that one address) or a CIDR range given for setting.
func parseNetwork(setting, s string) (netip.Prefix, error) {
	v := strings.TrimSpace(s)
	if !strings.Contains(v, "/") {
		a, err := netip.ParseAddr(v)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%s %q is not an IP address or CIDR range", setting, s)
		}
		return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
	}
	p, err := netip.ParsePrefix(v)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%s %q is not an IP address or CIDR range", setting, s)
	}
	return p.Masked(), nil
}

// OutboundReach is what outbound calls to admin-supplied URLs may reach besides the public internet
// (secure.OutboundClient): every private address with server.allow_private_networks, and the networks of
// server.allowed_networks (checked by Validate).
func (c *Config) OutboundReach() secure.Reach {
	r := secure.Reach{Private: c.Server.AllowPrivateNetworks}
	for _, s := range c.Server.AllowedNetworks {
		if p, err := parseNetwork("server.allowed_networks", s); err == nil {
			r.Networks = append(r.Networks, p)
		}
	}
	return r
}

// removedSettings are settings that no longer exist, and what to tell an operator whose configuration file still sets
// one: such a file keeps starting (the key is ignored) instead of failing as an unknown setting.
var removedSettings = map[string]string{
	"cluster.minority_grace": "cluster.minority_grace is no longer used and is ignored: a node cut off from the majority " +
		"is simply not ready and refuses what it cannot serve (remove it from the configuration file)",
}

// RemovedSettingWarnings lists a warning for each removed setting the configuration file still sets, sorted.
func (c *Config) RemovedSettingWarnings() []string {
	if c.ConfigFile == nil || c.ConfigFile.FileUsed() == "" {
		return nil
	}
	var w []string
	for path, msg := range removedSettings {
		section, key, _ := strings.Cut(path, ".")
		if slices.Contains(c.ConfigFile.GetKeys(section), key) {
			w = append(w, msg)
		}
	}
	slices.Sort(w)
	return w
}

// MailWarnings lists a warning for a mail setup that sends in clear text: mail carries reset links and one-time codes,
// so mail.tls "none" is warned about unless the SMTP server is on this machine (a loopback address or localhost).
func (c *Config) MailWarnings() []string {
	if !c.Mail.Enabled() || c.Mail.TLS != "none" {
		return nil
	}
	host := strings.TrimSuffix(strings.ToLower(c.Mail.SMTPHost), ".")
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); host == "localhost" || (err == nil && ip.IsLoopback()) {
		return nil
	}
	return []string{"mail.tls is none: reset links and one-time codes cross the network to " + c.Mail.SMTPHost +
		" unencrypted (use starttls or tls)"}
}

// UnknownKeys lists the keys of the configuration file that are not settings, as dotted paths, sorted: walking the
// file the cli package read, every table must be a section of settings and every value a setting. Removed settings
// (removedSettings) are not unknown.
func (c *Config) UnknownKeys() []string {
	known, sections := map[string]bool{}, map[string]bool{}
	for _, st := range settings(c) {
		known[st.Path] = true
		for i := range len(st.Path) {
			if st.Path[i] == '.' {
				sections[st.Path[:i]] = true
			}
		}
	}
	var unknown []string
	var walk func(prefix string)
	walk = func(prefix string) {
		for _, k := range c.ConfigFile.GetKeys(prefix) {
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			switch {
			case known[path], removedSettings[path] != "":
			case sections[path] && c.ConfigFile.GetKeys(path) != nil:
				walk(path)
			default:
				unknown = append(unknown, path)
			}
		}
	}
	walk("")
	slices.Sort(unknown)
	return unknown
}
