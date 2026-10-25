// Package cmd holds the command-line interface.
package cmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/paularlott/cli"
	logpkg "github.com/paularlott/logger"
	logslog "github.com/paularlott/logger/slog"
	"github.com/paularlott/quisora/internal/build"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secrets"
)

// Root returns the root command. Every setting can be given as a flag, an QUISORA_* environment variable or a key in
// the config file (see config.Flags); the config file is --config, or quisora.toml in the current directory,
// ~/.config/quisora or /etc/quisora.
func Root() *cli.Command { return newRoot(config.Default()) }

// newRoot builds the command tree with every setting bound to cfg (which holds the defaults). A configuration reload
// builds a second tree over a scratch configuration and parses it again (reloader).
func newRoot(cfg *config.Config) *cli.Command {
	flags := config.Flags(cfg)
	cfgFile, configFlag := config.NewConfigFile(cfg)
	server := slices.Clip(flags.Server) // full: each command's append(server, ...) gets its own copy
	return &cli.Command{
		Name:        "quisora",
		Version:     build.Version,
		Usage:       "Identity provider",
		Description: "OpenID Connect / OAuth 2 identity provider with SCIM 2.0, passkeys and clustering",
		ConfigFile:  cfgFile,
		Suggestions: true,
		Flags:       append([]cli.Flag{configFlag}, flags.Global...),
		PreRun: func(ctx context.Context, c *cli.Command) (context.Context, error) {
			warnSecretFlags(os.Stderr, cfg, c)
			warnLooseFiles(os.Stderr, cfg, c)
			return ctx, nil
		},
		Commands: []*cli.Command{serveCmd(cfg, server), bootstrapCmd(cfg, flags.For("bootstrap")), forceStartCmd(cfg, server), setPrimaryCmd(cfg, server), signOutCmd(cfg, server), inviteCmd(cfg, server), backupCmd(cfg, server), restoreCmd(cfg, server),
			healthcheckCmd(cfg, server), genkeyCmd()},
	}
}

// warnLooseFiles warns about files holding secrets that other users on the machine can read: the config file, and
// the files the secret stores' credentials are in. Keep them 0600 (or 0400), owned by the user Quisora runs as.
func warnLooseFiles(w io.Writer, cfg *config.Config, c *cli.Command) {
	if runtime.GOOS == "windows" {
		return
	}
	files := []string{cfg.Secrets.Vault.TokenFile, cfg.Secrets.Vault.SecretIDFile,
		cfg.Secrets.OnePassword.ConnectTokenFile, cfg.Secrets.OnePassword.ServiceAccountTokenFile}
	if c.ConfigFile != nil && c.ConfigFile.FileUsed() != "" && secretInFile(cfg, c) {
		files = append(files, c.ConfigFile.FileUsed())
	}
	for _, f := range files {
		if f == "" {
			continue
		}
		if st, err := os.Stat(f); err == nil && st.Mode().Perm()&0o077 != 0 {
			fmt.Fprintf(w, "warning: %s can be read by other users (mode %04o): it holds secrets; chmod 600 it\n",
				f, st.Mode().Perm())
		}
	}
}

// secretInFile reports whether the config file holds a secret itself (not a reference to a secret store).
func secretInFile(cfg *config.Config, c *cli.Command) bool {
	for _, s := range config.Settings(cfg) {
		if s.Secret && c.FlagSource(s.Flag) == cli.SourceConfigFile && !config.IsSecretRef(s.Value()) && s.Value() != "" {
			return true
		}
	}
	return false
}

// prepare reads the secret settings that name a secret store (op:// or vault://, internal/secrets) and validates
// the configuration: what every command that runs against the server does first.
func prepare(ctx context.Context, cfg *config.Config) error {
	if err := secrets.Apply(ctx, cfg); err != nil {
		return fmt.Errorf("secret stores: %w", err)
	}
	return cfg.Validate()
}

// logger builds the process logger from the (validated) configuration.
func logger(cfg *config.Config) logpkg.Logger {
	return logslog.New(logslog.Config{Level: cfg.Log.Level, Format: cfg.Log.Format})
}

func genkeyCmd() *cli.Command {
	return &cli.Command{
		Name:  "genkey",
		Usage: "Print a random 32-byte key (for server.master_key and cluster.key)",
		Run: func(ctx context.Context, c *cli.Command) error {
			b := make([]byte, 32)
			if _, err := rand.Read(b); err != nil {
				return err
			}
			fmt.Println(base64.StdEncoding.EncodeToString(b))
			return nil
		},
	}
}

// warnSecretFlags warns about secrets given as command-line flags: anyone on the machine sees them in the process
// list (ps), and orchestration often logs them. They are accepted (development tasks pass them that way); the config
// file and the environment are the places for them.
func warnSecretFlags(w io.Writer, cfg *config.Config, c *cli.Command) {
	for _, s := range config.Settings(cfg) {
		if !s.Secret || c.FlagSource(s.Flag) != cli.SourceCommandLine {
			continue
		}
		if s.Path == "audit.victorialogs_url" && !strings.Contains(cfg.Audit.VictoriaLogs, "@") {
			continue // a secret only when it carries basic-auth credentials
		}
		fmt.Fprintf(w, "warning: --%s is a secret on the command line, visible to anyone on this machine (ps); "+
			"set %s or %s in the config file instead\n", s.Flag, s.Env, s.Path)
	}
}
