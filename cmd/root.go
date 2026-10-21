// Package cmd holds the command-line interface.
package cmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/paularlott/cli"
	cli_toml "github.com/paularlott/cli/toml"
	logpkg "github.com/paularlott/logger"
	logslog "github.com/paularlott/logger/slog"
	"github.com/paularlott/quisora/internal/build"
	"github.com/paularlott/quisora/internal/config"
)

// configFileName is the file looked for in the search path when --config is not given.
const configFileName = "quisora.toml"

// Root returns the root command. Every setting can be given as a flag, an QUISORA_* environment variable or a key in
// the config file (see config.Flags); the config file is --config, or quisora.toml in the current directory,
// ~/.config/quisora or /etc/quisora.
func Root() *cli.Command { return newRoot(config.Default()) }

// newRoot builds the command tree with every setting bound to cfg (which holds the defaults). A configuration reload
// builds a second tree over a scratch configuration and parses it again (reloader).
func newRoot(cfg *config.Config) *cli.Command {
	configFile := configFileName
	global, server := config.Flags(cfg)
	cfgFile := cli_toml.NewConfigFile(&configFile, func() []string {
		paths := []string{"."}
		if home, err := os.UserHomeDir(); err == nil {
			paths = append(paths, filepath.Join(home, ".config", "quisora"))
		}
		if runtime.GOOS != "windows" {
			paths = append(paths, "/etc/quisora")
		}
		return paths
	})
	cfg.FileUsed = cfgFile.FileUsed
	others := without(server, "bootstrap-admin")
	return &cli.Command{
		Name:        "quisora",
		Version:     build.Version,
		Usage:       "Identity provider",
		Description: "OpenID Connect / OAuth 2 identity provider with SCIM 2.0, passkeys and clustering",
		ConfigFile:  cfgFile,
		Flags: append([]cli.Flag{
			&cli.StringFlag{Name: "config", Aliases: []string{"c"}, AssignTo: &configFile, Global: true,
				Usage:       "Configuration file (TOML)",
				DefaultText: configFileName + " in the current directory, ~/.config/quisora/ or /etc/quisora/",
				EnvVars:     []string{config.EnvPrefix + "CONFIG"}},
		}, global...),
		PreRun: func(ctx context.Context, c *cli.Command) (context.Context, error) {
			warnSecretFlags(os.Stderr, cfg, c)
			return ctx, nil
		},
		Commands: []*cli.Command{serveCmd(cfg, others), bootstrapCmd(cfg, server), forceStartCmd(cfg, others), setPrimaryCmd(cfg, others), signOutCmd(cfg, others), inviteCmd(cfg, others), backupCmd(cfg, others), restoreCmd(cfg, others),
			healthcheckCmd(cfg, others), genkeyCmd()},
	}
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

// without drops the named settings' flags: settings only one command reads (server.bootstrap_admin is read by
// "bootstrap" alone) are not offered by the others.
func without(flags []cli.Flag, names ...string) []cli.Flag {
	out := make([]cli.Flag, 0, len(flags))
next:
	for _, f := range flags {
		if s, ok := f.(*cli.StringFlag); ok {
			for _, n := range names {
				if s.Name == n {
					continue next
				}
			}
		}
		out = append(out, f)
	}
	return out
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
