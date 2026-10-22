// loadtest is a development tool, not part of the quisora binary: it seeds a store with a large synthetic dataset and
// drives HTTP load against a running server.
//
//	go build -o bin/loadtest ./tools/loadtest
//	QUISORA_LOADTEST=1 bin/loadtest -c quisora.toml seed --orgs 100
//	bin/loadtest run --url https://localhost:8443 --insecure --scenario refresh
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/paularlott/cli"
	"github.com/paularlott/quisora/internal/app"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/loadtest"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store"
)

func main() {
	cfg := config.Default()
	flags := config.Flags(cfg)
	cfgFile, configFlag := config.NewConfigFile(cfg) // the server's, read by seed
	cmd := &cli.Command{
		Name:        "loadtest",
		Usage:       "Seed a large synthetic dataset and drive load against a server (development only)",
		ConfigFile:  cfgFile,
		Suggestions: true,
		Flags:       append([]cli.Flag{configFlag}, flags.Global...),
		Commands:    []*cli.Command{seedCmd(cfg, flags.Server), runCmd()},
	}
	if err := cmd.Execute(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func seedCmd(cfg *config.Config, serverFlags []cli.Flag) *cli.Command {
	d := loadtest.DefaultSeedOptions()
	return &cli.Command{
		Name:  "seed",
		Usage: "Write orgs, users, groups, clients and refresh grants straight into the configured store",
		Description: "Takes the same settings as serve (flags, QUISORA_* environment, config file). The server must not be " +
			"running on a node-local store (BadgerDB, SQLite). Safe to repeat: organizations that exist are skipped.",
		Flags: append([]cli.Flag{
			&cli.IntFlag{Name: "orgs", DefaultValue: d.Orgs, Usage: "Organizations (org-00001 ...)"},
			&cli.IntFlag{Name: "users", DefaultValue: d.Users, Usage: "Users per organization"},
			&cli.IntFlag{Name: "groups", DefaultValue: d.Groups, Usage: "Groups per organization"},
			&cli.IntFlag{Name: "clients", DefaultValue: d.Clients, Usage: "OAuth clients per organization (2nd is client_credentials)"},
			&cli.IntFlag{Name: "member-pct", DefaultValue: d.MemberPct, Usage: "Percent of users that belong to one group"},
			&cli.IntFlag{Name: "grants", DefaultValue: d.Grants, Usage: "Refresh-token grants to create for the refresh scenarios"},
			&cli.IntFlag{Name: "sample", DefaultValue: d.Sample, Usage: "Organizations whose client credentials go into the data file"},
			&cli.IntFlag{Name: "workers", DefaultValue: d.Workers, Usage: "Parallel writers"},
			&cli.StringFlag{Name: "password", DefaultValue: d.Password, Usage: "Password of every seeded user"},
			&cli.StringFlag{Name: "data", DefaultValue: d.DataFile, Usage: "Output file for the run step"},
		}, serverFlags...),
		Run: func(ctx context.Context, c *cli.Command) error {
			// Seeding bypasses the audit log and writes thousands of accounts with one shared password: never by
			// accident against a production configuration.
			if os.Getenv("QUISORA_LOADTEST") != "1" {
				return errors.New("seed writes test data straight into the configured store; " +
					"set QUISORA_LOADTEST=1 to confirm this is a test system")
			}
			o := loadtest.SeedOptions{Orgs: c.GetInt("orgs"), Users: c.GetInt("users"), Groups: c.GetInt("groups"),
				Clients: c.GetInt("clients"), MemberPct: c.GetInt("member-pct"), Grants: c.GetInt("grants"),
				Sample: c.GetInt("sample"), Workers: c.GetInt("workers"), Password: c.GetString("password"),
				DataFile: c.GetString("data")}
			if err := o.Validate(); err != nil {
				return err
			}
			if err := cfg.Validate(); err != nil {
				return err
			}
			if err := os.MkdirAll(cfg.Server.DataDir, 0o700); err != nil {
				return err
			}
			for _, p := range []*config.SQLDSN{&cfg.Storage.Postgres, &cfg.Storage.MySQL, &cfg.Storage.MariaDB} {
				if p.MaxOpenConns == 0 {
					p.MaxOpenConns = o.Workers + 8
					p.MaxIdleConns = o.Workers + 8
				}
			}
			ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
			defer stop()
			key, err := masterKey(cfg)
			if err != nil {
				return err
			}
			sealer, err := secure.NewSealer(key)
			if err != nil {
				return err
			}
			st, err := app.OpenStore(ctx, cfg)
			if err != nil {
				return fmt.Errorf("storage: %w", err)
			}
			defer st.Close()
			store.SetOrigin("loadtest-seed")
			svc := service.New(cfg, st, sealer)
			_, err = loadtest.Seed(ctx, svc, o, os.Stdout)
			return err
		},
	}
}

// masterKey mirrors the server: the configured key (server.master_key), never one kept in the data directory.
func masterKey(c *config.Config) ([]byte, error) {
	if c.Server.MasterKey == "" {
		return nil, errors.New("server.master_key is not set: use the key the server is given (QUISORA_MASTER_KEY or --master-key)")
	}
	return base64.StdEncoding.DecodeString(c.Server.MasterKey)
}

func runCmd() *cli.Command {
	d := loadtest.DefaultRunOptions()
	return &cli.Command{
		Name:  "run",
		Usage: "HTTP load generator (HTTP/2, keep-alive) with a latency histogram",
		Description: "Scenarios: " + strings.Join(loadtest.Scenarios, ", ") +
			". --url may be repeated (or comma separated); requests are spread round-robin across the URLs.",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{Name: "url", Usage: "Server base URL, e.g. https://localhost:8443 (repeatable)"},
			&cli.StringFlag{Name: "scenario", DefaultValue: d.Scenario, Usage: strings.Join(loadtest.Scenarios, " | ")},
			&cli.IntFlag{Name: "concurrency", DefaultValue: d.Concurrency, Usage: "Concurrent workers"},
			&cli.StringFlag{Name: "duration", DefaultValue: d.Duration.String(), Usage: "Measured run time"},
			&cli.StringFlag{Name: "warmup", DefaultValue: "0s", Usage: "Run this long first without recording"},
			&cli.BoolFlag{Name: "insecure", Usage: "Do not verify the server certificate"},
			&cli.StringFlag{Name: "data", DefaultValue: d.DataFile, Usage: "Data file written by seed"},
			&cli.IntFlag{Name: "conns", Usage: "HTTP connections per URL (default concurrency/32)"},
			&cli.BoolFlag{Name: "http1", Usage: "Use HTTP/1.1 instead of HTTP/2"},
			&cli.StringFlag{Name: "json", Usage: "Append the report as a JSON line to this file"},
			&cli.StringFlag{Name: "label", Usage: "Free text stored in the JSON report"},
		},
		Run: func(ctx context.Context, c *cli.Command) error {
			urls, err := loadtest.ParseURLs(c.GetStringSlice("url"))
			if err != nil {
				return err
			}
			dur, err := time.ParseDuration(c.GetString("duration"))
			if err != nil {
				return fmt.Errorf("--duration: %w", err)
			}
			warm, err := time.ParseDuration(c.GetString("warmup"))
			if err != nil {
				return fmt.Errorf("--warmup: %w", err)
			}
			o := loadtest.RunOptions{URLs: urls, Scenario: c.GetString("scenario"), Concurrency: c.GetInt("concurrency"),
				Duration: dur, Warmup: warm, Insecure: c.GetBool("insecure"), DataFile: c.GetString("data"),
				Conns: c.GetInt("conns"), HTTP1: c.GetBool("http1"), JSONOut: c.GetString("json"), Label: c.GetString("label")}
			if err := o.Validate(); err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
			defer stop()
			rep, err := loadtest.Run(ctx, o)
			if rep != nil {
				rep.Print(os.Stdout)
			}
			return err
		},
	}
}
