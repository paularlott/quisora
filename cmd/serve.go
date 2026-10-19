package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/paularlott/cli"
	"github.com/paularlott/quisora/internal/app"
	"github.com/paularlott/quisora/internal/build"
	"github.com/paularlott/quisora/internal/config"
)

func serveCmd(cfg *config.Config, flags []cli.Flag) *cli.Command {
	return &cli.Command{
		Name:  "serve",
		Usage: "Run the server",
		Description: "With cluster.bind a node whose data may be out of date — it has not synced for longer than the " +
			"tombstone retention allows, or how long is unknown — refuses to start: deletions made meanwhile may be " +
			"gone from the other nodes, and its copies of those records would come back. Start it with an empty " +
			"database (it copies everything from the others), or, if it holds the only or the newest copy (after a " +
			"whole-cluster outage, or the only node with data next to new, empty ones), run \"quisora force-start\" on " +
			"it first and start the others with empty databases. See docs/REPLICATION.md.",
		Flags: flags,
		Run: func(ctx context.Context, c *cli.Command) error {
			if err := cfg.Validate(); err != nil {
				return err
			}
			log := logger(cfg)
			file := "none"
			if c.ConfigFile != nil && c.ConfigFile.FileUsed() != "" {
				file = c.ConfigFile.FileUsed()
			}
			log.Debug("configuration", "config_file", file, "listen", cfg.Server.Listen, "public_url",
				cfg.Server.PublicURL, "data_dir", cfg.Server.DataDir, "storage", cfg.Storage.Backend)
			log.Info("starting", "version", build.Version, "storage", cfg.Storage.Backend)
			ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
			defer stop()
			a, err := app.Start(ctx, cfg, log)
			if err != nil {
				return err
			}
			<-ctx.Done()
			log.Info("shutting down")
			a.Close()
			return nil
		},
	}
}
