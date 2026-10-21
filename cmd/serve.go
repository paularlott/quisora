package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"github.com/paularlott/cli"
	logpkg "github.com/paularlott/logger"
	"github.com/paularlott/quisora/internal/app"
	"github.com/paularlott/quisora/internal/build"
	"github.com/paularlott/quisora/internal/cluster"
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
			// SIGHUP re-reads the configuration: the master keys and, when clustering, the cluster keys and the
			// cluster size (rotations and resizes without restarts; docs/RUNNING.md). POST /api/cluster/reload does
			// the same on every node at once. Nothing else is reloaded.
			a.Node.SetReloader(reloader(c, a, log))
			hup := make(chan os.Signal, 1)
			signal.Notify(hup, syscall.SIGHUP)
			defer signal.Stop(hup)
			for {
				select {
				case <-ctx.Done():
					log.Info("shutting down")
					a.Close()
					return nil
				case <-hup:
					if r := a.Node.Reload(ctx); r.Error != "" {
						log.Error("configuration not (fully) reloaded", "error", r.Error, "applied", r.Changes)
					}
				}
			}
		},
	}
}

// reloader re-reads the configuration file and environment for a configuration reload (SIGHUP, or a cluster-wide
// reload): server.master_key and server.previous_master_keys, and when clustering cluster.key,
// cluster.previous_keys, cluster.size and cluster.peers. Checking only reads them and asks whether they can be
// applied; applying switches to them, master keys first. Values given on the command line cannot change while the
// server runs and are left alone (the report says so).
func reloader(c *cli.Command, a *app.App, log logpkg.Logger) cluster.Reloader {
	return func(ctx context.Context, apply bool, want int) cluster.ReloadReport {
		file := ""
		if c.ConfigFile != nil {
			file = c.ConfigFile.FileUsed()
		}
		r := cluster.ReloadReport{Size: a.Node.Size()}
		fail := func(what string, err error) cluster.ReloadReport {
			r.Error = what + ": " + err.Error()
			return r
		}
		fixed := func(what string) { r.Changes = append(r.Changes, what+" given on the command line: not reloaded") }

		var master string
		var masterPrev []string
		masterKeys := !onCommandLine(os.Args[1:], "master-key", "previous-master-keys")
		if masterKeys {
			var err error
			if master, masterPrev, err = config.LoadMasterKeys(file); err != nil {
				return fail("master keys", err)
			}
		} else {
			fixed("master keys")
		}
		clustering := a.Cfg.Cluster.Bind != ""
		var key string
		var keyPrev, peers []string
		clusterKeys := clustering && !onCommandLine(os.Args[1:], "cluster-key", "cluster-previous-keys")
		if clusterKeys {
			var err error
			if key, keyPrev, err = config.LoadClusterKeys(file); err != nil {
				return fail("cluster keys", err)
			}
		} else if clustering {
			fixed("cluster keys")
		}
		size := clustering && !onCommandLine(os.Args[1:], "cluster-size", "cluster-peers")
		if size {
			var err error
			if r.Size, peers, err = config.LoadClusterSize(file); err != nil {
				return fail("cluster size", err)
			}
			if err := a.Node.CheckResize(r.Size, peers); err != nil {
				return fail("cluster size", err)
			}
		} else if clustering {
			fixed("cluster size and peers")
		}
		if !apply {
			return r
		}
		if want != 0 && r.Size != want {
			return fail("cluster size", fmt.Errorf("this node's configuration names %d nodes, the others %d", r.Size, want))
		}

		if masterKeys {
			before := a.Svc.Sealer.KeyIDs()
			if err := a.ReloadMasterKeys(ctx, master, masterPrev); err != nil {
				return fail("master keys", err)
			}
			if !slices.Equal(before, a.Svc.Sealer.KeyIDs()) {
				r.Changes = append(r.Changes, "master keys")
			}
		}
		if clusterKeys {
			changed, err := a.Node.SetClusterKeys(key, keyPrev)
			if err != nil {
				return fail("cluster keys", err)
			}
			if changed {
				ids := a.Node.ClusterKeyIDs()
				log.Info("cluster keys reloaded", "key", ids[0], "previous", ids[1:])
				r.Changes = append(r.Changes, "cluster keys")
			}
		}
		if size {
			old := a.Node.Size()
			changed, err := a.Node.Resize(r.Size, peers)
			if err != nil {
				return fail("cluster size", err)
			}
			if changed {
				r.Changes = append(r.Changes, fmt.Sprintf("cluster size %d to %d", old, r.Size))
			}
		}
		log.Info("configuration reloaded", "changed", r.Changes)
		return r
	}
}

// onCommandLine reports whether one of the flags was given in args (--name, -name, with or without =value). The cli
// package does not tell a flag given on the command line from one filled from the config file.
func onCommandLine(args []string, names ...string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		a = strings.TrimLeft(a, "-")
		a, _, _ = strings.Cut(a, "=")
		if slices.Contains(names, a) {
			return true
		}
	}
	return false
}
