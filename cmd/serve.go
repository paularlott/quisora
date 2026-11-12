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
	"github.com/paularlott/quisora/internal/secrets"
	"github.com/paularlott/quisora/internal/service"
)

func serveCmd(cfg *config.Config, flags []cli.Flag) *cli.Command {
	return &cli.Command{
		Name:  "serve",
		Usage: "Run the server",
		Description: "With cluster.bind the node joins the cluster: it copies what it is missing from the other nodes " +
			"(everything, if its database is new or was lost) and takes part once it has. See docs/REPLICATION.md.",
		Flags: flags,
		Run: func(ctx context.Context, c *cli.Command) error {
			if err := prepare(ctx, cfg); err != nil {
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
			// SIGHUP re-reads the configuration: the limits and server.deny_networks (tightened mid-attack without a
			// restart, which would reset every counter), the master keys and, when clustering, the cluster keys and
			// the cluster size (rotations and resizes without restarts; docs/RUNNING.md). POST /api/cluster/reload
			// does the same on every node at once. SIGHUP also loads the TLS certificate again (a renewed certificate
			// is picked up within an hour anyway). Nothing else is reloaded.
			a.Node.SetReloader(reloader(c, a, log))
			hup := make(chan os.Signal, 1)
			signal.Notify(hup, syscall.SIGHUP)
			defer signal.Stop(hup)
			for {
				select {
				case <-ctx.Done():
					stop() // a second Ctrl+C (or SIGTERM) now ends the process at once
					log.Info("shutting down (interrupt again to stop at once)")
					a.Close()
					return nil
				case <-hup:
					_ = a.Server.ReloadCertificate() // logs its own outcome
					r := a.Node.Reload(ctx)
					if r.Error != "" {
						log.Error("configuration not (fully) reloaded", "error", r.Error, "applied", r.Changes)
					}
					auditReload(ctx, a, r)
				}
			}
		},
	}
}

// auditReload records a SIGHUP reload of this node in the primary organization's audit log (config.reload, or
// config.reload.failure when it was refused or stopped), naming the node and what changed, so that nodes whose limits
// or deny list diverged in the middle of an incident can be told apart afterwards. A cluster-wide reload is audited
// once by the console (cluster.reload), with every node's report. Nothing is recorded before the server is set up
// (there is no primary organization to hold it).
func auditReload(ctx context.Context, a *app.App, r cluster.ReloadReport) {
	org, err := a.Svc.PrimaryOrgID(ctx)
	if err != nil {
		return
	}
	action, detail := "config.reload", map[string]string{"node": r.Node, "source": "sighup",
		"changed": strings.Join(r.Changes, "; ")}
	if r.Error != "" {
		action, detail["error"] = "config.reload.failure", r.Error
	}
	a.Svc.Audit(ctx, service.System, org, action, r.Node, detail)
}

// reloadedSecrets are the secret settings a reload applies, read again from their secret store when they name one.
var reloadedSecrets = []string{"server.master_key", "server.previous_master_keys", "cluster.key", "cluster.previous_keys"}

// reloader re-reads the configuration for a configuration reload (SIGHUP, or a cluster-wide reload): it parses the
// command line, the environment and the config file again (read afresh) into a scratch configuration, through a
// second command tree, and takes from it the limits, server.deny_networks, server.master_key and
// server.previous_master_keys, and when clustering cluster.key, cluster.previous_keys, cluster.size and
// cluster.peers. Checking only reads them and asks whether they can be applied; applying switches to them, the
// limits and denied networks first (they cannot fail), then the master keys. A file that does not parse, or any of
// these that is not valid, fails the reload before anything is applied. Values given on the command line cannot
// change while the server runs and are left alone (the report says so for the keys).
func reloader(c *cli.Command, a *app.App, log logpkg.Logger) cluster.Reloader {
	onCommandLine := func(names ...string) bool {
		return slices.ContainsFunc(names, func(n string) bool { return c.FlagSource(n) == cli.SourceCommandLine })
	}
	return func(ctx context.Context, apply bool, want int) cluster.ReloadReport {
		r := cluster.ReloadReport{Size: a.Node.Size()}
		fail := func(what string, err error) cluster.ReloadReport {
			r.Error = what + ": " + err.Error()
			return r
		}
		fixed := func(what string) { r.Changes = append(r.Changes, what+" given on the command line: not reloaded") }
		fresh := config.Default()
		if err := newRoot(fresh).ReloadFlags(); err != nil {
			return fail("configuration", err)
		}
		// Keys that name a secret store are read from it again now: rotating one is an edit there and a reload.
		if err := secrets.Apply(ctx, fresh, reloadedSecrets...); err != nil {
			return fail("secret stores", err)
		}
		limits, err := fresh.CheckedLimits()
		if err != nil {
			return fail("limits", err)
		}
		deny, err := fresh.DeniedNetworks()
		if err != nil {
			return fail("server.deny_networks", err)
		}

		var master string
		var masterPrev []string
		masterKeys := !onCommandLine("master-key", "previous-master-keys")
		if masterKeys {
			var err error
			if master, masterPrev, err = fresh.MasterKeys(); err != nil {
				return fail("master keys", err)
			}
		} else {
			fixed("master keys")
		}
		clustering := a.Cfg.Cluster.Bind != ""
		var key string
		var keyPrev, peers []string
		clusterKeys := clustering && !onCommandLine("cluster-key", "cluster-previous-keys")
		if clusterKeys {
			var err error
			if key, keyPrev, err = fresh.ClusterKeys(); err != nil {
				return fail("cluster keys", err)
			}
		} else if clustering {
			fixed("cluster keys")
		}
		size := clustering && !onCommandLine("cluster-size", "cluster-peers")
		if size {
			var err error
			if r.Size, peers, err = fresh.ClusterSize(); err != nil {
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

		r.Changes = append(r.Changes, a.ApplyLimits(limits, deny)...)
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
