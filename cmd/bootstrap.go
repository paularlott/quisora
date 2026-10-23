package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/paularlott/cli"
	logslog "github.com/paularlott/logger/slog"
	"github.com/paularlott/quisora/internal/app"
	"github.com/paularlott/quisora/internal/config"
)

func bootstrapCmd(cfg *config.Config, flags []cli.Flag) *cli.Command {
	var newCluster bool
	return &cli.Command{
		Name:  "bootstrap",
		Usage: "Set up a new server: create the primary organization and its first administrator",
		Description: "Creates the primary organization (second factor required), its default tenant and a super admin " +
			"with the email address server.bootstrap_admin (default admin@example.com), and prints the admin's " +
			"single-use invitation link (valid 7 days). Run it once, before the first \"quisora serve\": serving never " +
			"creates anything. A second run changes nothing and says so (\"quisora invite\" issues a new link).\n\n" +
			"With a shared database, run it once for the whole cluster. In a gossip cluster (cluster.bind), run it on " +
			"one node of a new cluster, with --new-cluster, before any node starts, on an empty database (one that " +
			"holds data is refused: it already belongs to a cluster); the others copy it. A node joining an existing " +
			"cluster needs nothing: it copies everything. Run there by mistake on an empty database, it changes no " +
			"existing record of the cluster (what it writes is older than anything already there, and never replaces " +
			"a deletion), the node refuses to join a separately set-up cluster, and the invitation link it prints " +
			"opens nothing on the cluster.\n\n" + storeNote,
		Flags: append([]cli.Flag{&cli.BoolFlag{Name: "new-cluster", AssignTo: &newCluster,
			Usage: "With cluster.bind: confirm this node starts a new cluster (never on a node joining an existing one)"}}, flags...),
		Run: func(ctx context.Context, c *cli.Command) error {
			if err := prepare(ctx, cfg); err != nil {
				return err
			}
			if cfg.Cluster.Bind != "" && !newCluster {
				return errors.New("this node is part of a gossip cluster: a node joining an existing cluster copies " +
					"everything and needs no bootstrap. To set up a new cluster, run this on one node with --new-cluster " +
					"before any node starts")
			}
			log := logslog.New(logslog.Config{Level: "error", Format: cfg.Log.Format})
			user, link, err := app.Bootstrap(ctx, cfg, log)
			if err != nil {
				return err
			}
			if link == "" {
				fmt.Fprintln(os.Stderr, "Already set up: nothing was created. \"quisora invite primary <email>\" issues a new invitation link.")
				return nil
			}
			fmt.Fprintf(os.Stderr, "Created the primary organization and its first administrator, %s.\n", user)
			fmt.Fprintln(os.Stderr, "Open this single-use link (valid 7 days) to set a password or create a passkey, then a second factor:")
			fmt.Fprintln(os.Stdout, link)
			return nil
		},
	}
}
