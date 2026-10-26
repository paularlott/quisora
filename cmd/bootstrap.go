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
			"one node of a new cluster, with --new-cluster, on an empty database (one that holds data is refused: it " +
			"already belongs to a cluster). It creates the cluster's data set: its records become the first writes of " +
			"their partitions, under a new identity kept in cluster-state.json. The other nodes start with empty " +
			"databases, before or after it: they wait until a node publishes a data set, then adopt it and copy " +
			"everything. Nothing else creates a data set, so nodes that all start empty wait (\"no data set\") until " +
			"one is bootstrapped. A node that already holds a data set (it took part in a cluster, or adopted one) is " +
			"refused. A node joining an existing cluster needs nothing: it copies everything. Run there by mistake, the " +
			"node holds a data set of its own, which the cluster's nodes ignore (nothing passes between them, either " +
			"way); it refuses to serve, and the invitation link it prints opens nothing: start it again with an empty " +
			"database.\n\n" + storeNote,
		Flags: append([]cli.Flag{&cli.BoolFlag{Name: "new-cluster", AssignTo: &newCluster,
			Usage: "With cluster.bind: confirm this node starts a new cluster (never on a node joining an existing one)"}}, flags...),
		Run: func(ctx context.Context, c *cli.Command) error {
			if err := prepare(ctx, cfg); err != nil {
				return err
			}
			if cfg.Cluster.Bind != "" && !newCluster {
				return errors.New("this node is part of a gossip cluster: a node joining an existing cluster copies " +
					"everything and needs no bootstrap. To set up a new cluster, run this on one node, with an empty " +
					"database, with --new-cluster")
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
