package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/paularlott/cli"
	"github.com/paularlott/quisora/internal/cluster"
	"github.com/paularlott/quisora/internal/config"
)

func forceStartCmd(cfg *config.Config, flags []cli.Flag) *cli.Command {
	return &cli.Command{
		Name:  "force-start",
		Usage: "Let this gossip node start once with its data as the cluster's (after an outage, see docs/REPLICATION.md)",
		Description: "A gossip node refuses to start on its data when it may be out of date: it has not synced for " +
			"longer than the tombstone retention allows, or its data is of unknown age. After a whole-cluster " +
			"outage every node does: run this on the node with the newest data, start it, then start the others with " +
			"empty databases so they copy from it.\n\n" +
			"It is also how the only node that still holds data restarts while every other node is new and empty " +
			"(they lost their disks): a node that has joined a cluster does not count empty nodes towards catching " +
			"up, so without it nobody would ever serve.\n\n" +
			"It leaves a file in the data directory that the next start uses and removes: it applies to one start " +
			"only. That start is logged, and written to the primary organization's audit log (action " +
			"cluster.force_start) as soon as the node can write. A forced node that finds a peer serving the " +
			"cluster's data that synced more recently refuses after all. Never run it on a node whose data the " +
			"others already hold — start that one empty instead.",
		Flags: flags,
		Run: func(ctx context.Context, c *cli.Command) error {
			if err := prepare(ctx, cfg); err != nil {
				return err
			}
			if cfg.Cluster.Bind == "" {
				return fmt.Errorf("this node is not part of a gossip cluster (cluster.bind is not set): nothing to force")
			}
			if err := os.MkdirAll(cfg.Server.DataDir, 0o700); err != nil {
				return err
			}
			p := filepath.Join(cfg.Server.DataDir, cluster.ForceStartMarker)
			if err := os.WriteFile(p, []byte("one forced start\n"), 0o600); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "The next start of this node uses its data as the cluster's, once (logged and audited). "+
				"Start it, then start the other nodes with empty databases.")
			return nil
		},
	}
}
