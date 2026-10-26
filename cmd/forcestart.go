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
		Usage: "Let this gossip node start once by copying its data from the nodes that answer (after losing a disk while another node is down, see docs/REPLICATION.md)",
		Description: "A gossip node whose data was lost (a new disk) or restored copies everything from a majority of the " +
			"other nodes before it takes part. In a cluster of three that needs both of the others. When one of them is " +
			"down as well (two nodes impaired at once) the node can never get that majority, and the cluster cannot " +
			"tell whether the node that is up has every write that was acknowledged: this command is the operator " +
			"accepting that. The next start of this node copies its data from whichever other nodes answer, even just " +
			"one, and a write that only the nodes it could not reach held is lost.\n\n" +
			"It leaves a file in the data directory that the next start uses and removes: it applies to one start " +
			"only. That start is logged, and written to the primary organization's audit log (action " +
			"cluster.force_start) as soon as the node can write. A node whose data is in order needs none of this: " +
			"after any restart, a whole-cluster restart included, nodes catch up among themselves.",
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
			fmt.Fprintln(os.Stderr, "The next start of this node copies its data from the nodes that answer, once (logged "+
				"and audited), even if that is fewer than a majority of the others.")
			return nil
		},
	}
}
