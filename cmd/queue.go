package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/paularlott/cli"
	"github.com/paularlott/quisora/internal/app"
	"github.com/paularlott/quisora/internal/config"
)

func queueCmd(cfg *config.Config, flags []cli.Flag) *cli.Command {
	return &cli.Command{
		Name:  "queue",
		Usage: "Manage this node's delivery queues (email, back-channel logout)",
		Commands: []*cli.Command{{
			Name:  "purge-lost",
			Usage: "Remove queued items sealed with a master key that is lost",
			Description: "Queued emails and back-channel logouts are sealed with the master key. An item sealed with a " +
				"key that is no longer configured (neither server.master_key nor server.previous_master_keys) is kept, " +
				"to be delivered once its key is configured again, and while it is kept that key cannot be retired. " +
				"When the key is lost for good, this gives those items up: it removes them and nothing else (every item " +
				"a configured key opens stays queued).\n\n" +
				"Uses the same config file / QUISORA_* environment as serve, and needs the master keys. Run it on the " +
				"node whose queues hold the items, with the node stopped (the queues are in its data directory), then " +
				"start it again.",
			Flags: flags,
			Run: func(ctx context.Context, c *cli.Command) error {
				mail, logout, err := app.PurgeLostQueueItems(cfg)
				if err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "Removed %d email(s) and %d back-channel logout(s) sealed with a lost master key.\n", mail, logout)
				return nil
			},
		}},
	}
}
