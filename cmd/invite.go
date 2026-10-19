package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/paularlott/cli"
	logslog "github.com/paularlott/logger/slog"
	"github.com/paularlott/quisora/internal/app"
	"github.com/paularlott/quisora/internal/config"
)

func inviteCmd(cfg *config.Config, flags []cli.Flag) *cli.Command {
	return &cli.Command{
		Name:  "invite",
		Usage: "Issue a new invitation link for a user (set a password or create a passkey)",
		Description: "Prints a single-use invitation URL (valid 7 days) for the user with <email> in organization <org> and revokes " +
			"their earlier unused invitations. Use it to bootstrap or recover the first super admin (\"quisora invite " +
			"primary admin@example.com\") or to give a user whose password was removed a way back in.\n\n" +
			"Uses the same config file / QUISORA_* environment as serve and writes to the configured store. With a shared " +
			"database (postgres, mysql, mariadb, valkey) it works while the server runs. With a node-local store " +
			"(BadgerDB, SQLite) stop the server first: BadgerDB cannot be opened by two processes and the command then " +
			"fails with a message saying so.",
		Flags: flags,
		Arguments: []cli.Argument{
			&cli.StringArg{Name: "org", Usage: "Organization name", Required: true},
			&cli.StringArg{Name: "email", Usage: "Email address of the user", Required: true},
		},
		Run: func(ctx context.Context, c *cli.Command) error {
			if err := cfg.Validate(); err != nil {
				return err
			}
			log := logslog.New(logslog.Config{Level: "error", Format: cfg.Log.Format})
			link, expires, err := app.IssueInvite(ctx, cfg, log, c.GetStringArg("org"), c.GetStringArg("email"))
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, link)
			fmt.Fprintf(os.Stderr, "Single-use link, valid until %s.\n", expires.Local().Format("2006-01-02 15:04 MST"))
			return nil
		},
	}
}
