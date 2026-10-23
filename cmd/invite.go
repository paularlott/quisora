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
			"--break-glass is for getting back into a server nobody can sign in to: the invitation (valid 24 hours) works " +
			"even for a disabled account, such as a super admin that was locked out, and enables it again when used.\n\n" +
			"Uses the same config file / QUISORA_* environment as serve, and needs the master key. The servers keep " +
			"running: with a node's own store (BadgerDB, SQLite, or any database of a gossip cluster) the command asks " +
			"the running server at server.public_url (or --server), signing the request with the master key; when no " +
			"server answers, or with a shared database, it writes to the store itself.",
		Flags: append(flags,
			&cli.BoolFlag{Name: "break-glass", Usage: "Recover access: the invitation also works for a disabled account, and enables it"},
			&cli.StringFlag{Name: "server", Usage: "Ask this running server (https URL) instead of server.public_url"},
			&cli.StringFlag{Name: "ca-file", Usage: "PEM file of extra CA certificates trusted for the server"},
			&cli.BoolFlag{Name: "insecure", Usage: "Do not verify the server's certificate"},
		),
		Arguments: []cli.Argument{
			&cli.StringArg{Name: "org", Usage: "Organization name", Required: true},
			&cli.StringArg{Name: "email", Usage: "Email address of the user", Required: true},
		},
		Run: func(ctx context.Context, c *cli.Command) error {
			if err := prepare(ctx, cfg); err != nil {
				return err
			}
			log := logslog.New(logslog.Config{Level: "error", Format: cfg.Log.Format})
			link, expires, how, err := app.Invite(ctx, cfg, log, c.GetString("server"), c.GetString("ca-file"),
				c.GetBool("insecure"), c.GetStringArg("org"), c.GetStringArg("email"), c.GetBool("break-glass"))
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, link)
			fmt.Fprintf(os.Stderr, "Single-use link, valid until %s (issued by %s).\n",
				expires.Local().Format("2006-01-02 15:04 MST"), how)
			return nil
		},
	}
}
