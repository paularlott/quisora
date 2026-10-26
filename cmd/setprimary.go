package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/paularlott/cli"
	logslog "github.com/paularlott/logger/slog"
	"github.com/paularlott/quisora/internal/app"
	"github.com/paularlott/quisora/internal/config"
)

func setPrimaryCmd(cfg *config.Config, flags []cli.Flag) *cli.Command {
	var superAdmin string
	return &cli.Command{
		Name:  "set-primary",
		Usage: "Make another organization the primary one (where super admins belong)",
		Description: "Makes <org> the primary organization. Super admins belong to the primary organization only, so " +
			"the user given with --super-admin (a user of <org>) becomes its super admin, and the previous primary " +
			"organization's super admins become administrators of that organization. The change is audited in both " +
			"organizations. If it was interrupted (a node lost, a store refusing a write) run it again with the same " +
			"arguments: it finishes what is left.\n\n" +
			"Uses the same config file / QUISORA_* environment as serve, and needs the master key. With a shared " +
			"database (postgres, mysql, mariadb) it works while the servers run: they follow within seconds. With a " +
			"node-local store (BadgerDB, SQLite) stop the server first. In a gossip cluster it asks a running node at " +
			"server.public_url (or --server), signing the request with the master key: the data of a gossip cluster is " +
			"changed through its nodes.",
		Flags: append([]cli.Flag{&cli.StringFlag{Name: "super-admin", AssignTo: &superAdmin, Required: true,
			Usage: "Email address of the user of <org> who becomes its super admin"},
			&cli.StringFlag{Name: "server", Usage: "Ask this running server (https URL) instead of server.public_url"},
			&cli.StringFlag{Name: "ca-file", Usage: "PEM file of extra CA certificates trusted for the server"},
			&cli.BoolFlag{Name: "insecure", Usage: "Do not verify the server's certificate"}}, flags...),
		Arguments: []cli.Argument{
			&cli.StringArg{Name: "org", Usage: "Name of the organization to make primary", Required: true},
		},
		Run: func(ctx context.Context, c *cli.Command) error {
			if err := prepare(ctx, cfg); err != nil {
				return err
			}
			log := logslog.New(logslog.Config{Level: "error", Format: cfg.Log.Format})
			org := c.GetStringArg("org")
			previous, demoted, err := app.SetPrimaryVia(ctx, cfg, log, c.GetString("server"), c.GetString("ca-file"),
				c.GetBool("insecure"), org, superAdmin)
			if err != nil {
				return err
			}
			if previous == "" {
				fmt.Fprintf(os.Stderr, "%s is now the primary organization (an interrupted change finished); %s is its super admin.\n", org, superAdmin)
			} else {
				fmt.Fprintf(os.Stderr, "%s is now the primary organization (it was %s); %s is its super admin.\n", org, previous, superAdmin)
			}
			if len(demoted) > 0 {
				fmt.Fprintf(os.Stderr, "Now administrators instead of super admins: %s\n", strings.Join(demoted, ", "))
			}
			return nil
		},
	}
}
