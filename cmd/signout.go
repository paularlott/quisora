package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/paularlott/cli"
	logslog "github.com/paularlott/logger/slog"
	"github.com/paularlott/quisora/internal/app"
	"github.com/paularlott/quisora/internal/config"
	"golang.org/x/term"
)

func signOutCmd(cfg *config.Config, flags []cli.Flag) *cli.Command {
	var org, reason string
	var all, apiTokens, yes bool
	return &cli.Command{
		Name:  "sign-out",
		Usage: "Emergency sign-out: end every session of an organization, or of the whole server, at once",
		Description: "Break glass. Ends every browser session and refresh grant of one organization (--org) or of every " +
			"organization (--all) at once, and with --api-tokens every personal API token too. Applications are then told " +
			"(back-channel logout) and the ended records deleted. Signing in again works at once. The console has the same " +
			"lever (an organization's page, and the system page for the whole server); this command is for when the " +
			"console cannot be used. It is audited, with --reason.\n\n" +
			"Uses the same config file / QUISORA_* environment as serve, and needs the master key. With a shared database " +
			"(postgres, mysql, mariadb) it writes to the database while the servers run: they follow within seconds. " +
			"With a node-local store (BadgerDB, SQLite) it asks the running server at server.public_url (or --server), " +
			"signing the request with the master key; with the server stopped it writes to the store itself. In a gossip " +
			"cluster (cluster.bind) it always asks a running node, which writes it through the cluster like any change: " +
			"the nodes, or a majority of them, must be running. Through a server, the ended records are removed in the " +
			"background.",
		Flags: append([]cli.Flag{
			&cli.StringFlag{Name: "org", AssignTo: &org, Usage: "Name of the organization to sign out"},
			&cli.BoolFlag{Name: "all", AssignTo: &all, Usage: "Sign out every organization"},
			&cli.StringFlag{Name: "reason", AssignTo: &reason, Required: true, Usage: "Why (recorded in the audit log)"},
			&cli.BoolFlag{Name: "api-tokens", AssignTo: &apiTokens, Usage: "End personal API tokens too"},
			&cli.BoolFlag{Name: "yes", AssignTo: &yes, Usage: "Do not ask for confirmation"},
			&cli.StringFlag{Name: "server", Usage: "Ask this running server (https URL) instead of server.public_url"},
			&cli.StringFlag{Name: "ca-file", Usage: "PEM file of extra CA certificates trusted for the server"},
			&cli.BoolFlag{Name: "insecure", Usage: "Do not verify the server's certificate"},
		}, flags...),
		Run: func(ctx context.Context, c *cli.Command) error {
			if (org == "") == !all {
				return errors.New("give exactly one of --org <name> and --all")
			}
			if err := prepare(ctx, cfg); err != nil {
				return err
			}
			what, confirm := "every organization", "everyone"
			if org != "" {
				what, confirm = "organization "+org, org
			}
			if !yes {
				if err := confirmSignOut(what, confirm, apiTokens); err != nil {
					return err
				}
			}
			log := logslog.New(logslog.Config{Level: "error", Format: cfg.Log.Format})
			_, n, remote, err := app.SignOutVia(ctx, cfg, log, c.GetString("server"), c.GetString("ca-file"),
				c.GetBool("insecure"), org, reason, apiTokens)
			if remote {
				fmt.Fprintf(os.Stderr, "Signed out %s through the running server: everything it ended has stopped "+
					"working, and the server removes it in the background.\n", what)
				return nil
			}
			if n.Sessions+n.Grants+n.APITokens > 0 || err == nil {
				fmt.Fprintf(os.Stderr, "Signed out %s: removed %d sessions, %d refresh grants and %d API tokens.\n",
					what, n.Sessions, n.Grants, n.APITokens)
			}
			if err != nil && n.Sessions+n.Grants+n.APITokens > 0 {
				return fmt.Errorf("everything was signed out, but not every ended record could be removed: %w", err)
			}
			return err
		},
	}
}

// confirmSignOut asks on the terminal for the organization's name ("everyone" for the server) to be typed. Without a
// terminal, --yes is required.
func confirmSignOut(what, confirm string, apiTokens bool) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("not a terminal: confirm with --yes")
	}
	also := ""
	if apiTokens {
		also = " and every personal API token"
	}
	fmt.Fprintf(os.Stderr, "This ends every session%s of %s at once. Type %q to confirm: ", also, what, confirm)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if strings.TrimSpace(line) != confirm {
		return errors.New("not confirmed; nothing was changed")
	}
	return nil
}
