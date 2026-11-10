package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/paularlott/cli"
	"github.com/paularlott/quisora/internal/sshcli"
)

// sshCmd is `quisora ssh`: the client of a tenant's SSH certificate authority. It is a plain HTTPS client: none of its
// commands reads the configuration, needs the master key or opens a store (so none calls prepare).
func sshCmd() *cli.Command {
	return &cli.Command{
		Name:  "ssh",
		Usage: "Get SSH certificates from Quisora's certificate authority, and keep a server's trust files current",
		Description: "Quisora signs short-lived OpenSSH user certificates for people who signed in with a second factor, " +
			"and host certificates for servers. The commands take the tenant's discovery URL, shown on the tenant's SSH " +
			"page and in the account page: https://<server>/o/<org id>/ssh/<tenant>.",
		Commands: []*cli.Command{sshLoginCmd(), sshStatusCmd(), sshLogoutCmd(), sshHostSignCmd(), sshFetchCmd()},
	}
}

// sshEnv is the environment of one command: the process's output, and the TLS options.
func sshEnv(c *cli.Command) *sshcli.Env {
	return &sshcli.Env{Out: os.Stdout, Err: os.Stderr, Insecure: c.GetBool("insecure"), CACert: c.GetString("ca-cert")}
}

// sshTLSFlags are the flags every command that talks to the server takes.
func sshTLSFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{Name: "insecure", Usage: "Do not verify the server's certificate (development)"},
		&cli.StringFlag{Name: "ca-cert", Usage: "PEM file of CA certificates trusted for the server"},
	}
}

func sshURLArg() cli.Argument {
	return &cli.StringArg{Name: "url", Usage: "The tenant's discovery URL (https://<server>/o/<org id>/ssh/<tenant>)", Required: true}
}

func sshLoginCmd() *cli.Command {
	return &cli.Command{
		Name:  "login",
		Usage: "Sign in and get a user certificate, added to ssh-agent",
		Description: "Signs in to Quisora (a browser opens; a second factor is required) and gets a certificate for a new key, " +
			"which is added to ssh-agent (SSH_AUTH_SOCK) for as long as the certificate lasts, with the comment " +
			"quisora:<org>/<tenant>; the public key and certificate are also written to " +
			"~/.ssh/quisora/<org>-<tenant>.pub and -cert.pub (for IdentityFile and CertificateFile with IdentitiesOnly yes). " +
			"Without an agent, with --no-agent, when the agent does not take the key (it is locked, or does not accept " +
			"imported keys), and on Windows, the key and certificate are written to ~/.ssh/quisora/<org>-<tenant> instead. " +
			"With --key the certificate is made for that existing key (its .pub) and written to <key>-cert.pub.\n\n" +
			"--device signs in on another device with a code, for a machine without a browser; --no-browser prints the " +
			"URL instead of opening it (the browser must be on this machine).",
		Flags: append([]cli.Flag{
			&cli.BoolFlag{Name: "device", Usage: "Sign in with a code on another device (device flow)"},
			&cli.BoolFlag{Name: "no-browser", Usage: "Print the sign-in URL instead of opening the browser"},
			&cli.BoolFlag{Name: "no-agent", Usage: "Write the key and certificate to ~/.ssh/quisora, do not add them to ssh-agent"},
			&cli.StringFlag{Name: "key", Usage: "Use this key (its .pub) and write <key>-cert.pub, instead of a new key in ssh-agent"},
			&cli.StringSliceFlag{Name: "principal", Usage: "Ask for these principals only (repeatable; default: all the user may have)"},
			&cli.StringFlag{Name: "ttl", Usage: "Ask for a shorter certificate, e.g. 2h (default: the tenant's)"},
		}, sshTLSFlags()...),
		Arguments: []cli.Argument{sshURLArg()},
		Run: func(ctx context.Context, c *cli.Command) error {
			ttl, err := parseTTL(c.GetString("ttl"))
			if err != nil {
				return err
			}
			if c.GetBool("device") && c.GetBool("no-browser") {
				return fmt.Errorf("--no-browser is for the browser sign-in: --device never opens one")
			}
			return sshEnv(c).Login(ctx, sshcli.LoginOptions{URL: c.GetStringArg("url"), Device: c.GetBool("device"),
				NoBrowser: c.GetBool("no-browser"), NoAgent: c.GetBool("no-agent"), Key: c.GetString("key"),
				Principals: c.GetStringSlice("principal"), TTL: ttl})
		},
	}
}

// parseTTL reads --ttl: a duration (2h, 90m) or seconds, of at least a minute (the least the server signs).
func parseTTL(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	in := s
	if _, err := strconv.Atoi(s); err == nil {
		s += "s"
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < time.Minute {
		return 0, fmt.Errorf("--ttl %q: give a duration of at least 60 seconds, like 2h or 90m", in)
	}
	return d, nil
}

// parseHostTTL reads host-sign's --ttl: a number of days ("90" or "90d"), or hours that make whole days ("2160h"), at
// least one day (the API takes days).
func parseHostTTL(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	bad := fmt.Errorf("--ttl %q: give a whole number of days of at least 1, like 90 or 90d (or hours that make whole days, like 2160h)", s)
	if n, ok := strings.CutSuffix(s, "d"); ok {
		s = n
	} else if _, err := strconv.Atoi(s); err != nil {
		d, err := time.ParseDuration(s)
		if err != nil || d%(24*time.Hour) != 0 {
			return 0, bad
		}
		s = strconv.FormatInt(int64(d/(24*time.Hour)), 10)
	}
	days, err := strconv.Atoi(s)
	if err != nil || days < 1 || days > maxHostTTLDays {
		return 0, bad
	}
	return days, nil
}

// maxHostTTLDays is the longest host certificate any tenant can allow; the tenant's own limit is the server's to check.
const maxHostTTLDays = 365

func sshStatusCmd() *cli.Command {
	return &cli.Command{
		Name:  "status",
		Usage: "List the Quisora certificates in ssh-agent and ~/.ssh/quisora, with their principals and time left",
		Run: func(ctx context.Context, c *cli.Command) error {
			return sshEnv(c).Status()
		},
	}
}

func sshLogoutCmd() *cli.Command {
	return &cli.Command{
		Name:  "logout",
		Usage: "Remove Quisora certificates from ssh-agent and ~/.ssh/quisora",
		Description: "Removes the Quisora certificates (and the keys written without an agent). Give the tenant's " +
			"discovery URL to remove that tenant's only; without it, every Quisora certificate goes.",
		Flags:     sshTLSFlags(),
		Arguments: []cli.Argument{&cli.StringArg{Name: "url", Usage: "The tenant's discovery URL (default: every tenant)"}},
		Run: func(ctx context.Context, c *cli.Command) error {
			return sshEnv(c).Logout(ctx, c.GetStringArg("url"))
		},
	}
}

func sshHostSignCmd() *cli.Command {
	return &cli.Command{
		Name:  "host-sign",
		Usage: "Get a host certificate for a server's public key",
		Description: "Signs the host's public key (like /etc/ssh/ssh_host_ed25519_key.pub), writes the certificate beside it " +
			"(…-cert.pub) and prints the HostCertificate line for sshd_config. The principals are the names clients " +
			"connect to (default: this host's fully qualified name); the tenant limits them to its host patterns.\n\n" +
			"Authenticates with an access token (--token or QUISORA_TOKEN) or as a service account with the scope " +
			"ssh:host (--client-id and --client-secret or QUISORA_CLIENT_SECRET; the environment keeps the secret out " +
			"of the process list). A service account authenticates the way it was registered to: --auth-method auto " +
			"(the default) tries client_secret_post, which service accounts use unless made otherwise, and then " +
			"client_secret_basic; post or basic uses that one only.",
		Flags: append([]cli.Flag{
			&cli.StringSliceFlag{Name: "principal", Usage: "A name for the certificate (repeatable; default: this host's fully qualified name)"},
			&cli.StringFlag{Name: "token", EnvVars: []string{"QUISORA_TOKEN"}, Usage: "Access token with the scope ssh:host"},
			&cli.StringFlag{Name: "client-id", EnvVars: []string{"QUISORA_CLIENT_ID"}, Usage: "Client id of a service account with the scope ssh:host"},
			&cli.StringFlag{Name: "client-secret", EnvVars: []string{"QUISORA_CLIENT_SECRET"}, Usage: "Its client secret"},
			&cli.StringFlag{Name: "auth-method", DefaultValue: "auto", Usage: "How the service account authenticates: auto (post, then basic), post or basic"},
			&cli.StringFlag{Name: "ttl", Usage: "Ask for a certificate of this many days, e.g. 30 or 30d (default: the tenant's host certificate lifetime)"},
		}, sshTLSFlags()...),
		Arguments: []cli.Argument{sshURLArg(),
			&cli.StringArg{Name: "key", Usage: "The host's public key file", Required: true}},
		Run: func(ctx context.Context, c *cli.Command) error {
			days, err := parseHostTTL(c.GetString("ttl"))
			if err != nil {
				return err
			}
			return sshEnv(c).HostSign(ctx, sshcli.HostSignOptions{URL: c.GetStringArg("url"), KeyFile: c.GetStringArg("key"),
				Principals: c.GetStringSlice("principal"), Token: c.GetString("token"), ClientID: c.GetString("client-id"),
				Secret: c.GetString("client-secret"), AuthMethod: c.GetString("auth-method"), TTLDays: days})
		},
	}
}

func sshFetchCmd() *cli.Command {
	return &cli.Command{
		Name:  "fetch",
		Usage: "Update a server's trusted user CA keys and revocation list (for cron or a systemd timer)",
		Description: "Fetches the tenant's user CA keys and revocation list and writes them atomically to --ca-file " +
			"(sshd's TrustedUserCAKeys) and --krl-file (RevokedKeys), and with --known-hosts-file the host CA lines " +
			"for clients. Every answer is checked before anything is written, and the files in use are kept when the " +
			"server cannot be reached or answers with something invalid. A file is rewritten only when its bytes change; the " +
			"revocation list's change with each version, so its modification time shows when the server last answered. " +
			"The revocation list is installed only if ssh-keygen (when it is installed) can read it and it has a section for " +
			"at least one CA key the tenant publishes (so the CA keys and host CA lines are fetched with it, and checked, " +
			"even when not written). One older than the one in place (list versions are the server's clock) is kept, with a " +
			"note, while the other files are updated, unless it revokes something the one in place does not. " +
			"\"updated\" is printed for the revocation list only when what it revokes changed. " +
			"Exits 0 when the files are current, 1 when not.",
		Flags: append([]cli.Flag{
			&cli.StringFlag{Name: "ca-file", DefaultValue: "/etc/ssh/quisora_user_ca.pub", Usage: "Where to write the user CA keys"},
			&cli.StringFlag{Name: "krl-file", DefaultValue: "/etc/ssh/quisora.krl", Usage: "Where to write the revocation list"},
			&cli.StringFlag{Name: "known-hosts-file", Usage: "Where to write the host CA lines (default: not fetched)"},
			&cli.BoolFlag{Name: "end-revoked", Usage: "Also end open SSH connections whose certificate the revocation list revokes (Linux, sshd logging to journald; run as root)"},
		}, sshTLSFlags()...),
		Arguments: []cli.Argument{sshURLArg()},
		Run: func(ctx context.Context, c *cli.Command) error {
			return sshEnv(c).Fetch(ctx, sshcli.FetchOptions{URL: c.GetStringArg("url"), CAFile: c.GetString("ca-file"),
				KRLFile: c.GetString("krl-file"), KnownHostsFile: c.GetString("known-hosts-file"), EndRevoked: c.GetBool("end-revoked")})
		},
	}
}
