package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/paularlott/cli"
	"github.com/paularlott/quisora/internal/app"
	"github.com/paularlott/quisora/internal/backup"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/web"
)

const storeNote = "Uses the same config file / QUISORA_* environment as serve. With a shared database (postgres, mysql, " +
	"mariadb) it works while the server runs. With a node-local store (BadgerDB, SQLite) stop the server first."

func backupCmd(cfg *config.Config, flags []cli.Flag) *cli.Command {
	return &cli.Command{
		Name:  "backup",
		Usage: "Write every record of the store to a backup file",
		Description: "Writes a compressed backup of every organization, user, credential, application, key and audit " +
			"entry to <file> (\"-\" for standard output). Secrets stay sealed with the master key: a restore needs " +
			"that key too. Short-lived state (sign-in challenges, rate limits) is not included.\n\n" +
			"The file is always encrypted (AES-256-GCM, with a key derived from a password by argon2id). The " +
			"password (at least 12 characters) is read from --password-file, else from standard input " +
			"when it is a pipe, else asked for on the terminal (twice); keep it apart from the backup.\n\n" +
			"The backup is a consistent snapshot of the whole store (a point-in-time view of the database).\n\n" +
			"With --server it downloads the backup from a running server (any backend, the server keeps serving), " +
			"authenticated with a super admin's API token that has the \"backup\" scope (--token or " +
			"QUISORA_ADMIN_TOKEN; a token without that scope is refused with 403); the download is checked to be " +
			"complete before it is kept; the server encrypts it with the password, sent over TLS. Without --server " +
			"it reads the configured store directly. " + storeNote,
		Flags: append(flags,
			&cli.StringFlag{Name: "server", Usage: "Back up a running server: its base URL, such as https://id.example.com"},
			&cli.StringFlag{Name: "password-file", Usage: "File holding the password to encrypt the backup with (its first line)"},
			&cli.StringFlag{Name: "token", Usage: "API token of a super admin with the \"backup\" scope, for --server",
				EnvVars: []string{config.EnvPrefix + "ADMIN_TOKEN"}},
			&cli.StringFlag{Name: "ca-file", Usage: "PEM file of extra CA certificates trusted for --server"},
			&cli.BoolFlag{Name: "insecure", Usage: "Do not verify --server's certificate (a self-signed development server)"},
		),
		Arguments: []cli.Argument{
			&cli.StringArg{Name: "file", Usage: "Backup file to write, or - for standard output", Required: true},
		},
		Run: func(ctx context.Context, c *cli.Command) error {
			name := c.GetStringArg("file")
			var stats backup.Stats
			var err error
			// A backup is always encrypted: it holds every account and audit event, and its secrets are only as safe as the
			// master key that seals them, which may well sit beside it.
			password, err := backupPassword(c.GetString("password-file"), true, true)
			if err != nil {
				return err
			}
			if len(password) < backup.MinPassword {
				return fmt.Errorf("the backup password must have at least %d characters", backup.MinPassword)
			}
			// Interrupted from here on (Ctrl+C, SIGTERM), the backup stops and the temporary file is removed.
			ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
			defer stop()
			var w io.Writer = os.Stdout
			var tmp *os.File
			if name != "-" {
				// Written beside the target and renamed into place, so a failed backup never leaves a partial file
				// under the real name.
				f, err := os.CreateTemp(filepath.Dir(name), ".quisora-backup-*")
				if err != nil {
					return err
				}
				defer os.Remove(f.Name())
				if err := f.Chmod(0o600); err != nil {
					f.Close()
					return err
				}
				tmp, w = f, f
			}
			if server := c.GetString("server"); server != "" {
				stats, err = remoteBackup(ctx, server, c.GetString("token"), c.GetString("ca-file"), c.GetBool("insecure"),
					password, w)
			} else if err = prepare(ctx, cfg); err == nil {
				stats, err = app.Backup(ctx, cfg, w, backup.Options{Password: password})
			}
			if tmp != nil {
				if cerr := tmp.Close(); err == nil {
					err = cerr
				}
				if err == nil {
					err = os.Rename(tmp.Name(), name)
				}
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Backed up %d records, encrypted (%s).\n", stats.Total(), summary(stats))
			return nil
		},
	}
}

// remoteBackup downloads GET <server>/api/backup (over TLS) into w, encrypted by the server with password (sent in
// the X-Backup-Password header), checking the stream (backup.Verify, with the password) as it arrives: an incomplete
// or damaged download is an error.
func remoteBackup(ctx context.Context, server, token, caFile string, insecure bool, password string, w io.Writer) (_ backup.Stats, err error) {
	if token == "" {
		return nil, fmt.Errorf("--server needs a super admin's API token: --token or %sADMIN_TOKEN", config.EnvPrefix)
	}
	u, err := url.Parse(strings.TrimRight(server, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("--server must be an https URL, such as https://id.example.com")
	}
	roots, err := secure.RootPool(caFile)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{RootCAs: roots, InsecureSkipVerify: insecure}}}
	target := u.String() + "/api/backup"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Backup-Password", password)
	req.Header.Set(web.APIVersionHeader, web.APIVersionLatest)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e)
		return nil, fmt.Errorf("server answered %s: %s", resp.Status, e.Error)
	}
	pr, pw := io.Pipe()
	type result struct {
		stats backup.Stats
		err   error
	}
	done := make(chan result, 1)
	go func() {
		st, err := backup.Verify(pr, nil, password) // structure and completeness: the master key is not needed here
		_, _ = io.Copy(io.Discard, pr)              // keep the copy below from blocking if Verify stopped early
		done <- result{st, err}
	}()
	_, cerr := io.Copy(w, io.TeeReader(resp.Body, pw))
	pw.CloseWithError(cerr)
	res := <-done
	if cerr != nil {
		return nil, fmt.Errorf("download: %w", cerr)
	}
	if res.err != nil {
		return nil, fmt.Errorf("the downloaded backup is incomplete or damaged: %w", res.err)
	}
	return res.stats, nil
}

func restoreCmd(cfg *config.Config, flags []cli.Flag) *cli.Command {
	return &cli.Command{
		Name:  "restore",
		Usage: "Load a backup file into an empty store",
		Description: "Loads a backup made by \"quisora backup\" from <file> (\"-\" for standard input) into the configured " +
			"store, keeping every record's id and version. The store must be empty; --force merges into a store " +
			"that is not: records from the backup replace older versions of themselves, and where two different " +
			"records claim the same unique value (an organization name, an email address) the restore fails. " +
			"An encrypted backup is detected; " +
			"its password is read from --password-file, else from standard input when it is a pipe (and the backup " +
			"is a file), else asked for on the terminal. The master key must be the one of the server the backup came " +
			"from (or one of server.previous_master_keys).\n\n" +
			"In a gossip cluster, restore into one node with an empty database and start it, then start the others with " +
			"empty databases so they copy from it (a restore never goes over data in a cluster).\n\n" + storeNote,
		Flags: append(flags, &cli.BoolFlag{Name: "force", Usage: "Restore into a store that is not empty"},
			&cli.StringFlag{Name: "password-file", Usage: "File holding the encrypted backup's password (its first line)"}),
		Arguments: []cli.Argument{
			&cli.StringArg{Name: "file", Usage: "Backup file to read, or - for standard input", Required: true},
		},
		Run: func(ctx context.Context, c *cli.Command) error {
			if err := prepare(ctx, cfg); err != nil {
				return err
			}
			// The backup is read twice (verified whole before anything is written), so standard input is kept in
			// a temporary file first.
			var r io.ReadSeeker
			if name := c.GetStringArg("file"); name != "-" {
				f, err := os.Open(name)
				if err != nil {
					return err
				}
				defer f.Close()
				r = f
			} else {
				f, err := os.CreateTemp("", "quisora-restore-*")
				if err != nil {
					return err
				}
				defer os.Remove(f.Name())
				defer f.Close()
				if _, err := io.Copy(f, os.Stdin); err != nil {
					return err
				}
				if _, err := f.Seek(0, io.SeekStart); err != nil {
					return err
				}
				r = f
			}
			password := ""
			head := make([]byte, 8)
			n, _ := io.ReadFull(r, head)
			if _, err := r.Seek(0, io.SeekStart); err != nil {
				return err
			}
			if backup.PasswordProtected(head[:n]) {
				var err error
				if password, err = backupPassword(c.GetString("password-file"), c.GetStringArg("file") != "-", false); err != nil {
					return err
				}
			}
			stats, err := app.Restore(ctx, cfg, r, c.GetBool("force"), password)
			if err != nil {
				if stats != nil && stats.Total() > 0 {
					return fmt.Errorf("%w (%d records were restored before the error)", err, stats.Total())
				}
				return err
			}
			fmt.Fprintf(os.Stderr, "Restored %d records (%s).\n", stats.Total(), summary(stats))
			return nil
		},
	}
}

func summary(s backup.Stats) string {
	parts := make([]string, 0, len(s))
	for k, n := range s {
		parts = append(parts, fmt.Sprintf("%s %d", k, n))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}
