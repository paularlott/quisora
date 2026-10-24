// Package secrets reads the secret settings that name a secret store instead of holding their value: the master
// key, the cluster key, database and SMTP passwords and the like (every setting marked secret in internal/config).
//
//	op://<vault>/<item>/<field>           1Password: Connect, or a service account (builds with the onepassword tag)
//	op://<vault>/<item>/<section>/<field>
//	vault://<path>#<field>                HashiCorp Vault (or OpenBao): the API path after /v1/, such as
//	                                      vault://secret/data/quisora#master_key on a KV version 2 mount
//
// References are read when a command starts and again on a configuration reload (SIGHUP, or the cluster-wide reload
// the console's "Read secret stores now" runs), so rotating a key is an edit in the store and a reload. The values
// are kept in memory only, in the configuration; nothing is written to disk. A store that cannot be read fails the
// start (or the reload, which leaves the keys in use as they were).
package secrets

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
)

// Apply resolves the references of c's secret settings (only those at paths, TOML paths, when given) in place.
func Apply(ctx context.Context, c *config.Config, paths ...string) error {
	if !c.HasSecretRefs() {
		return nil
	}
	r := &resolver{cfg: c.Secrets}
	defer r.close()
	return c.ResolveSecrets(ctx, r.resolve, paths...)
}

// resolver reads references for one Apply, signing in to each store at most once.
type resolver struct {
	cfg   config.Secrets
	vault *vaultClient
	op    opReader
}

// opReader reads op:// references: 1Password Connect, or a service account.
type opReader interface {
	read(ctx context.Context, ref string) (string, error)
}

func (r *resolver) resolve(ctx context.Context, ref string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var (
		v   string
		err error
	)
	switch {
	case strings.HasPrefix(ref, "vault://"):
		if r.vault == nil {
			if r.vault, err = newVault(ctx, r.cfg.Vault); err != nil {
				return "", err
			}
		}
		v, err = r.vault.read(ctx, strings.TrimPrefix(ref, "vault://"))
	case strings.HasPrefix(ref, "op://"):
		if r.op == nil {
			if r.op, err = newOnePassword(ctx, r.cfg.OnePassword); err != nil {
				return "", err
			}
		}
		v, err = r.op.read(ctx, ref)
	default:
		return ref, nil
	}
	if err != nil {
		return "", fmt.Errorf("%s: %w", ref, err)
	}
	return v, nil // empty: no value (a previous key slot with no rotation running); a missing field is an error
}

func (r *resolver) close() {
	if c, ok := r.op.(interface{ close() }); ok {
		c.close()
	}
}

// credential is a store credential given inline, or in a file (its first line).
func credential(inline, file, what string) (string, error) {
	if inline != "" {
		return inline, nil
	}
	if file == "" {
		return "", nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	line, _, _ := strings.Cut(string(b), "\n")
	if line = strings.TrimSpace(line); line == "" {
		return "", fmt.Errorf("%s: %s is empty", what, file)
	}
	return line, nil
}

// httpClient talks to a store: TLS verified against the system roots and caFile, proxies from the environment.
func httpClient(caFile string) (*http.Client, error) {
	roots, err := secure.RootPool(caFile)
	if err != nil {
		return nil, err
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}, nil
}

// errNotConfigured explains a reference to a store that is not set up.
func errNotConfigured(store, section string) error {
	return errors.New("no " + store + " is configured: set " + section)
}

// PlainHTTP returns the settings of c that reach a secret store over plain http (allowed, for a store on the same
// host or a private network, but the keys then cross the network readable by anyone on it): the server warns of them.
func PlainHTTP(c config.Secrets) []string {
	var out []string
	if strings.HasPrefix(strings.ToLower(c.Vault.Address), "http://") {
		out = append(out, "secrets.vault.address")
	}
	if strings.HasPrefix(strings.ToLower(c.OnePassword.ConnectURL), "http://") {
		out = append(out, "secrets.onepassword.connect_url")
	}
	return out
}
